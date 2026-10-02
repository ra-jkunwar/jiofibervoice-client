package com.example.jiofibervoice

import android.content.Context
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.MediaRecorder
import android.util.Log
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean

/**
 * RTP (RFC 3550) Voice Engine for bidirectional VoIP audio streaming.
 * Supports G.711 A-law (PCMA, payload 8) and mu-law (PCMU, payload 0) with RFC 4733 DTMF.
 */
class RtpAudioEngine(private val context: Context) {
    companion object {
        private const val TAG = "RtpAudioEngine"
        const val SAMPLE_RATE = 8000
        const val FRAME_SIZE_MS = 20
        const val SAMPLES_PER_FRAME = (SAMPLE_RATE * FRAME_SIZE_MS) / 1000 // 160 samples
        const val PAYLOAD_PCMA = 8
        const val PAYLOAD_PCMU = 0
        const val PAYLOAD_DTMF = 101
    }

    private val audioManager = context.getSystemService(Context.AUDIO_SERVICE) as AudioManager
    private var socket: DatagramSocket? = null
    private var recordThread: Thread? = null
    private var playThread: Thread? = null
    private val isRunning = AtomicBoolean(false)

    var isMuted: Boolean = false
    var isSpeakerOn: Boolean = false
        set(value) {
            field = value
            try {
                audioManager.isSpeakerphoneOn = value
            } catch (e: Exception) {
                Log.e(TAG, "Error toggling speakerphone: ${e.message}")
            }
        }

    private var remoteAddress: InetAddress? = null
    private var remotePort: Int = 0
    private var payloadType: Int = PAYLOAD_PCMA
    private var ssrc: Int = SecureRandom().nextInt()
    private var seqNum: Short = SecureRandom().nextInt().toShort()
    private var timestamp: Int = SecureRandom().nextInt()

    /**
     * Start RTP audio streaming with the given remote endpoint and codec.
     */
    @Synchronized
    fun start(
        localPort: Int,
        remoteHost: String,
        remotePort: Int,
        codecPayload: Int = PAYLOAD_PCMA
    ) {
        if (isRunning.get()) {
            stop()
        }

        this.remoteAddress = InetAddress.getByName(remoteHost)
        this.remotePort = remotePort
        this.payloadType = if (codecPayload == PAYLOAD_PCMU) PAYLOAD_PCMU else PAYLOAD_PCMA
        this.ssrc = SecureRandom().nextInt()
        this.seqNum = (SecureRandom().nextInt() and 0xFFFF).toShort()
        this.timestamp = SecureRandom().nextInt()

        try {
            socket = DatagramSocket(localPort).apply {
                soTimeout = 2000
                trafficClass = 0x10 or 0x08 // IPTOS_LOWDELAY | IPTOS_THROUGHPUT
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to bind RTP socket to port $localPort, falling back to any port: ${e.message}")
            socket = DatagramSocket().apply {
                soTimeout = 2000
                trafficClass = 0x10 or 0x08
            }
        }

        try {
            audioManager.mode = AudioManager.MODE_IN_COMMUNICATION
            audioManager.isSpeakerphoneOn = isSpeakerOn
        } catch (e: Exception) {
            Log.w(TAG, "Failed setting audio mode: ${e.message}")
        }

        isRunning.set(true)
        startPlayback()
        startRecording()
        Log.i(TAG, "RTP Audio Engine started: local=${socket?.localPort} -> remote=$remoteHost:$remotePort (codec=$payloadType)")
    }

    val localPort: Int
        get() = socket?.localPort ?: 0

    private fun startRecording() {
        recordThread = Thread({
            val minBuf = AudioRecord.getMinBufferSize(
                SAMPLE_RATE,
                AudioFormat.CHANNEL_IN_MONO,
                AudioFormat.ENCODING_PCM_16BIT
            )
            val bufferSize = maxOf(minBuf, SAMPLES_PER_FRAME * 4)

            var recorder: AudioRecord? = null
            try {
                recorder = AudioRecord(
                    MediaRecorder.AudioSource.VOICE_COMMUNICATION,
                    SAMPLE_RATE,
                    AudioFormat.CHANNEL_IN_MONO,
                    AudioFormat.ENCODING_PCM_16BIT,
                    bufferSize
                )
            } catch (e: Exception) {
                Log.w(TAG, "AudioRecord VOICE_COMMUNICATION failed, falling back to MIC: ${e.message}")
                try {
                    recorder = AudioRecord(
                        MediaRecorder.AudioSource.MIC,
                        SAMPLE_RATE,
                        AudioFormat.CHANNEL_IN_MONO,
                        AudioFormat.ENCODING_PCM_16BIT,
                        bufferSize
                    )
                } catch (e2: Exception) {
                    Log.e(TAG, "Failed to initialize AudioRecord: ${e2.message}")
                    return@Thread
                }
            }

            try {
                recorder.startRecording()
            } catch (e: Exception) {
                Log.e(TAG, "AudioRecord startRecording failed: ${e.message}")
                recorder.release()
                return@Thread
            }

            val pcmBuffer = ShortArray(SAMPLES_PER_FRAME)
            val rtpPacketData = ByteArray(12 + SAMPLES_PER_FRAME)
            val silentAlaw = G711Codec.linearToAlaw(0)
            val silentUlaw = G711Codec.linearToUlaw(0)

            while (isRunning.get()) {
                val readSamples = recorder.read(pcmBuffer, 0, SAMPLES_PER_FRAME)
                if (readSamples < SAMPLES_PER_FRAME) continue

                // Build RTP Header (12 bytes)
                rtpPacketData[0] = 0x80.toByte() // V=2, P=0, X=0, CC=0
                rtpPacketData[1] = (payloadType and 0x7F).toByte()

                // Sequence number (16-bit)
                rtpPacketData[2] = ((seqNum.toInt() shr 8) and 0xFF).toByte()
                rtpPacketData[3] = (seqNum.toInt() and 0xFF).toByte()
                seqNum = (seqNum + 1).toShort()

                // Timestamp (32-bit)
                rtpPacketData[4] = ((timestamp shr 24) and 0xFF).toByte()
                rtpPacketData[5] = ((timestamp shr 16) and 0xFF).toByte()
                rtpPacketData[6] = ((timestamp shr 8) and 0xFF).toByte()
                rtpPacketData[7] = (timestamp and 0xFF).toByte()
                timestamp += SAMPLES_PER_FRAME

                // SSRC (32-bit)
                rtpPacketData[8] = ((ssrc shr 24) and 0xFF).toByte()
                rtpPacketData[9] = ((ssrc shr 16) and 0xFF).toByte()
                rtpPacketData[10] = ((ssrc shr 8) and 0xFF).toByte()
                rtpPacketData[11] = (ssrc and 0xFF).toByte()

                // Payload encoding
                if (isMuted) {
                    val silence = if (payloadType == PAYLOAD_PCMA) silentAlaw else silentUlaw
                    for (i in 0 until SAMPLES_PER_FRAME) {
                        rtpPacketData[12 + i] = silence
                    }
                } else {
                    if (payloadType == PAYLOAD_PCMA) {
                        for (i in 0 until SAMPLES_PER_FRAME) {
                            rtpPacketData[12 + i] = G711Codec.linearToAlaw(pcmBuffer[i])
                        }
                    } else {
                        for (i in 0 until SAMPLES_PER_FRAME) {
                            rtpPacketData[12 + i] = G711Codec.linearToUlaw(pcmBuffer[i])
                        }
                    }
                }

                // Send UDP packet
                try {
                    val targetAddr = remoteAddress
                    val targetP = remotePort
                    val sock = socket
                    if (targetAddr != null && targetP > 0 && sock != null && !sock.isClosed) {
                        val packet = DatagramPacket(rtpPacketData, rtpPacketData.size, targetAddr, targetP)
                        sock.send(packet)
                    }
                } catch (e: Exception) {
                    if (!isRunning.get()) break
                }
            }

            try {
                recorder.stop()
                recorder.release()
            } catch (e: Exception) {
                Log.w(TAG, "Error releasing AudioRecord: ${e.message}")
            }
        }, "RtpRecordThread").apply { start() }
    }

    private fun startPlayback() {
        playThread = Thread({
            val minBuf = AudioTrack.getMinBufferSize(
                SAMPLE_RATE,
                AudioFormat.CHANNEL_OUT_MONO,
                AudioFormat.ENCODING_PCM_16BIT
            )
            val bufferSize = maxOf(minBuf, SAMPLES_PER_FRAME * 4)

            var track: AudioTrack? = null
            try {
                track = AudioTrack(
                    AudioManager.STREAM_VOICE_CALL,
                    SAMPLE_RATE,
                    AudioFormat.CHANNEL_OUT_MONO,
                    AudioFormat.ENCODING_PCM_16BIT,
                    bufferSize,
                    AudioTrack.MODE_STREAM
                )
                track.play()
            } catch (e: Exception) {
                Log.e(TAG, "Failed to initialize AudioTrack: ${e.message}")
                return@Thread
            }

            val recvBuffer = ByteArray(1500)
            val pcmOut = ShortArray(SAMPLES_PER_FRAME)

            while (isRunning.get()) {
                val sock = socket ?: break
                if (sock.isClosed) break

                val packet = DatagramPacket(recvBuffer, recvBuffer.size)
                try {
                    sock.receive(packet)
                } catch (e: Exception) {
                    // Socket timeout or closed
                    continue
                }

                val len = packet.length
                if (len < 12) continue // Invalid RTP packet

                // Check version
                val v = (recvBuffer[0].toInt() and 0xC0) ushr 6
                if (v != 2) continue

                val pt = recvBuffer[1].toInt() and 0x7F
                val cc = recvBuffer[0].toInt() and 0x0F
                var offset = 12 + (cc * 4)

                // Skip extension header if present
                val x = (recvBuffer[0].toInt() and 0x10) != 0
                if (x && len >= offset + 4) {
                    val extLen = ((recvBuffer[offset + 2].toInt() and 0xFF) shl 8) or
                            (recvBuffer[offset + 3].toInt() and 0xFF)
                    offset += 4 + (extLen * 4)
                }

                val payloadLen = len - offset
                if (payloadLen <= 0) continue

                val samplesToDecode = minOf(payloadLen, SAMPLES_PER_FRAME)

                if (pt == PAYLOAD_PCMA) {
                    for (i in 0 until samplesToDecode) {
                        pcmOut[i] = G711Codec.alawToLinear(recvBuffer[offset + i])
                    }
                    track.write(pcmOut, 0, samplesToDecode)
                } else if (pt == PAYLOAD_PCMU) {
                    for (i in 0 until samplesToDecode) {
                        pcmOut[i] = G711Codec.ulawToLinear(recvBuffer[offset + i])
                    }
                    track.write(pcmOut, 0, samplesToDecode)
                }
            }

            try {
                track.stop()
                track.release()
            } catch (e: Exception) {
                Log.w(TAG, "Error releasing AudioTrack: ${e.message}")
            }
        }, "RtpPlayThread").apply { start() }
    }

    /**
     * Send RFC 4733 / RFC 2833 DTMF telephone-event packet.
     */
    fun sendDtmf(digit: Char) {
        val eventCode = when (digit) {
            in '0'..'9' -> digit - '0'
            '*' -> 10
            '#' -> 11
            'A', 'a' -> 12
            'B', 'b' -> 13
            'C', 'c' -> 14
            'D', 'd' -> 15
            else -> return
        }

        Thread {
            try {
                val targetAddr = remoteAddress ?: return@Thread
                val targetP = remotePort
                val sock = socket ?: return@Thread
                if (sock.isClosed) return@Thread

                val dtmfPacket = ByteArray(16) // 12 bytes RTP + 4 bytes RFC 4733
                dtmfPacket[0] = 0x80.toByte()
                dtmfPacket[1] = (PAYLOAD_DTMF and 0x7F).toByte()

                // 3 packets: start, middle, end
                val duration = 160 // 20ms
                for (step in 1..3) {
                    val isEnd = step == 3
                    dtmfPacket[2] = ((seqNum.toInt() shr 8) and 0xFF).toByte()
                    dtmfPacket[3] = (seqNum.toInt() and 0xFF).toByte()
                    seqNum = (seqNum + 1).toShort()

                    dtmfPacket[4] = ((timestamp shr 24) and 0xFF).toByte()
                    dtmfPacket[5] = ((timestamp shr 16) and 0xFF).toByte()
                    dtmfPacket[6] = ((timestamp shr 8) and 0xFF).toByte()
                    dtmfPacket[7] = (timestamp and 0xFF).toByte()

                    dtmfPacket[8] = ((ssrc shr 24) and 0xFF).toByte()
                    dtmfPacket[9] = ((ssrc shr 16) and 0xFF).toByte()
                    dtmfPacket[10] = ((ssrc shr 8) and 0xFF).toByte()
                    dtmfPacket[11] = (ssrc and 0xFF).toByte()

                    // DTMF payload (RFC 4733)
                    dtmfPacket[12] = eventCode.toByte()
                    dtmfPacket[13] = if (isEnd) 0x80.toByte() else 0x00 // E bit | Volume
                    val currentDur = duration * step
                    dtmfPacket[14] = ((currentDur shr 8) and 0xFF).toByte()
                    dtmfPacket[15] = (currentDur and 0xFF).toByte()

                    val packet = DatagramPacket(dtmfPacket, dtmfPacket.size, targetAddr, targetP)
                    sock.send(packet)
                    Thread.sleep(20)
                }
                timestamp += duration * 3
            } catch (e: Exception) {
                Log.w(TAG, "Failed sending DTMF event: ${e.message}")
            }
        }.start()
    }

    /**
     * Stop RTP audio streaming and release audio resources.
     */
    @Synchronized
    fun stop() {
        if (!isRunning.getAndSet(false)) return

        try {
            socket?.close()
        } catch (_: Exception) {}
        socket = null

        try {
            recordThread?.interrupt()
            playThread?.interrupt()
        } catch (_: Exception) {}
        recordThread = null
        playThread = null

        try {
            audioManager.mode = AudioManager.MODE_NORMAL
        } catch (_: Exception) {}

        Log.i(TAG, "RTP Audio Engine stopped")
    }
}
