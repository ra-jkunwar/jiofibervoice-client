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
 * Supports AMR-WB (16 kHz), AMR-NB (8 kHz), G.711 A-law/u-law (8 kHz) and RFC 4733 DTMF.
 */
class RtpAudioEngine(private val context: Context) {
    companion object {
        private const val TAG = "RtpAudioEngine"
        const val PAYLOAD_PCMU = 0
        const val PAYLOAD_PCMA = 8
        const val PAYLOAD_AMR = 118
        const val PAYLOAD_AMR_WB = 120
        const val PAYLOAD_AMR_OA = 123
        const val PAYLOAD_AMR_BE = 124
        const val PAYLOAD_AMR_WB_OA = 125
        const val PAYLOAD_AMR_WB_BE = 126
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
    private var payloadType: Int = PAYLOAD_AMR_WB_OA
    private var sampleRate: Int = 16000
    private var samplesPerFrame: Int = 320
    private var amrCodec: AmrCodec? = null

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
        codecPayload: Int = PAYLOAD_AMR_WB_OA
    ) {
        if (isRunning.get()) {
            stop()
        }

        this.remoteAddress = InetAddress.getByName(remoteHost)
        this.remotePort = remotePort
        this.payloadType = codecPayload

        val isWideband = codecPayload in listOf(PAYLOAD_AMR_WB, PAYLOAD_AMR_WB_OA, PAYLOAD_AMR_WB_BE)
        val isNarrowband = codecPayload in listOf(PAYLOAD_AMR, PAYLOAD_AMR_OA, PAYLOAD_AMR_BE)

        if (isWideband) {
            sampleRate = 16000
            samplesPerFrame = 320
            amrCodec = AmrCodec(isWideband = true).apply { init() }
        } else if (isNarrowband) {
            sampleRate = 8000
            samplesPerFrame = 160
            amrCodec = AmrCodec(isWideband = false).apply { init() }
        } else {
            sampleRate = 8000
            samplesPerFrame = 160
            amrCodec = null
        }

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
        Log.i(TAG, "RTP Audio Engine started: local=${socket?.localPort} -> remote=$remoteHost:$remotePort (codec=$payloadType, rate=$sampleRate)")
    }

    val localPort: Int
        get() = socket?.localPort ?: 0

    private fun startRecording() {
        val sRate = sampleRate
        val fSize = samplesPerFrame
        val codec = amrCodec
        val pt = payloadType

        recordThread = Thread({
            val minBuf = AudioRecord.getMinBufferSize(
                sRate,
                AudioFormat.CHANNEL_IN_MONO,
                AudioFormat.ENCODING_PCM_16BIT
            )
            val bufferSize = maxOf(minBuf, fSize * 4)

            var recorder: AudioRecord? = null
            try {
                recorder = AudioRecord(
                    MediaRecorder.AudioSource.VOICE_COMMUNICATION,
                    sRate,
                    AudioFormat.CHANNEL_IN_MONO,
                    AudioFormat.ENCODING_PCM_16BIT,
                    bufferSize
                )
            } catch (e: Exception) {
                Log.w(TAG, "AudioRecord VOICE_COMMUNICATION failed, falling back to MIC: ${e.message}")
                try {
                    recorder = AudioRecord(
                        MediaRecorder.AudioSource.MIC,
                        sRate,
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

            val pcmBuffer = ShortArray(fSize)
            val rtpHeader = ByteArray(12)

            while (isRunning.get()) {
                val readSamples = recorder.read(pcmBuffer, 0, fSize)
                if (readSamples < fSize) continue

                // Build RTP Header (12 bytes)
                rtpHeader[0] = 0x80.toByte() // V=2, P=0, X=0, CC=0
                rtpHeader[1] = (pt and 0x7F).toByte()

                // Sequence number (16-bit)
                rtpHeader[2] = ((seqNum.toInt() shr 8) and 0xFF).toByte()
                rtpHeader[3] = (seqNum.toInt() and 0xFF).toByte()
                seqNum = (seqNum + 1).toShort()

                // Timestamp (32-bit)
                rtpHeader[4] = ((timestamp shr 24) and 0xFF).toByte()
                rtpHeader[5] = ((timestamp shr 16) and 0xFF).toByte()
                rtpHeader[6] = ((timestamp shr 8) and 0xFF).toByte()
                rtpHeader[7] = (timestamp and 0xFF).toByte()
                timestamp += fSize

                // SSRC (32-bit)
                rtpHeader[8] = ((ssrc shr 24) and 0xFF).toByte()
                rtpHeader[9] = ((ssrc shr 16) and 0xFF).toByte()
                rtpHeader[10] = ((ssrc shr 8) and 0xFF).toByte()
                rtpHeader[11] = (ssrc and 0xFF).toByte()

                val packetBytes: ByteArray?
                if (codec != null) {
                    if (isMuted) {
                        pcmBuffer.fill(0)
                    }
                    val amrPayload = codec.encodeFrame(pcmBuffer, 0, fSize)
                    if (amrPayload != null) {
                        packetBytes = ByteArray(12 + amrPayload.size)
                        System.arraycopy(rtpHeader, 0, packetBytes, 0, 12)
                        System.arraycopy(amrPayload, 0, packetBytes, 12, amrPayload.size)
                    } else {
                        packetBytes = null
                    }
                } else {
                    // G.711 fallback
                    val g711Data = ByteArray(fSize)
                    if (isMuted) {
                        val silence = if (pt == PAYLOAD_PCMA) G711Codec.linearToAlaw(0) else G711Codec.linearToUlaw(0)
                        g711Data.fill(silence)
                    } else {
                        if (pt == PAYLOAD_PCMA) {
                            for (i in 0 until fSize) {
                                g711Data[i] = G711Codec.linearToAlaw(pcmBuffer[i])
                            }
                        } else {
                            for (i in 0 until fSize) {
                                g711Data[i] = G711Codec.linearToUlaw(pcmBuffer[i])
                            }
                        }
                    }
                    packetBytes = ByteArray(12 + fSize)
                    System.arraycopy(rtpHeader, 0, packetBytes, 0, 12)
                    System.arraycopy(g711Data, 0, packetBytes, 12, fSize)
                }

                // Send UDP packet
                if (packetBytes != null) {
                    try {
                        val targetAddr = remoteAddress
                        val targetP = remotePort
                        val sock = socket
                        if (targetAddr != null && targetP > 0 && sock != null && !sock.isClosed) {
                            val packet = DatagramPacket(packetBytes, packetBytes.size, targetAddr, targetP)
                            sock.send(packet)
                        }
                    } catch (e: Exception) {
                        if (!isRunning.get()) break
                    }
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
        val sRate = sampleRate
        val fSize = samplesPerFrame
        val codec = amrCodec

        playThread = Thread({
            val minBuf = AudioTrack.getMinBufferSize(
                sRate,
                AudioFormat.CHANNEL_OUT_MONO,
                AudioFormat.ENCODING_PCM_16BIT
            )
            val bufferSize = maxOf(minBuf, fSize * 4)

            var track: AudioTrack? = null
            try {
                track = AudioTrack(
                    AudioManager.STREAM_VOICE_CALL,
                    sRate,
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
            val pcmOut = ShortArray(fSize)

            while (isRunning.get()) {
                val sock = socket ?: break
                if (sock.isClosed) break

                val packet = DatagramPacket(recvBuffer, recvBuffer.size)
                try {
                    sock.receive(packet)
                } catch (e: Exception) {
                    continue
                }

                val len = packet.length
                if (len < 12) continue

                val v = (recvBuffer[0].toInt() and 0xC0) ushr 6
                if (v != 2) continue

                val pt = recvBuffer[1].toInt() and 0x7F
                val cc = recvBuffer[0].toInt() and 0x0F
                var offset = 12 + (cc * 4)

                val x = (recvBuffer[0].toInt() and 0x10) != 0
                if (x && len >= offset + 4) {
                    val extLen = ((recvBuffer[offset + 2].toInt() and 0xFF) shl 8) or
                            (recvBuffer[offset + 3].toInt() and 0xFF)
                    offset += 4 + (extLen * 4)
                }

                val payloadLen = len - offset
                if (payloadLen <= 0) continue

                if (codec != null && (pt in listOf(PAYLOAD_AMR_WB, PAYLOAD_AMR_WB_OA, PAYLOAD_AMR_WB_BE, PAYLOAD_AMR, PAYLOAD_AMR_OA, PAYLOAD_AMR_BE))) {
                    val decoded = codec.decodeFrame(recvBuffer, offset, payloadLen, pcmOut, 0)
                    if (decoded > 0) {
                        track.write(pcmOut, 0, decoded)
                    }
                } else if (pt == PAYLOAD_PCMA) {
                    val samples = minOf(payloadLen, fSize)
                    for (i in 0 until samples) {
                        pcmOut[i] = G711Codec.alawToLinear(recvBuffer[offset + i])
                    }
                    track.write(pcmOut, 0, samples)
                } else if (pt == PAYLOAD_PCMU) {
                    val samples = minOf(payloadLen, fSize)
                    for (i in 0 until samples) {
                        pcmOut[i] = G711Codec.ulawToLinear(recvBuffer[offset + i])
                    }
                    track.write(pcmOut, 0, samples)
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

                    dtmfPacket[12] = eventCode.toByte()
                    dtmfPacket[13] = if (isEnd) 0x80.toByte() else 0x00
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
        } catch (_: Exception) {}
        recordThread = null

        try {
            playThread?.interrupt()
        } catch (_: Exception) {}
        playThread = null

        amrCodec?.release()
        amrCodec = null

        try {
            audioManager.mode = AudioManager.MODE_NORMAL
        } catch (e: Exception) {
            Log.w(TAG, "Failed resetting audio mode: ${e.message}")
        }
        Log.i(TAG, "RTP Audio Engine stopped")
    }
}
