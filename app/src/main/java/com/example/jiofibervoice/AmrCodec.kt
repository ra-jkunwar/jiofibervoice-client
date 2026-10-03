package com.example.jiofibervoice

import android.media.MediaCodec
import android.media.MediaFormat
import android.util.Log

/**
 * Platform AMR-WB (16 kHz) and AMR-NB (8 kHz) encoder & decoder
 * using Android MediaCodec for VoLTE/VoNR IMS VoIP calls.
 * Formats frames according to RFC 4867 (RTP payload format for AMR/AMR-WB).
 */
class AmrCodec(val isWideband: Boolean) {
    companion object {
        private const val TAG = "AmrCodec"
        const val MIME_AMR_WB = "audio/amr-wb"
        const val MIME_AMR_NB = "audio/3gpp"
        const val CMR_NO_REQ: Byte = 0xF0.toByte()
    }

    val sampleRate = if (isWideband) 16000 else 8000
    val samplesPerFrame = if (isWideband) 320 else 160
    private val mime = if (isWideband) MIME_AMR_WB else MIME_AMR_NB

    private var encoder: MediaCodec? = null
    private var decoder: MediaCodec? = null
    var isEncoderInitialized = false
        private set
    var isDecoderInitialized = false
        private set

    fun init() {
        try {
            val encFormat = MediaFormat.createAudioFormat(mime, sampleRate, 1)
            encFormat.setInteger(MediaFormat.KEY_BIT_RATE, if (isWideband) 23850 else 12200)
            encFormat.setInteger(MediaFormat.KEY_CHANNEL_COUNT, 1)
            encFormat.setInteger(MediaFormat.KEY_SAMPLE_RATE, sampleRate)
            encoder = MediaCodec.createEncoderByType(mime).apply {
                configure(encFormat, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
                start()
            }
            isEncoderInitialized = true
            Log.i(TAG, "Initialized AMR encoder: mime=$mime rate=$sampleRate")
        } catch (e: Exception) {
            Log.w(TAG, "AMR encoder not supported/failed ($mime): ${e.message}")
        }

        try {
            val decFormat = MediaFormat.createAudioFormat(mime, sampleRate, 1)
            decFormat.setInteger(MediaFormat.KEY_CHANNEL_COUNT, 1)
            decFormat.setInteger(MediaFormat.KEY_SAMPLE_RATE, sampleRate)
            decoder = MediaCodec.createDecoderByType(mime).apply {
                configure(decFormat, null, null, 0)
                start()
            }
            isDecoderInitialized = true
            Log.i(TAG, "Initialized AMR decoder: mime=$mime rate=$sampleRate")
        } catch (e: Exception) {
            Log.w(TAG, "AMR decoder not supported/failed ($mime): ${e.message}")
        }
    }

    /**
     * Encodes 1 frame of linear PCM shorts into RFC 4867 octet-aligned AMR payload.
     * Returns CMR (0xF0) + AMR frame bytes, or null if encoding fails.
     */
    fun encodeFrame(pcm: ShortArray, offset: Int = 0, length: Int = samplesPerFrame): ByteArray? {
        val enc = encoder ?: return null
        if (!isEncoderInitialized) return null

        try {
            val inputIndex = enc.dequeueInputBuffer(2000L)
            if (inputIndex >= 0) {
                val inputBuffer = enc.getInputBuffer(inputIndex) ?: return null
                inputBuffer.clear()
                val byteCount = length * 2
                for (i in 0 until length) {
                    val s = pcm[offset + i]
                    inputBuffer.put((s.toInt() and 0xFF).toByte())
                    inputBuffer.put(((s.toInt() shr 8) and 0xFF).toByte())
                }
                enc.queueInputBuffer(inputIndex, 0, byteCount, 0, 0)
            }

            val bufferInfo = MediaCodec.BufferInfo()
            val outputIndex = enc.dequeueOutputBuffer(bufferInfo, 2000L)
            if (outputIndex >= 0) {
                val outputBuffer = enc.getOutputBuffer(outputIndex) ?: return null
                val frameData = ByteArray(bufferInfo.size)
                outputBuffer.position(bufferInfo.offset)
                outputBuffer.get(frameData)
                enc.releaseOutputBuffer(outputIndex, false)

                // RFC 4867 octet-aligned payload: CMR byte (0xF0) + AMR frame
                val rtpPayload = ByteArray(1 + frameData.size)
                rtpPayload[0] = CMR_NO_REQ
                System.arraycopy(frameData, 0, rtpPayload, 1, frameData.size)
                return rtpPayload
            }
        } catch (e: Exception) {
            Log.w(TAG, "encodeFrame error: ${e.message}")
        }
        return null
    }

    /**
     * Decodes an RFC 4867 AMR RTP payload into linear PCM shorts.
     * Handles octet-aligned payloads (CMR prefix).
     * Returns number of samples decoded into outPcm.
     */
    fun decodeFrame(amrPayload: ByteArray, offset: Int, length: Int, outPcm: ShortArray, outOffset: Int = 0): Int {
        val dec = decoder ?: return 0
        if (!isDecoderInitialized || length <= 0) return 0

        try {
            // Strip CMR byte if present
            val hasCmr = (amrPayload[offset].toInt() and 0x0F) == 0 && length > 1
            val dataOffset = if (hasCmr) offset + 1 else offset
            val dataLen = if (hasCmr) length - 1 else length

            val inputIndex = dec.dequeueInputBuffer(2000L)
            if (inputIndex >= 0) {
                val inputBuffer = dec.getInputBuffer(inputIndex) ?: return 0
                inputBuffer.clear()
                inputBuffer.put(amrPayload, dataOffset, dataLen)
                dec.queueInputBuffer(inputIndex, 0, dataLen, 0, 0)
            }

            val bufferInfo = MediaCodec.BufferInfo()
            val outputIndex = dec.dequeueOutputBuffer(bufferInfo, 2000L)
            if (outputIndex >= 0) {
                val outputBuffer = dec.getOutputBuffer(outputIndex) ?: return 0
                outputBuffer.position(bufferInfo.offset)
                val samplesDecoded = minOf(bufferInfo.size / 2, outPcm.size - outOffset)
                for (i in 0 until samplesDecoded) {
                    val low = outputBuffer.get().toInt() and 0xFF
                    val high = outputBuffer.get().toInt()
                    outPcm[outOffset + i] = ((high shl 8) or low).toShort()
                }
                dec.releaseOutputBuffer(outputIndex, false)
                return samplesDecoded
            }
        } catch (e: Exception) {
            Log.w(TAG, "decodeFrame error: ${e.message}")
        }
        return 0
    }

    fun release() {
        try {
            encoder?.stop()
            encoder?.release()
        } catch (_: Exception) {}
        try {
            decoder?.stop()
            decoder?.release()
        } catch (_: Exception) {}
        encoder = null
        decoder = null
        isEncoderInitialized = false
        isDecoderInitialized = false
    }
}
