package com.example.jiofibervoice

/**
 * ITU-T G.711 standard audio codec implementation (A-law and mu-law).
 * Converts between 16-bit linear PCM (8000 Hz) and 8-bit G.711 companded audio.
 */
object G711Codec {

    // Precomputed tables for fast A-law and mu-law decoding
    private val aLawToPcmTable = ShortArray(256)
    private val uLawToPcmTable = ShortArray(256)

    init {
        for (i in 0..255) {
            aLawToPcmTable[i] = decodeAlawSample(i.toByte())
            uLawToPcmTable[i] = decodeUlawSample(i.toByte())
        }
    }

    /**
     * Converts a 16-bit PCM sample to 8-bit A-law byte.
     */
    fun linearToAlaw(sample: Short): Byte {
        var pcm = sample.toInt()
        var mask: Int
        var sign = 0

        if (pcm >= 0) {
            mask = 0xD5
        } else {
            mask = 0x55
            sign = 0x80
            pcm = -pcm - 1
            if (pcm < 0) pcm = 32767
        }

        val seg = if (pcm >= 256) {
            val s = (31 - Integer.numberOfLeadingZeros(pcm shr 4))
            if (s > 7) 7 else s
        } else {
            0
        }

        val aval = if (seg >= 1) {
            sign or (seg shl 4) or ((pcm shr (seg + 3)) and 0x0F)
        } else {
            sign or (pcm shr 4)
        }

        return (aval xor mask).toByte()
    }

    /**
     * Converts an 8-bit A-law byte to 16-bit PCM sample.
     */
    fun alawToLinear(alaw: Byte): Short {
        return aLawToPcmTable[alaw.toInt() and 0xFF]
    }

    private fun decodeAlawSample(alaw: Byte): Short {
        var a = alaw.toInt() xor 0x55
        var sign = a and 0x80
        val seg = (a and 0x70) shr 4
        var pcm = (a and 0x0F) shl 4

        pcm = if (seg == 0) {
            pcm + 8
        } else {
            (pcm or 0x100) shl (seg - 1)
        }

        return (if (sign != 0) pcm else -pcm).toShort()
    }

    /**
     * Converts a 16-bit PCM sample to 8-bit mu-law byte.
     */
    fun linearToUlaw(sample: Short): Byte {
        val bias = 0x84
        val clip = 32635

        var pcm = sample.toInt()
        val sign = (pcm shr 8) and 0x80
        if (sign != 0) pcm = -pcm

        if (pcm > clip) pcm = clip
        pcm += bias

        var exponent = 7
        var expMask = 0x4000
        while ((pcm and expMask) == 0 && exponent > 0) {
            exponent--
            expMask = expMask shr 1
        }

        val mantissa = (pcm shr (exponent + 3)) and 0x0F
        val ulaw = sign or (exponent shl 4) or mantissa
        return (ulaw xor 0xFF).toByte()
    }

    /**
     * Converts an 8-bit mu-law byte to 16-bit PCM sample.
     */
    fun ulawToLinear(ulaw: Byte): Short {
        return uLawToPcmTable[ulaw.toInt() and 0xFF]
    }

    private fun decodeUlawSample(ulaw: Byte): Short {
        val u = (ulaw.toInt() and 0xFF) xor 0xFF
        val sign = u and 0x80
        val exponent = (u shr 4) and 0x07
        val mantissa = u and 0x0F
        var pcm = (mantissa shl 3) + 0x84
        pcm = pcm shl exponent
        pcm -= 0x84
        return (if (sign != 0) -pcm else pcm).toShort()
    }

    fun pcmToAlaw(pcm: ShortArray, alaw: ByteArray, length: Int) {
        for (i in 0 until length) {
            alaw[i] = linearToAlaw(pcm[i])
        }
    }

    fun alawToPcm(alaw: ByteArray, pcm: ShortArray, length: Int) {
        for (i in 0 until length) {
            pcm[i] = alawToLinear(alaw[i])
        }
    }

    fun pcmToUlaw(pcm: ShortArray, ulaw: ByteArray, length: Int) {
        for (i in 0 until length) {
            ulaw[i] = linearToUlaw(pcm[i])
        }
    }

    fun ulawToPcm(ulaw: ByteArray, pcm: ShortArray, length: Int) {
        for (i in 0 until length) {
            pcm[i] = ulawToLinear(ulaw[i])
        }
    }
}
