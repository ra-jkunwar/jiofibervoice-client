package com.example.jiofibervoice

import java.util.Locale

/**
 * Representation and parser for RFC 3261 SIP messages and SDP bodies.
 */
data class SipMessage(
    val startLine: String,
    val headers: Map<String, String>,
    val body: String = ""
) {
    val isResponse: Boolean
        get() = startLine.startsWith("SIP/2.0")

    val isRequest: Boolean
        get() = !isResponse

    val statusCode: Int
        get() = if (isResponse) {
            startLine.split(" ").getOrNull(1)?.toIntOrNull() ?: 0
        } else 0

    val reasonPhrase: String
        get() = if (isResponse) {
            val parts = startLine.split(" ")
            if (parts.size >= 3) parts.subList(2, parts.size).joinToString(" ") else ""
        } else ""

    val method: String
        get() = if (isRequest) {
            startLine.split(" ").firstOrNull() ?: ""
        } else {
            cseqMethod
        }

    val uri: String
        get() = if (isRequest) {
            startLine.split(" ").getOrNull(1) ?: ""
        } else ""

    fun header(name: String): String? {
        val lower = name.lowercase(Locale.ROOT)
        return headers[lower]
    }

    val callId: String
        get() = header("Call-ID") ?: header("i") ?: ""

    val cseq: String
        get() = header("CSeq") ?: ""

    val cseqNumber: Long
        get() = cseq.trim().split(" ").firstOrNull()?.toLongOrNull() ?: 0L

    val cseqMethod: String
        get() = cseq.trim().split(" ").getOrNull(1)?.uppercase(Locale.ROOT) ?: ""

    val from: String
        get() = header("From") ?: header("f") ?: ""

    val fromTag: String?
        get() = extractParameter(from, "tag")

    val to: String
        get() = header("To") ?: header("t") ?: ""

    val toTag: String?
        get() = extractParameter(to, "tag")

    val via: String
        get() = header("Via") ?: header("v") ?: ""

    val viaBranch: String?
        get() = extractParameter(via, "branch")

    val contact: String?
        get() = header("Contact") ?: header("m")

    val contentType: String?
        get() = header("Content-Type") ?: header("c")

    val contentLength: Int
        get() = (header("Content-Length") ?: header("l"))?.toIntOrNull() ?: body.toByteArray(Charsets.UTF_8).size

    // Extract SDP audio parameters
    val sdpAudioIp: String?
        get() {
            val match = Regex("""c=IN\s+IP4\s+([0-9.]+)""", RegexOption.IGNORE_CASE).find(body)
            return match?.groupValues?.get(1)
        }

    val sdpAudioPort: Int?
        get() {
            val match = Regex("""m=audio\s+(\d+)\s+""", RegexOption.IGNORE_CASE).find(body)
            return match?.groupValues?.get(1)?.toIntOrNull()
        }

    fun toWireString(): String {
        return buildString {
            append(startLine).append("\r\n")
            headers.forEach { (name, value) ->
                // Capitalize standard header names nicely
                val formattedName = formatHeaderName(name)
                append("$formattedName: $value\r\n")
            }
            append("\r\n")
            if (body.isNotEmpty()) {
                append(body)
            }
        }
    }

    companion object {
        fun parse(raw: String): SipMessage {
            val parts = raw.split("\r\n\r\n", limit = 2)
            val headerPart = parts[0]
            val body = if (parts.size > 1) parts[1] else ""

            val lines = headerPart.split("\r\n")
            val startLine = lines.firstOrNull()?.trim() ?: ""

            val headers = linkedMapOf<String, String>()
            var currentHeader: String? = null

            for (i in 1 until lines.size) {
                val line = lines[i]
                if (line.startsWith(" ") || line.startsWith("\t")) {
                    // Header continuation
                    currentHeader?.let { h ->
                        headers[h] = (headers[h] ?: "") + " " + line.trim()
                    }
                } else {
                    val idx = line.indexOf(':')
                    if (idx > 0) {
                        val name = line.substring(0, idx).trim().lowercase(Locale.ROOT)
                        val value = line.substring(idx + 1).trim()
                        headers[name] = value
                        currentHeader = name
                    }
                }
            }

            return SipMessage(startLine, headers, body)
        }

        private fun extractParameter(headerValue: String, paramName: String): String? {
            val match = Regex(""";\s*${paramName}=([^;>\s]+)""", RegexOption.IGNORE_CASE).find(headerValue)
            return match?.groupValues?.get(1)
        }

        private fun formatHeaderName(raw: String): String {
            return when (raw.lowercase(Locale.ROOT)) {
                "call-id", "i" -> "Call-ID"
                "cseq" -> "CSeq"
                "from", "f" -> "From"
                "to", "t" -> "To"
                "via", "v" -> "Via"
                "contact", "m" -> "Contact"
                "content-type", "c" -> "Content-Type"
                "content-length", "l" -> "Content-Length"
                "user-agent" -> "User-Agent"
                "max-forwards" -> "Max-Forwards"
                "route" -> "Route"
                "record-route" -> "Record-Route"
                "p-preferred-identity" -> "P-Preferred-Identity"
                "p-asserted-identity" -> "P-Asserted-Identity"
                "authorization" -> "Authorization"
                "proxy-authorization" -> "Proxy-Authorization"
                "www-authenticate" -> "WWW-Authenticate"
                "proxy-authenticate" -> "Proxy-Authenticate"
                "allow" -> "Allow"
                "supported" -> "Supported"
                "expires" -> "Expires"
                else -> raw.split("-").joinToString("-") { it.replaceFirstChar { c -> c.uppercase() } }
            }
        }
    }
}
