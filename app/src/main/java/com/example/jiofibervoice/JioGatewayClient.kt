package com.example.jiofibervoice

import android.content.Context
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

class JioGatewayClient(private val context: Context, var gatewayIp: String) {
    private val prefs = context.getSharedPreferences("client", Context.MODE_PRIVATE)

    val clientMac: String
        get() = prefs.getString("client_mac", null) ?: run {
            val bytes = ByteArray(6).also { SecureRandom().nextBytes(it) }
            // Locally administered, unicast-looking identifier.
            bytes[0] = ((bytes[0].toInt() and 0xFC) or 0x02).toByte()
            val mac = bytes.joinToString(":") { "%02x".format(it) }
            prefs.edit().putString("client_mac", mac).apply()
            mac
        }

    fun resetAppIdentifier(): String {
        val bytes = ByteArray(6).also { SecureRandom().nextBytes(it) }
        bytes[0] = ((bytes[0].toInt() and 0xFC) or 0x02).toByte()
        val mac = bytes.joinToString(":") { "%02x".format(it) }
        prefs.edit().putString("client_mac", mac).remove("juice_cookie").apply()
        return mac
    }

    var cookie: String?
        get() = prefs.getString("juice_cookie", null)
        set(value) {
            if (value == null) {
                prefs.edit().remove("juice_cookie").apply()
            } else {
                prefs.edit().putString("juice_cookie", value).apply()
            }
        }

    data class HttpResponse(val status: Int, val headers: Map<String, String>, val body: String)

    fun requestAccount(): HttpResponse = httpPlain("GET", "/request_account")

    /**
     * Attempts to fetch SIP provisioning directly without sending OTP.
     * Works if the current MAC/app identifier has already been whitelisted on the router.
     */
    fun checkDirectProvisioning(noOtp: Boolean = false): HttpResponse {
        val params = linkedMapOf(
            "terminal_sw_version" to "RCSAndrd",
            "terminal_vendor" to "Android",
            "terminal_model" to "Android",
            "SMS_port" to "0",
            "act_type" to "volatile",
            "IMSI" to "",
            "msisdn" to "",
            "IMEI" to "",
            "vers" to "0",
            "token" to "",
            "rcs_state" to "0",
            "rcs_version" to "5.1B",
            "rcs_profile" to "joyn_blackbird",
            "client_vendor" to "JUIC",
            "default_sms_app" to "2",
            "default_vvm_app" to "0",
            "device_type" to "vvm",
            "client_version" to "JSEAndrd-1.0",
            "mac_address" to clientMac,
            "alias" to "JioFiberVoiceClient",
            "nwk_intf" to if (noOtp) "eth" else "wifi"
        )

        val query = params.entries.joinToString("&") {
            "${urlEncode(it.key)}=${urlEncode(it.value)}"
        }

        return httpsLocal(
            "GET",
            "/?$query",
            mapOf("User-Agent" to "JioFiberVoiceClient/1.0")
        )
    }

    /**
     * Initiates the OTP registration request against the local gateway HTTPS port.
     */
    fun requestOtp(noOtp: Boolean = false): HttpResponse {
        cookie = null
        val params = linkedMapOf(
            "IMEI" to "",
            "rcs_profile" to "joyn_blackbird",
            "SMS_port" to "0",
            "default_sms_app" to "2",
            "msisdn" to "",
            "rcs_state" to "0",
            "vers" to "0",
            "terminal_vendor" to "Android",
            "terminal_model" to "Android",
            "provisioning_version" to "2.0",
            "rcs_version" to "5.1B",
            "device_type" to "vvm",
            "act_type" to "volatile",
            "terminal_sw_version" to "RCSAndrd",
            "default_vvm_app" to "0",
            "IMSI" to "",
            "client_vendor" to "JUIC",
            "client_version" to "JSEAndrd-1.0",
            "token" to "",
            "alias" to "JioFiberVoiceClient",
            "mac_address" to clientMac,
            "nwk_intf" to if (noOtp) "eth" else "wifi",
            "op_type" to "add"
        )

        val query = params.entries.joinToString("&") {
            "${urlEncode(it.key)}=${urlEncode(it.value)}"
        }

        val response = httpsLocal(
            "GET",
            "/?$query",
            mapOf("User-Agent" to "JioFiberVoiceClient/1.0")
        )

        response.headers["set-cookie"]?.let { header ->
            val parts = header.split(";")
            val cookiePairs = parts.map { it.trim() }.filter {
                it.contains("=") &&
                !it.startsWith("path=", ignoreCase = true) &&
                !it.startsWith("expires=", ignoreCase = true) &&
                !it.startsWith("max-age=", ignoreCase = true) &&
                !it.startsWith("domain=", ignoreCase = true) &&
                !it.startsWith("samesite=", ignoreCase = true)
            }
            if (cookiePairs.isNotEmpty()) {
                cookie = cookiePairs.joinToString("; ")
            } else {
                val c = header.substringBefore(';').trim()
                if (c.isNotBlank()) cookie = c
            }
        }

        return response
    }

    fun verifyOtp(otp: String): HttpResponse {
        require(otp.matches(Regex("\\d{4,8}"))) { "OTP must be numeric" }
        val c = cookie ?: error("No OTP session cookie. Please request OTP first.")
        return httpsLocal("GET", "/?OTP=${urlEncode(otp)}", mapOf("Cookie" to c, "User-Agent" to "JioFiberVoiceClient/1.0"))
    }

    private fun httpPlain(method: String, path: String): HttpResponse {
        Socket().use { socket ->
            socket.connect(InetSocketAddress(gatewayIp, 8080), 4000)
            socket.soTimeout = 5000
            val req = buildString {
                append("$method $path HTTP/1.1\r\n")
                append("Host: $gatewayIp:8080\r\n")
                append("Connection: close\r\n\r\n")
            }
            socket.getOutputStream().write(req.toByteArray(Charsets.US_ASCII))
            return readHttp(socket)
        }
    }

    private fun httpsLocal(method: String, path: String, extra: Map<String, String>): HttpResponse {
        val socketFactory = insecureLocalSslFactory()
        val socket = socketFactory.createSocket() as SSLSocket
        socket.use { s ->
            s.connect(InetSocketAddress(gatewayIp, 8443), 6000)
            val params = s.sslParameters
            params.serverNames = listOf(javax.net.ssl.SNIHostName("jiofiber.local.html"))
            s.sslParameters = params
            s.soTimeout = 8000
            s.startHandshake()
            val req = buildString {
                append("$method $path HTTP/1.1\r\n")
                append("Host: jiofiber.local.html\r\n")
                append("Connection: close\r\n")
                extra.forEach { (k, v) -> append("$k: $v\r\n") }
                append("\r\n")
            }
            s.getOutputStream().write(req.toByteArray(Charsets.US_ASCII))
            return readHttp(s)
        }
    }

    private fun readHttp(socket: Socket): HttpResponse {
        val input = BufferedReader(InputStreamReader(socket.getInputStream(), Charsets.UTF_8))
        val statusLine = input.readLine() ?: error("Empty HTTP response")
        val status = statusLine.split(" ").getOrNull(1)?.toIntOrNull() ?: -1
        val headers = linkedMapOf<String, String>()
        val setCookieLines = mutableListOf<String>()
        while (true) {
            val line = input.readLine() ?: break
            if (line.isEmpty()) break
            val idx = line.indexOf(':')
            if (idx > 0) {
                val key = line.substring(0, idx).trim().lowercase()
                val value = line.substring(idx + 1).trim()
                if (key == "set-cookie") {
                    setCookieLines.add(value)
                } else {
                    headers[key] = value
                }
            }
        }
        if (setCookieLines.isNotEmpty()) {
            headers["set-cookie"] = setCookieLines.joinToString("; ")
        }
        val contentLength = headers["content-length"]?.toIntOrNull()
        val body = if (contentLength != null) {
            val chars = CharArray(contentLength)
            var read = 0
            while (read < contentLength) {
                val n = input.read(chars, read, contentLength - read)
                if (n < 0) break
                read += n
            }
            String(chars, 0, read)
        } else input.readText()
        return HttpResponse(status, headers, body)
    }

    private fun insecureLocalSslFactory(): SSLSocketFactory {
        val trustAll = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) = Unit
            override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) = Unit
            override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
        }
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, arrayOf<TrustManager>(trustAll), SecureRandom())
        return ctx.socketFactory
    }

    private fun urlEncode(value: String): String =
        java.net.URLEncoder.encode(value, Charsets.UTF_8.name())
}
