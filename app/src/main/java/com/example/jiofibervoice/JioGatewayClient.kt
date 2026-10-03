package com.example.jiofibervoice

import android.content.Context
import android.os.Build
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
            // Locally administered, unicast identifier (e.g. 02:xx:xx:xx:xx:xx)
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

    data class HttpResponse(
        val status: Int,
        val headers: Map<String, String>,
        val rawHeaderLines: List<String>,
        val body: String
    )

    fun requestAccount(): HttpResponse = httpPlain("GET", "/request_account")

    private fun getSanitizedDeviceName(): String {
        val raw = Build.MODEL.ifBlank { "android" }
        val clean = raw.replace(Regex("[^a-zA-Z0-9]"), "")
        return clean.take(16).ifEmpty { "android" }
    }

    /**
     * Builds WITS query matching Discussion #70 reference implementation:
     * This vendor returns "Set-Cookie: WITRCSeConfigCookie=<uuid>" and "x-amn: <number>".
     */
    private fun buildWitsQuery(opTypeAdd: Boolean, isEth: Boolean): String {
        val nwk = if (isEth) "eth" else "wifi"
        val params = linkedMapOf(
            "IMEI" to "",
            "rcs_profile" to "joyn_blackbird",
            "SMS_port" to "0",
            "default_sms_app" to "1",
            "msisdn" to "",
            "rcs_state" to "0",
            "vers" to "0",
            "terminal_vendor" to "sams",
            "terminal_model" to "aosp",
            "provisioning_version" to "2.0",
            "rcs_version" to "5.1B",
            "device_type" to "vvm",
            "act_type" to "volatile",
            "terminal_sw_version" to "7.1.2",
            "default_vvm_app" to "0",
            "IMSI" to "",
            "client_vendor" to "WITS",
            "client_version" to "RCSAndrd-5.3",
            "alias" to "itsyourap",
            "mac_address" to clientMac,
            "nwk_intf" to nwk
        )
        if (opTypeAdd) {
            params["op_type"] = "add"
        }
        return params.entries.joinToString("&", postfix = "&") { "${it.key}=${it.value}" }
    }

    /**
     * Builds JUIC query matching JioJoin native app / STB implementation:
     */
    private fun buildJuicQuery(opTypeAdd: Boolean, isEth: Boolean): String {
        val hostname = getSanitizedDeviceName()
        val nwk = if (isEth) "eth" else "wifi"
        val params = linkedMapOf(
            "terminal_sw_version" to "RCSAndrd",
            "terminal_vendor" to hostname,
            "terminal_model" to hostname,
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
            "alias" to hostname,
            "nwk_intf" to nwk
        )
        if (opTypeAdd) {
            params["op_type"] = "add"
        }
        return params.entries.joinToString("&", postfix = "&") { "${it.key}=${it.value}" }
    }

    /**
     * Attempts to fetch SIP provisioning directly without sending OTP.
     * Tries STB bypass (nwk_intf=eth) using both WITS and JUIC formats.
     * Jio ONTs return the XML provisioning document for STBs without requiring OTP.
     */
    fun checkDirectProvisioning(useEthBypass: Boolean = true): HttpResponse {
        if (useEthBypass) {
            // Attempt 1: WITS eth query
            val witsEth = buildWitsQuery(opTypeAdd = false, isEth = true)
            val r1 = httpsLocal("GET", "/?$witsEth", emptyMap())
            if (r1.body.contains("<wap-provisioningdoc", ignoreCase = true)) {
                return r1
            }

            // Attempt 2: JUIC eth query
            val juicEth = buildJuicQuery(opTypeAdd = false, isEth = true)
            val r2 = httpsLocal("GET", "/?$juicEth", emptyMap())
            if (r2.body.contains("<wap-provisioningdoc", ignoreCase = true)) {
                return r2
            }
        }

        // Fallback: check if already whitelisted via wifi query
        val wifiQuery = buildWitsQuery(opTypeAdd = false, isEth = false)
        val rWifi = httpsLocal("GET", "/?$wifiQuery", emptyMap())
        if (rWifi.body.contains("<wap-provisioningdoc", ignoreCase = true)) {
            return rWifi
        }
        val juicWifi = buildJuicQuery(opTypeAdd = false, isEth = false)
        return httpsLocal("GET", "/?$juicWifi", emptyMap())
    }

    /**
     * Initiates the OTP registration request against the local gateway HTTPS port.
     * Uses client_vendor=WITS first to trigger generation of WITRCSeConfigCookie.
     * Extracts and persists WITRCSeConfigCookie for OTP verification.
     */
    fun requestOtp(): HttpResponse {
        cookie = null

        // 1. Try WITS flow (primary reference flow from Discussion #70)
        val witsQuery = buildWitsQuery(opTypeAdd = true, isEth = false)
        var response = httpsLocal("GET", "/?$witsQuery", emptyMap())

        extractAndSaveCookie(response)

        // 2. If cookie was not obtained with WITS and response was not successful, try JUIC flow
        if (cookie == null && response.status != 200) {
            val juicQuery = buildJuicQuery(opTypeAdd = true, isEth = false)
            val juicResp = httpsLocal("GET", "/?$juicQuery", emptyMap())
            extractAndSaveCookie(juicResp)
            if (cookie != null || juicResp.status == 200) {
                response = juicResp
            }
        }

        return response
    }

    private fun extractAndSaveCookie(response: HttpResponse) {
        val allHeadersText = response.rawHeaderLines.joinToString("\n") + "\n" + (response.headers["set-cookie"] ?: "")
        val witMatch = Regex("""WITRCSeConfigCookie=([^;\r\n\s]+)""", RegexOption.IGNORE_CASE).find(allHeadersText)
        if (witMatch != null) {
            val token = witMatch.groupValues[1]
            cookie = "WITRCSeConfigCookie=$token"
        } else {
            response.headers["set-cookie"]?.let { header ->
                val firstPart = header.substringBefore(';').trim()
                if (firstPart.contains('=')) {
                    cookie = firstPart
                }
            }
        }
    }

    /**
     * Verifies the OTP sent to user's mobile.
     * Strictly requires a valid OTP session cookie.
     */
    fun verifyOtp(otp: String): HttpResponse {
        require(otp.matches(Regex("""\d{4,8}"""))) { "OTP must be numeric" }
        val currentCookie = cookie ?: error("No OTP session cookie. Please request OTP first.")

        val headers = mapOf("Cookie" to currentCookie)

        // Attempt 1: Standard JioJoin / JFC verify: GET /?OTP=<otp> with Cookie
        val r1 = httpsLocal("GET", "/?OTP=$otp", headers)
        if (r1.body.contains("<wap-provisioningdoc", ignoreCase = true)) {
            return r1
        }

        // Attempt 2: Fallback with mac_address: GET /?OTP=<otp>&mac_address=<mac> with Cookie
        val r2 = httpsLocal("GET", "/?OTP=$otp&mac_address=$clientMac", headers)
        if (r2.body.contains("<wap-provisioningdoc", ignoreCase = true)) {
            return r2
        }

        return if (r1.status == 200 && r1.body.isNotEmpty()) r1 else r2
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
        // Try port 8443 first (JioFiber standard SSL port), fallback to 7443 (JioJoin REST port)
        val ports = listOf(8443, 7443)
        var lastException: Exception? = null

        for (port in ports) {
            try {
                val socketFactory = insecureLocalSslFactory()
                val socket = socketFactory.createSocket() as SSLSocket
                socket.use { s ->
                    s.connect(InetSocketAddress(gatewayIp, port), 6000)
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
            } catch (e: Exception) {
                lastException = e
            }
        }
        throw (lastException ?: RuntimeException("Failed to connect to gateway HTTPS"))
    }

    private fun readHttp(socket: Socket): HttpResponse {
        val input = BufferedReader(InputStreamReader(socket.getInputStream(), Charsets.UTF_8))
        val statusLine = input.readLine() ?: error("Empty HTTP response")
        val status = statusLine.split(" ").getOrNull(1)?.toIntOrNull() ?: -1
        val headers = linkedMapOf<String, String>()
        val rawHeaderLines = mutableListOf<String>()
        val setCookieLines = mutableListOf<String>()
        while (true) {
            val line = input.readLine() ?: break
            if (line.isEmpty()) break
            rawHeaderLines.add(line)
            val idx = line.indexOf(':')
            if (idx > 0) {
                val key = line.substring(0, idx).trim().lowercase()
                val value = line.substring(idx + 1).trim()
                if (key == "set-cookie") {
                    setCookieLines.add(value)
                }
                if (!headers.containsKey(key)) {
                    headers[key] = value
                } else if (key == "set-cookie") {
                    headers[key] = headers[key] + "; " + value
                }
            }
        }
        if (setCookieLines.isNotEmpty() && !headers.containsKey("set-cookie")) {
            headers["set-cookie"] = setCookieLines.joinToString("; ")
        }
        val contentLength = headers["content-length"]?.toIntOrNull()
        val isChunked = headers["transfer-encoding"]?.contains("chunked", ignoreCase = true) == true

        val body = try {
            when {
                contentLength != null && contentLength >= 0 -> {
                    val chars = CharArray(contentLength)
                    var read = 0
                    while (read < contentLength) {
                        val n = input.read(chars, read, contentLength - read)
                        if (n < 0) break
                        read += n
                    }
                    String(chars, 0, read)
                }
                isChunked -> {
                    readChunkedBody(input)
                }
                else -> {
                    // Read until EOF
                    input.readText()
                }
            }
        } catch (e: Exception) {
            ""
        }
        return HttpResponse(status, headers, rawHeaderLines, body)
    }

    private fun readChunkedBody(input: BufferedReader): String {
        val sb = StringBuilder()
        while (true) {
            val line = input.readLine() ?: break
            val trimmed = line.trim()
            if (trimmed.isEmpty()) continue
            val chunkSize = trimmed.split(";")[0].trim().toIntOrNull(16) ?: break
            if (chunkSize <= 0) break
            val chars = CharArray(chunkSize)
            var read = 0
            while (read < chunkSize) {
                val n = input.read(chars, read, chunkSize - read)
                if (n < 0) break
                read += n
            }
            sb.append(chars, 0, read)
            input.readLine() // consume trailing CRLF
        }
        return sb.toString()
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
}
