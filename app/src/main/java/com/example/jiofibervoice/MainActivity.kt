package com.example.jiofibervoice

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.app.Activity
import java.net.Inet4Address
import java.net.NetworkInterface
import java.util.Collections

class MainActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var account: TextView
    private lateinit var otp: EditText
    private var gatewayIp: String? = null
    private var client: JioGatewayClient? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        status = findViewById(R.id.statusText)
        account = findViewById(R.id.accountText)
        otp = findViewById(R.id.otpEdit)

        findViewById<Button>(R.id.discoverButton).setOnClickListener { runAsync { discover() } }
        findViewById<Button>(R.id.requestOtpButton).setOnClickListener { runAsync { requestOtp() } }
        findViewById<Button>(R.id.verifyButton).setOnClickListener { runAsync { verifyOtp() } }
    }

    private fun discover() {
        val ip = findGateway() ?: error("Could not find an IPv4 default gateway. Connect to AirFiber Wi-Fi first.")
        gatewayIp = ip
        client = JioGatewayClient(this, ip)
        val r = client!!.requestAccount()
        val safeBody = r.body.replace(Regex("(\\\"(?:msisdn|imsi)\\\"\\s*:\\s*\\\")[^\\\"]+"), "$1<redacted>")
        post { account.text = "Gateway: $ip\\nHTTP ${r.status}\\n$safeBody"; status.text = "Discovered AirFiber gateway. App ID: ${client!!.clientMac}" }
    }

    private fun requestOtp() {
        val c = requireClient()
        val r = c.requestOtp()
        val number = r.headers["x-amn"]?.let { maskPhone(it) } ?: "not returned"
        post { status.text = "OTP request: HTTP ${r.status}\\nJio linked number: $number\\nCookie: ${if (c.cookie != null) "received" else "missing"}" }
    }

    private fun verifyOtp() {
        val c = requireClient()
        val r = c.verifyOtp(otp.text.toString().trim())
        if (r.body.contains("<wap-provisioningdoc", ignoreCase = true)) {
            val cfg = SipConfigParser.parse(r.body)
            post {
                status.text = "Provisioning received.\\nRealm: ${cfg.realm}\\nProxy: ${cfg.proxy}\\nUsername: ${cfg.username}\\nUUID: ${cfg.uuid}\\n\\nThis MVP stops here: SIP registration/audio are intentionally not enabled yet."
            }
        } else {
            post { status.text = "OTP response: HTTP ${r.status}\\n${r.body.take(2000)}" }
        }
    }

    private fun requireClient(): JioGatewayClient = client ?: error("Tap Discover first")

    private fun findGateway(): String? {
        val interfaces = Collections.list(NetworkInterface.getNetworkInterfaces())
        for (intf in interfaces) {
            val addresses = Collections.list(intf.inetAddresses)
            for (addr in addresses) {
                if (addr is Inet4Address && !addr.isLoopbackAddress) {
                    val bytes = addr.address
                    // Heuristic for a /24 home LAN. For a production app, read LinkProperties.getRoutes().
                    val candidate = "${bytes[0].toInt() and 0xff}.${bytes[1].toInt() and 0xff}.${bytes[2].toInt() and 0xff}.1"
                    try {
                        java.net.Socket().use { s -> s.connect(java.net.InetSocketAddress(candidate, 8080), 300) }
                        return candidate
                    } catch (_: Exception) { }
                }
            }
        }
        return null
    }

    private fun maskPhone(s: String): String = if (s.length <= 5) "<redacted>" else s.take(3) + "***" + s.takeLast(2)

    private fun runAsync(block: () -> Unit) {
        status.text = "Working..."
        Thread {
            try { block() } catch (e: Exception) { post { status.text = "Error: ${e.message}" } }
        }.start()
    }

    private fun post(block: () -> Unit) = runOnUiThread(block)
}
