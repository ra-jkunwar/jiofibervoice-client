package com.example.jiofibervoice

import android.Manifest
import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ScrollView
import android.widget.TextView
import java.net.Inet4Address
import java.net.NetworkInterface
import java.util.Collections
import java.util.Locale

class MainActivity : Activity(), SipEngine.SipEventListener {

    // Views
    private lateinit var topStatusBadge: TextView
    private lateinit var tabDialerBtn: Button
    private lateinit var tabSettingsBtn: Button
    private lateinit var tabLogsBtn: Button

    private lateinit var viewDialer: View
    private lateinit var viewSettings: View
    private lateinit var viewLogs: View

    // Dialer views
    private lateinit var dialNumberEdit: EditText
    private lateinit var btnBackspace: Button
    private lateinit var btnCall: Button
    private lateinit var dialerStatusHint: TextView

    // Active call views
    private lateinit var activeCallCard: View
    private lateinit var activeCallStateText: TextView
    private lateinit var activeCallRemoteText: TextView
    private lateinit var activeCallTimerText: TextView
    private lateinit var btnMute: Button
    private lateinit var btnSpeaker: Button
    private lateinit var btnHangUp: Button

    // Incoming call views
    private lateinit var incomingCallCard: View
    private lateinit var incomingCallerText: TextView
    private lateinit var btnAnswerCall: Button
    private lateinit var btnDeclineCall: Button

    // Settings views
    private lateinit var gatewayIpEdit: EditText
    private lateinit var btnDiscoverGw: Button
    private lateinit var macInfoText: TextView
    private lateinit var btnCheckDirect: Button
    private lateinit var btnRequestOtp: Button
    private lateinit var otpResultText: TextView
    private lateinit var otpInputEdit: EditText
    private lateinit var btnVerifyOtp: Button
    private lateinit var accountSummaryText: TextView
    private lateinit var btnRegisterSip: Button
    private lateinit var btnUnregisterSip: Button
    private lateinit var btnClearAccount: Button

    // Logs views
    private lateinit var sipLogsText: TextView
    private lateinit var btnClearLogs: Button
    private lateinit var logsScrollView: ScrollView

    // Logic & Services
    private var gatewayClient: JioGatewayClient? = null
    private var sipService: SipService? = null
    private var isServiceBound = false

    private val mainHandler = Handler(Looper.getMainLooper())
    private var callStartTimeMs = 0L
    private val callTimerRunnable = object : Runnable {
        override fun run() {
            if (callStartTimeMs > 0L) {
                val elapsedSec = (System.currentTimeMillis() - callStartTimeMs) / 1000
                val mins = elapsedSec / 60
                val secs = elapsedSec % 60
                activeCallTimerText.text = String.format(Locale.ROOT, "%02d:%02d", mins, secs)
                mainHandler.postDelayed(this, 1000L)
            }
        }
    }

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            val binder = service as? SipService.LocalBinder
            sipService = binder?.service
            isServiceBound = true
            sipService?.sipEngine?.let { engine ->
                engine.listener = this@MainActivity
                updateUiForStates(engine.registrationState, engine.callState)
            }
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            isServiceBound = false
            sipService = null
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        initViews()
        setupListeners()
        requestAppPermissions()

        val gwIp = gatewayIpEdit.text.toString().trim()
        gatewayClient = JioGatewayClient(this, gwIp)
        macInfoText.text = "Client App ID (MAC): ${gatewayClient!!.clientMac}"

        refreshStoredAccountSummary()
        bindSipService()
        updateVerifyButtonState()

        // Auto-discover gateway if not already set
        Thread {
            val discovered = findGateway()
            if (discovered != null) {
                runOnUiThread {
                    gatewayIpEdit.setText(discovered)
                    gatewayClient?.gatewayIp = discovered
                }
            }
        }.start()
    }

    private fun initViews() {
        topStatusBadge = findViewById(R.id.topStatusBadge)
        tabDialerBtn = findViewById(R.id.tabDialerBtn)
        tabSettingsBtn = findViewById(R.id.tabSettingsBtn)
        tabLogsBtn = findViewById(R.id.tabLogsBtn)

        viewDialer = findViewById(R.id.viewDialer)
        viewSettings = findViewById(R.id.viewSettings)
        viewLogs = findViewById(R.id.viewLogs)

        dialNumberEdit = findViewById(R.id.dialNumberEdit)
        btnBackspace = findViewById(R.id.btnBackspace)
        btnCall = findViewById(R.id.btnCall)
        dialerStatusHint = findViewById(R.id.dialerStatusHint)

        activeCallCard = findViewById(R.id.activeCallCard)
        activeCallStateText = findViewById(R.id.activeCallStateText)
        activeCallRemoteText = findViewById(R.id.activeCallRemoteText)
        activeCallTimerText = findViewById(R.id.activeCallTimerText)
        btnMute = findViewById(R.id.btnMute)
        btnSpeaker = findViewById(R.id.btnSpeaker)
        btnHangUp = findViewById(R.id.btnHangUp)

        incomingCallCard = findViewById(R.id.incomingCallCard)
        incomingCallerText = findViewById(R.id.incomingCallerText)
        btnAnswerCall = findViewById(R.id.btnAnswerCall)
        btnDeclineCall = findViewById(R.id.btnDeclineCall)

        gatewayIpEdit = findViewById(R.id.gatewayIpEdit)
        btnDiscoverGw = findViewById(R.id.btnDiscoverGw)
        macInfoText = findViewById(R.id.macInfoText)
        btnCheckDirect = findViewById(R.id.btnCheckDirect)
        btnRequestOtp = findViewById(R.id.btnRequestOtp)
        otpResultText = findViewById(R.id.otpResultText)
        otpInputEdit = findViewById(R.id.otpInputEdit)
        btnVerifyOtp = findViewById(R.id.btnVerifyOtp)
        accountSummaryText = findViewById(R.id.accountSummaryText)
        btnRegisterSip = findViewById(R.id.btnRegisterSip)
        btnUnregisterSip = findViewById(R.id.btnUnregisterSip)
        btnClearAccount = findViewById(R.id.btnClearAccount)

        sipLogsText = findViewById(R.id.sipLogsText)
        btnClearLogs = findViewById(R.id.btnClearLogs)
        logsScrollView = findViewById(R.id.logsScrollView)
    }

    private fun setupListeners() {
        // Tab switching
        tabDialerBtn.setOnClickListener { switchTab(0) }
        tabSettingsBtn.setOnClickListener { switchTab(1) }
        tabLogsBtn.setOnClickListener { switchTab(2) }

        // Dialpad keys
        val keyMap = mapOf(
            R.id.key1 to '1', R.id.key2 to '2', R.id.key3 to '3',
            R.id.key4 to '4', R.id.key5 to '5', R.id.key6 to '6',
            R.id.key7 to '7', R.id.key8 to '8', R.id.key9 to '9',
            R.id.keyStar to '*', R.id.key0 to '0', R.id.keyHash to '#'
        )

        for ((id, char) in keyMap) {
            findViewById<Button>(id).setOnClickListener {
                if (activeCallCard.visibility == View.VISIBLE) {
                    // Send DTMF in call
                    sipService?.sipEngine?.sendDtmf(char)
                }
                appendDialDigit(char.toString())
            }
        }

        findViewById<Button>(R.id.key0).setOnLongClickListener {
            appendDialDigit("+")
            true
        }

        btnBackspace.setOnClickListener {
            val text = dialNumberEdit.text.toString()
            if (text.isNotEmpty()) {
                dialNumberEdit.setText(text.dropLast(1))
                dialNumberEdit.setSelection(dialNumberEdit.text.length)
            }
        }

        btnBackspace.setOnLongClickListener {
            dialNumberEdit.setText("")
            true
        }

        btnCall.setOnClickListener {
            val number = dialNumberEdit.text.toString().trim()
            if (number.isNotEmpty()) {
                val engine = sipService?.sipEngine
                if (engine == null || engine.registrationState != SipEngine.RegistrationState.REGISTERED) {
                    // Try auto-connecting if configured
                    val cfg = SipConfig.loadFromPrefs(this)
                    if (cfg != null) {
                        engine?.start(cfg)
                    }
                }
                sipService?.sipEngine?.makeCall(number)
            }
        }

        // Active call buttons
        btnMute.setOnClickListener {
            val rtp = sipService?.sipEngine?.rtpEngine ?: return@setOnClickListener
            rtp.isMuted = !rtp.isMuted
            btnMute.text = if (rtp.isMuted) "Unmute" else "Mute"
            btnMute.setBackgroundColor(if (rtp.isMuted) Color.parseColor("#F59E0B") else Color.parseColor("#E5E7EB"))
        }

        btnSpeaker.setOnClickListener {
            val rtp = sipService?.sipEngine?.rtpEngine ?: return@setOnClickListener
            rtp.isSpeakerOn = !rtp.isSpeakerOn
            btnSpeaker.text = if (rtp.isSpeakerOn) "Earpiece" else "Speaker"
            btnSpeaker.setBackgroundColor(if (rtp.isSpeakerOn) Color.parseColor("#3B82F6") else Color.parseColor("#E5E7EB"))
        }

        btnHangUp.setOnClickListener {
            sipService?.sipEngine?.endCall()
        }

        btnAnswerCall.setOnClickListener {
            sipService?.sipEngine?.answerCall()
        }

        btnDeclineCall.setOnClickListener {
            sipService?.sipEngine?.declineCall()
        }

        // Gateway & Pairing
        btnDiscoverGw.setOnClickListener {
            btnDiscoverGw.isEnabled = false
            btnDiscoverGw.text = "Scanning..."
            Thread {
                val ip = findGateway() ?: "192.168.29.1"
                runOnUiThread {
                    gatewayIpEdit.setText(ip)
                    gatewayClient?.gatewayIp = ip
                    btnDiscoverGw.isEnabled = true
                    btnDiscoverGw.text = "Auto-Detect"
                    otpResultText.text = "Gateway detected: $ip"
                }
            }.start()
        }

        macInfoText.setOnClickListener {
            val newMac = gatewayClient?.resetAppIdentifier()
            updateVerifyButtonState()
            macInfoText.text = "Client App ID (MAC): $newMac"
            otpResultText.setTextColor(Color.parseColor("#4B5563"))
            otpResultText.text = "Regenerated App ID: $newMac"
        }

        btnCheckDirect.setOnClickListener {
            updateGatewayIpFromEdit()
            otpResultText.setTextColor(Color.parseColor("#1D4ED8"))
            otpResultText.text = "Checking router whitelist..."
            Thread {
                try {
                    val client = gatewayClient ?: return@Thread
                    val r = client.checkDirectProvisioning(noOtp = false)
                    if (r.body.contains("<wap-provisioningdoc", ignoreCase = true)) {
                        val cfg = SipConfigParser.parse(r.body, client.gatewayIp)
                        cfg.saveToPrefs(this@MainActivity)
                        runOnUiThread {
                            otpResultText.setTextColor(Color.parseColor("#059669"))
                            otpResultText.text = "Success! Whitelist matched without OTP."
                            refreshStoredAccountSummary()
                            startSipRegistration(cfg)
                            updateVerifyButtonState()
                        }
                    } else {
                        runOnUiThread {
                            otpResultText.setTextColor(Color.parseColor("#4B5563"))
                            otpResultText.text = "Device not whitelisted (HTTP ${r.status}). Tap 'Send SMS OTP'."
                            updateVerifyButtonState()
                        }
                    }
                } catch (e: Exception) {
                    runOnUiThread {
                        otpResultText.setTextColor(Color.parseColor("#DC2626"))
                        otpResultText.text = "Check error: ${e.message}"
                        updateVerifyButtonState()
                    }
                }
            }.start()
        }

        btnRequestOtp.setOnClickListener {
            updateGatewayIpFromEdit()
            otpResultText.setTextColor(Color.parseColor("#1D4ED8"))
            otpResultText.text = "Requesting OTP from gateway..."
            btnRequestOtp.isEnabled = false
            gatewayClient?.cookie = null
            updateVerifyButtonState()

            Thread {
                try {
                    val client = gatewayClient ?: return@Thread
                    val r = client.requestOtp(noOtp = false)
                    val status = r.status
                    val hasCookie = !client.cookie.isNullOrBlank()
                    val cookieStr = if (hasCookie) "PRESENT (${client.cookie})" else "ABSENT"
                    val linkedNumber = r.headers["x-amn"] ?: "ABSENT"
                    val isSuccess = (status == 200 && hasCookie)

                    appendLog("[GATEWAY] OTP Request -> HTTP $status | Cookie: $cookieStr | Linked: $linkedNumber")
                    if (r.rawHeaderLines.isNotEmpty()) {
                        appendLog("[GATEWAY] Headers received:\n" + r.rawHeaderLines.joinToString("\n"))
                    }

                    val msg = buildString {
                        append("OTP HTTP: ").append(status).append("\n")
                        append("Cookie: ").append(cookieStr).append("\n")
                        append("Linked number: ").append(linkedNumber)
                        if (!isSuccess) {
                            if (r.rawHeaderLines.isNotEmpty()) {
                                append("\nHeaders:\n")
                                for (hl in r.rawHeaderLines.take(5)) {
                                    append("  ").append(hl).append("\n")
                                }
                            }
                            val trimmedBody = r.body.trim()
                            if (trimmedBody.isNotEmpty()) {
                                append("Body: ").append(trimmedBody.take(400))
                                if (trimmedBody.length > 400) append("...")
                            } else {
                                append("Body: (empty)")
                            }
                        }
                    }

                    runOnUiThread {
                        otpResultText.setTextColor(if (isSuccess) Color.parseColor("#059669") else Color.parseColor("#DC2626"))
                        otpResultText.text = msg
                        btnRequestOtp.isEnabled = true
                        updateVerifyButtonState()
                    }
                } catch (e: Exception) {
                    val errorMsg = e.message ?: e.javaClass.simpleName
                    appendLog("[GATEWAY] OTP Request Exception: $errorMsg")
                    runOnUiThread {
                        otpResultText.setTextColor(Color.parseColor("#DC2626"))
                        otpResultText.text = "OTP HTTP: ERROR\nCookie: ABSENT\nLinked number: ABSENT\nBody: $errorMsg"
                        btnRequestOtp.isEnabled = true
                        updateVerifyButtonState()
                    }
                }
            }.start()
        }

        btnVerifyOtp.setOnClickListener {
            updateGatewayIpFromEdit()
            val otp = otpInputEdit.text.toString().trim()
            if (otp.isEmpty()) {
                otpResultText.setTextColor(Color.parseColor("#DC2626"))
                otpResultText.text = "Please enter the OTP"
                return@setOnClickListener
            }
            if (gatewayClient?.cookie.isNullOrBlank()) {
                otpResultText.setTextColor(Color.parseColor("#DC2626"))
                otpResultText.text = "No OTP session cookie. Please request OTP first."
                updateVerifyButtonState()
                return@setOnClickListener
            }
            otpResultText.setTextColor(Color.parseColor("#1D4ED8"))
            otpResultText.text = "Verifying OTP ($otp)..."
            btnVerifyOtp.isEnabled = false

            Thread {
                try {
                    val client = gatewayClient ?: return@Thread
                    appendLog("[GATEWAY] Sending OTP verification for $otp with Cookie: ${client.cookie}")
                    val r = client.verifyOtp(otp)
                    appendLog("[GATEWAY] Verify response HTTP ${r.status}, body length=${r.body.length}")
                    if (r.rawHeaderLines.isNotEmpty()) {
                        appendLog("[GATEWAY] Verify headers:\n" + r.rawHeaderLines.joinToString("\n"))
                    }

                    if (r.body.contains("<wap-provisioningdoc", ignoreCase = true)) {
                        val cfg = SipConfigParser.parse(r.body, client.gatewayIp)
                        cfg.saveToPrefs(this@MainActivity)
                        appendLog("[GATEWAY] Successfully parsed and saved SIP config for +${cfg.cleanUsername}")
                        runOnUiThread {
                            otpResultText.setTextColor(Color.parseColor("#059669"))
                            otpResultText.text = "OTP verified! Stored profile for +${cfg.cleanUsername}."
                            updateVerifyButtonState()
                            refreshStoredAccountSummary()
                            startSipRegistration(cfg)
                            switchTab(0)
                        }
                    } else {
                        val trimmedBody = r.body.trim()
                        val bodySnippet = if (trimmedBody.isNotEmpty()) "\nBody: ${trimmedBody.take(300)}" else ""
                        appendLog("[GATEWAY] OTP verification failed: HTTP ${r.status}\n$trimmedBody")
                        runOnUiThread {
                            otpResultText.setTextColor(Color.parseColor("#DC2626"))
                            otpResultText.text = "Verification failed: HTTP ${r.status}$bodySnippet"
                            updateVerifyButtonState()
                        }
                    }
                } catch (e: Exception) {
                    val errorMsg = e.message ?: e.javaClass.simpleName
                    appendLog("[GATEWAY] OTP verification error: $errorMsg")
                    runOnUiThread {
                        otpResultText.setTextColor(Color.parseColor("#DC2626"))
                        otpResultText.text = "Verification error: $errorMsg"
                        updateVerifyButtonState()
                    }
                }
            }.start()
        }

        btnRegisterSip.setOnClickListener {
            val cfg = SipConfig.loadFromPrefs(this)
            if (cfg != null) {
                startSipRegistration(cfg)
            } else {
                otpResultText.setTextColor(Color.parseColor("#DC2626"))
                otpResultText.text = "No stored profile. Please pair above first."
            }
        }

        btnUnregisterSip.setOnClickListener {
            sipService?.sipEngine?.stop()
        }

        btnClearAccount.setOnClickListener {
            SipConfig.clearPrefs(this)
            gatewayClient?.cookie = null
            sipService?.sipEngine?.stop()
            refreshStoredAccountSummary()
            updateVerifyButtonState()
            otpResultText.setTextColor(Color.parseColor("#4B5563"))
            otpResultText.text = "Cleared stored SIP account."
        }

        btnClearLogs.setOnClickListener {
            sipLogsText.text = "-- Cleared --\n"
        }
    }

    private fun updateVerifyButtonState() {
        val hasCookie = !gatewayClient?.cookie.isNullOrBlank()
        btnVerifyOtp.isEnabled = hasCookie
        btnVerifyOtp.alpha = if (hasCookie) 1.0f else 0.5f
    }

    private fun updateGatewayIpFromEdit() {
        val ip = gatewayIpEdit.text.toString().trim()
        if (ip.isNotEmpty()) {
            gatewayClient?.gatewayIp = ip
        }
    }

    private fun switchTab(tabIndex: Int) {
        viewDialer.visibility = if (tabIndex == 0) View.VISIBLE else View.GONE
        viewSettings.visibility = if (tabIndex == 1) View.VISIBLE else View.GONE
        viewLogs.visibility = if (tabIndex == 2) View.VISIBLE else View.GONE

        tabDialerBtn.setBackgroundColor(if (tabIndex == 0) Color.WHITE else Color.parseColor("#1E3A5F"))
        tabDialerBtn.setTextColor(if (tabIndex == 0) Color.parseColor("#0A2540") else Color.WHITE)

        tabSettingsBtn.setBackgroundColor(if (tabIndex == 1) Color.WHITE else Color.parseColor("#1E3A5F"))
        tabSettingsBtn.setTextColor(if (tabIndex == 1) Color.parseColor("#0A2540") else Color.WHITE)

        tabLogsBtn.setBackgroundColor(if (tabIndex == 2) Color.WHITE else Color.parseColor("#1E3A5F"))
        tabLogsBtn.setTextColor(if (tabIndex == 2) Color.parseColor("#0A2540") else Color.WHITE)
    }

    private fun appendDialDigit(digit: String) {
        val current = dialNumberEdit.text.toString()
        val pos = dialNumberEdit.selectionStart
        val updated = current.substring(0, pos) + digit + current.substring(pos)
        dialNumberEdit.setText(updated)
        dialNumberEdit.setSelection(pos + digit.length)
    }

    private fun refreshStoredAccountSummary() {
        val cfg = SipConfig.loadFromPrefs(this)
        if (cfg != null) {
            accountSummaryText.text = "Number: +${cfg.cleanUsername}\nRealm: ${cfg.realm}\nProxy: ${cfg.proxyHost}:${cfg.proxyPort}\nUUID: ${cfg.uuid}"
            if (cfg.gatewayIp.isNotBlank()) {
                gatewayIpEdit.setText(cfg.gatewayIp)
            }
        } else {
            accountSummaryText.text = "No SIP profile stored. Complete pairing above."
        }
    }

    private fun startSipRegistration(config: SipConfig) {
        val serviceIntent = Intent(this, SipService::class.java).apply {
            action = SipService.ACTION_START
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent)
        } else {
            startService(serviceIntent)
        }
    }

    private fun bindSipService() {
        val serviceIntent = Intent(this, SipService::class.java)
        bindService(serviceIntent, serviceConnection, Context.BIND_AUTO_CREATE)
    }

    private fun updateUiForStates(regState: SipEngine.RegistrationState, callState: SipEngine.CallState) {
        runOnUiThread {
            when (regState) {
                SipEngine.RegistrationState.REGISTERED -> {
                    val cfg = SipConfig.loadFromPrefs(this)
                    topStatusBadge.text = "Online: +${cfg?.cleanUsername ?: ""}"
                    topStatusBadge.setBackgroundColor(Color.parseColor("#16A34A"))
                    dialerStatusHint.text = "Ready to place calls with JioFiber Voice"
                }
                SipEngine.RegistrationState.REGISTERING -> {
                    topStatusBadge.text = "Connecting..."
                    topStatusBadge.setBackgroundColor(Color.parseColor("#D97706"))
                    dialerStatusHint.text = "Registering with router..."
                }
                SipEngine.RegistrationState.FAILED -> {
                    topStatusBadge.text = "Offline (Error)"
                    topStatusBadge.setBackgroundColor(Color.parseColor("#DC2626"))
                    dialerStatusHint.text = "Registration failed. Check connection."
                }
                SipEngine.RegistrationState.UNREGISTERED -> {
                    topStatusBadge.text = "Offline"
                    topStatusBadge.setBackgroundColor(Color.parseColor("#64748B"))
                    dialerStatusHint.text = "Prefix numbers with ISD code (+91) or 0"
                }
            }

            when (callState) {
                SipEngine.CallState.CONNECTED -> {
                    activeCallCard.visibility = View.VISIBLE
                    incomingCallCard.visibility = View.GONE
                    activeCallStateText.text = "Connected"
                    if (callStartTimeMs == 0L) {
                        callStartTimeMs = System.currentTimeMillis()
                        mainHandler.post(callTimerRunnable)
                    }
                }
                SipEngine.CallState.CALLING -> {
                    activeCallCard.visibility = View.VISIBLE
                    incomingCallCard.visibility = View.GONE
                    activeCallStateText.text = "Calling..."
                    activeCallTimerText.text = "Connecting..."
                    callStartTimeMs = 0L
                }
                SipEngine.CallState.RINGING -> {
                    activeCallCard.visibility = View.VISIBLE
                    activeCallStateText.text = "Ringing..."
                    activeCallTimerText.text = "Ringing..."
                    callStartTimeMs = 0L
                }
                SipEngine.CallState.ENDED, SipEngine.CallState.IDLE -> {
                    activeCallCard.visibility = View.GONE
                    incomingCallCard.visibility = View.GONE
                    callStartTimeMs = 0L
                    mainHandler.removeCallbacks(callTimerRunnable)
                }
            }
        }
    }

    // SipEventListener overrides
    override fun onRegistrationStateChanged(state: SipEngine.RegistrationState, message: String) {
        val callSt = sipService?.sipEngine?.callState ?: SipEngine.CallState.IDLE
        updateUiForStates(state, callSt)
    }

    override fun onCallStateChanged(state: SipEngine.CallState, remoteNumber: String, message: String) {
        runOnUiThread {
            activeCallRemoteText.text = remoteNumber
            val regSt = sipService?.sipEngine?.registrationState ?: SipEngine.RegistrationState.UNREGISTERED
            updateUiForStates(regSt, state)
        }
    }

    override fun onIncomingCall(callerNumber: String) {
        runOnUiThread {
            incomingCallerText.text = callerNumber
            incomingCallCard.visibility = View.VISIBLE
        }
    }

    private fun appendLog(log: String) {
        runOnUiThread {
            sipLogsText.append(log + "\n\n")
            logsScrollView.post { logsScrollView.fullScroll(View.FOCUS_DOWN) }
        }
    }

    override fun onSipLog(log: String) {
        appendLog(log)
    }

    private fun requestAppPermissions() {
        val permissions = mutableListOf(
            Manifest.permission.RECORD_AUDIO,
            Manifest.permission.ACCESS_NETWORK_STATE
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permissions.add(Manifest.permission.POST_NOTIFICATIONS)
        }

        val missing = permissions.filter { checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }
        if (missing.isNotEmpty()) {
            requestPermissions(missing.toTypedArray(), 101)
        }
    }

    private fun findGateway(): String? {
        try {
            val interfaces = Collections.list(NetworkInterface.getNetworkInterfaces())
            for (intf in interfaces) {
                val addresses = Collections.list(intf.inetAddresses)
                for (addr in addresses) {
                    if (addr is Inet4Address && !addr.isLoopbackAddress) {
                        val bytes = addr.address
                        val candidate = "${bytes[0].toInt() and 0xff}.${bytes[1].toInt() and 0xff}.${bytes[2].toInt() and 0xff}.1"
                        try {
                            java.net.Socket().use { s -> s.connect(java.net.InetSocketAddress(candidate, 8080), 300) }
                            return candidate
                        } catch (_: Exception) {}
                    }
                }
            }
        } catch (_: Exception) {}
        return null
    }

    override fun onDestroy() {
        super.onDestroy()
        mainHandler.removeCallbacks(callTimerRunnable)
        if (isServiceBound) {
            unbindService(serviceConnection)
            isServiceBound = false
        }
    }
}
