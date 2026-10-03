package com.example.jiofibervoice

import android.content.Context
import android.media.AudioManager
import android.media.ToneGenerator
import android.os.Handler
import android.os.Looper
import android.util.Log
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

class SipEngine(private val context: Context) {

    companion object {
        private const val TAG = "SipEngine"
        // User agent string exactly matching JioJoin / Discussion #70 SIP captures
        private const val USER_AGENT = "itsyourap/android RCSAndrd/1.2.4 JUICEJSE/1.4.2.11"
    }

    enum class RegistrationState {
        UNREGISTERED,
        REGISTERING,
        REGISTERED,
        FAILED
    }

    enum class CallState {
        IDLE,
        CALLING,
        RINGING,
        CONNECTED,
        ENDED
    }

    interface SipEventListener {
        fun onRegistrationStateChanged(state: RegistrationState, message: String)
        fun onCallStateChanged(state: CallState, remoteNumber: String, message: String)
        fun onIncomingCall(callerNumber: String)
        fun onSipLog(log: String)
    }

    var listener: SipEventListener? = null
    val rtpEngine = RtpAudioEngine(context)

    var registrationState = RegistrationState.UNREGISTERED
        private set
    var callState = CallState.IDLE
        private set

    private var sslSocket: SSLSocket? = null
    private var socketIn: InputStream? = null
    private var socketOut: OutputStream? = null
    private var readerThread: Thread? = null
    private val isRunning = AtomicBoolean(false)

    private val mainHandler = Handler(Looper.getMainLooper())
    private var currentConfig: SipConfig? = null

    // Registration state
    private var regCallId = randomHex(32)
    private var regFromTag = randomHex(16)
    private var regCSeq = 1L
    private var reRegRunnable: Runnable? = null
    private var keepAliveRunnable: Runnable? = null

    // Active call state
    private var activeCallId = ""
    private var activeCallTarget = ""
    private var activeCallFromTag = ""
    private var activeCallToTag = ""
    private var activeCallCSeq = 1L
    private var activeInviteBranch = ""
    private var activeRemoteContact = ""
    private var activeLocalRtpPort = 52000
    private var activeRemoteRtpPort = 0
    private var activeRemoteRtpHost = ""
    private var activeRemotePayload = RtpAudioEngine.PAYLOAD_AMR_WB_OA
    private var incomingInviteMsg: SipMessage? = null

    private var toneGenerator: ToneGenerator? = null

    fun start(config: SipConfig) {
        currentConfig = config
        stopConnection()
        isRunning.set(true)

        Thread {
            try {
                connectTls(config)
                sendRegister(config)
            } catch (e: Exception) {
                Log.e(TAG, "Connection failed: ${e.message}", e)
                postRegState(RegistrationState.FAILED, "Connection error: ${e.message}")
            }
        }.start()
    }

    private fun connectTls(config: SipConfig) {
        log("Connecting TLS to ${config.proxyHost}:${config.proxyPort}...")
        val trustAll = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) = Unit
            override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) = Unit
            override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
        }
        val sslCtx = SSLContext.getInstance("TLS")
        sslCtx.init(null, arrayOf<TrustManager>(trustAll), SecureRandom())

        val s = sslCtx.socketFactory.createSocket() as SSLSocket
        s.connect(InetSocketAddress(config.proxyHost, config.proxyPort), 7000)
        val params = s.sslParameters
        params.serverNames = listOf(javax.net.ssl.SNIHostName("jiofiber.local.html"))
        s.sslParameters = params
        s.soTimeout = 0 // Blocking read on background thread
        s.startHandshake()

        sslSocket = s
        socketIn = s.inputStream
        socketOut = s.outputStream

        log("TLS Handshake completed successfully. Local endpoint: ${s.localAddress.hostAddress}:${s.localPort}")
        startReaderLoop()
        startKeepAlive()
    }

    private fun startReaderLoop() {
        readerThread = Thread({
            val buffer = ByteArray(8192)
            var accumulated = ""

            while (isRunning.get()) {
                val input = socketIn ?: break
                try {
                    val read = input.read(buffer)
                    if (read <= 0) {
                        log("TLS connection closed by peer")
                        break
                    }
                    accumulated += String(buffer, 0, read, Charsets.UTF_8)

                    while (true) {
                        val headerEnd = accumulated.indexOf("\r\n\r\n")
                        if (headerEnd == -1) break

                        val headerPart = accumulated.substring(0, headerEnd)
                        val contentLengthMatch = Regex("""(?:Content-Length|l):\s*(\d+)""", RegexOption.IGNORE_CASE).find(headerPart)
                        val contentLength = contentLengthMatch?.groupValues?.get(1)?.toIntOrNull() ?: 0

                        val totalMsgLen = headerEnd + 4 + contentLength
                        if (accumulated.length < totalMsgLen) {
                            break
                        }

                        val rawMsg = accumulated.substring(0, totalMsgLen)
                        accumulated = accumulated.substring(totalMsgLen)

                        val msg = SipMessage.parse(rawMsg)
                        handleIncomingMessage(msg)
                    }
                } catch (e: Exception) {
                    if (isRunning.get()) {
                        log("Reader error: ${e.message}")
                    }
                    break
                }
            }

            if (isRunning.get()) {
                postRegState(RegistrationState.UNREGISTERED, "Connection disconnected")
            }
        }, "SipReaderThread").apply { start() }
    }

    private fun handleIncomingMessage(msg: SipMessage) {
        log("<<< RX:\n${msg.startLine}\nCall-ID: ${msg.callId} CSeq: ${msg.cseq}")

        if (msg.isResponse) {
            handleResponse(msg)
        } else {
            handleRequest(msg)
        }
    }

    private fun handleResponse(msg: SipMessage) {
        val cseqMethod = msg.cseqMethod
        val code = msg.statusCode

        when (cseqMethod) {
            "REGISTER" -> handleRegisterResponse(msg)
            "INVITE" -> handleInviteResponse(msg)
            "PRACK" -> {
                log("PRACK response received ($code)")
            }
            "BYE", "CANCEL" -> {
                log("Received $code for $cseqMethod")
            }
            "OPTIONS" -> {
                log("OPTIONS keepalive acknowledged ($code)")
            }
        }
    }

    private fun handleRegisterResponse(msg: SipMessage) {
        val config = currentConfig ?: return
        when (msg.statusCode) {
            200 -> {
                postRegState(RegistrationState.REGISTERED, "Registered successfully as +${config.cleanUsername}")
                scheduleReRegistration(msg.header("Expires")?.toIntOrNull() ?: 300)
            }
            401 -> {
                val wwwAuth = msg.header("WWW-Authenticate")
                if (wwwAuth != null && regCSeq <= 2) {
                    log("Authenticating REGISTER with gateway...")
                    regCSeq++
                    sendRegister(config, authHeaderValue(config, "REGISTER", "sip:${config.realm}", wwwAuth))
                } else {
                    postRegState(RegistrationState.FAILED, "Authentication failed (401)")
                }
            }
            403 -> {
                postRegState(RegistrationState.FAILED, "Forbidden: Device not whitelisted (403). Pair again with OTP.")
            }
            else -> {
                postRegState(RegistrationState.FAILED, "Registration error: ${msg.statusCode} ${msg.reasonPhrase}")
            }
        }
    }

    private fun handleInviteResponse(msg: SipMessage) {
        val config = currentConfig ?: return
        when (msg.statusCode) {
            100 -> {
                postCallState(CallState.CALLING, activeCallTarget, "Calling...")
            }
            180, 183 -> {
                postCallState(CallState.RINGING, activeCallTarget, "Ringing...")
                startRingbackTone()

                val toTag = msg.toTag
                if (!toTag.isNullOrBlank()) activeCallToTag = toTag

                val contact = msg.contact
                if (!contact.isNullOrBlank()) {
                    activeRemoteContact = contact.substringAfter('<').substringBefore('>')
                }

                if (msg.statusCode == 183 && msg.body.isNotEmpty()) {
                    // Early media SDP present from carrier
                    val rtpPort = msg.sdpAudioPort
                    val rtpIp = msg.sdpAudioIp ?: config.proxyHost
                    val payload = msg.sdpAudioPayload ?: RtpAudioEngine.PAYLOAD_AMR_WB_OA
                    if (rtpPort != null && rtpPort > 0) {
                        activeRemoteRtpPort = rtpPort
                        activeRemoteRtpHost = rtpIp
                        activeRemotePayload = payload
                        stopRingbackTone()
                        log("Starting early media RTP stream: $rtpIp:$rtpPort (payload=$payload)")
                        rtpEngine.start(activeLocalRtpPort, rtpIp, rtpPort, payload)
                    }
                }

                // RFC 3262: If provisional response requests 100rel or contains RSeq, acknowledge with PRACK
                val rseq = msg.rseq
                if (rseq != null || msg.is100relRequired) {
                    sendPrack(config, msg, rseq ?: 1L)
                }
            }
            200 -> {
                stopRingbackTone()
                val toTag = msg.toTag
                if (!toTag.isNullOrBlank()) activeCallToTag = toTag

                val contact = msg.contact ?: "sip:${activeCallTarget}@${config.realm}"
                activeRemoteContact = contact.substringAfter('<').substringBefore('>')

                val remotePort = msg.sdpAudioPort ?: activeRemoteRtpPort
                val remoteIp = msg.sdpAudioIp ?: (if (activeRemoteRtpHost.isNotEmpty()) activeRemoteRtpHost else config.proxyHost)
                val payload = msg.sdpAudioPayload ?: activeRemotePayload

                activeRemoteRtpPort = remotePort
                activeRemoteRtpHost = remoteIp
                activeRemotePayload = payload

                // Send ACK for 200 OK
                sendAck(config, msg)

                // Start / update RTP audio stream
                if (remotePort > 0) {
                    log("Starting connected RTP stream: $remoteIp:$remotePort (payload=$payload)")
                    rtpEngine.start(activeLocalRtpPort, remoteIp, remotePort, payload)
                }

                postCallState(CallState.CONNECTED, activeCallTarget, "Connected")
            }
            401, 407 -> {
                stopRingbackTone()
                val authHeader = msg.header("Proxy-Authenticate") ?: msg.header("WWW-Authenticate")
                if (authHeader != null && activeCallCSeq <= 2) {
                    log("Authenticating INVITE...")
                    sendAck(config, msg)

                    activeCallCSeq++
                    val uri = "sip:${activeCallTarget}@${config.realm}?phone-context=${config.realm}&user=phone"
                    val authVal = authHeaderValue(config, "INVITE", uri, authHeader)
                    val isProxy = msg.statusCode == 407
                    sendInvite(config, activeCallTarget, authVal, isProxy)
                } else {
                    postCallState(CallState.ENDED, activeCallTarget, "Call failed: ${msg.statusCode} Auth error")
                }
            }
            486 -> {
                stopRingbackTone()
                sendAck(config, msg)
                postCallState(CallState.ENDED, activeCallTarget, "Busy")
            }
            else -> {
                stopRingbackTone()
                sendAck(config, msg)
                postCallState(CallState.ENDED, activeCallTarget, "Call ended: ${msg.statusCode} ${msg.reasonPhrase}")
            }
        }
    }

    private fun handleRequest(msg: SipMessage) {
        val config = currentConfig ?: return
        when (msg.method) {
            "INVITE" -> {
                incomingInviteMsg = msg
                val caller = extractCallerNumber(msg)
                activeCallId = msg.callId
                activeCallTarget = caller
                activeRemoteContact = msg.contact?.substringAfter('<')?.substringBefore('>') ?: ""

                // Send 180 Ringing
                val toTag = randomHex(16)
                activeCallToTag = toTag

                val resp = buildString {
                    append("SIP/2.0 180 Ringing\r\n")
                    append("Via: ${msg.via}\r\n")
                    append("From: ${msg.from}\r\n")
                    append("To: ${msg.to};tag=$toTag\r\n")
                    append("Call-ID: ${msg.callId}\r\n")
                    append("CSeq: ${msg.cseq}\r\n")
                    append("Contact: <sip:+${config.cleanUsername}@${localIp}:${localPort};transport=tls>\r\n")
                    append("User-Agent: $USER_AGENT\r\n")
                    append("Content-Length: 0\r\n\r\n")
                }
                sendRaw(resp)

                postCallState(CallState.RINGING, caller, "Incoming call from $caller")
                mainHandler.post { listener?.onIncomingCall(caller) }
            }
            "ACK" -> {
                log("ACK received for active call")
            }
            "BYE" -> {
                val resp = buildString {
                    append("SIP/2.0 200 OK\r\n")
                    append("Via: ${msg.via}\r\n")
                    append("From: ${msg.from}\r\n")
                    append("To: ${msg.to}\r\n")
                    append("Call-ID: ${msg.callId}\r\n")
                    append("CSeq: ${msg.cseq}\r\n")
                    append("User-Agent: $USER_AGENT\r\n")
                    append("Content-Length: 0\r\n\r\n")
                }
                sendRaw(resp)
                rtpEngine.stop()
                stopRingbackTone()
                postCallState(CallState.ENDED, activeCallTarget, "Call ended by remote")
            }
            "CANCEL" -> {
                val resp = buildString {
                    append("SIP/2.0 200 OK\r\n")
                    append("Via: ${msg.via}\r\n")
                    append("From: ${msg.from}\r\n")
                    append("To: ${msg.to}\r\n")
                    append("Call-ID: ${msg.callId}\r\n")
                    append("CSeq: ${msg.cseq}\r\n")
                    append("Content-Length: 0\r\n\r\n")
                }
                sendRaw(resp)
                stopRingbackTone()
                postCallState(CallState.ENDED, activeCallTarget, "Call canceled")
            }
            "OPTIONS" -> {
                val resp = buildString {
                    append("SIP/2.0 200 OK\r\n")
                    append("Via: ${msg.via}\r\n")
                    append("From: ${msg.from}\r\n")
                    append("To: ${msg.to}\r\n")
                    append("Call-ID: ${msg.callId}\r\n")
                    append("CSeq: ${msg.cseq}\r\n")
                    append("Allow: INVITE, ACK, CANCEL, OPTIONS, BYE\r\n")
                    append("Content-Length: 0\r\n\r\n")
                }
                sendRaw(resp)
            }
        }
    }

    private fun sendRegister(config: SipConfig, authHeader: String? = null) {
        postRegState(RegistrationState.REGISTERING, "Registering SIP account...")
        val branch = "z9hG4bK" + randomHex(16)
        val formattedUuid = formatUuid(config.uuid)

        val sipReq = buildString {
            append("REGISTER sip:${config.realm} SIP/2.0\r\n")
            append("Via: SIP/2.0/TLS ${localIp}:${localPort};branch=$branch;rkeep=180\r\n")
            append("Max-Forwards: 70\r\n")
            append("Contact: <sip:+${config.cleanUsername}@${localIp}:${localPort};transport=tls>;+sip.instance=\"<$formattedUuid>\";reg-id=1;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\";video;+g.3gpp.iari-ref=\"urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.jio.eucr\";+g.gsma.rcs.telephony=\"none\";q=0.5\r\n")
            append("To: <sip:+${config.cleanUsername}@${config.realm}>\r\n")
            append("From: <sip:+${config.cleanUsername}@${config.realm}>;tag=$regFromTag\r\n")
            append("Call-ID: $regCallId\r\n")
            append("CSeq: $regCSeq REGISTER\r\n")
            append("Expires: 86400\r\n")
            append("Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, SUBSCRIBE, UPDATE, PRACK, INFO\r\n")
            append("Supported: outbound, path, gruu, replaces, timer, norefersub\r\n")
            append("User-Agent: $USER_AGENT\r\n")
            append("P-Access-Network-Info: GPON;PSAPId=+${config.cleanUsername}\r\n")
            if (authHeader != null) {
                append("Authorization: $authHeader\r\n")
            } else {
                append("Authorization: Digest username=\"${config.sipAuthId}\",realm=\"${config.realm}\",uri=\"sip:${config.realm}\",nonce=\"\",response=\"\"\r\n")
            }
            append("Content-Length: 0\r\n\r\n")
        }

        sendRaw(sipReq)
    }

    fun makeCall(targetNumber: String) {
        val config = currentConfig ?: error("Not registered: configure account first")
        if (registrationState != RegistrationState.REGISTERED) {
            log("Warning: attempting to call while registration state is $registrationState")
        }

        val normalized = normalizeDialNumber(targetNumber)
        activeCallTarget = normalized
        activeCallId = randomHex(32)
        activeCallFromTag = randomHex(16)
        activeCallToTag = ""
        activeCallCSeq = 1L
        activeLocalRtpPort = 52000 + (SecureRandom().nextInt(50) * 2)

        postCallState(CallState.CALLING, normalized, "Initiating call to $normalized...")
        sendInvite(config, normalized, null, false)
    }

    private fun sendInvite(config: SipConfig, targetNumber: String, authHeader: String?, isProxy: Boolean) {
        activeInviteBranch = "z9hG4bK" + randomHex(16)
        val sdp = buildSdp(localIp, activeLocalRtpPort)
        val formattedUuid = formatUuid(config.uuid)

        val inviteReq = buildString {
            append("INVITE sip:${targetNumber}@${config.realm}?phone-context=${config.realm}&user=phone SIP/2.0\r\n")
            append("Via: SIP/2.0/TLS ${localIp}:${localPort};rkeep=180;branch=$activeInviteBranch\r\n")
            append("Max-Forwards: 70\r\n")
            append("Contact: <sip:${localIp}:${localPort};transport=tls>;+sip.instance=\"<$formattedUuid>\";reg-id=1;+g.3gpp.icsi-ref=\"urn:urn-7:3gpp-service.ims.icsi.mmtel\";video;+g.3gpp.iari-ref=\"urn:urn-7:3gpp-application.ims.iari.rcs.jio.eucr\";+g.gsma.rcs.telephony=\"none\";q=0.5\r\n")
            append("To: <sip:${targetNumber}@${config.realm}?phone-context=${config.realm}&user=phone>" + (if (activeCallToTag.isNotEmpty()) ";tag=$activeCallToTag" else "") + "\r\n")
            append("From: <sip:+${config.cleanUsername}@${config.realm}>;tag=$activeCallFromTag\r\n")
            append("Call-ID: $activeCallId\r\n")
            append("CSeq: $activeCallCSeq INVITE\r\n")
            append("Session-Expires: 1800\r\n")
            append("Min-SE: 90\r\n")
            append("Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, SUBSCRIBE, UPDATE, PRACK, INFO\r\n")
            append("Supported: outbound, path, gruu, replaces, timer, norefersub, 100rel\r\n")
            append("User-Agent: $USER_AGENT\r\n")
            append("P-Preferred-Identity: <sip:+${config.cleanUsername}@${config.realm}>\r\n")
            append("P-Access-Network-Info: GPON; PSAPId=+${config.cleanUsername}\r\n")
            if (authHeader != null) {
                if (isProxy) {
                    append("Proxy-Authorization: $authHeader\r\n")
                } else {
                    append("Authorization: $authHeader\r\n")
                }
            }
            append("Content-Type: application/sdp\r\n")
            val sdpBytes = sdp.toByteArray(Charsets.UTF_8)
            append("Content-Length: ${sdpBytes.size}\r\n\r\n")
            append(sdp)
        }

        sendRaw(inviteReq)
    }

    private fun sendAck(config: SipConfig, msg: SipMessage) {
        val branch = if (msg.statusCode == 200) "z9hG4bK" + randomHex(16) else activeInviteBranch
        val targetUri = msg.contact?.substringAfter('<')?.substringBefore('>')
            ?: "sip:${activeCallTarget}@${config.realm}?phone-context=${config.realm}&user=phone"
        val ack = buildString {
            append("ACK $targetUri SIP/2.0\r\n")
            append("Via: SIP/2.0/TLS ${localIp}:${localPort};rkeep=180;branch=$branch\r\n")
            append("Max-Forwards: 70\r\n")
            append("From: <sip:+${config.cleanUsername}@${config.realm}>;tag=$activeCallFromTag\r\n")
            append("To: ${msg.to}\r\n")
            append("Call-ID: $activeCallId\r\n")
            append("CSeq: $activeCallCSeq ACK\r\n")
            append("User-Agent: $USER_AGENT\r\n")
            append("Content-Length: 0\r\n\r\n")
        }
        sendRaw(ack)
    }

    private fun sendPrack(config: SipConfig, msg: SipMessage, rseq: Long) {
        val branch = "z9hG4bK" + randomHex(16)
        activeCallCSeq++
        val targetUri = msg.contact?.substringAfter('<')?.substringBefore('>')
            ?: "sip:${activeCallTarget}@${config.realm}?phone-context=${config.realm}&user=phone"
        val prack = buildString {
            append("PRACK $targetUri SIP/2.0\r\n")
            append("Via: SIP/2.0/TLS ${localIp}:${localPort};rkeep=180;branch=$branch\r\n")
            append("Max-Forwards: 70\r\n")
            append("From: <sip:+${config.cleanUsername}@${config.realm}>;tag=$activeCallFromTag\r\n")
            append("To: ${msg.to}\r\n")
            append("Call-ID: $activeCallId\r\n")
            append("CSeq: $activeCallCSeq PRACK\r\n")
            append("RAck: $rseq ${msg.cseqNumber} INVITE\r\n")
            append("User-Agent: $USER_AGENT\r\n")
            append("Content-Length: 0\r\n\r\n")
        }
        sendRaw(prack)
    }

    fun answerCall() {
        val msg = incomingInviteMsg ?: return
        val config = currentConfig ?: return
        activeLocalRtpPort = 52000 + (SecureRandom().nextInt(50) * 2)

        val remoteRtpPort = msg.sdpAudioPort ?: 0
        val remoteRtpIp = msg.sdpAudioIp ?: config.proxyHost
        val payload = msg.sdpAudioPayload ?: RtpAudioEngine.PAYLOAD_AMR_WB_OA

        val sdp = buildSdp(localIp, activeLocalRtpPort)

        val resp = buildString {
            append("SIP/2.0 200 OK\r\n")
            append("Via: ${msg.via}\r\n")
            append("From: ${msg.from}\r\n")
            append("To: ${msg.to};tag=$activeCallToTag\r\n")
            append("Call-ID: ${msg.callId}\r\n")
            append("CSeq: ${msg.cseq}\r\n")
            append("Contact: <sip:+${config.cleanUsername}@${localIp}:${localPort};transport=tls>\r\n")
            append("User-Agent: $USER_AGENT\r\n")
            append("Content-Type: application/sdp\r\n")
            val sdpBytes = sdp.toByteArray(Charsets.UTF_8)
            append("Content-Length: ${sdpBytes.size}\r\n\r\n")
            append(sdp)
        }
        sendRaw(resp)

        if (remoteRtpPort > 0) {
            rtpEngine.start(activeLocalRtpPort, remoteRtpIp, remoteRtpPort, payload)
        }

        postCallState(CallState.CONNECTED, activeCallTarget, "In Call")
    }

    fun declineCall() {
        val msg = incomingInviteMsg ?: return
        val resp = buildString {
            append("SIP/2.0 486 Busy Here\r\n")
            append("Via: ${msg.via}\r\n")
            append("From: ${msg.from}\r\n")
            append("To: ${msg.to};tag=$activeCallToTag\r\n")
            append("Call-ID: ${msg.callId}\r\n")
            append("CSeq: ${msg.cseq}\r\n")
            append("User-Agent: $USER_AGENT\r\n")
            append("Content-Length: 0\r\n\r\n")
        }
        sendRaw(resp)
        incomingInviteMsg = null
        stopRingbackTone()
        postCallState(CallState.ENDED, activeCallTarget, "Declined")
    }

    fun endCall() {
        stopRingbackTone()
        rtpEngine.stop()
        val config = currentConfig

        if (callState == CallState.CONNECTED && config != null && activeCallId.isNotEmpty()) {
            val branch = "z9hG4bK" + randomHex(16)
            activeCallCSeq++
            val byeTarget = if (activeRemoteContact.isNotEmpty()) activeRemoteContact else "sip:${activeCallTarget}@${config.realm}?phone-context=${config.realm}&user=phone"
            val bye = buildString {
                append("BYE $byeTarget SIP/2.0\r\n")
                append("Via: SIP/2.0/TLS ${localIp}:${localPort};rkeep=180;branch=$branch\r\n")
                append("Max-Forwards: 70\r\n")
                append("From: <sip:+${config.cleanUsername}@${config.realm}>;tag=$activeCallFromTag\r\n")
                append("To: <sip:${activeCallTarget}@${config.realm}>;tag=$activeCallToTag\r\n")
                append("Call-ID: $activeCallId\r\n")
                append("CSeq: $activeCallCSeq BYE\r\n")
                append("User-Agent: $USER_AGENT\r\n")
                append("Content-Length: 0\r\n\r\n")
            }
            sendRaw(bye)
        } else if (callState == CallState.CALLING || callState == CallState.RINGING) {
            if (config != null && activeCallId.isNotEmpty()) {
                val cancel = buildString {
                    append("CANCEL sip:${activeCallTarget}@${config.realm}?phone-context=${config.realm}&user=phone SIP/2.0\r\n")
                    append("Via: SIP/2.0/TLS ${localIp}:${localPort};rkeep=180;branch=$activeInviteBranch\r\n")
                    append("Max-Forwards: 70\r\n")
                    append("From: <sip:+${config.cleanUsername}@${config.realm}>;tag=$activeCallFromTag\r\n")
                    append("To: <sip:${activeCallTarget}@${config.realm}>\r\n")
                    append("Call-ID: $activeCallId\r\n")
                    append("CSeq: $activeCallCSeq CANCEL\r\n")
                    append("User-Agent: $USER_AGENT\r\n")
                    append("Content-Length: 0\r\n\r\n")
                }
                sendRaw(cancel)
            }
        }

        postCallState(CallState.ENDED, activeCallTarget, "Call ended")
    }

    fun sendDtmf(digit: Char) {
        rtpEngine.sendDtmf(digit)
    }

    private fun buildSdp(ip: String, port: Int): String {
        val sdpSession = System.currentTimeMillis() / 1000
        return buildString {
            append("v=0\r\n")
            append("o=Juice $sdpSession $sdpSession IN IP4 $ip\r\n")
            append("s=-\r\n")
            append("c=IN IP4 $ip\r\n")
            append("t=0 0\r\n")
            append("m=audio $port RTP/AVP 126 125 124 123 8 0 122 121 101\r\n")
            append("b=AS:37\r\n")
            append("b=RS:462\r\n")
            append("b=RR:1387\r\n")
            append("a=rtpmap:126 AMR-WB/16000\r\n")
            append("a=fmtp:126 mode-change-capability=2; max-red=0\r\n")
            append("a=rtpmap:125 AMR-WB/16000\r\n")
            append("a=fmtp:125 octet-align=1; mode-change-capability=2; max-red=0\r\n")
            append("a=rtpmap:124 AMR/8000\r\n")
            append("a=fmtp:124 mode-change-capability=2; max-red=0\r\n")
            append("a=rtpmap:123 AMR/8000\r\n")
            append("a=fmtp:123 octet-align=1; mode-change-capability=2; max-red=0\r\n")
            append("a=rtpmap:8 PCMA/8000\r\n")
            append("a=rtpmap:0 PCMU/8000\r\n")
            append("a=rtpmap:122 telephone-event/16000\r\n")
            append("a=fmtp:122 0-15\r\n")
            append("a=rtpmap:121 telephone-event/8000\r\n")
            append("a=fmtp:121 0-15\r\n")
            append("a=rtpmap:101 telephone-event/8000\r\n")
            append("a=fmtp:101 0-16\r\n")
            append("a=ptime:20\r\n")
            append("a=maxptime:240\r\n")
            append("a=sendrecv\r\n")
        }
    }

    private fun authHeaderValue(config: SipConfig, method: String, uri: String, authChallenge: String): String {
        val realm = extractAuthParam(authChallenge, "realm") ?: config.realm
        val nonce = extractAuthParam(authChallenge, "nonce") ?: ""
        val qop = extractAuthParam(authChallenge, "qop")
        val algorithm = extractAuthParam(authChallenge, "algorithm") ?: "MD5"
        val authUser = config.sipAuthId

        val ha1 = md5("$authUser:$realm:${config.password}")
        val ha2 = md5("$method:$uri")

        return if (qop != null && qop.contains("auth")) {
            val nc = "00000001"
            val cnonce = randomHex(8)
            val response = md5("$ha1:$nonce:$nc:$cnonce:auth:$ha2")
            "Digest username=\"$authUser\", realm=\"$realm\", nonce=\"$nonce\", uri=\"$uri\", response=\"$response\", algorithm=$algorithm, cnonce=\"$cnonce\", nc=$nc, qop=auth"
        } else {
            val response = md5("$ha1:$nonce:$ha2")
            "Digest username=\"$authUser\", realm=\"$realm\", nonce=\"$nonce\", uri=\"$uri\", response=\"$response\", algorithm=$algorithm"
        }
    }

    private fun extractAuthParam(header: String, param: String): String? {
        val match = Regex("""$param="([^"]+)"""", RegexOption.IGNORE_CASE).find(header)
            ?: Regex("""$param=([a-zA-Z0-9_\-]+)""", RegexOption.IGNORE_CASE).find(header)
        return match?.groupValues?.get(1)
    }

    private fun md5(input: String): String {
        val md = MessageDigest.getInstance("MD5")
        val bytes = md.digest(input.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun sendRaw(msg: String) {
        Thread {
            try {
                val out = socketOut ?: return@Thread
                val data = msg.toByteArray(Charsets.UTF_8)
                synchronized(out) {
                    out.write(data)
                    out.flush()
                }
                val firstLine = msg.lines().firstOrNull() ?: ""
                val callId = Regex("""Call-ID:\s*(.+)""", RegexOption.IGNORE_CASE).find(msg)?.groupValues?.get(1) ?: ""
                log(">>> TX:\n$firstLine\nCall-ID: $callId")
            } catch (e: Exception) {
                log("TX error: ${e.message}")
            }
        }.start()
    }

    private fun scheduleReRegistration(expiresSec: Int) {
        reRegRunnable?.let { mainHandler.removeCallbacks(it) }
        val refreshMs = (maxOf(expiresSec - 30, 60)) * 1000L
        reRegRunnable = Runnable {
            currentConfig?.let {
                regCSeq++
                sendRegister(it)
            }
        }
        mainHandler.postDelayed(reRegRunnable!!, refreshMs)
    }

    private fun startKeepAlive() {
        keepAliveRunnable?.let { mainHandler.removeCallbacks(it) }
        keepAliveRunnable = object : Runnable {
            override fun run() {
                if (isRunning.get() && sslSocket != null && !sslSocket!!.isClosed) {
                    // Send CRLF keep-alive ping per RFC 5626
                    Thread {
                        try {
                            val out = socketOut ?: return@Thread
                            synchronized(out) {
                                out.write("\r\n\r\n".toByteArray(Charsets.US_ASCII))
                                out.flush()
                            }
                        } catch (_: Exception) {}
                    }.start()
                    mainHandler.postDelayed(this, 25000L)
                }
            }
        }
        mainHandler.postDelayed(keepAliveRunnable!!, 25000L)
    }

    private fun startRingbackTone() {
        try {
            if (toneGenerator == null) {
                toneGenerator = ToneGenerator(AudioManager.STREAM_VOICE_CALL, 70)
            }
            toneGenerator?.startTone(ToneGenerator.TONE_SUP_RINGTONE)
        } catch (e: Exception) {
            Log.w(TAG, "ToneGenerator error: ${e.message}")
        }
    }

    private fun stopRingbackTone() {
        try {
            toneGenerator?.stopTone()
            toneGenerator?.release()
        } catch (_: Exception) {}
        toneGenerator = null
    }

    fun stop() {
        stopConnection()
        postRegState(RegistrationState.UNREGISTERED, "Disconnected")
        postCallState(CallState.IDLE, "", "")
    }

    private fun stopConnection() {
        isRunning.set(false)
        reRegRunnable?.let { mainHandler.removeCallbacks(it) }
        keepAliveRunnable?.let { mainHandler.removeCallbacks(it) }
        stopRingbackTone()
        rtpEngine.stop()

        try {
            socketIn?.close()
        } catch (_: Exception) {}
        try {
            socketOut?.close()
        } catch (_: Exception) {}
        try {
            sslSocket?.close()
        } catch (_: Exception) {}

        socketIn = null
        socketOut = null
        sslSocket = null
        readerThread?.interrupt()
        readerThread = null
    }

    private fun extractCallerNumber(msg: SipMessage): String {
        val from = msg.from
        val numMatch = Regex("""sip:(\+?\d+)@""", RegexOption.IGNORE_CASE).find(from)
        return numMatch?.groupValues?.get(1) ?: from.substringBefore('>')
    }

    /**
     * Normalizes dialed numbers for Jio IMS.
     * Fixed voice on Jio IMS expects Indian mobile numbers to start with 0 (e.g. 09876543210).
     */
    private fun normalizeDialNumber(raw: String): String {
        val digits = raw.trim().replace(Regex("""[^\d+]"""), "")
        val withoutPlus = digits.removePrefix("+")
        return when {
            // Indian number with country code 91: e.g. 919876543210 (12 digits) -> 09876543210
            withoutPlus.startsWith("91") && withoutPlus.length == 12 -> "0" + withoutPlus.drop(2)
            // 10-digit mobile or local number: e.g. 9876543210 -> 09876543210
            withoutPlus.length == 10 -> "0$withoutPlus"
            // Already starts with 0: e.g. 09876543210 or 022... -> keep as is
            withoutPlus.startsWith("0") -> withoutPlus
            // Short codes e.g. 100, 198 -> keep as is
            withoutPlus.length in 3..5 -> withoutPlus
            else -> "0$withoutPlus"
        }
    }

    private fun formatUuid(uuid: String): String {
        val trimmed = uuid.trim().removeSurrounding("<", ">").removePrefix("urn:uuid:").removePrefix("urn:UUID:")
        return if (trimmed.matches(Regex("""[0-9a-fA-F\-]{36}"""))) {
            trimmed
        } else {
            "00000000-0000-1000-8000-AABBCCDDEEFF"
        }
    }

    private val localIp: String
        get() = sslSocket?.localAddress?.hostAddress ?: "127.0.0.1"

    private val localPort: Int
        get() = sslSocket?.localPort ?: 5060

    private fun log(s: String) {
        Log.i(TAG, s)
        mainHandler.post { listener?.onSipLog(s) }
    }

    private fun postRegState(state: RegistrationState, msg: String) {
        registrationState = state
        log("Registration state: $state - $msg")
        mainHandler.post { listener?.onRegistrationStateChanged(state, msg) }
    }

    private fun postCallState(state: CallState, num: String, msg: String) {
        callState = state
        log("Call state: $state ($num) - $msg")
        mainHandler.post { listener?.onCallStateChanged(state, num, msg) }
    }

    private fun randomHex(len: Int): String {
        val bytes = ByteArray(len / 2)
        SecureRandom().nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
