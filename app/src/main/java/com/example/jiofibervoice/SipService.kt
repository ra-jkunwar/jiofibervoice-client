package com.example.jiofibervoice

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.media.AudioAttributes
import android.media.Ringtone
import android.media.RingtoneManager
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.os.VibrationEffect
import android.os.Vibrator
import android.util.Log

class SipService : Service(), SipEngine.SipEventListener {

    companion object {
        private const val TAG = "SipService"
        const val CHANNEL_ID_STATUS = "jiofiber_voice_status"
        const val CHANNEL_ID_CALL = "jiofiber_voice_call"
        const val NOTIFICATION_ID_STATUS = 1001
        const val NOTIFICATION_ID_CALL = 1002

        const val ACTION_START = "com.example.jiofibervoice.ACTION_START"
        const val ACTION_STOP = "com.example.jiofibervoice.ACTION_STOP"
        const val ACTION_ANSWER = "com.example.jiofibervoice.ACTION_ANSWER"
        const val ACTION_DECLINE = "com.example.jiofibervoice.ACTION_DECLINE"
        const val ACTION_HANGUP = "com.example.jiofibervoice.ACTION_HANGUP"

        var engine: SipEngine? = null
            private set
    }

    inner class LocalBinder : Binder() {
        val service: SipService get() = this@SipService
        val sipEngine: SipEngine get() = this@SipService.sipEngine
    }

    private val binder = LocalBinder()
    lateinit var sipEngine: SipEngine
        private set

    private var ringtone: Ringtone? = null
    private var vibrator: Vibrator? = null

    override fun onCreate() {
        super.onCreate()
        sipEngine = SipEngine(applicationContext)
        sipEngine.listener = this
        engine = sipEngine
        vibrator = getSystemService(Context.VIBRATOR_SERVICE) as? Vibrator
        createNotificationChannels()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                startForegroundNotification("JioFiber Voice Ready", "Connecting...")
                val cfg = SipConfig.loadFromPrefs(applicationContext)
                if (cfg != null) {
                    sipEngine.start(cfg)
                }
            }
            ACTION_STOP -> {
                sipEngine.stop()
                stopRinging()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
            ACTION_ANSWER -> {
                stopRinging()
                cancelCallNotification()
                sipEngine.answerCall()
            }
            ACTION_DECLINE -> {
                stopRinging()
                cancelCallNotification()
                sipEngine.declineCall()
            }
            ACTION_HANGUP -> {
                stopRinging()
                cancelCallNotification()
                sipEngine.endCall()
            }
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder = binder

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)

            // Status channel (Low priority, persistent)
            val statusChannel = NotificationChannel(
                CHANNEL_ID_STATUS,
                "JioFiber Voice Service Status",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows active registration and background connection"
                setShowBadge(false)
            }

            // Call channel (High priority, heads-up notification)
            val callChannel = NotificationChannel(
                CHANNEL_ID_CALL,
                "Incoming and Active Calls",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Shows incoming call alerts and ongoing call controls"
                setShowBadge(true)
                setSound(
                    RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE),
                    AudioAttributes.Builder()
                        .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                        .setUsage(AudioAttributes.USAGE_NOTIFICATION_RINGTONE)
                        .build()
                )
            }

            nm.createNotificationChannel(statusChannel)
            nm.createNotificationChannel(callChannel)
        }
    }

    private fun startForegroundNotification(title: String, content: String) {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notifBuilder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID_STATUS)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        val notification = notifBuilder
            .setContentTitle(title)
            .setContentText(content)
            .setSmallIcon(android.R.drawable.sym_call_outgoing)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                ServiceInfo.FOREGROUND_SERVICE_TYPE_PHONE_CALL
            } else {
                ServiceInfo.FOREGROUND_SERVICE_TYPE_PHONE_CALL
            }
            try {
                startForeground(NOTIFICATION_ID_STATUS, notification, type)
            } catch (e: Exception) {
                Log.w(TAG, "Foreground type phoneCall failed, trying without type: ${e.message}")
                startForeground(NOTIFICATION_ID_STATUS, notification)
            }
        } else {
            startForeground(NOTIFICATION_ID_STATUS, notification)
        }
    }

    private fun updateStatusNotification(title: String, content: String) {
        val nm = getSystemService(NotificationManager::class.java)
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notifBuilder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID_STATUS)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        val notification = notifBuilder
            .setContentTitle(title)
            .setContentText(content)
            .setSmallIcon(android.R.drawable.sym_call_outgoing)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()

        nm.notify(NOTIFICATION_ID_STATUS, notification)
    }

    private fun showIncomingCallNotification(caller: String) {
        val nm = getSystemService(NotificationManager::class.java)

        val fullScreenIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val fullScreenPending = PendingIntent.getActivity(
            this, 1, fullScreenIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val answerIntent = Intent(this, SipService::class.java).apply { action = ACTION_ANSWER }
        val answerPending = PendingIntent.getService(
            this, 2, answerIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val declineIntent = Intent(this, SipService::class.java).apply { action = ACTION_DECLINE }
        val declinePending = PendingIntent.getService(
            this, 3, declineIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notifBuilder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID_CALL)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        val notification = notifBuilder
            .setContentTitle("Incoming JioFiber Call")
            .setContentText("Call from $caller")
            .setSmallIcon(android.R.drawable.sym_call_incoming)
            .setContentIntent(fullScreenPending)
            .setFullScreenIntent(fullScreenPending, true)
            .addAction(android.R.drawable.ic_menu_call, "Answer", answerPending)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Decline", declinePending)
            .setOngoing(true)
            .setAutoCancel(false)
            .build()

        nm.notify(NOTIFICATION_ID_CALL, notification)
    }

    private fun cancelCallNotification() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.cancel(NOTIFICATION_ID_CALL)
    }

    private fun startRinging() {
        try {
            val uri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE)
            ringtone = RingtoneManager.getRingtone(applicationContext, uri)
            ringtone?.play()

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                vibrator?.vibrate(VibrationEffect.createWaveform(longArrayOf(0, 1000, 1000), 0))
            } else {
                @Suppress("DEPRECATION")
                vibrator?.vibrate(longArrayOf(0, 1000, 1000), 0)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Error starting ringtone: ${e.message}")
        }
    }

    private fun stopRinging() {
        try {
            ringtone?.stop()
            vibrator?.cancel()
        } catch (_: Exception) {}
        ringtone = null
    }

    // SipEventListener implementation
    override fun onRegistrationStateChanged(state: SipEngine.RegistrationState, message: String) {
        val title = when (state) {
            SipEngine.RegistrationState.REGISTERED -> "JioFiber Voice: Online"
            SipEngine.RegistrationState.REGISTERING -> "JioFiber Voice: Connecting..."
            SipEngine.RegistrationState.FAILED -> "JioFiber Voice: Failed"
            SipEngine.RegistrationState.UNREGISTERED -> "JioFiber Voice: Disconnected"
        }
        updateStatusNotification(title, message)
    }

    override fun onCallStateChanged(state: SipEngine.CallState, remoteNumber: String, message: String) {
        when (state) {
            SipEngine.CallState.CONNECTED -> {
                stopRinging()
                cancelCallNotification()
                updateStatusNotification("JioFiber Call Active", "In call with $remoteNumber")
            }
            SipEngine.CallState.ENDED, SipEngine.CallState.IDLE -> {
                stopRinging()
                cancelCallNotification()
                val cfg = SipConfig.loadFromPrefs(applicationContext)
                val statusTitle = if (sipEngine.registrationState == SipEngine.RegistrationState.REGISTERED) {
                    "JioFiber Voice: Online (+${cfg?.cleanUsername ?: ""})"
                } else {
                    "JioFiber Voice: Disconnected"
                }
                updateStatusNotification(statusTitle, "Ready for calls")
            }
            else -> {}
        }
    }

    override fun onIncomingCall(callerNumber: String) {
        startRinging()
        showIncomingCallNotification(callerNumber)
    }

    override fun onSipLog(log: String) {
        // Log is handled via engine callbacks in UI
    }

    override fun onDestroy() {
        super.onDestroy()
        stopRinging()
        sipEngine.stop()
        engine = null
    }
}
