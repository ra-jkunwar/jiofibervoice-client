package com.example.jiofibervoice

import android.content.Context
import org.xmlpull.v1.XmlPullParser
import java.io.StringReader

data class SipConfig(
    val realm: String,
    val username: String,
    val password: String,
    val proxy: String,
    val uuid: String,
    val privateIdentity: String,
    val publicIdentity: String,
    val homeNetworkDomainName: String = "",
    val gatewayIp: String = ""
) {
    val cleanUsername: String
        get() = username.trim().removePrefix("+")

    val sipAuthId: String
        get() = if (privateIdentity.isNotBlank()) {
            privateIdentity.trim().removePrefix("sip:").removePrefix("+")
        } else {
            "${cleanUsername}@${realm}"
        }

    val sipPublicUri: String
        get() = if (publicIdentity.isNotBlank()) {
            if (publicIdentity.startsWith("sip:")) publicIdentity else "sip:$publicIdentity"
        } else {
            "sip:+${cleanUsername}@${realm}"
        }

    val sipDomain: String
        get() = if (homeNetworkDomainName.isNotBlank()) homeNetworkDomainName else realm

    val proxyHost: String
        get() = when {
            gatewayIp.isNotBlank() -> gatewayIp
            proxy.isNotBlank() -> proxy.substringBefore(':')
            else -> "jiofiber.local.html"
        }

    val proxyPort: Int = 5068

    fun saveToPrefs(context: Context, gwIp: String = gatewayIp) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit()
            .putString("realm", realm)
            .putString("username", username)
            .putString("password", password)
            .putString("proxy", proxy)
            .putString("uuid", uuid)
            .putString("private_identity", privateIdentity)
            .putString("public_identity", publicIdentity)
            .putString("home_domain", homeNetworkDomainName)
            .putString("gateway_ip", gwIp)
            .apply()
    }

    companion object {
        private const val PREFS_NAME = "jio_sip_config"

        fun loadFromPrefs(context: Context): SipConfig? {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val username = prefs.getString("username", null) ?: return null
            val password = prefs.getString("password", null) ?: return null
            val realm = prefs.getString("realm", null) ?: return null
            val proxy = prefs.getString("proxy", "") ?: ""
            val uuid = prefs.getString("uuid", "") ?: ""
            val privateId = prefs.getString("private_identity", "") ?: ""
            val publicId = prefs.getString("public_identity", "") ?: ""
            val homeDomain = prefs.getString("home_domain", "") ?: ""
            val gwIp = prefs.getString("gateway_ip", "") ?: ""

            return SipConfig(
                realm = realm,
                username = username,
                password = password,
                proxy = proxy,
                uuid = uuid,
                privateIdentity = privateId,
                publicIdentity = publicId,
                homeNetworkDomainName = homeDomain,
                gatewayIp = gwIp
            )
        }

        fun clearPrefs(context: Context) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit().clear().apply()
        }
    }
}

object SipConfigParser {
    fun parse(xml: String, gatewayIp: String = ""): SipConfig {
        var realm = ""
        var username = ""
        var password = ""
        var proxy = ""
        var uuid = ""
        var privateId = ""
        var publicId = ""
        var homeDomain = ""

        val parser = android.util.Xml.newPullParser()
        parser.setInput(StringReader(xml))
        while (parser.eventType != XmlPullParser.END_DOCUMENT) {
            if (parser.eventType == XmlPullParser.START_TAG && parser.name == "parm") {
                val name = parser.getAttributeValue(null, "name") ?: ""
                val value = parser.getAttributeValue(null, "value") ?: ""
                when (name) {
                    "realm" -> realm = value
                    "username" -> username = value
                    "userpwd" -> password = value
                    "address" -> proxy = value
                    "uuid_value" -> uuid = value
                    "private_user_identity" -> privateId = value
                    "public_user_identity" -> publicId = value
                    "home_network_domain_name" -> homeDomain = value
                }
            }
            parser.next()
        }

        require(username.isNotBlank() && password.isNotBlank()) {
            "SIP credentials were not found in the provisioning document"
        }

        if (realm.isBlank() && homeDomain.isNotBlank()) {
            realm = homeDomain
        }

        return SipConfig(
            realm = realm,
            username = username,
            password = password,
            proxy = proxy,
            uuid = uuid,
            privateIdentity = privateId,
            publicIdentity = publicId,
            homeNetworkDomainName = homeDomain,
            gatewayIp = gatewayIp
        )
    }
}
