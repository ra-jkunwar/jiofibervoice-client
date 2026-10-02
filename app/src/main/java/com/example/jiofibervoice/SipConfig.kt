package com.example.jiofibervoice

import org.xmlpull.v1.XmlPullParser
import android.util.Xml
import java.io.StringReader

data class SipConfig(
    val realm: String,
    val username: String,
    val password: String,
    val proxy: String,
    val uuid: String,
    val privateIdentity: String,
    val publicIdentity: String
)

object SipConfigParser {
    fun parse(xml: String): SipConfig {
        var realm = ""
        var username = ""
        var password = ""
        var proxy = ""
        var uuid = ""
        var privateId = ""
        var publicId = ""

        val parser = Xml.newPullParser()
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
                }
            }
            parser.next()
        }
        require(username.isNotBlank() && password.isNotBlank() && proxy.isNotBlank()) {
            "SIP credentials/proxy were not present in the provisioning document"
        }
        return SipConfig(realm, username, password, proxy, uuid, privateId, publicId)
    }
}
