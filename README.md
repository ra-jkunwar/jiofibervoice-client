# JioFiberVoice Client — MVP

A local-only Android prototype based on the publicly documented/researched JioFiberVoice/JioJoin architecture.

## What it does

1. Discovers the IPv4 gateway on the current Wi‑Fi network.
2. Calls the gateway's `/request_account` endpoint over HTTP 8080.
3. Starts the documented OTP/whitelist flow against the local HTTPS service on 8443 using a persistent per-installation app identifier.
4. Stores the returned session cookie in app-local storage.
5. Submits the OTP and parses the returned SIP provisioning XML.
6. Displays the SIP realm, proxy, username, and UUID needed by a SIP client.

## What it deliberately does NOT do yet

- It does not extract credentials from JioJoin.
- It does not bypass OTP or gateway whitelisting.
- It does not send SIP REGISTER/INVITE or place calls yet.
- It does not upload captures or credentials anywhere.

The HTTPS connector accepts the AirFiber gateway's self-signed local certificate. This is only appropriate for a local development prototype; a real release should pin/verify the gateway certificate rather than trust all certificates.

## Build

Open the folder in Android Studio and let Gradle sync. Minimum SDK is 26; target SDK is 35.

## Use

Connect the phone to the AirFiber Wi‑Fi. Open the app and tap:

- Discover AirFiber
- Send OTP
- Enter the OTP
- Verify OTP / Get SIP config

The next engineering step is a native SIP/TLS/RTP layer using the returned provisioning data and the Jio-specific Contact +sip.instance and P-Access-Network-Info headers.
