# JioFiber Voice Client for Android

A complete, self-contained Android VoIP client for **JioFiber** and **JioAirFiber** voice calling, inspired by and compatible with the JFC / MicroSIP architecture.

## Overview

Unlike standard SIP clients that fail with 403 Forbidden ("Device not whitelisted"), this client implements the entire end-to-end JioFiber voice provisioning and signaling stack:

1. **Gateway Discovery & Pairing**:
   - Auto-discovers the local JioFiber router IP or accepts custom gateway host/IP.
   - Generates persistent locally-administered app identifier (MAC).
   - Direct provisioning check: directly retrieves SIP provisioning without OTP if already whitelisted on the router.
   - OTP registration flow: triggers OTP to the Jio registered mobile number and verifies OTP against the local HTTPS service on port 8443 with self-signed certificate handling.
   - Parses `<wap-provisioningdoc>` XML for SIP realm, IMS username, digest password, proxy, UUID, and identity headers.

2. **SIP over TLS Signaling Engine**:
   - Maintains persistent TLS connection to the gateway on port `5068`.
   - Performs SIP `REGISTER` with MD5 Digest Authentication (RFC 2617 / RFC 3261).
   - Formats `Contact` header with `+sip.instance="<UUID>"` and `Supported: outbound, path`.
   - Sends periodic keep-alive CRLF pings and automatic session re-registration.

3. **VoIP Calling & Audio Engine**:
   - **Outgoing Calls**: Formats dialed numbers with ISD code (`+91`), initiates `INVITE` with SDP, authenticates via digest challenge (401/407), plays ringback tone, handles 200 OK with `ACK`.
   - **Incoming Calls**: Listens for incoming `INVITE` over TLS, rings phone with ringtone & vibration, shows heads-up incoming call alert, supports Answer / Decline.
   - **RTP Audio Streaming**: Standard RFC 3550 RTP engine over UDP with G.711 A-law (PCMA) and mu-law (PCMU) codecs.
   - **In-Call Controls**: Speakerphone toggle, microphone mute, in-call DTMF keypad (RFC 4733 telephone-event packets), and call hangup (`BYE` / `CANCEL`).

4. **Background Service**:
   - Android Foreground Service (`SipService`) with ongoing notification so calls can be received when the app is in the background or screen is off.
   - Android 14/15 compatible permissions.

## Using the App

1. Connect phone to JioFiber / AirFiber Wi-Fi.
2. Open the app and go to the **Gateway & Pair** tab:
   - Tap **Auto-Detect** (or enter gateway IP manually, e.g. `192.168.29.1`).
   - If previously paired, tap **Check Whitelist (No OTP)**.
   - Otherwise, tap **Send SMS OTP**, enter the code received on your registered Jio mobile number, and tap **Verify & Save**.
3. Once paired, the app registers with the SIP server. The top status badge will indicate **Online: +91...**.
4. Go to the **Dialer** tab, dial any destination number (e.g. `+919876543210` or `09876543210`), and tap **Call**!

## Architecture

- `JioGatewayClient.kt`: HTTP 8080 discovery + HTTPS 8443 provisioning API.
- `SipConfig.kt`: Provisioning XML parser, credential data model, and local storage.
- `SipMessage.kt`: RFC 3261 SIP message parsing, serialization, and SDP inspection.
- `SipEngine.kt`: SIP over TLS state machine (REGISTER, INVITE, ACK, BYE, CANCEL, OPTIONS).
- `RtpAudioEngine.kt`: RFC 3550 UDP streaming, `AudioRecord` / `AudioTrack` pipelines, DTMF.
- `G711Codec.kt`: ITU-T G.711 A-law and mu-law companding codecs.
- `SipService.kt`: Foreground service for background keep-alive and incoming call alerts.
- `MainActivity.kt`: Dialer UI, in-call screen, pairing controls, and live SIP diagnostics.
