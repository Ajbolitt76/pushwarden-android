package com.x8bit.bitwarden.data.vault.l2.pc

import java.net.URI
import java.net.URLDecoder
import java.util.Base64

private const val KEY_BYTES = 32
private val DEVICE_ID = Regex("^[0-9a-z]{4}-[0-9a-z]{4}$")

/** What the extension's pairing QR code carries (PROTOCOL.md §5b). */
data class L2QrPair(
    val relayUrl: String,
    val extId: String,
    val extPublicKey: ByteArray,
    val secret: ByteArray,
    val pcName: String,
) {
    companion object {
        /** Parses `pushwarden://pair?...`; `null` for anything else or malformed values. */
        @Suppress("ReturnCount")
        fun parse(text: String): L2QrPair? {
            val uri = runCatching { URI(text.trim()) }.getOrNull() ?: return null
            if (uri.scheme != "pushwarden" || uri.host != "pair") return null
            val q = uri.rawQuery.orEmpty().split('&').mapNotNull {
                val parts = it.split('=', limit = 2)
                if (parts.size == 2) parts[0] to URLDecoder.decode(parts[1], "UTF-8") else null
            }.toMap()
            if (q["v"] != "1") return null
            val relay = q["r"] ?: return null
            val relayUri = runCatching { URI(relay) }.getOrNull() ?: return null
            val local = relayUri.host == "localhost" || relayUri.host == "127.0.0.1"
            if (relayUri.scheme != "https" && !(relayUri.scheme == "http" && local)) return null
            val extId = q["e"]?.takeIf { DEVICE_ID.matches(it) } ?: return null
            val pk = q["k"]?.let(::b64url)?.takeIf { it.size == KEY_BYTES } ?: return null
            val secret = q["s"]?.let(::b64url)?.takeIf { it.size == KEY_BYTES } ?: return null
            val name = q["n"].orEmpty().trim().take(PC_NAME_MAX).ifEmpty { "PC" }
            return L2QrPair(relay, extId, pk, secret, name)
        }

        private const val PC_NAME_MAX = 64

        private fun b64url(text: String): ByteArray? =
            runCatching { Base64.getUrlDecoder().decode(text) }.getOrNull()
    }
}
