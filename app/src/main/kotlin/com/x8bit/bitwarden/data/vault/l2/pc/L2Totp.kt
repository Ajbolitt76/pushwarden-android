package com.x8bit.bitwarden.data.vault.l2.pc

import java.net.URI
import java.net.URLDecoder
import java.nio.ByteBuffer
import java.time.Instant
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow

private const val DEFAULT_DIGITS = 6
private const val MAX_DIGITS = 8
private const val DEFAULT_PERIOD = 30L
private const val BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
private const val BITS_PER_CHAR = 5
private const val BITS_PER_BYTE = 8
private const val BYTE_MASK = 0xff
private const val OFFSET_MASK = 0x0f
private const val CODE_MASK = 0x7fffffff

/**
 * RFC 6238 TOTP for an L2 seed, which the SDK can't read because it is stored encrypted.
 * Accepts `otpauth://totp/...` URIs and bare base32 secrets.
 *
 * shortcut: no `steam://` support; such items get no code on a PC fill. Add it if needed.
 */
object L2Totp {
    /** The current code, or `null` if [seed] isn't a supported TOTP secret. */
    fun code(seed: String, now: Instant): String? {
        val trimmed = seed.trim()
        var secret = trimmed
        var digits = DEFAULT_DIGITS
        var period = DEFAULT_PERIOD
        var algorithm = "HmacSHA1"
        if (trimmed.startsWith("otpauth://", ignoreCase = true)) {
            val uri = runCatching { URI(trimmed) }.getOrNull() ?: return null
            if (!uri.host.equals("totp", ignoreCase = true)) return null
            val query = uri.rawQuery.orEmpty().split('&').associate {
                val (k, v) = (it.split('=', limit = 2) + "").take(2)
                k.lowercase() to URLDecoder.decode(v, "UTF-8")
            }
            secret = query["secret"] ?: return null
            digits = query["digits"]?.toIntOrNull() ?: DEFAULT_DIGITS
            period = query["period"]?.toLongOrNull() ?: DEFAULT_PERIOD
            algorithm = when (query["algorithm"]?.uppercase()) {
                "SHA256" -> "HmacSHA256"
                "SHA512" -> "HmacSHA512"
                else -> "HmacSHA1"
            }
        } else if (trimmed.contains("://")) {
            return null
        }
        if (digits !in DEFAULT_DIGITS..MAX_DIGITS || period <= 0) return null
        val key = base32(secret) ?: return null
        return generate(key, now.epochSecond / period, digits, algorithm)
    }

    /** RFC 4226 HOTP value for [counter]. */
    fun generate(key: ByteArray, counter: Long, digits: Int, algorithm: String): String {
        val mac = Mac.getInstance(algorithm).apply { init(SecretKeySpec(key, algorithm)) }
        val hash = mac.doFinal(ByteBuffer.allocate(Long.SIZE_BYTES).putLong(counter).array())
        val offset = hash.last().toInt() and OFFSET_MASK
        val binary = ByteBuffer.wrap(hash, offset, Int.SIZE_BYTES).int and CODE_MASK
        val code = binary % 10.0.pow(digits).toInt()
        return code.toString().padStart(digits, '0')
    }

    private fun base32(input: String): ByteArray? {
        val clean = input.uppercase().filterNot { it == ' ' || it == '=' || it == '-' }
        if (clean.isEmpty()) return null
        val out = ByteArray(clean.length * BITS_PER_CHAR / BITS_PER_BYTE)
        var buffer = 0
        var bits = 0
        var index = 0
        for (c in clean) {
            val v = BASE32.indexOf(c)
            if (v < 0) return null
            buffer = (buffer shl BITS_PER_CHAR) or v
            bits += BITS_PER_CHAR
            if (bits >= BITS_PER_BYTE) {
                bits -= BITS_PER_BYTE
                out[index++] = ((buffer shr bits) and BYTE_MASK).toByte()
            }
        }
        return out
    }
}
