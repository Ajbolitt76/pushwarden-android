package com.x8bit.bitwarden.data.vault.l2

import com.goterl.lazysodium.Sodium
import com.sun.jna.NativeLong
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.net.IDN
import java.net.URI
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Base64

private const val KEY_BYTES = 32
private const val SALT_BYTES = 16
private const val NONCE_BYTES = 24
private const val MAC_BYTES = 16
private const val WRAPPED_BYTES = NONCE_BYTES + MAC_BYTES + KEY_BYTES
private const val ARGON2ID13 = 2
private const val OPS_MIN = 3
private const val OPS_MAX = 10
private const val MEM_MIN_MIB = 64
private const val MEM_MAX_MIB = 1024
private const val BYTES_PER_MIB = 1024L * 1024L
private const val PHRASE_WORDS = 5

/** Prefix of every L2 field value (PROTOCOL.md §2). */
const val L2_PREFIX = "l2:v1:"

/** Name of the hidden custom field that holds the L2 key item (PROTOCOL.md §1). */
const val L2_KEY_FIELD_NAME = "l2key"

/** Display name for a newly created key item. Clients find it by [L2_KEY_FIELD_NAME]. */
const val L2_KEY_ITEM_NAME = "PushWarden key – do not edit"

/** Any `l2:` value. Unknown versions must not be treated as plaintext. */
fun String?.isL2Value(): Boolean = this?.startsWith("l2:") == true

/** The two login fields that can hold L2 values. */
enum class L2Field(val wire: String) {
    PASSWORD("password"),
    TOTP("totp"),
}

/** Argon2id cost for wrapping the L2 key. */
data class L2KdfParams(val ops: Int, val memMiB: Int) {
    companion object {
        val DEFAULT = L2KdfParams(ops = 3, memMiB = 256)
    }
}

/** What an L2 value is sealed to besides its field (PROTOCOL.md §2: `i`, `u`, `h`). */
data class L2Binding(val itemId: String, val username: String, val hosts: List<String>)

/** A decrypted L2 field: the secret, the username shown on approval, and the allowed hosts. */
data class L2Plain(val secret: String, val username: String, val hosts: List<String>)

/** The L2 password didn't unwrap the key. */
class L2WrongPasswordException : Exception("wrong L2 password")

/** Malformed, tampered, out-of-bounds or wrong-field L2 data. */
class L2FormatException(message: String) : Exception(message)

@Serializable
private data class KeyItemJson(
    val v: Int,
    val kdf: String,
    val ops: Int,
    val memMiB: Int,
    val salt: String,
    val wrappedKey: String,
)

@Serializable
private data class FieldPayload(
    @SerialName("f") val field: String,
    @SerialName("i") val itemId: String,
    @SerialName("u") val username: String,
    @SerialName("v") val value: String,
    @SerialName("h") val hosts: List<String>,
)

/**
 * Kotlin port of `protocol/src/l2.ts` and `pairing.ts`. Must produce byte-identical output for
 * the shared vectors in `protocol/vectors/v1.json`.
 */
class L2Crypto(private val sodium: Sodium) {
    private val json = Json { ignoreUnknownKeys = false }

    /** 32 random bytes. */
    fun createKey(): ByteArray = random(KEY_BYTES)

    /** Wraps [key] under [password]; returns the `l2key` field value. */
    fun wrapKey(
        key: ByteArray,
        password: String,
        params: L2KdfParams = L2KdfParams.DEFAULT,
        salt: ByteArray = random(SALT_BYTES),
        nonce: ByteArray = random(NONCE_BYTES),
    ): String {
        checkParams(params.ops, params.memMiB)
        require(key.size == KEY_BYTES) { "L2 key must be 32 bytes" }
        val kek = kek(password, salt, params)
        try {
            val boxed = ByteArray(MAC_BYTES + key.size)
            check(sodium.crypto_secretbox_easy(boxed, key, key.size.toLong(), nonce, kek) == 0)
            return json.encodeToString(
                KeyItemJson.serializer(),
                KeyItemJson(
                    v = 1,
                    kdf = "argon2id",
                    ops = params.ops,
                    memMiB = params.memMiB,
                    salt = b64(salt),
                    wrappedKey = b64(nonce + boxed),
                ),
            )
        } finally {
            kek.fill(0)
        }
    }

    /** Unwraps the L2 key; throws [L2WrongPasswordException] or [L2FormatException]. */
    fun unwrapKey(fieldValue: String, password: String): ByteArray =
        unwrapParsed(parseKeyItem(fieldValue), password)

    private fun unwrapParsed(item: KeyItemJson, password: String): ByteArray {
        val salt = unb64(item.salt, SALT_BYTES)
        val wrapped = unb64(item.wrappedKey, WRAPPED_BYTES)
        val kek = kek(password, salt, L2KdfParams(item.ops, item.memMiB))
        try {
            val key = ByteArray(KEY_BYTES)
            val boxed = wrapped.copyOfRange(NONCE_BYTES, wrapped.size)
            val ok = sodium.crypto_secretbox_open_easy(
                key,
                boxed,
                boxed.size.toLong(),
                wrapped.copyOfRange(0, NONCE_BYTES),
                kek,
            ) == 0
            if (!ok) throw L2WrongPasswordException()
            return key
        } finally {
            kek.fill(0)
        }
    }

    private fun parseKeyItem(fieldValue: String): KeyItemJson {
        val item = try {
            json.decodeFromString(KeyItemJson.serializer(), fieldValue)
        } catch (e: IllegalArgumentException) {
            throw L2FormatException("malformed L2 key item: ${e.javaClass.simpleName}")
        }
        if (item.v != 1 || item.kdf != "argon2id") throw L2FormatException("unsupported key item")
        checkParams(item.ops, item.memMiB)
        return item
    }

    private fun checkParams(ops: Int, memMiB: Int) {
        if (ops !in OPS_MIN..OPS_MAX || memMiB !in MEM_MIN_MIB..MEM_MAX_MIB) {
            throw L2FormatException("L2 key item KDF parameters out of bounds")
        }
    }

    private fun kek(password: String, salt: ByteArray, p: L2KdfParams): ByteArray {
        val out = ByteArray(KEY_BYTES)
        val pw = password.toByteArray(Charsets.UTF_8)
        try {
            val rc = sodium.crypto_pwhash(
                out,
                out.size.toLong(),
                pw,
                pw.size.toLong(),
                salt,
                p.ops.toLong(),
                NativeLong(p.memMiB * BYTES_PER_MIB),
                ARGON2ID13,
            )
            check(rc == 0) { "crypto_pwhash failed (out of memory?)" }
            return out
        } finally {
            pw.fill(0)
        }
    }

    /** Encrypts [secret] for [field], sealed to [binding]. */
    fun encryptField(
        key: ByteArray,
        field: L2Field,
        binding: L2Binding,
        secret: String,
        nonce: ByteArray = random(NONCE_BYTES),
    ): String {
        require(binding.itemId.isNotEmpty()) { "L2 values need the item id" }
        val payload = json
            .encodeToString(
                FieldPayload.serializer(),
                FieldPayload(field.wire, binding.itemId, binding.username, secret, binding.hosts),
            )
            .toByteArray(Charsets.UTF_8)
        val boxed = ByteArray(MAC_BYTES + payload.size)
        check(sodium.crypto_secretbox_easy(boxed, payload, payload.size.toLong(), nonce, key) == 0)
        payload.fill(0)
        return L2_PREFIX + b64(nonce + boxed)
    }

    /** Decrypts an L2 value read from [field] of item [itemId]; throws [L2FormatException]. */
    fun decryptField(key: ByteArray, field: L2Field, itemId: String, value: String): L2Plain {
        if (!value.startsWith(L2_PREFIX)) throw L2FormatException("not an l2:v1 value")
        val raw = unb64(value.removePrefix(L2_PREFIX))
        if (raw.size < NONCE_BYTES + MAC_BYTES) throw L2FormatException("L2 value too short")
        val boxed = raw.copyOfRange(NONCE_BYTES, raw.size)
        val plain = ByteArray(boxed.size - MAC_BYTES)
        val ok = sodium.crypto_secretbox_open_easy(
            plain,
            boxed,
            boxed.size.toLong(),
            raw.copyOfRange(0, NONCE_BYTES),
            key,
        ) == 0
        if (!ok) throw L2FormatException("L2 value doesn't decrypt")
        val payload = try {
            json.decodeFromString(FieldPayload.serializer(), plain.decodeStrictUtf8())
        } catch (e: IllegalArgumentException) {
            throw L2FormatException("malformed L2 payload: ${e.javaClass.simpleName}")
        } finally {
            plain.fill(0)
        }
        if (payload.field != field.wire) {
            throw L2FormatException("L2 value is for field ${payload.field}, read from ${field.wire}")
        }
        if (payload.itemId != itemId) throw L2FormatException("L2 value belongs to another item")
        return L2Plain(payload.value, payload.username, payload.hosts)
    }

    /** `b64(nonce ‖ crypto_box_easy(json))` (PROTOCOL.md §4). */
    fun seal(
        jsonText: String,
        recipientPk: ByteArray,
        senderSk: ByteArray,
        nonce: ByteArray = random(NONCE_BYTES),
    ): String {
        val msg = jsonText.toByteArray(Charsets.UTF_8)
        val boxed = ByteArray(MAC_BYTES + msg.size)
        check(
            sodium.crypto_box_easy(boxed, msg, msg.size.toLong(), nonce, recipientPk, senderSk) == 0,
        )
        return b64(nonce + boxed)
    }

    /** Opens a box from [senderPk]; throws [L2FormatException] if it doesn't authenticate. */
    fun open(body: String, senderPk: ByteArray, recipientSk: ByteArray): String {
        val raw = unb64(body)
        if (raw.size > MAX_BODY_BYTES || raw.size < NONCE_BYTES + MAC_BYTES) {
            throw L2FormatException("bad body length")
        }
        val boxed = raw.copyOfRange(NONCE_BYTES, raw.size)
        val plain = ByteArray(boxed.size - MAC_BYTES)
        val ok = sodium.crypto_box_open_easy(
            plain,
            boxed,
            boxed.size.toLong(),
            raw.copyOfRange(0, NONCE_BYTES),
            senderPk,
            recipientSk,
        ) == 0
        if (!ok) throw L2FormatException("message doesn't authenticate")
        return plain.decodeStrictUtf8()
    }

    /** New X25519 keypair: (publicKey, secretKey). */
    fun boxKeyPair(seed: ByteArray? = null): Pair<ByteArray, ByteArray> {
        val pk = ByteArray(KEY_BYTES)
        val sk = ByteArray(KEY_BYTES)
        val rc = if (seed == null) {
            sodium.crypto_box_keypair(pk, sk)
        } else {
            sodium.crypto_box_seed_keypair(pk, sk, seed)
        }
        check(rc == 0)
        return pk to sk
    }

    /** `SHA-256("l2-commit-v1" ‖ extPk ‖ nExt)`. */
    fun commitment(extPk: ByteArray, nExt: ByteArray): ByteArray =
        sha256("l2-commit-v1".toByteArray() + extPk + nExt)

    /** Constant-time commitment check. */
    fun checkCommitment(commit: ByteArray, extPk: ByteArray, nExt: ByteArray): Boolean =
        MessageDigest.isEqual(commit, commitment(extPk, nExt))

    /** `HMAC-SHA256(secret, "l2-qr-v1" ‖ phonePk ‖ extPk)`: proof the QR code was scanned (§5b). */
    fun qrProof(secret: ByteArray, phonePk: ByteArray, extPk: ByteArray): ByteArray {
        require(secret.size == KEY_BYTES) { "QR secret must be 32 bytes" }
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(javax.crypto.spec.SecretKeySpec(secret, "HmacSHA256"))
        return mac.doFinal("l2-qr-v1".toByteArray() + phonePk + extPk)
    }

    /** The 5 words both screens show, joined by "-". */
    fun fingerprintPhrase(
        phonePk: ByteArray,
        extPk: ByteArray,
        nExt: ByteArray,
        nPhone: ByteArray,
        wordlist: List<String>,
    ): String {
        require(listOf(phonePk, extPk, nExt, nPhone).all { it.size == KEY_BYTES })
        require(wordlist.size == WORDLIST_SIZE)
        val h = ByteBuffer.wrap(sha256("l2-pair-v1".toByteArray() + phonePk + extPk + nExt + nPhone))
        return (0 until PHRASE_WORDS).joinToString("-") { i ->
            val n = h.getInt(i * Int.SIZE_BYTES).toLong() and 0xffffffffL
            wordlist[(n % WORDLIST_SIZE).toInt()]
        }
    }

    /** Random bytes from libsodium. */
    fun random(size: Int): ByteArray = ByteArray(size).also { sodium.randombytes_buf(it, size) }

    private fun sha256(input: ByteArray): ByteArray {
        val out = ByteArray(KEY_BYTES)
        check(sodium.crypto_hash_sha256(out, input, input.size.toLong()) == 0)
        return out
    }

    companion object {
        /** Largest decoded relay `body` (PROTOCOL.md §3). */
        const val MAX_BODY_BYTES = 8 * 1024

        /** Entries in the EFF large wordlist. */
        const val WORDLIST_SIZE = 7776
    }
}

/** Standard base64 with padding. */
fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

/** Decodes standard base64; throws [L2FormatException] if malformed or not [len] bytes. */
fun unb64(text: String, len: Int? = null): ByteArray {
    val bytes = try {
        Base64.getDecoder().decode(text)
    } catch (e: IllegalArgumentException) {
        throw L2FormatException("bad base64: ${e.javaClass.simpleName}")
    }
    if (len != null && bytes.size != len) throw L2FormatException("expected $len bytes")
    return bytes
}

private fun ByteArray.decodeStrictUtf8(): String = try {
    Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(this)).toString()
} catch (e: java.nio.charset.CharacterCodingException) {
    throw L2FormatException("invalid UTF-8: ${e.javaClass.simpleName}")
}

/** Host rules from PROTOCOL.md §2. */
object L2Hosts {
    private val SCHEME = Regex("^[a-z][a-z0-9+.-]*://", RegexOption.IGNORE_CASE)

    /** Lowercased web hostnames (IDNs in punycode) from an item's URIs. */
    fun hostsFromUris(uris: List<String?>): List<String> = uris
        .mapNotNull { uri ->
            if (uri.isNullOrBlank()) return@mapNotNull null
            val withScheme = if (SCHEME.containsMatchIn(uri)) uri else "https://$uri"
            val parsed = runCatching { URI(withScheme) }.getOrNull() ?: return@mapNotNull null
            if (parsed.scheme?.lowercase() !in setOf("http", "https")) return@mapNotNull null
            // URI.host is null for non-ASCII hosts, so take it from the authority instead.
            val host = parsed.host ?: parsed.rawAuthority
                ?.substringAfterLast('@')
                ?.substringBefore(':')
                ?: return@mapNotNull null
            runCatching { IDN.toASCII(host).lowercase() }.getOrNull()
        }
        .filter { it.isNotEmpty() }
        .distinct()

    /** True when [origin] may receive a secret allowed on [hosts]. */
    fun originAllowed(origin: String, hosts: List<String>): Boolean {
        val uri = runCatching { URI(origin) }.getOrNull() ?: return false
        val host = uri.host?.lowercase() ?: return false
        val local = host == "localhost" || host == "127.0.0.1"
        val scheme = uri.scheme?.lowercase()
        if (scheme != "https" && !(scheme == "http" && local)) return false
        return hosts.any { raw ->
            val x = raw.lowercase()
            x.isNotEmpty() && (host == x || host.endsWith(".$x"))
        }
    }
}
