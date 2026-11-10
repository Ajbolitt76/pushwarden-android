package com.x8bit.bitwarden.data.vault.l2

import com.goterl.lazysodium.SodiumJava
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.io.File

/** Runs the shared vectors from `protocol/vectors/v1.json` against the Kotlin port. */
class L2CryptoTest {
    private val crypto = L2Crypto(SodiumJava())
    private val vectors: JsonObject = Json.parseToJsonElement(
        javaClass.getResource("/l2/v1.json")!!.readText(),
    ).jsonObject
    private val wordlist = File("src/main/assets/l2/eff_large_wordlist.txt").readLines()
    private val fast = L2KdfParams(ops = 3, memMiB = 64)

    private fun JsonObject.str(k: String) = getValue(k).jsonPrimitive.content
    private fun JsonObject.hex(k: String) = str(k).hexToByteArray()

    @Test
    fun `key item vector wraps and unwraps byte-identically`() {
        val k = vectors.getValue("keyItem").jsonObject
        val out = crypto.wrapKey(
            key = k.hex("keyHex"),
            password = k.str("password"),
            params = L2KdfParams(k.getValue("ops").jsonPrimitive.int, k.getValue("memMiB").jsonPrimitive.int),
            salt = k.hex("saltHex"),
            nonce = k.hex("nonceHex"),
        )
        assertEquals(k.str("fieldValue"), out)
        assertArrayEquals(k.hex("keyHex"), crypto.unwrapKey(k.str("fieldValue"), k.str("password")))
    }

    @Test
    fun `field vectors encrypt byte-identically and decrypt`() {
        for (e in vectors.getValue("fields").jsonArray) {
            val f = e.jsonObject
            val field = L2Field.entries.first { it.wire == f.str("field") }
            val hosts = f.getValue("hosts").jsonArray.map { it.jsonPrimitive.content }
            val id = f.str("itemId")
            val binding = L2Binding(id, f.str("username"), hosts)
            val value = crypto.encryptField(f.hex("keyHex"), field, binding, f.str("secret"), f.hex("nonceHex"))
            assertEquals(f.str("value"), value)
            assertEquals(
                L2Plain(f.str("secret"), f.str("username"), hosts),
                crypto.decryptField(f.hex("keyHex"), field, id, value),
            )
        }
    }

    @Test
    fun `box, commitment, phrase and host vectors`() {
        val b = vectors.getValue("box").jsonObject
        val (senderPk, senderSk) = crypto.boxKeyPair(b.hex("senderSeedHex"))
        val (recipientPk, recipientSk) = crypto.boxKeyPair(b.hex("recipientSeedHex"))
        assertArrayEquals(b.hex("senderPkHex"), senderPk)
        val opened = crypto.open(b.str("body"), senderPk, recipientSk)
        assertEquals(b.getValue("message"), Json.parseToJsonElement(opened))
        // JSON key order differs between serializers, so re-seal the opened text verbatim.
        assertEquals(b.str("body"), crypto.seal(opened, recipientPk, senderSk, b.hex("nonceHex")))

        val p = vectors.getValue("pairing").jsonObject
        assertArrayEquals(p.hex("commitHex"), crypto.commitment(p.hex("extPkHex"), p.hex("nExtHex")))
        assertTrue(crypto.checkCommitment(p.hex("commitHex"), p.hex("extPkHex"), p.hex("nExtHex")))
        assertEquals(
            p.str("phrase"),
            crypto.fingerprintPhrase(
                p.hex("phonePkHex"),
                p.hex("extPkHex"),
                p.hex("nExtHex"),
                p.hex("nPhoneHex"),
                wordlist,
            ),
        )

        assertArrayEquals(
            p.hex("qrProofHex"),
            crypto.qrProof(p.hex("qrSecretHex"), p.hex("phonePkHex"), p.hex("extPkHex")),
        )

        for (e in vectors.getValue("hostMatch").jsonArray) {
            val h = e.jsonObject
            val hosts = h.getValue("hosts").jsonArray.map { it.jsonPrimitive.content }
            assertEquals(
                h.getValue("allowed").jsonPrimitive.boolean,
                L2Hosts.originAllowed(h.str("origin"), hosts),
                h.str("origin"),
            )
        }
    }

    @Test
    fun `wrong password, bounds and tampering are rejected`() {
        val key = crypto.createKey()
        val item = crypto.wrapKey(key, "pw one", fast)
        assertThrows<L2WrongPasswordException> { crypto.unwrapKey(item, "pw two") }
        for (bad in listOf("\"memMiB\":64" to "\"memMiB\":1", "\"ops\":3" to "\"ops\":1", "\"v\":1" to "\"v\":2")) {
            assertThrows<L2FormatException> { crypto.unwrapKey(item.replace(bad.first, bad.second), "pw one") }
        }

        val totp = crypto.encryptField(key, L2Field.TOTP, L2Binding("item-1", "u", listOf("a.com")), "seed")
        assertThrows<L2FormatException> { crypto.decryptField(key, L2Field.PASSWORD, "item-1", totp) }
        assertThrows<L2FormatException> { crypto.decryptField(key, L2Field.TOTP, "item-2", totp) }
        val raw = unb64(totp.removePrefix(L2_PREFIX))
        raw[raw.size - 1] = (raw.last().toInt() xor 1).toByte()
        assertThrows<L2FormatException> {
            crypto.decryptField(key, L2Field.TOTP, "item-1", L2_PREFIX + b64(raw))
        }
        assertThrows<L2FormatException> {
            crypto.decryptField(crypto.createKey(), L2Field.TOTP, "item-1", totp)
        }
        assertThrows<L2FormatException> { crypto.decryptField(key, L2Field.TOTP, "item-1", "l2:v2:abc") }
        assertTrue("l2:v2:abc".isL2Value())
        assertFalse("hunter2".isL2Value())
    }

    @Test
    fun `hostsFromUris matches the TypeScript implementation`() {
        assertEquals(
            listOf("github.com", "example.org", "xn--bcher-kva.de"),
            L2Hosts.hostsFromUris(
                listOf("https://GitHub.com/login", "example.org", "androidapp://com.x", null, "http://bücher.de:81/x", "::bad"),
            ),
        )
    }
}
