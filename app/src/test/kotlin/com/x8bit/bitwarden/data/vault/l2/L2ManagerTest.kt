package com.x8bit.bitwarden.data.vault.l2

import com.bitwarden.vault.CipherView
import com.bitwarden.vault.LoginUriView
import com.bitwarden.vault.PasswordHistoryView
import com.goterl.lazysodium.SodiumJava
import com.x8bit.bitwarden.data.auth.datasource.disk.AuthDiskSource
import com.x8bit.bitwarden.data.vault.datasource.sdk.model.createMockCipherView
import com.x8bit.bitwarden.data.vault.datasource.sdk.model.createMockLoginView
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.time.Instant

class L2ManagerTest {
    private val crypto = L2Crypto(SodiumJava())
    private val keys = mutableMapOf<String, ByteArray>()
    private val keyStore = object : L2KeyStore {
        override fun save(userId: String, key: ByteArray) {
            keys[userId] = key.copyOf()
        }
        override fun load(userId: String) = keys[userId]?.copyOf()
        override fun clear(userId: String) {
            keys.remove(userId)
        }
    }
    private val authDiskSource: AuthDiskSource = mockk {
        every { userState } returns mockk { every { activeUserId } returns USER }
    }
    private val manager = L2ManagerImpl(crypto, keyStore, authDiskSource)
    private val key = crypto.createKey().also { keyStore.save(USER, it) }

    private fun login(
        id: String = "item-1",
        password: String? = "hunter2",
        totp: String? = "JBSWY3DPEHPK3PXP",
        uris: List<String> = listOf("https://github.com/login"),
        history: List<String> = listOf("old-plain"),
    ): CipherView = createMockCipherView(number = 1).copy(
        id = id,
        login = createMockLoginView(number = 1).copy(
            password = password,
            totp = totp,
            uris = uris.map { LoginUriView(uri = it, match = null, uriChecksum = null) },
        ),
        passwordHistory = history.map { PasswordHistoryView(it, Instant.EPOCH) },
    )

    @Test
    fun `toL2 encrypts password and TOTP bound to the item and drops history`() {
        val l2 = manager.toL2(login()).getOrThrow()

        assertTrue(l2.login!!.password.isL2Value())
        assertTrue(l2.login!!.totp.isL2Value())
        assertNull(l2.passwordHistory)
        val plain = crypto.decryptField(key, L2Field.PASSWORD, "item-1", l2.login!!.password!!)
        assertEquals(L2Plain("hunter2", "mockUsername-1", listOf("github.com")), plain)
        assertEquals(login().login, manager.decrypt(l2).login)
    }

    @Test
    fun `protect leaves L1 items alone`() {
        val item = login()
        assertEquals(item, manager.protect(stored = item, updated = item).getOrThrow())
        assertEquals(item, manager.protect(stored = null, updated = item).getOrThrow())
    }

    @Test
    fun `protect re-encrypts plaintext typed over an L2 item and drops new plaintext history`() {
        val stored = manager.toL2(login()).getOrThrow()
        val edited = manager.decrypt(stored).copy(
            passwordHistory = listOf(PasswordHistoryView("hunter2", Instant.EPOCH)),
        ).let { it.copy(login = it.login!!.copy(password = "new-pass")) }

        val saved = manager.protect(stored = stored, updated = edited).getOrThrow()

        assertTrue(saved.login!!.password.isL2Value())
        assertTrue(saved.login!!.totp.isL2Value())
        assertNull(saved.passwordHistory)
        assertEquals("new-pass", manager.decrypt(saved).login!!.password)
    }

    @Test
    fun `ordinary saves keep the sealed hosts and username, toL2 re-seals them`() {
        val stored = manager.toL2(login()).getOrThrow()
        // A URI and username synced from a compromised PC, then an unrelated phone edit.
        val synced = manager.decrypt(stored).let {
            it.copy(
                login = it.login!!.copy(
                    username = "admin",
                    password = "new-pass",
                    uris = it.login!!.uris!! +
                        LoginUriView(uri = "evil.com", match = null, uriChecksum = null),
                ),
            )
        }
        val saved = manager.protect(stored, synced).getOrThrow()
        val plain = crypto.decryptField(key, L2Field.PASSWORD, "item-1", saved.login!!.password!!)
        assertEquals(L2Plain("new-pass", "mockUsername-1", listOf("github.com")), plain)

        val resealed = manager.toL2(saved).getOrThrow()
        val after = crypto.decryptField(key, L2Field.PASSWORD, "item-1", resealed.login!!.password!!)
        assertEquals(L2Plain("new-pass", "admin", listOf("github.com", "evil.com")), after)
    }

    @Test
    fun `protect refuses ciphertext copied from another item`() {
        val bank = manager.toL2(login(id = "bank")).getOrThrow()
        val stored = manager.toL2(login(id = "evil", uris = listOf("evil.com"))).getOrThrow()
        val pasted = stored.copy(login = stored.login!!.copy(password = bank.login!!.password))

        assertTrue(manager.protect(stored, pasted).isFailure)
    }

    @Test
    fun `protect fails closed without the L2 key`() {
        val stored = manager.toL2(login()).getOrThrow()
        keyStore.clear(USER)

        val result = manager.protect(stored, login())

        assertTrue(result.exceptionOrNull() is L2NotSetUpException)
        assertEquals(stored, manager.decrypt(stored))
    }

    @Test
    fun `toL1 allows exactly one plaintext save`() {
        val stored = manager.toL2(login()).getOrThrow()
        val l1 = manager.toL1(stored).getOrThrow()
        assertEquals("hunter2", l1.login!!.password)

        assertEquals(l1, manager.protect(stored, l1).getOrThrow())
        assertTrue(manager.protect(stored, l1).getOrThrow().login!!.password.isL2Value())
    }

    private companion object {
        const val USER = "user-1"
    }
}
