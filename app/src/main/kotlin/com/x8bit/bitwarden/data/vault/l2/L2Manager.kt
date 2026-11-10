package com.x8bit.bitwarden.data.vault.l2

import com.bitwarden.vault.CipherView
import com.bitwarden.vault.LoginView
import com.x8bit.bitwarden.data.auth.datasource.disk.AuthDiskSource
import java.util.Collections

/**
 * A level 2 item's sealed binding: [hosts] and [username] are `null` when this phone can't
 * decrypt it (L2 not set up here).
 */
data class L2ItemStatus(val hosts: List<String>?, val username: String?)

/** L2 isn't set up on this phone, so an L2 item can't be encrypted or decrypted. */
class L2NotSetUpException : Exception("L2 is not set up on this phone")

/**
 * Core L2 operations on ciphers for the active user (PROTOCOL.md §2). Reading
 * decrypts L2 fields; writing never lets plaintext replace an L2 value.
 */
interface L2Manager {
    /** True when this phone holds the L2 key for the active user. */
    val isSetUp: Boolean

    /** A copy of [cipher] with its L2 fields decrypted, or [cipher] if that's not possible. */
    fun decrypt(cipher: CipherView): CipherView

    /**
     * Write guard: [stored] is the cipher as currently saved (L2 ciphertext intact), [updated]
     * what is about to be encrypted and uploaded. If [stored] is L2, plaintext password/TOTP in
     * [updated] are encrypted with the stored values' `u` and `h` (an ordinary save never
     * authorizes new hosts), and new plaintext password-history entries are dropped. Fails if
     * that needs the L2 key and it isn't on this phone, or a value belongs to another item.
     */
    fun protect(stored: CipherView?, updated: CipherView): Result<CipherView>

    /**
     * [cipher] with password and TOTP sealed to its current username and the hosts of its
     * current URIs, and plaintext password history removed. The UI confirms the hosts first.
     */
    fun toL2(cipher: CipherView): Result<CipherView>

    /** [cipher] with L2 fields decrypted; lets the next [protect] for it store plaintext. */
    fun toL1(cipher: CipherView): Result<CipherView>

    /** [L2ItemStatus] of a stored cipher, or `null` if it is level 1. */
    fun status(stored: CipherView): L2ItemStatus?

    /** Decrypts one L2 field of item [itemId] for a PC fill request; the caller checks the host. */
    fun decryptField(itemId: String, value: String, field: L2Field): Result<L2Plain>
}

/** Default [L2Manager]. */
class L2ManagerImpl(
    private val crypto: L2Crypto,
    private val keyStore: L2KeyStore,
    private val authDiskSource: AuthDiskSource,
) : L2Manager {
    private val downgrades: MutableSet<String> = Collections.synchronizedSet(mutableSetOf())

    private fun key(): ByteArray? =
        authDiskSource.userState?.activeUserId?.let { keyStore.load(it) }

    override val isSetUp: Boolean get() = key()?.also { it.fill(0) } != null

    override fun decrypt(cipher: CipherView): CipherView {
        val login = cipher.login ?: return cipher
        val id = cipher.id ?: return cipher
        if (!login.password.isL2Value() && !login.totp.isL2Value()) return cipher
        val key = key() ?: return cipher
        try {
            return cipher.copy(
                login = login.copy(
                    password = login.password.decryptOrKeep(key, id, L2Field.PASSWORD),
                    totp = login.totp.decryptOrKeep(key, id, L2Field.TOTP),
                ),
            )
        } finally {
            key.fill(0)
        }
    }

    private fun String?.decryptOrKeep(key: ByteArray, id: String, field: L2Field): String? =
        if (this.isL2Value()) {
            runCatching { crypto.decryptField(key, field, id, this!!).secret }.getOrDefault(this)
        } else {
            this
        }

    override fun protect(stored: CipherView?, updated: CipherView): Result<CipherView> {
        val storedLogin = stored?.login
        val storedIsL2 = storedLogin != null &&
            (storedLogin.password.isL2Value() || storedLogin.totp.isL2Value())
        if (!storedIsL2) return Result.success(updated)
        if (updated.id != null && downgrades.remove(updated.id)) return Result.success(updated)
        val login = updated.login ?: return Result.success(updated)
        val id = updated.id ?: return Result.failure(IllegalArgumentException("unsaved item"))
        return withKey { key ->
            // The binding of the stored ciphertext, not the (possibly synced) current URIs.
            val sealedTo = listOfNotNull(
                storedLogin.password?.takeIf { it.isL2Value() }?.let { L2Field.PASSWORD to it },
                storedLogin.totp?.takeIf { it.isL2Value() }?.let { L2Field.TOTP to it },
            ).first().let { (field, value) -> crypto.decryptField(key, field, id, value) }
            val binding = L2Binding(id, sealedTo.username, sealedTo.hosts)
            encryptLogin(updated, login, key, binding, stored.passwordHistory)
        }
    }

    override fun toL2(cipher: CipherView): Result<CipherView> {
        val login = cipher.login
            ?: return Result.failure(IllegalArgumentException("only logins can be L2"))
        val id = cipher.id ?: return Result.failure(IllegalArgumentException("unsaved item"))
        val binding = L2Binding(
            itemId = id,
            username = login.username.orEmpty(),
            hosts = L2Hosts.hostsFromUris(login.uris.orEmpty().map { it.uri }),
        )
        // Every earlier password is plaintext: drop the whole history. Existing L2 values are
        // re-sealed so the binding the user just confirmed applies to them too.
        return withKey { key ->
            val plain = toL1Values(cipher, login, key, id)
            encryptLogin(plain, plain.login!!, key, binding, storedHistory = null)
        }
    }

    override fun toL1(cipher: CipherView): Result<CipherView> {
        val login = cipher.login ?: return Result.success(cipher)
        val id = cipher.id ?: return Result.failure(IllegalArgumentException("unsaved item"))
        // Already L1: no downgrade allowance, or it would linger until the item is L2 again.
        if (!login.password.isL2Value() && !login.totp.isL2Value()) return Result.success(cipher)
        return withKey { key ->
            toL1Values(cipher, login, key, id).also { downgrades.add(id) }
        }
    }

    private fun toL1Values(cipher: CipherView, login: LoginView, key: ByteArray, id: String) =
        cipher.copy(
            login = login.copy(
                password = login.password?.takeIf { it.isL2Value() }
                    ?.let { crypto.decryptField(key, L2Field.PASSWORD, id, it).secret }
                    ?: login.password,
                totp = login.totp?.takeIf { it.isL2Value() }
                    ?.let { crypto.decryptField(key, L2Field.TOTP, id, it).secret }
                    ?: login.totp,
            ),
        )

    override fun status(stored: CipherView): L2ItemStatus? {
        val login = stored.login ?: return null
        val sealed = listOfNotNull(
            login.password?.takeIf { it.isL2Value() }?.let { L2Field.PASSWORD to it },
            login.totp?.takeIf { it.isL2Value() }?.let { L2Field.TOTP to it },
        ).firstOrNull() ?: return null
        val plain = stored.id?.let { decryptField(it, sealed.second, sealed.first).getOrNull() }
        return L2ItemStatus(hosts = plain?.hosts, username = plain?.username)
    }

    override fun decryptField(itemId: String, value: String, field: L2Field): Result<L2Plain> =
        withKey { key -> crypto.decryptField(key, field, itemId, value) }

    private fun encryptLogin(
        cipher: CipherView,
        login: LoginView,
        key: ByteArray,
        binding: L2Binding,
        storedHistory: List<com.bitwarden.vault.PasswordHistoryView>?,
    ): CipherView {
        fun seal(value: String?, field: L2Field): String? = when {
            value.isNullOrEmpty() -> value
            // Already ciphertext: kept as is. A value copied from another item fails the `i`
            // check here, so the save fails instead.
            value.isL2Value() -> value.also { crypto.decryptField(key, field, binding.itemId, it) }
            else -> crypto.encryptField(key, field, binding, value)
        }
        val keep = storedHistory.orEmpty().toSet()
        val history = cipher.passwordHistory
            ?.filter { it.password.isL2Value() || it in keep }
            ?.ifEmpty { null }
        return cipher.copy(
            login = login.copy(
                password = seal(login.password, L2Field.PASSWORD),
                totp = seal(login.totp, L2Field.TOTP),
            ),
            passwordHistory = history,
        )
    }

    private fun <T> withKey(block: (ByteArray) -> T): Result<T> {
        val key = key() ?: return Result.failure(L2NotSetUpException())
        return try {
            runCatching { block(key) }
        } finally {
            key.fill(0)
        }
    }
}
