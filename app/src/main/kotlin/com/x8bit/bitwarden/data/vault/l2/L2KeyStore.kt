package com.x8bit.bitwarden.data.vault.l2

import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.core.content.edit
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Keeps the L2 key on this phone, wrapped by a non-exportable Android Keystore key, per user.
 */
interface L2KeyStore {
    /** Stores [key] for [userId], replacing any previous one. */
    fun save(userId: String, key: ByteArray)

    /** The L2 key for [userId], or `null` when L2 isn't set up on this phone. */
    fun load(userId: String): ByteArray?

    /** Removes the L2 key for [userId]. */
    fun clear(userId: String)
}

private const val KEYSTORE = "AndroidKeyStore"
private const val TRANSFORMATION = "AES/GCM/NoPadding"
private const val GCM_TAG_BITS = 128
private const val GCM_IV_BYTES = 12
private const val AES_KEY_BITS = 256

/**
 * [L2KeyStore] backed by the Android Keystore. The Keystore key needs no per-use user
 * authentication: the L2 key is only usable while the vault is unlocked, and PC fill approvals
 * ask for biometrics separately (threat model: the phone is trusted).
 */
class L2KeyStoreImpl(
    private val prefs: SharedPreferences,
) : L2KeyStore {
    private val keyStore: KeyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    override fun save(userId: String, key: ByteArray) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey(userId))
        val sealed = cipher.iv + cipher.doFinal(key)
        prefs.edit { putString(prefKey(userId), b64(sealed)) }
    }

    override fun load(userId: String): ByteArray? {
        val sealed = prefs.getString(prefKey(userId), null)?.let { unb64(it) } ?: return null
        val alias = alias(userId)
        val wrapping = keyStore.getKey(alias, null) as? SecretKey ?: return null
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(
            Cipher.DECRYPT_MODE,
            wrapping,
            GCMParameterSpec(GCM_TAG_BITS, sealed, 0, GCM_IV_BYTES),
        )
        return cipher.doFinal(sealed, GCM_IV_BYTES, sealed.size - GCM_IV_BYTES)
    }

    override fun clear(userId: String) {
        prefs.edit { remove(prefKey(userId)) }
        if (keyStore.containsAlias(alias(userId))) keyStore.deleteEntry(alias(userId))
    }

    private fun wrappingKey(userId: String): SecretKey {
        (keyStore.getKey(alias(userId), null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(
            KeyGenParameterSpec
                .Builder(
                    alias(userId),
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(AES_KEY_BITS)
                .build(),
        )
        return generator.generateKey()
    }

    private fun alias(userId: String) = "bw_l2_$userId"
    private fun prefKey(userId: String) = "l2_key_$userId"
}
