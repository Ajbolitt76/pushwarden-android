package com.x8bit.bitwarden.data.vault.l2.pc

import android.content.SharedPreferences
import androidx.core.content.edit
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** A browser extension paired with this phone. */
@Serializable
data class PairedPc(val id: String, val publicKey: String, val name: String)

/** This phone's relay registration and paired extensions, per user. */
@Serializable
data class PcAutofillConfig(
    val relayUrl: String,
    val deviceId: String,
    val token: String,
    val publicKey: String,
    val secretKey: String,
    val pcs: List<PairedPc> = emptyList(),
)

/** Persists [PcAutofillConfig] in encrypted shared preferences. */
class L2PcStore(private val prefs: SharedPreferences) {
    private val json = Json { ignoreUnknownKeys = true }

    /** The config for [userId], or `null` when the phone isn't registered with a relay. */
    fun load(userId: String): PcAutofillConfig? =
        prefs.getString(key(userId), null)?.let {
            runCatching { json.decodeFromString(PcAutofillConfig.serializer(), it) }.getOrNull()
        }

    /** Replaces the config for [userId]; `null` removes it. */
    fun save(userId: String, config: PcAutofillConfig?) {
        prefs.edit {
            if (config == null) {
                remove(key(userId))
            } else {
                putString(key(userId), json.encodeToString(PcAutofillConfig.serializer(), config))
            }
        }
    }

    /** This install's FCM token, shared by all users; `null` on builds without FCM. */
    var pushToken: String?
        get() = prefs.getString(PUSH_TOKEN_KEY, null)
        set(value) = prefs.edit { putString(PUSH_TOKEN_KEY, value) }

    private fun key(userId: String) = "l2_pc_autofill_$userId"

    private companion object {
        const val PUSH_TOKEN_KEY = "l2_pc_push_token"
    }
}
