package com.x8bit.bitwarden.data.vault.l2

import com.bitwarden.core.data.manager.dispatcher.DispatcherManager
import com.bitwarden.vault.CipherListViewType
import com.bitwarden.vault.CipherRepromptType
import com.bitwarden.vault.CipherType
import com.bitwarden.vault.CipherView
import com.bitwarden.vault.FieldType
import com.bitwarden.vault.FieldView
import com.bitwarden.vault.SecureNoteType
import com.bitwarden.vault.SecureNoteView
import com.x8bit.bitwarden.data.auth.datasource.disk.AuthDiskSource
import com.x8bit.bitwarden.data.platform.util.isActive
import com.x8bit.bitwarden.data.vault.manager.model.GetCipherResult
import com.x8bit.bitwarden.data.vault.repository.VaultRepository
import com.x8bit.bitwarden.data.vault.repository.model.CreateCipherResult
import com.x8bit.bitwarden.data.vault.repository.model.UpdateCipherResult
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import java.time.Clock

/** Why an L2 setup step failed, for the UI. */
enum class L2SetupError {
    /** The vault already has a key item: unlock it instead of creating one. */
    KEY_ITEM_EXISTS,

    /** No key item: set up L2 first. */
    NO_KEY_ITEM,

    /** More than one key item: the user must delete the extra ones. */
    MULTIPLE_KEY_ITEMS,

    /** The L2 password didn't unwrap the key. */
    WRONG_PASSWORD,

    /** This phone doesn't hold the L2 key. */
    NOT_SET_UP,

    /** The key item is malformed, or saving to the server failed. */
    FAILED,
}

/** Thrown with the [L2SetupError] the UI should show. */
class L2SetupException(val error: L2SetupError, cause: Throwable? = null) :
    Exception(error.name, cause)

/** Creates, unlocks and re-wraps the L2 key item (DESIGN.md flow 1, PROTOCOL.md §1). */
interface L2SetupManager {
    /** True when this phone holds the L2 key for the active user. */
    val isSetUp: Boolean

    /** Creates a new L2 key and key item. */
    suspend fun setUp(password: String): Result<Unit>

    /** Unlocks the existing key item with [password] and keeps the key on this phone. */
    suspend fun unlock(password: String): Result<Unit>

    /** Re-wraps the key under [newPassword]; items stay as they are. */
    suspend fun changePassword(newPassword: String): Result<Unit>

    /** Removes the L2 key from this phone. The key item stays in the vault. */
    fun forget()
}

/** Default [L2SetupManager]. */
class L2SetupManagerImpl(
    private val crypto: L2Crypto,
    private val keyStore: L2KeyStore,
    private val l2Manager: L2Manager,
    private val vaultRepository: VaultRepository,
    private val authDiskSource: AuthDiskSource,
    private val clock: Clock,
    private val dispatcherManager: DispatcherManager,
) : L2SetupManager {
    private val userId: String
        get() = authDiskSource.userState?.activeUserId
            ?: throw L2SetupException(L2SetupError.FAILED)

    override val isSetUp: Boolean get() = l2Manager.isSetUp

    override suspend fun setUp(password: String): Result<Unit> = io {
        if (findKeyItems().isNotEmpty()) throw L2SetupException(L2SetupError.KEY_ITEM_EXISTS)
        val key = crypto.createKey()
        try {
            val result = vaultRepository.createCipher(keyItem(crypto.wrapKey(key, password)))
            if (result !is CreateCipherResult.Success) {
                throw L2SetupException(L2SetupError.FAILED, (result as? CreateCipherResult.Error)?.error)
            }
            keyStore.save(userId, key)
        } finally {
            key.fill(0)
        }
    }

    override suspend fun unlock(password: String): Result<Unit> = io {
        val item = singleKeyItem()
        val key = try {
            crypto.unwrapKey(item.keyField().value.orEmpty(), password)
        } catch (e: L2WrongPasswordException) {
            throw L2SetupException(L2SetupError.WRONG_PASSWORD, e)
        } catch (e: L2FormatException) {
            throw L2SetupException(L2SetupError.FAILED, e)
        }
        try {
            keyStore.save(userId, key)
        } finally {
            key.fill(0)
        }
    }

    override suspend fun changePassword(newPassword: String): Result<Unit> = io {
        val key = keyStore.load(userId) ?: throw L2SetupException(L2SetupError.NOT_SET_UP)
        try {
            val item = singleKeyItem()
            val newValue = crypto.wrapKey(key, newPassword)
            val updated = item.copy(
                fields = item.fields.orEmpty().map {
                    if (it.name == L2_KEY_FIELD_NAME) it.copy(value = newValue) else it
                },
            )
            val result = vaultRepository.updateCipher(cipherId = item.id!!, cipherView = updated)
            if (result !is UpdateCipherResult.Success) {
                throw L2SetupException(L2SetupError.FAILED, (result as? UpdateCipherResult.Error)?.error)
            }
        } finally {
            key.fill(0)
        }
    }

    override fun forget() {
        authDiskSource.userState?.activeUserId?.let(keyStore::clear)
    }

    private suspend fun singleKeyItem(): CipherView {
        val items = findKeyItems()
        return when (items.size) {
            0 -> throw L2SetupException(L2SetupError.NO_KEY_ITEM)
            1 -> items.single()
            else -> throw L2SetupException(L2SetupError.MULTIPLE_KEY_ITEMS)
        }
    }

    /** Active secure notes carrying an `l2key` field (PROTOCOL.md §1). */
    private suspend fun findKeyItems(): List<CipherView> {
        val list = vaultRepository.decryptCipherListResultStateFlow
            .first { it.data != null }
            .data
            ?.successes
            .orEmpty()
        return list
            .filter { it.type is CipherListViewType.SecureNote && it.isActive }
            .mapNotNull { it.id }
            .mapNotNull { (vaultRepository.getCipher(it) as? GetCipherResult.Success)?.cipherView }
            .filter { cipher -> cipher.fields.orEmpty().any { it.name == L2_KEY_FIELD_NAME } }
    }

    private fun CipherView.keyField(): FieldView =
        fields.orEmpty().first { it.name == L2_KEY_FIELD_NAME }

    private fun keyItem(fieldValue: String): CipherView = CipherView(
        id = null,
        organizationId = null,
        folderId = null,
        collectionIds = emptyList(),
        key = null,
        name = L2_KEY_ITEM_NAME,
        notes = "Level 2 key for this vault. Deleting or editing it makes L2 items unreadable " +
            "on new devices.",
        type = CipherType.SECURE_NOTE,
        login = null,
        identity = null,
        card = null,
        secureNote = SecureNoteView(type = SecureNoteType.GENERIC),
        sshKey = null,
        bankAccount = null,
        driversLicense = null,
        passport = null,
        favorite = false,
        reprompt = CipherRepromptType.NONE,
        organizationUseTotp = false,
        edit = true,
        permissions = null,
        viewPassword = true,
        localData = null,
        attachments = null,
        attachmentDecryptionFailures = null,
        fields = listOf(
            FieldView(
                name = L2_KEY_FIELD_NAME,
                value = fieldValue,
                type = FieldType.HIDDEN,
                linkedId = null,
            ),
        ),
        passwordHistory = null,
        creationDate = clock.instant(),
        deletedDate = null,
        revisionDate = clock.instant(),
        archivedDate = null,
        partial = false,
    )

    private suspend fun io(block: suspend () -> Unit): Result<Unit> =
        withContext(dispatcherManager.io) { runCatching { block() } }
}
