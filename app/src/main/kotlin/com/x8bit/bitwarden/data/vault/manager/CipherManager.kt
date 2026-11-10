package com.x8bit.bitwarden.data.vault.manager

import android.net.Uri
import com.bitwarden.vault.CipherView
import com.x8bit.bitwarden.data.vault.manager.model.GetCipherResult
import com.x8bit.bitwarden.data.vault.repository.model.ArchiveCipherResult
import com.x8bit.bitwarden.data.vault.repository.model.CreateAttachmentResult
import com.x8bit.bitwarden.data.vault.repository.model.CreateCipherResult
import com.x8bit.bitwarden.data.vault.repository.model.DeleteAttachmentResult
import com.x8bit.bitwarden.data.vault.repository.model.DeleteCipherResult
import com.x8bit.bitwarden.data.vault.repository.model.DownloadAttachmentResult
import com.x8bit.bitwarden.data.vault.repository.model.RestoreCipherResult
import com.x8bit.bitwarden.data.vault.repository.model.ShareCipherResult
import com.x8bit.bitwarden.data.vault.repository.model.UnarchiveCipherResult
import com.x8bit.bitwarden.data.vault.l2.L2ItemStatus
import com.x8bit.bitwarden.data.vault.repository.model.UpdateCipherResult

/**
 * Manages the creating, updating, and deleting ciphers and their attachments.
 */
@Suppress("TooManyFunctions")
interface CipherManager {
    /**
     * Attempt to create a cipher.
     */
    suspend fun createCipher(
        cipherView: CipherView,
    ): CreateCipherResult

    /**
     * Attempt to create a cipher that belongs to an organization.
     */
    suspend fun createCipherInOrganization(
        cipherView: CipherView,
        collectionIds: List<String>,
    ): CreateCipherResult

    /**
     * Attempt to create an attachment for the given [cipherView].
     */
    suspend fun createAttachment(
        cipherId: String,
        cipherView: CipherView,
        fileSizeBytes: String,
        fileName: String,
        fileUri: Uri,
    ): CreateAttachmentResult

    /**
     * Attempt to download an attachment file, specified by [attachmentId], for the given
     * [cipherView].
     */
    suspend fun downloadAttachment(
        cipherView: CipherView,
        attachmentId: String,
    ): DownloadAttachmentResult

    /**
     * Attempt to retrieve a decrypted cipher based on the [cipherId].
     */
    suspend fun getCipher(cipherId: String): GetCipherResult

    /**
     * Attempt to archive a cipher.
     */
    suspend fun archiveCipher(
        cipherId: String,
        cipherView: CipherView,
    ): ArchiveCipherResult

    /**
     * Attempt to unarchive a cipher.
     */
    suspend fun unarchiveCipher(
        cipherId: String,
        cipherView: CipherView,
    ): UnarchiveCipherResult

    /**
     * Attempt to delete a cipher.
     */
    suspend fun hardDeleteCipher(
        cipherId: String,
    ): DeleteCipherResult

    /**
     * Attempt to soft delete a cipher.
     */
    suspend fun softDeleteCipher(
        cipherId: String,
        cipherView: CipherView,
    ): DeleteCipherResult

    /**
     * Attempt to delete an attachment from a send.
     */
    suspend fun deleteCipherAttachment(
        cipherId: String,
        attachmentId: String,
        cipherView: CipherView,
    ): DeleteAttachmentResult

    /**
     * Attempt to restore a cipher.
     */
    suspend fun restoreCipher(
        cipherId: String,
        cipherView: CipherView,
    ): RestoreCipherResult

    /**
     * Attempt to share a cipher to the collections with the given collectionIds.
     */
    suspend fun shareCipher(
        cipherId: String,
        organizationId: String,
        cipherView: CipherView,
        collectionIds: List<String>,
    ): ShareCipherResult

    /**
     * Moves a login to L2: password and TOTP are encrypted with the L2 key and plaintext
     * password history is removed (DESIGN.md, flow 2).
     */
    suspend fun moveCipherToL2(cipherId: String): UpdateCipherResult

    /** Moves a login back to L1: password and TOTP are stored decrypted again. */
    suspend fun moveCipherToL1(cipherId: String): UpdateCipherResult

    /**
     * The level 2 state of [cipherId] as stored: `null` for a level 1 item. Item screens use it
     * because they only ever see decrypted copies.
     */
    suspend fun getL2Status(cipherId: String): L2ItemStatus?

    /**
     * [cipher] with its level 2 fields decrypted for showing or editing on this phone, or
     * unchanged if it isn't level 2 or the L2 key isn't here. Saves re-seal them.
     */
    fun decryptL2(cipher: CipherView): CipherView

    /**
     * Creates a login directly at level 2. It is first saved without password and TOTP, so the
     * server assigns the id the L2 values are bound to and no plaintext version ever exists
     * for a computer to sync; then the sealed values are saved.
     */
    suspend fun createCipherAtL2(cipherView: CipherView): CreateCipherResult

    /**
     * Attempt to update a cipher.
     */
    suspend fun updateCipher(
        cipherId: String,
        cipherView: CipherView,
    ): UpdateCipherResult

    /**
     * Attempt to update a cipher with the given collectionIds.
     */
    suspend fun updateCipherCollections(
        cipherId: String,
        collectionIds: List<String>,
    ): ShareCipherResult

    /**
     * Migrate the attachments if they don't have their own key
     */
    suspend fun migrateAttachments(
        userId: String,
        cipherView: CipherView,
    ): Result<CipherView>
}
