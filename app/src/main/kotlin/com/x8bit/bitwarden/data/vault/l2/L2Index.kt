package com.x8bit.bitwarden.data.vault.l2

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Ids of the active user's level 2 logins, for list markers. List views from the SDK carry no
 * password, so the vault sync fills this in the background (VaultSyncManagerImpl).
 *
 * shortcut: process-wide singleton read by `CipherListView.toLabelIcons` to avoid threading a
 * set through every list mapper; [VaultData.l2CipherIds] carries the same set so lists re-map
 * when it changes.
 */
object L2Index {
    private val mutableIds = MutableStateFlow<Set<String>>(emptySet())

    /** The current set of level 2 cipher ids. */
    val ids: StateFlow<Set<String>> = mutableIds.asStateFlow()

    /** Replaces the set. */
    fun update(ids: Set<String>) {
        mutableIds.value = ids
    }
}
