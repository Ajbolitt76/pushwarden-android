package com.x8bit.bitwarden.ui.vault.feature.addedit

import com.bitwarden.ui.platform.resource.BitwardenString
import com.bitwarden.ui.util.Text
import com.bitwarden.ui.util.asText
import com.x8bit.bitwarden.data.vault.l2.L2NotSetUpException

/**
 * The level 2 section of the add/edit screen.
 *
 * @property original whether the stored item is level 2 (`false` for new items).
 * @property enabled what the user selected; applied after a successful save.
 * @property sealedHosts the websites sealed into the stored item, `null` if not level 2 or
 * not readable on this phone.
 * @property allowNewHosts re-seal with the item's current URIs: an explicit choice, because
 * URIs can be added by a compromised computer (PROTOCOL.md §2).
 */
data class Level2EditState(
    val original: Boolean,
    val enabled: Boolean,
    val sealedHosts: List<String>? = null,
    val allowNewHosts: Boolean = false,
)

/** Thrown when a new organization item is set to level 2, which is personal only. */
class L2PersonalOnlyException : Exception("level 2 is for personal items only")

/** The level 2 error message for [this], or `null` for other errors. */
internal fun Throwable?.level2MessageOrNull(): Text? = when (this) {
    is L2NotSetUpException -> BitwardenString.level_2_not_set_up_on_this_device.asText()
    is L2PersonalOnlyException -> BitwardenString.level_2_personal_only.asText()
    else -> null
}
