package com.x8bit.bitwarden.ui.vault.feature.addedit

import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.bitwarden.ui.platform.base.util.standardHorizontalMargin
import com.bitwarden.ui.platform.components.header.BitwardenListHeaderText
import com.bitwarden.ui.platform.components.model.CardStyle
import com.bitwarden.ui.platform.components.toggle.BitwardenSwitch
import com.bitwarden.ui.platform.resource.BitwardenString
import com.x8bit.bitwarden.data.vault.l2.L2Hosts

/**
 * The "Security level" section: level 2 on/off, the websites a computer may fill the item on,
 * and an explicit opt-in for websites added since the item was sealed.
 */
fun LazyListScope.vaultAddEditLevel2Items(
    level2: Level2EditState,
    uris: List<String?>,
    onLevel2Change: (Level2EditState) -> Unit,
) {
    item(key = "level2") {
        val uriHosts = L2Hosts.hostsFromUris(uris)
        // An existing level 2 item keeps its sealed hosts unless the user allows new ones.
        val sealed = level2.sealedHosts
        val newHosts = if (level2.original && sealed != null) uriHosts - sealed.toSet() else emptyList()
        val shownHosts = when {
            !level2.original || sealed == null -> uriHosts
            level2.allowNewHosts -> uriHosts
            else -> sealed
        }
        Spacer(modifier = Modifier.height(16.dp))
        BitwardenListHeaderText(
            label = stringResource(id = BitwardenString.security_level),
            modifier = Modifier
                .fillMaxWidth()
                .standardHorizontalMargin()
                .padding(horizontal = 16.dp),
        )
        Spacer(modifier = Modifier.height(8.dp))
        BitwardenSwitch(
            label = stringResource(id = BitwardenString.level_2_switch_label),
            isChecked = level2.enabled,
            onCheckedChange = { onLevel2Change(level2.copy(enabled = it)) },
            supportingText = when {
                !level2.enabled -> stringResource(id = BitwardenString.level_1_description)
                shownHosts.isEmpty() -> stringResource(id = BitwardenString.level_2_no_hosts)
                else -> stringResource(
                    BitwardenString.level_2_hosts_x,
                    shownHosts.joinToString(", "),
                ) + if (!level2.original) {
                    "\n" + stringResource(id = BitwardenString.level_2_change_password_hint)
                } else {
                    ""
                }
            },
            cardStyle = if (level2.enabled && newHosts.isNotEmpty()) {
                CardStyle.Top()
            } else {
                CardStyle.Full
            },
            modifier = Modifier
                .testTag("Level2Switch")
                .fillMaxWidth()
                .standardHorizontalMargin(),
        )
        if (level2.enabled && newHosts.isNotEmpty()) {
            BitwardenSwitch(
                label = stringResource(
                    BitwardenString.level_2_allow_new_hosts_x,
                    newHosts.joinToString(", "),
                ),
                isChecked = level2.allowNewHosts,
                onCheckedChange = { onLevel2Change(level2.copy(allowNewHosts = it)) },
                supportingText = stringResource(id = BitwardenString.level_2_allow_new_hosts_hint),
                cardStyle = CardStyle.Bottom,
                modifier = Modifier
                    .testTag("Level2AllowNewHostsSwitch")
                    .fillMaxWidth()
                    .standardHorizontalMargin(),
            )
        }
    }
}
