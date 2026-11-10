package com.x8bit.bitwarden.ui.vault.feature.item

import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.material3.Text
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.bitwarden.ui.platform.base.util.cardStyle
import com.bitwarden.ui.platform.base.util.standardHorizontalMargin
import com.bitwarden.ui.platform.components.model.CardStyle
import com.bitwarden.ui.platform.resource.BitwardenString
import com.bitwarden.ui.platform.theme.BitwardenTheme
import com.x8bit.bitwarden.data.vault.l2.L2ItemStatus

/** The stored level of an item: [status] is `null` for level 1. */
data class Level2ViewStatus(val status: L2ItemStatus?)

/** A card under the item header saying which level the login is on. */
fun LazyListScope.level2StatusItem(level2: Level2ViewStatus) {
    item(key = "level2Status") {
        val status = level2.status
        val title = stringResource(
            id = if (status == null) BitwardenString.level_1 else BitwardenString.level_2_badge,
        )
        val body = when {
            status == null -> stringResource(id = BitwardenString.level_1_description)
            status.hosts == null -> stringResource(id = BitwardenString.level_2_item_locked)
            status.hosts.isEmpty() -> stringResource(id = BitwardenString.level_2_no_hosts)
            else -> stringResource(BitwardenString.level_2_status_x, status.hosts.joinToString(", "))
        }
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = "$title · $body",
            style = BitwardenTheme.typography.bodyMedium,
            color = if (status == null) {
                BitwardenTheme.colorScheme.text.secondary
            } else {
                BitwardenTheme.colorScheme.text.primary
            },
            modifier = Modifier
                .testTag("Level2Status")
                .fillMaxWidth()
                .standardHorizontalMargin()
                .cardStyle(cardStyle = CardStyle.Full)
                .padding(horizontal = 16.dp, vertical = 12.dp),
        )
    }
}
