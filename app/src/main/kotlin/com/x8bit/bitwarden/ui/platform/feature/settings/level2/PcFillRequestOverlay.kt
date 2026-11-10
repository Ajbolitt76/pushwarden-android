package com.x8bit.bitwarden.ui.platform.feature.settings.level2

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.bitwarden.ui.platform.base.util.cardStyle
import com.bitwarden.ui.platform.components.button.BitwardenFilledButton
import com.bitwarden.ui.platform.components.button.BitwardenOutlinedButton
import com.bitwarden.ui.platform.components.model.CardStyle
import com.bitwarden.ui.platform.resource.BitwardenString
import com.bitwarden.ui.platform.theme.BitwardenTheme
import com.x8bit.bitwarden.R
import com.x8bit.bitwarden.data.vault.l2.pc.L2PcAutofillManager
import com.x8bit.bitwarden.data.vault.l2.pc.PC_FILL_REQUEST_LIFETIME
import com.x8bit.bitwarden.data.vault.l2.pc.PcFillRequest
import com.x8bit.bitwarden.ui.platform.composition.LocalBiometricsManager
import com.x8bit.bitwarden.ui.platform.manager.biometrics.BiometricsManager
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import java.time.Clock
import java.time.Duration
import javax.inject.Inject

private const val TICK_MS = 1_000L

/** Shows the oldest pending PC fill request, wherever the user is in the app. */
@HiltViewModel
class PcFillRequestViewModel @Inject constructor(
    private val manager: L2PcAutofillManager,
    val clock: Clock,
) : ViewModel() {
    /** The request to show, or `null`. */
    val requestFlow: StateFlow<PcFillRequest?> = manager.stateFlow
        .map { it.requests.firstOrNull() }
        .stateIn(viewModelScope, SharingStarted.Eagerly, null)

    /** Called after biometrics or device credential succeeded. */
    fun approve(requestId: String) = manager.approve(requestId)

    /** Denied by the user, or the countdown ran out (then the reply is "expired"). */
    fun deny(requestId: String) = manager.deny(requestId)
}

/**
 * Full-screen approval for a PC fill request: a large lock, who asks for what, a countdown, and
 * Approve / Deny at the bottom. Approve asks for biometrics; when the countdown ends the request
 * is answered as expired. Back and taps outside don't answer it.
 */
@Suppress("LongMethod")
@Composable
fun PcFillRequestOverlay(
    viewModel: PcFillRequestViewModel = hiltViewModel(),
    biometricsManager: BiometricsManager = LocalBiometricsManager.current,
) {
    val request by viewModel.requestFlow.collectAsStateWithLifecycle()
    val current = request ?: return
    var secondsLeft by remember(current.requestId) {
        mutableLongStateOf(remaining(current, viewModel.clock))
    }
    LaunchedEffect(current.requestId) {
        while (secondsLeft > 0) {
            delay(TICK_MS)
            secondsLeft = remaining(current, viewModel.clock)
        }
        viewModel.deny(current.requestId)
    }
    Dialog(
        onDismissRequest = {},
        properties = DialogProperties(
            usePlatformDefaultWidth = false,
            dismissOnBackPress = false,
            dismissOnClickOutside = false,
            decorFitsSystemWindows = false,
        ),
    ) {
        Surface(
            modifier = Modifier.fillMaxSize(),
            color = BitwardenTheme.colorScheme.background.primary,
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier
                    .fillMaxSize()
                    .systemBarsPadding()
                    .padding(horizontal = 24.dp, vertical = 16.dp),
            ) {
                Spacer(modifier = Modifier.weight(1f))
                Image(
                    painter = painterResource(id = R.drawable.ic_l2_approval),
                    contentDescription = null,
                    modifier = Modifier.size(144.dp),
                )
                Spacer(modifier = Modifier.height(24.dp))
                Text(
                    text = stringResource(id = BitwardenString.pc_fill_request),
                    style = BitwardenTheme.typography.headlineSmall,
                    color = BitwardenTheme.colorScheme.text.primary,
                    textAlign = TextAlign.Center,
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = stringResource(
                        BitwardenString.pc_fill_request_summary,
                        current.pcName,
                        current.host,
                    ),
                    style = BitwardenTheme.typography.bodyLarge,
                    color = BitwardenTheme.colorScheme.text.secondary,
                    textAlign = TextAlign.Center,
                )
                Spacer(modifier = Modifier.height(24.dp))
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .cardStyle(cardStyle = CardStyle.Full)
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                ) {
                    DetailRow(stringResource(id = BitwardenString.website), current.host)
                    DetailRow(
                        stringResource(id = BitwardenString.account),
                        current.username.orEmpty().ifEmpty { "—" },
                    )
                    DetailRow(stringResource(id = BitwardenString.item), current.itemName)
                    DetailRow(stringResource(id = BitwardenString.computer), current.pcName)
                }
                Spacer(modifier = Modifier.height(24.dp))
                LinearProgressIndicator(
                    progress = {
                        secondsLeft.toFloat() / PC_FILL_REQUEST_LIFETIME.seconds.toFloat()
                    },
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = stringResource(BitwardenString.expires_in_x_seconds, secondsLeft),
                    style = BitwardenTheme.typography.bodySmall,
                    color = BitwardenTheme.colorScheme.text.secondary,
                )
                Spacer(modifier = Modifier.weight(1f))
                Text(
                    text = stringResource(id = BitwardenString.pc_fill_request_warning),
                    style = BitwardenTheme.typography.bodySmall,
                    color = BitwardenTheme.colorScheme.text.secondary,
                    textAlign = TextAlign.Center,
                )
                Spacer(modifier = Modifier.height(16.dp))
                BitwardenFilledButton(
                    label = stringResource(id = BitwardenString.approve_fill),
                    onClick = {
                        biometricsManager.promptUserVerification(
                            onSuccess = { viewModel.approve(current.requestId) },
                            onCancel = {},
                            onLockOut = {},
                            onError = {},
                            onNotSupported = {},
                        )
                    },
                    modifier = Modifier
                        .testTag("PcFillApprove")
                        .fillMaxWidth(),
                )
                Spacer(modifier = Modifier.height(12.dp))
                BitwardenOutlinedButton(
                    label = stringResource(id = BitwardenString.deny_fill),
                    onClick = { viewModel.deny(current.requestId) },
                    modifier = Modifier
                        .testTag("PcFillDeny")
                        .fillMaxWidth(),
                )
            }
        }
    }
}

@Composable
private fun DetailRow(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Text(
            text = label,
            style = BitwardenTheme.typography.bodyMedium,
            color = BitwardenTheme.colorScheme.text.secondary,
            modifier = Modifier.weight(0.4f),
        )
        Text(
            text = value,
            style = BitwardenTheme.typography.bodyMedium,
            color = BitwardenTheme.colorScheme.text.primary,
            modifier = Modifier.weight(0.6f),
        )
    }
}

private fun remaining(request: PcFillRequest, clock: Clock): Long =
    (PC_FILL_REQUEST_LIFETIME - Duration.between(request.requestTime, clock.instant()))
        .seconds
        .coerceAtLeast(0)
