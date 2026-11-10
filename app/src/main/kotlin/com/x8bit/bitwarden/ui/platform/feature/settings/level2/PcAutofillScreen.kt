package com.x8bit.bitwarden.ui.platform.feature.settings.level2

import android.Manifest
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.bitwarden.ui.platform.base.util.EventsEffect
import com.bitwarden.ui.platform.base.util.standardHorizontalMargin
import com.bitwarden.ui.platform.components.appbar.BitwardenTopAppBar
import com.bitwarden.ui.platform.components.button.BitwardenFilledButton
import com.bitwarden.ui.platform.components.button.BitwardenOutlinedButton
import com.bitwarden.ui.platform.components.button.BitwardenOutlinedErrorButton
import com.bitwarden.ui.platform.components.button.BitwardenTextButton
import com.bitwarden.ui.platform.components.camera.CameraPreview
import com.bitwarden.ui.platform.components.camera.QrCodeSquare
import com.bitwarden.ui.platform.components.dialog.BitwardenBasicDialog
import com.bitwarden.ui.platform.components.dialog.BitwardenLoadingDialog
import com.bitwarden.ui.platform.components.dialog.BitwardenTwoButtonDialog
import com.bitwarden.ui.platform.components.field.BitwardenTextField
import com.bitwarden.ui.platform.components.model.CardStyle
import com.bitwarden.ui.platform.components.scaffold.BitwardenScaffold
import com.bitwarden.ui.platform.components.util.rememberVectorPainter
import com.bitwarden.ui.platform.composition.LocalQrCodeAnalyzer
import com.bitwarden.ui.platform.feature.qrcodescan.util.QrCodeAnalyzer
import com.bitwarden.ui.platform.resource.BitwardenDrawable
import com.bitwarden.ui.platform.resource.BitwardenString
import com.bitwarden.ui.platform.theme.BitwardenTheme
import com.x8bit.bitwarden.data.vault.l2.pc.PcPairing
import com.x8bit.bitwarden.ui.platform.composition.LocalBiometricsManager
import com.x8bit.bitwarden.ui.platform.composition.LocalPermissionsManager
import com.x8bit.bitwarden.ui.platform.manager.biometrics.BiometricsManager
import com.x8bit.bitwarden.ui.platform.manager.permissions.PermissionsManager

/**
 * PC autofill: pair computers by QR code (or manually), and see which are paired. Fill requests
 * appear in a dialog anywhere in the app ([PcFillRequestOverlay]).
 */
@Suppress("LongMethod", "CyclomaticComplexMethod")
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PcAutofillScreen(
    onNavigateBack: () -> Unit,
    viewModel: PcAutofillViewModel = hiltViewModel(),
    biometricsManager: BiometricsManager = LocalBiometricsManager.current,
    permissionsManager: PermissionsManager = LocalPermissionsManager.current,
    qrCodeAnalyzer: QrCodeAnalyzer = LocalQrCodeAnalyzer.current,
) {
    val state by viewModel.stateFlow.collectAsStateWithLifecycle()
    EventsEffect(viewModel = viewModel) { event ->
        when (event) {
            PcAutofillEvent.NavigateBack -> onNavigateBack()
            is PcAutofillEvent.VerifyUser -> biometricsManager.promptUserVerification(
                onSuccess = { viewModel.trySendAction(PcAutofillAction.UserVerified(event.action)) },
                onCancel = {},
                onLockOut = {},
                onError = {},
                onNotSupported = {},
            )
        }
    }
    val cameraLauncher = permissionsManager.getLauncher { granted ->
        if (granted) viewModel.trySendAction(PcAutofillAction.ScanClick)
    }
    val onScanClick = {
        if (permissionsManager.checkPermission(Manifest.permission.CAMERA)) {
            viewModel.trySendAction(PcAutofillAction.ScanClick)
        } else {
            cameraLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    if (state.loading) {
        BitwardenLoadingDialog(text = stringResource(id = BitwardenString.loading))
    }
    state.pendingQr?.let { qr ->
        BitwardenTwoButtonDialog(
            title = stringResource(id = BitwardenString.pair_with_this_computer),
            message = stringResource(BitwardenString.pair_with_x_via_y, qr.pcName, qr.relayUrl),
            confirmButtonText = stringResource(id = BitwardenString.pair),
            dismissButtonText = stringResource(id = BitwardenString.cancel),
            onConfirmClick = { viewModel.trySendAction(PcAutofillAction.QrPairConfirm) },
            onDismissClick = { viewModel.trySendAction(PcAutofillAction.QrPairCancel) },
            onDismissRequest = { viewModel.trySendAction(PcAutofillAction.QrPairCancel) },
        )
    }
    state.message?.let { message ->
        BitwardenBasicDialog(
            title = null,
            message = stringResource(
                id = when (message) {
                    PcAutofillMessage.PAIRED -> BitwardenString.computer_paired
                    PcAutofillMessage.FAILED -> BitwardenString.generic_error_message
                    PcAutofillMessage.NOT_A_PAIRING_CODE -> BitwardenString.not_a_pairing_code
                },
            ),
            onDismissRequest = { viewModel.trySendAction(PcAutofillAction.DismissMessage) },
        )
    }

    val data = state.data
    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior(rememberTopAppBarState())
    val margin = Modifier.standardHorizontalMargin().fillMaxWidth()
    BitwardenScaffold(
        modifier = Modifier
            .fillMaxSize()
            .nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = {
            BitwardenTopAppBar(
                title = stringResource(id = BitwardenString.pc_autofill),
                scrollBehavior = scrollBehavior,
                navigationIcon = rememberVectorPainter(id = BitwardenDrawable.ic_back),
                navigationIconContentDescription = stringResource(id = BitwardenString.back),
                onNavigationIconClick = {
                    if (state.scanning) {
                        viewModel.trySendAction(PcAutofillAction.ScanCancel)
                    } else {
                        viewModel.trySendAction(PcAutofillAction.BackClick)
                    }
                },
            )
        },
    ) {
        if (state.scanning) {
            qrCodeAnalyzer.onQrCodeScanned = {
                viewModel.trySendAction(PcAutofillAction.QrScanned(it))
            }
            Box(modifier = Modifier.fillMaxSize()) {
                CameraPreview(
                    cameraErrorReceive = { viewModel.trySendAction(PcAutofillAction.ScanCancel) },
                    analyzer = qrCodeAnalyzer,
                    modifier = Modifier.fillMaxSize(),
                )
                QrCodeSquare(
                    squareOutlineSize = 250.dp,
                    modifier = Modifier.align(Alignment.Center),
                )
                Text(
                    text = stringResource(id = BitwardenString.scan_pairing_code_hint),
                    style = BitwardenTheme.typography.bodyMedium,
                    color = BitwardenTheme.colorScheme.text.primary,
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .padding(32.dp),
                )
            }
            return@BitwardenScaffold
        }

        var showManual by rememberSaveable { mutableStateOf(false) }
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState()),
        ) {
            Spacer(modifier = Modifier.height(12.dp))
            Body(stringResource(id = BitwardenString.pc_autofill_description), margin)
            Spacer(modifier = Modifier.height(16.dp))
            BitwardenFilledButton(
                label = stringResource(id = BitwardenString.scan_qr_code_from_computer),
                onClick = onScanClick,
                modifier = margin,
            )
            Spacer(modifier = Modifier.height(8.dp))
            Body(stringResource(id = BitwardenString.scan_qr_code_from_computer_hint), margin)

            if (data.pcs.isNotEmpty()) {
                Spacer(modifier = Modifier.height(24.dp))
                Title(stringResource(id = BitwardenString.paired_computers), margin)
                data.pcs.forEach { pc ->
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(
                        modifier = margin,
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Body(pc.name, Modifier.weight(1f))
                        BitwardenOutlinedErrorButton(
                            label = stringResource(id = BitwardenString.unpair),
                            onClick = { viewModel.trySendAction(PcAutofillAction.UnpairClick(pc.id)) },
                        )
                    }
                }
            }

            data.phoneId?.let { phoneId ->
                Spacer(modifier = Modifier.height(24.dp))
                Body(
                    stringResource(BitwardenString.phone_id_x, phoneId) + " · " + stringResource(
                        if (data.connected) {
                            BitwardenString.relay_connected
                        } else {
                            BitwardenString.relay_not_connected
                        },
                    ),
                    margin,
                )
            }

            Spacer(modifier = Modifier.height(16.dp))
            BitwardenTextButton(
                label = stringResource(id = BitwardenString.pair_manually),
                onClick = { showManual = !showManual },
                modifier = Modifier.standardHorizontalMargin(),
            )
            if (showManual) {
                ManualPairing(state = state, viewModel = viewModel, margin = margin)
            }
            Spacer(modifier = Modifier.height(16.dp))
            Spacer(modifier = Modifier.navigationBarsPadding())
        }
    }
}

/** The original flow: relay URL, phone ID typed on the PC, and a 5-word comparison. */
@Composable
private fun ManualPairing(
    state: PcAutofillScreenState,
    viewModel: PcAutofillViewModel,
    margin: Modifier,
) {
    val data = state.data
    Column {
        BitwardenTextField(
            label = stringResource(id = BitwardenString.relay_url),
            value = state.relayUrlInput.ifEmpty { data.relayUrl.orEmpty() },
            onValueChange = { viewModel.trySendAction(PcAutofillAction.RelayUrlChange(it)) },
            cardStyle = CardStyle.Full,
            modifier = margin,
        )
        Spacer(modifier = Modifier.height(12.dp))
        BitwardenOutlinedButton(
            label = stringResource(id = BitwardenString.register_with_relay),
            onClick = { viewModel.trySendAction(PcAutofillAction.RegisterClick) },
            modifier = margin,
        )
        if (data.phoneId == null) return@Column
        Spacer(modifier = Modifier.height(12.dp))
        when (val pairing = data.pairing) {
            null -> BitwardenOutlinedButton(
                label = stringResource(id = BitwardenString.pair_a_computer),
                onClick = { viewModel.trySendAction(PcAutofillAction.StartPairingClick) },
                modifier = margin,
            )

            PcPairing.Waiting -> Body(stringResource(id = BitwardenString.waiting_for_computer), margin)
            is PcPairing.Confirm -> {
                Body(stringResource(BitwardenString.pair_with_x_compare_words, pairing.pcName), margin)
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = pairing.phrase,
                    style = BitwardenTheme.typography.titleMedium,
                    fontFamily = FontFamily.Monospace,
                    color = BitwardenTheme.colorScheme.text.primary,
                    modifier = margin,
                )
                Spacer(modifier = Modifier.height(12.dp))
                BitwardenFilledButton(
                    label = stringResource(id = BitwardenString.words_match_pair),
                    onClick = { viewModel.trySendAction(PcAutofillAction.AcceptPairingClick) },
                    modifier = margin,
                )
                Spacer(modifier = Modifier.height(8.dp))
                BitwardenOutlinedErrorButton(
                    label = stringResource(id = BitwardenString.words_dont_match),
                    onClick = { viewModel.trySendAction(PcAutofillAction.RejectPairingClick) },
                    modifier = margin,
                )
            }
        }
    }
}

@Composable
private fun Title(text: String, modifier: Modifier) = Text(
    text = text,
    style = BitwardenTheme.typography.titleSmall,
    color = BitwardenTheme.colorScheme.text.primary,
    modifier = modifier,
)

@Composable
private fun Body(text: String, modifier: Modifier) = Text(
    text = text,
    style = BitwardenTheme.typography.bodyMedium,
    color = BitwardenTheme.colorScheme.text.secondary,
    modifier = modifier,
)
