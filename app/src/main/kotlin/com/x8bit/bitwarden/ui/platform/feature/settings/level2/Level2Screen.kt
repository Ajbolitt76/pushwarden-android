package com.x8bit.bitwarden.ui.platform.feature.settings.level2

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.bitwarden.ui.platform.base.util.EventsEffect
import com.bitwarden.ui.platform.base.util.standardHorizontalMargin
import com.bitwarden.ui.platform.components.appbar.BitwardenTopAppBar
import com.bitwarden.ui.platform.components.button.BitwardenFilledButton
import com.bitwarden.ui.platform.components.button.BitwardenOutlinedButton
import com.bitwarden.ui.platform.components.button.BitwardenOutlinedErrorButton
import com.bitwarden.ui.platform.components.dialog.BitwardenBasicDialog
import com.bitwarden.ui.platform.components.dialog.BitwardenLoadingDialog
import com.bitwarden.ui.platform.components.field.BitwardenPasswordField
import com.bitwarden.ui.platform.components.model.CardStyle
import com.bitwarden.ui.platform.components.row.BitwardenTextRow
import com.bitwarden.ui.platform.components.scaffold.BitwardenScaffold
import com.bitwarden.ui.platform.components.util.rememberVectorPainter
import com.bitwarden.ui.platform.resource.BitwardenDrawable
import com.bitwarden.ui.platform.resource.BitwardenString
import com.bitwarden.ui.platform.theme.BitwardenTheme

/**
 * Level 2 settings: set up, unlock on this device, change password, remove, PC autofill.
 */
@Suppress("LongMethod")
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun Level2Screen(
    onNavigateBack: () -> Unit,
    onNavigateToPcAutofill: () -> Unit,
    viewModel: Level2ViewModel = hiltViewModel(),
) {
    val state by viewModel.stateFlow.collectAsStateWithLifecycle()
    EventsEffect(viewModel = viewModel) { event ->
        when (event) {
            Level2Event.NavigateBack -> onNavigateBack()
            Level2Event.NavigateToPcAutofill -> onNavigateToPcAutofill()
        }
    }

    when (val dialog = state.dialog) {
        Level2State.Dialog.Loading -> BitwardenLoadingDialog(
            text = stringResource(id = BitwardenString.loading),
        )

        is Level2State.Dialog.Error -> BitwardenBasicDialog(
            title = stringResource(id = BitwardenString.an_error_has_occurred),
            message = dialog.message(),
            onDismissRequest = { viewModel.trySendAction(Level2Action.DismissDialog) },
        )

        null -> Unit
    }

    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior(rememberTopAppBarState())
    BitwardenScaffold(
        modifier = Modifier
            .fillMaxSize()
            .nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = {
            BitwardenTopAppBar(
                title = stringResource(id = BitwardenString.level_2),
                scrollBehavior = scrollBehavior,
                navigationIcon = rememberVectorPainter(id = BitwardenDrawable.ic_back),
                navigationIconContentDescription = stringResource(id = BitwardenString.back),
                onNavigationIconClick = { viewModel.trySendAction(Level2Action.BackClick) },
            )
        },
    ) {
        var showPassword by rememberSaveable { mutableStateOf(false) }
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState()),
        ) {
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = stringResource(id = BitwardenString.level_2_description),
                style = BitwardenTheme.typography.bodyMedium,
                color = BitwardenTheme.colorScheme.text.primary,
                modifier = Modifier.standardHorizontalMargin(),
            )
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = stringResource(
                    id = if (state.isSetUp) {
                        BitwardenString.level_2_status_set_up
                    } else {
                        BitwardenString.level_2_status_none
                    },
                ),
                style = BitwardenTheme.typography.titleSmall,
                color = BitwardenTheme.colorScheme.text.primary,
                modifier = Modifier.standardHorizontalMargin(),
            )
            Spacer(modifier = Modifier.height(16.dp))
            BitwardenPasswordField(
                label = stringResource(id = BitwardenString.level_2_password),
                value = state.password,
                showPassword = showPassword,
                showPasswordChange = { showPassword = it },
                onValueChange = { viewModel.trySendAction(Level2Action.PasswordChange(it)) },
                supportingText = stringResource(id = BitwardenString.level_2_password_hint),
                cardStyle = CardStyle.Full,
                modifier = Modifier
                    .standardHorizontalMargin()
                    .fillMaxWidth(),
            )
            Spacer(modifier = Modifier.height(16.dp))
            if (state.isSetUp) {
                BitwardenFilledButton(
                    label = stringResource(id = BitwardenString.change_level_2_password),
                    onClick = { viewModel.trySendAction(Level2Action.ChangePasswordClick) },
                    modifier = Modifier.standardHorizontalMargin().fillMaxWidth(),
                )
                Spacer(modifier = Modifier.height(12.dp))
                BitwardenOutlinedErrorButton(
                    label = stringResource(id = BitwardenString.remove_level_2_from_this_device),
                    onClick = { viewModel.trySendAction(Level2Action.ForgetClick) },
                    modifier = Modifier.standardHorizontalMargin().fillMaxWidth(),
                )
                Spacer(modifier = Modifier.height(16.dp))
                BitwardenTextRow(
                    text = stringResource(id = BitwardenString.pc_autofill),
                    onClick = { viewModel.trySendAction(Level2Action.PcAutofillClick) },
                    withDivider = false,
                    cardStyle = CardStyle.Full,
                    modifier = Modifier.standardHorizontalMargin().fillMaxWidth(),
                )
            } else {
                BitwardenFilledButton(
                    label = stringResource(id = BitwardenString.unlock_level_2),
                    onClick = { viewModel.trySendAction(Level2Action.UnlockClick) },
                    modifier = Modifier.standardHorizontalMargin().fillMaxWidth(),
                )
                Spacer(modifier = Modifier.height(12.dp))
                BitwardenOutlinedButton(
                    label = stringResource(id = BitwardenString.set_up_level_2),
                    onClick = { viewModel.trySendAction(Level2Action.SetUpClick) },
                    modifier = Modifier.standardHorizontalMargin().fillMaxWidth(),
                )
            }
            Spacer(modifier = Modifier.height(16.dp))
            Spacer(modifier = Modifier.navigationBarsPadding())
        }
    }
}
