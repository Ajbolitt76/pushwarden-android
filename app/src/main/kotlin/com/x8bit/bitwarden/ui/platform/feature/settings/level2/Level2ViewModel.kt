package com.x8bit.bitwarden.ui.platform.feature.settings.level2

import androidx.lifecycle.viewModelScope
import com.bitwarden.ui.platform.base.BaseViewModel
import com.bitwarden.ui.platform.resource.BitwardenString
import com.bitwarden.ui.util.Text
import com.bitwarden.ui.util.asText
import com.x8bit.bitwarden.data.vault.l2.L2SetupError
import com.x8bit.bitwarden.data.vault.l2.L2SetupException
import com.x8bit.bitwarden.data.vault.l2.L2SetupManager
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** Shortest L2 password accepted when creating or changing it (about 4–5 random words). */
private const val MIN_L2_PASSWORD_LENGTH = 20

/**
 * View model for the level 2 settings screen: set up L2, unlock it on this device, change
 * its password, or remove it from this device.
 */
@HiltViewModel
class Level2ViewModel @Inject constructor(
    private val l2SetupManager: L2SetupManager,
) : BaseViewModel<Level2State, Level2Event, Level2Action>(
    initialState = Level2State(isSetUp = l2SetupManager.isSetUp),
) {
    override fun handleAction(action: Level2Action) {
        when (action) {
            Level2Action.BackClick -> sendEvent(Level2Event.NavigateBack)
            Level2Action.PcAutofillClick -> sendEvent(Level2Event.NavigateToPcAutofill)
            Level2Action.DismissDialog -> mutableStateFlow.update { it.copy(dialog = null) }
            is Level2Action.PasswordChange -> mutableStateFlow.update { it.copy(password = action.value) }
            Level2Action.SetUpClick -> run(requireStrong = true) { l2SetupManager.setUp(it) }
            Level2Action.UnlockClick -> run(requireStrong = false) { l2SetupManager.unlock(it) }
            Level2Action.ChangePasswordClick -> {
                run(requireStrong = true) { l2SetupManager.changePassword(it) }
            }

            Level2Action.ForgetClick -> {
                l2SetupManager.forget()
                mutableStateFlow.update { it.copy(isSetUp = false) }
            }

            is Level2Action.Internal.ResultReceive -> handleResult(action)
        }
    }

    private fun run(requireStrong: Boolean, block: suspend (String) -> Result<Unit>) {
        val password = state.password
        if (requireStrong && password.length < MIN_L2_PASSWORD_LENGTH) {
            mutableStateFlow.update {
                it.copy(
                    dialog = Level2State.Dialog.Error(
                        BitwardenString.level_2_password_too_short.asText(),
                    ),
                )
            }
            return
        }
        mutableStateFlow.update { it.copy(dialog = Level2State.Dialog.Loading) }
        viewModelScope.launch {
            sendAction(Level2Action.Internal.ResultReceive(block(password)))
        }
    }

    private fun handleResult(action: Level2Action.Internal.ResultReceive) {
        val error = action.result.exceptionOrNull()
        mutableStateFlow.update {
            it.copy(
                isSetUp = l2SetupManager.isSetUp,
                password = if (error == null) "" else it.password,
                dialog = error?.let { e -> Level2State.Dialog.Error(e.toMessage()) },
            )
        }
    }

    private fun Throwable.toMessage(): Text =
        when ((this as? L2SetupException)?.error) {
            L2SetupError.WRONG_PASSWORD -> BitwardenString.level_2_wrong_password
            L2SetupError.KEY_ITEM_EXISTS -> BitwardenString.level_2_key_item_exists
            L2SetupError.MULTIPLE_KEY_ITEMS -> BitwardenString.level_2_multiple_key_items
            L2SetupError.NO_KEY_ITEM -> BitwardenString.level_2_no_key_item
            L2SetupError.NOT_SET_UP -> BitwardenString.level_2_not_set_up_on_this_device
            L2SetupError.FAILED, null -> BitwardenString.generic_error_message
        }.asText()
}

/**
 * State of the level 2 settings screen.
 */
data class Level2State(
    val isSetUp: Boolean,
    val password: String = "",
    val dialog: Dialog? = null,
) {
    /** Dialogs shown over the screen. */
    sealed class Dialog {
        /** Work in progress (Argon2id can take a few seconds). */
        data object Loading : Dialog()

        /** Something failed. */
        data class Error(val message: Text) : Dialog()
    }
}

/**
 * One-off events for the level 2 settings screen.
 */
sealed class Level2Event {
    /** Leave the screen. */
    data object NavigateBack : Level2Event()

    /** Open the PC autofill (pairing) screen. */
    data object NavigateToPcAutofill : Level2Event()
}

/**
 * User and internal actions on the level 2 settings screen.
 */
sealed class Level2Action {
    /** Back arrow. */
    data object BackClick : Level2Action()

    /** "PC autofill" row. */
    data object PcAutofillClick : Level2Action()

    /** Dialog dismissed. */
    data object DismissDialog : Level2Action()

    /** Password field edited. */
    data class PasswordChange(val value: String) : Level2Action()

    /** "Set up level 2". */
    data object SetUpClick : Level2Action()

    /** "Use level 2 on this device". */
    data object UnlockClick : Level2Action()

    /** "Change level 2 password". */
    data object ChangePasswordClick : Level2Action()

    /** "Remove level 2 from this device". */
    data object ForgetClick : Level2Action()

    /** Internal actions. */
    sealed class Internal : Level2Action() {
        /** A setup step finished. */
        data class ResultReceive(val result: Result<Unit>) : Internal()
    }
}
