package com.x8bit.bitwarden.ui.platform.feature.settings.level2

import android.os.Build
import androidx.lifecycle.viewModelScope
import com.bitwarden.ui.platform.base.BaseViewModel
import com.x8bit.bitwarden.data.vault.l2.pc.L2PcAutofillManager
import com.x8bit.bitwarden.data.vault.l2.pc.L2QrPair
import com.x8bit.bitwarden.data.vault.l2.pc.PcAutofillState
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * View model for the PC autofill screen: pairing by QR code (default) or manually, and the list
 * of paired computers. The relay connection itself is managed by [L2PcAutofillManager].
 */
@HiltViewModel
class PcAutofillViewModel @Inject constructor(
    private val manager: L2PcAutofillManager,
) : BaseViewModel<PcAutofillScreenState, PcAutofillEvent, PcAutofillAction>(
    initialState = PcAutofillScreenState(data = manager.stateFlow.value),
) {
    init {
        manager.stateFlow
            .map { PcAutofillAction.Internal.StateReceive(it) }
            .onEach(::sendAction)
            .launchIn(viewModelScope)
    }

    override fun handleAction(action: PcAutofillAction) {
        when (action) {
            PcAutofillAction.BackClick -> sendEvent(PcAutofillEvent.NavigateBack)
            PcAutofillAction.ScanClick -> mutableStateFlow.update { it.copy(scanning = true) }
            PcAutofillAction.ScanCancel -> mutableStateFlow.update { it.copy(scanning = false) }
            is PcAutofillAction.QrScanned -> handleQrScanned(action.text)
            PcAutofillAction.QrPairConfirm -> {
                sendEvent(PcAutofillEvent.VerifyUser(VerifiedAction.PairQr))
            }

            PcAutofillAction.QrPairCancel -> mutableStateFlow.update { it.copy(pendingQr = null) }
            is PcAutofillAction.RelayUrlChange -> mutableStateFlow.update {
                it.copy(relayUrlInput = action.value)
            }

            PcAutofillAction.RegisterClick -> handleRegister()
            PcAutofillAction.StartPairingClick -> manager.startPairing()
            PcAutofillAction.RejectPairingClick -> manager.finishPairing(accept = false)
            PcAutofillAction.AcceptPairingClick -> {
                sendEvent(PcAutofillEvent.VerifyUser(VerifiedAction.Pair))
            }

            is PcAutofillAction.UnpairClick -> manager.unpair(action.pcId)
            is PcAutofillAction.UserVerified -> handleUserVerified(action.action)
            PcAutofillAction.DismissMessage -> mutableStateFlow.update { it.copy(message = null) }
            is PcAutofillAction.Internal.StateReceive -> mutableStateFlow.update {
                it.copy(data = action.data)
            }

            is PcAutofillAction.Internal.Result -> mutableStateFlow.update {
                it.copy(loading = false, message = action.message)
            }
        }
    }

    private fun handleQrScanned(text: String) {
        if (!state.scanning) return // the analyzer keeps reporting until the camera closes
        val qr = L2QrPair.parse(text)
        mutableStateFlow.update {
            it.copy(
                scanning = false,
                pendingQr = qr,
                message = if (qr == null) PcAutofillMessage.NOT_A_PAIRING_CODE else null,
            )
        }
    }

    private fun handleUserVerified(action: VerifiedAction) {
        when (action) {
            VerifiedAction.Pair -> manager.finishPairing(accept = true)
            VerifiedAction.PairQr -> {
                val qr = state.pendingQr ?: return
                mutableStateFlow.update { it.copy(pendingQr = null, loading = true) }
                viewModelScope.launch {
                    val ok = manager.pairWithQr(qr, phoneName = Build.MODEL ?: "Phone").isSuccess
                    sendAction(
                        PcAutofillAction.Internal.Result(
                            if (ok) PcAutofillMessage.PAIRED else PcAutofillMessage.FAILED,
                        ),
                    )
                }
            }
        }
    }

    private fun handleRegister() {
        val url = state.relayUrlInput.ifBlank { state.data.relayUrl.orEmpty() }
        mutableStateFlow.update { it.copy(loading = true) }
        viewModelScope.launch {
            val ok = manager.register(url).isSuccess
            sendAction(
                PcAutofillAction.Internal.Result(if (ok) null else PcAutofillMessage.FAILED),
            )
        }
    }
}

/** What the user verified for. */
sealed class VerifiedAction {
    /** Accept a manual (word phrase) pairing. */
    data object Pair : VerifiedAction()

    /** Pair with the computer whose QR code was scanned. */
    data object PairQr : VerifiedAction()
}

/** One-line results shown in a dialog. */
enum class PcAutofillMessage {
    PAIRED,
    FAILED,
    NOT_A_PAIRING_CODE,
}

/**
 * State of the PC autofill screen.
 */
data class PcAutofillScreenState(
    val data: PcAutofillState,
    val relayUrlInput: String = "",
    val loading: Boolean = false,
    val scanning: Boolean = false,
    val pendingQr: L2QrPair? = null,
    val message: PcAutofillMessage? = null,
)

/**
 * One-off events of the PC autofill screen.
 */
sealed class PcAutofillEvent {
    /** Leave the screen. */
    data object NavigateBack : PcAutofillEvent()

    /** Ask for biometrics or the device credential before [action]. */
    data class VerifyUser(val action: VerifiedAction) : PcAutofillEvent()
}

/**
 * Actions on the PC autofill screen.
 */
sealed class PcAutofillAction {
    /** Back arrow. */
    data object BackClick : PcAutofillAction()

    /** "Scan QR code" (camera permission already granted). */
    data object ScanClick : PcAutofillAction()

    /** Camera closed without a code. */
    data object ScanCancel : PcAutofillAction()

    /** The camera read [text]. */
    data class QrScanned(val text: String) : PcAutofillAction()

    /** "Pair" in the QR confirmation dialog. */
    data object QrPairConfirm : PcAutofillAction()

    /** "Cancel" in the QR confirmation dialog. */
    data object QrPairCancel : PcAutofillAction()

    /** Relay URL edited (manual pairing). */
    data class RelayUrlChange(val value: String) : PcAutofillAction()

    /** "Register with relay" (manual pairing). */
    data object RegisterClick : PcAutofillAction()

    /** "Pair with words" (manual pairing). */
    data object StartPairingClick : PcAutofillAction()

    /** "Words match, pair". */
    data object AcceptPairingClick : PcAutofillAction()

    /** "Words don't match". */
    data object RejectPairingClick : PcAutofillAction()

    /** Unpair a computer. */
    data class UnpairClick(val pcId: String) : PcAutofillAction()

    /** The user passed biometrics or device credential for [action]. */
    data class UserVerified(val action: VerifiedAction) : PcAutofillAction()

    /** Result dialog dismissed. */
    data object DismissMessage : PcAutofillAction()

    /** Internal actions. */
    sealed class Internal : PcAutofillAction() {
        /** Manager state changed. */
        data class StateReceive(val data: PcAutofillState) : Internal()

        /** Registration or pairing finished; [message] to show, if any. */
        data class Result(val message: PcAutofillMessage?) : Internal()
    }
}
