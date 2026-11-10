package com.x8bit.bitwarden.ui.auth.feature.welcome

import android.os.Parcelable
import androidx.lifecycle.viewModelScope
import com.bitwarden.data.datasource.disk.model.ServerConfig
import com.bitwarden.data.repository.ServerConfigRepository
import com.bitwarden.ui.platform.base.BaseViewModel
import com.bitwarden.ui.platform.resource.BitwardenDrawable
import com.bitwarden.ui.platform.resource.BitwardenString
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.update
import kotlinx.parcelize.Parcelize
import javax.inject.Inject

/**
 * Manages application state for the welcome screen.
 */
@HiltViewModel
class WelcomeViewModel @Inject constructor(
    serverConfigRepository: ServerConfigRepository,
) : BaseViewModel<WelcomeState, WelcomeEvent, WelcomeAction>(
    initialState = WelcomeState(
        index = 0,
        pages = listOf(
            WelcomeState.WelcomeCard.CardOne,
            WelcomeState.WelcomeCard.CardTwo,
            WelcomeState.WelcomeCard.CardThree,
            WelcomeState.WelcomeCard.CardFour,
        ),
        disableCreateAccount = serverConfigRepository
            .serverConfigStateFlow
            .value
            ?.serverData
            ?.settings
            ?.disableUserRegistration == true,
    ),
) {

    init {
        serverConfigRepository
            .serverConfigStateFlow
            .map { WelcomeAction.Internal.ServerConfigReceived(it) }
            .onEach(::sendAction)
            .launchIn(viewModelScope)
    }

    override fun handleAction(action: WelcomeAction) {
        when (action) {
            is WelcomeAction.PagerSwipe -> handlePagerSwipe(action)
            is WelcomeAction.DotClick -> handleDotClick(action)
            WelcomeAction.CreateAccountClick -> handleCreateAccountClick()
            WelcomeAction.LoginClick -> handleLoginClick()
            is WelcomeAction.Internal -> handleInternalAction(action)
        }
    }

    private fun handleInternalAction(action: WelcomeAction.Internal) {
        when (action) {
            is WelcomeAction.Internal.ServerConfigReceived -> handleServerConfigReceived(action)
        }
    }

    private fun handlePagerSwipe(action: WelcomeAction.PagerSwipe) {
        mutableStateFlow.update { it.copy(index = action.index) }
    }

    private fun handleDotClick(action: WelcomeAction.DotClick) {
        mutableStateFlow.update { it.copy(index = action.index) }
        sendEvent(WelcomeEvent.UpdatePager(index = action.index))
    }

    private fun handleCreateAccountClick() {
        sendEvent(WelcomeEvent.NavigateToStartRegistration)
    }

    private fun handleLoginClick() {
        sendEvent(WelcomeEvent.NavigateToLogin)
    }

    private fun handleServerConfigReceived(action: WelcomeAction.Internal.ServerConfigReceived) {
        mutableStateFlow.update {
            it.copy(
                disableCreateAccount = action
                    .serverConfig
                    ?.serverData
                    ?.settings
                    ?.disableUserRegistration == true,
            )
        }
    }
}

/**
 * Models state of the welcome screen.
 */
@Parcelize
data class WelcomeState(
    val index: Int,
    val pages: List<WelcomeCard>,
    val disableCreateAccount: Boolean,
) : Parcelable {
    /**
     * Determines if the user should be allowed to create a new account.
     */
    val allowCreateAccount: Boolean get() = !disableCreateAccount

    /**
     * A sealed class to represent the different cards the user can view on the welcome screen.
     */
    sealed class WelcomeCard : Parcelable {
        abstract val imageRes: Int
        abstract val titleRes: Int
        abstract val messageRes: Int

        /**
         * Represents the first card the user should see on the welcome screen.
         */
        @Parcelize
        data object CardOne : WelcomeCard() {
            override val imageRes: Int get() = BitwardenDrawable.logo_bitwarden_icon
            override val titleRes: Int get() = BitwardenString.welcome_to_pushwarden
            override val messageRes: Int get() = BitwardenString.pushwarden_is_an_independent_fork_of_bitwarden
        }

        /**
         * Represents the second card the user should see on the welcome screen.
         */
        @Parcelize
        data object CardTwo : WelcomeCard() {
            override val imageRes: Int get() = BitwardenDrawable.ill_lock
            override val titleRes: Int get() = BitwardenString.level_2_badge
            override val messageRes: Int get() = BitwardenString.mark_your_most_important_logins_as_protected
        }

        /**
         * Represents the third card the user should see on the welcome screen.
         */
        @Parcelize
        data object CardThree : WelcomeCard() {
            override val imageRes: Int get() = BitwardenDrawable.ill_items
            override val titleRes: Int get() = BitwardenString.set_it_up_on_this_phone
            override val messageRes: Int get() = BitwardenString.after_you_log_in_open_settings_protected_items
        }

        /**
         * Represents the fourth card the user should see on the welcome screen.
         */
        @Parcelize
        data object CardFour : WelcomeCard() {
            override val imageRes: Int get() = BitwardenDrawable.ill_secure_devices
            override val titleRes: Int get() = BitwardenString.connect_your_computer
            override val messageRes: Int get() = BitwardenString.install_the_pushwarden_browser_extension_and_pair
        }
    }
}

/**
 * Models events for the welcome screen.
 */
sealed class WelcomeEvent {
    /**
     * Updates the current index of the pager.
     */
    data class UpdatePager(
        val index: Int,
    ) : WelcomeEvent()

    /**
     * Navigates to the login screen.
     */
    data object NavigateToLogin : WelcomeEvent()

    /**
     * Navigates to the start registration screen.
     */
    data object NavigateToStartRegistration : WelcomeEvent()
}

/**
 * Models actions for the welcome screen.
 */
sealed class WelcomeAction {
    /**
     * Swipe the pager to the given [index].
     */
    data class PagerSwipe(
        val index: Int,
    ) : WelcomeAction()

    /**
     * Click one of the page indicator dots at the given [index].
     */
    data class DotClick(
        val index: Int,
    ) : WelcomeAction()

    /**
     * Click the create account button.
     */
    data object CreateAccountClick : WelcomeAction()

    /**
     * Click the login button.
     */
    data object LoginClick : WelcomeAction()

    /**
     * Actions for internal use by the ViewModel.
     */
    sealed class Internal : WelcomeAction() {
        /**
         * Indicates that an updated [serverConfig] has been received.
         */
        data class ServerConfigReceived(
            val serverConfig: ServerConfig?,
        ) : Internal()
    }
}
