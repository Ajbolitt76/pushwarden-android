package com.x8bit.bitwarden.ui.platform.feature.settings.level2

import androidx.navigation.NavController
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavOptions
import com.bitwarden.ui.platform.base.util.composableWithPushTransitions
import kotlinx.serialization.Serializable

/**
 * The type-safe route for the PC autofill screen.
 */
@Serializable
data object PcAutofillRoute

/**
 * Add the PC autofill destination to the nav graph.
 */
fun NavGraphBuilder.pcAutofillDestination(onNavigateBack: () -> Unit) {
    composableWithPushTransitions<PcAutofillRoute> {
        PcAutofillScreen(onNavigateBack = onNavigateBack)
    }
}

/**
 * Navigate to the PC autofill screen.
 */
fun NavController.navigateToPcAutofill(navOptions: NavOptions? = null) {
    this.navigate(route = PcAutofillRoute, navOptions = navOptions)
}
