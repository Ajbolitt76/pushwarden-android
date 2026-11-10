package com.x8bit.bitwarden.ui.platform.feature.settings.level2

import androidx.navigation.NavController
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavOptions
import com.bitwarden.ui.platform.base.util.composableWithPushTransitions
import kotlinx.serialization.Serializable

/**
 * The type-safe route for the level 2 settings screen.
 */
@Serializable
data object Level2Route

/**
 * Add the level 2 settings destination to the nav graph.
 */
fun NavGraphBuilder.level2Destination(
    onNavigateBack: () -> Unit,
    onNavigateToPcAutofill: () -> Unit,
) {
    composableWithPushTransitions<Level2Route> {
        Level2Screen(
            onNavigateBack = onNavigateBack,
            onNavigateToPcAutofill = onNavigateToPcAutofill,
        )
    }
}

/**
 * Navigate to the level 2 settings screen.
 */
fun NavController.navigateToLevel2(navOptions: NavOptions? = null) {
    this.navigate(route = Level2Route, navOptions = navOptions)
}
