package com.x8bit.bitwarden.data.push

import com.bitwarden.annotation.OmitFromCoverage
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import com.x8bit.bitwarden.data.platform.manager.PushManager
import com.x8bit.bitwarden.data.vault.l2.pc.L2PcAutofillManager
import com.x8bit.bitwarden.data.vault.l2.pc.L2PcNotifier
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject

/**
 * Handles setup and receiving of push notifications.
 */
@OmitFromCoverage
@AndroidEntryPoint
class BitwardenFirebaseMessagingService : FirebaseMessagingService() {
    @Inject
    lateinit var pushManager: PushManager

    @Inject
    lateinit var l2PcAutofillManager: L2PcAutofillManager

    @Inject
    lateinit var l2PcNotifier: L2PcNotifier

    override fun onMessageReceived(message: RemoteMessage) {
        // Our relay's wake-up (PROTOCOL.md §3) carries no content: just ask the user to open
        // the app. Anything else is Bitwarden's own push format.
        if (message.data["t"] == "wake") {
            l2PcNotifier.notifyFillRequest()
            return
        }
        pushManager.onMessageReceived(message.data)
    }

    override fun onNewToken(token: String) {
        pushManager.registerPushTokenIfNecessary(token)
        l2PcAutofillManager.onPushToken(token)
    }
}
