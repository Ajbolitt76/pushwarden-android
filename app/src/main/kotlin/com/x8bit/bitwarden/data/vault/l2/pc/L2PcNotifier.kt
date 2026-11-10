package com.x8bit.bitwarden.data.vault.l2.pc

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.app.NotificationChannelCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.bitwarden.annotation.OmitFromCoverage
import com.bitwarden.core.util.toPendingIntentMutabilityFlag
import com.bitwarden.ui.platform.resource.BitwardenDrawable
import com.bitwarden.ui.platform.resource.BitwardenString
import com.x8bit.bitwarden.MainActivity
import com.x8bit.bitwarden.ui.platform.util.PC_AUTOFILL_SHORTCUT_URI

private const val CHANNEL_ID = "l2_pc_fill_requests"
private const val NOTIFICATION_ID = 2_202
private const val REQUEST_CODE = 2_202

/** The relay holds a request for 120 s; the notification shouldn't outlive it by much. */
private const val TIMEOUT_MILLIS = 120_000L

/**
 * Shows "PC fill request" when the relay wakes the phone. The wake carries no content, so the
 * notification only opens the PC autofill screen, where the request is fetched and approved.
 */
@OmitFromCoverage
class L2PcNotifier(private val context: Context) {
    /** Posts (or replaces) the fill request notification. */
    @SuppressLint("MissingPermission")
    fun notifyFillRequest() {
        val manager = NotificationManagerCompat.from(context)
        manager.createNotificationChannel(
            NotificationChannelCompat
                .Builder(CHANNEL_ID, NotificationManagerCompat.IMPORTANCE_HIGH)
                .setName(context.getString(BitwardenString.pc_fill_requests))
                .build(),
        )
        if (!manager.areNotificationsEnabled()) return
        val intent = Intent(context, MainActivity::class.java)
            .setData(Uri.parse(PC_AUTOFILL_SHORTCUT_URI))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val content = PendingIntent.getActivity(
            context,
            REQUEST_CODE,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT.toPendingIntentMutabilityFlag(),
        )
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setContentTitle(context.getString(BitwardenString.pc_fill_request))
            .setContentText(context.getString(BitwardenString.pc_fill_request_tap_to_review))
            .setSmallIcon(BitwardenDrawable.ic_notification)
            .setContentIntent(content)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setAutoCancel(true)
            .setTimeoutAfter(TIMEOUT_MILLIS)
            .build()
        manager.notify(NOTIFICATION_ID, notification)
    }
}
