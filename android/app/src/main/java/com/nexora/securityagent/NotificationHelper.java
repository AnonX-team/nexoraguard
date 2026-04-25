package com.nexora.securityagent;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import androidx.core.app.NotificationCompat;

/**
 * Handles creating notification channels and posting threat alerts.
 */
public class NotificationHelper {

    public static final String CHANNEL_THREATS = "nexora_threats";
    private static final int NOTIF_ID_THREAT = 1001;

    public static void createChannel(Context context) {
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_THREATS,
                context.getString(R.string.channel_threats),
                NotificationManager.IMPORTANCE_HIGH
        );
        channel.setDescription(context.getString(R.string.channel_threats_desc));
        channel.enableVibration(true);
        channel.enableLights(true);
        channel.setLightColor(0xFF00E5FF);

        NotificationManager nm = context.getSystemService(NotificationManager.class);
        nm.createNotificationChannel(channel);
    }

    public static void postThreatAlert(Context context, String riskLevel, String summary) {
        Intent intent = new Intent(context, MainActivity.class);
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent pi = PendingIntent.getActivity(
                context, 0, intent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        int color = "CRITICAL".equals(riskLevel) ? 0xFFD32F2F : 0xFFF57C00;

        NotificationCompat.Builder builder = new NotificationCompat.Builder(context, CHANNEL_THREATS)
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle("NexoraGuard — " + riskLevel + " Threat")
                .setContentText(summary != null ? summary : "Threat detected on your system")
                .setStyle(new NotificationCompat.BigTextStyle()
                        .bigText(summary != null ? summary : "Threat detected on your system"))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setColor(color)
                .setAutoCancel(true)
                .setContentIntent(pi);

        NotificationManager nm = context.getSystemService(NotificationManager.class);
        nm.notify(NOTIF_ID_THREAT, builder.build());
    }
}
