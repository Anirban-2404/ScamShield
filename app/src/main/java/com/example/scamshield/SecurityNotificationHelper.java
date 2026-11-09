package com.example.scamshield;

import android.Manifest;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;

import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import androidx.core.content.ContextCompat;

public class SecurityNotificationHelper {

    private static final String CHANNEL_ID = "high_risk_alerts";
    private static final String CHANNEL_NAME = "High-Risk Security Alerts";

    public static void showHighRiskNotification(
            Context context,
            String scanType,
            int riskScore,
            String scannedContent
    ) {

        // Only notify for high-risk scans.
        if (riskScore < 60) {
            return;
        }

        // Android 13+ notification permission check.
        if (Build.VERSION.SDK_INT >= 33 &&
                ContextCompat.checkSelfPermission(
                        context,
                        Manifest.permission.POST_NOTIFICATIONS
                ) != PackageManager.PERMISSION_GRANTED) {
            return;
        }

        createNotificationChannel(context);

        Intent intent = new Intent(context, HistoryActivity.class);

        PendingIntent pendingIntent = PendingIntent.getActivity(
                context,
                2001,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT |
                        PendingIntent.FLAG_IMMUTABLE
        );

        String content = scannedContent == null
                ? "Suspicious content detected."
                : scannedContent;

        if (content.length() > 80) {
            content = content.substring(0, 80) + "...";
        }

        NotificationCompat.Builder builder =
                new NotificationCompat.Builder(context, CHANNEL_ID)
                        .setSmallIcon(R.drawable.ic_launcher_foreground)
                        .setContentTitle("Potential Threat Detected!")
                        .setContentText(
                                scanType + " scan detected HIGH RISK (" +
                                        riskScore + "/100)"
                        )
                        .setStyle(
                                new NotificationCompat.BigTextStyle()
                                        .bigText(
                                                "ScamShield detected potentially suspicious " +
                                                        scanType.toLowerCase() +
                                                        " content.\n\n" +
                                                        "Risk Score: " + riskScore + "/100\n\n" +
                                                        "Content: " + content +
                                                        "\n\nOpen ScamShield to review the analysis."
                                        )
                        )
                        .setPriority(NotificationCompat.PRIORITY_HIGH)
                        .setAutoCancel(true)
                        .setContentIntent(pendingIntent);

        int notificationId = (int) (System.currentTimeMillis() & 0x7fffffff);

        NotificationManagerCompat.from(context)
                .notify(notificationId, builder.build());
    }

    private static void createNotificationChannel(Context context) {

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {

            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    CHANNEL_NAME,
                    NotificationManager.IMPORTANCE_HIGH
            );

            channel.setDescription(
                    "Alerts users when a scan detects potentially dangerous content."
            );

            NotificationManager manager =
                    context.getSystemService(NotificationManager.class);

            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
    }
}