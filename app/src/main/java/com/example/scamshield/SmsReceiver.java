package com.example.scamshield;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.provider.Telephony;
import android.telephony.SmsMessage;
import android.util.Log;

import com.google.firebase.auth.FirebaseAuth;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SmsReceiver extends BroadcastReceiver {

    private static final String TAG = "ScamShieldSMS";

    private static final ExecutorService executor =
            Executors.newSingleThreadExecutor();

    @Override
    public void onReceive(Context context, Intent intent) {

        if (intent == null ||
                !Telephony.Sms.Intents.SMS_RECEIVED_ACTION
                        .equals(intent.getAction())) {
            return;
        }

        SharedPreferences preferences =
                context.getSharedPreferences(
                        "ScamShieldData",
                        Context.MODE_PRIVATE
                );

        // Scan only when ScamShield protection is enabled.
        if (!preferences.getBoolean("protection_active", false)) {
            return;
        }

        // A Firebase account must be logged in.
        if (FirebaseAuth.getInstance().getCurrentUser() == null) {
            Log.d(TAG, "No authenticated user. SMS scan skipped.");
            return;
        }

        final PendingResult pendingResult = goAsync();

        executor.execute(() -> {

            ScanDatabaseHelper databaseHelper = null;

            try {

                SmsMessage[] messages =
                        Telephony.Sms.Intents.getMessagesFromIntent(intent);

                if (messages == null || messages.length == 0) {
                    return;
                }

                StringBuilder body = new StringBuilder();

                long receivedAt = 0;

                for (SmsMessage sms : messages) {

                    if (sms == null) {
                        continue;
                    }

                    body.append(sms.getMessageBody());

                    receivedAt = Math.max(
                            receivedAt,
                            sms.getTimestampMillis()
                    );
                }

                String message = body.toString().trim();

                if (message.isEmpty()) {
                    return;
                }

                // Analyze the entire SMS locally.
                SmsScanner.ScanResult messageResult =
                        SmsScanner.scanMessage(message);

                databaseHelper = new ScanDatabaseHelper(
                        context.getApplicationContext()
                );

                long timestamp = receivedAt > 0
                        ? receivedAt
                        : System.currentTimeMillis();

                // Save the SMS only if it is suspicious.
                if (messageResult.messageScore >= 30) {

                    databaseHelper.insertScan(
                            "MESSAGE",
                            message,
                            messageResult.messageScore,
                            SmsScanner.getRiskLevel(
                                    messageResult.messageScore
                            ),
                            messageResult.messageReasons.toString(),
                            timestamp
                    );

                    Log.d(TAG, "Suspicious SMS detected and saved.");
                }

                // Inspect every URL found in the SMS.
                for (String url : messageResult.urls) {

                    SmsScanner.UrlResult urlResult =
                            SmsScanner.scanUrl(url);

                    if (urlResult.score >= 30) {

                        databaseHelper.insertScan(
                                "URL",
                                url,
                                urlResult.score,
                                SmsScanner.getRiskLevel(urlResult.score),
                                urlResult.reasons.toString(),
                                timestamp
                        );

                        Log.d(TAG, "Suspicious URL detected and saved.");
                    }
                }

            } catch (Exception e) {

                Log.e(TAG, "Automatic SMS scanning failed.", e);

            } finally {

                if (databaseHelper != null) {
                    databaseHelper.close();
                }

                pendingResult.finish();
            }
        });
    }
}