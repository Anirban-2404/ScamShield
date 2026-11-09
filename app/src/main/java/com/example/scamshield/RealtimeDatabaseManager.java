
package com.example.scamshield;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseUser;
import com.google.firebase.database.DatabaseReference;
import com.google.firebase.database.FirebaseDatabase;
import com.google.firebase.database.ServerValue;

import java.util.HashMap;
import java.util.Map;

public class RealtimeDatabaseManager {

    public interface UpdateCallback {
        void onSuccess();
        void onFailure(Exception error);
    }

    // Synchronize complete statistics using local SQLite data.
    public static void syncScanStatistics(
            int messageCount,
            int urlCount,
            int highRiskCount,
            long lastScanAt,
            UpdateCallback callback
    ) {

        FirebaseUser user =
                FirebaseAuth.getInstance().getCurrentUser();

        if (user == null) {
            if (callback != null) {
                callback.onFailure(
                        new IllegalStateException("User is not logged in.")
                );
            }
            return;
        }

        Map<String, Object> stats = new HashMap<>();

        stats.put("totalMessageScans", messageCount);
        stats.put("totalUrlScans", urlCount);
        stats.put("highRiskDetections", highRiskCount);
        stats.put("lastScanAt", lastScanAt);
        stats.put("lastUpdatedAt", ServerValue.TIMESTAMP);

        FirebaseDatabase.getInstance()
                .getReference("users")
                .child(user.getUid())
                .child("stats")
                .updateChildren(stats)
                .addOnSuccessListener(unused -> {
                    if (callback != null) {
                        callback.onSuccess();
                    }
                })
                .addOnFailureListener(error -> {
                    if (callback != null) {
                        callback.onFailure(error);
                    }
                });
    }

    // Increment statistics for an individual scan.
    public static void updateScanStatistics(
            String scanType,
            int riskScore,
            long scannedAt,
            UpdateCallback callback
    ) {

        FirebaseUser user =
                FirebaseAuth.getInstance().getCurrentUser();

        if (user == null) {
            if (callback != null) {
                callback.onFailure(
                        new IllegalStateException("User is not logged in.")
                );
            }
            return;
        }

        String uid = user.getUid();

        DatabaseReference statsRef =
                FirebaseDatabase.getInstance()
                        .getReference("users")
                        .child(uid)
                        .child("stats");

        Map<String, Object> updates = new HashMap<>();

        if ("MESSAGE".equalsIgnoreCase(scanType)) {
            updates.put("totalMessageScans", ServerValue.increment(1));
        } else if ("URL".equalsIgnoreCase(scanType)) {
            updates.put("totalUrlScans", ServerValue.increment(1));
        }

        if (riskScore >= 60) {
            updates.put("highRiskDetections", ServerValue.increment(1));
        }

        updates.put("lastScanAt", scannedAt);
        updates.put("lastUpdatedAt", ServerValue.TIMESTAMP);

        statsRef.updateChildren(updates)
                .addOnSuccessListener(unused -> {
                    if (callback != null) {
                        callback.onSuccess();
                    }
                })
                .addOnFailureListener(error -> {
                    if (callback != null) {
                        callback.onFailure(error);
                    }
                });
    }
}
