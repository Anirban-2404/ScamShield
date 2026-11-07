
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

    public static void updateScanStatistics(
            String scanType,
            int riskScore,
            long scannedAt,
            UpdateCallback callback
    ) {

        FirebaseUser user =
                FirebaseAuth.getInstance().getCurrentUser();

        if (user == null) {
            callback.onFailure(
                    new IllegalStateException("User is not logged in.")
            );
            return;
        }

        String uid = user.getUid();

        DatabaseReference statsRef =
                FirebaseDatabase.getInstance()
                        .getReference("users")
                        .child(uid)
                        .child("stats");

        Map<String, Object> updates = new HashMap<>();

        // Increment the appropriate scan counter.
        if ("MESSAGE".equalsIgnoreCase(scanType)) {
            updates.put("totalMessageScans", ServerValue.increment(1));
        } else if ("URL".equalsIgnoreCase(scanType)) {
            updates.put("totalUrlScans", ServerValue.increment(1));
        }

        // Count high-risk detections (score >= 70).
        if (riskScore >= 70) {
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
