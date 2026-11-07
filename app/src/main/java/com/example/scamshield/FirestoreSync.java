
package com.example.scamshield;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseUser;
import com.google.firebase.firestore.FirebaseFirestore;

import java.util.HashMap;
import java.util.Map;

public class FirestoreSync {

    public interface SyncCallback {
        void onSuccess();
        void onFailure(Exception error);
    }

    public static void uploadScan(
            ScanRecord scan,
            SyncCallback callback
    ) {
        FirebaseUser user =
                FirebaseAuth.getInstance().getCurrentUser();

        if (user == null) {
            callback.onFailure(
                    new IllegalStateException("Please log in first.")
            );
            return;
        }

        String uid = user.getUid();

        Map<String, Object> data = new HashMap<>();
        data.put("userUid", uid);
        data.put("scanId", String.valueOf(scan.getId()));
        data.put("scanType", scan.getScanType());
        data.put("scannedContent", scan.getScannedContent());
        data.put("riskScore", scan.getRiskScore());
        data.put("riskLevel", scan.getRiskLevel());
        data.put("explanation", scan.getExplanation());
        data.put("scannedAt", scan.getScannedAt());

        FirebaseFirestore.getInstance()
                .collection("users")
                .document(uid)
                .collection("scans")
                .add(data)
                .addOnSuccessListener(documentReference ->
                        callback.onSuccess()
                )
                .addOnFailureListener(callback::onFailure);
    }
}
