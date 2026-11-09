
package com.example.scamshield;

import com.google.firebase.firestore.CollectionReference;
import com.google.firebase.firestore.DocumentSnapshot;
import com.google.firebase.firestore.WriteBatch;

import java.util.List;

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


    public static void deleteAllScans(
            String uid,
            SyncCallback callback
    ) {

        if (uid == null || uid.trim().isEmpty()) {
            callback.onFailure(
                    new IllegalArgumentException("Invalid user ID.")
            );
            return;
        }

        FirebaseFirestore firestore = FirebaseFirestore.getInstance();

        CollectionReference scansRef = firestore
                .collection("users")
                .document(uid)
                .collection("scans");

        scansRef.get()
                .addOnSuccessListener(snapshot -> {

                    List<DocumentSnapshot> documents =
                            snapshot.getDocuments();

                    deleteBatch(scansRef, documents, 0, callback);
                })
                .addOnFailureListener(callback::onFailure);
    }

    private static void deleteBatch(
            CollectionReference collection,
            List<DocumentSnapshot> documents,
            int startIndex,
            SyncCallback callback
    ) {

        if (startIndex >= documents.size()) {
            callback.onSuccess();
            return;
        }

        FirebaseFirestore firestore = FirebaseFirestore.getInstance();

        WriteBatch batch = firestore.batch();

        int endIndex = Math.min(startIndex + 500, documents.size());

        for (int i = startIndex; i < endIndex; i++) {
            batch.delete(documents.get(i).getReference());
        }

        batch.commit()
                .addOnSuccessListener(unused ->
                        deleteBatch(
                                collection,
                                documents,
                                endIndex,
                                callback
                        )
                )
                .addOnFailureListener(callback::onFailure);
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
                .document(String.valueOf(scan.getId()))
                .set(data)
                .addOnSuccessListener(result ->
                        callback.onSuccess()
                )
                .addOnFailureListener(callback::onFailure);
    }
}
