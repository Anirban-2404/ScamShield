
package com.example.scamshield;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.util.Log;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseUser;

import java.util.ArrayList;
import java.util.List;

public class ScanDatabaseHelper extends SQLiteOpenHelper {

    private final Context appContext;

    private static final String DATABASE_NAME = "scamshield.db";
    private static final int DATABASE_VERSION = 3;

    private static final String TABLE_SCANS = "scans";

    private static final String COL_ID = "id";
    private static final String COL_SYNCED = "is_synced";
    private static final String COL_TYPE = "scan_type";
    private static final String COL_CONTENT = "scanned_content";
    private static final String COL_SCORE = "risk_score";
    private static final String COL_LEVEL = "risk_level";
    private static final String COL_EXPLANATION = "explanation";
    private static final String COL_TIMESTAMP = "scanned_at";
    private static final String COL_USER_UID = "user_uid";

    private static final String LEGACY_UID = "legacy_unassigned";

    public ScanDatabaseHelper(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
        this.appContext = context.getApplicationContext();
    }

    private String getCurrentUserUid() {
        FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();

        if (user == null) {
            return null;
        }

        return user.getUid();
    }

    @Override
    public void onCreate(SQLiteDatabase db) {

        String query = "CREATE TABLE " + TABLE_SCANS + " ("
                + COL_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, "
                + COL_TYPE + " TEXT NOT NULL, "
                + COL_CONTENT + " TEXT NOT NULL, "
                + COL_SCORE + " INTEGER NOT NULL, "
                + COL_LEVEL + " TEXT NOT NULL, "
                + COL_EXPLANATION + " TEXT, "
                + COL_TIMESTAMP + " INTEGER NOT NULL, "
                + COL_USER_UID + " TEXT NOT NULL, "
                + COL_SYNCED + " INTEGER NOT NULL DEFAULT 0)";

        db.execSQL(query);

        db.execSQL(
                "CREATE INDEX IF NOT EXISTS idx_scans_user "
                        + "ON " + TABLE_SCANS
                        + "(" + COL_USER_UID + ")"
        );
    }

    @Override
    public void onUpgrade(
            SQLiteDatabase db,
            int oldVersion,
            int newVersion
    ) {

        if (oldVersion < 2) {

            db.execSQL(
                    "ALTER TABLE " + TABLE_SCANS
                            + " ADD COLUMN " + COL_USER_UID
                            + " TEXT NOT NULL DEFAULT '"
                            + LEGACY_UID + "'"
            );

            db.execSQL(
                    "CREATE INDEX IF NOT EXISTS idx_scans_user "
                            + "ON " + TABLE_SCANS
                            + "(" + COL_USER_UID + ")"
            );
        }

        if (oldVersion < 3) {

            db.execSQL(
                    "ALTER TABLE " + TABLE_SCANS
                            + " ADD COLUMN " + COL_SYNCED
                            + " INTEGER NOT NULL DEFAULT 0"
            );
        }
    }

    // Save a scan locally and synchronize it with Firebase.
    public long insertScan(
            String scanType,
            String scannedContent,
            int riskScore,
            String riskLevel,
            String explanation,
            long scannedAt
    ) {

        String uid = getCurrentUserUid();

        if (uid == null) {
            throw new IllegalStateException(
                    "User must be logged in before saving a scan."
            );
        }

        if (scanType == null ||
                (!scanType.equalsIgnoreCase("MESSAGE")
                        && !scanType.equalsIgnoreCase("URL"))) {

            throw new IllegalArgumentException("Invalid scan type");
        }

        if (scannedContent == null ||
                scannedContent.trim().isEmpty()) {

            throw new IllegalArgumentException(
                    "Scanned content cannot be empty"
            );
        }

        if (riskScore < 0 || riskScore > 100) {
            throw new IllegalArgumentException(
                    "Risk score must be 0-100"
            );
        }

        if (riskLevel == null || riskLevel.trim().isEmpty()) {
            throw new IllegalArgumentException(
                    "Risk level cannot be empty"
            );
        }

        SQLiteDatabase db = getWritableDatabase();

        ContentValues values = new ContentValues();

        String normalizedType = scanType.toUpperCase();

        values.put(COL_TYPE, normalizedType);
        values.put(COL_CONTENT, scannedContent);
        values.put(COL_SCORE, riskScore);
        values.put(COL_LEVEL, riskLevel);
        values.put(COL_EXPLANATION, explanation);
        values.put(COL_TIMESTAMP, scannedAt);
        values.put(COL_USER_UID, uid);
        values.put(COL_SYNCED, 0);

        // Save locally first.
        long insertedId = db.insert(TABLE_SCANS, null, values);

        if (insertedId != -1) {

            // Send notification for high-risk scans.
            if (riskScore >= 60) {
                SecurityNotificationHelper.showHighRiskNotification(
                        appContext,
                        normalizedType,
                        riskScore,
                        scannedContent
                );
            }

            ScanRecord record = new ScanRecord(
                    (int) insertedId,
                    normalizedType,
                    scannedContent,
                    riskScore,
                    riskLevel,
                    explanation,
                    scannedAt
            );

            // Attempt immediate Firestore upload.
            FirestoreSync.uploadScan(
                    record,
                    new FirestoreSync.SyncCallback() {

                        @Override
                        public void onSuccess() {

                            markScanAsSynced((int) insertedId);

                            Log.d(
                                    "FirestoreSync",
                                    "Scan uploaded successfully."
                            );
                        }

                        @Override
                        public void onFailure(Exception error) {

                            Log.e(
                                    "FirestoreSync",
                                    "Immediate upload failed. "
                                            + "Background retry will handle it.",
                                    error
                            );
                        }
                    }
            );

            // Schedule background synchronization.
            // Pending scans will be retried when internet is available.
            FirestoreSyncWorker.schedule(appContext);

            // Update Firebase Realtime Database statistics.
            RealtimeDatabaseManager.updateScanStatistics(
                    normalizedType,
                    riskScore,
                    scannedAt,
                    new RealtimeDatabaseManager.UpdateCallback() {

                        @Override
                        public void onSuccess() {
                            Log.d(
                                    "RealtimeDatabase",
                                    "Statistics updated successfully."
                            );
                        }

                        @Override
                        public void onFailure(Exception error) {
                            Log.e(
                                    "RealtimeDatabase",
                                    "Statistics update failed.",
                                    error
                            );
                        }
                    }
            );
        }

        return insertedId;
    }

    // Retrieve all scans belonging to the current user.
    public List<ScanRecord> getAllScans() {

        List<ScanRecord> scanList = new ArrayList<>();

        String uid = getCurrentUserUid();

        if (uid == null) {
            return scanList;
        }

        SQLiteDatabase db = getReadableDatabase();

        try (Cursor cursor = db.query(
                TABLE_SCANS,
                null,
                COL_USER_UID + " = ?",
                new String[]{uid},
                null,
                null,
                COL_TIMESTAMP + " DESC"
        )) {

            while (cursor.moveToNext()) {

                scanList.add(new ScanRecord(
                        cursor.getInt(
                                cursor.getColumnIndexOrThrow(COL_ID)
                        ),
                        cursor.getString(
                                cursor.getColumnIndexOrThrow(COL_TYPE)
                        ),
                        cursor.getString(
                                cursor.getColumnIndexOrThrow(COL_CONTENT)
                        ),
                        cursor.getInt(
                                cursor.getColumnIndexOrThrow(COL_SCORE)
                        ),
                        cursor.getString(
                                cursor.getColumnIndexOrThrow(COL_LEVEL)
                        ),
                        cursor.getString(
                                cursor.getColumnIndexOrThrow(COL_EXPLANATION)
                        ),
                        cursor.getLong(
                                cursor.getColumnIndexOrThrow(COL_TIMESTAMP)
                        )
                ));
            }
        }

        return scanList;
    }

    // Retrieve scans that have not yet been uploaded to Firestore.
    public List<ScanRecord> getPendingScans() {

        List<ScanRecord> pendingScans = new ArrayList<>();

        String uid = getCurrentUserUid();

        if (uid == null) {
            return pendingScans;
        }

        SQLiteDatabase db = getReadableDatabase();

        try (Cursor cursor = db.query(
                TABLE_SCANS,
                null,
                COL_USER_UID + " = ? AND " + COL_SYNCED + " = ?",
                new String[]{uid, "0"},
                null,
                null,
                COL_TIMESTAMP + " ASC"
        )) {

            while (cursor.moveToNext()) {

                pendingScans.add(new ScanRecord(
                        cursor.getInt(
                                cursor.getColumnIndexOrThrow(COL_ID)
                        ),
                        cursor.getString(
                                cursor.getColumnIndexOrThrow(COL_TYPE)
                        ),
                        cursor.getString(
                                cursor.getColumnIndexOrThrow(COL_CONTENT)
                        ),
                        cursor.getInt(
                                cursor.getColumnIndexOrThrow(COL_SCORE)
                        ),
                        cursor.getString(
                                cursor.getColumnIndexOrThrow(COL_LEVEL)
                        ),
                        cursor.getString(
                                cursor.getColumnIndexOrThrow(COL_EXPLANATION)
                        ),
                        cursor.getLong(
                                cursor.getColumnIndexOrThrow(COL_TIMESTAMP)
                        )
                ));
            }
        }

        return pendingScans;
    }

    // Mark a scan as successfully synchronized with Firestore.
    public void markScanAsSynced(int scanId) {

        String uid = getCurrentUserUid();

        if (uid == null) {
            return;
        }

        ContentValues values = new ContentValues();
        values.put(COL_SYNCED, 1);

        int updatedRows = getWritableDatabase().update(
                TABLE_SCANS,
                values,
                COL_ID + " = ? AND " + COL_USER_UID + " = ?",
                new String[]{
                        String.valueOf(scanId),
                        uid
                }
        );

        Log.d(
                "FirestoreSync",
                "Marked scan " + scanId
                        + " as synced. Updated rows: " + updatedRows
        );
    }

    public int getTotalScans() {
        return getCount(null);
    }

    public int getMessageScanCount() {
        return getCount("MESSAGE");
    }

    public int getUrlScanCount() {
        return getCount("URL");
    }

    public int getThreatCount() {

        String uid = getCurrentUserUid();

        if (uid == null) {
            return 0;
        }

        SQLiteDatabase db = getReadableDatabase();

        String query = "SELECT COUNT(*) FROM " + TABLE_SCANS
                + " WHERE " + COL_USER_UID + " = ?"
                + " AND UPPER(" + COL_LEVEL + ") = ?";

        try (Cursor cursor = db.rawQuery(
                query,
                new String[]{uid, "HIGH"}
        )) {

            if (cursor.moveToFirst()) {
                return cursor.getInt(0);
            }
        }

        return 0;
    }

    private int getCount(String scanType) {

        String uid = getCurrentUserUid();

        if (uid == null) {
            return 0;
        }

        SQLiteDatabase db = getReadableDatabase();

        String query;
        String[] args;

        if (scanType == null) {

            query = "SELECT COUNT(*) FROM " + TABLE_SCANS
                    + " WHERE " + COL_USER_UID + " = ?";

            args = new String[]{uid};

        } else {

            query = "SELECT COUNT(*) FROM " + TABLE_SCANS
                    + " WHERE " + COL_USER_UID + " = ?"
                    + " AND UPPER(" + COL_TYPE + ") = ?";

            args = new String[]{uid, scanType};
        }

        try (Cursor cursor = db.rawQuery(query, args)) {

            if (cursor.moveToFirst()) {
                return cursor.getInt(0);
            }
        }

        return 0;
    }

    // Clear only the current user's local scan history.

    public void clearHistory() {

        String uid = getCurrentUserUid();

        if (uid == null) {
            return;
        }

        // 1. Clear local SQLite history.
        getWritableDatabase().delete(
                TABLE_SCANS,
                COL_USER_UID + " = ?",
                new String[]{uid}
        );

        // 2. Reset Firebase Realtime Database statistics.
        java.util.Map<String, Object> resetStats =
                new java.util.HashMap<>();

        resetStats.put("totalMessageScans", 0);
        resetStats.put("totalUrlScans", 0);
        resetStats.put("highRiskDetections", 0);
        resetStats.put("lastScanAt", 0);
        resetStats.put(
                "lastUpdatedAt",
                com.google.firebase.database.ServerValue.TIMESTAMP
        );

        com.google.firebase.database.FirebaseDatabase
                .getInstance()
                .getReference("users")
                .child(uid)
                .child("stats")
                .updateChildren(resetStats)
                .addOnSuccessListener(unused ->
                        Log.d("ScanDatabase", "History and statistics cleared.")
                )
                .addOnFailureListener(error ->
                        Log.e("ScanDatabase", "Failed to reset Firebase statistics.", error)
                );
    }

}
