
package com.example.scamshield;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseUser;

import java.util.ArrayList;
import java.util.List;

public class ScanDatabaseHelper extends SQLiteOpenHelper {

    private static final String DATABASE_NAME = "scamshield.db";
    private static final int DATABASE_VERSION = 2;

    private static final String TABLE_SCANS = "scans";

    private static final String COL_ID = "id";
    private static final String COL_TYPE = "scan_type";
    private static final String COL_CONTENT = "scanned_content";
    private static final String COL_SCORE = "risk_score";
    private static final String COL_LEVEL = "risk_level";
    private static final String COL_EXPLANATION = "explanation";
    private static final String COL_TIMESTAMP = "scanned_at";
    private static final String COL_USER_UID = "user_uid";

    // Old records cannot be assigned to an account reliably.
    private static final String LEGACY_UID = "legacy_unassigned";

    public ScanDatabaseHelper(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }

    // Get the currently authenticated user's Firebase UID.
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
                + COL_USER_UID + " TEXT NOT NULL)";

        db.execSQL(query);
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
    }

    // Save a scan under the currently logged-in account.
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

        values.put(COL_TYPE, scanType.toUpperCase());
        values.put(COL_CONTENT, scannedContent);
        values.put(COL_SCORE, riskScore);
        values.put(COL_LEVEL, riskLevel);
        values.put(COL_EXPLANATION, explanation);
        values.put(COL_TIMESTAMP, scannedAt);
        values.put(COL_USER_UID, uid);

        return db.insert(TABLE_SCANS, null, values);
    }

    // Retrieve only the current user's scans.
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

    // Clear only the currently logged-in user's history.
    public void clearHistory() {

        String uid = getCurrentUserUid();

        if (uid == null) {
            return;
        }

        getWritableDatabase().delete(
                TABLE_SCANS,
                COL_USER_UID + " = ?",
                new String[]{uid}
        );
    }
}
