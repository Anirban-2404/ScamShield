
package com.example.scamshield;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import java.util.ArrayList;
import java.util.List;

public class ScanDatabaseHelper extends SQLiteOpenHelper {

    private static final String DATABASE_NAME = "scamshield.db";
    private static final int DATABASE_VERSION = 1;
    private static final String TABLE_SCANS = "scans";

    private static final String COL_ID = "id";
    private static final String COL_TYPE = "scan_type";
    private static final String COL_CONTENT = "scanned_content";
    private static final String COL_SCORE = "risk_score";
    private static final String COL_LEVEL = "risk_level";
    private static final String COL_EXPLANATION = "explanation";
    private static final String COL_TIMESTAMP = "scanned_at";

    public ScanDatabaseHelper(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
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
                + COL_TIMESTAMP + " INTEGER NOT NULL)";

        db.execSQL(query);
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        db.execSQL("DROP TABLE IF EXISTS " + TABLE_SCANS);
        onCreate(db);
    }

    public long insertScan(
            String scanType,
            String scannedContent,
            int riskScore,
            String riskLevel,
            String explanation,
            long scannedAt) {

        if (scanType == null ||
                (!scanType.equalsIgnoreCase("MESSAGE")
                        && !scanType.equalsIgnoreCase("URL"))) {
            throw new IllegalArgumentException("Invalid scan type");
        }

        if (scannedContent == null || scannedContent.trim().isEmpty()) {
            throw new IllegalArgumentException("Scanned content cannot be empty");
        }

        if (riskScore < 0 || riskScore > 100) {
            throw new IllegalArgumentException("Risk score must be 0-100");
        }

        if (riskLevel == null || riskLevel.trim().isEmpty()) {
            throw new IllegalArgumentException("Risk level cannot be empty");
        }

        SQLiteDatabase db = getWritableDatabase();

        ContentValues values = new ContentValues();
        values.put(COL_TYPE, scanType.toUpperCase());
        values.put(COL_CONTENT, scannedContent);
        values.put(COL_SCORE, riskScore);
        values.put(COL_LEVEL, riskLevel);
        values.put(COL_EXPLANATION, explanation);
        values.put(COL_TIMESTAMP, scannedAt);

        return db.insert(TABLE_SCANS, null, values);
    }

    public List<ScanRecord> getAllScans() {
        List<ScanRecord> scanList = new ArrayList<>();

        SQLiteDatabase db = getReadableDatabase();

        try (Cursor cursor = db.query(
                TABLE_SCANS,
                null,
                null,
                null,
                null,
                null,
                COL_TIMESTAMP + " DESC")) {

            while (cursor.moveToNext()) {
                scanList.add(new ScanRecord(
                        cursor.getInt(cursor.getColumnIndexOrThrow(COL_ID)),
                        cursor.getString(cursor.getColumnIndexOrThrow(COL_TYPE)),
                        cursor.getString(cursor.getColumnIndexOrThrow(COL_CONTENT)),
                        cursor.getInt(cursor.getColumnIndexOrThrow(COL_SCORE)),
                        cursor.getString(cursor.getColumnIndexOrThrow(COL_LEVEL)),
                        cursor.getString(cursor.getColumnIndexOrThrow(COL_EXPLANATION)),
                        cursor.getLong(cursor.getColumnIndexOrThrow(COL_TIMESTAMP))
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
        SQLiteDatabase db = getReadableDatabase();

        try (Cursor cursor = db.rawQuery(
                "SELECT COUNT(*) FROM " + TABLE_SCANS
                        + " WHERE UPPER(" + COL_LEVEL + ") = ?",
                new String[]{"HIGH"})) {

            if (cursor.moveToFirst()) {
                return cursor.getInt(0);
            }
        }

        return 0;
    }

    private int getCount(String scanType) {
        SQLiteDatabase db = getReadableDatabase();

        String query;
        String[] args;

        if (scanType == null) {
            query = "SELECT COUNT(*) FROM " + TABLE_SCANS;
            args = null;
        } else {
            query = "SELECT COUNT(*) FROM " + TABLE_SCANS
                    + " WHERE UPPER(" + COL_TYPE + ") = ?";
            args = new String[]{scanType};
        }

        try (Cursor cursor = db.rawQuery(query, args)) {
            if (cursor.moveToFirst()) {
                return cursor.getInt(0);
            }
        }

        return 0;
    }

    public void clearHistory() {
        getWritableDatabase().delete(TABLE_SCANS, null, null);
    }
}
