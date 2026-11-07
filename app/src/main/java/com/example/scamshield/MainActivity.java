
package com.example.scamshield;

import android.content.Intent;
import com.example.scamshield.databinding.ActivityMainBinding;
import android.os.Bundle;
import android.graphics.Color;
import android.view.Gravity;
import android.view.View;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.List;
import java.util.Locale;

public class MainActivity extends AppCompatActivity {

    private ActivityMainBinding binding;

    private TextView messageCount, urlCount, threatCount;

    private ScanDatabaseHelper databaseHelper;

    private static final String PREFS = "ScamShieldData";
    private static final String HISTORY = "scan_history";
    private static final String MIGRATION_DONE = "sqlite_migration_done";

    private final int WHITE = Color.WHITE;
    private final int MUTED = Color.rgb(140, 169, 154);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        databaseHelper = new ScanDatabaseHelper(this);

        initializeViews();

        migrateOldHistory();

        setupClickListeners();

        updateDashboard();
    }

    private void initializeViews() {
        messageCount = findViewById(R.id.messageCount);
        urlCount = findViewById(R.id.urlCount);
        threatCount = findViewById(R.id.threatCount);
    }

    private void setupClickListeners() {

        findViewById(R.id.messageScanCard).setOnClickListener(v -> {
            Intent intent = new Intent(MainActivity.this, MessageScannerActivity.class);
            startActivity(intent);
        });

        findViewById(R.id.urlScanCard).setOnClickListener(v -> {
            Intent intent = new Intent(MainActivity.this, UrlScannerActivity.class);
            startActivity(intent);
        });

        findViewById(R.id.viewHistory).setOnClickListener(v ->
                showHistory());

        findViewById(R.id.historyNav).setOnClickListener(v ->
                showHistory());

        findViewById(R.id.statsNav).setOnClickListener(v ->
                showStatistics());

        findViewById(R.id.settingsNav).setOnClickListener(v ->
                showSettings());

        View home = findViewById(R.id.messageCount);

        if (home != null) {
            home.setOnClickListener(v ->
                    Toast.makeText(this, "You are on Home",
                            Toast.LENGTH_SHORT).show());
        }
    }

    // ---------------- MESSAGE SCANNER ----------------

    private void showMessageScanner() {

        EditText input = new EditText(this);
        input.setHint("Paste a suspicious message here...");
        input.setTextColor(WHITE);
        input.setHintTextColor(MUTED);
        input.setGravity(Gravity.TOP);
        input.setMinLines(5);
        input.setPadding(25, 20, 25, 20);
        input.setBackgroundColor(Color.rgb(28, 43, 36));

        LinearLayout container = new LinearLayout(this);
        container.setPadding(20, 10, 20, 5);
        container.addView(input);

        new AlertDialog.Builder(this)
                .setTitle("Message Scanner")
                .setMessage("Enter the SMS, email or message you want to analyze.")
                .setView(container)
                .setPositiveButton("Analyze", (dialog, which) -> {

                    String message = input.getText().toString().trim();

                    if (message.isEmpty()) {
                        Toast.makeText(this, "Please enter a message",
                                Toast.LENGTH_SHORT).show();
                        return;
                    }

                    analyzeMessage(message);
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void analyzeMessage(String message) {

        String text = message.toLowerCase(Locale.ROOT);

        int score = 0;
        JSONArray reasons = new JSONArray();

        String[] urgentWords = {
                "urgent", "immediately", "expire", "suspended",
                "suspend", "limited time", "act now", "verify now"
        };

        String[] sensitiveWords = {
                "otp", "pin", "password", "bank details",
                "credit card", "account number"
        };

        String[] rewardWords = {
                "you won", "winner", "prize", "lottery",
                "free gift", "claim your reward"
        };

        String[] suspiciousWords = {
                "click here", "verify your account",
                "account blocked", "send money",
                "payment required"
        };

        score += checkWords(text, urgentWords, 15,
                reasons, "Urgent or threatening language detected");

        score += checkWords(text, sensitiveWords, 25,
                reasons, "Sensitive information is requested");

        score += checkWords(text, rewardWords, 20,
                reasons, "Unexpected reward or prize language detected");

        score += checkWords(text, suspiciousWords, 20,
                reasons, "Potentially deceptive request detected");

        score = Math.min(score, 100);

        saveScan("MESSAGE", message, score, reasons);

        showResult("Message Analysis", score, reasons);
    }

    // ---------------- URL SCANNER ----------------

    private void showUrlScanner() {

        EditText input = new EditText(this);
        input.setHint("https://example.com");
        input.setTextColor(WHITE);
        input.setHintTextColor(MUTED);
        input.setSingleLine(true);
        input.setPadding(25, 20, 25, 20);
        input.setBackgroundColor(Color.rgb(28, 43, 36));

        LinearLayout container = new LinearLayout(this);
        container.setPadding(20, 10, 20, 5);
        container.addView(input);

        new AlertDialog.Builder(this)
                .setTitle("URL Inspector")
                .setMessage("Enter a website address to inspect.")
                .setView(container)
                .setPositiveButton("Analyze", (dialog, which) -> {

                    String url = input.getText().toString().trim();

                    if (url.isEmpty()) {
                        Toast.makeText(this, "Please enter a URL",
                                Toast.LENGTH_SHORT).show();
                        return;
                    }

                    analyzeUrl(url);
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void analyzeUrl(String url) {

        String text = url.toLowerCase(Locale.ROOT);

        int score = 0;
        JSONArray reasons = new JSONArray();

        if (!text.matches("^(https?://)?[a-z0-9.-]+\\.[a-z]{2,}(:[0-9]+)?([/?#].*)?$")) {
            score += 40;
            addReason(reasons, "Invalid or unusual URL format");
        }

        if (text.startsWith("http://")) {
            score += 20;
            addReason(reasons, "Website does not use HTTPS");
        }

        if (text.contains("@")) {
            score += 30;
            addReason(reasons, "URL contains an unusual @ symbol");
        }

        if (text.matches(".*\\d+\\.\\d+\\.\\d+\\.\\d+.*")) {
            score += 30;
            addReason(reasons, "URL appears to use an IP address");
        }

        String[] suspiciousTerms = {
                "login", "verify", "secure", "account",
                "update", "free", "prize", "claim"
        };

        for (String term : suspiciousTerms) {
            if (text.contains(term)) {
                score += 10;
                addReason(reasons,
                        "Suspicious keyword found: " + term);
                break;
            }
        }

        if (text.length() > 100) {
            score += 15;
            addReason(reasons, "Unusually long URL");
        }

        score = Math.min(score, 100);

        saveScan("URL", url, score, reasons);

        showResult("URL Analysis", score, reasons);
    }

    // ---------------- ANALYSIS HELPERS ----------------

    private int checkWords(String text, String[] words, int points,
                           JSONArray reasons, String description) {

        for (String word : words) {
            if (text.contains(word)) {
                addReason(reasons, description);
                return points;
            }
        }

        return 0;
    }

    private void addReason(JSONArray reasons, String reason) {
        reasons.put(reason);
    }

    private String getRiskLevel(int score) {

        if (score >= 60) {
            return "HIGH";
        } else if (score >= 30) {
            return "MODERATE";
        } else {
            return "LOW";
        }
    }

    private void showResult(String title, int score, JSONArray reasons) {

        String level;
        String recommendation;

        if (score >= 60) {
            level = "HIGH RISK";
            recommendation = "Do not click links or share personal information.";
        } else if (score >= 30) {
            level = "MODERATE RISK";
            recommendation = "Be cautious and verify the source independently.";
        } else {
            level = "LOW RISK";
            recommendation = "No major warning signs were detected by this basic scan.";
        }

        StringBuilder result = new StringBuilder();

        result.append("Risk Score: ").append(score).append("/100\n\n");
        result.append("Assessment: ").append(level).append("\n\n");
        result.append("Warning Signs:\n");

        if (reasons.length() == 0) {
            result.append("• No suspicious indicators detected.\n");
        } else {
            for (int i = 0; i < reasons.length(); i++) {
                result.append("• ")
                        .append(reasons.optString(i))
                        .append("\n");
            }
        }

        result.append("\nRecommendation:\n")
                .append(recommendation);

        result.append("\n\nNote: This is a basic rule-based analysis, not a guarantee that content is safe or malicious.");

        new AlertDialog.Builder(this)
                .setTitle(title)
                .setMessage(result.toString())
                .setPositiveButton("OK", null)
                .show();

        updateDashboard();
    }

    // ---------------- SQLITE STORAGE ----------------

    private void saveScan(String type, String content,
                          int score, JSONArray reasons) {

        String riskLevel = getRiskLevel(score);

        long result = databaseHelper.insertScan(
                type,
                content,
                score,
                riskLevel,
                reasons.toString(),
                System.currentTimeMillis()
        );

        if (result == -1) {
            Toast.makeText(this, "Could not save scan",
                    Toast.LENGTH_SHORT).show();
        }

        updateDashboard();
    }

    // Migrate previously saved SharedPreferences history into SQLite
    private void migrateOldHistory() {

        android.content.SharedPreferences preferences =
                getSharedPreferences(PREFS, MODE_PRIVATE);

        if (preferences.getBoolean(MIGRATION_DONE, false)) {
            return;
        }

        String oldData = preferences.getString(HISTORY, "[]");

        try {
            JSONArray oldHistory = new JSONArray(oldData);

            for (int i = 0; i < oldHistory.length(); i++) {

                JSONObject item = oldHistory.optJSONObject(i);

                if (item == null) {
                    continue;
                }

                String type = item.optString("type", "");
                String content = item.optString("content", "");
                int score = item.optInt("score", 0);
                long time = item.optLong("time", System.currentTimeMillis());

                JSONArray reasons = item.optJSONArray("reasons");

                if (reasons == null) {
                    reasons = new JSONArray();
                }

                if (content.trim().isEmpty()) {
                    continue;
                }

                if (!type.equalsIgnoreCase("Message")
                        && !type.equalsIgnoreCase("URL")) {
                    continue;
                }

                // Avoid importing records already present.
                boolean alreadyImported = false;

                List<ScanRecord> existingRecords = databaseHelper.getAllScans();

                for (ScanRecord record : existingRecords) {
                    if (record.getScanType().equalsIgnoreCase(type)
                            && record.getScannedContent().equals(content)
                            && record.getScannedAt() == time) {
                        alreadyImported = true;
                        break;
                    }
                }

                if (!alreadyImported && score >= 0 && score <= 100) {
                    databaseHelper.insertScan(
                            type.toUpperCase(Locale.ROOT),
                            content,
                            score,
                            getRiskLevel(score),
                            reasons.toString(),
                            time
                    );
                }
            }

        } catch (JSONException e) {
            Toast.makeText(this, "Old history migration failed",
                    Toast.LENGTH_LONG).show();
        }

        preferences.edit()
                .putBoolean(MIGRATION_DONE, true)
                .apply();
    }

    private void updateDashboard() {

        int messages = databaseHelper.getMessageScanCount();
        int urls = databaseHelper.getUrlScanCount();
        int threats = databaseHelper.getThreatCount();

        messageCount.setText(String.valueOf(messages));
        urlCount.setText(String.valueOf(urls));
        threatCount.setText(String.valueOf(threats));
    }

    // ---------------- HISTORY SCREEN ----------------

    private void showHistory() {

        List<ScanRecord> history = databaseHelper.getAllScans();

        if (history.isEmpty()) {
            new AlertDialog.Builder(this)
                    .setTitle("Analysis History")
                    .setMessage("No analysis records found.\n\nStart your first scan!")
                    .setPositiveButton("OK", null)
                    .show();
            return;
        }

        String[] entries = new String[history.size()];

        for (int i = 0; i < history.size(); i++) {

            ScanRecord item = history.get(i);

            String content = item.getScannedContent();

            if (content.length() > 35) {
                content = content.substring(0, 35) + "...";
            }

            entries[i] = item.getScanType()
                    + " | Risk: "
                    + item.getRiskScore()
                    + "/100\n"
                    + content;
        }

        new AlertDialog.Builder(this)
                .setTitle("Analysis History")
                .setItems(entries, (dialog, which) -> {

                    if (which >= 0 && which < history.size()) {
                        showSavedResult(history.get(which));
                    }
                })
                .setPositiveButton("Close", null)
                .show();
    }

    private void showSavedResult(ScanRecord item) {

        StringBuilder details = new StringBuilder();

        details.append("Type: ").append(item.getScanType());

        details.append("\n\nContent:\n")
                .append(item.getScannedContent());

        details.append("\n\nRisk Score: ")
                .append(item.getRiskScore())
                .append("/100");

        details.append("\n\nAssessment: ")
                .append(item.getRiskLevel())
                .append(" RISK");

        JSONArray reasons;

        try {
            reasons = new JSONArray(item.getExplanation());
        } catch (JSONException e) {
            reasons = new JSONArray();
        }

        details.append("\n\nWarning Signs:");

        if (reasons.length() > 0) {
            for (int i = 0; i < reasons.length(); i++) {
                details.append("\n• ").append(reasons.optString(i));
            }
        } else {
            details.append("\nNo warning signs detected.");
        }

        new AlertDialog.Builder(this)
                .setTitle("Saved Analysis")
                .setMessage(details.toString())
                .setPositiveButton("Close", null)
                .show();
    }

    // ---------------- STATISTICS ----------------

    private void showStatistics() {

        int total = databaseHelper.getTotalScans();
        int messages = databaseHelper.getMessageScanCount();
        int urls = databaseHelper.getUrlScanCount();
        int threats = databaseHelper.getThreatCount();

        String statistics =
                "Total Analyses: " + total
                        + "\n\nMessages Scanned: " + messages
                        + "\nURLs Scanned: " + urls
                        + "\nHigh-Risk Results: " + threats
                        + "\n\nLow/Moderate-Risk Results: "
                        + (total - threats);

        new AlertDialog.Builder(this)
                .setTitle("Security Statistics")
                .setMessage(statistics)
                .setPositiveButton("OK", null)
                .show();
    }

    // ---------------- SETTINGS ----------------

    private void showSettings() {

        String[] options = {
                "View App Information",
                "Clear Analysis History"
        };

        new AlertDialog.Builder(this)
                .setTitle("Settings")
                .setItems(options, (dialog, which) -> {

                    if (which == 0) {
                        showAppInformation();
                    } else if (which == 1) {
                        confirmClearHistory();
                    }
                })
                .setNegativeButton("Close", null)
                .show();
    }

    private void showAppInformation() {

        new AlertDialog.Builder(this)
                .setTitle("About ScamShield")
                .setMessage(
                        "ScamShield\n\n"
                                + "A security awareness application designed "
                                + "to identify potential scam messages and "
                                + "suspicious website links.\n\n"
                                + "Version: 1.0\n"
                                + "Analysis: Rule-based\n"
                                + "Storage: SQLite local database"
                )
                .setPositiveButton("OK", null)
                .show();
    }

    private void confirmClearHistory() {

        new AlertDialog.Builder(this)
                .setTitle("Clear History?")
                .setMessage("This will permanently delete all saved scan records.")
                .setPositiveButton("Clear", (dialog, which) -> {

                    databaseHelper.clearHistory();

                    updateDashboard();

                    Toast.makeText(this, "History cleared",
                            Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();

        if (databaseHelper != null) {
            databaseHelper.close();
        }
    }
}
