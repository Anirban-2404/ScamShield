
package com.example.scamshield;

import android.os.Bundle;
import android.graphics.Color;
import android.graphics.Typeface;
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

import java.util.Locale;

public class MainActivity extends AppCompatActivity {

    private TextView messageCount, urlCount, threatCount;

    private static final String PREFS = "ScamShieldData";
    private static final String HISTORY = "scan_history";

    private final int BG = Color.rgb(11, 21, 18);
    private final int GREEN = Color.rgb(120, 220, 167);
    private final int WHITE = Color.WHITE;
    private final int MUTED = Color.rgb(140, 169, 154);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        initializeViews();
        setupClickListeners();
        updateDashboard();
    }

    private void initializeViews() {
        messageCount = findViewById(R.id.messageCount);
        urlCount = findViewById(R.id.urlCount);
        threatCount = findViewById(R.id.threatCount);
    }

    private void setupClickListeners() {

        findViewById(R.id.messageScanCard).setOnClickListener(v ->
                showMessageScanner());

        findViewById(R.id.urlScanCard).setOnClickListener(v ->
                showUrlScanner());

        findViewById(R.id.viewHistory).setOnClickListener(v ->
                showHistory());

        findViewById(R.id.historyNav).setOnClickListener(v ->
                showHistory());

        findViewById(R.id.statsNav).setOnClickListener(v ->
                showStatistics());

        findViewById(R.id.settingsNav).setOnClickListener(v ->
                showSettings());

        // Home button
        View home = findViewById(R.id.messageCount);
        if (home != null) {
            findViewById(R.id.messageCount).setOnClickListener(v ->
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

        saveScan("Message", message, score, reasons);

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

    // ---------------- LOCAL HISTORY ----------------

    private JSONArray getHistory() {

        String data = getSharedPreferences(PREFS, MODE_PRIVATE)
                .getString(HISTORY, "[]");

        try {
            return new JSONArray(data);
        } catch (JSONException e) {
            return new JSONArray();
        }
    }

    private void saveScan(String type, String content,
                          int score, JSONArray reasons) {

        JSONArray history = getHistory();

        JSONObject item = new JSONObject();

        try {
            item.put("type", type);
            item.put("content", content);
            item.put("score", score);
            item.put("reasons", reasons);
            item.put("time", System.currentTimeMillis());

            history.put(item);

            getSharedPreferences(PREFS, MODE_PRIVATE)
                    .edit()
                    .putString(HISTORY, history.toString())
                    .apply();

        } catch (JSONException e) {
            Toast.makeText(this, "Could not save scan",
                    Toast.LENGTH_SHORT).show();
        }
    }

    private void updateDashboard() {

        JSONArray history = getHistory();

        int messages = 0;
        int urls = 0;
        int threats = 0;

        for (int i = 0; i < history.length(); i++) {

            JSONObject item = history.optJSONObject(i);

            if (item == null) continue;

            if ("Message".equals(item.optString("type"))) {
                messages++;
            } else if ("URL".equals(item.optString("type"))) {
                urls++;
            }

            if (item.optInt("score") >= 60) {
                threats++;
            }
        }

        messageCount.setText(String.valueOf(messages));
        urlCount.setText(String.valueOf(urls));
        threatCount.setText(String.valueOf(threats));
    }

    // ---------------- HISTORY SCREEN ----------------

    private void showHistory() {

        JSONArray history = getHistory();

        if (history.length() == 0) {
            new AlertDialog.Builder(this)
                    .setTitle("Analysis History")
                    .setMessage("No analysis records found.\n\nStart your first scan!")
                    .setPositiveButton("OK", null)
                    .show();
            return;
        }

        String[] entries = new String[history.length()];

        for (int i = history.length() - 1; i >= 0; i--) {

            JSONObject item = history.optJSONObject(i);

            if (item == null) continue;

            String content = item.optString("content");
            if (content.length() > 35) {
                content = content.substring(0, 35) + "...";
            }

            entries[history.length() - 1 - i] =
                    item.optString("type") + " | Risk: "
                            + item.optInt("score") + "/100\n"
                            + content;
        }

        new AlertDialog.Builder(this)
                .setTitle("Analysis History")
                .setItems(entries, (dialog, which) -> {

                    JSONObject item = history.optJSONObject(
                            history.length() - 1 - which);

                    if (item != null) {
                        showSavedResult(item);
                    }
                })
                .setPositiveButton("Close", null)
                .show();
    }

    private void showSavedResult(JSONObject item) {

        StringBuilder details = new StringBuilder();

        details.append("Type: ").append(item.optString("type"));
        details.append("\n\nContent:\n")
                .append(item.optString("content"));

        details.append("\n\nRisk Score: ")
                .append(item.optInt("score"))
                .append("/100");

        JSONArray reasons = item.optJSONArray("reasons");

        details.append("\n\nWarning Signs:");

        if (reasons != null && reasons.length() > 0) {
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

        JSONArray history = getHistory();

        int messages = 0;
        int urls = 0;
        int threats = 0;

        for (int i = 0; i < history.length(); i++) {

            JSONObject item = history.optJSONObject(i);

            if (item == null) continue;

            if ("Message".equals(item.optString("type"))) {
                messages++;
            } else if ("URL".equals(item.optString("type"))) {
                urls++;
            }

            if (item.optInt("score") >= 60) {
                threats++;
            }
        }

        String statistics =
                "Total Analyses: " + history.length()
                        + "\n\nMessages Scanned: " + messages
                        + "\nURLs Scanned: " + urls
                        + "\nHigh-Risk Results: " + threats
                        + "\n\nLow/Moderate-Risk Results: "
                        + (history.length() - threats);

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
                                + "Storage: Local device storage"
                )
                .setPositiveButton("OK", null)
                .show();
    }

    private void confirmClearHistory() {

        new AlertDialog.Builder(this)
                .setTitle("Clear History?")
                .setMessage("This will permanently delete all saved scan records.")
                .setPositiveButton("Clear", (dialog, which) -> {

                    getSharedPreferences(PREFS, MODE_PRIVATE)
                            .edit()
                            .remove(HISTORY)
                            .apply();

                    updateDashboard();

                    Toast.makeText(this, "History cleared",
                            Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }
}
