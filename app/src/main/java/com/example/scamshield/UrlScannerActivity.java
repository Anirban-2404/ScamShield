
package com.example.scamshield;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import com.example.scamshield.databinding.ActivityUrlScannerBinding;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

public class UrlScannerActivity extends AppCompatActivity {

    private ActivityUrlScannerBinding binding;
    private ScanDatabaseHelper databaseHelper;

    private boolean isScanning = false;

    private static final Pattern IP_PATTERN = Pattern.compile(
            "^(\\d{1,3}\\.){3}\\d{1,3}$",
            Pattern.CASE_INSENSITIVE
    );

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityUrlScannerBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        databaseHelper = new ScanDatabaseHelper(this);

        binding.backButton.setOnClickListener(v -> finish());

        binding.scanButton.setOnClickListener(v -> analyzeUrl());
    }

    private void analyzeUrl() {

        if (isScanning) {
            return;
        }

        String url = binding.urlInput.getText().toString().trim();

        if (url.isEmpty()) {
            binding.urlInput.setError("Please enter a URL");
            return;
        }

        String text = url.toLowerCase(Locale.ROOT);

        int score = 0;
        List<String> reasons = new ArrayList<>();

        // Add a scheme temporarily for checking URLs without one.
        String normalizedUrl = text;

        if (!normalizedUrl.startsWith("http://")
                && !normalizedUrl.startsWith("https://")) {
            normalizedUrl = "https://" + normalizedUrl;
        }

        // 1. HTTP instead of HTTPS (+15)
        if (text.startsWith("http://")) {
            score += 15;
            reasons.add(
                    "Unencrypted HTTP connection detected (+15)"
            );
        }

        // 2. @ symbol in URL (+25)
        if (text.contains("@")) {
            score += 25;
            reasons.add(
                    "URL contains an @ symbol, which may disguise its destination (+25)"
            );
        }

        // 3. IP address used as hostname (+25)
        String hostPart = normalizedUrl
                .replaceFirst("^https?://", "")
                .split("[/?#]", 2)[0]
                .split(":", 2)[0];

        if (IP_PATTERN.matcher(hostPart).matches()) {
            score += 25;
            reasons.add(
                    "URL uses an IP address instead of a normal domain (+25)"
            );
        }

        // 4. Suspicious keywords (+20)
        String[] suspiciousWords = {
                "login", "verify", "account", "secure",
                "update", "banking", "password", "confirm",
                "wallet", "free", "prize", "claim"
        };

        if (containsAny(text, suspiciousWords)) {
            score += 20;
            reasons.add(
                    "Suspicious keywords detected in URL (+20)"
            );
        }

        // 5. Unusually long URL (+10)
        if (url.length() > 75) {
            score += 10;
            reasons.add(
                    "Unusually long URL detected (+10)"
            );
        }

        score = Math.min(score, 100);

        String explanation;

        if (reasons.isEmpty()) {
            explanation =
                    "No major suspicious indicators were detected by the current rule-based analysis.";
        } else {
            StringBuilder result = new StringBuilder();

            for (String reason : reasons) {
                result.append("• ")
                        .append(reason)
                        .append("\n");
            }

            explanation = result.toString().trim();
        }

        // Preserve local score and explanation.
        final int localScore = score;
        final String localExplanation = explanation;

        // Prevent repeated requests.
        isScanning = true;
        binding.scanButton.setEnabled(false);
        binding.scanButton.setText("Checking URL...");

        // Check URL against URLhaus.
        UrlhausChecker.check(
                url,
                BuildConfig.URLHAUS_AUTH_KEY,
                result -> {

                    // Activity may have been closed during the request.
                    if (isFinishing() || isDestroyed()) {
                        return;
                    }

                    isScanning = false;
                    binding.scanButton.setEnabled(true);
                    binding.scanButton.setText("Scan URL");

                    int finalScore = localScore;

                    StringBuilder finalExplanation =
                            new StringBuilder(localExplanation);

                    if (result.successful && result.listed) {

                        // Confirmed URLhaus malware match.
                        finalScore = Math.max(finalScore, 85);

                        finalExplanation.append(
                                "\n\nLive Threat Intelligence:\n"
                        ).append(result.message);

                    } else if (result.successful) {

                        finalExplanation.append(
                                "\n\nLive Threat Intelligence:\n"
                        ).append(result.message);

                    } else {

                        finalExplanation.append(
                                "\n\nLive Threat Intelligence:\n"
                        ).append(result.message);

                        finalExplanation.append(
                                "\nLocal rule-based assessment retained."
                        );
                    }

                    finalScore = Math.min(finalScore, 100);

                    String finalRiskLevel =
                            getRiskLevel(finalScore);

                    String recommendation =
                            getRecommendation(finalRiskLevel);

                    // Save final assessment to SQLite.
                    long insertedId = databaseHelper.insertScan(
                            "URL",
                            url,
                            finalScore,
                            finalRiskLevel,
                            finalExplanation.toString(),
                            System.currentTimeMillis()
                    );

                    if (insertedId == -1) {
                        Toast.makeText(
                                UrlScannerActivity.this,
                                "Failed to save scan history.",
                                Toast.LENGTH_SHORT
                        ).show();
                    }

                    // Firestore and Realtime Database
                    // are already connected inside insertScan().
                    showResult(
                            url,
                            finalScore,
                            finalRiskLevel,
                            finalExplanation.toString(),
                            recommendation,
                            result.successful
                    );
                }
        );
    }

    private boolean containsAny(String text, String[] keywords) {

        for (String keyword : keywords) {
            if (text.contains(keyword)) {
                return true;
            }
        }

        return false;
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

    private String getRecommendation(String riskLevel) {

        switch (riskLevel) {

            case "HIGH":
                return "Avoid opening this URL. Do not enter passwords, OTPs or financial information.";

            case "MODERATE":
                return "Verify the website's identity before opening it or entering personal information.";

            default:
                return "No major warning signs detected by this basic check. This does not guarantee that the website is safe.";
        }
    }

    private void showResult(
            String url,
            int score,
            String riskLevel,
            String explanation,
            String recommendation,
            boolean liveCheckSuccessful
    ) {

        String liveStatus = liveCheckSuccessful
                ? "URLhaus live lookup completed."
                : "URLhaus lookup unavailable; local rules were used.";

        String result =
                "URL: " + url + "\n\n" +
                        "Risk Score: " + score + "/100\n\n" +
                        "Risk Level: " + riskLevel + "\n\n" +
                        "Analysis:\n" + explanation + "\n\n" +
                        "Recommendation:\n" + recommendation + "\n\n" +
                        "Threat Intelligence Status:\n" + liveStatus + "\n\n" +
                        "Note: No URLhaus match does not guarantee that a URL is safe.";

        new AlertDialog.Builder(this)
                .setTitle("URL Security Analysis")
                .setMessage(result)
                .setPositiveButton("Share Result", (dialog, which) -> {

                    Intent shareIntent =
                            new Intent(Intent.ACTION_SEND);

                    shareIntent.setType("text/plain");

                    shareIntent.putExtra(
                            Intent.EXTRA_TEXT,
                            "ScamShield - URL Analysis\n\n" + result
                    );

                    startActivity(
                            Intent.createChooser(
                                    shareIntent,
                                    "Share Scan Result"
                            )
                    );
                })
                .setNegativeButton("Close", null)
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
