
package com.example.scamshield;

import android.content.Intent;
import android.os.Bundle;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import com.example.scamshield.databinding.ActivityMessageScannerBinding;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class MessageScannerActivity extends AppCompatActivity {

    private ActivityMessageScannerBinding binding;
    private ScanDatabaseHelper databaseHelper;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMessageScannerBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        databaseHelper = new ScanDatabaseHelper(this);

        binding.backButton.setOnClickListener(v -> finish());

        binding.scanButton.setOnClickListener(v -> analyzeMessage());
    }

    private void analyzeMessage() {

        String message = binding.messageInput.getText().toString().trim();

        if (message.isEmpty()) {
            binding.messageInput.setError("Please enter a message");
            return;
        }

        String text = message.toLowerCase(Locale.ROOT);

        int score = 0;
        List<String> reasons = new ArrayList<>();

        // 1. Urgency indicators (+15)
        String[] urgencyWords = {
                "urgent", "immediately", "expire", "suspended",
                "suspend", "limited time", "act now", "verify now"
        };

        if (containsAny(text, urgencyWords)) {
            score += 15;
            reasons.add("Urgency or pressure tactics detected (+15)");
        }

        // 2. Sensitive information requests (+25)
        String[] sensitiveWords = {
                "otp", "pin", "password", "bank details",
                "credit card", "account number"
        };

        if (containsAny(text, sensitiveWords)) {
            score += 25;
            reasons.add("Sensitive financial or personal information mentioned (+25)");
        }

        // 3. Reward and prize indicators (+20)
        String[] rewardWords = {
                "you won", "winner", "prize", "lottery",
                "free gift", "claim your reward"
        };

        if (containsAny(text, rewardWords)) {
            score += 20;
            reasons.add("Suspicious reward or prize language detected (+20)");
        }

        // 4. Deceptive requests (+20)
        String[] deceptiveWords = {
                "click here", "verify your account",
                "account blocked", "send money", "payment required"
        };

        if (containsAny(text, deceptiveWords)) {
            score += 20;
            reasons.add("Potentially deceptive request detected (+20)");
        }

        // Maximum risk score is 100
        score = Math.min(score, 100);

        String riskLevel = getRiskLevel(score);

        String explanation;

        if (reasons.isEmpty()) {
            explanation = "No major scam indicators were detected by the current rule-based analysis.";
        } else {
            StringBuilder result = new StringBuilder();

            for (String reason : reasons) {
                result.append("• ").append(reason).append("\n");
            }

            explanation = result.toString().trim();
        }

        String recommendation = getRecommendation(riskLevel);

        // Save scan result to SQLite
        databaseHelper.insertScan(
                "MESSAGE",
                message,
                score,
                riskLevel,
                explanation,
                System.currentTimeMillis()
        );

        // Display result
        showResult(message, score, riskLevel, explanation, recommendation);
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
                return "Do not click links or share personal information.";

            case "MODERATE":
                return "Be cautious and verify the source independently.";

            default:
                return "No major warning signs detected. Continue to stay alert.";
        }
    }

    private void showResult(
            String message,
            int score,
            String riskLevel,
            String explanation,
            String recommendation
    ) {

        String result =
                "Risk Score: " + score + "/100\n\n" +
                        "Risk Level: " + riskLevel + "\n\n" +
                        "Analysis:\n" + explanation + "\n\n" +
                        "Recommendation:\n" + recommendation +
                        "\n\nNote: This is a rule-based assessment, not a guarantee that the message is safe.";

        new AlertDialog.Builder(this)
                .setTitle("Message Security Analysis")
                .setMessage(result)
                .setPositiveButton("Share Result", (dialog, which) -> {

                    String shareText =
                            "ScamShield - Message Analysis\n\n" +
                                    "Message: " + message + "\n\n" +
                                    result;

                    Intent shareIntent = new Intent(Intent.ACTION_SEND);
                    shareIntent.setType("text/plain");
                    shareIntent.putExtra(Intent.EXTRA_TEXT, shareText);

                    startActivity(
                            Intent.createChooser(shareIntent, "Share Scan Result")
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
