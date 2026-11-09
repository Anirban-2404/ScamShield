package com.example.scamshield;

import android.util.Patterns;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;

public class SmsScanner {

    public static class ScanResult {
        public int messageScore;
        public List<String> messageReasons = new ArrayList<>();
        public List<String> urls = new ArrayList<>();
    }

    public static class UrlResult {
        public String url;
        public int score;
        public List<String> reasons = new ArrayList<>();
    }

    public static ScanResult scanMessage(String message) {

        ScanResult result = new ScanResult();

        if (message == null || message.trim().isEmpty()) {
            return result;
        }

        String text = message.toLowerCase(Locale.ROOT);

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

        result.messageScore += checkWords(
                text, urgentWords, 15,
                result.messageReasons,
                "Urgent or threatening language detected"
        );

        result.messageScore += checkWords(
                text, sensitiveWords, 25,
                result.messageReasons,
                "Sensitive information is requested"
        );

        result.messageScore += checkWords(
                text, rewardWords, 20,
                result.messageReasons,
                "Unexpected reward or prize language detected"
        );

        result.messageScore += checkWords(
                text, suspiciousWords, 20,
                result.messageReasons,
                "Potentially deceptive request detected"
        );

        result.messageScore = Math.min(result.messageScore, 100);

        extractUrls(message, result.urls);

        return result;
    }

    private static int checkWords(
            String text,
            String[] words,
            int points,
            List<String> reasons,
            String description) {

        for (String word : words) {
            if (text.contains(word)) {
                reasons.add(description);
                return points;
            }
        }

        return 0;
    }

    private static void extractUrls(
            String message,
            List<String> urls) {

        Matcher matcher = Patterns.WEB_URL.matcher(message);

        while (matcher.find()) {

            String url = matcher.group();

            // Remove common punctuation from the end.
            url = url.replaceAll("[.,!?;:]+$", "");

            if (!url.isEmpty() && !urls.contains(url)) {
                urls.add(url);
            }
        }
    }

    public static UrlResult scanUrl(String url) {

        UrlResult result = new UrlResult();

        result.url = url;

        String text = url.toLowerCase(Locale.ROOT);

        if (!text.matches(
                "^(https?://)?[a-z0-9.-]+\\.[a-z]{2,}(:[0-9]+)?([/?#].*)?$")) {

            result.score += 40;
            result.reasons.add("Invalid or unusual URL format");
        }

        if (text.startsWith("http://")) {
            result.score += 20;
            result.reasons.add("Website does not use HTTPS");
        }

        if (text.contains("@")) {
            result.score += 30;
            result.reasons.add("URL contains an unusual @ symbol");
        }

        if (text.matches(".*\\d+\\.\\d+\\.\\d+\\.\\d+.*")) {
            result.score += 30;
            result.reasons.add("URL appears to use an IP address");
        }

        String[] suspiciousTerms = {
                "login", "verify", "secure", "account",
                "update", "free", "prize", "claim"
        };

        for (String term : suspiciousTerms) {

            if (text.contains(term)) {

                result.score += 10;

                result.reasons.add(
                        "Suspicious keyword found: " + term
                );

                break;
            }
        }

        if (text.length() > 100) {
            result.score += 15;
            result.reasons.add("Unusually long URL");
        }

        result.score = Math.min(result.score, 100);

        return result;
    }

    public static String getRiskLevel(int score) {

        if (score >= 60) {
            return "HIGH";
        } else if (score >= 30) {
            return "MODERATE";
        }

        return "LOW";
    }
}