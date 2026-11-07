
package com.example.scamshield;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class UrlhausChecker {

    private static final String API_URL =
            "https://urlhaus-api.abuse.ch/v1/url/";

    private static final ExecutorService EXECUTOR =
            Executors.newSingleThreadExecutor();

    public interface Callback {
        void onResult(Result result);
    }

    public static class Result {
        public final boolean listed;
        public final boolean successful;
        public final String message;

        public Result(
                boolean listed,
                boolean successful,
                String message
        ) {
            this.listed = listed;
            this.successful = successful;
            this.message = message;
        }
    }

    public static void check(
            String urlToCheck,
            String authKey,
            Callback callback
    ) {
        EXECUTOR.execute(() -> {
            Result result;

            try {
                HttpURLConnection connection =
                        (HttpURLConnection)
                                new URL(API_URL).openConnection();

                connection.setRequestMethod("POST");
                connection.setConnectTimeout(10000);
                connection.setReadTimeout(10000);
                connection.setDoOutput(true);
                connection.setRequestProperty(
                        "Auth-Key", authKey.trim()
                );
                connection.setRequestProperty(
                        "Content-Type",
                        "application/x-www-form-urlencoded"
                );

                String formData = "url=" +
                        URLEncoder.encode(
                                urlToCheck,
                                StandardCharsets.UTF_8.name()
                        );

                try (OutputStream output =
                             connection.getOutputStream()) {
                    output.write(
                            formData.getBytes(StandardCharsets.UTF_8)
                    );
                }

                int statusCode = connection.getResponseCode();

                InputStream stream = statusCode >= 200
                        && statusCode < 300
                        ? connection.getInputStream()
                        : connection.getErrorStream();

                if (stream == null) {
                    throw new IllegalStateException(
                            "URLhaus returned HTTP " + statusCode
                    );
                }

                StringBuilder response = new StringBuilder();

                try (BufferedReader reader =
                             new BufferedReader(
                                     new InputStreamReader(
                                             stream,
                                             StandardCharsets.UTF_8
                                     ))) {
                    String line;

                    while ((line = reader.readLine()) != null) {
                        response.append(line);
                    }
                } finally {
                    connection.disconnect();
                }

                if (statusCode < 200 || statusCode >= 300) {
                    throw new IllegalStateException(
                            "URLhaus returned HTTP " + statusCode
                    );
                }

                JSONObject json =
                        new JSONObject(response.toString());

                String queryStatus =
                        json.optString("query_status", "");

                if ("ok".equalsIgnoreCase(queryStatus)) {
                    result = new Result(
                            true,
                            true,
                            "URLhaus reports this URL as a known malware-distribution URL."
                    );
                } else if ("no_results".equalsIgnoreCase(queryStatus)) {
                    result = new Result(
                            false,
                            true,
                            "URLhaus returned no matching malware URL."
                    );
                } else {
                    result = new Result(
                            false,
                            false,
                            "URLhaus could not complete the lookup: "
                                    + queryStatus
                    );
                }

            } catch (Exception error) {
                result = new Result(
                        false,
                        false,
                        "URLhaus lookup unavailable: "
                                + error.getMessage()
                );
            }

            Result finalResult = result;

            android.os.Handler mainHandler =
                    new android.os.Handler(
                            android.os.Looper.getMainLooper()
                    );

            mainHandler.post(() -> callback.onResult(finalResult));
        });
    }
}
