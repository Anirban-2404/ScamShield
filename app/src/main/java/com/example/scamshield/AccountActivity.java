
package com.example.scamshield;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Bundle;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.example.scamshield.databinding.ActivityAccountBinding;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseUser;

public class AccountActivity extends AppCompatActivity {

    private ActivityAccountBinding binding;
    private FirebaseAuth auth;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityAccountBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        auth = FirebaseAuth.getInstance();

        // Back navigation
        binding.btnBack.setOnClickListener(v -> finish());

        // Load account information
        loadAccountInformation();

        // Copy Firebase UID
        binding.btnCopyUid.setOnClickListener(v -> copyUserId());

        // Send verification email
        binding.btnVerifyEmail.setOnClickListener(v -> sendVerificationEmail());
    }

    @Override
    protected void onResume() {
        super.onResume();

        // Refresh verification status when returning to the app
        refreshVerificationStatus();
    }

    private void loadAccountInformation() {

        FirebaseUser user = auth.getCurrentUser();

        if (user == null) {

            Toast.makeText(
                    this,
                    "No authenticated account found.",
                    Toast.LENGTH_SHORT
            ).show();

            finish();
            return;
        }

        // Email address
        String email = user.getEmail();

        binding.tvEmail.setText(
                email != null ? email : "Not available"
        );

        // Firebase UID
        binding.tvUid.setText(user.getUid());

        // Sign-in provider
        binding.tvProvider.setText("Email and Password");

        // Initial verification status
        updateVerificationUI(user);
    }

    private void updateVerificationUI(FirebaseUser user) {

        if (user.isEmailVerified()) {

            binding.tvStatus.setText("Email Verified");
            binding.tvStatus.setTextColor(
                    android.graphics.Color.parseColor("#42D392")
            );

            binding.btnVerifyEmail.setEnabled(false);
            binding.btnVerifyEmail.setText("Email Verified");

        } else {

            binding.tvStatus.setText("Email Not Verified");
            binding.tvStatus.setTextColor(
                    android.graphics.Color.parseColor("#FFB74D")
            );

            binding.btnVerifyEmail.setEnabled(true);
            binding.btnVerifyEmail.setText("Send Verification Email");
        }
    }

    private void refreshVerificationStatus() {

        FirebaseUser user = auth.getCurrentUser();

        if (user == null) {
            return;
        }

        user.reload().addOnCompleteListener(task -> {

            if (isFinishing() || isDestroyed()) {
                return;
            }

            FirebaseUser refreshedUser = auth.getCurrentUser();

            if (task.isSuccessful() && refreshedUser != null) {

                updateVerificationUI(refreshedUser);

            } else {

                Toast.makeText(
                        this,
                        "Could not refresh account status.",
                        Toast.LENGTH_SHORT
                ).show();
            }
        });
    }

    private void sendVerificationEmail() {

        FirebaseUser user = auth.getCurrentUser();

        if (user == null) {

            Toast.makeText(
                    this,
                    "Please log in again.",
                    Toast.LENGTH_SHORT
            ).show();

            return;
        }

        if (user.isEmailVerified()) {

            Toast.makeText(
                    this,
                    "Your email is already verified.",
                    Toast.LENGTH_SHORT
            ).show();

            updateVerificationUI(user);
            return;
        }

        binding.btnVerifyEmail.setEnabled(false);
        binding.btnVerifyEmail.setText("Sending...");

        user.sendEmailVerification()
                .addOnCompleteListener(task -> {

                    if (isFinishing() || isDestroyed()) {
                        return;
                    }

                    if (task.isSuccessful()) {

                        Toast.makeText(
                                AccountActivity.this,
                                "Verification email sent. Check your inbox.",
                                Toast.LENGTH_LONG
                        ).show();

                        binding.btnVerifyEmail.setText(
                                "Verification Email Sent"
                        );

                    } else {

                        binding.btnVerifyEmail.setEnabled(true);
                        binding.btnVerifyEmail.setText(
                                "Send Verification Email"
                        );

                        String error = task.getException() != null
                                ? task.getException().getMessage()
                                : "Unknown error";

                        Toast.makeText(
                                AccountActivity.this,
                                "Failed to send verification email: " + error,
                                Toast.LENGTH_LONG
                        ).show();
                    }
                });
    }

    private void copyUserId() {

        String uid = binding.tvUid.getText().toString().trim();

        if (uid.isEmpty() || uid.equals("Loading...")) {

            Toast.makeText(
                    this,
                    "User ID is not available",
                    Toast.LENGTH_SHORT
            ).show();

            return;
        }

        ClipboardManager clipboard =
                (ClipboardManager) getSystemService(
                        Context.CLIPBOARD_SERVICE
                );

        if (clipboard == null) {

            Toast.makeText(
                    this,
                    "Clipboard service unavailable",
                    Toast.LENGTH_SHORT
            ).show();

            return;
        }

        ClipData clip = ClipData.newPlainText(
                "ScamShield User ID",
                uid
        );

        clipboard.setPrimaryClip(clip);

        Toast.makeText(
                this,
                "User ID copied successfully",
                Toast.LENGTH_SHORT
        ).show();
    }
}
