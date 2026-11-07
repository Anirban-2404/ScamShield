
package com.example.scamshield;

import android.content.Intent;
import android.os.Bundle;
import android.util.Patterns;
import android.view.View;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.example.scamshield.databinding.ActivityRegisterBinding;
import com.google.firebase.auth.FirebaseAuth;

public class RegisterActivity extends AppCompatActivity {

    private ActivityRegisterBinding binding;
    private FirebaseAuth firebaseAuth;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityRegisterBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        firebaseAuth = FirebaseAuth.getInstance();

        binding.backButton.setOnClickListener(v -> finish());

        binding.registerButton.setOnClickListener(v -> registerUser());
    }

    private void registerUser() {

        String name = binding.nameInput.getText().toString().trim();
        String email = binding.emailInput.getText().toString().trim();
        String password = binding.passwordInput.getText().toString();
        String confirmPassword =
                binding.confirmPasswordInput.getText().toString();

        if (name.isEmpty()) {
            binding.nameInput.setError("Enter your full name");
            binding.nameInput.requestFocus();
            return;
        }

        if (email.isEmpty() ||
                !Patterns.EMAIL_ADDRESS.matcher(email).matches()) {
            binding.emailInput.setError("Enter a valid email address");
            binding.emailInput.requestFocus();
            return;
        }

        if (password.length() < 6) {
            binding.passwordInput.setError(
                    "Password must contain at least 6 characters"
            );
            binding.passwordInput.requestFocus();
            return;
        }

        if (!password.equals(confirmPassword)) {
            binding.confirmPasswordInput.setError(
                    "Passwords do not match"
            );
            binding.confirmPasswordInput.requestFocus();
            return;
        }

        setLoading(true);

        firebaseAuth.createUserWithEmailAndPassword(email, password)
                .addOnCompleteListener(this, task -> {

                    if (task.isSuccessful()) {

                        if (firebaseAuth.getCurrentUser() != null) {
                            firebaseAuth.getCurrentUser()
                                    .updateProfile(
                                            new com.google.firebase.auth
                                                    .UserProfileChangeRequest
                                                    .Builder()
                                                    .setDisplayName(name)
                                                    .build()
                                    )
                                    .addOnCompleteListener(profileTask -> {
                                        setLoading(false);

                                        Toast.makeText(
                                                this,
                                                "Account created successfully!",
                                                Toast.LENGTH_LONG
                                        ).show();

                                        openDashboard();
                                    });
                        } else {
                            setLoading(false);
                            openDashboard();
                        }

                    } else {
                        setLoading(false);

                        String error = task.getException() != null
                                ? task.getException().getLocalizedMessage()
                                : "Registration failed. Please try again.";

                        Toast.makeText(
                                this,
                                error,
                                Toast.LENGTH_LONG
                        ).show();
                    }
                });
    }

    private void setLoading(boolean loading) {
        binding.registerButton.setEnabled(!loading);
        binding.registerProgress.setVisibility(
                loading ? View.VISIBLE : View.GONE
        );
    }

    private void openDashboard() {
        Intent intent = new Intent(this, MainActivity.class);
        intent.addFlags(
                Intent.FLAG_ACTIVITY_NEW_TASK |
                        Intent.FLAG_ACTIVITY_CLEAR_TASK
        );
        startActivity(intent);
        finish();
    }
}
