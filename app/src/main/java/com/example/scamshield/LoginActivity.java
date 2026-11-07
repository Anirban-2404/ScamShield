
package com.example.scamshield;

import android.content.Intent;
import android.os.Bundle;
import android.util.Patterns;
import android.view.View;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.example.scamshield.databinding.ActivityLoginBinding;
import com.google.firebase.auth.FirebaseAuth;

public class LoginActivity extends AppCompatActivity {

    private ActivityLoginBinding binding;
    private FirebaseAuth firebaseAuth;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityLoginBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        firebaseAuth = FirebaseAuth.getInstance();

        // Keep an existing authenticated session.
        if (firebaseAuth.getCurrentUser() != null) {
            openDashboard();
            return;
        }

        binding.loginButton.setOnClickListener(v -> loginUser());

        binding.registerLink.setOnClickListener(v -> {
            startActivity(new Intent(this, RegisterActivity.class));
        });
    }

    private void loginUser() {

        String email = binding.emailInput.getText().toString().trim();
        String password = binding.passwordInput.getText().toString();

        if (email.isEmpty()) {
            binding.emailInput.setError("Enter your email address");
            binding.emailInput.requestFocus();
            return;
        }

        if (!Patterns.EMAIL_ADDRESS.matcher(email).matches()) {
            binding.emailInput.setError("Enter a valid email address");
            binding.emailInput.requestFocus();
            return;
        }

        if (password.isEmpty()) {
            binding.passwordInput.setError("Enter your password");
            binding.passwordInput.requestFocus();
            return;
        }

        setLoading(true);

        firebaseAuth.signInWithEmailAndPassword(email, password)
                .addOnCompleteListener(this, task -> {
                    setLoading(false);

                    if (task.isSuccessful()) {
                        Toast.makeText(
                                this,
                                "Login successful!",
                                Toast.LENGTH_SHORT
                        ).show();

                        openDashboard();

                    } else {
                        String error = task.getException() != null
                                ? task.getException().getLocalizedMessage()
                                : "Login failed. Please try again.";

                        Toast.makeText(
                                this,
                                error,
                                Toast.LENGTH_LONG
                        ).show();
                    }
                });
    }

    private void setLoading(boolean loading) {
        binding.loginButton.setEnabled(!loading);
        binding.registerLink.setEnabled(!loading);
        binding.loginProgress.setVisibility(
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
