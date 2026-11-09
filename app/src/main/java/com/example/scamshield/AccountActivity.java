
package com.example.scamshield;

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

        binding.btnBack.setOnClickListener(v -> finish());

        loadAccountInformation();
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

        String email = user.getEmail();

        binding.tvEmail.setText(
                email != null ? email : "Not available"
        );

        binding.tvUid.setText(user.getUid());

        String provider = "Email and Password";

        if (user.getProviderData() != null) {
            for (com.google.firebase.auth.UserInfo info
                    : user.getProviderData()) {

                if ("google.com".equals(info.getProviderId())) {
                    provider = "Google";
                    break;
                }
            }
        }

        binding.tvProvider.setText(provider);
        binding.tvStatus.setText("Authenticated");
    }
}
