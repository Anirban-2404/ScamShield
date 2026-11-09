
package com.example.scamshield;

import android.os.Bundle;
import android.widget.Toast;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.os.Build;
import android.content.Context;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import com.example.scamshield.databinding.ActivityDashboardBinding;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseUser;
import com.google.firebase.database.DataSnapshot;
import com.google.firebase.database.DatabaseError;
import com.google.firebase.database.DatabaseReference;
import com.google.firebase.database.FirebaseDatabase;
import com.google.firebase.database.ValueEventListener;

public class DashboardActivity extends AppCompatActivity {

    private ActivityDashboardBinding binding;

    private DatabaseReference statsReference;
    private ValueEventListener statsListener;

    private FirebaseAuth firebaseAuth;

    private NetworkChangeReceiver networkReceiver;
    private boolean receiverRegistered = false;

    private boolean internetConnected = false;
    private boolean firebaseConnected = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityDashboardBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        binding.btnBack.setOnClickListener(v -> finish());

        firebaseAuth = FirebaseAuth.getInstance();

        FirebaseUser currentUser = firebaseAuth.getCurrentUser();

        if (currentUser == null) {
            Toast.makeText(
                    this,
                    "Please log in first.",
                    Toast.LENGTH_LONG
            ).show();

            finish();
            return;
        }

        String uid = currentUser.getUid();

        statsReference = FirebaseDatabase.getInstance()
                .getReference("users")
                .child(uid)
                .child("stats");

        binding.btnRefresh.setOnClickListener(v -> {
            loadStatistics();

            Toast.makeText(
                    this,
                    "Refreshing statistics...",
                    Toast.LENGTH_SHORT
            ).show();
        });

        loadStatistics();
    }

    private void loadStatistics() {

        if (statsReference == null) {
            return;
        }

        if (statsListener != null) {
            statsReference.removeEventListener(statsListener);
        }

        firebaseConnected = false;
        updateConnectionStatus();

        statsListener = new ValueEventListener() {

            @Override
            public void onDataChange(@NonNull DataSnapshot snapshot) {

                long messageScans = getLongValue(
                        snapshot, "totalMessageScans");

                long urlScans = getLongValue(
                        snapshot, "totalUrlScans");

                long highRisk = getLongValue(
                        snapshot, "highRiskDetections");

                long totalScans = messageScans + urlScans;

                binding.tvTotalScans.setText(
                        String.valueOf(totalScans));

                binding.tvUrlScans.setText(
                        String.valueOf(urlScans));

                binding.tvMessageScans.setText(
                        String.valueOf(messageScans));

                binding.tvHighRisk.setText(
                        String.valueOf(highRisk));

                long lastScanAt = getLongValue(
                        snapshot, "lastScanAt");

                if (lastScanAt > 0) {

                    java.text.SimpleDateFormat formatter =
                            new java.text.SimpleDateFormat(
                                    "dd MMM yyyy, hh:mm a",
                                    java.util.Locale.getDefault()
                            );

                    String formattedDate = formatter.format(
                            new java.util.Date(lastScanAt));

                    binding.tvLastScan.setText(
                            "Last scan: " + formattedDate);

                } else {

                    binding.tvLastScan.setText(
                            "Last scan: No scans yet");
                }

                firebaseConnected = true;
                updateConnectionStatus();
            }

            @Override
            public void onCancelled(@NonNull DatabaseError error) {

                firebaseConnected = false;
                updateConnectionStatus();

                Toast.makeText(
                        DashboardActivity.this,
                        "Firebase error: " + error.getMessage(),
                        Toast.LENGTH_LONG
                ).show();
            }
        };

        statsReference.addValueEventListener(statsListener);
    }

    private long getLongValue(
            DataSnapshot snapshot,
            String childName) {

        Long value = snapshot.child(childName).getValue(Long.class);

        return value != null ? value : 0L;
    }

    // Network connectivity receiver

    private void setupNetworkReceiver() {

        networkReceiver = new NetworkChangeReceiver(isConnected -> {
            internetConnected = isConnected;
            updateConnectionStatus();
        });

        IntentFilter filter = new IntentFilter(
                ConnectivityManager.CONNECTIVITY_ACTION);

        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(
                    networkReceiver,
                    filter,
                    Context.RECEIVER_NOT_EXPORTED
            );
        } else {
            registerReceiver(networkReceiver, filter);
        }

        receiverRegistered = true;

        // Check current internet connection immediately.
        networkReceiver.onReceive(
                this,
                new android.content.Intent(
                        ConnectivityManager.CONNECTIVITY_ACTION)
        );
    }

    private void updateConnectionStatus() {

        String internetStatus = internetConnected
                ? "Internet: Connected"
                : "Internet: Offline";

        String firebaseStatus = firebaseConnected
                ? "Firebase: Connected"
                : "Firebase: Disconnected";

        binding.tvConnectionStatus.setText(
                internetStatus + " | " + firebaseStatus
        );
    }

    @Override
    protected void onStart() {
        super.onStart();
        setupNetworkReceiver();
    }

    @Override
    protected void onStop() {
        super.onStop();

        if (receiverRegistered && networkReceiver != null) {
            unregisterReceiver(networkReceiver);
            receiverRegistered = false;
        }
    }

    @Override
    protected void onDestroy() {

        if (statsReference != null && statsListener != null) {
            statsReference.removeEventListener(statsListener);
        }

        super.onDestroy();
    }
}
