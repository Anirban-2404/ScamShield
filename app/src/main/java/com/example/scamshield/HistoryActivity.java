package com.example.scamshield;

import android.os.Bundle;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;

import com.example.scamshield.databinding.ActivityHistoryBinding;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class HistoryActivity extends AppCompatActivity {

    private ActivityHistoryBinding binding;
    private ScanDatabaseHelper databaseHelper;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityHistoryBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        databaseHelper = new ScanDatabaseHelper(this);

        binding.backButton.setOnClickListener(v -> finish());

        binding.historyRecyclerView.setLayoutManager(
                new LinearLayoutManager(this)
        );

        loadHistory();
    }

    private void loadHistory() {

        List<ScanRecord> scans = databaseHelper.getAllScans();

        if (scans == null || scans.isEmpty()) {
            binding.emptyText.setVisibility(android.view.View.VISIBLE);
            binding.historyRecyclerView.setVisibility(android.view.View.GONE);
            return;
        }

        binding.emptyText.setVisibility(android.view.View.GONE);
        binding.historyRecyclerView.setVisibility(android.view.View.VISIBLE);

        ScanHistoryAdapter adapter = new ScanHistoryAdapter(
                scans,
                this::showScanDetails
        );

        binding.historyRecyclerView.setAdapter(adapter);
    }

    private void showScanDetails(ScanRecord record) {

        String date = new SimpleDateFormat(
                "dd MMM yyyy, hh:mm a",
                Locale.getDefault()
        ).format(new Date(record.getScannedAt()));

        String details =
                "Scan Type: " + record.getScanType() + "\n\n" +
                        "Scanned Content:\n" + record.getScannedContent() + "\n\n" +
                        "Risk Score: " + record.getRiskScore() + "/100\n\n" +
                        "Risk Level: " + record.getRiskLevel() + "\n\n" +
                        "Analysis:\n" + record.getExplanation() + "\n\n" +
                        "Date: " + date;

        new AlertDialog.Builder(this)
                .setTitle("Scan Details")
                .setMessage(details)
                .setPositiveButton("Close", null)
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
