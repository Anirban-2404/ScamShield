
package com.example.scamshield;

import android.app.AlertDialog;
import android.os.Bundle;

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

        binding.historyRecyclerView.setLayoutManager(
                new LinearLayoutManager(this)
        );

        binding.backButton.setOnClickListener(v -> finish());

        loadHistory();
    }

    private void loadHistory() {

        List<ScanRecord> scanList = databaseHelper.getAllScans();

        if (scanList == null || scanList.isEmpty()) {
            binding.historyRecyclerView.setVisibility(android.view.View.GONE);
            binding.emptyText.setVisibility(android.view.View.VISIBLE);
            return;
        }

        binding.historyRecyclerView.setVisibility(android.view.View.VISIBLE);
        binding.emptyText.setVisibility(android.view.View.GONE);

        ScanHistoryAdapter adapter = new ScanHistoryAdapter(
                scanList,
                record -> showScanDetails(record)
        );

        binding.historyRecyclerView.setAdapter(adapter);
    }

    private void showScanDetails(ScanRecord scan) {

        SimpleDateFormat formatter = new SimpleDateFormat(
                "dd MMM yyyy, hh:mm a",
                Locale.getDefault()
        );

        String scanDate = formatter.format(
                new Date(scan.getScannedAt())
        );

        String details =
                "Scan Type: " + scan.getScanType()
                        + "\n\nScanned Content:\n"
                        + scan.getScannedContent()
                        + "\n\nRisk Score: "
                        + scan.getRiskScore() + "/100"
                        + "\n\nRisk Level: "
                        + scan.getRiskLevel()
                        + "\n\nScan Date: "
                        + scanDate
                        + "\n\nExplanation:\n"
                        + (scan.getExplanation() == null
                        ? "No explanation available."
                        : scan.getExplanation());

        new AlertDialog.Builder(this)
                .setTitle("Scan Details")
                .setMessage(details)
                .setNeutralButton("Share Report", (dialog, which) ->
                        ScanReportHelper.shareScan(this, scan)
                )
                .setPositiveButton("Close", null)
                .show();
    }

    @Override
    protected void onResume() {
        super.onResume();

        if (databaseHelper != null) {
            loadHistory();
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();

        if (databaseHelper != null) {
            databaseHelper.close();
            databaseHelper = null;
        }
    }
}
