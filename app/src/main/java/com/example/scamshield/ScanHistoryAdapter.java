
package com.example.scamshield;

import android.graphics.Color;
import android.view.LayoutInflater;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.example.scamshield.databinding.ItemScanHistoryBinding;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class ScanHistoryAdapter
        extends RecyclerView.Adapter<ScanHistoryAdapter.ScanViewHolder> {

    public interface OnScanClickListener {
        void onScanClick(ScanRecord record);
    }

    private final List<ScanRecord> scanList;
    private final OnScanClickListener listener;

    public ScanHistoryAdapter(
            List<ScanRecord> scanList,
            OnScanClickListener listener
    ) {
        this.scanList = scanList;
        this.listener = listener;
    }

    @NonNull
    @Override
    public ScanViewHolder onCreateViewHolder(
            @NonNull ViewGroup parent,
            int viewType
    ) {
        ItemScanHistoryBinding binding =
                ItemScanHistoryBinding.inflate(
                        LayoutInflater.from(parent.getContext()),
                        parent,
                        false
                );

        return new ScanViewHolder(binding);
    }

    @Override
    public void onBindViewHolder(
            @NonNull ScanViewHolder holder,
            int position
    ) {
        ScanRecord record = scanList.get(position);
        ItemScanHistoryBinding binding = holder.binding;

        binding.scanType.setText(record.getScanType() + " SCAN");
        binding.scannedContent.setText(record.getScannedContent());
        binding.riskLevel.setText(record.getRiskLevel());
        binding.riskScore.setText(
                "Risk Score: " + record.getRiskScore() + "/100"
        );

        String date = new SimpleDateFormat(
                "dd MMM yyyy, hh:mm a",
                Locale.getDefault()
        ).format(new Date(record.getScannedAt()));

        binding.scanDate.setText(date);

        switch (record.getRiskLevel()) {
            case "HIGH":
                binding.riskLevel.setTextColor(Color.rgb(255, 107, 107));
                break;

            case "MODERATE":
                binding.riskLevel.setTextColor(Color.rgb(255, 190, 80));
                break;

            default:
                binding.riskLevel.setTextColor(Color.rgb(22, 199, 132));
                break;
        }

        holder.itemView.setOnClickListener(v -> {
            if (listener != null) {
                listener.onScanClick(record);
            }
        });
    }

    @Override
    public int getItemCount() {
        return scanList.size();
    }

    static class ScanViewHolder extends RecyclerView.ViewHolder {

        final ItemScanHistoryBinding binding;

        ScanViewHolder(ItemScanHistoryBinding binding) {
            super(binding.getRoot());
            this.binding = binding;
        }
    }
}
