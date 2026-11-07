
package com.example.scamshield;

public class ScanRecord {

    private final int id;
    private final String scanType;
    private final String scannedContent;
    private final int riskScore;
    private final String riskLevel;
    private final String explanation;
    private final long scannedAt;

    public ScanRecord(
            int id,
            String scanType,
            String scannedContent,
            int riskScore,
            String riskLevel,
            String explanation,
            long scannedAt
    ) {
        this.id = id;
        this.scanType = scanType;
        this.scannedContent = scannedContent;
        this.riskScore = riskScore;
        this.riskLevel = riskLevel;
        this.explanation = explanation;
        this.scannedAt = scannedAt;
    }

    public int getId() {
        return id;
    }

    public String getScanType() {
        return scanType;
    }

    public String getScannedContent() {
        return scannedContent;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public String getExplanation() {
        return explanation;
    }

    public long getScannedAt() {
        return scannedAt;
    }
}
