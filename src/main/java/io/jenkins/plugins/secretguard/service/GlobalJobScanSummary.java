package io.jenkins.plugins.secretguard.service;

public class GlobalJobScanSummary {
    private final int jobsScanned;
    private final int jobsWithFindings;
    private final int jobsWithHighSeverity;
    private final int jobsFailed;

    public GlobalJobScanSummary(int jobsScanned, int jobsWithFindings, int jobsWithHighSeverity, int jobsFailed) {
        this.jobsScanned = jobsScanned;
        this.jobsWithFindings = jobsWithFindings;
        this.jobsWithHighSeverity = jobsWithHighSeverity;
        this.jobsFailed = jobsFailed;
    }

    public int getJobsScanned() {
        return jobsScanned;
    }

    public int getJobsWithFindings() {
        return jobsWithFindings;
    }

    public int getJobsWithHighSeverity() {
        return jobsWithHighSeverity;
    }

    public int getJobsFailed() {
        return jobsFailed;
    }
}
