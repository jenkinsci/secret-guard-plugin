package io.jenkins.plugins.secretguard.service;

import java.time.Instant;
import java.util.List;

public class GlobalJobScanStatus {
    public enum State {
        IDLE,
        RUNNING,
        COMPLETED,
        CANCELLED,
        FAILED
    }

    private final State state;
    private final int totalJobs;
    private final int jobsScanned;
    private final int jobsWithFindings;
    private final int jobsWithHighSeverity;
    private final int jobsFailed;
    private final String currentJobFullName;
    private final String message;
    private final Instant startedAt;
    private final Instant finishedAt;
    private final List<String> failedJobFullNames;

    public GlobalJobScanStatus(
            State state,
            int totalJobs,
            int jobsScanned,
            int jobsWithFindings,
            int jobsWithHighSeverity,
            int jobsFailed,
            String currentJobFullName,
            String message,
            Instant startedAt,
            Instant finishedAt,
            List<String> failedJobFullNames) {
        this.state = state == null ? State.IDLE : state;
        this.totalJobs = totalJobs;
        this.jobsScanned = jobsScanned;
        this.jobsWithFindings = jobsWithFindings;
        this.jobsWithHighSeverity = jobsWithHighSeverity;
        this.jobsFailed = jobsFailed;
        this.currentJobFullName = currentJobFullName;
        this.message = message;
        this.startedAt = startedAt;
        this.finishedAt = finishedAt;
        this.failedJobFullNames = failedJobFullNames == null ? List.of() : List.copyOf(failedJobFullNames);
    }

    public static GlobalJobScanStatus idle() {
        return new GlobalJobScanStatus(State.IDLE, 0, 0, 0, 0, 0, null, null, null, null, List.of());
    }

    public State getState() {
        return state;
    }

    public int getTotalJobs() {
        return totalJobs;
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

    public String getCurrentJobFullName() {
        return currentJobFullName;
    }

    public String getMessage() {
        return message;
    }

    public Instant getStartedAt() {
        return startedAt;
    }

    public Instant getFinishedAt() {
        return finishedAt;
    }

    public List<String> getFailedJobFullNames() {
        return failedJobFullNames;
    }

    public boolean isIdle() {
        return state == State.IDLE;
    }

    public boolean isRunning() {
        return state == State.RUNNING;
    }

    public boolean isTerminal() {
        return state == State.COMPLETED || state == State.CANCELLED || state == State.FAILED;
    }

    public boolean hasFailedJobs() {
        return !failedJobFullNames.isEmpty();
    }

    public int getProgressPercentage() {
        if (totalJobs <= 0) {
            return 0;
        }
        return Math.min(100, (jobsScanned * 100) / totalJobs);
    }

    public int getProgressMax() {
        return totalJobs <= 0 ? 1 : totalJobs;
    }

    public GlobalJobScanSummary getSummary() {
        return new GlobalJobScanSummary(jobsScanned, jobsWithFindings, jobsWithHighSeverity, jobsFailed);
    }
}
