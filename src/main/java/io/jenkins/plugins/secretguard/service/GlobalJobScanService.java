package io.jenkins.plugins.secretguard.service;

import hudson.model.Job;
import hudson.security.ACL;
import hudson.security.ACLContext;
import io.jenkins.plugins.secretguard.model.Severity;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.locks.LockSupport;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import jenkins.util.Timer;

public class GlobalJobScanService {
    private static final Logger LOGGER = Logger.getLogger(GlobalJobScanService.class.getName());
    private static final String LOG_PREFIX = "[Secret Guard][Global Scan] ";
    private static final int DEFAULT_YIELD_AFTER_JOBS = 25;
    private static final long DEFAULT_YIELD_NANOS = Duration.ofMillis(10).toNanos();

    private final ManualJobScanService manualJobScanService;
    private final Executor executor;
    private final Supplier<List<Job<?, ?>>> jobSupplier;
    private final int yieldAfterJobs;
    private final Runnable yieldAction;
    private final Object lock = new Object();

    private GlobalJobScanStatus status = GlobalJobScanStatus.idle();
    private ScanExecution activeExecution;

    public GlobalJobScanService() {
        this(
                new ManualJobScanService(),
                command -> Timer.get().submit(command),
                GlobalJobScanService::loadAllJobs,
                DEFAULT_YIELD_AFTER_JOBS,
                GlobalJobScanService::yieldScheduling);
    }

    GlobalJobScanService(ManualJobScanService manualJobScanService) {
        this(
                manualJobScanService,
                command -> Timer.get().submit(command),
                GlobalJobScanService::loadAllJobs,
                DEFAULT_YIELD_AFTER_JOBS,
                GlobalJobScanService::yieldScheduling);
    }

    GlobalJobScanService(ManualJobScanService manualJobScanService, Executor executor) {
        this(
                manualJobScanService,
                executor,
                GlobalJobScanService::loadAllJobs,
                DEFAULT_YIELD_AFTER_JOBS,
                GlobalJobScanService::yieldScheduling);
    }

    GlobalJobScanService(
            ManualJobScanService manualJobScanService,
            Executor executor,
            Supplier<List<Job<?, ?>>> jobSupplier,
            int yieldAfterJobs,
            Runnable yieldAction) {
        this.manualJobScanService = manualJobScanService;
        this.executor = executor;
        this.jobSupplier = jobSupplier;
        this.yieldAfterJobs = Math.max(1, yieldAfterJobs);
        this.yieldAction = yieldAction == null ? GlobalJobScanService::yieldScheduling : yieldAction;
    }

    public boolean canStartScanAllJobs() {
        synchronized (lock) {
            return activeExecution == null;
        }
    }

    public GlobalJobScanStatus getStatus() {
        synchronized (lock) {
            return status;
        }
    }

    public boolean cancelScanAllJobs() {
        synchronized (lock) {
            if (activeExecution == null) {
                return false;
            }
            activeExecution.requestCancel();
            status = activeExecution.snapshot();
            return true;
        }
    }

    public boolean clearFinishedStatus() {
        synchronized (lock) {
            if (activeExecution != null || !status.isTerminal()) {
                return false;
            }
            status = GlobalJobScanStatus.idle();
            return true;
        }
    }

    public void startScanAllJobs() {
        startScanAllJobs(GlobalJobScanRequest.all());
    }

    public void startScanAllJobs(GlobalJobScanRequest request) {
        ScanExecution execution;
        synchronized (lock) {
            if (activeExecution != null) {
                return;
            }
            execution = new ScanExecution(request == null ? GlobalJobScanRequest.all() : request);
            activeExecution = execution;
            status = execution.snapshot();
        }
        executor.execute(() -> runScan(execution));
    }

    private void runScan(ScanExecution execution) {
        try (ACLContext ignored = ACL.as2(ACL.SYSTEM2)) {
            List<Job<?, ?>> jobs = new ArrayList<>();
            for (Job<?, ?> job : jobSupplier.get()) {
                if (execution.matches(job)) {
                    jobs.add(job);
                }
            }
            execution.markRunning(jobs.size());
            publish(execution);

            for (int index = 0; index < jobs.size(); index++) {
                Job<?, ?> job = jobs.get(index);
                if (execution.isCancelRequested()) {
                    execution.markCancelled();
                    finish(execution);
                    return;
                }
                execution.startJob(job.getFullName());
                publish(execution);
                try {
                    var result = manualJobScanService.scanJob(job);
                    execution.recordSuccess(
                            result.hasFindings(), result.getHighestSeverity().isAtLeast(Severity.HIGH));
                } catch (IOException | RuntimeException e) {
                    execution.recordFailure(job.getFullName());
                    LOGGER.log(Level.WARNING, LOG_PREFIX + "Failed to scan job " + job.getFullName(), e);
                }
                publish(execution);
                if ((index + 1) < jobs.size() && execution.shouldYield(yieldAfterJobs)) {
                    yieldAction.run();
                }
            }

            if (execution.isCancelRequested()) {
                execution.markCancelled();
            } else {
                execution.markCompleted();
            }
        } catch (RuntimeException e) {
            execution.markFailed(e.getMessage());
            LOGGER.log(Level.WARNING, LOG_PREFIX + "Global job scan failed unexpectedly", e);
        }
        finish(execution);
    }

    private void publish(ScanExecution execution) {
        synchronized (lock) {
            if (activeExecution == execution) {
                status = execution.snapshot();
            }
        }
    }

    private void finish(ScanExecution execution) {
        synchronized (lock) {
            status = execution.snapshot();
            if (activeExecution == execution) {
                activeExecution = null;
            }
        }

        GlobalJobScanStatus snapshot = execution.snapshot();
        if (snapshot.getState() == GlobalJobScanStatus.State.COMPLETED) {
            LOGGER.log(
                    Level.FINE,
                    LOG_PREFIX
                            + "Completed global scan: jobsScanned={0}, jobsWithFindings={1}, jobsWithHighSeverity={2}, jobsFailed={3}",
                    new Object[] {
                        snapshot.getJobsScanned(),
                        snapshot.getJobsWithFindings(),
                        snapshot.getJobsWithHighSeverity(),
                        snapshot.getJobsFailed()
                    });
        }
    }

    private static List<Job<?, ?>> loadAllJobs() {
        List<Job<?, ?>> jobs = new ArrayList<>();
        for (Job<?, ?> job : Jenkins.get().allItems(Job.class)) {
            jobs.add(job);
        }
        return jobs;
    }

    private static void yieldScheduling() {
        LockSupport.parkNanos(DEFAULT_YIELD_NANOS);
    }

    private static final class ScanExecution {
        private GlobalJobScanStatus.State state = GlobalJobScanStatus.State.RUNNING;
        private final GlobalJobScanRequest request;
        private int totalJobs;
        private int jobsScanned;
        private int jobsWithFindings;
        private int jobsWithHighSeverity;
        private int jobsFailed;
        private String currentJobFullName;
        private String message = "Queued global scan.";
        private boolean cancelRequested;
        private Instant startedAt;
        private Instant finishedAt;
        private final List<String> failedJobFullNames = new ArrayList<>();

        private ScanExecution(GlobalJobScanRequest request) {
            this.request = request == null ? GlobalJobScanRequest.all() : request;
        }

        synchronized void markRunning(int totalJobs) {
            this.totalJobs = totalJobs;
            this.startedAt = Instant.now();
            this.message = totalJobs == 0
                    ? (request.hasFilters() ? "No jobs matched the selected scan filters." : "No jobs found to scan.")
                    : "Global scan is running.";
        }

        synchronized void startJob(String jobFullName) {
            currentJobFullName = jobFullName;
            message = "Scanning " + jobFullName;
        }

        synchronized void recordSuccess(boolean hasFindings, boolean hasHighSeverity) {
            jobsScanned++;
            if (hasFindings) {
                jobsWithFindings++;
            }
            if (hasHighSeverity) {
                jobsWithHighSeverity++;
            }
            currentJobFullName = null;
            message = "Scanned " + jobsScanned + " of " + totalJobs + " jobs.";
        }

        synchronized void recordFailure(String jobFullName) {
            jobsScanned++;
            jobsFailed++;
            if (jobFullName != null && failedJobFullNames.size() < 20) {
                failedJobFullNames.add(jobFullName);
            }
            currentJobFullName = null;
            message = "Scanned " + jobsScanned + " of " + totalJobs + " jobs.";
        }

        synchronized void requestCancel() {
            cancelRequested = true;
            if (state == GlobalJobScanStatus.State.RUNNING) {
                message = "Cancelling after the current job finishes.";
            }
        }

        synchronized boolean isCancelRequested() {
            return cancelRequested;
        }

        synchronized boolean shouldYield(int everyNJobs) {
            return jobsScanned > 0 && jobsScanned % Math.max(1, everyNJobs) == 0;
        }

        synchronized void markCompleted() {
            state = GlobalJobScanStatus.State.COMPLETED;
            finishedAt = Instant.now();
            currentJobFullName = null;
            message = "Global scan completed.";
        }

        synchronized void markCancelled() {
            state = GlobalJobScanStatus.State.CANCELLED;
            finishedAt = Instant.now();
            currentJobFullName = null;
            message = "Global scan cancelled.";
        }

        synchronized void markFailed(String errorMessage) {
            state = GlobalJobScanStatus.State.FAILED;
            finishedAt = Instant.now();
            currentJobFullName = null;
            message = errorMessage == null || errorMessage.isBlank()
                    ? "Global scan failed."
                    : "Global scan failed: " + errorMessage;
        }

        boolean matches(Job<?, ?> job) {
            return request.matches(job);
        }

        synchronized GlobalJobScanStatus snapshot() {
            return new GlobalJobScanStatus(
                    state,
                    totalJobs,
                    jobsScanned,
                    jobsWithFindings,
                    jobsWithHighSeverity,
                    jobsFailed,
                    currentJobFullName,
                    message,
                    request.describeScope(),
                    startedAt,
                    finishedAt,
                    failedJobFullNames);
        }
    }
}
