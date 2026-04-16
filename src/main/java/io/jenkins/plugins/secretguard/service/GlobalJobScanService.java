package io.jenkins.plugins.secretguard.service;

import hudson.model.Job;
import hudson.security.ACL;
import hudson.security.ACLContext;
import io.jenkins.plugins.secretguard.model.Severity;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;

public class GlobalJobScanService {
    private static final Logger LOGGER = Logger.getLogger(GlobalJobScanService.class.getName());
    private static final String LOG_PREFIX = "[Secret Guard][Global Scan] ";

    private final ManualJobScanService manualJobScanService;

    public GlobalJobScanService() {
        this(new ManualJobScanService());
    }

    GlobalJobScanService(ManualJobScanService manualJobScanService) {
        this.manualJobScanService = manualJobScanService;
    }

    public GlobalJobScanSummary scanAllJobs() {
        int jobsScanned = 0;
        int jobsWithFindings = 0;
        int jobsWithHighSeverity = 0;
        int jobsFailed = 0;

        try (ACLContext ignored = ACL.as2(ACL.SYSTEM2)) {
            for (Job<?, ?> job : Jenkins.get().allItems(Job.class)) {
                jobsScanned++;
                try {
                    var result = manualJobScanService.scanJob(job);
                    if (result.hasFindings()) {
                        jobsWithFindings++;
                    }
                    if (result.getHighestSeverity().isAtLeast(Severity.HIGH)) {
                        jobsWithHighSeverity++;
                    }
                } catch (IOException | RuntimeException e) {
                    jobsFailed++;
                    LOGGER.log(Level.WARNING, LOG_PREFIX + "Failed to scan job " + job.getFullName(), e);
                }
            }
        }

        LOGGER.log(
                Level.FINE,
                LOG_PREFIX
                        + "Completed global scan: jobsScanned={0}, jobsWithFindings={1}, jobsWithHighSeverity={2}, jobsFailed={3}",
                new Object[] {jobsScanned, jobsWithFindings, jobsWithHighSeverity, jobsFailed});
        return new GlobalJobScanSummary(jobsScanned, jobsWithFindings, jobsWithHighSeverity, jobsFailed);
    }
}
