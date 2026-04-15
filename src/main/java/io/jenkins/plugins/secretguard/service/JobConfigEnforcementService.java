package io.jenkins.plugins.secretguard.service;

import hudson.model.Job;
import io.jenkins.plugins.secretguard.config.SecretGuardGlobalConfiguration;
import io.jenkins.plugins.secretguard.model.EnforcementMode;
import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.ScanPhase;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.scan.ConfigXmlScanner;

public class JobConfigEnforcementService {
    private final SecretScanService scanService;
    private final ConfigXmlScanner configXmlScanner;

    public JobConfigEnforcementService() {
        this(new SecretScanService(), new ConfigXmlScanner());
    }

    JobConfigEnforcementService(SecretScanService scanService, ConfigXmlScanner configXmlScanner) {
        this.scanService = scanService;
        this.configXmlScanner = configXmlScanner;
    }

    public SecretScanResult scan(Job<?, ?> job, String content, ScanPhase phase) {
        return scanService.scan(configXmlScanner, createContext(job, phase), content);
    }

    public String buildBlockedMessage(String action, String targetName, SecretScanResult result) {
        String effectiveTargetName = targetName == null || targetName.isBlank() ? "job" : targetName;
        if (result == null || result.getFindings().isEmpty()) {
            return "Secret Guard blocked " + action + " for " + effectiveTargetName
                    + " because unexempted high severity secret risks were found.";
        }
        SecretFinding finding = result.getFindings().get(0);
        return "Secret Guard blocked " + action + " for " + effectiveTargetName + " because of "
                + finding.getSeverity().name() + " finding `" + finding.getRuleId() + "` with masked snippet `"
                + finding.getMaskedSnippet() + "`.";
    }

    private ScanContext createContext(Job<?, ?> job, ScanPhase phase) {
        SecretGuardGlobalConfiguration configuration = SecretGuardGlobalConfiguration.get();
        return new ScanContext(
                job.getFullName(),
                "config.xml",
                job.getClass().getSimpleName(),
                FindingLocationType.CONFIG_XML,
                phase,
                configuration == null ? EnforcementMode.AUDIT : configuration.getEnforcementMode(),
                configuration == null ? Severity.HIGH : configuration.getBlockThreshold());
    }
}
