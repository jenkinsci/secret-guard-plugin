package io.jenkins.plugins.secretguard.service;

import hudson.model.Job;
import io.jenkins.plugins.secretguard.config.SecretGuardGlobalConfiguration;
import io.jenkins.plugins.secretguard.model.EnforcementMode;
import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.ScanPhase;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.scan.ConfigXmlScanner;
import java.io.IOException;

public class ManualJobScanService {
    private final SecretScanService scanService;
    private final ConfigXmlScanner configXmlScanner;

    public ManualJobScanService() {
        this(new SecretScanService(), new ConfigXmlScanner());
    }

    ManualJobScanService(SecretScanService scanService, ConfigXmlScanner configXmlScanner) {
        this.scanService = scanService;
        this.configXmlScanner = configXmlScanner;
    }

    public SecretScanResult scanJob(Job<?, ?> job) throws IOException {
        SecretGuardGlobalConfiguration configuration = SecretGuardGlobalConfiguration.get();
        ScanContext context = new ScanContext(
                job.getFullName(),
                "config.xml",
                job.getClass().getSimpleName(),
                FindingLocationType.CONFIG_XML,
                ScanPhase.MANUAL,
                EnforcementMode.AUDIT,
                configuration == null ? Severity.HIGH : configuration.getBlockThreshold());
        return scanService.scan(configXmlScanner, context, job.getConfigFile().asString());
    }
}
