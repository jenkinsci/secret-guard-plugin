package io.jenkins.plugins.secretguard.listener;

import hudson.Extension;
import hudson.XmlFile;
import hudson.model.Job;
import hudson.model.Saveable;
import hudson.model.listeners.SaveableListener;
import io.jenkins.plugins.secretguard.config.SecretGuardGlobalConfiguration;
import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.ScanPhase;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.scan.ConfigXmlScanner;
import io.jenkins.plugins.secretguard.service.SecretScanService;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

@Extension
public class SecretGuardSaveableListener extends SaveableListener {
    private static final Logger LOGGER = Logger.getLogger(SecretGuardSaveableListener.class.getName());

    private final SecretScanService scanService = new SecretScanService();
    private final ConfigXmlScanner configXmlScanner = new ConfigXmlScanner();

    @Override
    public void onChange(Saveable saveable, XmlFile file) {
        if (!(saveable instanceof Job<?, ?> job) || file == null) {
            return;
        }
        try {
            SecretScanResult result = scanService.scan(configXmlScanner, createContext(job), file.asString());
            if (result.isBlocked()) {
                throw new IllegalStateException("Secret Guard blocked saving " + job.getFullName()
                        + " because high severity secrets were found.");
            }
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Failed to scan job configuration for " + job.getFullName(), e);
        }
    }

    private ScanContext createContext(Job<?, ?> job) {
        SecretGuardGlobalConfiguration configuration = SecretGuardGlobalConfiguration.get();
        return new ScanContext(
                job.getFullName(),
                "config.xml",
                job.getClass().getSimpleName(),
                FindingLocationType.CONFIG_XML,
                ScanPhase.SAVE,
                configuration == null ? io.jenkins.plugins.secretguard.model.EnforcementMode.AUDIT : configuration.getEnforcementMode(),
                configuration == null ? io.jenkins.plugins.secretguard.model.Severity.HIGH : configuration.getBlockThreshold());
    }
}
