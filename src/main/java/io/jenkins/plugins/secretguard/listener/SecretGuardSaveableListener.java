package io.jenkins.plugins.secretguard.listener;

import hudson.Extension;
import hudson.XmlFile;
import hudson.model.Job;
import hudson.model.Saveable;
import hudson.model.listeners.SaveableListener;
import io.jenkins.plugins.secretguard.model.ScanPhase;
import io.jenkins.plugins.secretguard.service.JobConfigEnforcementService;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

@Extension
public class SecretGuardSaveableListener extends SaveableListener {
    private static final Logger LOGGER = Logger.getLogger(SecretGuardSaveableListener.class.getName());

    private final JobConfigEnforcementService enforcementService = new JobConfigEnforcementService();

    @Override
    public void onChange(Saveable saveable, XmlFile file) {
        if (!(saveable instanceof Job<?, ?> job) || file == null) {
            return;
        }
        try {
            enforcementService.scan(job, file.asString(), ScanPhase.SAVE);
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Failed to scan job configuration for " + job.getFullName(), e);
        }
    }
}
