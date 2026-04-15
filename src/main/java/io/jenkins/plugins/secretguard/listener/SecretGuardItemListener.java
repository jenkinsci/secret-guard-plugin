package io.jenkins.plugins.secretguard.listener;

import hudson.Extension;
import hudson.model.AbstractItem;
import hudson.model.Item;
import hudson.model.Job;
import hudson.model.listeners.ItemListener;
import io.jenkins.plugins.secretguard.config.SecretGuardGlobalConfiguration;
import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.ScanPhase;
import io.jenkins.plugins.secretguard.scan.ConfigXmlScanner;
import io.jenkins.plugins.secretguard.service.ScanResultStore;
import io.jenkins.plugins.secretguard.service.SecretScanService;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

@Extension
public class SecretGuardItemListener extends ItemListener {
    private static final Logger LOGGER = Logger.getLogger(SecretGuardItemListener.class.getName());

    private final SecretScanService scanService = new SecretScanService();
    private final ConfigXmlScanner configXmlScanner = new ConfigXmlScanner();

    @Override
    public void onCreated(Item item) {
        scanItem(item);
    }

    @Override
    public void onUpdated(Item item) {
        scanItem(item);
    }

    @Override
    public void onDeleted(Item item) {
        if (item != null) {
            ScanResultStore.get().remove(item.getFullName());
        }
    }

    @Override
    public void onLocationChanged(Item item, String oldFullName, String newFullName) {
        ScanResultStore.get().remove(oldFullName);
        scanItem(item);
    }

    private void scanItem(Item item) {
        if (!(item instanceof Job<?, ?> job) || !(item instanceof AbstractItem abstractItem)) {
            return;
        }
        try {
            SecretGuardGlobalConfiguration configuration = SecretGuardGlobalConfiguration.get();
            ScanContext context = new ScanContext(
                    job.getFullName(),
                    "config.xml",
                    job.getClass().getSimpleName(),
                    FindingLocationType.CONFIG_XML,
                    ScanPhase.SAVE,
                    configuration == null ? io.jenkins.plugins.secretguard.model.EnforcementMode.AUDIT : configuration.getEnforcementMode(),
                    configuration == null ? io.jenkins.plugins.secretguard.model.Severity.HIGH : configuration.getBlockThreshold());
            scanService.scan(configXmlScanner, context, abstractItem.getConfigFile().asString());
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Failed to scan updated item " + item.getFullName(), e);
        }
    }
}
