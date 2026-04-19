package io.jenkins.plugins.secretguard.listener;

import hudson.Extension;
import hudson.model.AbstractItem;
import hudson.model.Failure;
import hudson.model.Item;
import hudson.model.Job;
import hudson.model.listeners.ItemListener;
import io.jenkins.plugins.secretguard.model.ScanPhase;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.service.JobConfigEnforcementService;
import io.jenkins.plugins.secretguard.service.ScanResultStore;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

@Extension
public class SecretGuardItemListener extends ItemListener {
    private static final Logger LOGGER = Logger.getLogger(SecretGuardItemListener.class.getName());
    private static final String LOG_PREFIX = "[Secret Guard][Item Sync] ";

    private final JobConfigEnforcementService enforcementService = new JobConfigEnforcementService();

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
    public void onCheckCopy(Item src, hudson.model.ItemGroup parent) throws Failure {
        if (!(src instanceof Job<?, ?> job) || !(src instanceof AbstractItem abstractItem)) {
            return;
        }
        try {
            SecretScanResult result =
                    enforcementService.scan(job, abstractItem.getConfigFile().asString(), ScanPhase.SAVE);
            if (!result.isBlocked()) {
                return;
            }
            throw new Failure(enforcementService.buildBlockedMessage("copying", job.getFullName(), result));
        } catch (IOException e) {
            LOGGER.log(
                    Level.WARNING,
                    LOG_PREFIX + "Failed to scan job configuration before copying " + job.getFullName(),
                    e);
        }
    }

    @Override
    public void onLocationChanged(Item item, String oldFullName, String newFullName) {
        ScanResultStore.get().remove(oldFullName);
        scanItem(item);
    }

    private void scanItem(Item item) {
        if (JobConfigSaveScanGuard.isFilterManagedSave()) {
            return;
        }
        if (!(item instanceof Job<?, ?> job) || !(item instanceof AbstractItem abstractItem)) {
            return;
        }
        try {
            enforcementService.scan(job, abstractItem.getConfigFile().asString(), ScanPhase.SAVE);
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, LOG_PREFIX + "Failed to scan updated item " + item.getFullName(), e);
        }
    }
}
