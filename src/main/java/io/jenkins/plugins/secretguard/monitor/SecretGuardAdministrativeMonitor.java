package io.jenkins.plugins.secretguard.monitor;

import hudson.Extension;
import hudson.model.AdministrativeMonitor;
import io.jenkins.plugins.secretguard.service.ScanResultStore;

@Extension
public class SecretGuardAdministrativeMonitor extends AdministrativeMonitor {
    @Override
    public String getDisplayName() {
        return "Jenkins Secret Guard";
    }

    @Override
    public boolean isActivated() {
        return ScanResultStore.get().getUnexemptedHighCount() > 0;
    }

    public long getUnexemptedHighCount() {
        return ScanResultStore.get().getUnexemptedHighCount();
    }
}
