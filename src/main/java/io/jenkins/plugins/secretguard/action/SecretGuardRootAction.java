package io.jenkins.plugins.secretguard.action;

import hudson.Extension;
import hudson.model.RootAction;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.service.ScanResultStore;
import java.util.List;

@Extension
public class SecretGuardRootAction implements RootAction {
    @Override
    public String getIconFileName() {
        return "symbol-shield-checkmark-outline plugin-ionicons-api";
    }

    @Override
    public String getDisplayName() {
        return "Secret Guard";
    }

    @Override
    public String getUrlName() {
        return "secret-guard";
    }

    public List<SecretScanResult> getResults() {
        return ScanResultStore.get().getAll();
    }

    public long getUnexemptedHighCount() {
        return ScanResultStore.get().getUnexemptedHighCount();
    }
}
