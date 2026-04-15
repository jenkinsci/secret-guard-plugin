package io.jenkins.plugins.secretguard.action;

import hudson.model.Action;
import hudson.model.Job;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.service.ScanResultStore;
import java.util.Collections;
import java.util.List;

public class SecretGuardJobAction implements Action, SeverityBadgeSupport {
    private final Job<?, ?> job;

    public SecretGuardJobAction(Job<?, ?> job) {
        this.job = job;
    }

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

    public Job<?, ?> getJob() {
        return job;
    }

    public SecretScanResult getResult() {
        return ScanResultStore.get()
                .get(job.getFullName())
                .orElse(SecretScanResult.empty(job.getFullName(), job.getClass().getSimpleName()));
    }

    public List<SecretFinding> getFindings() {
        return getResult().getFindings();
    }

    public boolean hasFindings() {
        return !getFindings().isEmpty();
    }

    public List<SecretScanResult> getResults() {
        return Collections.singletonList(getResult());
    }
}
