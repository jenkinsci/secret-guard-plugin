package io.jenkins.plugins.secretguard.action;

import hudson.model.Failure;
import hudson.model.Item;
import hudson.model.Action;
import hudson.model.Job;
import io.jenkins.plugins.secretguard.config.SecretGuardGlobalConfiguration;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.service.ManualJobScanService;
import io.jenkins.plugins.secretguard.service.ScanResultStore;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.interceptor.RequirePOST;

public class SecretGuardJobAction implements Action, SeverityBadgeSupport {
    private final Job<?, ?> job;
    private final ManualJobScanService manualJobScanService;

    public SecretGuardJobAction(Job<?, ?> job) {
        this(job, new ManualJobScanService());
    }

    SecretGuardJobAction(Job<?, ?> job, ManualJobScanService manualJobScanService) {
        this.job = job;
        this.manualJobScanService = manualJobScanService;
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
        return result().orElse(SecretScanResult.empty(job.getFullName(), job.getClass().getSimpleName()));
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

    public boolean hasRecordedResult() {
        return result().isPresent();
    }

    public boolean isPluginEnabled() {
        SecretGuardGlobalConfiguration configuration = SecretGuardGlobalConfiguration.get();
        return configuration == null || configuration.isEnabled();
    }

    public boolean canScanNow() {
        return job != null && isPluginEnabled() && job.hasPermission(Item.CONFIGURE);
    }

    public boolean isManualScanCompleted() {
        StaplerRequest2 request = Stapler.getCurrentRequest2();
        return request != null && "success".equals(request.getParameter("manualScan"));
    }

    @RequirePOST
    public HttpResponse doScanNow() throws Exception {
        job.checkPermission(Item.CONFIGURE);
        try {
            manualJobScanService.scanJob(job);
        } catch (Exception e) {
            throw new Failure("Secret Guard manual scan failed: " + e.getMessage());
        }
        return HttpResponses.redirectViaContextPath(
                SecretGuardRootAction.toJobSecretGuardPath(job.getFullName()) + "?manualScan=success");
    }

    private Optional<SecretScanResult> result() {
        return ScanResultStore.get().get(job.getFullName());
    }
}
