package io.jenkins.plugins.secretguard.action;

import hudson.Extension;
import hudson.Util;
import hudson.model.RootAction;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.service.GlobalJobScanService;
import io.jenkins.plugins.secretguard.service.GlobalJobScanStatus;
import io.jenkins.plugins.secretguard.service.ScanResultStore;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerProxy;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.interceptor.RequirePOST;

@Extension
public class SecretGuardRootAction implements RootAction, SeverityBadgeSupport, StaplerProxy {
    private final GlobalJobScanService globalJobScanService;

    public SecretGuardRootAction() {
        this(new GlobalJobScanService());
    }

    SecretGuardRootAction(GlobalJobScanService globalJobScanService) {
        this.globalJobScanService = globalJobScanService;
    }

    @Override
    public String getIconFileName() {
        if (!Jenkins.get().hasPermission(Jenkins.MANAGE)) {
            return null;
        }
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

    public Object getTarget() {
        Jenkins.get().checkPermission(Jenkins.MANAGE);
        return this;
    }

    public boolean canScanAllNow() {
        return globalJobScanService.canStartScanAllJobs();
    }

    public GlobalJobScanStatus getScanAllStatus() {
        return globalJobScanService.getStatus();
    }

    public boolean hasScanAllStatus() {
        return !getScanAllStatus().isIdle();
    }

    public boolean isScanAllRunning() {
        return getScanAllStatus().isRunning();
    }

    public boolean canCancelScanAll() {
        return isScanAllRunning();
    }

    public boolean canDismissScanAllStatus() {
        return hasScanAllStatus() && !isScanAllRunning();
    }

    public String getScanAllPrimaryButtonLabel() {
        if (isScanAllRunning()) {
            return "Scanning...";
        }
        return hasScanAllStatus() ? "Scan Again" : "Scan All Jobs";
    }

    public boolean isScanAllDetailsOpen() {
        GlobalJobScanStatus status = getScanAllStatus();
        return status.isRunning() || status.getState() == GlobalJobScanStatus.State.FAILED;
    }

    public String getScanAllSummaryText() {
        GlobalJobScanStatus status = getScanAllStatus();
        if (status.isIdle()) {
            return "No global scan has run yet.";
        }
        return "Scanned " + status.getJobsScanned() + " of " + status.getTotalJobs() + " jobs"
                + ", findings in " + status.getJobsWithFindings()
                + ", high severity in " + status.getJobsWithHighSeverity()
                + ", failed " + status.getJobsFailed() + ".";
    }

    public String getScanAllDurationText() {
        GlobalJobScanStatus status = getScanAllStatus();
        if (status.getStartedAt() == null) {
            return null;
        }
        Instant finishedAt = status.getFinishedAt() == null ? Instant.now() : status.getFinishedAt();
        Duration duration = Duration.between(status.getStartedAt(), finishedAt);
        long seconds = Math.max(0, duration.getSeconds());
        long hours = seconds / 3600;
        long minutes = (seconds % 3600) / 60;
        long remainingSeconds = seconds % 60;
        if (hours > 0) {
            return hours + "h " + minutes + "m";
        }
        if (minutes > 0) {
            return minutes + "m " + remainingSeconds + "s";
        }
        return remainingSeconds + "s";
    }

    public String getScanAllStateBadgeStyle(GlobalJobScanStatus.State state) {
        if (state == GlobalJobScanStatus.State.COMPLETED) {
            return "display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:700;"
                    + "line-height:1.5;border:1px solid #b7dfb9;background:#edf7ed;color:#1e6b2a;";
        }
        if (state == GlobalJobScanStatus.State.RUNNING) {
            return "display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:700;"
                    + "line-height:1.5;border:1px solid #b6d4fe;background:#eff6ff;color:#175cd3;";
        }
        if (state == GlobalJobScanStatus.State.CANCELLED) {
            return "display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:700;"
                    + "line-height:1.5;border:1px solid #d5d7da;background:#f5f5f5;color:#344054;";
        }
        if (state == GlobalJobScanStatus.State.FAILED) {
            return "display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:700;"
                    + "line-height:1.5;border:1px solid #f5c2c0;background:#fff1f0;color:#b42318;";
        }
        return "display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:700;"
                + "line-height:1.5;border:1px solid #d5d7da;background:#f5f5f5;color:#344054;";
    }

    public List<SecretScanResult> getResults() {
        return ScanResultStore.get().getAll();
    }

    public long getUnexemptedHighCount() {
        return ScanResultStore.get().getUnexemptedHighCount();
    }

    @RequirePOST
    public HttpResponse doScanAll() {
        Jenkins.get().checkPermission(Jenkins.MANAGE);
        globalJobScanService.startScanAllJobs();
        return HttpResponses.redirectViaContextPath("secret-guard");
    }

    @RequirePOST
    public HttpResponse doCancelScanAll() {
        Jenkins.get().checkPermission(Jenkins.MANAGE);
        globalJobScanService.cancelScanAllJobs();
        return HttpResponses.redirectViaContextPath("secret-guard");
    }

    @RequirePOST
    public HttpResponse doDismissScanAllStatus() {
        Jenkins.get().checkPermission(Jenkins.MANAGE);
        globalJobScanService.clearFinishedStatus();
        return HttpResponses.redirectViaContextPath("secret-guard");
    }

    public String getJobSecretGuardUrl(SecretScanResult result) {
        if (result == null) {
            return null;
        }
        String relativePath = toJobSecretGuardPath(result.getTargetId());
        if (relativePath == null) {
            return null;
        }
        StaplerRequest2 currentRequest = Stapler.getCurrentRequest2();
        if (currentRequest == null
                || currentRequest.getContextPath() == null
                || currentRequest.getContextPath().isBlank()) {
            return "/" + relativePath;
        }
        return currentRequest.getContextPath() + "/" + relativePath;
    }

    static String toJobSecretGuardPath(String targetId) {
        if (targetId == null || targetId.isBlank()) {
            return null;
        }
        StringBuilder path = new StringBuilder();
        for (String segment : targetId.split("/")) {
            if (segment.isBlank()) {
                continue;
            }
            if (path.length() > 0) {
                path.append('/');
            }
            path.append("job/").append(Util.rawEncode(segment));
        }
        if (path.length() == 0) {
            return null;
        }
        path.append("/secret-guard");
        return path.toString();
    }
}
