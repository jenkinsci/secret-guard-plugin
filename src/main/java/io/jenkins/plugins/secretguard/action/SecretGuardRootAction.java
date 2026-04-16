package io.jenkins.plugins.secretguard.action;

import hudson.Extension;
import hudson.Util;
import hudson.model.Failure;
import hudson.model.RootAction;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.service.GlobalJobScanService;
import io.jenkins.plugins.secretguard.service.GlobalJobScanSummary;
import io.jenkins.plugins.secretguard.service.ScanResultStore;
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
        return true;
    }

    public boolean isScanAllCompleted() {
        StaplerRequest2 request = Stapler.getCurrentRequest2();
        return request != null && "success".equals(request.getParameter("scanAll"));
    }

    public GlobalJobScanSummary getScanAllSummary() {
        StaplerRequest2 request = Stapler.getCurrentRequest2();
        if (request == null || !"success".equals(request.getParameter("scanAll"))) {
            return null;
        }
        return new GlobalJobScanSummary(
                intParameter(request, "jobsScanned"),
                intParameter(request, "jobsWithFindings"),
                intParameter(request, "jobsWithHighSeverity"),
                intParameter(request, "jobsFailed"));
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
        if (!canScanAllNow()) {
            throw new Failure("Secret Guard global scan is unavailable.");
        }
        GlobalJobScanSummary summary = globalJobScanService.scanAllJobs();
        return HttpResponses.redirectViaContextPath("secret-guard?scanAll=success"
                + "&jobsScanned=" + summary.getJobsScanned()
                + "&jobsWithFindings=" + summary.getJobsWithFindings()
                + "&jobsWithHighSeverity=" + summary.getJobsWithHighSeverity()
                + "&jobsFailed=" + summary.getJobsFailed());
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

    private int intParameter(StaplerRequest2 request, String name) {
        String value = request.getParameter(name);
        if (value == null || value.isBlank()) {
            return 0;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }
}
