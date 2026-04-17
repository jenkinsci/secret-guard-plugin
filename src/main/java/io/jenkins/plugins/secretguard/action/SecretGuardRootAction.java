package io.jenkins.plugins.secretguard.action;

import hudson.Extension;
import hudson.Util;
import hudson.model.RootAction;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.service.GlobalJobScanService;
import io.jenkins.plugins.secretguard.service.GlobalJobScanStatus;
import io.jenkins.plugins.secretguard.service.ScanResultStore;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerProxy;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.interceptor.RequirePOST;

@Extension
public class SecretGuardRootAction implements RootAction, SeverityBadgeSupport, ScanTimeDisplaySupport, StaplerProxy {
    private static final int MAX_DISPLAY_TARGET_LENGTH = 72;
    private static final int DISPLAY_TARGET_TAIL_SEGMENTS = 3;
    private static final String ELLIPSIS = "\u2026";

    private final GlobalJobScanService globalJobScanService;

    enum ResultFilter {
        ALL("all", "All"),
        HIGH("high", "High"),
        BLOCKED("blocked", "Blocked"),
        WITH_FINDINGS("with-findings", "With Findings");

        private final String parameterValue;
        private final String displayName;

        ResultFilter(String parameterValue, String displayName) {
            this.parameterValue = parameterValue;
            this.displayName = displayName;
        }

        String getParameterValue() {
            return parameterValue;
        }

        String getDisplayName() {
            return displayName;
        }

        static ResultFilter fromParameter(String value) {
            if (value == null || value.isBlank()) {
                return ALL;
            }
            for (ResultFilter filter : values()) {
                if (filter.parameterValue.equalsIgnoreCase(value.trim())) {
                    return filter;
                }
            }
            return ALL;
        }
    }

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
                + ", jobs with findings: " + status.getJobsWithFindings()
                + ", jobs with high severity findings: " + status.getJobsWithHighSeverity()
                + ", failed: " + status.getJobsFailed() + ".";
    }

    public String getScanAllDurationText() {
        GlobalJobScanStatus status = getScanAllStatus();
        if (status.getStartedAt() == null) {
            return null;
        }
        Instant finishedAt = status.getFinishedAt() == null ? Instant.now() : status.getFinishedAt();
        return formatDuration(Duration.between(status.getStartedAt(), finishedAt));
    }

    static String formatDuration(Duration duration) {
        long millis = Math.max(0, duration.toMillis());
        if (millis < 1000) {
            return millis + "ms";
        }
        long seconds = millis / 1000;
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
        return sortResults(ScanResultStore.get().getAll());
    }

    public List<SecretScanResult> getFilteredResults() {
        return filterResults(getResults(), getActiveResultFilter());
    }

    public int getScannedJobCount() {
        return getResults().size();
    }

    public long getJobsWithFindingsCount() {
        return getResults().stream().filter(SecretScanResult::hasFindings).count();
    }

    public long getBlockedJobCount() {
        return getResults().stream().filter(SecretScanResult::isBlocked).count();
    }

    public long getHighRiskJobCount() {
        return getResults().stream()
                .filter(result -> result.hasActionableFindingsAtOrAbove(Severity.HIGH))
                .count();
    }

    public long getTotalFindingsCount() {
        return getResults().stream()
                .mapToLong(result -> result.getFindings().size())
                .sum();
    }

    public long getUnexemptedHighCount() {
        return ScanResultStore.get().getUnexemptedHighCount();
    }

    public boolean hasResults() {
        return !getResults().isEmpty();
    }

    public boolean hasFilteredResults() {
        return !getFilteredResults().isEmpty();
    }

    public String getEmptyResultsMessage() {
        return hasResults()
                ? "No Secret Guard scan results match the selected filter."
                : "No Secret Guard scan results have been recorded yet.";
    }

    public String getFilterUrl(String filterValue) {
        ResultFilter filter = ResultFilter.fromParameter(filterValue);
        return buildResultsUrl(filter);
    }

    public boolean isActiveFilter(String filterValue) {
        return getActiveResultFilter() == ResultFilter.fromParameter(filterValue);
    }

    public String getFilterButtonClass(String filterValue) {
        return isActiveFilter(filterValue)
                ? "jenkins-button jenkins-submit-button jenkins-button--primary"
                : "jenkins-button jenkins-button--secondary";
    }

    public String getFilterButtonLabel(String filterValue) {
        ResultFilter filter = ResultFilter.fromParameter(filterValue);
        return filter.getDisplayName() + " (" + getFilterCount(filter) + ")";
    }

    public int getFilteredResultCount() {
        return getFilteredResults().size();
    }

    public String getHighFindingsCardClass() {
        return getUnexemptedHighCount() > 0
                ? "jenkins-alert jenkins-alert-warning"
                : "jenkins-alert jenkins-alert-info";
    }

    public String getBlockedJobsCardClass() {
        return getBlockedJobCount() > 0 ? "jenkins-alert jenkins-alert-danger" : "jenkins-alert jenkins-alert-info";
    }

    public String getBlockedBadgeStyle(boolean blocked) {
        if (blocked) {
            return "display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:700;"
                    + "line-height:1.5;border:1px solid #f5c2c0;background:#fff1f0;color:#b42318;";
        }
        return "display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:700;"
                + "line-height:1.5;border:1px solid #d5d7da;background:#f5f5f5;color:#344054;";
    }

    public String getBlockedBadgeLabel(boolean blocked) {
        return blocked ? "Blocked" : "Allowed";
    }

    public String getDisplayTargetId(SecretScanResult result) {
        if (result == null) {
            return "";
        }
        return compactTargetId(result.getTargetId());
    }

    public String getResultRowStyle(SecretScanResult result) {
        if (result == null) {
            return "";
        }
        if (result.isBlocked()) {
            return "background:#fff1f0;";
        }
        if (result.hasActionableFindingsAtOrAbove(Severity.HIGH)) {
            return "background:#fff8e5;";
        }
        return "";
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

    private String getRootActionUrl() {
        StaplerRequest2 currentRequest = Stapler.getCurrentRequest2();
        if (currentRequest == null
                || currentRequest.getContextPath() == null
                || currentRequest.getContextPath().isBlank()) {
            return "/secret-guard";
        }
        return currentRequest.getContextPath() + "/secret-guard";
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

    static String compactTargetId(String targetId) {
        if (targetId == null || targetId.length() <= MAX_DISPLAY_TARGET_LENGTH) {
            return targetId == null ? "" : targetId;
        }
        String pathTail = compactPathTail(targetId);
        if (!pathTail.equals(targetId)) {
            return middleEllipsize(pathTail);
        }
        return middleEllipsize(targetId);
    }

    private static String compactPathTail(String targetId) {
        String[] segments = targetId.split("/");
        List<String> visibleSegments = new java.util.ArrayList<>();
        for (String segment : segments) {
            if (!segment.isBlank()) {
                visibleSegments.add(segment);
            }
        }
        if (visibleSegments.size() <= DISPLAY_TARGET_TAIL_SEGMENTS) {
            return targetId;
        }
        int start = visibleSegments.size() - DISPLAY_TARGET_TAIL_SEGMENTS;
        return ELLIPSIS + "/" + String.join("/", visibleSegments.subList(start, visibleSegments.size()));
    }

    private static String middleEllipsize(String value) {
        if (value.length() <= MAX_DISPLAY_TARGET_LENGTH) {
            return value;
        }
        int remainingLength = MAX_DISPLAY_TARGET_LENGTH - ELLIPSIS.length();
        int prefixLength = remainingLength / 2;
        int suffixLength = remainingLength - prefixLength;
        return value.substring(0, prefixLength) + ELLIPSIS + value.substring(value.length() - suffixLength);
    }

    private ResultFilter getActiveResultFilter() {
        StaplerRequest2 currentRequest = Stapler.getCurrentRequest2();
        return currentRequest == null
                ? ResultFilter.ALL
                : ResultFilter.fromParameter(currentRequest.getParameter("filter"));
    }

    static List<SecretScanResult> filterResults(List<SecretScanResult> results, ResultFilter filter) {
        return results.stream().filter(result -> matchesFilter(result, filter)).toList();
    }

    static List<SecretScanResult> sortResults(List<SecretScanResult> results) {
        return results.stream()
                .sorted(Comparator.comparing(SecretScanResult::isBlocked)
                        .reversed()
                        .thenComparing(
                                result -> result.hasActionableFindingsAtOrAbove(Severity.HIGH),
                                Comparator.reverseOrder())
                        .thenComparing(result -> result.getFindings().size(), Comparator.reverseOrder())
                        .thenComparing(SecretScanResult::getScannedAt, Comparator.reverseOrder())
                        .thenComparing(SecretScanResult::getTargetId))
                .toList();
    }

    private long getFilterCount(ResultFilter filter) {
        return filterResults(getResults(), filter).size();
    }

    private String buildResultsUrl(ResultFilter filter) {
        StringBuilder url = new StringBuilder(getRootActionUrl());
        if (filter != ResultFilter.ALL) {
            url.append("?filter=").append(Util.rawEncode(filter.getParameterValue()));
        }
        return url.toString();
    }

    private static boolean matchesFilter(SecretScanResult result, ResultFilter filter) {
        if (result == null) {
            return false;
        }
        return switch (filter) {
            case ALL -> true;
            case HIGH -> result.hasActionableFindingsAtOrAbove(Severity.HIGH);
            case BLOCKED -> result.isBlocked();
            case WITH_FINDINGS -> result.hasFindings();
        };
    }
}
