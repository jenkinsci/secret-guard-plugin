package io.jenkins.plugins.secretguard.action;

import hudson.model.Action;
import hudson.model.Failure;
import hudson.model.Item;
import hudson.model.Job;
import hudson.model.JobProperty;
import io.jenkins.plugins.secretguard.config.SecretGuardGlobalConfiguration;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.service.ManualJobScanService;
import io.jenkins.plugins.secretguard.service.ScanResultStore;
import io.jenkins.plugins.secretguard.util.OptionalPluginClassResolver;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.interceptor.RequirePOST;

public class SecretGuardJobAction implements Action, SeverityBadgeSupport {
    private static final Logger LOGGER = Logger.getLogger(SecretGuardJobAction.class.getName());
    private static final String LOG_PREFIX = "[Secret Guard][Manual Scan] ";
    private static final String BRANCH_JOB_PROPERTY_CLASS =
            "org.jenkinsci.plugins.workflow.multibranch.BranchJobProperty";
    private static final int MAX_DISPLAY_LOCATION_LENGTH = 96;
    private static final int DISPLAY_LOCATION_TAIL_SEGMENTS = 3;
    private static final String ELLIPSIS = "\u2026";
    private static final List<Severity> DISPLAY_SEVERITY_ORDER = List.of(Severity.HIGH, Severity.MEDIUM, Severity.LOW);

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
        return result().orElse(
                        SecretScanResult.empty(job.getFullName(), job.getClass().getSimpleName()));
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

    public List<SeverityGroup> getSeverityGroups() {
        return groupFindingsBySeverity(getFindings());
    }

    public boolean hasRecordedResult() {
        return result().isPresent();
    }

    public boolean isPluginEnabled() {
        SecretGuardGlobalConfiguration configuration = SecretGuardGlobalConfiguration.get();
        return configuration == null || configuration.isEnabled();
    }

    public boolean canScanNow() {
        return job != null && isPluginEnabled() && hasManualScanPermission();
    }

    public boolean isManualScanCompleted() {
        StaplerRequest2 request = Stapler.getCurrentRequest2();
        return request != null && "success".equals(request.getParameter("manualScan"));
    }

    public String getDisplayLocation(SecretFinding finding) {
        if (finding == null) {
            return "";
        }
        return compactLocation(finding.getSourceName());
    }

    @RequirePOST
    public HttpResponse doScanNow() throws Exception {
        LOGGER.log(Level.FINE, LOG_PREFIX + "Manual Secret Guard scan requested for {0}", job.getFullName());
        checkManualScanPermission();
        try {
            SecretScanResult result = manualJobScanService.scanJob(job);
            LOGGER.log(
                    Level.FINE,
                    LOG_PREFIX + "Manual Secret Guard scan completed for {0}: findings={1}, highestSeverity={2}",
                    new Object[] {job.getFullName(), result.getFindings().size(), result.getHighestSeverity()});
        } catch (Exception e) {
            LOGGER.log(Level.FINE, LOG_PREFIX + "Manual Secret Guard scan failed for " + job.getFullName(), e);
            throw new Failure("Secret Guard manual scan failed: " + e.getMessage());
        }
        return HttpResponses.redirectViaContextPath(
                SecretGuardRootAction.toJobSecretGuardPath(job.getFullName()) + "?manualScan=success");
    }

    private Optional<SecretScanResult> result() {
        return ScanResultStore.get().get(job.getFullName());
    }

    static List<SeverityGroup> groupFindingsBySeverity(List<SecretFinding> findings) {
        List<SeverityGroup> groups = new ArrayList<>();
        List<SecretFinding> safeFindings = findings == null ? List.of() : findings;
        for (Severity severity : DISPLAY_SEVERITY_ORDER) {
            List<SecretFinding> matches = safeFindings.stream()
                    .filter(finding -> finding != null && finding.getSeverity() == severity)
                    .toList();
            if (!matches.isEmpty()) {
                groups.add(new SeverityGroup(severity, matches));
            }
        }
        return groups;
    }

    private static String compactLocation(String location) {
        if (location == null || location.length() <= MAX_DISPLAY_LOCATION_LENGTH) {
            return location == null ? "" : location;
        }
        String pathTail = compactPathTail(location);
        if (!pathTail.equals(location)) {
            return middleEllipsize(pathTail);
        }
        return middleEllipsize(location);
    }

    private static String compactPathTail(String location) {
        String[] segments = location.split("/");
        List<String> visibleSegments = new java.util.ArrayList<>();
        for (String segment : segments) {
            if (!segment.isBlank()) {
                visibleSegments.add(segment);
            }
        }
        if (visibleSegments.size() <= DISPLAY_LOCATION_TAIL_SEGMENTS) {
            return location;
        }
        int start = visibleSegments.size() - DISPLAY_LOCATION_TAIL_SEGMENTS;
        return ELLIPSIS + "/" + String.join("/", visibleSegments.subList(start, visibleSegments.size()));
    }

    private static String middleEllipsize(String value) {
        if (value.length() <= MAX_DISPLAY_LOCATION_LENGTH) {
            return value;
        }
        int remainingLength = MAX_DISPLAY_LOCATION_LENGTH - ELLIPSIS.length();
        int prefixLength = remainingLength / 2;
        int suffixLength = remainingLength - prefixLength;
        return value.substring(0, prefixLength) + ELLIPSIS + value.substring(value.length() - suffixLength);
    }

    private boolean hasManualScanPermission() {
        if (job.hasPermission(Item.CONFIGURE)) {
            return true;
        }
        return multibranchOwner()
                .map(owner -> owner.hasPermission(Item.CONFIGURE))
                .orElse(false);
    }

    private void checkManualScanPermission() {
        if (job.hasPermission(Item.CONFIGURE)) {
            return;
        }
        Optional<Item> owner = multibranchOwner();
        if (owner.isPresent()) {
            owner.get().checkPermission(Item.CONFIGURE);
            return;
        }
        job.checkPermission(Item.CONFIGURE);
    }

    private Optional<Item> multibranchOwner() {
        if (!isMultibranchBranchJob()) {
            return Optional.empty();
        }
        return job.getParent() instanceof Item item ? Optional.of(item) : Optional.empty();
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private boolean isMultibranchBranchJob() {
        Optional<Class<?>> propertyClass = OptionalPluginClassResolver.resolve(BRANCH_JOB_PROPERTY_CLASS, getClass());
        if (propertyClass.isEmpty() || !JobProperty.class.isAssignableFrom(propertyClass.get())) {
            return false;
        }
        return job.getProperty((Class) propertyClass.get()) != null;
    }

    public static final class SeverityGroup {
        private final Severity severity;
        private final List<SecretFinding> findings;

        SeverityGroup(Severity severity, List<SecretFinding> findings) {
            this.severity = severity;
            this.findings = List.copyOf(findings);
        }

        public Severity getSeverity() {
            return severity;
        }

        public List<SecretFinding> getFindings() {
            return findings;
        }

        public int getCount() {
            return findings.size();
        }
    }
}
