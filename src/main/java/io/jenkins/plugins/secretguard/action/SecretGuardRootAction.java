package io.jenkins.plugins.secretguard.action;

import hudson.Extension;
import hudson.Util;
import hudson.model.Job;
import hudson.model.RootAction;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.service.GlobalJobScanRequest;
import io.jenkins.plugins.secretguard.service.GlobalJobScanService;
import io.jenkins.plugins.secretguard.service.GlobalJobScanStatus;
import io.jenkins.plugins.secretguard.service.ScanResultStore;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
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
    private static final int DEFAULT_PAGE_SIZE = 100;
    private static final List<Integer> PAGE_SIZE_OPTIONS = List.of(50, 100, 200);
    private static final String REQUEST_CACHE_KEY_PREFIX = SecretGuardRootAction.class.getName() + ".";
    private static final String ELLIPSIS = "\u2026";

    private final GlobalJobScanService globalJobScanService;

    enum ResultFilter {
        ALL("all", "All"),
        HIGH("high", "High"),
        BLOCKED("blocked", "Blocked"),
        WITH_FINDINGS("with-findings", "With Findings"),
        WITH_EXEMPTIONS("with-exemptions", "With Exemptions"),
        WITH_NOTES("with-notes", "With Notes");

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

    public String getScanAllScopeText() {
        GlobalJobScanStatus status = getScanAllStatus();
        return status == null || status.getScanScopeDescription().isBlank()
                ? "All jobs"
                : status.getScanScopeDescription();
    }

    public List<JobTypeOption> getAvailableJobTypeOptions() {
        Map<String, JobTypeOption> optionsByClassName = new LinkedHashMap<>();
        for (Job<?, ?> job : Jenkins.get().allItems(Job.class)) {
            optionsByClassName.putIfAbsent(
                    job.getClass().getName(), new JobTypeOption(job.getClass().getName(), describeJobType(job)));
        }
        return optionsByClassName.values().stream()
                .sorted(Comparator.comparing(JobTypeOption::getLabel, String.CASE_INSENSITIVE_ORDER))
                .toList();
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

    public String getScanAllStateBadgeClass(GlobalJobScanStatus.State state) {
        if (state == GlobalJobScanStatus.State.COMPLETED) {
            return "secret-guard-badge secret-guard-badge--state-completed";
        }
        if (state == GlobalJobScanStatus.State.RUNNING) {
            return "secret-guard-badge secret-guard-badge--state-running";
        }
        if (state == GlobalJobScanStatus.State.CANCELLED) {
            return "secret-guard-badge secret-guard-badge--state-cancelled";
        }
        if (state == GlobalJobScanStatus.State.FAILED) {
            return "secret-guard-badge secret-guard-badge--state-failed";
        }
        return "secret-guard-badge secret-guard-badge--state-idle";
    }

    public List<SecretScanResult> getResults() {
        return getRequestCachedValue(
                "results", () -> sortResults(ScanResultStore.get().getAll()));
    }

    public List<SecretScanResult> getFilteredResults() {
        return getRequestCachedValue(
                "filteredResults", () -> filterResults(getSearchedResults(), getActiveResultFilter()));
    }

    public PagedResults getPagedResults() {
        return getRequestCachedValue(
                "pagedResults",
                () -> paginateResults(getFilteredResults(), getRequestedPage(), getRequestedPageSize()));
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

    public long getExemptedFindingsCount(SecretScanResult result) {
        return result == null ? 0 : result.getExemptedFindingsCount();
    }

    public boolean hasResults() {
        return !getResults().isEmpty();
    }

    public boolean hasFilteredResults() {
        return !getPagedResults().getItems().isEmpty();
    }

    public String getEmptyResultsMessage() {
        return hasResults()
                ? (hasActiveSearchQuery()
                        ? "No Secret Guard scan results match the selected filter and search."
                        : "No Secret Guard scan results match the selected filter.")
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
        return getPagedResults().getTotalCount();
    }

    public String getSearchQuery() {
        StaplerRequest2 currentRequest = Stapler.getCurrentRequest2();
        return currentRequest == null ? "" : normalizeSearchQuery(currentRequest.getParameter("q"));
    }

    public boolean hasActiveSearchQuery() {
        return !getSearchQuery().isBlank();
    }

    public String getClearSearchUrl() {
        return buildResultsUrl(getActiveResultFilter(), 1, getRequestedPageSize(), "");
    }

    public String getSearchFormAction() {
        return getRootActionUrl();
    }

    public String getActiveFilterParameterValue() {
        return getActiveResultFilter().getParameterValue();
    }

    public String getResultWindowSummary() {
        PagedResults pagedResults = getPagedResults();
        if (pagedResults.getTotalCount() == 0) {
            return "Showing 0 of 0";
        }
        return "Showing " + pagedResults.getStartIndex() + "-" + pagedResults.getEndIndex() + " of "
                + pagedResults.getTotalCount();
    }

    public boolean hasMultipleResultPages() {
        return getPagedResults().getTotalPages() > 1;
    }

    public List<Integer> getAvailablePageSizes() {
        return PAGE_SIZE_OPTIONS;
    }

    public boolean isActivePageSize(int pageSize) {
        return getPagedResults().getPageSize() == pageSize;
    }

    public String getPageSizeButtonClass(int pageSize) {
        return isActivePageSize(pageSize)
                ? "jenkins-button jenkins-submit-button jenkins-button--primary"
                : "jenkins-button jenkins-button--secondary";
    }

    public List<PaginationLink> getPaginationLinks() {
        return getRequestCachedValue("paginationLinks", () -> buildPaginationLinks(getPagedResults()));
    }

    public String getPreviousPageUrl() {
        PagedResults pagedResults = getPagedResults();
        return pagedResults.hasPreviousPage()
                ? buildResultsUrl(getActiveResultFilter(), pagedResults.getPage() - 1, pagedResults.getPageSize())
                : null;
    }

    public String getNextPageUrl() {
        PagedResults pagedResults = getPagedResults();
        return pagedResults.hasNextPage()
                ? buildResultsUrl(getActiveResultFilter(), pagedResults.getPage() + 1, pagedResults.getPageSize())
                : null;
    }

    public String getPageSizeUrl(int pageSize) {
        return buildResultsUrl(getActiveResultFilter(), 1, normalizePageSize(pageSize));
    }

    public String getPaginationSummaryText() {
        PagedResults pagedResults = getPagedResults();
        if (pagedResults.getTotalCount() == 0) {
            return "Page 0 of 0";
        }
        return "Page " + pagedResults.getPage() + " of " + pagedResults.getTotalPages();
    }

    public String getHighFindingsCardClass() {
        return getUnexemptedHighCount() > 0
                ? "jenkins-alert jenkins-alert-warning"
                : "jenkins-alert jenkins-alert-info";
    }

    public String getBlockedJobsCardClass() {
        return getBlockedJobCount() > 0 ? "jenkins-alert jenkins-alert-danger" : "jenkins-alert jenkins-alert-info";
    }

    public String getBlockedBadgeClass(boolean blocked) {
        if (blocked) {
            return "secret-guard-badge secret-guard-badge--blocked";
        }
        return "secret-guard-badge secret-guard-badge--allowed";
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

    public String getResultRowClass(SecretScanResult result) {
        if (result == null) {
            return "";
        }
        if (result.isBlocked()) {
            return "secret-guard-row--blocked";
        }
        if (result.hasActionableFindingsAtOrAbove(Severity.HIGH)) {
            return "secret-guard-row--high";
        }
        return "";
    }

    @RequirePOST
    public HttpResponse doScanAll(StaplerRequest2 request) {
        Jenkins.get().checkPermission(Jenkins.MANAGE);
        String jobTypeFilter = request == null ? null : request.getParameter("jobTypeFilter");
        globalJobScanService.startScanAllJobs(new GlobalJobScanRequest(
                jobTypeFilter,
                resolveJobTypeFilterLabel(jobTypeFilter),
                request == null ? null : request.getParameter("folderFilter"),
                request == null ? null : request.getParameter("nameFilter")));
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
        return filterResults(getSearchedResults(), filter).size();
    }

    private String buildResultsUrl(ResultFilter filter) {
        return buildResultsUrl(filter, 1, getRequestedPageSize(), getSearchQuery());
    }

    private String buildResultsUrl(ResultFilter filter, int page, int pageSize) {
        return buildResultsUrl(filter, page, pageSize, getSearchQuery());
    }

    private String buildResultsUrl(ResultFilter filter, int page, int pageSize, String searchQuery) {
        StringBuilder url = new StringBuilder(getRootActionUrl());
        boolean hasQuery = false;
        if (filter != ResultFilter.ALL) {
            hasQuery = appendQueryParameter(url, hasQuery, "filter", filter.getParameterValue());
        }
        if (page > 1) {
            hasQuery = appendQueryParameter(url, hasQuery, "page", Integer.toString(page));
        }
        if (pageSize != DEFAULT_PAGE_SIZE) {
            hasQuery = appendQueryParameter(url, hasQuery, "pageSize", Integer.toString(pageSize));
        }
        if (searchQuery != null && !searchQuery.isBlank()) {
            appendQueryParameter(url, hasQuery, "q", searchQuery);
        }
        return url.toString();
    }

    private static boolean matchesFilter(SecretScanResult result, ResultFilter filter) {
        if (result == null) {
            return false;
        }
        return switch (filter) {
            case ALL -> true;
            case HIGH -> result.getHighestSeverity().isAtLeast(Severity.HIGH);
            case BLOCKED -> result.isBlocked();
            case WITH_FINDINGS -> result.hasFindings();
            case WITH_EXEMPTIONS -> result.hasExemptedFindings();
            case WITH_NOTES -> result.hasNotes();
        };
    }

    private List<SecretScanResult> getSearchedResults() {
        return getRequestCachedValue("searchedResults", () -> searchResults(getResults(), getSearchQuery()));
    }

    static List<SecretScanResult> searchResults(List<SecretScanResult> results, String query) {
        String normalizedQuery = normalizeSearchQuery(query);
        if (normalizedQuery.isBlank()) {
            return results == null ? List.of() : results;
        }
        String normalizedNeedle = normalizedQuery.toLowerCase(java.util.Locale.ROOT);
        List<SecretScanResult> safeResults = results == null ? List.of() : results;
        return safeResults.stream()
                .filter(result -> result != null
                        && result.getTargetId() != null
                        && result.getTargetId()
                                .toLowerCase(java.util.Locale.ROOT)
                                .contains(normalizedNeedle))
                .toList();
    }

    private String resolveJobTypeFilterLabel(String jobTypeFilter) {
        if (jobTypeFilter == null || jobTypeFilter.isBlank()) {
            return "";
        }
        for (JobTypeOption option : getAvailableJobTypeOptions()) {
            if (option.getValue().equals(jobTypeFilter)) {
                return option.getLabel();
            }
        }
        return simplifyClassName(jobTypeFilter);
    }

    private static String describeJobType(Job<?, ?> job) {
        @SuppressWarnings("unchecked")
        Class<? extends hudson.model.Describable> jobTypeClass =
                (Class<? extends hudson.model.Describable>) job.getClass();
        var descriptor = Jenkins.get().getDescriptor(jobTypeClass);
        String displayName = descriptor == null ? "" : descriptor.getDisplayName();
        String simpleName = simplifyClassName(job.getClass().getName());
        if (displayName == null || displayName.isBlank() || displayName.equals(simpleName)) {
            return simpleName;
        }
        return displayName + " (" + simpleName + ")";
    }

    private static String simplifyClassName(String className) {
        if (className == null || className.isBlank()) {
            return "";
        }
        int separator = className.lastIndexOf('.');
        return separator >= 0 ? className.substring(separator + 1) : className;
    }

    private int getRequestedPage() {
        StaplerRequest2 currentRequest = Stapler.getCurrentRequest2();
        return currentRequest == null ? 1 : parsePositiveInt(currentRequest.getParameter("page"), 1);
    }

    private int getRequestedPageSize() {
        StaplerRequest2 currentRequest = Stapler.getCurrentRequest2();
        return currentRequest == null
                ? DEFAULT_PAGE_SIZE
                : normalizePageSize(parsePositiveInt(currentRequest.getParameter("pageSize"), DEFAULT_PAGE_SIZE));
    }

    private static int parsePositiveInt(String value, int defaultValue) {
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        try {
            int parsed = Integer.parseInt(value.trim());
            return parsed > 0 ? parsed : defaultValue;
        } catch (NumberFormatException ignored) {
            return defaultValue;
        }
    }

    private static int normalizePageSize(int pageSize) {
        return PAGE_SIZE_OPTIONS.contains(pageSize) ? pageSize : DEFAULT_PAGE_SIZE;
    }

    private static String normalizeSearchQuery(String query) {
        return query == null ? "" : query.trim();
    }

    static PagedResults paginateResults(List<SecretScanResult> results, int page, int pageSize) {
        int safePageSize = normalizePageSize(pageSize);
        List<SecretScanResult> safeResults = results == null ? List.of() : results;
        int totalCount = safeResults.size();
        if (totalCount == 0) {
            return new PagedResults(List.of(), 0, 1, safePageSize, 0, 0);
        }
        int totalPages = (int) Math.ceil((double) totalCount / safePageSize);
        int safePage = Math.min(Math.max(1, page), totalPages);
        int fromIndex = (safePage - 1) * safePageSize;
        int toIndex = Math.min(totalCount, fromIndex + safePageSize);
        return new PagedResults(
                safeResults.subList(fromIndex, toIndex), totalCount, safePage, safePageSize, fromIndex + 1, toIndex);
    }

    private List<PaginationLink> buildPaginationLinks(PagedResults pagedResults) {
        if (pagedResults.getTotalPages() <= 1) {
            return List.of();
        }
        List<PaginationLink> links = new ArrayList<>();
        List<Integer> pageNumbers = buildVisiblePageNumbers(pagedResults.getPage(), pagedResults.getTotalPages());
        int previousPageNumber = -1;
        for (int pageNumber : pageNumbers) {
            if (previousPageNumber > 0 && pageNumber - previousPageNumber > 1) {
                links.add(PaginationLink.gap());
            }
            links.add(PaginationLink.page(
                    Integer.toString(pageNumber),
                    pageNumber,
                    pageNumber == pagedResults.getPage(),
                    buildResultsUrl(getActiveResultFilter(), pageNumber, pagedResults.getPageSize())));
            previousPageNumber = pageNumber;
        }
        return links;
    }

    private static List<Integer> buildVisiblePageNumbers(int currentPage, int totalPages) {
        if (totalPages <= 7) {
            List<Integer> pages = new ArrayList<>();
            for (int pageNumber = 1; pageNumber <= totalPages; pageNumber++) {
                pages.add(pageNumber);
            }
            return pages;
        }

        List<Integer> pages = new ArrayList<>();
        pages.add(1);

        int start = Math.max(2, currentPage - 1);
        int end = Math.min(totalPages - 1, currentPage + 1);

        if (currentPage <= 4) {
            start = 2;
            end = 5;
        } else if (currentPage >= totalPages - 3) {
            start = totalPages - 4;
            end = totalPages - 1;
        }

        for (int pageNumber = start; pageNumber <= end; pageNumber++) {
            pages.add(pageNumber);
        }

        pages.add(totalPages);
        return pages;
    }

    private static boolean appendQueryParameter(StringBuilder url, boolean hasQuery, String name, String value) {
        url.append(hasQuery ? '&' : '?')
                .append(Util.rawEncode(name))
                .append('=')
                .append(Util.rawEncode(value));
        return true;
    }

    @SuppressWarnings("unchecked")
    private <T> T getRequestCachedValue(String keySuffix, Supplier<T> loader) {
        StaplerRequest2 currentRequest = Stapler.getCurrentRequest2();
        if (currentRequest == null) {
            return loader.get();
        }
        String cacheKey = REQUEST_CACHE_KEY_PREFIX + keySuffix;
        Object cached = currentRequest.getAttribute(cacheKey);
        if (cached != null) {
            return (T) cached;
        }
        T loaded = loader.get();
        currentRequest.setAttribute(cacheKey, loaded);
        return loaded;
    }

    public static final class JobTypeOption {
        private final String value;
        private final String label;

        private JobTypeOption(String value, String label) {
            this.value = value;
            this.label = label;
        }

        public String getValue() {
            return value;
        }

        public String getLabel() {
            return label;
        }
    }

    public static final class PagedResults {
        private final List<SecretScanResult> items;
        private final int totalCount;
        private final int page;
        private final int pageSize;
        private final int startIndex;
        private final int endIndex;

        private PagedResults(
                List<SecretScanResult> items, int totalCount, int page, int pageSize, int startIndex, int endIndex) {
            this.items = List.copyOf(items);
            this.totalCount = totalCount;
            this.page = page;
            this.pageSize = pageSize;
            this.startIndex = startIndex;
            this.endIndex = endIndex;
        }

        public List<SecretScanResult> getItems() {
            return items;
        }

        public int getTotalCount() {
            return totalCount;
        }

        public int getPage() {
            return page;
        }

        public int getPageSize() {
            return pageSize;
        }

        public int getStartIndex() {
            return startIndex;
        }

        public int getEndIndex() {
            return endIndex;
        }

        public int getTotalPages() {
            if (totalCount == 0) {
                return 0;
            }
            return (int) Math.ceil((double) totalCount / pageSize);
        }

        public boolean hasPreviousPage() {
            return page > 1;
        }

        public boolean hasNextPage() {
            return page < getTotalPages();
        }
    }

    public static final class PaginationLink {
        private final String label;
        private final int pageNumber;
        private final boolean current;
        private final boolean gap;
        private final String url;

        private PaginationLink(String label, int pageNumber, boolean current, boolean gap, String url) {
            this.label = label;
            this.pageNumber = pageNumber;
            this.current = current;
            this.gap = gap;
            this.url = url;
        }

        private static PaginationLink gap() {
            return new PaginationLink(ELLIPSIS, -1, false, true, null);
        }

        private static PaginationLink page(String label, int pageNumber, boolean current, String url) {
            return new PaginationLink(label, pageNumber, current, false, url);
        }

        public String getLabel() {
            return label;
        }

        public int getPageNumber() {
            return pageNumber;
        }

        public boolean isCurrent() {
            return current;
        }

        public boolean isGap() {
            return gap;
        }

        public String getUrl() {
            return url;
        }
    }
}
