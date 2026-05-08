package io.jenkins.plugins.secretguard.action;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.FreeStyleProject;
import io.jenkins.plugins.secretguard.config.SecretGuardGlobalConfiguration;
import io.jenkins.plugins.secretguard.model.EnforcementMode;
import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.service.GlobalJobScanRequest;
import io.jenkins.plugins.secretguard.service.GlobalJobScanService;
import io.jenkins.plugins.secretguard.service.GlobalJobScanStatus;
import io.jenkins.plugins.secretguard.service.ScanResultStore;
import java.io.StringReader;
import java.lang.reflect.Field;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import javax.xml.transform.stream.StreamSource;
import jenkins.model.Jenkins;
import org.htmlunit.HttpMethod;
import org.htmlunit.Page;
import org.htmlunit.WebRequest;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

class SecretGuardRootActionTest {
    @Test
    void formatsSubSecondScanDurationWithMilliseconds() {
        assertEquals("450ms", SecretGuardRootAction.formatDuration(Duration.ofMillis(450)));
        assertEquals("1s", SecretGuardRootAction.formatDuration(Duration.ofMillis(1000)));
        assertEquals("1m 5s", SecretGuardRootAction.formatDuration(Duration.ofSeconds(65)));
    }

    @Test
    void buildsJobSecretGuardPathForNestedJob() {
        assertEquals(
                "job/folder/job/sub%20job/secret-guard", SecretGuardRootAction.toJobSecretGuardPath("folder/sub job"));
    }

    @Test
    void returnsNullWhenTargetIdIsBlank() {
        assertNull(SecretGuardRootAction.toJobSecretGuardPath(" "));
        assertNull(SecretGuardRootAction.toJobSecretGuardPath(null));
    }

    @Test
    void compactsLongTargetIdToUsefulTailSegments() {
        assertEquals(
                "\u2026/service-group/sub-folder/release-build",
                SecretGuardRootAction.compactTargetId(
                        "root-folder/platform-team/application-suite/service-group/sub-folder/release-build"));
    }

    @Test
    void highlightsBlockedAndActionableHighRows() {
        SecretGuardRootAction action = new SecretGuardRootAction(null);
        SecretScanResult blockedResult =
                new SecretScanResult("blocked-job", "WorkflowJob", List.of(finding(Severity.HIGH)), true);
        SecretScanResult highResult =
                new SecretScanResult("high-job", "WorkflowJob", List.of(finding(Severity.HIGH)), false);
        SecretScanResult lowResult =
                new SecretScanResult("low-job", "WorkflowJob", List.of(finding(Severity.LOW)), false);

        assertEquals("secret-guard-row--blocked", action.getResultRowClass(blockedResult));
        assertEquals("secret-guard-row--high", action.getResultRowClass(highResult));
        assertEquals("", action.getResultRowClass(lowResult));
    }

    @Test
    void filtersResultsByQuickFilter() {
        SecretScanResult blockedResult =
                new SecretScanResult("blocked-job", "WorkflowJob", List.of(finding(Severity.HIGH)), true);
        SecretScanResult highResult =
                new SecretScanResult("high-job", "WorkflowJob", List.of(finding(Severity.HIGH)), false);
        SecretScanResult lowResult =
                new SecretScanResult("low-job", "WorkflowJob", List.of(finding(Severity.LOW)), false);
        SecretScanResult emptyResult = new SecretScanResult("empty-job", "WorkflowJob", List.of(), false);
        SecretScanResult notesResult =
                new SecretScanResult("notes-job", "WorkflowJob", List.of(), false, List.of("manual follow-up"));
        SecretScanResult exemptedResult = new SecretScanResult(
                "exempted-job",
                "WorkflowJob",
                List.of(finding(Severity.HIGH).withExemption("approved test exemption")),
                false);
        List<SecretScanResult> results =
                List.of(blockedResult, highResult, lowResult, emptyResult, notesResult, exemptedResult);

        assertEquals(
                List.of(blockedResult, highResult, exemptedResult),
                SecretGuardRootAction.filterResults(results, SecretGuardRootAction.ResultFilter.HIGH));
        assertEquals(
                List.of(blockedResult),
                SecretGuardRootAction.filterResults(results, SecretGuardRootAction.ResultFilter.BLOCKED));
        assertEquals(
                List.of(blockedResult, highResult, lowResult, exemptedResult),
                SecretGuardRootAction.filterResults(results, SecretGuardRootAction.ResultFilter.WITH_FINDINGS));
        assertEquals(
                List.of(exemptedResult),
                SecretGuardRootAction.filterResults(results, SecretGuardRootAction.ResultFilter.WITH_EXEMPTIONS));
        assertEquals(
                List.of(notesResult),
                SecretGuardRootAction.filterResults(results, SecretGuardRootAction.ResultFilter.WITH_NOTES));
    }

    @Test
    void searchesResultsByJobFullNameCaseInsensitively() {
        SecretScanResult releaseResult =
                new SecretScanResult("team/release-build", "WorkflowJob", List.of(finding(Severity.LOW)), false);
        SecretScanResult deployResult =
                new SecretScanResult("team/deploy-build", "WorkflowJob", List.of(finding(Severity.LOW)), false);

        assertEquals(
                List.of(releaseResult),
                SecretGuardRootAction.searchResults(List.of(releaseResult, deployResult), "RELEASE"));
    }

    @Test
    void searchResultsReturnOriginalListForBlankQueryAndIgnoreNullTargets() {
        SecretScanResult releaseResult =
                new SecretScanResult("team/release-build", "WorkflowJob", List.of(finding(Severity.LOW)), false);
        SecretScanResult nullTargetResult =
                new SecretScanResult(null, "WorkflowJob", List.of(finding(Severity.LOW)), false);
        List<SecretScanResult> results = List.of(releaseResult, nullTargetResult);

        assertSame(results, SecretGuardRootAction.searchResults(results, "   "));
        assertEquals(List.of(), SecretGuardRootAction.searchResults(null, "release"));
        assertEquals(List.of(), SecretGuardRootAction.searchResults(null, "   "));
        assertEquals(List.of(releaseResult), SecretGuardRootAction.searchResults(results, " release "));
    }

    @Test
    void sortsResultsByRiskThenFindingCountThenScanTime() {
        SecretScanResult allowedLowResult = new SecretScanResult(
                "allowed-low-job",
                "WorkflowJob",
                List.of(finding(Severity.LOW), finding(Severity.LOW)),
                false,
                Instant.parse("2026-01-01T00:00:00Z"));
        SecretScanResult blockedResult = new SecretScanResult(
                "blocked-job",
                "WorkflowJob",
                List.of(finding(Severity.LOW)),
                true,
                Instant.parse("2026-01-02T00:00:00Z"));
        SecretScanResult highResult = new SecretScanResult(
                "high-job",
                "WorkflowJob",
                List.of(finding(Severity.HIGH)),
                false,
                Instant.parse("2026-01-03T00:00:00Z"));
        SecretScanResult emptyResult = new SecretScanResult(
                "empty-job", "WorkflowJob", List.of(), false, Instant.parse("2026-01-04T00:00:00Z"));

        assertEquals(
                List.of(blockedResult, highResult, allowedLowResult, emptyResult),
                SecretGuardRootAction.sortResults(List.of(emptyResult, allowedLowResult, highResult, blockedResult)));
    }

    @Test
    void defaultsUnknownFilterToAll() {
        assertEquals(
                SecretGuardRootAction.ResultFilter.ALL, SecretGuardRootAction.ResultFilter.fromParameter("unexpected"));
    }

    @Test
    void buildsAbsoluteFilterUrlWithoutRequestContext() {
        SecretGuardRootAction action = new SecretGuardRootAction(null);

        assertEquals("/secret-guard", action.getFilterUrl("all"));
        assertEquals("/secret-guard?filter=high", action.getFilterUrl("high"));
        assertEquals("/secret-guard?filter=with-exemptions", action.getFilterUrl("with-exemptions"));
        assertEquals("/secret-guard?filter=with-notes", action.getFilterUrl("with-notes"));
        assertEquals("/secret-guard?pageSize=200", action.getPageSizeUrl(200));
    }

    @Test
    void paginatesResultsAndClampsOutOfRangePageNumbers() {
        SecretGuardRootAction.PagedResults pagedResults =
                SecretGuardRootAction.paginateResults(sampleResults(120), 9, 50);

        assertEquals(120, pagedResults.getTotalCount());
        assertEquals(3, pagedResults.getPage());
        assertEquals(50, pagedResults.getPageSize());
        assertEquals(101, pagedResults.getStartIndex());
        assertEquals(120, pagedResults.getEndIndex());
        assertEquals(20, pagedResults.getItems().size());
        assertEquals(3, pagedResults.getTotalPages());
    }

    @Test
    void fallsBackToDefaultPageSizeWhenRequestUsesUnsupportedValue() {
        SecretGuardRootAction.PagedResults pagedResults =
                SecretGuardRootAction.paginateResults(sampleResults(120), 1, 25);

        assertEquals(100, pagedResults.getPageSize());
        assertEquals(100, pagedResults.getItems().size());
        assertEquals(2, pagedResults.getTotalPages());
    }

    @Test
    void paginatesEmptyResultsAndReportsNoPageNavigation() {
        SecretGuardRootAction.PagedResults pagedResults = SecretGuardRootAction.paginateResults(null, 3, 50);

        assertTrue(pagedResults.getItems().isEmpty());
        assertEquals(0, pagedResults.getTotalCount());
        assertEquals(1, pagedResults.getPage());
        assertEquals(50, pagedResults.getPageSize());
        assertEquals(0, pagedResults.getStartIndex());
        assertEquals(0, pagedResults.getEndIndex());
        assertEquals(0, pagedResults.getTotalPages());
        assertFalse(pagedResults.hasPreviousPage());
        assertFalse(pagedResults.hasNextPage());
    }

    @Test
    void pagedResultsReportNavigationStateForMiddleAndLastPages() {
        SecretGuardRootAction.PagedResults middlePage =
                SecretGuardRootAction.paginateResults(sampleResults(250), 2, 50);
        SecretGuardRootAction.PagedResults lastPage = SecretGuardRootAction.paginateResults(sampleResults(250), 5, 50);

        assertTrue(middlePage.hasPreviousPage());
        assertTrue(middlePage.hasNextPage());
        assertTrue(lastPage.hasPreviousPage());
        assertFalse(lastPage.hasNextPage());
    }

    @Test
    void visiblePageNumbersCollapseForStartMiddleAndEndRanges() throws Exception {
        assertIterableEquals(List.of(1, 2, 3, 4, 5, 10), buildVisiblePageNumbers(1, 10));
        assertIterableEquals(List.of(1, 5, 6, 7, 10), buildVisiblePageNumbers(6, 10));
        assertIterableEquals(List.of(1, 6, 7, 8, 9, 10), buildVisiblePageNumbers(10, 10));
        assertIterableEquals(List.of(1, 2, 3, 4, 5, 6, 7), buildVisiblePageNumbers(4, 7));
    }

    @Test
    void paginationLinksIncludeCurrentPageGapMarkersAndUrls() throws Exception {
        SecretGuardRootAction action = new SecretGuardRootAction(null);
        SecretGuardRootAction.PagedResults pagedResults =
                SecretGuardRootAction.paginateResults(sampleResults(500), 6, 50);

        @SuppressWarnings("unchecked")
        List<SecretGuardRootAction.PaginationLink> links =
                (List<SecretGuardRootAction.PaginationLink>) invokePrivateInstanceMethod(
                        action,
                        "buildPaginationLinks",
                        new Class<?>[] {SecretGuardRootAction.PagedResults.class},
                        pagedResults);

        assertEquals(7, links.size());
        assertEquals("1", links.get(0).getLabel());
        assertEquals("/secret-guard?pageSize=50", links.get(0).getUrl());
        assertTrue(links.get(1).isGap());
        assertNull(links.get(1).getUrl());
        assertEquals("6", links.get(3).getLabel());
        assertTrue(links.get(3).isCurrent());
        assertEquals("/secret-guard?page=6&pageSize=50", links.get(3).getUrl());
        assertTrue(links.get(5).isGap());
        assertEquals("10", links.get(6).getLabel());
        assertEquals(10, links.get(6).getPageNumber());
        assertFalse(links.get(6).isCurrent());
        assertFalse(links.get(6).isGap());
    }

    @Test
    void parsingHelpersNormalizeSearchQueryAndPageSize() throws Exception {
        assertEquals(
                1, invokePrivateStaticIntMethod("parsePositiveInt", new Class<?>[] {String.class, int.class}, null, 1));
        assertEquals(
                1, invokePrivateStaticIntMethod("parsePositiveInt", new Class<?>[] {String.class, int.class}, "", 1));
        assertEquals(
                1, invokePrivateStaticIntMethod("parsePositiveInt", new Class<?>[] {String.class, int.class}, "-3", 1));
        assertEquals(
                1,
                invokePrivateStaticIntMethod("parsePositiveInt", new Class<?>[] {String.class, int.class}, "abc", 1));
        assertEquals(
                7,
                invokePrivateStaticIntMethod("parsePositiveInt", new Class<?>[] {String.class, int.class}, " 7 ", 1));
        assertEquals(100, invokePrivateStaticIntMethod("normalizePageSize", new Class<?>[] {int.class}, 25));
        assertEquals(200, invokePrivateStaticIntMethod("normalizePageSize", new Class<?>[] {int.class}, 200));
        assertEquals(
                "",
                invokePrivateStaticStringMethod(
                        "normalizeSearchQuery", new Class<?>[] {String.class}, new Object[] {null}));
        assertEquals(
                "release",
                invokePrivateStaticStringMethod(
                        "normalizeSearchQuery", new Class<?>[] {String.class}, new Object[] {" release "}));
    }

    @Test
    @WithJenkins
    void globalPageRequiresManagePermission(JenkinsRule jenkinsRule) throws Exception {
        jenkinsRule.jenkins.setSecurityRealm(jenkinsRule.createDummySecurityRealm());
        jenkinsRule.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.ADMINISTER)
                .everywhere()
                .to("admin")
                .grant(Jenkins.READ)
                .everywhere()
                .to("alice")
                .grant(Jenkins.READ, Jenkins.MANAGE)
                .everywhere()
                .to("bob"));

        JenkinsRule.WebClient deniedClient = jenkinsRule.createWebClient().withThrowExceptionOnFailingStatusCode(false);
        deniedClient.login("alice");
        Page deniedPage = deniedClient.goTo("secret-guard");
        assertEquals(403, deniedPage.getWebResponse().getStatusCode());

        JenkinsRule.WebClient allowedClient =
                jenkinsRule.createWebClient().withThrowExceptionOnFailingStatusCode(false);
        allowedClient.login("bob");
        Page allowedPage = allowedClient.goTo("secret-guard");
        assertEquals(200, allowedPage.getWebResponse().getStatusCode());
        assertTrue(allowedPage.getWebResponse().getContentAsString().contains("Jenkins Secret Guard"));
        assertTrue(allowedPage
                .getWebResponse()
                .getContentAsString()
                .contains("/plugin/secret-guard/scripts/secret-guard-root-action.js"));
    }

    @Test
    @WithJenkins
    void manageUserCanScanAllJobsFromRootPage(JenkinsRule jenkinsRule) throws Exception {
        SecretGuardGlobalConfiguration configuration = SecretGuardGlobalConfiguration.get();
        configuration.setEnabled(false);

        FreeStyleProject project = jenkinsRule.createFreeStyleProject("scan-all-target");
        project.updateByXml(new StreamSource(
                new StringReader(withRiskyParameter(project.getConfigFile().asString()))));
        assertTrue(ScanResultStore.get().get(project.getFullName()).isEmpty());

        configuration.setEnabled(true);
        configuration.setEnforcementMode(EnforcementMode.BLOCK);
        configuration.setBlockThreshold(Severity.HIGH);

        jenkinsRule.jenkins.setSecurityRealm(jenkinsRule.createDummySecurityRealm());
        jenkinsRule.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.ADMINISTER)
                .everywhere()
                .to("admin")
                .grant(Jenkins.READ, Jenkins.MANAGE)
                .everywhere()
                .to("bob"));

        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient().withThrowExceptionOnFailingStatusCode(false);
        webClient.login("bob");

        Page page = webClient.goTo("secret-guard");
        assertTrue(page.getWebResponse().getContentAsString().contains("Scan All Jobs"));

        WebRequest request = new WebRequest(webClient.createCrumbedUrl("secret-guard/scanAll"), HttpMethod.POST);
        Page postResult = webClient.getPage(request);

        assertEquals(200, postResult.getWebResponse().getStatusCode());
        SecretGuardRootAction rootAction = jenkinsRule
                .jenkins
                .getExtensionList(SecretGuardRootAction.class)
                .get(0);
        waitForGlobalScanToFinish(rootAction);

        Page completedPage = webClient.goTo("secret-guard");

        assertTrue(completedPage.getWebResponse().getContentAsString().contains("COMPLETED"));
        assertTrue(completedPage
                .getWebResponse()
                .getContentAsString()
                .contains(
                        "Scanned 1 of 1 jobs, jobs with findings: 1, jobs with high severity findings: 1, failed: 0."));
        assertTrue(completedPage.getWebResponse().getContentAsString().contains("Hide Status"));
        assertFalse(rootAction.canCancelScanAll());
        assertTrue(rootAction.canDismissScanAllStatus());
        assertTrue(ScanResultStore.get().get(project.getFullName()).isPresent());
        assertTrue(
                ScanResultStore.get().get(project.getFullName()).orElseThrow().hasFindings());
        assertTrue(
                ScanResultStore.get().get(project.getFullName()).orElseThrow().isBlocked());

        WebRequest dismissRequest =
                new WebRequest(webClient.createCrumbedUrl("secret-guard/dismissScanAllStatus"), HttpMethod.POST);
        Page dismissedPage = webClient.getPage(dismissRequest);

        assertEquals(200, dismissedPage.getWebResponse().getStatusCode());
        assertFalse(dismissedPage.getWebResponse().getContentAsString().contains("Hide Status"));
        assertFalse(rootAction.canDismissScanAllStatus());
    }

    @Test
    @WithJenkins
    void rootPageKeepsAutoRefreshMarkerWhenScanStateChangesDuringRender(JenkinsRule jenkinsRule) throws Exception {
        SecretGuardRootAction rootAction = jenkinsRule
                .jenkins
                .getExtensionList(SecretGuardRootAction.class)
                .get(0);
        setGlobalJobScanService(rootAction, new RenderRaceGlobalJobScanService());

        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient();
        Page page = webClient.goTo("secret-guard");
        String content = page.getWebResponse().getContentAsString();

        assertTrue(content.contains("cancelScanAll"));
        assertTrue(content.contains("id=\"secret-guard-scan-all-details\""));
        assertTrue(content.contains("id=\"secret-guard-auto-refresh\""));
        assertTrue(content.contains("Current job: <code>example-job</code>"));
        assertTrue(content.contains("This page refreshes automatically while the scan runs."));
        assertFalse(content.contains("dismissScanAllStatus"));
    }

    @Test
    @WithJenkins
    void rootPageUsesSingleHiddenDetailsPanelWithoutDroppingStatusFields(JenkinsRule jenkinsRule) throws Exception {
        SecretGuardRootAction rootAction = jenkinsRule
                .jenkins
                .getExtensionList(SecretGuardRootAction.class)
                .get(0);
        setGlobalJobScanService(rootAction, new HiddenDetailsGlobalJobScanService());

        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient();
        Page page = webClient.goTo("secret-guard");
        String content = page.getWebResponse().getContentAsString();

        assertEquals(1, countOccurrences(content, "id=\"secret-guard-scan-all-details\""));
        assertTrue(
                content.contains("class=\"jenkins-hidden secret-guard-details-body secret-guard-scan-details-panel\""));
        assertTrue(content.contains("Current job: <code>example-job</code>"));
        assertFalse(content.contains("id=\"secret-guard-auto-refresh\""));
    }

    @Test
    @WithJenkins
    void rootPageFormatsScanAllDetailTimestampsWithoutRawInstantText(JenkinsRule jenkinsRule) throws Exception {
        Instant startedAt = Instant.parse("2026-04-19T02:24:50.103104950Z");
        Instant finishedAt = Instant.parse("2026-04-19T02:24:52.632356931Z");
        SecretGuardRootAction rootAction = jenkinsRule
                .jenkins
                .getExtensionList(SecretGuardRootAction.class)
                .get(0);
        setGlobalJobScanService(rootAction, new CompletedGlobalJobScanService(startedAt, finishedAt));

        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient();
        Page page = webClient.goTo("secret-guard");
        String content = page.getWebResponse().getContentAsString();

        assertTrue(content.contains("Started: " + rootAction.getDisplayTimeTitle(startedAt)));
        assertTrue(content.contains("Finished: " + rootAction.getDisplayTimeTitle(finishedAt)));
        assertFalse(content.contains(startedAt.toString()));
        assertFalse(content.contains(finishedAt.toString()));
    }

    @Test
    @WithJenkins
    void filteredRootPageUsesAbsoluteScanActionTargets(JenkinsRule jenkinsRule) throws Exception {
        jenkinsRule.createFreeStyleProject("freestyle-job");
        jenkinsRule.createProject(WorkflowJob.class, "workflow-job");

        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient();
        Page page = webClient.goTo("secret-guard?filter=high");
        String content = page.getWebResponse().getContentAsString();

        assertTrue(content.contains("id=\"secret-guard-open-scan-all-dialog\""));
        assertTrue(content.contains("id=\"secret-guard-scan-all-dialog\""));
        assertTrue(content.contains("action=\"/jenkins/secret-guard/scanAll\""));
        assertTrue(content.contains("<option value=\"\">All</option>"));
        assertTrue(content.contains("name=\"jobTypeFilter\""));
        assertTrue(content.contains("value=\"" + WorkflowJob.class.getName() + "\""));
        assertTrue(content.contains("Pipeline (WorkflowJob)"));
        assertTrue(content.contains("name=\"folderFilter\""));
        assertTrue(content.contains("name=\"nameFilter\""));
        assertTrue(content.contains("Start Scan"));
    }

    @Test
    @WithJenkins
    void rootPageSubmitsScanFiltersToGlobalScanService(JenkinsRule jenkinsRule) throws Exception {
        jenkinsRule.createProject(WorkflowJob.class, "workflow-job");

        SecretGuardRootAction rootAction = jenkinsRule
                .jenkins
                .getExtensionList(SecretGuardRootAction.class)
                .get(0);
        CapturingGlobalJobScanService capturingService = new CapturingGlobalJobScanService();
        setGlobalJobScanService(rootAction, capturingService);

        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient();
        WebRequest request = new WebRequest(
                webClient.createCrumbedUrl("secret-guard/scanAll?jobTypeFilter=" + WorkflowJob.class.getName()
                        + "&folderFilter=team/platform&nameFilter=release"),
                HttpMethod.POST);
        Page postResult = webClient.getPage(request);

        assertEquals(200, postResult.getWebResponse().getStatusCode());
        assertEquals(WorkflowJob.class.getName(), capturingService.lastRequest.getJobTypeFilter());
        assertEquals("Pipeline (WorkflowJob)", capturingService.lastRequest.getJobTypeLabel());
        assertEquals("team/platform", capturingService.lastRequest.getFolderFilter());
        assertEquals("release", capturingService.lastRequest.getNameFilter());
    }

    @Test
    @WithJenkins
    void rootPageFallsBackToSimpleClassNameForUnknownJobTypeFilter(JenkinsRule jenkinsRule) throws Exception {
        SecretGuardRootAction rootAction = jenkinsRule
                .jenkins
                .getExtensionList(SecretGuardRootAction.class)
                .get(0);
        CapturingGlobalJobScanService capturingService = new CapturingGlobalJobScanService();
        setGlobalJobScanService(rootAction, capturingService);

        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient();
        String unknownJobType = "example.custom.CustomWorkflowJob";
        WebRequest request = new WebRequest(
                webClient.createCrumbedUrl("secret-guard/scanAll?jobTypeFilter=" + unknownJobType), HttpMethod.POST);
        Page postResult = webClient.getPage(request);

        assertEquals(200, postResult.getWebResponse().getStatusCode());
        assertEquals(unknownJobType, capturingService.lastRequest.getJobTypeFilter());
        assertEquals("CustomWorkflowJob", capturingService.lastRequest.getJobTypeLabel());
        assertEquals("", capturingService.lastRequest.getFolderFilter());
        assertEquals("", capturingService.lastRequest.getNameFilter());
    }

    @Test
    @WithJenkins
    void availableJobTypeOptionsAreUniqueAndSortedByLabel(JenkinsRule jenkinsRule) throws Exception {
        jenkinsRule.createProject(WorkflowJob.class, "workflow-a");
        jenkinsRule.createProject(WorkflowJob.class, "workflow-b");
        jenkinsRule.createFreeStyleProject("freestyle-job");

        SecretGuardRootAction rootAction = jenkinsRule
                .jenkins
                .getExtensionList(SecretGuardRootAction.class)
                .get(0);
        List<SecretGuardRootAction.JobTypeOption> options = rootAction.getAvailableJobTypeOptions();

        assertEquals(2, options.size());
        assertEquals(FreeStyleProject.class.getName(), options.get(0).getValue());
        assertTrue(options.get(0).getLabel().endsWith("(FreeStyleProject)"));
        assertEquals(WorkflowJob.class.getName(), options.get(1).getValue());
        assertEquals("Pipeline (WorkflowJob)", options.get(1).getLabel());
    }

    @Test
    void scanAllScopeTextFallsBackToAllJobsAndUsesStatusDescription() {
        SecretGuardRootAction blankAction = new SecretGuardRootAction(new NullStatusGlobalJobScanService());
        SecretGuardRootAction filteredAction =
                new SecretGuardRootAction(new FixedStatusGlobalJobScanService("Folder: team/platform"));

        assertEquals("All jobs", blankAction.getScanAllScopeText());
        assertEquals("Folder: team/platform", filteredAction.getScanAllScopeText());
    }

    @Test
    @WithJenkins
    void rootPageShowsNotePresenceWithoutRenderingFullNoteText(JenkinsRule jenkinsRule) throws Exception {
        String targetId = "job-with-note";
        String note =
                "Secret Guard could not read the SCM-backed Jenkinsfile because lightweight access was unavailable.";
        ScanResultStore.get()
                .put(new SecretScanResult(targetId, "WorkflowJob", List.of(), false, List.of(note), Instant.now()));

        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient();
        Page page = webClient.goTo("secret-guard");
        String content = page.getWebResponse().getContentAsString();

        assertTrue(content.contains(">Yes<"));
        assertTrue(content.contains("secret-guard-pill--warning"));
        assertFalse(content.contains(note));

        ScanResultStore.get().remove(targetId);
    }

    @Test
    @WithJenkins
    void rootPageShowsExemptedFindingCountWithoutRenderingReason(JenkinsRule jenkinsRule) throws Exception {
        String targetId = "job-with-exemption";
        String exemptionReason = "approved test exemption should stay on the detailed job report";
        ScanResultStore.get()
                .put(new SecretScanResult(
                        targetId,
                        "WorkflowJob",
                        List.of(finding(Severity.HIGH).withExemption(exemptionReason)),
                        false,
                        List.of(),
                        Instant.now()));

        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient();
        Page page = webClient.goTo("secret-guard?filter=with-exemptions");
        String content = page.getWebResponse().getContentAsString();

        assertTrue(content.contains("With Exemptions (1)"));
        assertTrue(content.contains(">1 exempted<"));
        assertTrue(content.contains("secret-guard-pill--warning"));
        assertTrue(content.contains("id=\"secret-guard-results-section\""));
        assertTrue(content.contains("secret-guard-filter-link"));
        assertTrue(content.contains(targetId));
        assertFalse(content.contains(exemptionReason));

        ScanResultStore.get().remove(targetId);
    }

    @Test
    @WithJenkins
    void rootPageRendersServerSidePaginationControlsAndCurrentPageOnly(JenkinsRule jenkinsRule) throws Exception {
        List<String> targetIds = populateStoredResultsWithNotes(120);

        try {
            JenkinsRule.WebClient webClient = jenkinsRule.createWebClient();
            Page page = webClient.goTo("secret-guard?filter=with-notes&page=2&pageSize=50");
            String content = page.getWebResponse().getContentAsString();

            assertTrue(content.contains("Showing 51-100 of 120"));
            assertEquals(50, countOccurrences(content, ">View report<"));
            assertFalse(content.contains("Page size:"));
            assertTrue(content.contains("href=\"/jenkins/secret-guard?filter=with-notes&amp;page=3&amp;pageSize=50\""));
            assertTrue(content.contains("href=\"/jenkins/secret-guard?pageSize=50\""));
            assertFalse(content.contains("jenkins-table sortable"));
        } finally {
            removeStoredResults(targetIds);
        }
    }

    @Test
    @WithJenkins
    void rootPageSearchesByJobFullNameAndPreservesSearchInResultLinks(JenkinsRule jenkinsRule) throws Exception {
        List<String> targetIds = populateStoredResultsWithNotes(
                List.of("team/release-build", "team/release-candidate", "team/deploy-build"));

        try {
            JenkinsRule.WebClient webClient = jenkinsRule.createWebClient();
            Page page = webClient.goTo("secret-guard?filter=with-notes&q=release&pageSize=50");
            String content = page.getWebResponse().getContentAsString();

            assertTrue(content.contains("Showing 1-2 of 2"));
            assertTrue(content.contains("value=\"release\""));
            assertTrue(content.contains("team/release-build"));
            assertTrue(content.contains("team/release-candidate"));
            assertFalse(content.contains("team/deploy-build"));
            assertFalse(content.contains("Page size:"));
            assertTrue(
                    content.contains("href=\"/jenkins/secret-guard?filter=with-notes&amp;pageSize=50&amp;q=release\""));
        } finally {
            removeStoredResults(targetIds);
        }
    }

    @Test
    @WithJenkins
    void rootPageShowsSearchSpecificEmptyStateAndZeroPagingSummary(JenkinsRule jenkinsRule) throws Exception {
        List<String> targetIds = populateStoredResultsWithNotes(List.of("team/deploy-build"));

        try {
            JenkinsRule.WebClient webClient = jenkinsRule.createWebClient();
            Page page = webClient.goTo("secret-guard?filter=with-notes&q=release");
            String content = page.getWebResponse().getContentAsString();

            assertTrue(content.contains("No Secret Guard scan results match the selected filter and search."));
            assertTrue(content.contains("value=\"release\""));
            assertTrue(content.contains("href=\"/jenkins/secret-guard?filter=with-notes\""));
        } finally {
            removeStoredResults(targetIds);
        }
    }

    private String withRiskyParameter(String xml) {
        String property = """
                <properties>
                  <hudson.model.ParametersDefinitionProperty>
                    <parameterDefinitions>
                      <hudson.model.StringParameterDefinition>
                        <name>API_TOKEN</name>
                        <defaultValue>ghp_012345678901234567890123456789012345</defaultValue>
                        <trim>false</trim>
                      </hudson.model.StringParameterDefinition>
                    </parameterDefinitions>
                  </hudson.model.ParametersDefinitionProperty>
                </properties>
                """;
        if (xml.contains("<properties/>")) {
            return xml.replace("<properties/>", property);
        }
        return xml.replace("<properties></properties>", property);
    }

    private static SecretFinding finding(Severity severity) {
        return new SecretFinding(
                "synthetic-rule",
                "Synthetic finding",
                severity,
                FindingLocationType.CONFIG_XML,
                "example-job",
                "config.xml",
                1,
                "field",
                "****",
                "Review the value.");
    }

    private static List<SecretScanResult> sampleResults(int count) {
        List<SecretScanResult> results = new ArrayList<>();
        Instant baseTime = Instant.parse("2026-01-01T00:00:00Z");
        for (int index = 1; index <= count; index++) {
            results.add(new SecretScanResult(
                    String.format("job-%03d", index),
                    "WorkflowJob",
                    List.of(finding(Severity.LOW)),
                    false,
                    baseTime.plusSeconds(index)));
        }
        return results;
    }

    private static List<String> populateStoredResults(int count) {
        List<String> targetIds = new ArrayList<>();
        for (SecretScanResult result : sampleResults(count)) {
            ScanResultStore.get().put(result);
            targetIds.add(result.getTargetId());
        }
        return targetIds;
    }

    private static List<String> populateStoredResultsWithNotes(int count) {
        List<String> targetIds = new ArrayList<>();
        Instant baseTime = Instant.parse("2026-01-01T00:00:00Z");
        for (int index = 1; index <= count; index++) {
            SecretScanResult result = new SecretScanResult(
                    String.format("notes-job-%03d", index),
                    "WorkflowJob",
                    List.of(finding(Severity.LOW)),
                    false,
                    List.of("sanitized follow-up note"),
                    baseTime.plusSeconds(index));
            ScanResultStore.get().put(result);
            targetIds.add(result.getTargetId());
        }
        return targetIds;
    }

    private static List<String> populateStoredResultsWithNotes(List<String> targetIds) {
        List<String> storedTargetIds = new ArrayList<>();
        Instant baseTime = Instant.parse("2026-01-01T00:00:00Z");
        for (int index = 0; index < targetIds.size(); index++) {
            SecretScanResult result = new SecretScanResult(
                    targetIds.get(index),
                    "WorkflowJob",
                    List.of(finding(Severity.LOW)),
                    false,
                    List.of("sanitized follow-up note"),
                    baseTime.plusSeconds(index + 1L));
            ScanResultStore.get().put(result);
            storedTargetIds.add(result.getTargetId());
        }
        return storedTargetIds;
    }

    private static void removeStoredResults(List<String> targetIds) {
        for (String targetId : targetIds) {
            ScanResultStore.get().remove(targetId);
        }
    }

    private void waitForGlobalScanToFinish(SecretGuardRootAction rootAction) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 10000;
        while (rootAction.getScanAllStatus().isRunning() && System.currentTimeMillis() < deadline) {
            Thread.sleep(100);
        }
        assertFalse(rootAction.getScanAllStatus().isRunning());
    }

    private static void setGlobalJobScanService(SecretGuardRootAction rootAction, GlobalJobScanService service)
            throws Exception {
        Field field = SecretGuardRootAction.class.getDeclaredField("globalJobScanService");
        field.setAccessible(true);
        field.set(rootAction, service);
    }

    private static int countOccurrences(String content, String needle) {
        int count = 0;
        int index = 0;
        while ((index = content.indexOf(needle, index)) != -1) {
            count++;
            index += needle.length();
        }
        return count;
    }

    @SuppressWarnings("unchecked")
    private static List<Integer> buildVisiblePageNumbers(int currentPage, int totalPages) throws Exception {
        return (List<Integer>) invokePrivateStaticMethod(
                "buildVisiblePageNumbers", new Class<?>[] {int.class, int.class}, currentPage, totalPages);
    }

    private static Object invokePrivateInstanceMethod(
            Object target, String methodName, Class<?>[] parameterTypes, Object... args) throws Exception {
        var method = SecretGuardRootAction.class.getDeclaredMethod(methodName, parameterTypes);
        method.setAccessible(true);
        return method.invoke(target, args);
    }

    private static Object invokePrivateStaticMethod(String methodName, Class<?>[] parameterTypes, Object... args)
            throws Exception {
        return invokePrivateInstanceMethod(null, methodName, parameterTypes, args);
    }

    private static int invokePrivateStaticIntMethod(String methodName, Class<?>[] parameterTypes, Object... args)
            throws Exception {
        return (Integer) invokePrivateStaticMethod(methodName, parameterTypes, args);
    }

    private static String invokePrivateStaticStringMethod(String methodName, Class<?>[] parameterTypes, Object[] args)
            throws Exception {
        return (String) invokePrivateStaticMethod(methodName, parameterTypes, args);
    }

    private static final class RenderRaceGlobalJobScanService extends GlobalJobScanService {
        private final AtomicInteger statusCalls = new AtomicInteger();

        @Override
        public boolean canStartScanAllJobs() {
            return false;
        }

        @Override
        public GlobalJobScanStatus getStatus() {
            if (statusCalls.incrementAndGet() <= 2) {
                return runningStatus();
            }
            return completedStatus();
        }

        private GlobalJobScanStatus runningStatus() {
            return new GlobalJobScanStatus(
                    GlobalJobScanStatus.State.RUNNING,
                    3,
                    1,
                    0,
                    0,
                    0,
                    "example-job",
                    "Scanning example-job",
                    Instant.now(),
                    null,
                    List.of());
        }

        private GlobalJobScanStatus completedStatus() {
            return new GlobalJobScanStatus(
                    GlobalJobScanStatus.State.COMPLETED,
                    3,
                    3,
                    0,
                    0,
                    0,
                    null,
                    "Global scan completed.",
                    Instant.now(),
                    Instant.now(),
                    List.of());
        }
    }

    private static final class CompletedGlobalJobScanService extends GlobalJobScanService {
        private final Instant startedAt;
        private final Instant finishedAt;

        private CompletedGlobalJobScanService(Instant startedAt, Instant finishedAt) {
            this.startedAt = startedAt;
            this.finishedAt = finishedAt;
        }

        @Override
        public GlobalJobScanStatus getStatus() {
            return new GlobalJobScanStatus(
                    GlobalJobScanStatus.State.COMPLETED,
                    2,
                    2,
                    0,
                    0,
                    0,
                    null,
                    "Global scan completed.",
                    startedAt,
                    finishedAt,
                    List.of());
        }
    }

    private static final class HiddenDetailsGlobalJobScanService extends GlobalJobScanService {
        @Override
        public GlobalJobScanStatus getStatus() {
            return new GlobalJobScanStatus(
                    GlobalJobScanStatus.State.COMPLETED,
                    4,
                    4,
                    1,
                    1,
                    1,
                    "example-job",
                    "Global scan completed.",
                    Instant.parse("2026-04-19T02:24:50Z"),
                    Instant.parse("2026-04-19T02:25:00Z"),
                    List.of("folder/example-job"));
        }
    }

    private static final class CapturingGlobalJobScanService extends GlobalJobScanService {
        private GlobalJobScanRequest lastRequest;

        @Override
        public void startScanAllJobs(GlobalJobScanRequest request) {
            this.lastRequest = request;
        }
    }

    private static final class NullStatusGlobalJobScanService extends GlobalJobScanService {
        @Override
        public GlobalJobScanStatus getStatus() {
            return null;
        }
    }

    private static final class FixedStatusGlobalJobScanService extends GlobalJobScanService {
        private final String scanScopeDescription;

        private FixedStatusGlobalJobScanService(String scanScopeDescription) {
            this.scanScopeDescription = scanScopeDescription;
        }

        @Override
        public GlobalJobScanStatus getStatus() {
            return new GlobalJobScanStatus(
                    GlobalJobScanStatus.State.COMPLETED,
                    2,
                    2,
                    0,
                    0,
                    0,
                    null,
                    "Global scan completed.",
                    scanScopeDescription,
                    Instant.now(),
                    Instant.now(),
                    List.of());
        }
    }
}
