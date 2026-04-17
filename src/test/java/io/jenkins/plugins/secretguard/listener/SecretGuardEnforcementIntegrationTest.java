package io.jenkins.plugins.secretguard.listener;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Failure;
import hudson.model.FreeStyleProject;
import hudson.model.Item;
import hudson.model.Result;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.scm.NullSCM;
import hudson.scm.SCM;
import hudson.scm.SCMDescriptor;
import hudson.scm.SCMRevisionState;
import io.jenkins.plugins.secretguard.action.SecretGuardRunAction;
import io.jenkins.plugins.secretguard.config.SecretGuardGlobalConfiguration;
import io.jenkins.plugins.secretguard.model.EnforcementMode;
import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.service.ScanResultStore;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.xml.transform.stream.StreamSource;
import jenkins.branch.BranchSource;
import jenkins.model.Jenkins;
import jenkins.scm.api.SCMFile;
import jenkins.scm.api.SCMFileSystem;
import jenkins.scm.api.SCMHead;
import jenkins.scm.api.SCMHeadEvent;
import jenkins.scm.api.SCMHeadObserver;
import jenkins.scm.api.SCMProbeStat;
import jenkins.scm.api.SCMRevision;
import jenkins.scm.api.SCMSource;
import jenkins.scm.api.SCMSourceCriteria;
import jenkins.scm.api.SCMSourceDescriptor;
import org.htmlunit.HttpMethod;
import org.htmlunit.Page;
import org.htmlunit.WebRequest;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.cps.CpsScmFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.jenkinsci.plugins.workflow.multibranch.WorkflowBranchProjectFactory;
import org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.TestExtension;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

class SecretGuardEnforcementIntegrationTest {
    @Test
    @WithJenkins
    void blocksConfigXmlModificationInBlockMode(JenkinsRule jenkinsRule) throws Exception {
        configure(EnforcementMode.BLOCK);
        FreeStyleProject project = jenkinsRule.createFreeStyleProject("guarded");
        String originalXml = project.getConfigFile().asString();
        String riskyXml = withRiskyParameter(originalXml);

        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient().withThrowExceptionOnFailingStatusCode(false);
        WebRequest request =
                new WebRequest(webClient.createCrumbedUrl(project.getUrl() + "config.xml"), HttpMethod.POST);
        request.setAdditionalHeader("Content-Type", "application/xml");
        request.setRequestBody(riskyXml);

        Page page = webClient.getPage(request);

        assertEquals(409, page.getWebResponse().getStatusCode());
        assertTrue(page.getWebResponse().getContentAsString().contains("Secret Guard blocked saving"));
        String restoredXml = jenkinsRule
                .jenkins
                .getItemByFullName(project.getFullName(), FreeStyleProject.class)
                .getConfigFile()
                .asString();
        assertFalse(restoredXml.contains("API_TOKEN"));
        assertFalse(restoredXml.contains("ghp_012345678901234567890123456789012345"));
        assertTrue(restoredXml.contains("<properties/>") || restoredXml.contains("<properties></properties>"));
    }

    @Test
    @WithJenkins
    void auditModeAllowsConfigXmlModificationWithoutBlocking(JenkinsRule jenkinsRule) throws Exception {
        configure(EnforcementMode.AUDIT);
        FreeStyleProject project = jenkinsRule.createFreeStyleProject("audit-allowed");
        String riskyXml = withRiskyParameter(project.getConfigFile().asString());

        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient().withThrowExceptionOnFailingStatusCode(false);
        WebRequest request =
                new WebRequest(webClient.createCrumbedUrl(project.getUrl() + "config.xml"), HttpMethod.POST);
        request.setAdditionalHeader("Content-Type", "application/xml");
        request.setRequestBody(riskyXml);

        Page page = webClient.getPage(request);

        assertTrue(page.getWebResponse().getStatusCode() < 400);
        assertFalse(page.getWebResponse().getContentAsString().contains("Secret Guard blocked saving"));
        String persistedXml = jenkinsRule
                .jenkins
                .getItemByFullName(project.getFullName(), FreeStyleProject.class)
                .getConfigFile()
                .asString();
        assertTrue(persistedXml.contains("API_TOKEN"));
        assertTrue(persistedXml.contains("ghp_012345678901234567890123456789012345"));
    }

    @Test
    @WithJenkins
    void warnModeAllowsConfigXmlModificationWithoutBlocking(JenkinsRule jenkinsRule) throws Exception {
        configure(EnforcementMode.WARN);
        FreeStyleProject project = jenkinsRule.createFreeStyleProject("warn-allowed");
        String riskyXml = withRiskyParameter(project.getConfigFile().asString());

        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient().withThrowExceptionOnFailingStatusCode(false);
        WebRequest request =
                new WebRequest(webClient.createCrumbedUrl(project.getUrl() + "config.xml"), HttpMethod.POST);
        request.setAdditionalHeader("Content-Type", "application/xml");
        request.setRequestBody(riskyXml);

        Page page = webClient.getPage(request);

        assertTrue(page.getWebResponse().getStatusCode() < 400);
        assertFalse(page.getWebResponse().getContentAsString().contains("Secret Guard blocked saving"));
        String persistedXml = jenkinsRule
                .jenkins
                .getItemByFullName(project.getFullName(), FreeStyleProject.class)
                .getConfigFile()
                .asString();
        assertTrue(persistedXml.contains("API_TOKEN"));
        assertTrue(persistedXml.contains("ghp_012345678901234567890123456789012345"));
    }

    @Test
    @WithJenkins
    void blocksCreatingJobFromXmlInBlockMode(JenkinsRule jenkinsRule) throws Exception {
        configure(EnforcementMode.BLOCK);
        FreeStyleProject template = jenkinsRule.createFreeStyleProject("template");
        String riskyXml = withRiskyParameter(template.getConfigFile().asString());

        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient().withThrowExceptionOnFailingStatusCode(false);
        WebRequest request =
                new WebRequest(webClient.createCrumbedUrl("createItem?name=blocked-created-job"), HttpMethod.POST);
        request.setAdditionalHeader("Content-Type", "application/xml");
        request.setRequestBody(riskyXml);

        Page page = webClient.getPage(request);

        assertEquals(409, page.getWebResponse().getStatusCode());
        assertTrue(page.getWebResponse().getContentAsString().contains("Secret Guard blocked creating"));
        assertNull(jenkinsRule.jenkins.getItem("blocked-created-job"));
    }

    @Test
    @WithJenkins
    void blocksCopyingRiskyJobInBlockMode(JenkinsRule jenkinsRule) throws Exception {
        configure(EnforcementMode.AUDIT);
        FreeStyleProject source = jenkinsRule.createFreeStyleProject("copy-source");
        source.updateByXml(new StreamSource(
                new StringReader(withRiskyParameter(source.getConfigFile().asString()))));

        configure(EnforcementMode.BLOCK);

        Failure failure = assertThrows(
                Failure.class,
                () -> jenkinsRule.jenkins.copy((hudson.model.AbstractProject<?, ?>) source, "copy-target"));

        assertTrue(failure.getMessage().contains("Secret Guard blocked copying"));
        assertFalse(jenkinsRule.jenkins.getAllItems(FreeStyleProject.class).stream()
                .anyMatch(project -> project.getName().equals("copy-target")));
    }

    @Test
    @WithJenkins
    void allowsSavingPipelineConfigXmlWithRuntimeHeaderReferenceInBlockMode(JenkinsRule jenkinsRule) throws Exception {
        configure(EnforcementMode.BLOCK);
        WorkflowJob template = jenkinsRule.createProject(WorkflowJob.class, "runtime-save-template");
        template.setDefinition(new CpsFlowDefinition(runtimeHeaderPipelineScript("\"$SERVICE_API_TOKEN\""), true));
        String allowedXml = template.getConfigFile().asString();

        WorkflowJob target = jenkinsRule.createProject(WorkflowJob.class, "runtime-save-target");
        target.setDefinition(
                new CpsFlowDefinition("pipeline { agent any; stages { stage('ok') { steps { echo 'ok' } } } }", true));

        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient().withThrowExceptionOnFailingStatusCode(false);
        WebRequest request =
                new WebRequest(webClient.createCrumbedUrl(target.getUrl() + "config.xml"), HttpMethod.POST);
        request.setAdditionalHeader("Content-Type", "application/xml");
        request.setRequestBody(allowedXml);

        Page page = webClient.getPage(request);

        assertTrue(page.getWebResponse().getStatusCode() < 400);
        assertFalse(page.getWebResponse().getContentAsString().contains("Secret Guard blocked saving"));
        String persistedXml = jenkinsRule
                .jenkins
                .getItemByFullName(target.getFullName(), WorkflowJob.class)
                .getConfigFile()
                .asString();
        assertTrue(persistedXml.contains("x-service-token"));
        assertTrue(persistedXml.contains("$SERVICE_API_TOKEN"));
    }

    @Test
    @WithJenkins
    void allowsCreatingPipelineFromXmlWithRuntimeHeaderReferenceInBlockMode(JenkinsRule jenkinsRule) throws Exception {
        configure(EnforcementMode.BLOCK);
        WorkflowJob template = jenkinsRule.createProject(WorkflowJob.class, "runtime-create-template");
        template.setDefinition(new CpsFlowDefinition(runtimeHeaderPipelineScript("\"${SERVICE_API_TOKEN}\""), true));
        String allowedXml = template.getConfigFile().asString();

        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient().withThrowExceptionOnFailingStatusCode(false);
        WebRequest request =
                new WebRequest(webClient.createCrumbedUrl("createItem?name=runtime-created-job"), HttpMethod.POST);
        request.setAdditionalHeader("Content-Type", "application/xml");
        request.setRequestBody(allowedXml);

        Page page = webClient.getPage(request);

        assertTrue(page.getWebResponse().getStatusCode() < 400);
        assertFalse(page.getWebResponse().getContentAsString().contains("Secret Guard blocked creating"));
        WorkflowJob created = jenkinsRule.jenkins.getItemByFullName("runtime-created-job", WorkflowJob.class);
        assertNotNull(created);
        assertTrue(created.getConfigFile().asString().contains("${SERVICE_API_TOKEN}"));
    }

    @Test
    @WithJenkins
    void persistsRunActionForPipelineBuildWithoutJavaTimeSerializationFailure(JenkinsRule jenkinsRule)
            throws Exception {
        configure(EnforcementMode.AUDIT);
        WorkflowJob job = jenkinsRule.createProject(WorkflowJob.class, "pipeline-run-action");
        job.setDefinition(new CpsFlowDefinition("""
                def webhookUrl = 'https://chat.example.invalid/cgi-bin/webhook/send?key=123e4567-e89b-12d3-a456-426614174999'
                """, true));

        WorkflowRun run = jenkinsRule.buildAndAssertSuccess(job);

        SecretGuardRunAction action = run.getAction(SecretGuardRunAction.class);
        assertNotNull(action);
        assertFalse(action.getFindings().isEmpty());
        assertTrue(action.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("url-query-secret")));

        String buildXml = Files.readString(run.getRootDir().toPath().resolve("build.xml"));
        assertTrue(buildXml.contains("<scannedAtEpochMillis>"));
        assertFalse(buildXml.contains("java.time.Instant"));
    }

    @Test
    @WithJenkins
    void blockModeDoesNotFailBuildForRuntimeHeaderReference(JenkinsRule jenkinsRule) throws Exception {
        configure(EnforcementMode.BLOCK);
        WorkflowJob job = jenkinsRule.createProject(WorkflowJob.class, "runtime-build-safe");
        job.setDefinition(new CpsFlowDefinition(runtimeHeaderPipelineScript("env.SERVICE_API_TOKEN"), true));

        WorkflowRun run = jenkinsRule.buildAndAssertSuccess(job);

        SecretGuardRunAction action = run.getAction(SecretGuardRunAction.class);
        assertNotNull(action);
        assertTrue(action.getFindings().isEmpty());
    }

    @Test
    @WithJenkins
    void blockModeFailsBuildForHighSeverityPipelineFinding(JenkinsRule jenkinsRule) throws Exception {
        configure(EnforcementMode.BLOCK);
        WorkflowJob job = jenkinsRule.createProject(WorkflowJob.class, "block-build-failure");
        job.setDefinition(new CpsFlowDefinition("""
                def webhookUrl = 'https://chat.example.invalid/cgi-bin/webhook/send?key=123e4567-e89b-12d3-a456-426614174999'
                pipeline {
                  agent any
                  stages {
                    stage('should-not-pass') {
                      steps {
                        echo 'running'
                      }
                    }
                  }
                }
                """, true));

        WorkflowRun run = jenkinsRule.buildAndAssertStatus(Result.FAILURE, job);

        SecretGuardRunAction action = run.getAction(SecretGuardRunAction.class);
        assertNotNull(action);
        assertTrue(action.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("url-query-secret")));
        assertEquals(Result.FAILURE, run.getResult());
    }

    @Test
    @WithJenkins
    void manualScanEndpointStoresFreshResultForJobPage(JenkinsRule jenkinsRule) throws Exception {
        SecretGuardGlobalConfiguration configuration = SecretGuardGlobalConfiguration.get();
        configuration.setEnabled(false);
        FreeStyleProject project = jenkinsRule.createFreeStyleProject("manual-scan");
        project.updateByXml(new StreamSource(
                new StringReader(withRiskyParameter(project.getConfigFile().asString()))));
        assertFalse(ScanResultStore.get().get(project.getFullName()).isPresent());

        configure(EnforcementMode.AUDIT);

        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient().withThrowExceptionOnFailingStatusCode(false);
        WebRequest request =
                new WebRequest(webClient.createCrumbedUrl(project.getUrl() + "secret-guard/scanNow"), HttpMethod.POST);

        Page page = webClient.getPage(request);

        assertEquals(200, page.getWebResponse().getStatusCode());
        assertTrue(page.getWebResponse().getContentAsString().contains("Manual scan completed."));
        assertTrue(ScanResultStore.get().get(project.getFullName()).isPresent());
        assertTrue(
                ScanResultStore.get().get(project.getFullName()).orElseThrow().hasFindings());
    }

    @Test
    @WithJenkins
    void manualScanEndpointReadsPipelineFromScmJenkinsfile(JenkinsRule jenkinsRule) throws Exception {
        configure(EnforcementMode.AUDIT);
        WorkflowJob job = jenkinsRule.createProject(WorkflowJob.class, "manual-scm-scan");
        job.setDefinition(new CpsScmFlowDefinition(
                new MemoryScm(
                        Map.of(
                                "ci/Jenkinsfile",
                                "def webhookUrl = 'https://chat.example.invalid/cgi-bin/webhook/send?key=123e4567-e89b-12d3-a456-426614174999'")),
                "ci/Jenkinsfile"));

        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient().withThrowExceptionOnFailingStatusCode(false);
        WebRequest request =
                new WebRequest(webClient.createCrumbedUrl(job.getUrl() + "secret-guard/scanNow"), HttpMethod.POST);

        Page page = webClient.getPage(request);

        assertEquals(200, page.getWebResponse().getStatusCode());
        assertTrue(page.getWebResponse().getContentAsString().contains("Manual scan completed."));
        assertTrue(ScanResultStore.get().get(job.getFullName()).orElseThrow().getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("url-query-secret")
                        && finding.getLocationType() == FindingLocationType.JENKINSFILE
                        && finding.getSourceName().equals("Jenkinsfile from SCM: ci/Jenkinsfile")));
    }

    @Test
    @WithJenkins
    void manualScanReportsUnavailableScmJenkinsfileOnJobAndRootPages(JenkinsRule jenkinsRule) throws Exception {
        configure(EnforcementMode.AUDIT);
        WorkflowJob job = jenkinsRule.createProject(WorkflowJob.class, "manual-scm-unavailable");
        job.setDefinition(new CpsScmFlowDefinition(
                new MemoryScm(Map.of("ci/OtherPipelineScript", "echo 'ok'")), "ci/Jenkinsfile"));

        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient().withThrowExceptionOnFailingStatusCode(false);
        WebRequest request =
                new WebRequest(webClient.createCrumbedUrl(job.getUrl() + "secret-guard/scanNow"), HttpMethod.POST);

        Page jobPage = webClient.getPage(request);
        SecretScanResult storedResult =
                ScanResultStore.get().get(job.getFullName()).orElseThrow();

        assertEquals(200, jobPage.getWebResponse().getStatusCode());
        assertFalse(storedResult.hasFindings());
        assertTrue(storedResult.hasNotes());
        assertTrue(storedResult.getNotes().get(0).contains("could not read SCM Jenkinsfile"));
        assertTrue(storedResult.getNotes().get(0).contains("ci/Jenkinsfile"));
        assertTrue(jobPage.getWebResponse().getContentAsString().contains("Scan notes"));
        assertTrue(jobPage.getWebResponse().getContentAsString().contains("ci/Jenkinsfile"));

        Page rootPage = webClient.goTo("secret-guard");

        assertTrue(rootPage.getWebResponse().getContentAsString().contains("manual-scm-unavailable"));
        assertTrue(rootPage.getWebResponse().getContentAsString().contains(">Yes<"));
        assertFalse(rootPage.getWebResponse().getContentAsString().contains("could not read SCM Jenkinsfile"));
    }

    @Test
    @WithJenkins
    void warnModeScansPipelineFromScmJenkinsfileAtBuildStart(JenkinsRule jenkinsRule) throws Exception {
        configure(EnforcementMode.WARN);
        WorkflowJob job = jenkinsRule.createProject(WorkflowJob.class, "build-scm-scan");
        job.setDefinition(new CpsScmFlowDefinition(
                new MemoryScm(
                        Map.of(
                                "Jenkinsfile",
                                "def webhookUrl = 'https://chat.example.invalid/cgi-bin/webhook/send?key=123e4567-e89b-12d3-a456-426614174999'")),
                "Jenkinsfile"));

        WorkflowRun run = jenkinsRule.buildAndAssertStatus(Result.UNSTABLE, job);

        SecretGuardRunAction action = run.getAction(SecretGuardRunAction.class);
        assertNotNull(action);
        assertTrue(action.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("url-query-secret")
                        && finding.getLocationType() == FindingLocationType.JENKINSFILE
                        && finding.getSourceName().equals("Jenkinsfile from SCM: Jenkinsfile")));
    }

    @Test
    @WithJenkins
    void buildReportShowsScanNotesWhenScmJenkinsfileReadIsUnavailable(JenkinsRule jenkinsRule) throws Exception {
        configure(EnforcementMode.WARN);
        WorkflowJob job = jenkinsRule.createProject(WorkflowJob.class, "build-scan-notes-present");
        job.setDefinition(new CpsScmFlowDefinition(
                new MemoryScm(Map.of("ci/OtherPipelineScript", "echo 'ok'")), "ci/Jenkinsfile"));

        WorkflowRun run = jenkinsRule.buildAndAssertStatus(Result.FAILURE, job);
        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient().withThrowExceptionOnFailingStatusCode(false);

        Page page = webClient.goTo(run.getUrl() + "secret-guard");

        assertTrue(page.getWebResponse().getContentAsString().contains("Scan notes"));
        assertTrue(page.getWebResponse().getContentAsString().contains("could not read SCM Jenkinsfile"));
        assertTrue(page.getWebResponse().getContentAsString().contains("ci/Jenkinsfile"));
    }

    @Test
    @WithJenkins
    void manualScanServiceReadsMultibranchJenkinsfile(JenkinsRule jenkinsRule) throws Exception {
        configure(EnforcementMode.AUDIT);
        WorkflowJob branchJob = createMultibranchJob(jenkinsRule, "manual-multibranch-scan", "ci/Jenkinsfile", """
                def webhookUrl = 'https://chat.example.invalid/cgi-bin/webhook/send?key=123e4567-e89b-12d3-a456-426614174999'
                """);

        assertTrue(new io.jenkins.plugins.secretguard.service.ManualJobScanService()
                .scanJob(branchJob).getFindings().stream()
                        .anyMatch(finding -> finding.getRuleId().equals("url-query-secret")
                                && finding.getLocationType() == FindingLocationType.JENKINSFILE
                                && finding.getSourceName().equals("Jenkinsfile from Multibranch SCM: ci/Jenkinsfile")));
        assertTrue(ScanResultStore.get().get(branchJob.getFullName()).isPresent());
    }

    @Test
    @WithJenkins
    void warnModeScansMultibranchJenkinsfileAtBuildStart(JenkinsRule jenkinsRule) throws Exception {
        configure(EnforcementMode.WARN);
        WorkflowJob branchJob = createMultibranchJob(jenkinsRule, "build-multibranch-scan", "Jenkinsfile", """
                def webhookUrl = 'https://chat.example.invalid/cgi-bin/webhook/send?key=123e4567-e89b-12d3-a456-426614174999'
                """);

        WorkflowRun run = jenkinsRule.buildAndAssertStatus(Result.UNSTABLE, branchJob);

        SecretGuardRunAction action = run.getAction(SecretGuardRunAction.class);
        assertNotNull(action);
        assertTrue(action.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("url-query-secret")
                        && finding.getLocationType() == FindingLocationType.JENKINSFILE
                        && finding.getSourceName().equals("Jenkinsfile from Multibranch SCM: Jenkinsfile")));
    }

    @Test
    @WithJenkins
    void multibranchManualScanRequiresConfigurePermissionForBuildUser(JenkinsRule jenkinsRule) throws Exception {
        configure(EnforcementMode.AUDIT);
        WorkflowJob branchJob = createMultibranchJob(jenkinsRule, "multibranch-scan-button", "ci/Jenkinsfile", """
                def webhookUrl = 'https://chat.example.invalid/cgi-bin/webhook/send?key=123e4567-e89b-12d3-a456-426614174999'
                """);
        JenkinsRule.WebClient webClient = createBuildOnlyWebClient(jenkinsRule, branchJob);

        webClient.goTo(branchJob.getUrl() + "secret-guard");

        WebRequest request = new WebRequest(
                webClient.createCrumbedUrl(branchJob.getUrl() + "secret-guard/scanNow"), HttpMethod.POST);
        Page postResult = webClient.getPage(request);

        assertEquals(403, postResult.getWebResponse().getStatusCode());
    }

    @Test
    @WithJenkins
    void multibranchManualScanRequiresConfigurePermissionForReadOnlyUser(JenkinsRule jenkinsRule) throws Exception {
        configure(EnforcementMode.AUDIT);
        WorkflowJob branchJob =
                createMultibranchJob(jenkinsRule, "multibranch-read-scan-button", "ci/Jenkinsfile", """
                def webhookUrl = 'https://chat.example.invalid/cgi-bin/webhook/send?key=123e4567-e89b-12d3-a456-426614174999'
                """);
        JenkinsRule.WebClient webClient = createReadOnlyWebClient(jenkinsRule, branchJob);

        webClient.goTo(branchJob.getUrl() + "secret-guard");

        WebRequest request = new WebRequest(
                webClient.createCrumbedUrl(branchJob.getUrl() + "secret-guard/scanNow"), HttpMethod.POST);
        Page postResult = webClient.getPage(request);

        assertEquals(403, postResult.getWebResponse().getStatusCode());
    }

    @Test
    @WithJenkins
    void multibranchSecretGuardPageShowsScanButtonForConfigureUser(JenkinsRule jenkinsRule) throws Exception {
        configure(EnforcementMode.AUDIT);
        WorkflowJob branchJob =
                createMultibranchJob(jenkinsRule, "multibranch-configure-scan-button", "ci/Jenkinsfile", """
                def webhookUrl = 'https://chat.example.invalid/cgi-bin/webhook/send?key=123e4567-e89b-12d3-a456-426614174999'
                """);
        JenkinsRule.WebClient webClient = createConfigureWebClient(jenkinsRule, branchJob);

        Page secretGuardPage = webClient.goTo(branchJob.getUrl() + "secret-guard");

        assertTrue(secretGuardPage.getWebResponse().getContentAsString().contains("Scan Now"));
    }

    private WorkflowJob createMultibranchJob(
            JenkinsRule jenkinsRule, String projectName, String scriptPath, String jenkinsfile) throws Exception {
        WorkflowMultiBranchProject project = jenkinsRule.createProject(WorkflowMultiBranchProject.class, projectName);
        ((WorkflowBranchProjectFactory) project.getProjectFactory()).setScriptPath(scriptPath);
        project.getSourcesList()
                .add(new BranchSource(
                        new MemoryScmSource("memory-source", Map.of("main", Map.of(scriptPath, jenkinsfile)))));
        project.scheduleBuild2(0);
        jenkinsRule.waitUntilNoActivity();
        WorkflowJob branchJob = project.getItemByBranchName("main");
        assertNotNull(branchJob);
        return branchJob;
    }

    private JenkinsRule.WebClient createBuildOnlyWebClient(JenkinsRule jenkinsRule, WorkflowJob branchJob)
            throws Exception {
        jenkinsRule.jenkins.setSecurityRealm(jenkinsRule.createDummySecurityRealm());
        jenkinsRule.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.ADMINISTER)
                .everywhere()
                .to("admin")
                .grant(Jenkins.READ)
                .everywhere()
                .to("alice")
                .grant(Item.READ, Item.BUILD)
                .onItems((Item) branchJob.getParent(), branchJob)
                .to("alice"));
        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient().withThrowExceptionOnFailingStatusCode(false);
        webClient.login("alice");
        return webClient;
    }

    private JenkinsRule.WebClient createReadOnlyWebClient(JenkinsRule jenkinsRule, WorkflowJob branchJob)
            throws Exception {
        jenkinsRule.jenkins.setSecurityRealm(jenkinsRule.createDummySecurityRealm());
        jenkinsRule.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.ADMINISTER)
                .everywhere()
                .to("admin")
                .grant(Jenkins.READ)
                .everywhere()
                .to("alice")
                .grant(Item.READ)
                .onItems((Item) branchJob.getParent(), branchJob)
                .to("alice"));
        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient().withThrowExceptionOnFailingStatusCode(false);
        webClient.login("alice");
        return webClient;
    }

    private JenkinsRule.WebClient createConfigureWebClient(JenkinsRule jenkinsRule, WorkflowJob branchJob)
            throws Exception {
        jenkinsRule.jenkins.setSecurityRealm(jenkinsRule.createDummySecurityRealm());
        jenkinsRule.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.ADMINISTER)
                .everywhere()
                .to("admin")
                .grant(Jenkins.READ)
                .everywhere()
                .to("alice")
                .grant(Item.READ, Item.CONFIGURE)
                .onItems((Item) branchJob.getParent(), branchJob)
                .to("alice"));
        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient().withThrowExceptionOnFailingStatusCode(false);
        webClient.login("alice");
        return webClient;
    }

    private void configure(EnforcementMode mode) {
        SecretGuardGlobalConfiguration configuration = SecretGuardGlobalConfiguration.get();
        configuration.setEnabled(true);
        configuration.setEnforcementMode(mode);
        configuration.setBlockThreshold(Severity.HIGH);
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

    private String runtimeHeaderPipelineScript(String headerValueReference) {
        return """
                def invokeRemoteCheck() {
                    def response = httpRequest(
                        httpMode: "POST",
                        contentType: 'APPLICATION_JSON',
                        requestBody: groovy.json.JsonOutput.toJson([status: 'ok']),
                        url: "https://api.example.invalid/v1/request-check",
                        customHeaders: [[name: "x-service-token", value: %s, maskValue: true]]
                    )
                    return response
                }

                pipeline {
                    agent any
                    stages {
                        stage('noop') {
                            steps {
                                echo 'ready'
                            }
                        }
                    }
                }
                """.formatted(headerValueReference);
    }

    public static class MemoryScm extends NullSCM {
        private final Map<String, String> files;

        MemoryScm(Map<String, String> files) {
            this.files = new LinkedHashMap<>(files);
        }

        @Override
        public void checkout(
                Run<?, ?> build,
                Launcher launcher,
                FilePath workspace,
                TaskListener listener,
                File changelogFile,
                SCMRevisionState baseline)
                throws IOException, InterruptedException {
            for (Map.Entry<String, String> entry : files.entrySet()) {
                workspace.child(entry.getKey()).write(entry.getValue(), StandardCharsets.UTF_8.name());
            }
        }
    }

    public static class MemoryScmSource extends SCMSource {
        private final Map<String, Map<String, String>> branches;

        MemoryScmSource(String id, Map<String, Map<String, String>> branches) {
            super(id);
            this.branches = new LinkedHashMap<>();
            for (Map.Entry<String, Map<String, String>> branch : branches.entrySet()) {
                this.branches.put(branch.getKey(), new LinkedHashMap<>(branch.getValue()));
            }
        }

        @Override
        protected void retrieve(
                SCMSourceCriteria criteria, SCMHeadObserver observer, SCMHeadEvent<?> event, TaskListener listener)
                throws IOException, InterruptedException {
            for (Map.Entry<String, Map<String, String>> branch : branches.entrySet()) {
                SCMHead head = new SCMHead(branch.getKey());
                MemoryScmRevision revision = new MemoryScmRevision(head, "revision-" + branch.getKey());
                if (criteria == null || criteria.isHead(new MemoryScmProbe(head, branch.getValue()), listener)) {
                    observer.observe(head, revision);
                }
                if (!observer.isObserving()) {
                    return;
                }
            }
        }

        @Override
        protected SCMRevision retrieve(SCMHead head, TaskListener listener) {
            if (branches.containsKey(head.getName())) {
                return new MemoryScmRevision(head, "revision-" + head.getName());
            }
            return null;
        }

        @Override
        public SCM build(SCMHead head, SCMRevision revision) {
            return new MemoryScm(branches.getOrDefault(head.getName(), Collections.emptyMap()));
        }

        private Map<String, String> filesFor(SCMHead head) {
            return branches.getOrDefault(head.getName(), Collections.emptyMap());
        }

        @TestExtension
        public static class DescriptorImpl extends SCMSourceDescriptor {
            @Override
            public String getDisplayName() {
                return "Memory SCM Source";
            }
        }
    }

    private static class MemoryScmRevision extends SCMRevision {
        private final String hash;

        MemoryScmRevision(SCMHead head, String hash) {
            super(head);
            this.hash = hash;
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof MemoryScmRevision that
                    && getHead().equals(that.getHead())
                    && hash.equals(that.hash);
        }

        @Override
        public int hashCode() {
            return getHead().hashCode() * 31 + hash.hashCode();
        }
    }

    private static class MemoryScmProbe extends SCMSourceCriteria.Probe {
        private final SCMHead head;
        private final Map<String, String> files;

        MemoryScmProbe(SCMHead head, Map<String, String> files) {
            this.head = head;
            this.files = files;
        }

        @Override
        public String name() {
            return head.getName();
        }

        @Override
        public long lastModified() {
            return 0;
        }

        @Override
        public boolean exists(String path) {
            return files.containsKey(path);
        }

        @Override
        public SCMProbeStat stat(String path) {
            if (files.containsKey(path)) {
                return SCMProbeStat.fromType(SCMFile.Type.REGULAR_FILE);
            }
            String prefix = path.endsWith("/") ? path : path + "/";
            if (files.keySet().stream().anyMatch(file -> file.startsWith(prefix))) {
                return SCMProbeStat.fromType(SCMFile.Type.DIRECTORY);
            }
            return SCMProbeStat.fromType(SCMFile.Type.NONEXISTENT);
        }
    }

    @TestExtension
    public static class MemoryScmFileSystemBuilder extends SCMFileSystem.Builder {
        @Override
        public boolean supports(SCM scm) {
            return scm instanceof MemoryScm;
        }

        @Override
        public boolean supports(SCMSource source) {
            return source instanceof MemoryScmSource;
        }

        @Override
        protected boolean supportsDescriptor(SCMDescriptor descriptor) {
            return false;
        }

        @Override
        protected boolean supportsDescriptor(SCMSourceDescriptor descriptor) {
            return false;
        }

        @Override
        public SCMFileSystem build(hudson.model.Item owner, SCM scm, SCMRevision rev) {
            return new MemoryScmFileSystem((MemoryScm) scm);
        }

        @Override
        public SCMFileSystem build(hudson.model.Item owner, SCM scm, SCMRevision rev, Run<?, ?> run) {
            return new MemoryScmFileSystem((MemoryScm) scm);
        }

        @Override
        public SCMFileSystem build(SCMSource source, SCMHead head, SCMRevision rev) {
            return new MemoryScmFileSystem(((MemoryScmSource) source).filesFor(head));
        }
    }

    private static class MemoryScmFileSystem extends SCMFileSystem {
        private final Map<String, String> files;
        private final SCMFile root;

        MemoryScmFileSystem(MemoryScm scm) {
            this(scm.files);
        }

        MemoryScmFileSystem(Map<String, String> files) {
            super(null);
            this.files = files;
            this.root = new MemoryScmFile(this);
        }

        @Override
        public long lastModified() {
            return 0;
        }

        @Override
        public SCMFile getRoot() {
            return root;
        }
    }

    private static class MemoryScmFile extends SCMFile {
        private final MemoryScmFileSystem fileSystem;
        private final String path;

        MemoryScmFile(MemoryScmFileSystem fileSystem) {
            super();
            this.fileSystem = fileSystem;
            this.path = "";
        }

        MemoryScmFile(MemoryScmFile parent, String name) {
            super(parent, name);
            this.fileSystem = parent.fileSystem;
            this.path = parent.path.isBlank() ? name : parent.path + "/" + name;
        }

        @Override
        protected SCMFile newChild(String name, boolean assumeIsDirectory) {
            return new MemoryScmFile(this, name);
        }

        @Override
        public Iterable<SCMFile> children() {
            return Collections.emptyList();
        }

        @Override
        public long lastModified() {
            return 0;
        }

        @Override
        protected Type type() {
            if (path.isBlank()) {
                return Type.DIRECTORY;
            }
            if (fileSystem.files.containsKey(path)) {
                return Type.REGULAR_FILE;
            }
            String prefix = path + "/";
            return fileSystem.files.keySet().stream().anyMatch(file -> file.startsWith(prefix))
                    ? Type.DIRECTORY
                    : Type.NONEXISTENT;
        }

        @Override
        public InputStream content() throws IOException {
            String content = fileSystem.files.get(path);
            if (content == null) {
                throw new IOException("No such file: " + path);
            }
            return new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));
        }
    }
}
