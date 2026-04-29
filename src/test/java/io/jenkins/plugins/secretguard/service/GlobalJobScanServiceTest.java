package io.jenkins.plugins.secretguard.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.FreeStyleProject;
import hudson.model.Job;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

class GlobalJobScanServiceTest {
    @Test
    @WithJenkins
    void scansOnlyJobsMatchingTypeAndNameFilters(JenkinsRule jenkinsRule) throws Exception {
        FreeStyleProject freestyle = jenkinsRule.createFreeStyleProject("release-freestyle");
        WorkflowJob workflowRelease = jenkinsRule.createProject(WorkflowJob.class, "release-workflow");
        WorkflowJob workflowNightly = jenkinsRule.createProject(WorkflowJob.class, "nightly-workflow");
        RecordingManualJobScanService manualJobScanService = new RecordingManualJobScanService();
        List<Job<?, ?>> jobs = List.of(freestyle, workflowRelease, workflowNightly);
        GlobalJobScanService service =
                new GlobalJobScanService(manualJobScanService, Runnable::run, () -> jobs, 25, () -> {});

        service.startScanAllJobs(new GlobalJobScanRequest(WorkflowJob.class.getName(), "Pipeline", "", "release"));

        assertIterableEquals(List.of("release-workflow"), manualJobScanService.scannedJobFullNames);
        assertEquals(GlobalJobScanStatus.State.COMPLETED, service.getStatus().getState());
        assertEquals(1, service.getStatus().getJobsScanned());
        assertEquals(
                "Job type: Pipeline | Job name contains: release",
                service.getStatus().getScanScopeDescription());
    }

    @Test
    @WithJenkins
    void yieldsBetweenBatchesOfJobs(JenkinsRule jenkinsRule) throws Exception {
        List<Job<?, ?>> jobs = new ArrayList<>();
        for (int index = 0; index < 5; index++) {
            jobs.add(jenkinsRule.createFreeStyleProject("yield-job-" + index));
        }
        RecordingManualJobScanService manualJobScanService = new RecordingManualJobScanService();
        AtomicInteger yieldCalls = new AtomicInteger();
        GlobalJobScanService service = new GlobalJobScanService(
                manualJobScanService, Runnable::run, () -> jobs, 2, yieldCalls::incrementAndGet);

        service.startScanAllJobs(GlobalJobScanRequest.all());

        assertEquals(2, yieldCalls.get());
        assertEquals(5, service.getStatus().getJobsScanned());
        assertTrue(service.getStatus().getMessage().contains("Global scan completed"));
    }

    @Test
    @WithJenkins
    void reportsWhenNoJobsMatchSelectedFilters(JenkinsRule jenkinsRule) throws Exception {
        FreeStyleProject freestyle = jenkinsRule.createFreeStyleProject("release-freestyle");
        RecordingManualJobScanService manualJobScanService = new RecordingManualJobScanService();
        List<Job<?, ?>> jobs = List.of(freestyle);
        GlobalJobScanService service =
                new GlobalJobScanService(manualJobScanService, Runnable::run, () -> jobs, 25, () -> {});

        service.startScanAllJobs(new GlobalJobScanRequest(WorkflowJob.class.getName(), "Pipeline", "", "release"));

        assertTrue(manualJobScanService.scannedJobFullNames.isEmpty());
        assertEquals(GlobalJobScanStatus.State.COMPLETED, service.getStatus().getState());
        assertEquals(0, service.getStatus().getTotalJobs());
        assertEquals(0, service.getStatus().getJobsScanned());
        assertEquals("Global scan completed.", service.getStatus().getMessage());
        assertEquals(
                "Job type: Pipeline | Job name contains: release",
                service.getStatus().getScanScopeDescription());
    }

    @Test
    @WithJenkins
    void noArgScanAllUsesAllJobsScope(JenkinsRule jenkinsRule) {
        RecordingManualJobScanService manualJobScanService = new RecordingManualJobScanService();
        GlobalJobScanService service =
                new GlobalJobScanService(manualJobScanService, Runnable::run, List::<Job<?, ?>>of, 25, () -> {});

        service.startScanAllJobs();

        assertTrue(manualJobScanService.scannedJobFullNames.isEmpty());
        assertEquals(GlobalJobScanStatus.State.COMPLETED, service.getStatus().getState());
        assertEquals(0, service.getStatus().getTotalJobs());
        assertEquals("Global scan completed.", service.getStatus().getMessage());
        assertEquals("All jobs", service.getStatus().getScanScopeDescription());
    }

    @Test
    @WithJenkins
    void nullRequestFallsBackToAllJobs(JenkinsRule jenkinsRule) throws Exception {
        FreeStyleProject freestyle = jenkinsRule.createFreeStyleProject("release-freestyle");
        RecordingManualJobScanService manualJobScanService = new RecordingManualJobScanService();
        List<Job<?, ?>> jobs = List.of(freestyle);
        GlobalJobScanService service =
                new GlobalJobScanService(manualJobScanService, Runnable::run, () -> jobs, 25, () -> {});

        service.startScanAllJobs((GlobalJobScanRequest) null);

        assertIterableEquals(List.of("release-freestyle"), manualJobScanService.scannedJobFullNames);
        assertFalse(service.getStatus().hasFailedJobs());
        assertEquals("All jobs", service.getStatus().getScanScopeDescription());
    }

    private static final class RecordingManualJobScanService extends ManualJobScanService {
        private final List<String> scannedJobFullNames = new ArrayList<>();

        @Override
        public SecretScanResult scanJob(Job<?, ?> job) throws IOException {
            scannedJobFullNames.add(job.getFullName());
            return new SecretScanResult(job.getFullName(), job.getClass().getSimpleName(), List.of(), false);
        }
    }
}
