package io.jenkins.plugins.secretguard.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.FreeStyleProject;
import hudson.model.Job;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

class GlobalJobScanRequestTest {
    private static final String WORKFLOW_JOB = "org.jenkinsci.plugins.workflow.job.WorkflowJob";
    private static final String FREESTYLE_PROJECT = "hudson.model.FreeStyleProject";

    @Test
    void matchesTypeFolderAndNameFilters() {
        GlobalJobScanRequest request = new GlobalJobScanRequest(WORKFLOW_JOB, "Pipeline", "team/platform", "release");

        assertTrue(request.matches(WORKFLOW_JOB, "team/platform/release-build", "release-build"));
        assertFalse(request.matches(FREESTYLE_PROJECT, "team/platform/release-check", "release-check"));
        assertFalse(
                request.matches("jenkins.branch.OrganizationFolder", "team/platform/release-build", "release-build"));
        assertFalse(request.matches(WORKFLOW_JOB, "team/other/release-build", "release-build"));
        assertFalse(request.matches(WORKFLOW_JOB, "team/platform/nightly-build", "nightly-build"));
    }

    @Test
    void describesScopeForFilteredScans() {
        GlobalJobScanRequest request = new GlobalJobScanRequest(WORKFLOW_JOB, "Pipeline", "/team/platform/", "release");

        assertEquals(
                "Job type: Pipeline | Folder: team/platform | Job name contains: release", request.describeScope());
        assertTrue(request.hasFilters());
    }

    @Test
    void defaultsToAllJobsWhenNoFiltersAreProvided() {
        GlobalJobScanRequest request = GlobalJobScanRequest.all();

        assertEquals("All jobs", request.describeScope());
        assertFalse(request.hasFilters());
        assertTrue(request.matches(WORKFLOW_JOB, "folder/release-build", "release-build"));
    }

    @Test
    void describesScopeUsingClassNameWhenJobTypeLabelIsBlank() {
        GlobalJobScanRequest request = new GlobalJobScanRequest(WORKFLOW_JOB, "/team/platform/", "release");

        assertEquals(
                "Job type: " + WORKFLOW_JOB + " | Folder: team/platform | Job name contains: release",
                request.describeScope());
        assertEquals(WORKFLOW_JOB, request.getJobTypeFilter());
        assertEquals("", request.getJobTypeLabel());
        assertEquals("team/platform", request.getFolderFilter());
        assertEquals("release", request.getNameFilter());
    }

    @Test
    @WithJenkins
    void normalizesFiltersAndMatchesRealJobInstances(JenkinsRule jenkinsRule) throws Exception {
        FreeStyleProject project = jenkinsRule.createFreeStyleProject("Release Build");
        GlobalJobScanRequest request = new GlobalJobScanRequest(
                "  " + FreeStyleProject.class.getName() + "  ", "", " /Release Build/ ", "  release   build ");

        assertTrue(request.matches(project));
        assertFalse(request.matches((Job<?, ?>) null));
        assertEquals(FreeStyleProject.class.getName(), request.getJobTypeFilter());
        assertEquals("", request.getJobTypeLabel());
        assertEquals("Release Build", request.getFolderFilter());
        assertEquals("release build", request.getNameFilter());
    }
}
