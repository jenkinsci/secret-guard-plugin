package io.jenkins.plugins.secretguard.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

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
}
