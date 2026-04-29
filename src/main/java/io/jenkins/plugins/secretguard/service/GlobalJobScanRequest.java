package io.jenkins.plugins.secretguard.service;

import hudson.model.Job;

public class GlobalJobScanRequest {
    private final String jobTypeFilter;
    private final String jobTypeLabel;
    private final String folderFilter;
    private final String nameFilter;

    public static GlobalJobScanRequest all() {
        return new GlobalJobScanRequest("", "", "", "");
    }

    public GlobalJobScanRequest(String jobTypeFilter, String folderFilter, String nameFilter) {
        this(jobTypeFilter, "", folderFilter, nameFilter);
    }

    public GlobalJobScanRequest(String jobTypeFilter, String jobTypeLabel, String folderFilter, String nameFilter) {
        this.jobTypeFilter = normalizeText(jobTypeFilter);
        this.jobTypeLabel = normalizeText(jobTypeLabel);
        this.folderFilter = normalizeFolderFilter(folderFilter);
        this.nameFilter = normalizeText(nameFilter);
    }

    public boolean matches(Job<?, ?> job) {
        if (job == null) {
            return false;
        }
        return matches(job.getClass().getName(), job.getFullName(), job.getName());
    }

    boolean matches(String jobTypeClassName, String jobFullName, String jobName) {
        String normalizedJobType = normalizeText(jobTypeClassName);
        String normalizedFullName = normalizePath(jobFullName);
        String normalizedJobName = normalizeText(jobName);
        if (!jobTypeFilter.isBlank() && !jobTypeFilter.equals(normalizedJobType)) {
            return false;
        }
        if (!folderFilter.isBlank()
                && !(normalizedFullName.equals(folderFilter) || normalizedFullName.startsWith(folderFilter + "/"))) {
            return false;
        }
        return nameFilter.isBlank()
                || normalizedJobName
                        .toLowerCase(java.util.Locale.ENGLISH)
                        .contains(nameFilter.toLowerCase(java.util.Locale.ENGLISH));
    }

    public boolean hasFilters() {
        return !jobTypeFilter.isBlank() || !folderFilter.isBlank() || !nameFilter.isBlank();
    }

    public String describeScope() {
        if (!hasFilters()) {
            return "All jobs";
        }
        java.util.List<String> parts = new java.util.ArrayList<>();
        if (!jobTypeFilter.isBlank()) {
            parts.add("Job type: " + (jobTypeLabel.isBlank() ? jobTypeFilter : jobTypeLabel));
        }
        if (!folderFilter.isBlank()) {
            parts.add("Folder: " + folderFilter);
        }
        if (!nameFilter.isBlank()) {
            parts.add("Job name contains: " + nameFilter);
        }
        return String.join(" | ", parts);
    }

    public String getJobTypeFilter() {
        return jobTypeFilter;
    }

    public String getJobTypeLabel() {
        return jobTypeLabel;
    }

    public String getFolderFilter() {
        return folderFilter;
    }

    public String getNameFilter() {
        return nameFilter;
    }

    private static String normalizeFolderFilter(String value) {
        return normalizePath(value);
    }

    private static String normalizePath(String value) {
        String normalized = normalizeText(value);
        while (normalized.startsWith("/")) {
            normalized = normalized.substring(1);
        }
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private static String normalizeText(String value) {
        return value == null ? "" : value.trim().replaceAll("\\s+", " ");
    }
}
