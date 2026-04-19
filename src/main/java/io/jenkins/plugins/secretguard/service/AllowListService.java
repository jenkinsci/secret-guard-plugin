package io.jenkins.plugins.secretguard.service;

import io.jenkins.plugins.secretguard.config.SecretGuardGlobalConfiguration;
import io.jenkins.plugins.secretguard.model.SecretFinding;

public class AllowListService {
    public boolean isAllowListed(SecretFinding finding) {
        SecretGuardGlobalConfiguration configuration = SecretGuardGlobalConfiguration.get();
        if (configuration == null) {
            return false;
        }
        return containsIgnoreCase(configuration.getRuleIdAllowListEntries(), finding.getRuleId())
                || containsIgnoreCase(configuration.getJobAllowListEntries(), finding.getJobFullName())
                || containsIgnoreCase(configuration.getFieldNameAllowListEntries(), finding.getFieldName());
    }

    private boolean containsIgnoreCase(Iterable<String> values, String candidate) {
        if (candidate == null || candidate.isBlank()) {
            return false;
        }
        for (String value : values) {
            if (value.equalsIgnoreCase(candidate)) {
                return true;
            }
        }
        return false;
    }
}
