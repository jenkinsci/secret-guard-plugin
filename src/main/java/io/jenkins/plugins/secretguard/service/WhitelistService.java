package io.jenkins.plugins.secretguard.service;

import io.jenkins.plugins.secretguard.config.SecretGuardGlobalConfiguration;
import io.jenkins.plugins.secretguard.model.SecretFinding;

public class WhitelistService {
    public boolean isWhitelisted(SecretFinding finding) {
        SecretGuardGlobalConfiguration configuration = SecretGuardGlobalConfiguration.get();
        if (configuration == null) {
            return false;
        }
        return containsIgnoreCase(configuration.getRuleIdWhitelistEntries(), finding.getRuleId())
                || containsIgnoreCase(configuration.getJobWhitelistEntries(), finding.getJobFullName())
                || containsIgnoreCase(configuration.getFieldNameWhitelistEntries(), finding.getFieldName());
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
