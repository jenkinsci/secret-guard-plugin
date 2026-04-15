package io.jenkins.plugins.secretguard.service;

import io.jenkins.plugins.secretguard.config.SecretGuardGlobalConfiguration;
import io.jenkins.plugins.secretguard.model.SecretFinding;

public class ExemptionService {
    public SecretFinding applyExemption(SecretFinding finding) {
        String reason = getExemptionReason(finding);
        return reason.isBlank() ? finding : finding.withExemption(reason);
    }

    public String getExemptionReason(SecretFinding finding) {
        SecretGuardGlobalConfiguration configuration = SecretGuardGlobalConfiguration.get();
        if (configuration == null) {
            return "";
        }
        for (String exemption : configuration.getExemptionEntries()) {
            String[] parts = exemption.split("\\|", 3);
            if (parts.length == 3
                    && parts[0].trim().equalsIgnoreCase(finding.getJobFullName())
                    && parts[1].trim().equalsIgnoreCase(finding.getRuleId())
                    && !parts[2].trim().isEmpty()) {
                return parts[2].trim();
            }
        }
        return "";
    }
}
