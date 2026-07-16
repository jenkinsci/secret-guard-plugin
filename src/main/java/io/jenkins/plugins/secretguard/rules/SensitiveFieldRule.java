package io.jenkins.plugins.secretguard.rules;

import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.util.NonSecretHeuristics;
import java.util.Collections;
import java.util.List;

final class SensitiveFieldRule implements SecretRule {
    @Override
    public String getId() {
        return "sensitive-field-name";
    }

    @Override
    public List<SecretFinding> scan(
            ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
        String normalizedValue = SecretRuleSupport.normalizeAssignedLiteralValue(fieldName, value);
        if (!SecretRuleSupport.isSensitiveField(fieldName) || NonSecretHeuristics.isCredentialIdField(fieldName)) {
            return Collections.emptyList();
        }
        if (NonSecretHeuristics.looksLikeCredentialBindingVariableReference(fieldName, normalizedValue)) {
            return Collections.emptyList();
        }
        if (NonSecretHeuristics.looksLikeSensitiveFileReference(fieldName, normalizedValue)) {
            return Collections.emptyList();
        }
        if (NonSecretHeuristics.looksLikeReadableEndpointUrl(normalizedValue)) {
            return Collections.emptyList();
        }
        if (NonSecretHeuristics.looksLikePlaceholderValue(normalizedValue)) {
            return List.of(SecretRuleSupport.finding(
                    getId(),
                    "Sensitive field contains a placeholder-like value",
                    Severity.LOW,
                    context,
                    sourceName,
                    lineNumber,
                    fieldName,
                    normalizedValue,
                    SecretRuleSupport.Recommendations.PLACEHOLDER,
                    "Downgraded because the value looks like a redaction placeholder instead of a real secret."));
        }
        if (SecretRuleSupport.looksLikeSafeReference(normalizedValue)) {
            return Collections.emptyList();
        }
        Severity severity = normalizedValue.trim().length() >= 8 ? Severity.HIGH : Severity.LOW;
        String recommendation = context.getLocationType().name().contains("CONFIG")
                ? SecretRuleSupport.Recommendations.NO_CONFIG_SECRET
                : SecretRuleSupport.Recommendations.CREDENTIALS;
        return List.of(SecretRuleSupport.finding(
                getId(),
                "Sensitive field contains a plaintext value",
                severity,
                context,
                sourceName,
                lineNumber,
                fieldName,
                normalizedValue,
                recommendation));
    }
}
