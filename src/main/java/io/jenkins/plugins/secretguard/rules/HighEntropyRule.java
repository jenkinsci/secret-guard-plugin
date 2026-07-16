package io.jenkins.plugins.secretguard.rules;

import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.util.NonSecretHeuristics;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class HighEntropyRule implements SecretRule {
    private static final Logger LOGGER = Logger.getLogger(HighEntropyRule.class.getName());
    private static final Pattern CANDIDATE = Pattern.compile("\\b[A-Za-z0-9+/=_-]{32,}\\b");
    private static final Pattern PRIVATE_KEY_BLOCK =
            Pattern.compile("-----BEGIN [A-Z ]*PRIVATE KEY-----[\\s\\S]*?-----END [A-Z ]*PRIVATE KEY-----");

    @Override
    public String getId() {
        return "high-entropy-string";
    }

    @Override
    public List<SecretFinding> scan(
            ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
        if (value == null || value.isBlank() || SecretRuleSupport.looksLikeSafeReference(value)) {
            return Collections.emptyList();
        }
        Matcher matcher = CANDIDATE.matcher(value);
        List<SecretFinding> findings = new ArrayList<>();
        while (matcher.find()) {
            String candidate = matcher.group();
            if (isPrivateKeyPayloadFragment(value, candidate)) {
                continue;
            }
            String suppressionReason =
                    NonSecretHeuristics.nonSecretHighEntropyReason(sourceName, value, fieldName, candidate);
            if (!suppressionReason.isEmpty() || NonSecretHeuristics.entropy(candidate) < 4.0) {
                if (!suppressionReason.isEmpty() && LOGGER.isLoggable(Level.FINE)) {
                    LOGGER.fine("[Secret Guard][Heuristics] " + suppressionReason + " Source=" + sourceName + ", field="
                            + fieldName + ", line=" + lineNumber + ".");
                }
                continue;
            }
            findings.add(SecretRuleSupport.finding(
                    getId(),
                    "High entropy string may be a secret",
                    Severity.MEDIUM,
                    context,
                    sourceName,
                    lineNumber,
                    fieldName,
                    candidate,
                    SecretRuleSupport.Recommendations.CREDENTIALS));
        }
        return findings;
    }

    private boolean isPrivateKeyPayloadFragment(String value, String candidate) {
        Matcher privateKeyMatcher = PRIVATE_KEY_BLOCK.matcher(value);
        while (privateKeyMatcher.find()) {
            if (privateKeyMatcher.group().contains(candidate)) {
                return true;
            }
        }
        return false;
    }
}
