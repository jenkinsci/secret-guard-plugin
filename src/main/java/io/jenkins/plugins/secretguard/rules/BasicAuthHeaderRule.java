package io.jenkins.plugins.secretguard.rules;

import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.util.NonSecretHeuristics;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class BasicAuthHeaderRule implements SecretRule {
    private static final Pattern BASIC_AUTH_LITERAL = Pattern.compile("(?i)\\bBasic\\s+([A-Za-z0-9+/=]{8,})");

    @Override
    public String getId() {
        return "basic-auth-header";
    }

    @Override
    public List<SecretFinding> scan(
            ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
        if (value == null
                || value.isBlank()
                || NonSecretHeuristics.isCredentialIdField(fieldName)
                || SecretRuleSupport.looksLikeSafeReference(value)) {
            return Collections.emptyList();
        }
        Matcher matcher = BASIC_AUTH_LITERAL.matcher(value);
        List<SecretFinding> findings = new ArrayList<>();
        while (matcher.find()) {
            String token = matcher.group(1);
            if (!looksLikeBasicAuthCredential(token)) {
                continue;
            }
            findings.add(SecretRuleSupport.finding(
                    getId(),
                    "HTTP Basic authentication credential is hardcoded",
                    Severity.HIGH,
                    context,
                    sourceName,
                    lineNumber,
                    fieldName,
                    token,
                    SecretRuleSupport.Recommendations.NO_COMMAND_LINE_SECRET));
        }
        return findings;
    }

    private boolean looksLikeBasicAuthCredential(String token) {
        try {
            String decoded = new String(Base64.getDecoder().decode(token), StandardCharsets.UTF_8);
            int separator = decoded.indexOf(':');
            return separator > 0 && separator < decoded.length();
        } catch (IllegalArgumentException ignored) {
            return false;
        }
    }
}
