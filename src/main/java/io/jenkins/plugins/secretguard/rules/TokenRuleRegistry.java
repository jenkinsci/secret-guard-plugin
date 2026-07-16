package io.jenkins.plugins.secretguard.rules;

import io.jenkins.plugins.secretguard.model.Severity;
import java.util.List;
import java.util.regex.Pattern;

final class TokenRuleRegistry {
    private TokenRuleRegistry() {}

    static void addRules(List<SecretRule> rules) {
        rules.add(new GenericSecretRules.PatternSecretRule(
                "jwt-token",
                "JWT token is hardcoded",
                Severity.HIGH,
                Pattern.compile("\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b"),
                SecretRuleSupport.Recommendations.CREDENTIALS));
        rules.add(new GenericSecretRules.PatternSecretRule(
                "github-token",
                "GitHub token is hardcoded",
                Severity.HIGH,
                GitHubTokenPatterns.HIGH_CONFIDENCE_TOKEN,
                SecretRuleSupport.Recommendations.CREDENTIALS));
        rules.add(new GenericSecretRules.PatternSecretRule(
                "aws-access-key",
                "AWS access key is hardcoded",
                Severity.HIGH,
                Pattern.compile("\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b"),
                SecretRuleSupport.Recommendations.CREDENTIALS));
        rules.add(new GenericSecretRules.PatternSecretRule(
                "aws-secret-key",
                "AWS secret key pattern is hardcoded",
                Severity.HIGH,
                Pattern.compile(
                        "(?i)(?:aws(.{0,20})?)?(?:secret|secretAccessKey|secret_access_key)['\"\\s:=]+([A-Za-z0-9/+=]{40})"),
                SecretRuleSupport.Recommendations.CREDENTIALS,
                2));
        rules.add(new GenericSecretRules.PatternSecretRule(
                "bearer-token",
                "Bearer token is hardcoded",
                Severity.HIGH,
                Pattern.compile("(?i)\\bBearer\\s+([A-Za-z0-9._~+/=-]{12,})"),
                SecretRuleSupport.Recommendations.NO_COMMAND_LINE_SECRET,
                1));
        rules.add(new GenericSecretRules.PatternSecretRule(
                "slack-bot-token",
                "Slack bot token is hardcoded",
                Severity.HIGH,
                Pattern.compile("\\bxoxb-[0-9]{8,}(?:-[0-9]{8,})?-[A-Za-z0-9-]{20,}\\b"),
                SecretRuleSupport.Recommendations.CREDENTIALS));
        rules.add(new GenericSecretRules.PatternSecretRule(
                "pypi-api-token",
                "PyPI API token is hardcoded",
                Severity.HIGH,
                Pattern.compile("\\bpypi-[A-Za-z0-9_-]{60,}\\b"),
                SecretRuleSupport.Recommendations.CREDENTIALS));
        rules.add(new GenericSecretRules.PatternSecretRule(
                "gitlab-token",
                "GitLab token is hardcoded",
                Severity.HIGH,
                Pattern.compile(
                        "\\b(?:glpat|gloas|gldt|glrt|glrtr|glcbt|glptt|glft|glimt|glagent|glwt|glsoat|glffct)-[A-Za-z0-9_-]{20,}\\b"),
                SecretRuleSupport.Recommendations.CREDENTIALS));
        rules.add(new BasicAuthHeaderRule());
    }
}
