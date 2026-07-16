package io.jenkins.plugins.secretguard.rules;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jenkins.plugins.secretguard.config.CustomPatternRuleEntry;
import io.jenkins.plugins.secretguard.model.EnforcementMode;
import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.ScanPhase;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.Severity;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

class RuleRegistryCoverageTest {
    private final ScanContext context = new ScanContext(
            "folder/job",
            "Pipeline script",
            "WorkflowJob",
            FindingLocationType.PIPELINE_SCRIPT,
            ScanPhase.BUILD,
            EnforcementMode.BLOCK,
            Severity.HIGH);

    @Test
    void secretRuleSupportCoversSharedHelperBranches() {
        assertTrue(SecretRuleSupport.isSensitiveField("serviceApiToken"));
        assertFalse(SecretRuleSupport.isSensitiveField(null));
        assertEquals(
                "PlainSecret42",
                SecretRuleSupport.normalizeAssignedLiteralValue("PASSWORD", "PASSWORD = 'PlainSecret42'"));
        assertEquals(
                "OTHER = 'PlainSecret42'",
                SecretRuleSupport.normalizeAssignedLiteralValue("PASSWORD", "OTHER = 'PlainSecret42'"));
        assertTrue(SecretRuleSupport.shouldSkipContextLiteral(null));
        assertTrue(SecretRuleSupport.shouldSkipContextLiteral("short"));
        assertTrue(SecretRuleSupport.shouldSkipContextLiteral("${SERVICE_TOKEN}"));
        assertFalse(SecretRuleSupport.shouldSkipContextLiteral("PlainSecret42"));
        assertTrue(SecretRuleSupport.looksLikeKnownProviderWebhookUrl(slackWebhookUrl()));
        assertFalse(
                SecretRuleSupport.looksLikeKnownProviderWebhookUrl("https://hooks.example.invalid/services/runtime"));
        assertEquals("", SecretRuleSupport.nullToEmpty(null));
        assertEquals("value", SecretRuleSupport.nullToEmpty("value"));
        assertNotNull(SecretRuleSupport.Recommendations.CREDENTIALS);
    }

    @Test
    void basicAuthHeaderRuleSkipsInvalidAndNonCredentialTokens() {
        BasicAuthHeaderRule rule = new BasicAuthHeaderRule();

        assertTrue(scanRule(rule, "Authorization", "Authorization: Basic not-base64____")
                .isEmpty());
        assertTrue(scanRule(rule, "Authorization", "Authorization: Basic cGxhaW5zZWNyZXQ=")
                .isEmpty());
        assertTrue(scanRule(rule, "serviceCredentialsId", "Authorization: Basic QWxhZGRpbjpPcGVuU2VzYW1l")
                .isEmpty());
    }

    @Test
    void genericPatternRulesHandleGroupedMatchesAndSafeReferences() {
        GenericSecretRules.PatternSecretRule patternRule = new GenericSecretRules.PatternSecretRule(
                "grouped-secret",
                "Grouped secret is hardcoded",
                Severity.HIGH,
                Pattern.compile("secret=([A-Za-z0-9]+)"),
                SecretRuleSupport.Recommendations.CREDENTIALS,
                1);
        GenericSecretRules.PatternSecretRule directMatchRule = new GenericSecretRules.PatternSecretRule(
                "direct-secret",
                "Direct secret is hardcoded",
                Severity.HIGH,
                Pattern.compile("PlainSecret42"),
                SecretRuleSupport.Recommendations.CREDENTIALS);

        List<SecretFinding> groupedFindings = scanRule(patternRule, "", "secret=PlainSecret42");
        assertEquals("grouped-secret", patternRule.getId());
        assertEquals(1, groupedFindings.size());
        assertEquals("grouped-secret", groupedFindings.get(0).getRuleId());

        List<SecretFinding> directFindings = scanRule(directMatchRule, "", "PlainSecret42");
        assertEquals("direct-secret", directMatchRule.getId());
        assertEquals(1, directFindings.size());
        assertTrue(
                scanRule(directMatchRule, "tokenCredentialsId", "PlainSecret42").isEmpty());
        assertTrue(scanRule(directMatchRule, "", "${SERVICE_TOKEN}").isEmpty());
    }

    @Test
    void customPatternSecretRuleSkipsSafeReferencesAndReportsConfiguredMatches() {
        CustomPatternRuleEntry entry = new CustomPatternRuleEntry(
                "oracle-connection-url",
                "Oracle connection string contains a hardcoded password",
                Severity.HIGH,
                "(?i)password=([^;\\s]+)",
                1);
        GenericSecretRules.CustomPatternSecretRule rule = new GenericSecretRules.CustomPatternSecretRule(entry);

        List<SecretFinding> findings = scanRule(
                rule, "databaseUrl", "jdbc:oracle:thin:@repo-host:1521/builddb?user=build_user&password=PlainSecret42");

        assertEquals("oracle-connection-url", rule.getId());
        assertEquals(1, findings.size());
        assertTrue(scanRule(rule, "databaseUrl", "jdbc:oracle:thin:@repo-host:1521/builddb?password=${DB_PASSWORD}")
                .isEmpty());
    }

    @Test
    void databaseConnectionStringRuleCoversAuthorityAndQueryBranches() {
        GenericSecretRules.DatabaseConnectionStringRule rule = new GenericSecretRules.DatabaseConnectionStringRule(
                "postgres-connection-string",
                "PostgreSQL connection string contains a hardcoded password",
                Pattern.compile("(?i)\\b(?:jdbc:)?postgres(?:ql)?://[^\\s'\"<>]+"));

        assertEquals(
                1,
                scanRule(rule, "", "postgresql://build_user:PlainSecret42@db.example.invalid:5432/example)")
                        .size());
        assertEquals(
                1,
                scanRule(
                                rule,
                                "",
                                "postgresql://db.example.invalid:5432/example?username=build_user;password=PlainSecret42#fragment")
                        .size());
        assertTrue(scanRule(rule, "", "postgresql://build_user@db.example.invalid:5432/example")
                .isEmpty());
        assertTrue(scanRule(rule, "", "postgresql://db.example.invalid:5432/example?user=build_user&password=short")
                .isEmpty());
    }

    @Test
    void urlRulesCoverRuntimeReferencesAndAdditionalNotifierBranches() {
        SecretRule queryRule = registryRule(UrlRuleRegistry::addRules, "url-query-secret");
        SecretRule notifierRule = registryRule(UrlRuleRegistry::addRules, "notifier-url-secret");

        assertTrue(scanRule(queryRule, "", "https://notify.example.invalid/api/webhook/deliver?token=${SERVICE_TOKEN}")
                .isEmpty());
        assertTrue(scanRule(queryRule, "", "https://notify.example.invalid/api/webhook/deliver?key=short")
                .isEmpty());
        assertEquals(
                1,
                scanRule(
                                notifierRule,
                                "webhookUrl",
                                "https://notify.example.invalid/api/hook/123e4567-e89b-12d3-a456-426614174000")
                        .size());
        assertTrue(scanRule(
                        notifierRule, "downloadUrl", "https://downloads.example.invalid/files/Nr8YkL2Pm5Qx7Vd1Hs4Jt6Ua")
                .isEmpty());
        assertTrue(scanRule(notifierRule, "notifyUrl", "https://notify.example.invalid")
                .isEmpty());
    }

    @Test
    void contextRulesCoverAdditionalGuardPaths() {
        SecretRule jfrogRule = registryRule(ContextRuleRegistry::addRules, "jfrog-access-token-context");
        SecretRule commandRule = registryRule(ContextRuleRegistry::addRules, "command-user-password-argument");
        SecretRule dockerStdinRule = registryRule(ContextRuleRegistry::addRules, "docker-password-stdin-secret");
        SecretRule pypiRule = registryRule(ContextRuleRegistry::addRules, "pypi-password-context");
        SecretRule npmAuthRule = registryRule(ContextRuleRegistry::addRules, "npm-auth-token-context");

        assertEquals(
                1,
                scanRule(jfrogRule, "", "artifactory config --access-token PlainSecret42")
                        .size());
        assertTrue(scanRule(commandRule, "", "curl -u build-user https://example.invalid")
                .isEmpty());
        assertTrue(scanRule(
                        dockerStdinRule,
                        "",
                        "echo short | docker login --username build-user --password-stdin registry.example.invalid")
                .isEmpty());
        assertEquals(
                1,
                scanRule(
                                pypiRule,
                                "distConfig",
                                "repository: https://upload.pypi.org/legacy/\npassword = PlainSecret42")
                        .size());
        assertTrue(scanRule(npmAuthRule, "", "").isEmpty());
    }

    @Test
    void highEntropyRuleReturnsEmptyForSafeReferences() {
        HighEntropyRule rule = new HighEntropyRule();

        assertTrue(scanRule(rule, "token", "${SERVICE_TOKEN}").isEmpty());
    }

    private List<SecretFinding> scanRule(SecretRule rule, String fieldName, String value) {
        return scanRule(rule, fieldName, value, 1);
    }

    private List<SecretFinding> scanRule(SecretRule rule, String fieldName, String value, int lineNumber) {
        return rule.scan(context, "Pipeline script", lineNumber, fieldName, value);
    }

    private SecretRule registryRule(RuleRegistrar registrar, String ruleId) {
        List<SecretRule> rules = new ArrayList<>();
        registrar.addTo(rules);
        return rules.stream()
                .filter(rule -> rule.getId().equals(ruleId))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Missing rule: " + ruleId));
    }

    private String slackWebhookUrl() {
        return "https://hooks.slack.com"
                + "/services/"
                + "T00000000"
                + "/"
                + "B00000000"
                + "/"
                + "Nr8YkL2Pm5Qx7Vd1Hs4Jt6Ua";
    }

    @FunctionalInterface
    private interface RuleRegistrar {
        void addTo(List<SecretRule> rules);
    }
}
