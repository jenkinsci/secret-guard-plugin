package io.jenkins.plugins.secretguard.rules;

import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.Severity;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class ContextRuleRegistry {
    private ContextRuleRegistry() {}

    static void addRules(List<SecretRule> rules) {
        rules.add(new NpmAuthTokenContextRule());
        rules.add(new NpmLegacyAuthContextRule());
        rules.add(new JfrogAccessTokenContextRule());
        rules.add(new CommandUserPasswordContextRule());
        rules.add(new DockerPasswordStdinContextRule());
        rules.add(new PyPiPasswordContextRule());
        rules.add(new KubernetesSecretLiteralContextRule());
    }

    private abstract static class ContextPatternRuleSupport implements SecretRule {
        protected final void addContextFindings(
                ScanContext context,
                String sourceName,
                int lineNumber,
                String fieldName,
                String value,
                Pattern pattern,
                List<SecretFinding> findings,
                String fallbackFieldName,
                String title,
                String recommendation) {
            Matcher matcher = pattern.matcher(value);
            while (matcher.find()) {
                String token = matcher.group(2);
                if (SecretRuleSupport.shouldSkipContextLiteral(token)) {
                    continue;
                }
                findings.add(SecretRuleSupport.finding(
                        getId(),
                        title,
                        Severity.HIGH,
                        context,
                        sourceName,
                        lineNumber,
                        fieldName.isBlank() ? fallbackFieldName : fieldName,
                        token,
                        recommendation));
            }
        }
    }

    private static final class NpmAuthTokenContextRule extends ContextPatternRuleSupport {
        private static final Pattern ASSIGNED_AUTH_TOKEN = Pattern.compile(
                "(?i)(?:^|\\s)(?:(?://[^\\s'\"=]+/)?:_authToken|_authToken)\\s*[=:]\\s*(['\"]?)([^\\s'\"}]+)\\1");
        private static final Pattern CONFIG_SET_AUTH_TOKEN =
                Pattern.compile("(?i)\\bnpm\\s+config\\s+set\\s+//[^\\s]+/:_authToken\\s+(['\"]?)([^\\s'\"\\\\]+)\\1");

        @Override
        public String getId() {
            return "npm-auth-token-context";
        }

        @Override
        public List<SecretFinding> scan(
                ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
            if (value == null || value.isBlank()) {
                return Collections.emptyList();
            }
            List<SecretFinding> findings = new ArrayList<>();
            addContextFindings(
                    context,
                    sourceName,
                    lineNumber,
                    fieldName,
                    value,
                    ASSIGNED_AUTH_TOKEN,
                    findings,
                    "_authToken",
                    "npm registry auth token is hardcoded",
                    SecretRuleSupport.Recommendations.CREDENTIALS);
            addContextFindings(
                    context,
                    sourceName,
                    lineNumber,
                    fieldName,
                    value,
                    CONFIG_SET_AUTH_TOKEN,
                    findings,
                    "_authToken",
                    "npm registry auth token is hardcoded",
                    SecretRuleSupport.Recommendations.CREDENTIALS);
            return findings;
        }
    }

    private static final class JfrogAccessTokenContextRule extends ContextPatternRuleSupport {
        private static final Pattern CLI_ACCESS_TOKEN_ARGUMENT =
                Pattern.compile("(?i)--access-token(?:=|\\s+)(['\"]?)([^\\s'\"\\\\]+)\\1");
        private static final Pattern JFROG_CLI_ACCESS_TOKEN_ASSIGNMENT =
                Pattern.compile("(?i)\\bJFROG_CLI_ACCESS_TOKEN\\s*[=:]\\s*(['\"]?)([^\\s'\";]+)\\1");
        private static final Pattern JFROG_API_KEY_HEADER =
                Pattern.compile("(?i)X-JFrog-Art-Api\\s*[:=]\\s*(['\"]?)([^\\s'\";]+)\\1");

        @Override
        public String getId() {
            return "jfrog-access-token-context";
        }

        @Override
        public List<SecretFinding> scan(
                ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
            if (value == null || value.isBlank()) {
                return Collections.emptyList();
            }
            List<SecretFinding> findings = new ArrayList<>();
            addContextFindings(
                    context,
                    sourceName,
                    lineNumber,
                    fieldName,
                    value,
                    JFROG_CLI_ACCESS_TOKEN_ASSIGNMENT,
                    findings,
                    "JFROG_CLI_ACCESS_TOKEN",
                    "JFrog access token or API key is hardcoded",
                    SecretRuleSupport.Recommendations.CREDENTIALS);
            addContextFindings(
                    context,
                    sourceName,
                    lineNumber,
                    fieldName,
                    value,
                    JFROG_API_KEY_HEADER,
                    findings,
                    "X-JFrog-Art-Api",
                    "JFrog access token or API key is hardcoded",
                    SecretRuleSupport.Recommendations.CREDENTIALS);
            if (looksLikeJfrogCommandContext(value)) {
                addContextFindings(
                        context,
                        sourceName,
                        lineNumber,
                        fieldName,
                        value,
                        CLI_ACCESS_TOKEN_ARGUMENT,
                        findings,
                        fieldName,
                        "JFrog access token or API key is hardcoded",
                        SecretRuleSupport.Recommendations.CREDENTIALS);
            }
            return findings;
        }

        private boolean looksLikeJfrogCommandContext(String value) {
            String lower = value.toLowerCase(Locale.ENGLISH);
            return lower.contains("jf ")
                    || lower.contains("jfrog ")
                    || lower.contains("artifactory")
                    || lower.contains("jf c ")
                    || lower.contains("jf rt ");
        }
    }

    private static final class NpmLegacyAuthContextRule extends ContextPatternRuleSupport {
        private static final Pattern ASSIGNED_AUTH =
                Pattern.compile("(?i)(?:^|\\s)(?:(?://[^\\s'\"=]+/)?:_auth|_auth)\\s*[=:]\\s*(['\"]?)([^\\s'\"}]+)\\1");
        private static final Pattern ASSIGNED_PASSWORD = Pattern.compile(
                "(?i)(?:^|\\s)(?:(?://[^\\s'\"=]+/)?:_password|_password)\\s*[=:]\\s*(['\"]?)([^\\s'\"}]+)\\1");
        private static final Pattern CONFIG_SET_AUTH =
                Pattern.compile("(?i)\\bnpm\\s+config\\s+set\\s+(?://[^\\s]+/:)?_auth\\s+(['\"]?)([^\\s'\"\\\\]+)\\1");
        private static final Pattern CONFIG_SET_PASSWORD = Pattern.compile(
                "(?i)\\bnpm\\s+config\\s+set\\s+(?://[^\\s]+/:)?_password\\s+(['\"]?)([^\\s'\"\\\\]+)\\1");

        @Override
        public String getId() {
            return "npm-legacy-auth-context";
        }

        @Override
        public List<SecretFinding> scan(
                ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
            if (value == null || value.isBlank()) {
                return Collections.emptyList();
            }
            List<SecretFinding> findings = new ArrayList<>();
            addContextFindings(
                    context,
                    sourceName,
                    lineNumber,
                    fieldName,
                    value,
                    ASSIGNED_AUTH,
                    findings,
                    "_auth",
                    "npm legacy auth credential is hardcoded",
                    SecretRuleSupport.Recommendations.CREDENTIALS);
            addContextFindings(
                    context,
                    sourceName,
                    lineNumber,
                    fieldName,
                    value,
                    ASSIGNED_PASSWORD,
                    findings,
                    "_password",
                    "npm legacy auth credential is hardcoded",
                    SecretRuleSupport.Recommendations.CREDENTIALS);
            addContextFindings(
                    context,
                    sourceName,
                    lineNumber,
                    fieldName,
                    value,
                    CONFIG_SET_AUTH,
                    findings,
                    "_auth",
                    "npm legacy auth credential is hardcoded",
                    SecretRuleSupport.Recommendations.CREDENTIALS);
            addContextFindings(
                    context,
                    sourceName,
                    lineNumber,
                    fieldName,
                    value,
                    CONFIG_SET_PASSWORD,
                    findings,
                    "_password",
                    "npm legacy auth credential is hardcoded",
                    SecretRuleSupport.Recommendations.CREDENTIALS);
            return findings;
        }
    }

    private static final class CommandUserPasswordContextRule extends ContextPatternRuleSupport {
        private static final Pattern CURL_USER_ARGUMENT =
                Pattern.compile("(?i)\\bcurl\\b[^\\r\\n]*?(?:\\s-u|\\s--user)(?:=|\\s+)(['\"]?)([^\\s'\"\\\\]+)\\1");
        private static final Pattern DOCKER_PASSWORD_ARGUMENT = Pattern.compile(
                "(?i)\\bdocker\\b[^\\r\\n]*?\\blogin\\b[^\\r\\n]*?(?:\\s-p|\\s--password)(?:=|\\s+)(['\"]?)([^\\s'\"\\\\]+)\\1");
        private static final Pattern MYSQL_PASSWORD_ARGUMENT = Pattern.compile(
                "(?i)\\b(?:mysql|mysqldump|mysqlimport)\\b[^\\r\\n]*?\\s--password(?:=|\\s+)(['\"]?)([^\\s'\"\\\\]+)\\1");
        private static final Pattern MYSQL_SHORT_PASSWORD_ARGUMENT =
                Pattern.compile("(?i)\\b(?:mysql|mysqldump|mysqlimport)\\b[^\\r\\n]*?\\s-p(['\"]?)([^\\s'\"\\\\]+)\\1");
        private static final Pattern SSHPASS_PASSWORD_ARGUMENT =
                Pattern.compile("(?i)\\bsshpass\\b[^\\r\\n]*?\\s-p(?:\\s+)?(['\"]?)([^\\s'\"\\\\]+)\\1");
        private static final Pattern WGET_PASSWORD_ARGUMENT =
                Pattern.compile("(?i)\\bwget\\b[^\\r\\n]*?\\s--password(?:=|\\s+)(['\"]?)([^\\s'\"\\\\]+)\\1");

        @Override
        public String getId() {
            return "command-user-password-argument";
        }

        @Override
        public List<SecretFinding> scan(
                ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
            if (value == null || value.isBlank()) {
                return Collections.emptyList();
            }
            List<SecretFinding> findings = new ArrayList<>();
            collectCurlFindings(context, sourceName, lineNumber, fieldName, value, findings);
            addContextFindings(
                    context,
                    sourceName,
                    lineNumber,
                    fieldName,
                    value,
                    DOCKER_PASSWORD_ARGUMENT,
                    findings,
                    "--password",
                    "Command line password argument is hardcoded",
                    SecretRuleSupport.Recommendations.NO_COMMAND_LINE_SECRET);
            addContextFindings(
                    context,
                    sourceName,
                    lineNumber,
                    fieldName,
                    value,
                    SSHPASS_PASSWORD_ARGUMENT,
                    findings,
                    "-p",
                    "Command line password argument is hardcoded",
                    SecretRuleSupport.Recommendations.NO_COMMAND_LINE_SECRET);
            addContextFindings(
                    context,
                    sourceName,
                    lineNumber,
                    fieldName,
                    value,
                    WGET_PASSWORD_ARGUMENT,
                    findings,
                    "--password",
                    "Command line password argument is hardcoded",
                    SecretRuleSupport.Recommendations.NO_COMMAND_LINE_SECRET);
            addContextFindings(
                    context,
                    sourceName,
                    lineNumber,
                    fieldName,
                    value,
                    MYSQL_PASSWORD_ARGUMENT,
                    findings,
                    "--password",
                    "Command line password argument is hardcoded",
                    SecretRuleSupport.Recommendations.NO_COMMAND_LINE_SECRET);
            addContextFindings(
                    context,
                    sourceName,
                    lineNumber,
                    fieldName,
                    value,
                    MYSQL_SHORT_PASSWORD_ARGUMENT,
                    findings,
                    "-p",
                    "Command line password argument is hardcoded",
                    SecretRuleSupport.Recommendations.NO_COMMAND_LINE_SECRET);
            return findings;
        }

        private void collectCurlFindings(
                ScanContext context,
                String sourceName,
                int lineNumber,
                String fieldName,
                String value,
                List<SecretFinding> findings) {
            Matcher matcher = CURL_USER_ARGUMENT.matcher(value);
            while (matcher.find()) {
                String token = matcher.group(2);
                if (SecretRuleSupport.shouldSkipContextLiteral(token) || !token.contains(":")) {
                    continue;
                }
                findings.add(SecretRuleSupport.finding(
                        getId(),
                        "Command line basic authentication credential is hardcoded",
                        Severity.HIGH,
                        context,
                        sourceName,
                        lineNumber,
                        fieldName.isBlank() ? "--user" : fieldName,
                        token,
                        SecretRuleSupport.Recommendations.NO_COMMAND_LINE_SECRET));
            }
        }
    }

    private static final class DockerPasswordStdinContextRule implements SecretRule {
        private static final Pattern ECHO_PASSWORD_STDIN = Pattern.compile(
                "(?i)\\becho\\b\\s+(['\"]?)([^\\s'\"\\\\|]+)\\1\\s*\\|\\s*docker\\b[^\\r\\n]*?\\blogin\\b[^\\r\\n]*?\\s--password-stdin(?:\\s|$)");

        @Override
        public String getId() {
            return "docker-password-stdin-secret";
        }

        @Override
        public List<SecretFinding> scan(
                ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
            if (value == null || value.isBlank()) {
                return Collections.emptyList();
            }
            Matcher matcher = ECHO_PASSWORD_STDIN.matcher(value);
            List<SecretFinding> findings = new ArrayList<>();
            while (matcher.find()) {
                String token = matcher.group(2);
                if (SecretRuleSupport.shouldSkipContextLiteral(token)) {
                    continue;
                }
                findings.add(SecretRuleSupport.finding(
                        getId(),
                        "docker login password-stdin secret is hardcoded",
                        Severity.HIGH,
                        context,
                        sourceName,
                        lineNumber,
                        fieldName.isBlank() ? "--password-stdin" : fieldName,
                        token,
                        SecretRuleSupport.Recommendations.NO_COMMAND_LINE_SECRET));
            }
            return findings;
        }
    }

    private static final class PyPiPasswordContextRule extends ContextPatternRuleSupport {
        private static final Pattern TWINE_PASSWORD_ASSIGNMENT =
                Pattern.compile("(?i)\\bTWINE_PASSWORD\\s*[=:]\\s*(['\"]?)([^\\s'\";]+)\\1");
        private static final Pattern TWINE_PASSWORD_ARGUMENT = Pattern.compile(
                "(?i)\\btwine\\s+upload\\b[^\\r\\n]*?(?:\\s-p|\\s--password)(?:=|\\s+)(['\"]?)([^\\s'\"\\\\]+)\\1");
        private static final Pattern PYPIRC_PASSWORD_LINE =
                Pattern.compile("(?im)^\\s*password\\s*=\\s*(['\"]?)([^\\s'\"#;]+)\\1");

        @Override
        public String getId() {
            return "pypi-password-context";
        }

        @Override
        public List<SecretFinding> scan(
                ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
            if (value == null || value.isBlank()) {
                return Collections.emptyList();
            }
            List<SecretFinding> findings = new ArrayList<>();
            addContextFindings(
                    context,
                    sourceName,
                    lineNumber,
                    fieldName,
                    value,
                    TWINE_PASSWORD_ASSIGNMENT,
                    findings,
                    "TWINE_PASSWORD",
                    "PyPI or Twine password is hardcoded",
                    SecretRuleSupport.Recommendations.CREDENTIALS);
            addContextFindings(
                    context,
                    sourceName,
                    lineNumber,
                    fieldName,
                    value,
                    TWINE_PASSWORD_ARGUMENT,
                    findings,
                    "--password",
                    "PyPI or Twine password is hardcoded",
                    SecretRuleSupport.Recommendations.CREDENTIALS);
            if (looksLikePypircContext(fieldName, value)) {
                addContextFindings(
                        context,
                        sourceName,
                        lineNumber,
                        fieldName,
                        value,
                        PYPIRC_PASSWORD_LINE,
                        findings,
                        "password",
                        "PyPI or Twine password is hardcoded",
                        SecretRuleSupport.Recommendations.CREDENTIALS);
            }
            return findings;
        }

        private boolean looksLikePypircContext(String fieldName, String value) {
            String lowerFieldName = SecretRuleSupport.nullToEmpty(fieldName).toLowerCase(Locale.ENGLISH);
            String lowerValue = SecretRuleSupport.nullToEmpty(value).toLowerCase(Locale.ENGLISH);
            return lowerFieldName.contains("pypirc")
                    || lowerValue.contains("[distutils]")
                    || lowerValue.contains("index-servers")
                    || lowerValue.contains("[pypi]")
                    || lowerValue.contains("repository:");
        }
    }

    private static final class KubernetesSecretLiteralContextRule implements SecretRule {
        private static final Pattern SECRET_FROM_LITERAL = Pattern.compile(
                "(?i)\\b(?:kubectl|oc)\\b[^\\r\\n]*?\\bcreate\\s+secret\\b[^\\r\\n]*?--from-literal(?:=|\\s+)([A-Za-z0-9_.-]+)=(['\"]?)([^\\s'\"\\\\]+)\\2");

        @Override
        public String getId() {
            return "kubernetes-secret-from-literal";
        }

        @Override
        public List<SecretFinding> scan(
                ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
            if (value == null || value.isBlank()) {
                return Collections.emptyList();
            }
            Matcher matcher = SECRET_FROM_LITERAL.matcher(value);
            List<SecretFinding> findings = new ArrayList<>();
            while (matcher.find()) {
                String literalFieldName = matcher.group(1);
                String token = matcher.group(3);
                if (SecretRuleSupport.shouldSkipContextLiteral(token)) {
                    continue;
                }
                findings.add(SecretRuleSupport.finding(
                        getId(),
                        "Kubernetes secret literal is hardcoded on the command line",
                        Severity.HIGH,
                        context,
                        sourceName,
                        lineNumber,
                        literalFieldName,
                        token,
                        SecretRuleSupport.Recommendations.NO_COMMAND_LINE_SECRET));
            }
            return findings;
        }
    }
}
