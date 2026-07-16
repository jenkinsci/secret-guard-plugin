package io.jenkins.plugins.secretguard.rules;

import io.jenkins.plugins.secretguard.model.Severity;
import java.util.List;
import java.util.regex.Pattern;

final class PrivateKeyRuleRegistry {
    private PrivateKeyRuleRegistry() {}

    static void addRules(List<SecretRule> rules) {
        rules.add(new GenericSecretRules.PatternSecretRule(
                "openssh-private-key",
                "OpenSSH private key is hardcoded",
                Severity.HIGH,
                Pattern.compile("-----BEGIN OPENSSH PRIVATE KEY-----[\\s\\S]*?-----END OPENSSH PRIVATE KEY-----"),
                SecretRuleSupport.Recommendations.CREDENTIALS));
        rules.add(new GenericSecretRules.PatternSecretRule(
                "rsa-private-key",
                "RSA private key is hardcoded",
                Severity.HIGH,
                Pattern.compile("-----BEGIN RSA PRIVATE KEY-----[\\s\\S]*?-----END RSA PRIVATE KEY-----"),
                SecretRuleSupport.Recommendations.CREDENTIALS));
        rules.add(new GenericSecretRules.PatternSecretRule(
                "ec-private-key",
                "EC private key is hardcoded",
                Severity.HIGH,
                Pattern.compile("-----BEGIN EC PRIVATE KEY-----[\\s\\S]*?-----END EC PRIVATE KEY-----"),
                SecretRuleSupport.Recommendations.CREDENTIALS));
        rules.add(new GenericSecretRules.PatternSecretRule(
                "pgp-private-key",
                "PGP private key is hardcoded",
                Severity.HIGH,
                Pattern.compile("-----BEGIN PGP PRIVATE KEY BLOCK-----[\\s\\S]*?-----END PGP PRIVATE KEY BLOCK-----"),
                SecretRuleSupport.Recommendations.CREDENTIALS));
        rules.add(new GenericSecretRules.PatternSecretRule(
                "pem-private-key",
                "PEM private key is hardcoded",
                Severity.HIGH,
                Pattern.compile("-----BEGIN [A-Z ]*PRIVATE KEY-----[\\s\\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
                SecretRuleSupport.Recommendations.CREDENTIALS));
    }
}
