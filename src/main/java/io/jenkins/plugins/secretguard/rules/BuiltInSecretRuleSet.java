package io.jenkins.plugins.secretguard.rules;

import io.jenkins.plugins.secretguard.config.CustomPatternRuleEntry;
import io.jenkins.plugins.secretguard.config.SecretGuardGlobalConfiguration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class BuiltInSecretRuleSet {
    private final List<SecretRule> builtInRules;
    private final List<CustomPatternRuleEntry> explicitCustomPatternRules;

    public BuiltInSecretRuleSet() {
        this(null);
    }

    public BuiltInSecretRuleSet(List<CustomPatternRuleEntry> explicitCustomPatternRules) {
        this.explicitCustomPatternRules = explicitCustomPatternRules == null
                ? null
                : Collections.unmodifiableList(new ArrayList<>(explicitCustomPatternRules));
        this.builtInRules = Collections.unmodifiableList(buildBuiltInRules());
    }

    public List<SecretRule> getRules() {
        List<CustomPatternRuleEntry> customPatternRules = explicitCustomPatternRules;
        if (customPatternRules == null) {
            SecretGuardGlobalConfiguration configuration = SecretGuardGlobalConfiguration.get();
            customPatternRules = configuration == null ? List.of() : configuration.getCustomPatternRuleEntries();
        }
        if (customPatternRules.isEmpty()) {
            return builtInRules;
        }
        List<SecretRule> rules = new ArrayList<>(builtInRules);
        for (CustomPatternRuleEntry customPatternRule : customPatternRules) {
            rules.add(new GenericSecretRules.CustomPatternSecretRule(customPatternRule));
        }
        return Collections.unmodifiableList(rules);
    }

    private List<SecretRule> buildBuiltInRules() {
        List<SecretRule> rules = new ArrayList<>();
        rules.add(new SensitiveFieldRule());
        TokenRuleRegistry.addRules(rules);
        ContextRuleRegistry.addRules(rules);
        PrivateKeyRuleRegistry.addRules(rules);
        UrlRuleRegistry.addRules(rules);
        rules.add(new HighEntropyRule());
        return rules;
    }
}
