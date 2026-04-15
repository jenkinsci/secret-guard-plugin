package io.jenkins.plugins.secretguard.config;

import static org.junit.jupiter.api.Assertions.assertEquals;

import hudson.util.ListBoxModel;
import io.jenkins.plugins.secretguard.model.EnforcementMode;
import io.jenkins.plugins.secretguard.model.Severity;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class SecretGuardGlobalConfigurationTest {
    @Test
    void buildsAllEnforcementModeOptions() {
        ListBoxModel items = SecretGuardGlobalConfiguration.buildEnforcementModeItems();

        assertEquals(
                List.of(EnforcementMode.AUDIT.name(), EnforcementMode.WARN.name(), EnforcementMode.BLOCK.name()),
                valuesOf(items));
    }

    @Test
    void buildsAllBlockThresholdOptions() {
        ListBoxModel items = SecretGuardGlobalConfiguration.buildBlockThresholdItems();

        assertEquals(List.of(Severity.LOW.name(), Severity.MEDIUM.name(), Severity.HIGH.name()), valuesOf(items));
    }

    private List<String> valuesOf(ListBoxModel items) {
        return items.stream().map(option -> option.value).collect(Collectors.toList());
    }
}
