package io.jenkins.plugins.secretguard.config;

import hudson.Extension;
import hudson.util.ListBoxModel;
import io.jenkins.plugins.secretguard.model.EnforcementMode;
import io.jenkins.plugins.secretguard.model.Severity;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import jenkins.model.GlobalConfiguration;
import org.kohsuke.stapler.DataBoundSetter;

@Extension
public class SecretGuardGlobalConfiguration extends GlobalConfiguration {
    private boolean enabled = true;
    private EnforcementMode enforcementMode = EnforcementMode.AUDIT;
    private Severity blockThreshold = Severity.HIGH;
    private String ruleIdWhitelist = "";
    private String jobWhitelist = "";
    private String fieldNameWhitelist = "";
    private String exemptions = "";

    public SecretGuardGlobalConfiguration() {
        load();
    }

    public static SecretGuardGlobalConfiguration get() {
        try {
            return GlobalConfiguration.all().get(SecretGuardGlobalConfiguration.class);
        } catch (IllegalStateException ignored) {
            return null;
        }
    }

    @Override
    public String getDisplayName() {
        return "Jenkins Secret Guard";
    }

    public boolean isEnabled() {
        return enabled;
    }

    @DataBoundSetter
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        save();
    }

    public EnforcementMode getEnforcementMode() {
        return enforcementMode == null ? EnforcementMode.AUDIT : enforcementMode;
    }

    @DataBoundSetter
    public void setEnforcementMode(EnforcementMode enforcementMode) {
        this.enforcementMode = enforcementMode == null ? EnforcementMode.AUDIT : enforcementMode;
        save();
    }

    public Severity getBlockThreshold() {
        return blockThreshold == null ? Severity.HIGH : blockThreshold;
    }

    @DataBoundSetter
    public void setBlockThreshold(Severity blockThreshold) {
        this.blockThreshold = blockThreshold == null ? Severity.HIGH : blockThreshold;
        save();
    }

    public String getRuleIdWhitelist() {
        return ruleIdWhitelist == null ? "" : ruleIdWhitelist;
    }

    @DataBoundSetter
    public void setRuleIdWhitelist(String ruleIdWhitelist) {
        this.ruleIdWhitelist = normalizeText(ruleIdWhitelist);
        save();
    }

    public String getJobWhitelist() {
        return jobWhitelist == null ? "" : jobWhitelist;
    }

    @DataBoundSetter
    public void setJobWhitelist(String jobWhitelist) {
        this.jobWhitelist = normalizeText(jobWhitelist);
        save();
    }

    public String getFieldNameWhitelist() {
        return fieldNameWhitelist == null ? "" : fieldNameWhitelist;
    }

    @DataBoundSetter
    public void setFieldNameWhitelist(String fieldNameWhitelist) {
        this.fieldNameWhitelist = normalizeText(fieldNameWhitelist);
        save();
    }

    public String getExemptions() {
        return exemptions == null ? "" : exemptions;
    }

    @DataBoundSetter
    public void setExemptions(String exemptions) {
        this.exemptions = normalizeText(exemptions);
        save();
    }

    public List<String> getRuleIdWhitelistEntries() {
        return splitEntries(getRuleIdWhitelist());
    }

    public List<String> getJobWhitelistEntries() {
        return splitEntries(getJobWhitelist());
    }

    public List<String> getFieldNameWhitelistEntries() {
        return splitEntries(getFieldNameWhitelist());
    }

    public List<String> getExemptionEntries() {
        return splitEntries(getExemptions());
    }

    public EnforcementMode[] getEnforcementModes() {
        return EnforcementMode.values();
    }

    public Severity[] getSeverities() {
        return Severity.values();
    }

    public ListBoxModel doFillEnforcementModeItems() {
        return buildEnforcementModeItems();
    }

    public ListBoxModel doFillBlockThresholdItems() {
        return buildBlockThresholdItems();
    }

    static ListBoxModel buildEnforcementModeItems() {
        ListBoxModel items = new ListBoxModel();
        for (EnforcementMode mode : EnforcementMode.values()) {
            items.add(mode.name(), mode.name());
        }
        return items;
    }

    static ListBoxModel buildBlockThresholdItems() {
        ListBoxModel items = new ListBoxModel();
        for (Severity severity : Severity.values()) {
            items.add(severity.name(), severity.name());
        }
        return items;
    }

    private static String normalizeText(String value) {
        return value == null ? "" : value.trim();
    }

    private static List<String> splitEntries(String value) {
        if (value == null || value.isBlank()) {
            return Collections.emptyList();
        }
        return Arrays.stream(value.split("[,\\n\\r]+"))
                .map(String::trim)
                .filter(entry -> !entry.isEmpty())
                .collect(Collectors.toList());
    }
}
