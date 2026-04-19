package io.jenkins.plugins.secretguard.config;

import hudson.Extension;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import io.jenkins.plugins.secretguard.model.EnforcementMode;
import io.jenkins.plugins.secretguard.model.Severity;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

@Extension
public class SecretGuardGlobalConfiguration extends GlobalConfiguration {
    private boolean enabled = true;
    private EnforcementMode enforcementMode = EnforcementMode.AUDIT;
    private Severity blockThreshold = Severity.HIGH;
    private String ruleIdAllowList = "";
    private String jobAllowList = "";
    private String fieldNameAllowList = "";
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

    public String getRuleIdAllowList() {
        return ruleIdAllowList == null ? "" : ruleIdAllowList;
    }

    @DataBoundSetter
    public void setRuleIdAllowList(String ruleIdAllowList) {
        this.ruleIdAllowList = normalizeText(ruleIdAllowList);
        save();
    }

    public String getJobAllowList() {
        return jobAllowList == null ? "" : jobAllowList;
    }

    @DataBoundSetter
    public void setJobAllowList(String jobAllowList) {
        this.jobAllowList = normalizeText(jobAllowList);
        save();
    }

    public String getFieldNameAllowList() {
        return fieldNameAllowList == null ? "" : fieldNameAllowList;
    }

    @DataBoundSetter
    public void setFieldNameAllowList(String fieldNameAllowList) {
        this.fieldNameAllowList = normalizeText(fieldNameAllowList);
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

    public List<String> getRuleIdAllowListEntries() {
        return splitAllowListEntries(getRuleIdAllowList());
    }

    public List<String> getJobAllowListEntries() {
        return splitAllowListEntries(getJobAllowList());
    }

    public List<String> getFieldNameAllowListEntries() {
        return splitAllowListEntries(getFieldNameAllowList());
    }

    public List<String> getExemptionEntries() {
        return splitExemptionEntries(getExemptions());
    }

    public EnforcementMode[] getEnforcementModes() {
        return EnforcementMode.values();
    }

    public Severity[] getSeverities() {
        return Severity.values();
    }

    @POST
    public ListBoxModel doFillEnforcementModeItems() {
        Jenkins.get().checkPermission(Jenkins.MANAGE);
        return buildEnforcementModeItems();
    }

    @POST
    public ListBoxModel doFillBlockThresholdItems() {
        Jenkins.get().checkPermission(Jenkins.MANAGE);
        return buildBlockThresholdItems();
    }

    @POST
    public FormValidation doCheckExemptions(@QueryParameter String value) {
        Jenkins.get().checkPermission(Jenkins.MANAGE);
        return validateExemptions(value);
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

    static List<String> splitAllowListEntries(String value) {
        if (value == null || value.isBlank()) {
            return Collections.emptyList();
        }
        return Arrays.stream(value.split("[,\\n\\r]+"))
                .map(String::trim)
                .filter(entry -> !entry.isEmpty())
                .collect(Collectors.toList());
    }

    static List<String> splitExemptionEntries(String value) {
        if (value == null || value.isBlank()) {
            return Collections.emptyList();
        }
        return Arrays.stream(value.split("\\r?\\n"))
                .map(String::trim)
                .filter(entry -> !entry.isEmpty())
                .collect(Collectors.toList());
    }

    static FormValidation validateExemptions(String value) {
        boolean hasEmptyReason = false;
        List<String> entries = splitExemptionEntries(value);
        for (int index = 0; index < entries.size(); index++) {
            String entry = entries.get(index);
            String[] parts = entry.split("\\|", 3);
            int lineNumber = index + 1;
            if (parts.length < 3) {
                return FormValidation.error("Line %d must use jobFullName|ruleId|reason.", lineNumber);
            }
            if (parts[0].trim().isEmpty()) {
                return FormValidation.error("Line %d is missing jobFullName.", lineNumber);
            }
            if (parts[1].trim().isEmpty()) {
                return FormValidation.error("Line %d is missing ruleId.", lineNumber);
            }
            if (parts[2].trim().isEmpty()) {
                hasEmptyReason = true;
            }
        }
        if (hasEmptyReason) {
            return FormValidation.warning("Entries with an empty reason are ignored until a reason is provided.");
        }
        return FormValidation.ok();
    }
}
