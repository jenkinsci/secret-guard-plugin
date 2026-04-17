package io.jenkins.plugins.secretguard.action;

import hudson.model.Action;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import java.util.List;

public class SecretGuardRunAction implements Action, SeverityBadgeSupport {
    private final SecretScanResult result;

    public SecretGuardRunAction(SecretScanResult result) {
        this.result = result;
    }

    @Override
    public String getIconFileName() {
        return isVisible() ? "symbol-warning-outline plugin-ionicons-api" : null;
    }

    @Override
    public String getDisplayName() {
        return isVisible() ? "Secret Guard" : null;
    }

    @Override
    public String getUrlName() {
        return isVisible() ? "secret-guard" : null;
    }

    public SecretScanResult getResult() {
        return result;
    }

    public List<SecretFinding> getFindings() {
        return result.getFindings();
    }

    public List<String> getNotes() {
        return result.getNotes();
    }

    public boolean hasNotes() {
        return result.hasNotes();
    }

    private boolean isVisible() {
        return result.hasFindings() || result.hasNotes();
    }
}
