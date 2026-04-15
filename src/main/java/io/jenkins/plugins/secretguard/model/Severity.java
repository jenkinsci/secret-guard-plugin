package io.jenkins.plugins.secretguard.model;

public enum Severity {
    LOW,
    MEDIUM,
    HIGH;

    public boolean isAtLeast(Severity threshold) {
        return ordinal() >= threshold.ordinal();
    }
}
