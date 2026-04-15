package io.jenkins.plugins.secretguard.model;

public class ScanContext {
    private final String jobFullName;
    private final String sourceName;
    private final String targetType;
    private final FindingLocationType locationType;
    private final ScanPhase scanPhase;
    private final EnforcementMode enforcementMode;
    private final Severity blockThreshold;

    public ScanContext(
            String jobFullName,
            String sourceName,
            String targetType,
            FindingLocationType locationType,
            ScanPhase scanPhase,
            EnforcementMode enforcementMode,
            Severity blockThreshold) {
        this.jobFullName = jobFullName == null ? "" : jobFullName;
        this.sourceName = sourceName == null ? "" : sourceName;
        this.targetType = targetType == null ? "" : targetType;
        this.locationType = locationType;
        this.scanPhase = scanPhase;
        this.enforcementMode = enforcementMode;
        this.blockThreshold = blockThreshold;
    }

    public String getJobFullName() {
        return jobFullName;
    }

    public String getSourceName() {
        return sourceName;
    }

    public String getTargetType() {
        return targetType;
    }

    public FindingLocationType getLocationType() {
        return locationType;
    }

    public ScanPhase getScanPhase() {
        return scanPhase;
    }

    public EnforcementMode getEnforcementMode() {
        return enforcementMode;
    }

    public Severity getBlockThreshold() {
        return blockThreshold;
    }

    public ScanContext withLocationType(FindingLocationType newLocationType) {
        return new ScanContext(
                jobFullName, sourceName, targetType, newLocationType, scanPhase, enforcementMode, blockThreshold);
    }
}
