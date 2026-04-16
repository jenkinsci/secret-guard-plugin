package io.jenkins.plugins.secretguard.service;

import io.jenkins.plugins.secretguard.model.FindingLocationType;

public class PipelineScriptSource {
    private final String sourceName;
    private final String content;
    private final FindingLocationType locationType;

    public PipelineScriptSource(String sourceName, String content, FindingLocationType locationType) {
        this.sourceName = sourceName == null ? "" : sourceName;
        this.content = content == null ? "" : content;
        this.locationType = locationType == null ? FindingLocationType.PIPELINE_SCRIPT : locationType;
    }

    public String getSourceName() {
        return sourceName;
    }

    public String getContent() {
        return content;
    }

    public FindingLocationType getLocationType() {
        return locationType;
    }
}
