package io.jenkins.plugins.secretguard.service;

import java.util.List;
import java.util.Optional;

public final class PipelineSourceResolution {
    private static final PipelineSourceResolution NONE = new PipelineSourceResolution(null, List.of());

    private final PipelineScriptSource source;
    private final List<String> notes;

    private PipelineSourceResolution(PipelineScriptSource source, List<String> notes) {
        this.source = source;
        this.notes = notes == null ? List.of() : List.copyOf(notes);
    }

    public static PipelineSourceResolution none() {
        return NONE;
    }

    public static PipelineSourceResolution found(PipelineScriptSource source) {
        return new PipelineSourceResolution(source, List.of());
    }

    public static PipelineSourceResolution unavailable(String note) {
        return new PipelineSourceResolution(null, List.of(note));
    }

    public Optional<PipelineScriptSource> getSource() {
        return Optional.ofNullable(source);
    }

    public boolean hasSource() {
        return source != null;
    }

    public List<String> getNotes() {
        return notes;
    }

    public boolean hasNotes() {
        return !notes.isEmpty();
    }
}
