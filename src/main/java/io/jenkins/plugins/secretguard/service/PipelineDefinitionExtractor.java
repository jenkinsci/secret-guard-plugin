package io.jenkins.plugins.secretguard.service;

import hudson.model.Job;
import hudson.scm.SCM;
import io.jenkins.plugins.secretguard.model.FindingLocationType;
import java.lang.reflect.Method;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

public class PipelineDefinitionExtractor {
    private static final Logger LOGGER = Logger.getLogger(PipelineDefinitionExtractor.class.getName());
    private static final String DEFAULT_SCRIPT_PATH = "Jenkinsfile";

    private final ScmJenkinsfileReader scmJenkinsfileReader;

    public PipelineDefinitionExtractor() {
        this(new ScmJenkinsfileReader());
    }

    PipelineDefinitionExtractor(ScmJenkinsfileReader scmJenkinsfileReader) {
        this.scmJenkinsfileReader = scmJenkinsfileReader;
    }

    public Optional<PipelineScriptSource> extractScript(Job<?, ?> job) {
        Optional<Object> definition = definition(job);
        if (definition.isEmpty()) {
            return Optional.empty();
        }
        Optional<PipelineScriptSource> inlineScript = extractInlineScript(definition.get());
        if (inlineScript.isPresent()) {
            return inlineScript;
        }
        return extractScmScript(job, definition.get());
    }

    public Optional<PipelineScriptSource> extractScmScript(Job<?, ?> job) {
        Optional<Object> definition = definition(job);
        return definition.flatMap(value -> extractScmScript(job, value));
    }

    private Optional<Object> definition(Job<?, ?> job) {
        if (job == null) {
            return Optional.empty();
        }
        try {
            Method getDefinition = job.getClass().getMethod("getDefinition");
            return Optional.ofNullable(getDefinition.invoke(job));
        } catch (ReflectiveOperationException | SecurityException e) {
            LOGGER.log(Level.FINE, "Job does not expose a Pipeline definition: " + job.getFullName(), e);
            return Optional.empty();
        }
    }

    private Optional<PipelineScriptSource> extractInlineScript(Object definition) {
        try {
            Method getScript = definition.getClass().getMethod("getScript");
            Object script = getScript.invoke(definition);
            if (script instanceof String scriptText && !scriptText.isBlank()) {
                return Optional.of(
                        new PipelineScriptSource("Pipeline script", scriptText, FindingLocationType.PIPELINE_SCRIPT));
            }
        } catch (ReflectiveOperationException | SecurityException ignored) {
            return Optional.empty();
        }
        return Optional.empty();
    }

    private Optional<PipelineScriptSource> extractScmScript(Job<?, ?> job, Object definition) {
        try {
            Method getScm = definition.getClass().getMethod("getScm");
            Object scm = getScm.invoke(definition);
            if (!(scm instanceof SCM jenkinsScm)) {
                return Optional.empty();
            }
            return scmJenkinsfileReader.read(job, jenkinsScm, extractScriptPath(definition));
        } catch (ReflectiveOperationException | SecurityException ignored) {
            return Optional.empty();
        }
    }

    private String extractScriptPath(Object definition) {
        try {
            Method getScriptPath = definition.getClass().getMethod("getScriptPath");
            Object scriptPath = getScriptPath.invoke(definition);
            if (scriptPath instanceof String value && !value.isBlank()) {
                return value;
            }
        } catch (ReflectiveOperationException | SecurityException ignored) {
            return DEFAULT_SCRIPT_PATH;
        }
        return DEFAULT_SCRIPT_PATH;
    }
}
