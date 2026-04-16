package io.jenkins.plugins.secretguard.service;

import hudson.model.Job;
import hudson.model.Run;
import hudson.scm.SCM;
import io.jenkins.plugins.secretguard.model.FindingLocationType;
import java.lang.reflect.Method;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

public class PipelineDefinitionExtractor {
    private static final Logger LOGGER = Logger.getLogger(PipelineDefinitionExtractor.class.getName());
    private static final String LOG_PREFIX = "[Secret Guard][Pipeline Source] ";
    private static final String DEFAULT_SCRIPT_PATH = "Jenkinsfile";

    private final ScmJenkinsfileReader scmJenkinsfileReader;
    private final MultibranchContextResolver multibranchContextResolver;
    private final MultibranchJenkinsfileReader multibranchJenkinsfileReader;

    public PipelineDefinitionExtractor() {
        this(new ScmJenkinsfileReader(), new MultibranchContextResolver(), new MultibranchJenkinsfileReader());
    }

    PipelineDefinitionExtractor(
            ScmJenkinsfileReader scmJenkinsfileReader,
            MultibranchContextResolver multibranchContextResolver,
            MultibranchJenkinsfileReader multibranchJenkinsfileReader) {
        this.scmJenkinsfileReader = scmJenkinsfileReader;
        this.multibranchContextResolver = multibranchContextResolver;
        this.multibranchJenkinsfileReader = multibranchJenkinsfileReader;
    }

    public Optional<PipelineScriptSource> extractScript(Job<?, ?> job) {
        return extractScript(job, null);
    }

    public Optional<PipelineScriptSource> extractScript(Job<?, ?> job, Run<?, ?> run) {
        if (job == null) {
            LOGGER.fine(LOG_PREFIX + "Skipping Pipeline definition extraction because job is null");
            return Optional.empty();
        }
        Optional<Object> definition = definition(job);
        if (definition.isPresent()) {
            Optional<PipelineScriptSource> inlineScript = extractInlineScript(definition.get());
            if (inlineScript.isPresent()) {
                LOGGER.log(Level.FINE, LOG_PREFIX + "Using inline Pipeline script for {0}", job.getFullName());
                return inlineScript;
            }
            Optional<PipelineScriptSource> scmScript = extractScmScript(job, definition.get());
            if (scmScript.isPresent()) {
                LOGGER.log(Level.FINE, LOG_PREFIX + "Using SCM-backed Jenkinsfile source {0} for {1}", new Object[] {
                    scmScript.get().getSourceName(), job.getFullName()
                });
                return scmScript;
            }
        }
        Optional<PipelineScriptSource> multibranchScript = extractMultibranchScript(job, run);
        if (multibranchScript.isPresent()) {
            LOGGER.log(Level.FINE, LOG_PREFIX + "Using multibranch Jenkinsfile source {0} for {1}", new Object[] {
                multibranchScript.get().getSourceName(), job.getFullName()
            });
        } else {
            LOGGER.log(Level.FINE, LOG_PREFIX + "No Pipeline script source resolved for {0}", job.getFullName());
        }
        return multibranchScript;
    }

    public Optional<PipelineScriptSource> extractScmScript(Job<?, ?> job) {
        return extractScmScript(job, null);
    }

    public Optional<PipelineScriptSource> extractScmScript(Job<?, ?> job, Run<?, ?> run) {
        Optional<Object> definition = definition(job);
        Optional<PipelineScriptSource> scmScript = definition.flatMap(value -> extractScmScript(job, value));
        return scmScript.or(() -> extractMultibranchScript(job, run));
    }

    private Optional<Object> definition(Job<?, ?> job) {
        if (job == null) {
            return Optional.empty();
        }
        try {
            Method getDefinition = job.getClass().getMethod("getDefinition");
            return Optional.ofNullable(getDefinition.invoke(job));
        } catch (ReflectiveOperationException | SecurityException e) {
            LOGGER.log(Level.FINE, LOG_PREFIX + "Job does not expose a Pipeline definition: " + job.getFullName(), e);
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
                LOGGER.log(
                        Level.FINEST,
                        LOG_PREFIX + "Pipeline definition for {0} does not expose SCM content",
                        job.getFullName());
                return Optional.empty();
            }
            String scriptPath = extractScriptPath(definition);
            LOGGER.log(
                    Level.FINE,
                    LOG_PREFIX + "Attempting SCM Jenkinsfile read for {0} with scriptPath {1}",
                    new Object[] {job.getFullName(), scriptPath});
            return scmJenkinsfileReader.read(job, jenkinsScm, scriptPath);
        } catch (ReflectiveOperationException | SecurityException ignored) {
            return Optional.empty();
        }
    }

    private Optional<PipelineScriptSource> extractMultibranchScript(Job<?, ?> job, Run<?, ?> run) {
        return multibranchContextResolver.resolve(job, run).flatMap(multibranchJenkinsfileReader::read);
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
