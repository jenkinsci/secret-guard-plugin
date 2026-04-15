package io.jenkins.plugins.secretguard.listener;

import hudson.Extension;
import hudson.model.Executor;
import hudson.model.Job;
import hudson.model.Result;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.model.listeners.RunListener;
import io.jenkins.plugins.secretguard.action.SecretGuardRunAction;
import io.jenkins.plugins.secretguard.config.SecretGuardGlobalConfiguration;
import io.jenkins.plugins.secretguard.model.EnforcementMode;
import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.ScanPhase;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.scan.PipelineScriptScanner;
import io.jenkins.plugins.secretguard.service.SecretScanService;
import java.lang.reflect.Method;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

@Extension
public class SecretGuardRunListener extends RunListener<Run<?, ?>> {
    private static final Logger LOGGER = Logger.getLogger(SecretGuardRunListener.class.getName());

    private final SecretScanService scanService = new SecretScanService();
    private final PipelineScriptScanner pipelineScriptScanner = new PipelineScriptScanner();

    @Override
    public void onStarted(Run<?, ?> run, TaskListener listener) {
        Optional<String> script = extractPipelineScript(run.getParent());
        if (script.isEmpty()) {
            return;
        }
        SecretGuardGlobalConfiguration configuration = SecretGuardGlobalConfiguration.get();
        ScanContext context = new ScanContext(
                run.getParent().getFullName(),
                "Pipeline script",
                run.getParent().getClass().getSimpleName(),
                FindingLocationType.PIPELINE_SCRIPT,
                ScanPhase.BUILD,
                configuration == null ? EnforcementMode.AUDIT : configuration.getEnforcementMode(),
                configuration == null ? Severity.HIGH : configuration.getBlockThreshold());
        SecretScanResult result = scanService.scan(pipelineScriptScanner, context, script.get());
        run.addAction(new SecretGuardRunAction(result));
        if (!result.hasFindings()) {
            return;
        }
        listener.getLogger()
                .println("[Secret Guard] Found " + result.getFindings().size() + " potential secret risk(s).");
        EnforcementMode mode = configuration == null ? EnforcementMode.AUDIT : configuration.getEnforcementMode();
        if (mode == EnforcementMode.WARN) {
            run.setResult(Result.UNSTABLE);
            listener.getLogger().println("[Secret Guard] Build marked UNSTABLE by Warn mode.");
        } else if (result.isBlocked()) {
            run.setResult(Result.FAILURE);
            listener.error("[Secret Guard] Build blocked because high severity secret risks were found.");
            Executor executor = Executor.currentExecutor();
            if (executor != null) {
                executor.interrupt(Result.FAILURE);
            }
        }
    }

    private Optional<String> extractPipelineScript(Job<?, ?> job) {
        try {
            Method getDefinition = job.getClass().getMethod("getDefinition");
            Object definition = getDefinition.invoke(job);
            if (definition == null) {
                return Optional.empty();
            }
            Method getScript = definition.getClass().getMethod("getScript");
            Object script = getScript.invoke(definition);
            if (script instanceof String scriptText && !scriptText.isBlank()) {
                return Optional.of(scriptText);
            }
        } catch (ReflectiveOperationException | SecurityException e) {
            LOGGER.log(Level.FINE, "Job does not expose an inline Pipeline script: " + job.getFullName(), e);
        }
        return Optional.empty();
    }
}
