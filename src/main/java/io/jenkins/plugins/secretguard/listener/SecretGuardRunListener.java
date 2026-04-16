package io.jenkins.plugins.secretguard.listener;

import hudson.Extension;
import hudson.model.Executor;
import hudson.model.Result;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.model.listeners.RunListener;
import io.jenkins.plugins.secretguard.action.SecretGuardRunAction;
import io.jenkins.plugins.secretguard.config.SecretGuardGlobalConfiguration;
import io.jenkins.plugins.secretguard.model.EnforcementMode;
import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.ScanPhase;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.scan.PipelineScriptScanner;
import io.jenkins.plugins.secretguard.service.PipelineDefinitionExtractor;
import io.jenkins.plugins.secretguard.service.PipelineScriptSource;
import io.jenkins.plugins.secretguard.service.SecretScanService;
import java.util.Optional;

@Extension
public class SecretGuardRunListener extends RunListener<Run<?, ?>> {
    private final SecretScanService scanService = new SecretScanService();
    private final PipelineScriptScanner pipelineScriptScanner = new PipelineScriptScanner();
    private final PipelineDefinitionExtractor pipelineDefinitionExtractor = new PipelineDefinitionExtractor();

    @Override
    public void onStarted(Run<?, ?> run, TaskListener listener) {
        Optional<PipelineScriptSource> script = pipelineDefinitionExtractor.extractScript(run.getParent());
        if (script.isEmpty()) {
            return;
        }
        PipelineScriptSource source = script.get();
        SecretGuardGlobalConfiguration configuration = SecretGuardGlobalConfiguration.get();
        ScanContext context = new ScanContext(
                run.getParent().getFullName(),
                source.getSourceName(),
                run.getParent().getClass().getSimpleName(),
                source.getLocationType(),
                ScanPhase.BUILD,
                configuration == null ? EnforcementMode.AUDIT : configuration.getEnforcementMode(),
                configuration == null ? Severity.HIGH : configuration.getBlockThreshold());
        SecretScanResult result = scanService.scan(pipelineScriptScanner, context, source.getContent());
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
}
