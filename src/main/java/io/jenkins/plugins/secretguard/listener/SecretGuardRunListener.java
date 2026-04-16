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
import java.util.logging.Level;
import java.util.logging.Logger;

@Extension
public class SecretGuardRunListener extends RunListener<Run<?, ?>> {
    private static final Logger LOGGER = Logger.getLogger(SecretGuardRunListener.class.getName());
    private static final String LOG_PREFIX = "[Secret Guard][Build Scan] ";

    private final SecretScanService scanService = new SecretScanService();
    private final PipelineScriptScanner pipelineScriptScanner = new PipelineScriptScanner();
    private final PipelineDefinitionExtractor pipelineDefinitionExtractor = new PipelineDefinitionExtractor();

    @Override
    public void onStarted(Run<?, ?> run, TaskListener listener) {
        Optional<PipelineScriptSource> script = pipelineDefinitionExtractor.extractScript(run.getParent(), run);
        if (script.isEmpty()) {
            LOGGER.log(
                    Level.FINE,
                    LOG_PREFIX + "No Pipeline script source was resolved at build start for {0}",
                    run.getParent().getFullName());
            return;
        }
        PipelineScriptSource source = script.get();
        LOGGER.log(Level.FINE, LOG_PREFIX + "Starting Secret Guard build scan for {0} from source {1}", new Object[] {
            run.getParent().getFullName(), source.getSourceName()
        });
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
        LOGGER.log(
                Level.FINE,
                LOG_PREFIX
                        + "Completed Secret Guard build scan for {0}: findings={1}, blocked={2}, highestSeverity={3}",
                new Object[] {
                    run.getParent().getFullName(),
                    result.getFindings().size(),
                    result.isBlocked(),
                    result.getHighestSeverity()
                });
        if (!result.hasFindings()) {
            return;
        }
        listener.getLogger()
                .println("[Secret Guard] Found " + result.getFindings().size() + " potential secret risk(s).");
        EnforcementMode mode = configuration == null ? EnforcementMode.AUDIT : configuration.getEnforcementMode();
        if (mode == EnforcementMode.WARN) {
            run.setResult(Result.UNSTABLE);
            listener.getLogger().println("[Secret Guard] Build marked UNSTABLE by Warn mode.");
            LOGGER.log(
                    Level.FINE,
                    LOG_PREFIX + "Build {0} marked UNSTABLE by Secret Guard Warn mode",
                    run.getFullDisplayName());
        } else if (result.isBlocked()) {
            run.setResult(Result.FAILURE);
            listener.error("[Secret Guard] Build blocked because high severity secret risks were found.");
            LOGGER.log(Level.FINE, LOG_PREFIX + "Build {0} blocked by Secret Guard", run.getFullDisplayName());
            Executor executor = Executor.currentExecutor();
            if (executor != null) {
                executor.interrupt(Result.FAILURE);
            }
        }
    }
}
