package io.jenkins.plugins.secretguard.service;

import hudson.model.Job;
import io.jenkins.plugins.secretguard.config.SecretGuardGlobalConfiguration;
import io.jenkins.plugins.secretguard.model.EnforcementMode;
import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.ScanPhase;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.scan.ConfigXmlScanner;
import io.jenkins.plugins.secretguard.scan.PipelineScriptScanner;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ManualJobScanService {
    private static final Logger LOGGER = Logger.getLogger(ManualJobScanService.class.getName());
    private static final String LOG_PREFIX = "[Secret Guard][Manual Scan] ";

    private final SecretScanService scanService;
    private final ConfigXmlScanner configXmlScanner;
    private final PipelineScriptScanner pipelineScriptScanner;
    private final PipelineDefinitionExtractor pipelineDefinitionExtractor;

    public ManualJobScanService() {
        this(
                new SecretScanService(),
                new ConfigXmlScanner(),
                new PipelineScriptScanner(),
                new PipelineDefinitionExtractor());
    }

    ManualJobScanService(
            SecretScanService scanService,
            ConfigXmlScanner configXmlScanner,
            PipelineScriptScanner pipelineScriptScanner,
            PipelineDefinitionExtractor pipelineDefinitionExtractor) {
        this.scanService = scanService;
        this.configXmlScanner = configXmlScanner;
        this.pipelineScriptScanner = pipelineScriptScanner;
        this.pipelineDefinitionExtractor = pipelineDefinitionExtractor;
    }

    public SecretScanResult scanJob(Job<?, ?> job) throws IOException {
        LOGGER.log(Level.FINE, LOG_PREFIX + "Starting manual Secret Guard scan for {0}", job.getFullName());
        SecretGuardGlobalConfiguration configuration = SecretGuardGlobalConfiguration.get();
        EnforcementMode enforcementMode =
                configuration == null ? EnforcementMode.AUDIT : configuration.getEnforcementMode();
        Severity blockThreshold = configuration == null ? Severity.HIGH : configuration.getBlockThreshold();
        ScanContext context = new ScanContext(
                job.getFullName(),
                "config.xml",
                job.getClass().getSimpleName(),
                FindingLocationType.CONFIG_XML,
                ScanPhase.MANUAL,
                enforcementMode,
                blockThreshold);
        List<SecretFinding> findings = new ArrayList<>(
                configXmlScanner.scan(context, job.getConfigFile().asString()).getFindings());
        LOGGER.log(Level.FINE, LOG_PREFIX + "Config XML scan for {0} produced {1} finding(s)", new Object[] {
            job.getFullName(), findings.size()
        });
        PipelineSourceResolution scmScript = pipelineDefinitionExtractor.extractScmScript(job);
        if (scmScript.hasSource()) {
            PipelineScriptSource source = scmScript.getSource().orElseThrow();
            LOGGER.log(
                    Level.FINE,
                    LOG_PREFIX + "Manual scan for {0} will also inspect external Pipeline source {1}",
                    new Object[] {job.getFullName(), source.getSourceName()});
            ScanContext scmContext = new ScanContext(
                    job.getFullName(),
                    source.getSourceName(),
                    job.getClass().getSimpleName(),
                    source.getLocationType(),
                    ScanPhase.MANUAL,
                    enforcementMode,
                    blockThreshold);
            findings.addAll(
                    pipelineScriptScanner.scan(scmContext, source.getContent()).getFindings());
        } else {
            LOGGER.log(
                    Level.FINE,
                    LOG_PREFIX + "No external Pipeline source was available for manual scan of {0}",
                    job.getFullName());
        }
        SecretScanResult result = scanService.process(context, findings, scmScript.getNotes());
        LOGGER.log(
                Level.FINE,
                LOG_PREFIX + "Finished manual Secret Guard scan for {0}: findings={1}, highestSeverity={2}",
                new Object[] {job.getFullName(), result.getFindings().size(), result.getHighestSeverity()});
        return result;
    }
}
