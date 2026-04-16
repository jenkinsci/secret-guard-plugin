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
import java.util.Optional;

public class ManualJobScanService {
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
        SecretGuardGlobalConfiguration configuration = SecretGuardGlobalConfiguration.get();
        ScanContext context = new ScanContext(
                job.getFullName(),
                "config.xml",
                job.getClass().getSimpleName(),
                FindingLocationType.CONFIG_XML,
                ScanPhase.MANUAL,
                EnforcementMode.AUDIT,
                configuration == null ? Severity.HIGH : configuration.getBlockThreshold());
        List<SecretFinding> findings =
                new ArrayList<>(configXmlScanner.scan(context, job.getConfigFile().asString()).getFindings());
        Optional<PipelineScriptSource> scmScript = pipelineDefinitionExtractor.extractScmScript(job);
        if (scmScript.isPresent()) {
            PipelineScriptSource source = scmScript.get();
            ScanContext scmContext = new ScanContext(
                    job.getFullName(),
                    source.getSourceName(),
                    job.getClass().getSimpleName(),
                    source.getLocationType(),
                    ScanPhase.MANUAL,
                    EnforcementMode.AUDIT,
                    configuration == null ? Severity.HIGH : configuration.getBlockThreshold());
            findings.addAll(pipelineScriptScanner.scan(scmContext, source.getContent()).getFindings());
        }
        return scanService.process(context, findings);
    }
}
