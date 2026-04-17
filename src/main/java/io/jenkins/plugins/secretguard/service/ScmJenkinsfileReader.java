package io.jenkins.plugins.secretguard.service;

import hudson.model.Item;
import hudson.scm.SCM;
import io.jenkins.plugins.secretguard.model.FindingLocationType;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.scm.api.SCMFile;
import jenkins.scm.api.SCMFileSystem;

public class ScmJenkinsfileReader {
    private static final Logger LOGGER = Logger.getLogger(ScmJenkinsfileReader.class.getName());
    private static final String LOG_PREFIX = "[Secret Guard][SCM Read] ";
    private static final String DEFAULT_SCRIPT_PATH = "Jenkinsfile";

    public PipelineSourceResolution read(Item item, SCM scm, String scriptPath) {
        if (item == null || scm == null) {
            return PipelineSourceResolution.none();
        }
        String normalizedPath = normalizeScriptPath(scriptPath);
        try (SCMFileSystem fileSystem = SCMFileSystem.of(item, scm)) {
            if (fileSystem == null) {
                LOGGER.log(
                        Level.FINE,
                        LOG_PREFIX + "SCM does not support lightweight Jenkinsfile access for {0}",
                        item.getFullName());
                return unavailable(normalizedPath, "lightweight SCM access is unavailable");
            }
            SCMFile jenkinsfile = fileSystem.getRoot().child(normalizedPath);
            if (!jenkinsfile.isFile()) {
                LOGGER.log(Level.FINE, LOG_PREFIX + "SCM Jenkinsfile {0} was not found for {1}", new Object[] {
                    normalizedPath, item.getFullName()
                });
                return unavailable(normalizedPath, "the Jenkinsfile was not found");
            }
            String content = jenkinsfile.contentAsString();
            if (content == null || content.isBlank()) {
                LOGGER.log(Level.FINE, LOG_PREFIX + "SCM Jenkinsfile {0} for {1} is empty", new Object[] {
                    normalizedPath, item.getFullName()
                });
                return unavailable(normalizedPath, "the Jenkinsfile is empty");
            }
            LOGGER.log(
                    Level.FINE,
                    LOG_PREFIX + "Read SCM Jenkinsfile {0} for {1} via lightweight access",
                    new Object[] {normalizedPath, item.getFullName()});
            return PipelineSourceResolution.found(new PipelineScriptSource(
                    "Jenkinsfile from SCM: " + normalizedPath, content, FindingLocationType.JENKINSFILE));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.log(
                    Level.FINE, LOG_PREFIX + "Interrupted while reading SCM Jenkinsfile for " + item.getFullName(), e);
        } catch (IOException | RuntimeException e) {
            LOGGER.log(Level.FINE, LOG_PREFIX + "Unable to read SCM Jenkinsfile for " + item.getFullName(), e);
        }
        return unavailable(normalizedPath, "the lightweight SCM read failed");
    }

    private String normalizeScriptPath(String scriptPath) {
        if (scriptPath == null || scriptPath.isBlank()) {
            return DEFAULT_SCRIPT_PATH;
        }
        String normalized = scriptPath.trim();
        while (normalized.startsWith("/")) {
            normalized = normalized.substring(1);
        }
        return normalized.isBlank() ? DEFAULT_SCRIPT_PATH : normalized;
    }

    private PipelineSourceResolution unavailable(String normalizedPath, String reason) {
        return PipelineSourceResolution.unavailable("Secret Guard could not read SCM Jenkinsfile `" + normalizedPath
                + "` via lightweight access (" + reason + "), so that source was skipped.");
    }
}
