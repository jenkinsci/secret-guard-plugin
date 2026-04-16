package io.jenkins.plugins.secretguard.service;

import hudson.model.Item;
import hudson.scm.SCM;
import io.jenkins.plugins.secretguard.model.FindingLocationType;
import java.io.IOException;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.scm.api.SCMFile;
import jenkins.scm.api.SCMFileSystem;

public class ScmJenkinsfileReader {
    private static final Logger LOGGER = Logger.getLogger(ScmJenkinsfileReader.class.getName());
    private static final String DEFAULT_SCRIPT_PATH = "Jenkinsfile";

    public Optional<PipelineScriptSource> read(Item item, SCM scm, String scriptPath) {
        if (item == null || scm == null) {
            return Optional.empty();
        }
        String normalizedPath = normalizeScriptPath(scriptPath);
        try (SCMFileSystem fileSystem = SCMFileSystem.of(item, scm)) {
            if (fileSystem == null) {
                LOGGER.log(
                        Level.FINE,
                        "SCM does not support lightweight Jenkinsfile access for {0}",
                        item.getFullName());
                return Optional.empty();
            }
            SCMFile jenkinsfile = fileSystem.getRoot().child(normalizedPath);
            if (!jenkinsfile.isFile()) {
                LOGGER.log(
                        Level.FINE,
                        "SCM Jenkinsfile {0} was not found for {1}",
                        new Object[] {normalizedPath, item.getFullName()});
                return Optional.empty();
            }
            String content = jenkinsfile.contentAsString();
            if (content == null || content.isBlank()) {
                return Optional.empty();
            }
            return Optional.of(new PipelineScriptSource(
                    "Jenkinsfile from SCM: " + normalizedPath, content, FindingLocationType.JENKINSFILE));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.log(Level.FINE, "Interrupted while reading SCM Jenkinsfile for " + item.getFullName(), e);
        } catch (IOException | RuntimeException e) {
            LOGGER.log(Level.FINE, "Unable to read SCM Jenkinsfile for " + item.getFullName(), e);
        }
        return Optional.empty();
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
}
