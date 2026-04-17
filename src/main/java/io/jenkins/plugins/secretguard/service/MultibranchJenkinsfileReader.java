package io.jenkins.plugins.secretguard.service;

import io.jenkins.plugins.secretguard.model.FindingLocationType;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.scm.api.SCMFile;
import jenkins.scm.api.SCMFileSystem;

public class MultibranchJenkinsfileReader {
    private static final Logger LOGGER = Logger.getLogger(MultibranchJenkinsfileReader.class.getName());
    private static final String LOG_PREFIX = "[Secret Guard][SCM Read][Multibranch] ";
    private static final String DEFAULT_SCRIPT_PATH = "Jenkinsfile";

    public PipelineSourceResolution read(MultibranchContext context) {
        if (context == null || context.getSource() == null || context.getHead() == null) {
            return PipelineSourceResolution.none();
        }
        String normalizedPath = normalizeScriptPath(context.getScriptPath());
        try (SCMFileSystem fileSystem = context.getRevision() == null
                ? SCMFileSystem.of(context.getSource(), context.getHead())
                : SCMFileSystem.of(context.getSource(), context.getHead(), context.getRevision())) {
            if (fileSystem == null) {
                LOGGER.log(
                        Level.FINE,
                        LOG_PREFIX + "SCM source does not support lightweight multibranch Jenkinsfile access");
                return unavailable(normalizedPath, "lightweight SCM access is unavailable");
            }
            SCMFile jenkinsfile = fileSystem.getRoot().child(normalizedPath);
            if (!jenkinsfile.isFile()) {
                LOGGER.log(Level.FINE, LOG_PREFIX + "Multibranch Jenkinsfile {0} was not found", normalizedPath);
                return unavailable(normalizedPath, "the Jenkinsfile was not found");
            }
            String content = jenkinsfile.contentAsString();
            if (content == null || content.isBlank()) {
                LOGGER.log(Level.FINE, LOG_PREFIX + "Multibranch Jenkinsfile {0} is empty", normalizedPath);
                return unavailable(normalizedPath, "the Jenkinsfile is empty");
            }
            LOGGER.log(
                    Level.FINE,
                    LOG_PREFIX + "Read multibranch Jenkinsfile {0} via lightweight access; revisionPresent={1}",
                    new Object[] {normalizedPath, context.getRevision() != null});
            return PipelineSourceResolution.found(new PipelineScriptSource(
                    "Jenkinsfile from Multibranch SCM: " + normalizedPath, content, FindingLocationType.JENKINSFILE));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.log(Level.FINE, LOG_PREFIX + "Interrupted while reading multibranch Jenkinsfile", e);
        } catch (IOException | RuntimeException e) {
            LOGGER.log(Level.FINE, LOG_PREFIX + "Unable to read multibranch Jenkinsfile", e);
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
        return PipelineSourceResolution.unavailable("Secret Guard could not read multibranch Jenkinsfile `"
                + normalizedPath + "` via lightweight access (" + reason + "), so that source was skipped.");
    }
}
