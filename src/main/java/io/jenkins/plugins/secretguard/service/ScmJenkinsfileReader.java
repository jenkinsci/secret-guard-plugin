package io.jenkins.plugins.secretguard.service;

import hudson.model.Item;
import hudson.scm.SCM;
import hudson.util.XStream2;
import io.jenkins.plugins.secretguard.model.FindingLocationType;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.scm.api.SCMFile;
import jenkins.scm.api.SCMFileSystem;

public class ScmJenkinsfileReader {
    private static final Logger LOGGER = Logger.getLogger(ScmJenkinsfileReader.class.getName());
    private static final String LOG_PREFIX = "[Secret Guard][SCM Read] ";
    private static final String DEFAULT_SCRIPT_PATH = "Jenkinsfile";
    private static final String GIT_SCM_CLASS = "hudson.plugins.git.GitSCM";
    private static final XStream2 XSTREAM = new XStream2();

    public PipelineSourceResolution read(Item item, SCM scm, String scriptPath) {
        if (item == null || scm == null) {
            return PipelineSourceResolution.none();
        }
        String normalizedPath = normalizeScriptPath(scriptPath);
        try (SCMFileSystem fileSystem = openFileSystem(item, scm)) {
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

    private SCMFileSystem openFileSystem(Item item, SCM scm) throws IOException, InterruptedException {
        SCMFileSystem fileSystem = SCMFileSystem.of(item, scm);
        if (fileSystem != null) {
            return fileSystem;
        }
        Optional<GitNormalizationResult> normalizedScm = normalizeGitScmForLightweight(scm);
        if (normalizedScm.isEmpty()) {
            return null;
        }
        LOGGER.log(
                Level.FINE,
                LOG_PREFIX + "Retrying lightweight SCM Jenkinsfile access for {0} with normalized Git branch spec {1}",
                new Object[] {item.getFullName(), normalizedScm.orElseThrow().normalizedBranch()});
        return SCMFileSystem.of(item, normalizedScm.orElseThrow().scm());
    }

    private Optional<GitNormalizationResult> normalizeGitScmForLightweight(SCM scm) {
        if (!GIT_SCM_CLASS.equals(scm.getClass().getName())) {
            return Optional.empty();
        }
        try {
            List<?> branches = readBranches(scm);
            if (branches.size() != 1) {
                return Optional.empty();
            }
            String branchName = readBranchName(branches.get(0));
            String normalizedBranch = normalizeGitBranchSpec(branchName);
            if (normalizedBranch.equals(branchName)) {
                return Optional.empty();
            }
            return rebuildGitScmWithNormalizedBranch(scm, branchName, normalizedBranch)
                    .map(normalizedScm -> new GitNormalizationResult(normalizedScm, normalizedBranch));
        } catch (ReflectiveOperationException | RuntimeException e) {
            LOGGER.log(Level.FINE, LOG_PREFIX + "Unable to normalize Git branch spec for lightweight access", e);
            return Optional.empty();
        }
    }

    @SuppressWarnings("unchecked")
    private List<?> readBranches(SCM scm) throws ReflectiveOperationException {
        Method getBranches = scm.getClass().getMethod("getBranches");
        Object branches = getBranches.invoke(scm);
        return branches instanceof List<?> list ? list : List.of();
    }

    private String readBranchName(Object branchSpec) throws ReflectiveOperationException {
        Method getName = branchSpec.getClass().getMethod("getName");
        Object branchName = getName.invoke(branchSpec);
        return branchName instanceof String value ? value : "";
    }

    private String normalizeGitBranchSpec(String branchName) {
        if (branchName == null) {
            return "";
        }
        String normalized = branchName.trim();
        if (normalized.isEmpty()
                || normalized.startsWith("refs/heads/")
                || normalized.startsWith("refs/tags/")
                || normalized.startsWith("*/")
                || normalized.contains("*")
                || normalized.contains("?")
                || normalized.contains("$")
                || normalized.contains("${")
                || normalized.contains("@{")) {
            return normalized;
        }
        return normalized.contains("/") ? "refs/heads/" + normalized : normalized;
    }

    private Optional<SCM> rebuildGitScmWithNormalizedBranch(SCM scm, String originalBranch, String normalizedBranch) {
        try {
            Object rebuilt = XSTREAM.fromXML(XSTREAM.toXML(scm));
            if (!(rebuilt instanceof SCM normalizedScm)) {
                return Optional.empty();
            }
            List<?> branchSpecs = readBranches(normalizedScm);
            for (Object branchSpec : branchSpecs) {
                String currentName = readBranchName(branchSpec).trim();
                if (!originalBranch.equals(currentName)) {
                    continue;
                }
                updateBranchName(branchSpec, normalizedBranch);
                return Optional.of(normalizedScm);
            }
        } catch (ReflectiveOperationException | RuntimeException e) {
            LOGGER.log(Level.FINE, LOG_PREFIX + "Unable to rebuild Git SCM with normalized branch spec", e);
        }
        return Optional.empty();
    }

    private void updateBranchName(Object branchSpec, String normalizedBranch) throws ReflectiveOperationException {
        Field nameField = findField(branchSpec.getClass(), "name");
        if (nameField == null) {
            throw new NoSuchFieldException("name");
        }
        nameField.setAccessible(true);
        nameField.set(branchSpec, normalizedBranch);
    }

    private Field findField(Class<?> type, String name) {
        Class<?> current = type;
        while (current != null) {
            try {
                return current.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {
                current = current.getSuperclass();
            }
        }
        return null;
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

    private record GitNormalizationResult(SCM scm, String normalizedBranch) {}
}
