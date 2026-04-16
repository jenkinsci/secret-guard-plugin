package io.jenkins.plugins.secretguard.service;

import hudson.model.Item;
import hudson.model.Job;
import hudson.model.JobProperty;
import hudson.model.Run;
import io.jenkins.plugins.secretguard.util.OptionalPluginClassResolver;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.scm.api.SCMHead;
import jenkins.scm.api.SCMRevision;
import jenkins.scm.api.SCMRevisionAction;
import jenkins.scm.api.SCMSource;
import jenkins.scm.api.SCMSourceOwner;

public class MultibranchContextResolver {
    private static final Logger LOGGER = Logger.getLogger(MultibranchContextResolver.class.getName());
    private static final String LOG_PREFIX = "[Secret Guard][Multibranch] ";
    private static final String BRANCH_JOB_PROPERTY_CLASS =
            "org.jenkinsci.plugins.workflow.multibranch.BranchJobProperty";
    private static final String DEFAULT_SCRIPT_PATH = "Jenkinsfile";

    public Optional<MultibranchContext> resolve(Job<?, ?> job, Run<?, ?> run) {
        if (job == null) {
            LOGGER.fine(LOG_PREFIX + "Skipping multibranch context resolution because job is null");
            return Optional.empty();
        }
        Optional<Object> branch = findBranch(job);
        if (branch.isEmpty()) {
            LOGGER.log(
                    Level.FINE,
                    LOG_PREFIX + "Job {0} is not recognized as a multibranch branch job",
                    job.getFullName());
            return Optional.empty();
        }
        Optional<SCMHead> head = invoke(branch.get(), "getHead", SCMHead.class);
        if (head.isEmpty()) {
            LOGGER.log(Level.FINE, LOG_PREFIX + "Multibranch branch head is unavailable for {0}", job.getFullName());
            return Optional.empty();
        }
        Optional<SCMSourceOwner> owner = findSourceOwner(job);
        if (owner.isEmpty()) {
            LOGGER.log(
                    Level.FINE,
                    LOG_PREFIX + "SCMSourceOwner is unavailable for multibranch job {0}",
                    job.getFullName());
            return Optional.empty();
        }
        Optional<SCMSource> source = findSource(owner.get(), branch.get());
        if (source.isEmpty()) {
            LOGGER.log(
                    Level.FINE,
                    LOG_PREFIX + "SCMSource could not be resolved for multibranch job {0}",
                    job.getFullName());
            return Optional.empty();
        }
        String scriptPath = findScriptPath(owner.get());
        SCMRevision revision = findRevision(source.get(), job, run, owner.get()).orElse(null);
        LOGGER.log(
                Level.FINE,
                LOG_PREFIX
                        + "Resolved multibranch context for {0}: sourceId={1}, head={2}, scriptPath={3}, hasRevision={4}",
                new Object[] {
                    job.getFullName(), source.get().getId(), head.get().getName(), scriptPath, revision != null
                });
        return Optional.of(new MultibranchContext(source.get(), head.get(), revision, scriptPath));
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private Optional<Object> findBranch(Job<?, ?> job) {
        try {
            Optional<Class<?>> propertyClass =
                    OptionalPluginClassResolver.resolve(BRANCH_JOB_PROPERTY_CLASS, getClass());
            if (propertyClass.isEmpty()) {
                LOGGER.log(
                        Level.FINE,
                        LOG_PREFIX + "workflow-multibranch BranchJobProperty is unavailable for {0}",
                        job.getFullName());
                return Optional.empty();
            }
            if (!JobProperty.class.isAssignableFrom(propertyClass.get())) {
                return Optional.empty();
            }
            JobProperty<?> property = job.getProperty((Class) propertyClass.get());
            if (property == null) {
                LOGGER.log(Level.FINEST, LOG_PREFIX + "No BranchJobProperty found on job {0}", job.getFullName());
                return Optional.empty();
            }
            return invoke(property, "getBranch", Object.class);
        } catch (RuntimeException e) {
            LOGGER.log(Level.FINE, LOG_PREFIX + "Unable to resolve multibranch metadata for " + job.getFullName(), e);
        }
        return Optional.empty();
    }

    private Optional<SCMSourceOwner> findSourceOwner(Job<?, ?> job) {
        Object current = job.getParent();
        while (current != null) {
            if (current instanceof SCMSourceOwner owner) {
                return Optional.of(owner);
            }
            if (current instanceof Item item) {
                current = item.getParent();
            } else {
                return Optional.empty();
            }
        }
        return Optional.empty();
    }

    private Optional<SCMSource> findSource(SCMSourceOwner owner, Object branch) {
        String sourceId = invoke(branch, "getSourceId", String.class).orElse(null);
        if (sourceId != null && !sourceId.isBlank()) {
            SCMSource source = owner.getSCMSource(sourceId);
            if (source != null) {
                LOGGER.log(Level.FINEST, LOG_PREFIX + "Resolved multibranch SCMSource by sourceId {0}", sourceId);
                return Optional.of(source);
            }
        }
        List<SCMSource> sources = owner.getSCMSources();
        if (sources.size() == 1) {
            LOGGER.log(Level.FINEST, LOG_PREFIX + "Resolved multibranch SCMSource via single-source fallback");
            return Optional.ofNullable(sources.get(0));
        }
        LOGGER.log(
                Level.FINE,
                LOG_PREFIX + "Unable to resolve SCMSource: sourceId={0}, candidateSources={1}",
                new Object[] {sourceId, sources.size()});
        return Optional.empty();
    }

    private String findScriptPath(SCMSourceOwner owner) {
        try {
            Method getProjectFactory = owner.getClass().getMethod("getProjectFactory");
            Object projectFactory = getProjectFactory.invoke(owner);
            if (projectFactory == null) {
                return DEFAULT_SCRIPT_PATH;
            }
            Optional<String> scriptPath = invoke(projectFactory, "getScriptPath", String.class);
            return normalizeScriptPath(scriptPath.orElse(DEFAULT_SCRIPT_PATH));
        } catch (ReflectiveOperationException | SecurityException e) {
            LOGGER.log(
                    Level.FINE, LOG_PREFIX + "Unable to resolve multibranch script path for " + owner.getFullName(), e);
            return DEFAULT_SCRIPT_PATH;
        }
    }

    private Optional<SCMRevision> findRevision(SCMSource source, Job<?, ?> job, Run<?, ?> run, SCMSourceOwner owner) {
        if (run != null) {
            SCMRevision revision = SCMRevisionAction.getRevision(source, run);
            if (revision != null) {
                return Optional.of(revision);
            }
        }
        SCMRevision jobRevision = SCMRevisionAction.getRevision(source, job);
        if (jobRevision != null) {
            return Optional.of(jobRevision);
        }
        try {
            Method getProjectFactory = owner.getClass().getMethod("getProjectFactory");
            Object projectFactory = getProjectFactory.invoke(owner);
            return invokeProjectFactoryRevision(projectFactory, "getRevision", job)
                    .or(() -> invokeProjectFactoryRevision(projectFactory, "getLastSeenRevision", job));
        } catch (ReflectiveOperationException | SecurityException e) {
            LOGGER.log(Level.FINE, LOG_PREFIX + "Unable to resolve multibranch revision for " + job.getFullName(), e);
            return Optional.empty();
        }
    }

    private Optional<SCMRevision> invokeProjectFactoryRevision(
            Object projectFactory, String methodName, Job<?, ?> job) {
        if (projectFactory == null) {
            return Optional.empty();
        }
        for (Method method : projectFactory.getClass().getMethods()) {
            if (method.getName().equals(methodName) && method.getParameterCount() == 1) {
                try {
                    Object revision = method.invoke(projectFactory, job);
                    if (revision instanceof SCMRevision scmRevision) {
                        return Optional.of(scmRevision);
                    }
                } catch (ReflectiveOperationException | SecurityException e) {
                    LOGGER.log(
                            Level.FINEST,
                            LOG_PREFIX + "Unable to call " + methodName + " on multibranch project factory",
                            e);
                    return Optional.empty();
                }
            }
        }
        return Optional.empty();
    }

    private <T> Optional<T> invoke(Object target, String methodName, Class<T> type) {
        try {
            Method method = target.getClass().getMethod(methodName);
            Object value = method.invoke(target);
            if (type.isInstance(value)) {
                return Optional.of(type.cast(value));
            }
        } catch (ReflectiveOperationException | SecurityException e) {
            LOGGER.log(
                    Level.FINEST,
                    LOG_PREFIX + "Unable to call " + methodName + " on "
                            + target.getClass().getName(),
                    e);
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
