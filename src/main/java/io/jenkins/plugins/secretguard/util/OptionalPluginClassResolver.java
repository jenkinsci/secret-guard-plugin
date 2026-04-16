package io.jenkins.plugins.secretguard.util;

import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;

public final class OptionalPluginClassResolver {
    private static final Logger LOGGER = Logger.getLogger(OptionalPluginClassResolver.class.getName());
    private static final String LOG_PREFIX = "[Secret Guard][ClassLoader] ";

    private OptionalPluginClassResolver() {}

    public static Optional<Class<?>> resolve(String className, Class<?> fallbackAnchor) {
        if (className == null || className.isBlank()) {
            return Optional.empty();
        }
        ClassLoader primary = null;
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins != null && jenkins.getPluginManager() != null) {
            primary = jenkins.getPluginManager().uberClassLoader;
        }
        ClassLoader fallback = fallbackAnchor == null ? null : fallbackAnchor.getClassLoader();
        return resolve(className, primary, fallback);
    }

    static Optional<Class<?>> resolve(String className, ClassLoader primary, ClassLoader fallback) {
        Optional<Class<?>> resolved = load(className, primary);
        if (resolved.isPresent()) {
            LOGGER.log(
                    Level.FINE, LOG_PREFIX + "Resolved optional plugin class {0} from primary class loader", className);
            return resolved;
        }
        resolved = load(className, fallback);
        if (resolved.isPresent()) {
            LOGGER.log(
                    Level.FINE,
                    LOG_PREFIX + "Resolved optional plugin class {0} from fallback class loader",
                    className);
        } else {
            LOGGER.log(Level.FINE, LOG_PREFIX + "Optional plugin class {0} is not available", className);
        }
        return resolved;
    }

    private static Optional<Class<?>> load(String className, ClassLoader classLoader) {
        if (classLoader == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(Class.forName(className, false, classLoader));
        } catch (ClassNotFoundException e) {
            return Optional.empty();
        }
    }
}
