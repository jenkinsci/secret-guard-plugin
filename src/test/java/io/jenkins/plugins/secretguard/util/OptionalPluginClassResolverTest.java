package io.jenkins.plugins.secretguard.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;
import org.junit.jupiter.api.Test;

class OptionalPluginClassResolverTest {
    @Test
    void fallsBackToSecondaryClassLoaderWhenPrimaryCannotLoadClass() {
        ClassLoader empty = new ClassLoader(null) {};

        Optional<Class<?>> resolved = OptionalPluginClassResolver.resolve(
                String.class.getName(), empty, getClass().getClassLoader());

        assertTrue(resolved.isPresent());
        assertEquals(String.class, resolved.orElseThrow());
    }

    @Test
    void returnsEmptyWhenClassIsMissingEverywhere() {
        ClassLoader empty = new ClassLoader(null) {};

        Optional<Class<?>> resolved = OptionalPluginClassResolver.resolve(
                "no.such.Type", empty, getClass().getClassLoader());

        assertTrue(resolved.isEmpty());
    }
}
