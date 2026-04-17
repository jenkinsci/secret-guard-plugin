package io.jenkins.plugins.secretguard.testutil;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public final class TestResourceLoader {
    private TestResourceLoader() {}

    public static String load(String resourcePath) {
        try (InputStream inputStream = TestResourceLoader.class.getResourceAsStream(resourcePath)) {
            assertNotNull(inputStream, () -> "Missing test resource: " + resourcePath);
            return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException exception) {
            throw new IllegalStateException("Failed to load test resource: " + resourcePath, exception);
        }
    }
}
