package io.jenkins.plugins.secretguard.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class SecretMaskerTest {
    @Test
    void masksJwtAndUrlCredentials() {
        assertEquals("eyJhbG.***.nature", SecretMasker.mask("eyJhbGciOiJIUzI1NiJ9.payload.signature"));
        assertEquals("https://***:***@example.com/api", SecretMasker.mask("https://user:password@example.com/api"));
    }

    @Test
    void masksPemPrivateKey() {
        String masked = SecretMasker.mask("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----");
        assertTrue(masked.contains("BEGIN PRIVATE KEY"));
        assertTrue(masked.contains("END PRIVATE KEY"));
    }
}
