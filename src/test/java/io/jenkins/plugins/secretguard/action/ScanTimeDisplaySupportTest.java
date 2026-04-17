package io.jenkins.plugins.secretguard.action;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Instant;
import java.time.ZoneId;
import org.junit.jupiter.api.Test;

class ScanTimeDisplaySupportTest {
    @Test
    void formatsPastRelativeTime() {
        Instant scannedAt = Instant.parse("2026-04-17T12:00:00Z");
        Instant reference = Instant.parse("2026-04-17T12:05:00Z");

        assertEquals("5 min 0 sec ago", ScanTimeDisplaySupport.formatRelativeTime(scannedAt, reference));
    }

    @Test
    void formatsFutureRelativeTime() {
        Instant scannedAt = Instant.parse("2026-04-17T12:05:00Z");
        Instant reference = Instant.parse("2026-04-17T12:00:00Z");

        assertEquals("in 5 min 0 sec", ScanTimeDisplaySupport.formatRelativeTime(scannedAt, reference));
    }

    @Test
    void formatsVeryRecentTimeAsJustNow() {
        Instant scannedAt = Instant.parse("2026-04-17T12:00:00Z");
        Instant reference = Instant.parse("2026-04-17T12:00:00.500Z");

        assertEquals("just now", ScanTimeDisplaySupport.formatRelativeTime(scannedAt, reference));
    }

    @Test
    void formatsAbsoluteTimeInProvidedZone() {
        Instant scannedAt = Instant.parse("2026-04-17T12:07:26.198Z");

        assertEquals(
                "2026-04-17 20:07:26",
                ScanTimeDisplaySupport.formatAbsoluteTime(scannedAt, ZoneId.of("Asia/Shanghai")));
    }
}
