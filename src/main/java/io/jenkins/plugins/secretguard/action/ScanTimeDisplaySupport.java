package io.jenkins.plugins.secretguard.action;

import hudson.Util;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

public interface ScanTimeDisplaySupport {
    DateTimeFormatter ABSOLUTE_TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss", Locale.ENGLISH);

    default String getDisplayTime(Instant scannedAt) {
        return formatRelativeTime(scannedAt, Instant.now());
    }

    default String getDisplayTimeTitle(Instant scannedAt) {
        return formatAbsoluteTime(scannedAt, ZoneId.systemDefault());
    }

    static String formatRelativeTime(Instant scannedAt, Instant referenceTime) {
        if (scannedAt == null) {
            return "";
        }
        Duration duration = Duration.between(scannedAt, referenceTime == null ? Instant.now() : referenceTime);
        long millis = Math.abs(duration.toMillis());
        if (millis < 1000) {
            return "just now";
        }
        String timeSpan = Util.getTimeSpanString(millis);
        return duration.isNegative() ? "in " + timeSpan : timeSpan + " ago";
    }

    static String formatAbsoluteTime(Instant scannedAt, ZoneId zoneId) {
        if (scannedAt == null) {
            return "";
        }
        return ABSOLUTE_TIME_FORMATTER
                .withZone(zoneId == null ? ZoneId.systemDefault() : zoneId)
                .format(scannedAt);
    }
}
