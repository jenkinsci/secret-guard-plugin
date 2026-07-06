package io.jenkins.plugins.secretguard.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jenkins.plugins.secretguard.model.Severity;
import java.util.List;
import org.junit.jupiter.api.Test;

class CustomPatternRuleEntryTest {
    @Test
    void parseStrictReturnsEmptyListForNullOrBlankInput() {
        assertTrue(CustomPatternRuleEntry.parseStrict(null).isEmpty());
        assertTrue(CustomPatternRuleEntry.parseStrict("   \n  ").isEmpty());
    }

    @Test
    void parseLenientReturnsEmptyListForNullOrBlankInput() {
        assertTrue(CustomPatternRuleEntry.parseLenient(null).isEmpty());
        assertTrue(CustomPatternRuleEntry.parseLenient("   \n  ").isEmpty());
    }

    @Test
    void parseStrictSkipsBlankLinesAroundValidEntries() {
        List<CustomPatternRuleEntry> entries = CustomPatternRuleEntry.parseStrict(
                "\noracle-connection-url|Oracle connection string contains a hardcoded password|HIGH|password=([^;\\s]+)|1\n\n");

        assertEquals(1, entries.size());
        assertEquals("oracle-connection-url", entries.get(0).getRuleId());
    }

    @Test
    void parseLenientSkipsInvalidAndDuplicateEntries() {
        List<CustomPatternRuleEntry> entries =
                CustomPatternRuleEntry.parseLenient("invalid rule id|Bad rule|HIGH|password=([^;\\s]+)|1\n"
                        + "oracle-connection-url|Oracle connection string contains a hardcoded password|HIGH|password=([^;\\s]+)|1\n"
                        + "oracle-connection-url|Duplicate rule|HIGH|password=([^;\\s]+)|1");

        assertEquals(1, entries.size());
        assertEquals("oracle-connection-url", entries.get(0).getRuleId());
    }

    @Test
    void compilePatternReturnsCompiledRegex() {
        CustomPatternRuleEntry entry = new CustomPatternRuleEntry(
                "oracle-connection-url",
                "Oracle connection string contains a hardcoded password",
                Severity.HIGH,
                "password=([^;\\s]+)",
                1);

        assertNotNull(entry.compilePattern());
        assertTrue(entry.compilePattern().matcher("password=PlainSecret42").find());
    }

    @Test
    void rejectsDuplicateRuleIds() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> CustomPatternRuleEntry.parseStrict("oracle-connection-url|First rule|HIGH|password=([^;\\s]+)|1\n"
                        + "oracle-connection-url|Second rule|HIGH|password=([^;\\s]+)|1"));

        assertTrue(exception.getMessage().contains("duplicate ruleId"));
    }

    @Test
    void rejectsMissingRuleId() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> CustomPatternRuleEntry.parseStrict(
                        "|Oracle connection string contains a hardcoded password|HIGH|password=([^;\\s]+)|1"));

        assertTrue(exception.getMessage().contains("missing ruleId"));
    }

    @Test
    void rejectsRuleIdsWithUnsupportedCharacters() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> CustomPatternRuleEntry.parseStrict(
                        "oracle_connection_url|Oracle connection string contains a hardcoded password|HIGH|password=([^;\\s]+)|1"));

        assertTrue(exception.getMessage().contains("lowercase letters, digits, and hyphens"));
    }

    @Test
    void rejectsMissingTitle() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> CustomPatternRuleEntry.parseStrict("oracle-connection-url||HIGH|password=([^;\\s]+)|1"));

        assertTrue(exception.getMessage().contains("missing title"));
    }

    @Test
    void rejectsUnsupportedSeverity() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> CustomPatternRuleEntry.parseStrict(
                        "oracle-connection-url|Oracle connection string contains a hardcoded password|CRITICAL|password=([^;\\s]+)|1"));

        assertTrue(exception.getMessage().contains("severity must be one of LOW, MEDIUM, or HIGH"));
    }

    @Test
    void rejectsMissingPattern() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> CustomPatternRuleEntry.parseStrict(
                        "oracle-connection-url|Oracle connection string contains a hardcoded password|HIGH||1"));

        assertTrue(exception.getMessage().contains("missing pattern"));
    }

    @Test
    void rejectsInvalidRegularExpression() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> CustomPatternRuleEntry.parseStrict(
                        "oracle-connection-url|Oracle connection string contains a hardcoded password|HIGH|(|1"));

        assertTrue(exception.getMessage().contains("invalid regular expression"));
    }

    @Test
    void acceptsOptionalBlankMatchingGroupAsWholeMatch() {
        List<CustomPatternRuleEntry> entries = CustomPatternRuleEntry.parseStrict(
                "oracle-connection-url|Oracle connection string contains a hardcoded password|HIGH|password=([^;\\s]+)|");

        assertEquals(1, entries.size());
        assertEquals(0, entries.get(0).getMatchingGroup());
    }

    @Test
    void rejectsNonNumericMatchingGroup() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> CustomPatternRuleEntry.parseStrict(
                        "oracle-connection-url|Oracle connection string contains a hardcoded password|HIGH|password=([^;\\s]+)|abc"));

        assertTrue(exception.getMessage().contains("matchingGroup must be a non-negative integer"));
    }

    @Test
    void rejectsNegativeMatchingGroup() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> CustomPatternRuleEntry.parseStrict(
                        "oracle-connection-url|Oracle connection string contains a hardcoded password|HIGH|password=([^;\\s]+)|-1"));

        assertTrue(exception.getMessage().contains("matchingGroup must be a non-negative integer"));
    }

    @Test
    void preservesEscapedPipeAndBackslashCharacters() {
        List<CustomPatternRuleEntry> entries = CustomPatternRuleEntry.parseStrict(
                "service-token|Service \\| token path|MEDIUM|C:\\\\temp\\\\service\\|token=([A-Za-z0-9_-]{12,})|1");

        assertEquals(1, entries.size());
        assertEquals("Service | token path", entries.get(0).getTitle());
        assertEquals(
                "C:\\temp\\service|token=([A-Za-z0-9_-]{12,})", entries.get(0).getPattern());
    }
}
