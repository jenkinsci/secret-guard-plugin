package io.jenkins.plugins.secretguard.config;

import io.jenkins.plugins.secretguard.model.Severity;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class CustomPatternRuleEntry {
    private final String ruleId;
    private final String title;
    private final Severity severity;
    private final String pattern;
    private final int matchingGroup;

    public CustomPatternRuleEntry(String ruleId, String title, Severity severity, String pattern, int matchingGroup) {
        this.ruleId = ruleId;
        this.title = title;
        this.severity = severity;
        this.pattern = pattern;
        this.matchingGroup = matchingGroup;
    }

    public String getRuleId() {
        return ruleId;
    }

    public String getTitle() {
        return title;
    }

    public Severity getSeverity() {
        return severity;
    }

    public String getPattern() {
        return pattern;
    }

    public int getMatchingGroup() {
        return matchingGroup;
    }

    public Pattern compilePattern() {
        return Pattern.compile(pattern);
    }

    static List<CustomPatternRuleEntry> parseStrict(String value) {
        if (value == null || value.isBlank()) {
            return Collections.emptyList();
        }
        List<CustomPatternRuleEntry> entries = new ArrayList<>();
        Set<String> ruleIds = new LinkedHashSet<>();
        String[] lines = value.split("\\r?\\n");
        for (int index = 0; index < lines.length; index++) {
            String line = lines[index].trim();
            if (line.isEmpty()) {
                continue;
            }
            CustomPatternRuleEntry entry = parseLine(line, index + 1);
            if (!ruleIds.add(entry.getRuleId())) {
                throw new IllegalArgumentException(
                        "Line %d uses duplicate ruleId '%s'.".formatted(index + 1, entry.getRuleId()));
            }
            entries.add(entry);
        }
        return entries;
    }

    static List<CustomPatternRuleEntry> parseLenient(String value) {
        if (value == null || value.isBlank()) {
            return Collections.emptyList();
        }
        List<CustomPatternRuleEntry> entries = new ArrayList<>();
        Set<String> ruleIds = new LinkedHashSet<>();
        String[] lines = value.split("\\r?\\n");
        for (int index = 0; index < lines.length; index++) {
            String line = lines[index].trim();
            if (line.isEmpty()) {
                continue;
            }
            try {
                CustomPatternRuleEntry entry = parseLine(line, index + 1);
                if (ruleIds.add(entry.getRuleId())) {
                    entries.add(entry);
                }
            } catch (IllegalArgumentException ignored) {
                // Validation rejects malformed entries during save. Lenient parsing avoids scan failures
                // if a persisted configuration is manually edited into an invalid state.
            }
        }
        return entries;
    }

    private static CustomPatternRuleEntry parseLine(String line, int lineNumber) {
        List<String> parts = splitEscapedFields(line);
        if (parts.size() < 4 || parts.size() > 5) {
            throw new IllegalArgumentException(
                    "Line %d must use ruleId|title|severity|pattern|matchingGroup(optional).".formatted(lineNumber));
        }
        String ruleId = parts.get(0).trim();
        String title = parts.get(1).trim();
        String severityText = parts.get(2).trim();
        String pattern = parts.get(3).trim();
        if (ruleId.isEmpty()) {
            throw new IllegalArgumentException("Line %d is missing ruleId.".formatted(lineNumber));
        }
        if (!ruleId.matches("[a-z0-9]+(?:-[a-z0-9]+)*")) {
            throw new IllegalArgumentException(
                    "Line %d ruleId must use lowercase letters, digits, and hyphens.".formatted(lineNumber));
        }
        if (title.isEmpty()) {
            throw new IllegalArgumentException("Line %d is missing title.".formatted(lineNumber));
        }
        Severity severity;
        try {
            severity = Severity.valueOf(severityText.toUpperCase(Locale.ENGLISH));
        } catch (IllegalArgumentException ignored) {
            throw new IllegalArgumentException(
                    "Line %d severity must be one of LOW, MEDIUM, or HIGH.".formatted(lineNumber));
        }
        if (pattern.isEmpty()) {
            throw new IllegalArgumentException("Line %d is missing pattern.".formatted(lineNumber));
        }
        Pattern compiledPattern;
        try {
            compiledPattern = Pattern.compile(pattern);
        } catch (PatternSyntaxException exception) {
            throw new IllegalArgumentException(
                    "Line %d has an invalid regular expression: %s".formatted(lineNumber, exception.getDescription()));
        }
        int matchingGroup = 0;
        if (parts.size() == 5) {
            String matchingGroupText = parts.get(4).trim();
            if (!matchingGroupText.isEmpty()) {
                try {
                    matchingGroup = Integer.parseInt(matchingGroupText);
                } catch (NumberFormatException ignored) {
                    throw new IllegalArgumentException(
                            "Line %d matchingGroup must be a non-negative integer.".formatted(lineNumber));
                }
                if (matchingGroup < 0) {
                    throw new IllegalArgumentException(
                            "Line %d matchingGroup must be a non-negative integer.".formatted(lineNumber));
                }
            }
        }
        if (matchingGroup > compiledPattern.matcher("").groupCount()) {
            throw new IllegalArgumentException(
                    "Line %d matchingGroup %d exceeds the pattern group count.".formatted(lineNumber, matchingGroup));
        }
        return new CustomPatternRuleEntry(ruleId, title, severity, pattern, matchingGroup);
    }

    private static List<String> splitEscapedFields(String line) {
        List<String> parts = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        for (int index = 0; index < line.length(); index++) {
            char character = line.charAt(index);
            if (character == '\\' && index + 1 < line.length()) {
                char next = line.charAt(index + 1);
                if (next == '|' || next == '\\') {
                    current.append(next);
                    index++;
                    continue;
                }
            }
            if (character == '|') {
                parts.add(current.toString());
                current.setLength(0);
                continue;
            }
            current.append(character);
        }
        parts.add(current.toString());
        return parts;
    }
}
