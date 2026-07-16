package io.jenkins.plugins.secretguard.rules;

import java.util.regex.Pattern;

public final class GitHubTokenPatterns {
    // Require the documented App ID and JWT structure to avoid treating arbitrary ghs_ references as secrets.
    public static final String HIGH_CONFIDENCE_TOKEN_EXPRESSION = "(?:gh[pousr]_[A-Za-z0-9_]{30,255}"
            + "|github_pat_[A-Za-z0-9_]{60,255}"
            + "|ghs_[0-9]+_eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,})";
    public static final Pattern HIGH_CONFIDENCE_TOKEN =
            Pattern.compile("\\b" + HIGH_CONFIDENCE_TOKEN_EXPRESSION + "\\b");

    private GitHubTokenPatterns() {}
}
