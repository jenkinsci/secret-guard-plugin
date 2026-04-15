package io.jenkins.plugins.secretguard.rules;

import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import java.util.List;

public interface SecretRule {
    String getId();

    List<SecretFinding> scan(ScanContext context, String sourceName, int lineNumber, String fieldName, String value);
}
