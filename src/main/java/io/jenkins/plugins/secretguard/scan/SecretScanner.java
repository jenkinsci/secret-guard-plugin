package io.jenkins.plugins.secretguard.scan;

import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.SecretScanResult;

public interface SecretScanner {
    SecretScanResult scan(ScanContext context, String content);
}
