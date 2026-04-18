package io.jenkins.plugins.secretguard.scan;

import io.jenkins.plugins.secretguard.model.SecretFinding;
import java.util.List;

record ConfigXmlElementScanResult(List<SecretFinding> findings, boolean skipSubtree) {
    static ConfigXmlElementScanResult skip() {
        return new ConfigXmlElementScanResult(List.of(), true);
    }

    static ConfigXmlElementScanResult skipWithFindings(List<SecretFinding> findings) {
        return new ConfigXmlElementScanResult(List.copyOf(findings), true);
    }
}
