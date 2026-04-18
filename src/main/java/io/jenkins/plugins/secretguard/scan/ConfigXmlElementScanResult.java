package io.jenkins.plugins.secretguard.scan;

import io.jenkins.plugins.secretguard.model.SecretFinding;
import java.util.List;

record ConfigXmlElementScanResult(List<SecretFinding> findings, boolean skipSubtree, List<String> notes) {
    static ConfigXmlElementScanResult skip() {
        return new ConfigXmlElementScanResult(List.of(), true, List.of());
    }

    static ConfigXmlElementScanResult skip(String note) {
        return new ConfigXmlElementScanResult(List.of(), true, List.of(note));
    }

    static ConfigXmlElementScanResult skipWithFindings(List<SecretFinding> findings) {
        return new ConfigXmlElementScanResult(List.copyOf(findings), true, List.of());
    }

    static ConfigXmlElementScanResult skipWithFindings(List<SecretFinding> findings, String note) {
        return new ConfigXmlElementScanResult(List.copyOf(findings), true, List.of(note));
    }

    ConfigXmlElementScanResult {
        findings = findings == null ? List.of() : List.copyOf(findings);
        notes = notes == null ? List.of() : List.copyOf(notes);
    }
}
