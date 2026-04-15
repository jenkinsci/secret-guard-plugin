package io.jenkins.plugins.secretguard.service;

import hudson.XmlFile;
import hudson.util.XStream2;
import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.model.Severity;
import java.io.File;
import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;

public class ScanResultStore {
    private static final Logger LOGGER = Logger.getLogger(ScanResultStore.class.getName());
    private static final XStream2 XSTREAM = new XStream2();
    private static final ScanResultStore INSTANCE = new ScanResultStore(null);

    private final ConcurrentMap<String, SecretScanResult> results = new ConcurrentHashMap<>();
    private final File resultsDirectory;

    ScanResultStore(File resultsDirectory) {
        this.resultsDirectory = resultsDirectory;
    }

    public static ScanResultStore get() {
        return INSTANCE;
    }

    static ScanResultStore inDirectory(File resultsDirectory) {
        return new ScanResultStore(resultsDirectory);
    }

    public void put(SecretScanResult result) {
        if (result != null && !result.getTargetId().isBlank()) {
            results.put(result.getTargetId(), result);
            save(result);
        }
    }

    public Optional<SecretScanResult> get(String targetId) {
        if (targetId == null || targetId.isBlank()) {
            return Optional.empty();
        }
        SecretScanResult cached = results.get(targetId);
        if (cached != null) {
            return Optional.of(cached);
        }
        Optional<SecretScanResult> loaded = load(targetId);
        loaded.ifPresent(result -> results.put(result.getTargetId(), result));
        return loaded;
    }

    public List<SecretScanResult> getAll() {
        loadAllFromDisk();
        List<SecretScanResult> values = new ArrayList<>(results.values());
        values.sort(Comparator.comparing(SecretScanResult::getScannedAt).reversed());
        return values;
    }

    public long getUnexemptedHighCount() {
        loadAllFromDisk();
        return results.values().stream()
                .mapToLong(SecretScanResult::getUnexemptedHighCount)
                .sum();
    }

    public void remove(String targetId) {
        if (targetId == null || targetId.isBlank()) {
            return;
        }
        results.remove(targetId);
        File file = resultFile(targetId);
        if (file != null && file.isFile() && !file.delete()) {
            LOGGER.log(Level.FINE, "Failed to delete Secret Guard result file {0}", file);
        }
    }

    private void save(SecretScanResult result) {
        File file = resultFile(result.getTargetId());
        if (file == null) {
            return;
        }
        File parent = file.getParentFile();
        if (!parent.isDirectory() && !parent.mkdirs()) {
            LOGGER.log(Level.FINE, "Failed to create Secret Guard result directory {0}", parent);
            return;
        }
        try {
            new XmlFile(XSTREAM, file).write(PersistedScanResult.from(result));
        } catch (IOException | RuntimeException e) {
            LOGGER.log(Level.WARNING, "Failed to persist Secret Guard scan result for " + result.getTargetId(), e);
        }
    }

    private Optional<SecretScanResult> load(String targetId) {
        File file = resultFile(targetId);
        if (file == null || !file.isFile()) {
            return Optional.empty();
        }
        return load(file);
    }

    private Optional<SecretScanResult> load(File file) {
        try {
            Object value = new XmlFile(XSTREAM, file).read();
            if (value instanceof PersistedScanResult persisted) {
                SecretScanResult result = persisted.toScanResult();
                if (!result.getTargetId().isBlank()) {
                    return Optional.of(result);
                }
            }
        } catch (IOException | RuntimeException e) {
            LOGGER.log(Level.WARNING, "Failed to load Secret Guard scan result from " + file, e);
        }
        return Optional.empty();
    }

    private void loadAllFromDisk() {
        File directory = resultDirectory();
        if (directory == null || !directory.isDirectory()) {
            return;
        }
        File[] files = directory.listFiles((dir, name) -> name.endsWith(".xml"));
        if (files == null) {
            return;
        }
        for (File file : files) {
            String targetId = decodeTargetId(file.getName());
            if (targetId != null && results.containsKey(targetId)) {
                continue;
            }
            load(file).ifPresent(result -> results.put(result.getTargetId(), result));
        }
    }

    private File resultFile(String targetId) {
        File directory = resultDirectory();
        if (directory == null) {
            return null;
        }
        return new File(directory, encodeTargetId(targetId) + ".xml");
    }

    private File resultDirectory() {
        if (resultsDirectory != null) {
            return resultsDirectory;
        }
        try {
            Jenkins jenkins = Jenkins.get();
            return new File(jenkins.getRootDir(), "secret-guard/results");
        } catch (IllegalStateException ignored) {
            return null;
        }
    }

    private String encodeTargetId(String targetId) {
        return URLEncoder.encode(targetId, StandardCharsets.UTF_8);
    }

    private String decodeTargetId(String fileName) {
        if (!fileName.endsWith(".xml")) {
            return null;
        }
        String encoded = fileName.substring(0, fileName.length() - 4);
        return URLDecoder.decode(encoded, StandardCharsets.UTF_8);
    }

    public static class PersistedScanResult {
        public String targetId;
        public String targetType;
        public boolean blocked;
        public long scannedAtEpochMillis;
        public List<PersistedFinding> findings = new ArrayList<>();

        public static PersistedScanResult from(SecretScanResult result) {
            PersistedScanResult persisted = new PersistedScanResult();
            persisted.targetId = result.getTargetId();
            persisted.targetType = result.getTargetType();
            persisted.blocked = result.isBlocked();
            persisted.scannedAtEpochMillis = result.getScannedAt().toEpochMilli();
            for (SecretFinding finding : result.getFindings()) {
                persisted.findings.add(PersistedFinding.from(finding));
            }
            return persisted;
        }

        public SecretScanResult toScanResult() {
            List<SecretFinding> restoredFindings = new ArrayList<>();
            if (findings != null) {
                for (PersistedFinding finding : findings) {
                    restoredFindings.add(finding.toFinding());
                }
            }
            return new SecretScanResult(
                    targetId,
                    targetType,
                    restoredFindings,
                    blocked,
                    scannedAtEpochMillis <= 0 ? Instant.now() : Instant.ofEpochMilli(scannedAtEpochMillis));
        }
    }

    public static class PersistedFinding {
        public String ruleId;
        public String title;
        public String severity;
        public String locationType;
        public String jobFullName;
        public String sourceName;
        public int lineNumber;
        public String fieldName;
        public String maskedSnippet;
        public String recommendation;
        public boolean exempted;
        public String exemptionReason;

        public static PersistedFinding from(SecretFinding finding) {
            PersistedFinding persisted = new PersistedFinding();
            persisted.ruleId = finding.getRuleId();
            persisted.title = finding.getTitle();
            persisted.severity = finding.getSeverity().name();
            persisted.locationType = finding.getLocationType().name();
            persisted.jobFullName = finding.getJobFullName();
            persisted.sourceName = finding.getSourceName();
            persisted.lineNumber = finding.getLineNumber();
            persisted.fieldName = finding.getFieldName();
            persisted.maskedSnippet = finding.getMaskedSnippet();
            persisted.recommendation = finding.getRecommendation();
            persisted.exempted = finding.isExempted();
            persisted.exemptionReason = finding.getExemptionReason();
            return persisted;
        }

        public SecretFinding toFinding() {
            SecretFinding finding = new SecretFinding(
                    nullToDefault(ruleId, "unknown"),
                    nullToDefault(title, "Persisted Secret Guard finding"),
                    parseSeverity(severity),
                    parseLocationType(locationType),
                    jobFullName,
                    sourceName,
                    lineNumber,
                    fieldName,
                    maskedSnippet,
                    recommendation);
            return exempted ? finding.withExemption(exemptionReason) : finding;
        }

        private Severity parseSeverity(String value) {
            try {
                return value == null ? Severity.LOW : Severity.valueOf(value);
            } catch (IllegalArgumentException e) {
                return Severity.LOW;
            }
        }

        private FindingLocationType parseLocationType(String value) {
            try {
                return value == null ? FindingLocationType.CONFIG_XML : FindingLocationType.valueOf(value);
            } catch (IllegalArgumentException e) {
                return FindingLocationType.CONFIG_XML;
            }
        }

        private String nullToDefault(String value, String defaultValue) {
            return value == null ? defaultValue : value;
        }
    }
}
