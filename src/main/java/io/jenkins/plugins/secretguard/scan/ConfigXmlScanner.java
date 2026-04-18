package io.jenkins.plugins.secretguard.scan;

import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.rules.BuiltInSecretRuleSet;
import io.jenkins.plugins.secretguard.rules.SecretRule;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class ConfigXmlScanner implements SecretScanner {
    private final BuiltInSecretRuleSet ruleSet;
    private final PipelineScriptScanner pipelineScriptScanner;
    private final HttpRequestPluginConfigAdapter httpRequestPluginConfigAdapter;
    private final GitPluginConfigAdapter gitPluginConfigAdapter;

    public ConfigXmlScanner() {
        this(new BuiltInSecretRuleSet());
    }

    ConfigXmlScanner(BuiltInSecretRuleSet ruleSet) {
        this.ruleSet = ruleSet;
        this.pipelineScriptScanner = new PipelineScriptScanner(ruleSet);
        this.httpRequestPluginConfigAdapter = new HttpRequestPluginConfigAdapter();
        this.gitPluginConfigAdapter = new GitPluginConfigAdapter();
    }

    @Override
    public SecretScanResult scan(ScanContext context, String content) {
        if (content == null || content.isBlank()) {
            return SecretScanResult.empty(context.getJobFullName(), context.getTargetType());
        }
        List<SecretFinding> findings = new ArrayList<>();
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setExpandEntityReferences(false);
            Document document = factory.newDocumentBuilder().parse(new InputSource(new StringReader(content)));
            Element root = document.getDocumentElement();
            if (root != null) {
                scanElement(context, content, findings, root, "/" + root.getNodeName());
            }
        } catch (Exception ignored) {
            scanRawLines(context, content, findings);
        }
        return new SecretScanResult(context.getJobFullName(), context.getTargetType(), findings, false);
    }

    private void scanElement(
            ScanContext context, String content, List<SecretFinding> findings, Element element, String path) {
        HttpRequestPluginConfigAdapter.ElementScanResult adapterResult = httpRequestPluginConfigAdapter
                .scanElement(context, content, element, path)
                .orElse(null);
        if (adapterResult != null) {
            findings.addAll(adapterResult.findings());
            if (adapterResult.skipSubtree()) {
                return;
            }
        }
        if (gitPluginConfigAdapter.shouldSkipElement(element, path)) {
            return;
        }

        NamedNodeMap attributes = element.getAttributes();
        for (int index = 0; index < attributes.getLength(); index++) {
            Node attribute = attributes.item(index);
            scanValue(
                    context,
                    content,
                    findings,
                    path + "/@" + attribute.getNodeName(),
                    attribute.getNodeName(),
                    attribute.getNodeValue());
        }

        String directText = directText(element);
        if (!directText.isBlank()) {
            if (isPipelineScriptElement(path, element.getNodeName(), directText)) {
                ScanContext scriptContext = context.withLocationType(FindingLocationType.PIPELINE_SCRIPT);
                findings.addAll(
                        pipelineScriptScanner.scan(scriptContext, directText).getFindings());
            } else {
                scanValue(context, content, findings, path, element.getNodeName(), directText);
            }
        }

        NodeList children = element.getChildNodes();
        for (int index = 0; index < children.getLength(); index++) {
            Node child = children.item(index);
            if (child instanceof Element childElement) {
                scanElement(context, content, findings, childElement, path + "/" + childElement.getNodeName());
            }
        }
    }

    private void scanValue(
            ScanContext context,
            String content,
            List<SecretFinding> findings,
            String path,
            String fieldName,
            String value) {
        if (value == null || value.isBlank()) {
            return;
        }
        ScanContext locationContext = context.withLocationType(classify(path, fieldName));
        int lineNumber = lineNumber(content, value);
        for (SecretRule rule : ruleSet.getRules()) {
            findings.addAll(rule.scan(locationContext, path, lineNumber, fieldName, value));
        }
    }

    private FindingLocationType classify(String path, String fieldName) {
        String lower = (path + "/" + fieldName).toLowerCase();
        if (lower.contains("defaultvalue")) {
            return FindingLocationType.PARAMETER_DEFAULT;
        }
        if (lower.contains("env") || lower.contains("environment")) {
            return FindingLocationType.ENVIRONMENT;
        }
        return FindingLocationType.CONFIG_XML;
    }

    private boolean isPipelineScriptElement(String path, String fieldName, String value) {
        String lowerPath = (path + "/" + fieldName).toLowerCase();
        if (!lowerPath.endsWith("/script/script") && !lowerPath.endsWith("/script")) {
            return false;
        }
        String lowerValue = value.toLowerCase();
        return lowerValue.contains("pipeline {")
                || lowerValue.contains("httprequest")
                || lowerValue.contains("withcredentials")
                || lowerValue.contains(" sh ")
                || lowerValue.contains(" sh(");
    }

    private String directText(Element element) {
        StringBuilder value = new StringBuilder();
        NodeList children = element.getChildNodes();
        for (int index = 0; index < children.getLength(); index++) {
            Node child = children.item(index);
            if (child.getNodeType() == Node.TEXT_NODE || child.getNodeType() == Node.CDATA_SECTION_NODE) {
                value.append(child.getTextContent());
            }
        }
        return value.toString().trim();
    }

    private void scanRawLines(ScanContext context, String content, List<SecretFinding> findings) {
        String[] lines = content.split("\\R", -1);
        for (int index = 0; index < lines.length; index++) {
            String line = lines[index];
            for (SecretRule rule : ruleSet.getRules()) {
                findings.addAll(
                        rule.scan(context, context.getSourceName(), index + 1, extractXmlFieldName(line), line));
            }
        }
    }

    private String extractXmlFieldName(String line) {
        int start = line.indexOf('<');
        int end = line.indexOf('>');
        if (start >= 0 && end > start) {
            String candidate = line.substring(start + 1, end).trim();
            if (!candidate.startsWith("/") && !candidate.contains(" ")) {
                return candidate;
            }
        }
        return "";
    }

    private int lineNumber(String content, String needle) {
        int offset = content.indexOf(needle);
        if (offset < 0) {
            return -1;
        }
        int line = 1;
        for (int index = 0; index < offset; index++) {
            if (content.charAt(index) == '\n') {
                line++;
            }
        }
        return line;
    }
}
