package io.jenkins.plugins.secretguard.scan;

import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

final class GenericHeaderPluginConfigAdapter implements ConfigXmlScanAdapter {
    private static final String GENERIC_HEADERS_NOTE =
            "Adapter: parsed generic plugin header configuration with header semantics.";

    @Override
    public Optional<ConfigXmlElementScanResult> scanElement(
            ScanContext context, String content, Element element, String path) {
        String lowerPath = (path + "/" + element.getNodeName()).toLowerCase(Locale.ENGLISH);
        if (!isPluginConfigPath(lowerPath) || !looksLikeHeaderContext(lowerPath)) {
            return Optional.empty();
        }

        List<HttpRequestHeaderSupport.ParsedCustomHeader> headers = parseStructuredHeaders(content, element, lowerPath);
        String directText = directText(element);
        if (headers.isEmpty() && !directText.isBlank() && isHeaderContainer(lowerPath)) {
            headers = HttpRequestHeaderSupport.parseHeaderExpression(directText, lineNumber(content, directText));
        }
        if (headers.isEmpty()) {
            return Optional.empty();
        }

        ScanContext headerContext = context.withLocationType(FindingLocationType.COMMAND_STEP);
        List<SecretFinding> findings = new ArrayList<>();
        for (HttpRequestHeaderSupport.ParsedCustomHeader header : headers) {
            findings.addAll(HttpRequestHeaderSupport.scanHardcodedCustomHeader(
                    headerContext,
                    header.lineNumber(),
                    header.name(),
                    header.valueExpression(),
                    header.maskValueFalse()));
        }
        return Optional.of(ConfigXmlElementScanResult.skipWithFindings(findings, GENERIC_HEADERS_NOTE));
    }

    private boolean isPluginConfigPath(String lowerPath) {
        return lowerPath.contains("/publishers/")
                || lowerPath.contains("/buildwrappers/")
                || lowerPath.contains("/builders/")
                || lowerPath.contains("/properties/");
    }

    private boolean looksLikeHeaderContext(String lowerPath) {
        return lowerPath.contains("header");
    }

    private boolean isHeaderContainer(String lowerPath) {
        return lowerPath.endsWith("/headers/headers")
                || lowerPath.endsWith("/customheaders/customheaders")
                || lowerPath.endsWith("/requestheaders/requestheaders")
                || lowerPath.contains("/headers/")
                || lowerPath.contains("/customheaders/")
                || lowerPath.contains("/requestheaders/");
    }

    private List<HttpRequestHeaderSupport.ParsedCustomHeader> parseStructuredHeaders(
            String content, Element element, String lowerPath) {
        List<HttpRequestHeaderSupport.ParsedCustomHeader> headers = new ArrayList<>();
        if (looksLikeHeaderEntry(element, lowerPath)) {
            addHeaderIfPresent(content, headers, element);
            return headers;
        }
        for (Element child : childElements(element)) {
            if (looksLikeHeaderEntry(
                    child, lowerPath + "/" + child.getNodeName().toLowerCase(Locale.ENGLISH))) {
                addHeaderIfPresent(content, headers, child);
            }
        }
        return headers;
    }

    private void addHeaderIfPresent(
            String content, List<HttpRequestHeaderSupport.ParsedCustomHeader> headers, Element headerElement) {
        String headerName = firstNonBlank(childText(headerElement, "name"), childText(headerElement, "headerName"));
        String headerValue = firstNonBlank(childText(headerElement, "value"), childText(headerElement, "headerValue"));
        if (headerValue.isBlank()) {
            return;
        }
        String maskValue = firstNonBlank(childText(headerElement, "maskValue"), childText(headerElement, "masked"));
        headers.add(new HttpRequestHeaderSupport.ParsedCustomHeader(
                headerName, headerValue, "false".equalsIgnoreCase(maskValue), lineNumber(content, headerValue)));
    }

    private boolean looksLikeHeaderEntry(Element element, String lowerPath) {
        if (!lowerPath.contains("header")) {
            return false;
        }
        return !firstNonBlank(childText(element, "value"), childText(element, "headerValue"))
                        .isBlank()
                && !firstNonBlank(childText(element, "name"), childText(element, "headerName"))
                        .isBlank();
    }

    private List<Element> childElements(Element element) {
        List<Element> children = new ArrayList<>();
        NodeList nodes = element.getChildNodes();
        for (int index = 0; index < nodes.getLength(); index++) {
            Node node = nodes.item(index);
            if (node instanceof Element child) {
                children.add(child);
            }
        }
        return children;
    }

    private String childText(Element element, String childName) {
        NodeList nodes = element.getChildNodes();
        for (int index = 0; index < nodes.getLength(); index++) {
            Node node = nodes.item(index);
            if (node instanceof Element child && childName.equals(child.getNodeName())) {
                return directText(child);
            }
        }
        return "";
    }

    private String firstNonBlank(String first, String second) {
        return first == null || first.isBlank() ? (second == null ? "" : second) : first;
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

    private int lineNumber(String content, String needle) {
        if (needle == null || needle.isBlank()) {
            return -1;
        }
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
