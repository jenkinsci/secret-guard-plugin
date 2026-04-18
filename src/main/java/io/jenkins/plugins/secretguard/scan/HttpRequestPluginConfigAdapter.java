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

final class HttpRequestPluginConfigAdapter implements ConfigXmlScanAdapter {
    private static final String AUTHENTICATION_REFERENCE_NOTE =
            "Adapter: skipped HTTP Request authentication reference.";
    private static final String CUSTOM_HEADERS_NOTE =
            "Adapter: parsed HTTP Request customHeaders with header semantics.";

    @Override
    public Optional<ConfigXmlElementScanResult> scanElement(
            ScanContext context, String content, Element element, String path) {
        String lowerPath = (path + "/" + element.getNodeName()).toLowerCase(Locale.ENGLISH);
        String directText = directText(element);
        if (!looksLikeHttpRequestContext(lowerPath)) {
            return Optional.empty();
        }
        if (isAuthenticationField(lowerPath)) {
            return Optional.of(ConfigXmlElementScanResult.skip(AUTHENTICATION_REFERENCE_NOTE));
        }
        if (isCustomHeadersField(lowerPath)) {
            List<HttpRequestHeaderSupport.ParsedCustomHeader> headers = parseStructuredHeaders(content, element);
            if (headers.isEmpty() && !directText.isBlank()) {
                headers = HttpRequestHeaderSupport.parseHeaderExpression(directText, lineNumber(content, directText));
            }
            if (!headers.isEmpty()) {
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
                return Optional.of(ConfigXmlElementScanResult.skipWithFindings(findings, CUSTOM_HEADERS_NOTE));
            }
            return Optional.empty();
        }
        return Optional.empty();
    }

    private boolean looksLikeHttpRequestContext(String lowerPath) {
        return lowerPath.contains("httprequest")
                || lowerPath.contains("http_request")
                || lowerPath.contains("customheaders");
    }

    private boolean isAuthenticationField(String lowerPath) {
        return lowerPath.endsWith("/authentication/authentication")
                || lowerPath.endsWith("/proxyauthentication/proxyauthentication")
                || lowerPath.endsWith("/credentialid/credentialid")
                || lowerPath.endsWith("/credentialsid/credentialsid");
    }

    private boolean isCustomHeadersField(String lowerPath) {
        return lowerPath.endsWith("/customheaders/customheaders") || lowerPath.contains("/customheaders/");
    }

    private List<HttpRequestHeaderSupport.ParsedCustomHeader> parseStructuredHeaders(String content, Element element) {
        List<HttpRequestHeaderSupport.ParsedCustomHeader> headers = new ArrayList<>();
        if (looksLikeHeaderEntry(element)) {
            addHeaderIfPresent(content, headers, element);
            return headers;
        }
        for (Element child : childElements(element)) {
            if (looksLikeHeaderEntry(child)) {
                addHeaderIfPresent(content, headers, child);
            }
        }
        return headers;
    }

    private void addHeaderIfPresent(
            String content, List<HttpRequestHeaderSupport.ParsedCustomHeader> headers, Element headerElement) {
        String headerName = childText(headerElement, "name");
        String headerValue = childText(headerElement, "value");
        if (headerValue.isBlank()) {
            return;
        }
        String maskValue = childText(headerElement, "maskValue");
        headers.add(new HttpRequestHeaderSupport.ParsedCustomHeader(
                headerName, headerValue, "false".equalsIgnoreCase(maskValue), lineNumber(content, headerValue)));
    }

    private boolean looksLikeHeaderEntry(Element element) {
        return !childText(element, "value").isBlank()
                && (!childText(element, "name").isBlank()
                        || !childText(element, "maskValue").isBlank());
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
