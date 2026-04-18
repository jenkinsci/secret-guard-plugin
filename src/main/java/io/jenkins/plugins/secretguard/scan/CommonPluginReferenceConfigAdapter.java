package io.jenkins.plugins.secretguard.scan;

import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.util.NonSecretHeuristics;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

final class CommonPluginReferenceConfigAdapter implements ConfigXmlScanAdapter {
    private static final String EXTERNAL_REFERENCE_NOTE =
            "Config adapter skipped common plugin external secret or credential reference.";
    private static final Pattern REFERENCE_VALUE = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._/@:-]{0,127}");
    private static final Pattern HIGH_CONFIDENCE_SECRET = Pattern.compile("(?is).*("
            + "gh[pousr]_[A-Za-z0-9_]{30,255}"
            + "|github_pat_[A-Za-z0-9_]{60,255}"
            + "|eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}"
            + "|(?:AKIA|ASIA)[A-Z0-9]{16}"
            + "|Bearer\\s+[A-Za-z0-9._~+/=-]{12,}"
            + "|-----BEGIN [A-Z ]*PRIVATE KEY-----"
            + ").*");

    @Override
    public Optional<ConfigXmlElementScanResult> scanElement(
            ScanContext context, String content, Element element, String path) {
        String lowerPath = (path + "/" + element.getNodeName()).toLowerCase(Locale.ENGLISH);
        if (!isCommonPluginConfigPath(lowerPath) || !isReferenceField(element, lowerPath)) {
            return Optional.empty();
        }
        String value = directText(element);
        if (looksLikeReferenceValue(value)) {
            return Optional.of(ConfigXmlElementScanResult.skip(EXTERNAL_REFERENCE_NOTE));
        }
        return Optional.empty();
    }

    private boolean isCommonPluginConfigPath(String lowerPath) {
        return lowerPath.contains("/publishers/")
                || lowerPath.contains("/buildwrappers/")
                || lowerPath.contains("/builders/");
    }

    private boolean isReferenceField(Element element, String lowerPath) {
        String normalizedName = normalize(element.getNodeName());
        if (normalizedName.equals("secretname")
                || normalizedName.equals("credentialname")
                || normalizedName.equals("credentialsname")
                || normalizedName.equals("credential")
                || normalizedName.equals("credentials")) {
            return true;
        }
        return normalizedName.equals("secretkey") && hasSibling(element, "secretName");
    }

    private boolean looksLikeReferenceValue(String value) {
        String trimmed = value == null ? "" : value.trim();
        if (trimmed.isEmpty()
                || trimmed.contains("://")
                || trimmed.contains("?")
                || !REFERENCE_VALUE.matcher(trimmed).matches()
                || HIGH_CONFIDENCE_SECRET.matcher(trimmed).matches()) {
            return false;
        }
        return trimmed.length() < 32 || NonSecretHeuristics.entropy(trimmed) < 4.0;
    }

    private boolean hasSibling(Element element, String siblingName) {
        Node parent = element.getParentNode();
        if (parent == null) {
            return false;
        }
        NodeList nodes = parent.getChildNodes();
        for (int index = 0; index < nodes.getLength(); index++) {
            Node node = nodes.item(index);
            if (node instanceof Element sibling && siblingName.equals(sibling.getNodeName())) {
                return true;
            }
        }
        return false;
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

    private String normalize(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ENGLISH).replaceAll("[^a-z0-9]", "");
    }
}
