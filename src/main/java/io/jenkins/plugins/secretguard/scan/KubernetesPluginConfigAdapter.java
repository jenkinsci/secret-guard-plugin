package io.jenkins.plugins.secretguard.scan;

import io.jenkins.plugins.secretguard.model.ScanContext;
import java.util.Locale;
import java.util.Optional;
import org.w3c.dom.Element;

final class KubernetesPluginConfigAdapter implements ConfigXmlScanAdapter {
    @Override
    public Optional<ConfigXmlElementScanResult> scanElement(
            ScanContext context, String content, Element element, String path) {
        String lowerPath = (path + "/" + element.getNodeName()).toLowerCase(Locale.ENGLISH);
        if (!looksLikeKubernetesContext(element, lowerPath)) {
            return Optional.empty();
        }
        if (isSecretBackedEnvironmentVariable(lowerPath)) {
            return Optional.of(ConfigXmlElementScanResult.skip());
        }
        return Optional.empty();
    }

    private boolean looksLikeKubernetesContext(Element element, String lowerPath) {
        String className = element.getAttribute("class").toLowerCase(Locale.ENGLISH);
        return lowerPath.contains("org.csanchez.jenkins.plugins.kubernetes")
                || className.contains("org.csanchez.jenkins.plugins.kubernetes");
    }

    private boolean isSecretBackedEnvironmentVariable(String lowerPath) {
        return lowerPath.contains("secretenvvar");
    }
}
