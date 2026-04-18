package io.jenkins.plugins.secretguard.scan;

import java.util.Locale;
import org.w3c.dom.Element;

final class KubernetesPluginConfigAdapter {
    boolean shouldSkipElement(Element element, String path) {
        String lowerPath = (path + "/" + element.getNodeName()).toLowerCase(Locale.ENGLISH);
        if (!looksLikeKubernetesContext(element, lowerPath)) {
            return false;
        }
        return isSecretBackedEnvironmentVariable(lowerPath);
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
