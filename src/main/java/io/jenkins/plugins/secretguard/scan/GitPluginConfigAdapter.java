package io.jenkins.plugins.secretguard.scan;

import java.util.Locale;
import org.w3c.dom.Element;

final class GitPluginConfigAdapter {
    boolean shouldSkipElement(Element element, String path) {
        String lowerPath = (path + "/" + element.getNodeName()).toLowerCase(Locale.ENGLISH);
        if (!looksLikeGitContext(element, lowerPath)) {
            return false;
        }
        return isBranchSpecNameField(lowerPath) || isRefspecField(lowerPath) || isRemoteConfigNameField(lowerPath);
    }

    private boolean looksLikeGitContext(Element element, String lowerPath) {
        String className = element.getAttribute("class").toLowerCase(Locale.ENGLISH);
        return lowerPath.contains("hudson.plugins.git")
                || lowerPath.contains("jenkins.plugins.git")
                || className.contains("hudson.plugins.git")
                || className.contains("jenkins.plugins.git");
    }

    private boolean isBranchSpecNameField(String lowerPath) {
        return lowerPath.contains("branchspec") && lowerPath.endsWith("/name");
    }

    private boolean isRefspecField(String lowerPath) {
        return lowerPath.endsWith("/refspec");
    }

    private boolean isRemoteConfigNameField(String lowerPath) {
        return lowerPath.contains("userremoteconfig") && lowerPath.endsWith("/name");
    }
}
