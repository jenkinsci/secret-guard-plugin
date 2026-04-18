package io.jenkins.plugins.secretguard.scan;

import io.jenkins.plugins.secretguard.model.ScanContext;
import java.util.Locale;
import java.util.Optional;
import org.w3c.dom.Element;

final class GitPluginConfigAdapter implements ConfigXmlScanAdapter {
    private static final String BRANCH_SPEC_NOTE = "Adapter: skipped Git branch metadata.";
    private static final String REFSPEC_NOTE = "Adapter: skipped Git refspec metadata.";
    private static final String REMOTE_NAME_NOTE = "Adapter: skipped Git remote name metadata.";

    @Override
    public Optional<ConfigXmlElementScanResult> scanElement(
            ScanContext context, String content, Element element, String path) {
        String lowerPath = (path + "/" + element.getNodeName()).toLowerCase(Locale.ENGLISH);
        if (!looksLikeGitContext(element, lowerPath)) {
            return Optional.empty();
        }
        if (isBranchSpecNameField(lowerPath)) {
            return Optional.of(ConfigXmlElementScanResult.skip(BRANCH_SPEC_NOTE));
        }
        if (isRefspecField(lowerPath)) {
            return Optional.of(ConfigXmlElementScanResult.skip(REFSPEC_NOTE));
        }
        if (isRemoteConfigNameField(lowerPath)) {
            return Optional.of(ConfigXmlElementScanResult.skip(REMOTE_NAME_NOTE));
        }
        return Optional.empty();
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
