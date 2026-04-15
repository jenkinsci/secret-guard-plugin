package io.jenkins.plugins.secretguard.action;

import hudson.Extension;
import hudson.Util;
import hudson.model.RootAction;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.service.ScanResultStore;
import java.util.List;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest2;

@Extension
public class SecretGuardRootAction implements RootAction {
    @Override
    public String getIconFileName() {
        return "symbol-shield-checkmark-outline plugin-ionicons-api";
    }

    @Override
    public String getDisplayName() {
        return "Secret Guard";
    }

    @Override
    public String getUrlName() {
        return "secret-guard";
    }

    public List<SecretScanResult> getResults() {
        return ScanResultStore.get().getAll();
    }

    public long getUnexemptedHighCount() {
        return ScanResultStore.get().getUnexemptedHighCount();
    }

    public String getJobSecretGuardUrl(SecretScanResult result) {
        if (result == null) {
            return null;
        }
        String relativePath = toJobSecretGuardPath(result.getTargetId());
        if (relativePath == null) {
            return null;
        }
        StaplerRequest2 currentRequest = Stapler.getCurrentRequest2();
        if (currentRequest == null
                || currentRequest.getContextPath() == null
                || currentRequest.getContextPath().isBlank()) {
            return "/" + relativePath;
        }
        return currentRequest.getContextPath() + "/" + relativePath;
    }

    static String toJobSecretGuardPath(String targetId) {
        if (targetId == null || targetId.isBlank()) {
            return null;
        }
        StringBuilder path = new StringBuilder();
        for (String segment : targetId.split("/")) {
            if (segment.isBlank()) {
                continue;
            }
            if (path.length() > 0) {
                path.append('/');
            }
            path.append("job/").append(Util.rawEncode(segment));
        }
        if (path.length() == 0) {
            return null;
        }
        path.append("/secret-guard");
        return path.toString();
    }
}
