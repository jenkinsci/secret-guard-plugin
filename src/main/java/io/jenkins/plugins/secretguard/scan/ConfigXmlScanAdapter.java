package io.jenkins.plugins.secretguard.scan;

import io.jenkins.plugins.secretguard.model.ScanContext;
import java.util.Optional;
import org.w3c.dom.Element;

interface ConfigXmlScanAdapter {
    Optional<ConfigXmlElementScanResult> scanElement(ScanContext context, String content, Element element, String path);
}
