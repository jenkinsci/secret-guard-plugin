package io.jenkins.plugins.secretguard.service;

import jenkins.scm.api.SCMHead;
import jenkins.scm.api.SCMRevision;
import jenkins.scm.api.SCMSource;

public class MultibranchContext {
    private final SCMSource source;
    private final SCMHead head;
    private final SCMRevision revision;
    private final String scriptPath;

    public MultibranchContext(SCMSource source, SCMHead head, SCMRevision revision, String scriptPath) {
        this.source = source;
        this.head = head;
        this.revision = revision;
        this.scriptPath = scriptPath;
    }

    public SCMSource getSource() {
        return source;
    }

    public SCMHead getHead() {
        return head;
    }

    public SCMRevision getRevision() {
        return revision;
    }

    public String getScriptPath() {
        return scriptPath;
    }
}
