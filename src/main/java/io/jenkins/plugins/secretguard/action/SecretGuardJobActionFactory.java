package io.jenkins.plugins.secretguard.action;

import hudson.Extension;
import hudson.model.Job;
import java.util.Collection;
import java.util.Collections;
import jenkins.model.TransientActionFactory;

@Extension
public class SecretGuardJobActionFactory extends TransientActionFactory<Job> {
    @Override
    public Class<Job> type() {
        return Job.class;
    }

    @Override
    public Collection<SecretGuardJobAction> createFor(Job target) {
        return Collections.singletonList(new SecretGuardJobAction(target));
    }
}
