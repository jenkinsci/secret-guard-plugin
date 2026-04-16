package io.jenkins.plugins.secretguard.action;

import hudson.Extension;
import hudson.model.Job;
import java.util.Collection;
import java.util.Collections;
import java.util.function.Predicate;
import jenkins.model.TransientActionFactory;

@Extension
public class SecretGuardJobActionFactory extends TransientActionFactory<Job> {
    private final Predicate<Job<?, ?>> showAction;

    public SecretGuardJobActionFactory() {
        this(job -> true);
    }

    SecretGuardJobActionFactory(Predicate<Job<?, ?>> showAction) {
        this.showAction = showAction;
    }

    @Override
    public Class<Job> type() {
        return Job.class;
    }

    @Override
    public Collection<SecretGuardJobAction> createFor(Job target) {
        if (!showAction.test(target)) {
            return Collections.emptyList();
        }
        return Collections.singletonList(new SecretGuardJobAction(target));
    }
}
