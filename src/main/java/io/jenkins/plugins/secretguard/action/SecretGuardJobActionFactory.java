package io.jenkins.plugins.secretguard.action;

import hudson.Extension;
import hudson.model.Job;
import io.jenkins.plugins.secretguard.service.ScanResultStore;
import java.util.Collection;
import java.util.Collections;
import java.util.function.Predicate;
import jenkins.model.TransientActionFactory;

@Extension
public class SecretGuardJobActionFactory extends TransientActionFactory<Job> {
    private final Predicate<Job<?, ?>> hasScanResult;

    public SecretGuardJobActionFactory() {
        this(job -> ScanResultStore.get().get(job.getFullName()).isPresent());
    }

    SecretGuardJobActionFactory(Predicate<Job<?, ?>> hasScanResult) {
        this.hasScanResult = hasScanResult;
    }

    @Override
    public Class<Job> type() {
        return Job.class;
    }

    @Override
    public Collection<SecretGuardJobAction> createFor(Job target) {
        if (!hasScanResult.test(target)) {
            return Collections.emptyList();
        }
        return Collections.singletonList(new SecretGuardJobAction(target));
    }
}
