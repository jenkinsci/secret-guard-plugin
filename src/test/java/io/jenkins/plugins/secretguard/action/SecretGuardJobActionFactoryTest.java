package io.jenkins.plugins.secretguard.action;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collection;
import org.junit.jupiter.api.Test;

class SecretGuardJobActionFactoryTest {
    @Test
    void hidesActionWhenPredicateRejectsJob() {
        SecretGuardJobActionFactory factory = new SecretGuardJobActionFactory(job -> false);

        Collection<SecretGuardJobAction> actions = factory.createFor(null);

        assertTrue(actions.isEmpty());
    }

    @Test
    void showsActionWhenPredicateAcceptsJob() {
        SecretGuardJobActionFactory factory = new SecretGuardJobActionFactory(job -> true);

        Collection<SecretGuardJobAction> actions = factory.createFor(null);

        assertEquals(1, actions.size());
    }
}
