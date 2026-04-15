package io.jenkins.plugins.secretguard.action;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

class SecretGuardRootActionTest {
    @Test
    void buildsJobSecretGuardPathForNestedJob() {
        assertEquals(
                "job/folder/job/sub%20job/secret-guard", SecretGuardRootAction.toJobSecretGuardPath("folder/sub job"));
    }

    @Test
    void returnsNullWhenTargetIdIsBlank() {
        assertNull(SecretGuardRootAction.toJobSecretGuardPath(" "));
        assertNull(SecretGuardRootAction.toJobSecretGuardPath(null));
    }
}
