package io.jenkins.plugins.secretguard.action;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class SecretGuardRootActionScriptTest {
    @Test
    void resultsSearchScriptWhitelistsSearchParameters() throws IOException {
        String script = Files.readString(Path.of("src/main/webapp/scripts/secret-guard-root-action.js"));

        assertTrue(script.contains("appendResultsFormField(form, params, RESULTS_FILTER_PARAM);"));
        assertTrue(script.contains("appendResultsFormField(form, params, RESULTS_QUERY_PARAM);"));
        assertFalse(script.contains("new window.FormData(form)"));
    }
}
