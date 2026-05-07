package io.jenkins.plugins.secretguard.scan;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jenkins.plugins.secretguard.model.EnforcementMode;
import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.ScanPhase;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.Severity;
import java.util.List;
import org.junit.jupiter.api.Test;

class HttpRequestHeaderSupportTest {
    @Test
    void parseHeaderExpressionReturnsEmptyForNonListInput() {
        assertTrue(HttpRequestHeaderSupport.parseHeaderExpression("helperCall()", 7)
                .isEmpty());
    }

    @Test
    void parseHeaderExpressionSkipsUnsupportedSegmentsAndTracksLineNumbers() {
        String expression = """
                ([
                  helperCall(),
                  [name: 'Authorization', ignoredProperty, value:
                      'Bearer abcdefghijklmnopqrstuvwxyz', maskValue: false],
                  ([name: 'X-Safe', value: headerToken]),
                  [name: 'X-WithoutValue']
                ]) as List<Map>
                """;

        List<HttpRequestHeaderSupport.ParsedCustomHeader> headers =
                HttpRequestHeaderSupport.parseHeaderExpression(expression, 20);

        assertEquals(2, headers.size());

        HttpRequestHeaderSupport.ParsedCustomHeader authorizationHeader = headers.get(0);
        assertEquals("Authorization", authorizationHeader.name());
        assertEquals("'Bearer abcdefghijklmnopqrstuvwxyz'", authorizationHeader.valueExpression());
        assertTrue(authorizationHeader.maskValueFalse());
        assertEquals(22, authorizationHeader.lineNumber());

        HttpRequestHeaderSupport.ParsedCustomHeader safeHeader = headers.get(1);
        assertEquals("X-Safe", safeHeader.name());
        assertEquals("headerToken", safeHeader.valueExpression());
        assertFalse(safeHeader.maskValueFalse());
        assertEquals(24, safeHeader.lineNumber());
    }

    @Test
    void extractBracketedExpressionReturnsEmptyWhenNoListStarts() {
        String[] lines = {"httpRequest customHeaders: helper(note: 'no list here')"};

        HttpRequestHeaderSupport.ExtractedExpression extracted =
                HttpRequestHeaderSupport.extractBracketedExpression(lines, 0, lines[0].indexOf("customHeaders:"));

        assertEquals("", extracted.value());
        assertEquals(0, extracted.endLineIndex());
        assertEquals(-1, extracted.endColumnIndex());
    }

    @Test
    void extractBracketedExpressionSkipsQuotedBracketsAndHandlesEscapedQuotes() {
        String[] lines = {
            "httpRequest customHeaders: helper(note: \"[ignored]\"),",
            "    [[name: \"Authorization\", value: \"Bearer abcdefghijklmnop\\\\\\\"qrst[]uv\"],",
            "     [name: 'X-Safe', value: 'ok']]"
        };

        HttpRequestHeaderSupport.ExtractedExpression extracted =
                HttpRequestHeaderSupport.extractBracketedExpression(lines, 0, lines[0].indexOf("customHeaders:"));

        assertEquals("""
                [[name: "Authorization", value: "Bearer abcdefghijklmnop\\\\\\\"qrst[]uv"],
                     [name: 'X-Safe', value: 'ok']]""".stripIndent(), extracted.value());
        assertEquals(2, extracted.endLineIndex());
        assertEquals(lines[2].length() - 1, extracted.endColumnIndex());
    }

    @Test
    void scanHardcodedCustomHeaderReportsMaskedAndUnmaskedFindings() {
        List<SecretFinding> findings = HttpRequestHeaderSupport.scanHardcodedCustomHeader(
                context(), 14, "Authorization", "'Bearer abcdefghijklmnopqrstuvwxyz'", true);

        assertEquals(2, findings.size());
        assertEquals("http-request-hardcoded-header-secret", findings.get(0).getRuleId());
        assertEquals("http-request-unmasked-header-secret", findings.get(1).getRuleId());
        assertEquals("Authorization", findings.get(0).getFieldName());
        assertEquals(14, findings.get(0).getLineNumber());
        assertFalse(findings.get(0).getMaskedSnippet().contains("abcdefghijklmnopqrstuvwxyz"));
        assertEquals("abcdefghijklmnopqrstuvwxyz", findings.get(0).getEvidenceKey());
    }

    @Test
    void scanHardcodedCustomHeaderIgnoresVariablesAndRuntimeReferences() {
        assertTrue(
                HttpRequestHeaderSupport.scanHardcodedCustomHeader(context(), 9, "Authorization", "headerToken", false)
                        .isEmpty());
        assertTrue(HttpRequestHeaderSupport.scanHardcodedCustomHeader(
                        context(), 10, "Authorization", "\"$SERVICE_TOKEN\"", false)
                .isEmpty());
        assertTrue(HttpRequestHeaderSupport.looksLikeGroovyVariableReference("headerToken"));
        assertFalse(HttpRequestHeaderSupport.looksLikeGroovyVariableReference("'headerToken'"));
    }

    private ScanContext context() {
        return new ScanContext(
                "folder/job",
                "Pipeline script",
                "WorkflowJob",
                FindingLocationType.PIPELINE_SCRIPT,
                ScanPhase.BUILD,
                EnforcementMode.BLOCK,
                Severity.HIGH);
    }
}
