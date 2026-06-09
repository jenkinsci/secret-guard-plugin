package io.jenkins.plugins.secretguard.scanner;

import static org.junit.Assert.*;

import io.jenkins.plugins.secretguard.model.ScanResult;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class PipelineScriptScannerTest {

    private static final String FALSE_POSITIVES_DIR =
            "/io/jenkins/plugins/secretguard/fixtures/false-positives/";

    private PipelineScriptScanner scanner;
    private String fixtureName;
    private String scriptContent;

    public PipelineScriptScannerTest(String fixtureName, String scriptContent) {
        this.fixtureName = fixtureName;
        this.scriptContent = scriptContent;
    }

    @Parameterized.Parameters(name = "{0}")
    public static Iterable<Object[]> data() throws IOException, URISyntaxException {
        URL dirUrl = PipelineScriptScannerTest.class.getResource(FALSE_POSITIVES_DIR);
        if (dirUrl == null) {
            throw new IOException("False positives directory not found: " + FALSE_POSITIVES_DIR);
        }
        Path dirPath = Paths.get(dirUrl.toURI());
        List<Path> fixtureFiles = Files.list(dirPath)
                .filter(p -> p.toString().endsWith(".groovy"))
                .sorted()
                .collect(Collectors.toList());

        return fixtureFiles.stream()
                .map(path -> {
                    try {
                        String name = path.getFileName().toString();
                        String content = new String(Files.readAllBytes(path));
                        return new Object[] { name, content };
                    } catch (IOException e) {
                        throw new RuntimeException("Failed to read fixture: " + path, e);
                    }
                })
                .collect(Collectors.toList());
    }

    @Before
    public void setUp() {
        scanner = new PipelineScriptScanner();
    }

    @Test
    public void testFalsePositives() {
        ScanResult result = scanner.scan(scriptContent);
        assertFalse(
                "Fixture '" + fixtureName + "' should not produce any findings, but got: " + result.getFindings(),
                result.hasFindings());
    }
}