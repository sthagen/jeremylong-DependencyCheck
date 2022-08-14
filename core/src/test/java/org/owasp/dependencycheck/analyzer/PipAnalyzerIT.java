package org.owasp.dependencycheck.analyzer;

import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.Assert.assertTrue;

/**
 *
 * @author anupamjuniwal
 */
public class PipAnalyzerIT extends BaseTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(PipAnalyzerIT.class);

    /**
     * The analyzer to test.
     */
    private PipAnalyzer analyzer;

    /**
     * Correctly setup the analyzer for testing.
     *
     * @throws Exception thrown if there is a problem
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        getSettings().setBoolean(Settings.KEYS.ANALYZER_PIP_ENABLED, true);
        analyzer = new PipAnalyzer();
        analyzer.setFilesMatched(true);
        analyzer.initialize(getSettings());
    }

    /**
     * Cleanup the analyzer's temp files, etc.
     *
     * @throws Exception thrown if there is a problem
     */
    @After
    @Override
    public void tearDown() throws Exception {
        if (analyzer != null) {
            getSettings().setBoolean(Settings.KEYS.ANALYZER_PIP_ENABLED, false);
            analyzer.close();
            analyzer = null;
        }
        super.tearDown();
    }

    /**
     * Tests analysis, evidence collected, of class PipAnalyzer.
     *
     * @throws AnalysisException thrown if there is a problem
     */
    @Test
    public void testAnalyzePipAnalyzer() throws AnalysisException{
        try (Engine engine = new Engine(getSettings())) {
            analyzer.prepare(engine);
            final Dependency toScan = new Dependency(BaseTest.getResourceAsFile(this, "requirements.txt"));
            analyzer.analyze(toScan, engine);
            boolean found = false;
            assertTrue("More then 1 dependency should be identified", 1 < engine.getDependencies().length);
            for (Dependency result : engine.getDependencies()) {
                if ("PyYAML".equals(result.getName())) {
                    found = true;
                    assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().contains("PyYAML"));
                    assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("PyYAML"));
                    assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("3.12"));
                    assertTrue(result.isVirtual());
                }
            }
            assertTrue("Expeced to find PyYAML", found);
        } catch (InitializationException ex) {
            //yarn is not installed - skip the test case.
            Assume.assumeNoException(ex);
        }
    }
}
