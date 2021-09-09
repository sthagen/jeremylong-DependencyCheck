/*
 * This file is part of dependency-check-maven.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.maven;

import java.io.File;
import java.lang.reflect.Field;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import mockit.Mock;
import mockit.MockUp;
import mockit.Tested;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.testing.stubs.ArtifactStub;
import org.apache.maven.project.MavenProject;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import org.junit.Assume;
import org.junit.Test;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.exception.ExceptionCollection;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;

/**
 *
 * @author Jeremy Long
 */
public class BaseDependencyCheckMojoTest extends BaseTest {

    @Tested
    MavenProject project;

    /**
     * Checks if the test can be run. The test in this class fail, presumable
     * due to jmockit, if the JDK is 1.8+.
     *
     * @return true if the JDK is below 1.8.
     */
    public boolean canRun() {
        String version = System.getProperty("java.version");
        int firstDot = version.indexOf('.');
        if (firstDot < 0) {
            // new java.version format, so Java 9 or above
            return false;
        }
        int secondDot = version.indexOf('.', firstDot+1);
        if (secondDot < 0) {
            // new java.version format, so Java 9 or above
            return false;
        }
        version = version.substring(0, secondDot);

        double v = Double.parseDouble(version);
        return v == 1.7;
    }

    /**
     * Test of scanArtifacts method, of class BaseDependencyCheckMojo.
     */
    @Test
    public void testScanArtifacts() throws DatabaseException, InvalidSettingException {
        new MockUp<MavenProject>() {
            @Mock
            public Set<Artifact> getArtifacts() {
                Set<Artifact> artifacts = new HashSet<>();
                Artifact a = new ArtifactStub();
                try {
                    File file = new File(Test.class.getProtectionDomain().getCodeSource().getLocation().toURI());
                    a.setFile(file);
                    artifacts.add(a);
                } catch (URISyntaxException ex) {
                    Logger.getLogger(BaseDependencyCheckMojoTest.class.getName()).log(Level.SEVERE, null, ex);
                }
                //File file = new File(this.getClass().getClassLoader().getResource("daytrader-ear-2.1.7.ear").getPath());

                return artifacts;
            }

            @Mock
            public String getName() {
                return "test-project";
            }
        };

        if (canRun()) {
            boolean autoUpdate = getSettings().getBoolean(Settings.KEYS.AUTO_UPDATE);
            getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, false);
            try (Engine engine = new Engine(getSettings())) {
                getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, autoUpdate);

                assertTrue(engine.getDependencies().length == 0);
                BaseDependencyCheckMojoImpl instance = new BaseDependencyCheckMojoImpl();
                ExceptionCollection exCol = null;
                try { //the mock above fails under some JDKs
                    exCol = instance.scanArtifacts(project, engine);
                } catch (NullPointerException ex) {
                    Assume.assumeNoException(ex);
                }
                assertNull(exCol);
                assertFalse(engine.getDependencies().length == 0);
            }
        }
    }

    @Test
    public void should_newDependency_get_pom_from_base_dir() {
        // Given
        BaseDependencyCheckMojo instance = new BaseDependencyCheckMojoImpl();

        new MockUp<MavenProject>() {
            @Mock
            public File getBasedir() {
                return new File("src/test/resources/maven_project_base_dir");
            }
        };

        String expectOutput = "pom.xml";

        // When
        String output = instance.newDependency(project).getFileName();

        // Then
        assertEquals(expectOutput, output);
    }

    @Test
    public void should_newDependency_get_default_virtual_dependency() {
        // Given
        BaseDependencyCheckMojo instance = new BaseDependencyCheckMojoImpl();

        new MockUp<MavenProject>() {
            @Mock
            public File getBasedir() {
                return new File("src/test/resources/dir_without_pom");
            }

            @Mock
            public File getFile() {
                return new File("src/test/resources/dir_without_pom");
            }
        };

        // When
        String output = instance.newDependency(project).getFileName();

        // Then
        assertNull(output);
    }

    @Test
    public void should_newDependency_get_pom_declared_as_module() {
        // Given
        BaseDependencyCheckMojo instance = new BaseDependencyCheckMojoImpl();

        new MockUp<MavenProject>() {
            @Mock
            public File getBasedir() {
                return new File("src/test/resources/dir_containing_maven_poms_declared_as_modules_in_another_pom");
            }

            @Mock
            public File getFile() {
                return new File("src/test/resources/dir_containing_maven_poms_declared_as_modules_in_another_pom/serverlibs.pom");
            }
        };

        String expectOutput = "serverlibs.pom";

        // When
        String output = instance.newDependency(project).getFileName();

        // Then
        assertEquals(expectOutput, output);
    }

    /**
     * Implementation of ODC Mojo for testing.
     */
    public static class BaseDependencyCheckMojoImpl extends BaseDependencyCheckMojo {

        @Override
        protected void runCheck() throws MojoExecutionException, MojoFailureException {
            throw new UnsupportedOperationException("Operation not supported");
        }

        @Override
        public String getName(Locale locale) {
            return "test implementation";
        }

        @Override
        public String getDescription(Locale locale) {
            return "test implementation";
        }

        @Override
        public boolean canGenerateReport() {
            throw new UnsupportedOperationException("Operation not supported");
        }

        @Override
        protected ExceptionCollection scanDependencies(Engine engine) throws MojoExecutionException {
            throw new UnsupportedOperationException("Operation not supported");
        }
    }

    @Test
    public void testPopulateSettingsShouldSetDefaultValueToCveUrlModified() throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
      // Given
      System.clearProperty(Settings.KEYS.CVE_MODIFIED_JSON);
      System.clearProperty(Settings.KEYS.CVE_BASE_JSON);

      BaseDependencyCheckMojo instance = new BaseDependencyCheckMojoImpl();

      Field cveUrlModified = instance.getClass().getSuperclass().getDeclaredField("cveUrlModified");
      cveUrlModified.setAccessible(true);
      cveUrlModified.set(instance, null);

      Field cveUrlBase = instance.getClass().getSuperclass().getDeclaredField("cveUrlBase");
      cveUrlBase.setAccessible(true);
      cveUrlBase.set(instance, "https://my-custom-mirror-of-nvd/feeds/json/cve/1.1/nvdcve-1.1-%d.json.gz");

      org.apache.maven.settings.Settings mavenSettings = new org.apache.maven.settings.Settings();
      Field mavenSettingsField = instance.getClass().getSuperclass().getDeclaredField("mavenSettings");
      mavenSettingsField.setAccessible(true);
      mavenSettingsField.set(instance, mavenSettings);

      // When
      instance.populateSettings();

      // Then
      String output = instance.getSettings().getString(Settings.KEYS.CVE_MODIFIED_JSON);
      String expectedOutput = "https://my-custom-mirror-of-nvd/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz";
      assertThat("cveUrlModified must be set to a default of the same model", output, is(expectedOutput));
    }

    @Test
    public void testPopulateSettingsShouldSetDefaultValueToCveUrlModifiedWhenCveUrlModifiedIsEmpty() throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
      // Given
      System.clearProperty(Settings.KEYS.CVE_MODIFIED_JSON);
      System.clearProperty(Settings.KEYS.CVE_BASE_JSON);

      BaseDependencyCheckMojo instance = new BaseDependencyCheckMojoImpl();

      Field cveUrlModified = instance.getClass().getSuperclass().getDeclaredField("cveUrlModified");
      cveUrlModified.setAccessible(true);
      cveUrlModified.set(instance, "");

      Field cveUrlBase = instance.getClass().getSuperclass().getDeclaredField("cveUrlBase");
      cveUrlBase.setAccessible(true);
      cveUrlBase.set(instance, "https://my-custom-mirror-of-nvd/feeds/json/cve/1.1/nvdcve-1.1-%d.json.gz");

      org.apache.maven.settings.Settings mavenSettings = new org.apache.maven.settings.Settings();
      Field mavenSettingsField = instance.getClass().getSuperclass().getDeclaredField("mavenSettings");
      mavenSettingsField.setAccessible(true);
      mavenSettingsField.set(instance, mavenSettings);

      // When
      instance.populateSettings();

      // Then
      String output = instance.getSettings().getString(Settings.KEYS.CVE_MODIFIED_JSON);
      String expectedOutput = "https://my-custom-mirror-of-nvd/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz";
      assertThat("cveUrlModified must be set to a default of the same model when arg is empty", output, is(expectedOutput));
    }

    @Test
    public void testPopulateSettingsShouldNotSetDefaultValueToCveUrlModifiedWhenValueIsExplicitelySet() throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
      // Given
      System.clearProperty(Settings.KEYS.CVE_MODIFIED_JSON);
      System.clearProperty(Settings.KEYS.CVE_BASE_JSON);

      BaseDependencyCheckMojo instance = new BaseDependencyCheckMojoImpl();

      Field cveUrlModified = instance.getClass().getSuperclass().getDeclaredField("cveUrlModified");
      cveUrlModified.setAccessible(true);
      cveUrlModified.set(instance, "https://another-custom-mirror-of-nvd/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz");

      Field cveUrlBase = instance.getClass().getSuperclass().getDeclaredField("cveUrlBase");
      cveUrlBase.setAccessible(true);
      cveUrlBase.set(instance, "https://my-custom-mirror-of-nvd/feeds/json/cve/1.1/some-unusual-file-name-%d.json.gz");

      org.apache.maven.settings.Settings mavenSettings = new org.apache.maven.settings.Settings();
      Field mavenSettingsField = instance.getClass().getSuperclass().getDeclaredField("mavenSettings");
      mavenSettingsField.setAccessible(true);
      mavenSettingsField.set(instance, mavenSettings);

      // When
      instance.populateSettings();

      // Then
      String output = instance.getSettings().getString(Settings.KEYS.CVE_MODIFIED_JSON);
      String expectedOutput = "https://another-custom-mirror-of-nvd/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz";
      assertThat("cveUrlModified must be set to the specified value", output, is(expectedOutput));
    }

    @Test
    public void testPopulateSettingsShouldNotSetDefaultValueToCveUrlModifiedWhenUnknownValueIsSet() throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
      // Given
      System.clearProperty(Settings.KEYS.CVE_MODIFIED_JSON);
      System.clearProperty(Settings.KEYS.CVE_BASE_JSON);

      BaseDependencyCheckMojo instance = new BaseDependencyCheckMojoImpl();

      Field cveUrlModified = instance.getClass().getSuperclass().getDeclaredField("cveUrlModified");
      cveUrlModified.setAccessible(true);
      cveUrlModified.set(instance, null);

      Field cveUrlBase = instance.getClass().getSuperclass().getDeclaredField("cveUrlBase");
      cveUrlBase.setAccessible(true);
      cveUrlBase.set(instance, "https://my-custom-mirror-of-nvd/feeds/json/cve/1.1/some-unusual-file-name-%d.json.gz");

      org.apache.maven.settings.Settings mavenSettings = new org.apache.maven.settings.Settings();
      Field mavenSettingsField = instance.getClass().getSuperclass().getDeclaredField("mavenSettings");
      mavenSettingsField.setAccessible(true);
      mavenSettingsField.set(instance, mavenSettings);

      // When
      instance.populateSettings();

      // Then
      String output = instance.getSettings().getString(Settings.KEYS.CVE_MODIFIED_JSON);
      String expectedOutput = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz";
      assertThat("cveUrlModified must not be set when name is not the same as from the nvd datasource", output, is(expectedOutput));
    }
}
