/*
 * This file is part of dependency-check-core.
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
 * Copyright (c) 2018 Nicolas Henneaux. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.artifactory;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Settings;

import java.net.UnknownHostException;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ArtifactorySearchTest extends BaseTest {
    private static String httpsProxyHostOrig;
    private static String httpsPortOrig;

    @BeforeAll
    static void tinkerProxies() {
        httpsProxyHostOrig = System.getProperty("https.proxyHost");
        if (httpsProxyHostOrig == null) {
            httpsProxyHostOrig = System.getenv("https.proxyHost");
        }
        httpsPortOrig = System.getProperty("https.proxyPort");
        if (httpsPortOrig == null) {
            httpsPortOrig = System.getenv("https.proxyPort");
        }
        System.setProperty("https.proxyHost", "");
        System.setProperty("https.proxyPort", "");
    }

    @AfterAll
    static void restoreProxies() {
        if (httpsProxyHostOrig != null) {
            System.setProperty("https.proxyHost", httpsProxyHostOrig);
        }
        if (httpsPortOrig != null) {
            System.setProperty("https.proxyPort", httpsPortOrig);
        }
    }

    @BeforeEach
    @Override
    public void setUp() throws Exception {
        super.setUp();
    }


    @Test
    void shouldFailWhenHostUnknown() {
        // Given
        Dependency dependency = new Dependency();
        dependency.setSha1sum("c5b4c491aecb72e7c32a78da0b5c6b9cda8dee0f");
        dependency.setSha256sum("512b4bf6927f4864acc419b8c5109c23361c30ed1f5798170248d33040de068e");
        dependency.setMd5sum("2d1dd0fc21ee96bccfab4353d5379649");

        final Settings settings = getSettings();
        settings.setString(Settings.KEYS.ANALYZER_ARTIFACTORY_URL, "https://artifactory.techno.ingenico.com.invalid/artifactory");
        final ArtifactorySearch artifactorySearch = new ArtifactorySearch(settings);
        // When
        UnknownHostException exception = assertThrows(UnknownHostException.class, () -> artifactorySearch.search(dependency),
                "Should have thrown an UnknownHostException");

        // Then
        assertNotNull(exception.getMessage());
        assertTrue(exception.getMessage().contains("artifactory.techno.ingenico.com.invalid"));
    }

}
