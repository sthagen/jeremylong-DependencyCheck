/*
 * This file is part of dependency-check-ant.
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
 * Copyright (c) 2021 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import java.util.Objects;

/**
 * Default implementation of a {@code CveUrlParser}.
 *
 * @author nhumblot
 *
 */
public final class DefaultCveUrlModifiedParser implements CveUrlParser {

    /**
     * The URL separator character.
     */
    private static final String URL_SEPARATOR = "/";
    /**
     * The configured ODC settings.
     */
    private final Settings settings;

    /**
     * Constructs the default CVE Modified URL parser.
     *
     * @param settings the configured settings
     */
    DefaultCveUrlModifiedParser(Settings settings) {
        this.settings = settings;
    }

    @Override
    public String getDefaultCveUrlModified(String baseUrl) {
        final String defaultBaseUrlEnd = URL_SEPARATOR + settings.getString(Settings.KEYS.CVE_BASE_DEFAULT_FILENAME);
        if (Objects.nonNull(baseUrl) && baseUrl.endsWith(defaultBaseUrlEnd)) {
            final String defaultModifiedUrlEnd = URL_SEPARATOR + settings.getString(Settings.KEYS.CVE_MODIFIED_DEFAULT_FILENAME);
            return baseUrl.substring(0, baseUrl.length() - defaultBaseUrlEnd.length()) + defaultModifiedUrlEnd;
        }
        return null;
    }
}
