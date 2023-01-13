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
 * Copyright (c) 2023 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.dependency;

import java.io.Serializable;

/**
 * POJO to store a reference to the "included by" node in a dependency tree;
 * where included by is the root node that caused a dependency to be included.
 *
 * @author Jeremy Long
 */
public class IncludedByReference implements Serializable {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 4339975160204621746L;

    /**
     * The reference.
     */
    private final String reference;
    /**
     * The reference's type.
     */
    private final String type;

    /**
     * Constructs a new reference.
     *
     * @param reference the reference
     * @param type the reference's type
     */
    public IncludedByReference(String reference, String type) {
        this.reference = reference;
        this.type = type;
    }

    /**
     * Get the value of reference.
     *
     * @return the value of reference
     */
    public String getReference() {
        return reference;
    }

    /**
     * Get the value of type.
     *
     * @return the value of type
     */
    public String getType() {
        return type;
    }

}
