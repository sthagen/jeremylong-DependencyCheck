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
 * Copyright (c) 2018 Paul Irwin. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nuget;

import org.owasp.dependencycheck.utils.XmlUtils;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import org.owasp.dependencycheck.utils.InterpolationUtil;
import org.owasp.dependencycheck.utils.InterpolationUtil.SyntaxStyle;

/**
 * Parses a nuget's Directory.Packages.props file using XPath.
 *
 * @author Jeremy Long
 */
public class DirectoryPackagesPropsParser {

    /**
     * Parses the given stream for Directory.Packages.props elements.
     *
     * @param stream the input stream to parse
     * @param props the Directory.Build.props properties
     * @return a collection of discovered NuGet package references
     * @throws MSBuildProjectParseException if an exception occurs
     */
    public Map<String, String> parse(InputStream stream, Properties props) throws MSBuildProjectParseException {
        try {
            final DocumentBuilder db = XmlUtils.buildSecureDocumentBuilder();
            final Document d = db.parse(stream);

            final XPath xpath = XPathFactory.newInstance().newXPath();
            final Map<String, String> packages = new HashMap<>();
            final Node centralNode = (Node) xpath.evaluate("/Project/PropertyGroup/ManagePackageVersionsCentrally", d, XPathConstants.NODE);
            if (centralNode != null && centralNode.getChildNodes().getLength() == 1) {
                final String val = centralNode.getChildNodes().item(0).getNodeValue();
                if (!"true".equalsIgnoreCase(val)) {
                    return packages;
                }
            } else {
                return packages;
            }
            final NodeList nodeList = (NodeList) xpath.evaluate("//PackageVersion", d, XPathConstants.NODESET);

            if (nodeList == null) {
                throw new MSBuildProjectParseException("Unable to parse Directory.Packages.props file");
            }

            for (int i = 0; i < nodeList.getLength(); i++) {
                final Node node = nodeList.item(i);
                final NamedNodeMap attrs = node.getAttributes();

                final Node includeAttr = attrs.getNamedItem("Include");
                if (includeAttr == null) {
                    // Issue 5144 work-around for NPE on packageReferences other than includes
                    continue;
                }
                final String include = includeAttr.getNodeValue();
                String version = null;

                if (attrs.getNamedItem("Version") != null) {
                    version = attrs.getNamedItem("Version").getNodeValue();
                } else if (xpath.evaluate("Version", node, XPathConstants.NODE) instanceof Node) {
                    version = ((Node) xpath.evaluate("Version", node, XPathConstants.NODE)).getTextContent();
                }

                if (include != null && version != null) {
                    version = InterpolationUtil.interpolate(version, props, SyntaxStyle.MSBUILD);
                    packages.put(include, version);
                }
            }

            return packages;
        } catch (ParserConfigurationException | SAXException | IOException | XPathExpressionException | MSBuildProjectParseException e) {
            throw new MSBuildProjectParseException("Unable to parse Directory.Packages.props file", e);
        }
    }

}
