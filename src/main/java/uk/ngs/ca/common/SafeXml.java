/*
 * CertWizard - UK eScience CA Certificate Management Client
 * Copyright (C) 2021 UKRI-STFC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package uk.ngs.ca.common;

import org.w3c.dom.Document;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * XML parsing and serialisation for CA server documents, hardened against
 * XXE: DOCTYPE declarations are rejected outright, and external entities,
 * external DTDs/schemas and XInclude are all disabled.
 */
public final class SafeXml {

    private SafeXml() {
    }

    /** A new, empty DOM document for building request bodies. */
    public static Document newDocument() {
        try {
            return newBuilder().newDocument();
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException("Cannot create XML document builder", e);
        }
    }

    /**
     * Parse an XML document.
     *
     * @param bytes    raw document bytes
     * @param charset  charset from the Content-Type header, or null to let the
     *                 parser detect it from the BOM / XML declaration
     * @throws IOException if the bytes are not a well-formed (DOCTYPE-free)
     *                     XML document
     */
    public static Document parse(byte[] bytes, String charset) throws IOException {
        InputSource source = new InputSource(new ByteArrayInputStream(bytes));
        if (charset != null) {
            source.setEncoding(charset);
        }
        try {
            return newBuilder().parse(source);
        } catch (SAXException e) {
            throw new IOException("Could not parse XML response from the CA server: " + e.getMessage(), e);
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException("Cannot create XML document builder", e);
        }
    }

    /**
     * Serialise a DOM document exactly as the original Restlet
     * DomRepresentation did: XML declaration with UTF-8 encoding and
     * {@code standalone="no"}, no indentation.
     */
    public static byte[] serialize(Document document) {
        try {
            TransformerFactory tf = TransformerFactory.newInstance();
            tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
            Transformer transformer = tf.newTransformer();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            transformer.transform(new DOMSource(document), new StreamResult(out));
            return out.toByteArray();
        } catch (TransformerException e) {
            throw new IllegalStateException("Cannot serialise XML document", e);
        }
    }

    private static DocumentBuilder newBuilder() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        dbf.setNamespaceAware(false);
        dbf.setValidating(false);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        // Report problems only through the thrown exception (the default
        // handler also prints "[Fatal Error]" lines to stderr).
        builder.setErrorHandler(new ErrorHandler() {
            @Override
            public void warning(SAXParseException e) {
            }

            @Override
            public void error(SAXParseException e) throws SAXException {
                throw e;
            }

            @Override
            public void fatalError(SAXParseException e) throws SAXException {
                throw e;
            }
        });
        return builder;
    }
}
