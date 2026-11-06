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

import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class SafeXmlTest {

    @Test
    public void rejectsExternalEntity() throws Exception {
        File secret = File.createTempFile("certwizard-xxe", ".txt");
        secret.deleteOnExit();
        Files.write(secret.toPath(), "TOP-SECRET".getBytes(StandardCharsets.UTF_8));
        String xml = "<?xml version=\"1.0\"?><!DOCTYPE CA [<!ENTITY xxe SYSTEM \"" + secret.toURI() + "\">]>"
                + "<CA><Motd><text>&xxe;</text></Motd></CA>";
        try {
            SafeXml.parse(xml.getBytes(StandardCharsets.UTF_8), null);
            fail("a DOCTYPE must be rejected");
        } catch (IOException expected) {
            assertFalse(expected.getMessage().contains("TOP-SECRET"));
        }
    }

    @Test
    public void rejectsInternalEntityExpansion() {
        String xml = "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;\">]>"
                + "<lolz>&lol2;</lolz>";
        try {
            SafeXml.parse(xml.getBytes(StandardCharsets.UTF_8), null);
            fail("a DOCTYPE must be rejected");
        } catch (IOException expected) {
            // ok
        }
    }

    @Test
    public void rejectsMalformedXmlWithIOException() {
        try {
            SafeXml.parse("<html><body>503 Service Unavailable".getBytes(StandardCharsets.UTF_8), null);
            fail();
        } catch (IOException expected) {
            assertTrue(expected.getMessage().startsWith("Could not parse XML response"));
        }
    }

    @Test
    public void honoursContentTypeCharset() throws Exception {
        byte[] latin1 = "<CA><ra>Zürich</ra></CA>".getBytes(StandardCharsets.ISO_8859_1);
        Document d = SafeXml.parse(latin1, "ISO-8859-1");
        assertEquals("Zürich", d.getDocumentElement().getTextContent());

        Map<String, List<String>> headers = Collections.singletonMap("Content-Type",
                Collections.singletonList("application/xml; charset=ISO-8859-1"));
        assertEquals("Zürich", new CaHttpResponse(200, headers, latin1).getBodyAsXml().getDocumentElement().getTextContent());
    }

    @Test
    public void detectsEncodingFromDeclarationWithoutCharset() throws Exception {
        byte[] utf8 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CA>Façade</CA>".getBytes(StandardCharsets.UTF_8);
        assertEquals("Façade", SafeXml.parse(utf8, null).getDocumentElement().getTextContent());
    }

    @Test
    public void serialisesLikeRestletDomRepresentation() {
        Document d = SafeXml.newDocument();
        Element root = d.createElement("Revoke");
        d.appendChild(root);
        Element reason = d.createElement("reason");
        reason.appendChild(d.createTextNode("a < b & \"c\""));
        root.appendChild(reason);
        assertEquals("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>"
                        + "<Revoke><reason>a &lt; b &amp; \"c\"</reason></Revoke>",
                new String(SafeXml.serialize(d), StandardCharsets.UTF_8));
    }
}
