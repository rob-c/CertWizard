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
package uk.ngs.ca.info;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import uk.ngs.ca.common.CaHttpClient;
import uk.ngs.ca.common.CaHttpRequest;
import uk.ngs.ca.common.CaHttpResponse;
import uk.ngs.ca.tools.property.SysProperty;

import javax.xml.xpath.*;
import java.io.IOException;
import java.util.ArrayList;

/**
 * Retrieves CA information when calling <tt>/CA</tt> Rest resource.
 *
 * @author xw75 (Xiao Wang)
 * @author David Meredith (some small modification, javadoc, lots to refactor
 * still)
 */
public class CAInfo {

    final String CAURL = SysProperty.getValue("uk.ngs.ca.request.ca.url");
    private final Document document;

    /**
     * Create a new CAInfo instance and call the CA server.
     *
     * @throws IOException If the remote call to fetch the RA list fails
     */
    public CAInfo() throws IOException {
        CaHttpRequest request = CaHttpRequest.get(CAURL)
                .header("PPPK", "this is pppk")
                .build();
        CaHttpResponse response = CaHttpClient.getDefault().send(request);
        if (response.getStatusCode() != 200) {
            throw new IOException("Could not fetch the RA list: the CA server responded "
                    + response.getStatusDescription());
        }
        try {
            document = response.getBodyAsXml();
        } catch (IOException ex) {
            throw new IllegalStateException("Could not parse CAInfo response", ex); // coding error
        }
    }

    /**
     * @return the list of RAs fetched from the server.
     */
    public String[] getRAs() {
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/CA/RAlist/ra");
            NodeList raLists = (NodeList) expr.evaluate(document, XPathConstants.NODESET);
            ArrayList<String> RAs = new ArrayList<>();
            for (int i = 0; i < raLists.getLength(); i++) {
                Element raElement = (Element) raLists.item(i);
                NodeList ouLists = raElement.getElementsByTagName("ou");
                Element ouElement = (Element) ouLists.item(0);
                String ou = ouElement.getFirstChild().getNodeValue();

                NodeList lLists = raElement.getElementsByTagName("l");
                Element lElement = (Element) lLists.item(0);
                String l = lElement.getFirstChild().getNodeValue();

                if (ou != null && l != null) {
                    String RA = ou.trim() + " " + l.trim();
                    RAs.add(RA);
                }
            }
            //Arrays.sort(RAs); // do not sort, we need to preserve the order returned from server 
            return RAs.toArray(new String[0]);
        } catch (XPathExpressionException ex) {
            throw new IllegalStateException("Problem parsing RAList", ex); // coding error
        }
    }
}
