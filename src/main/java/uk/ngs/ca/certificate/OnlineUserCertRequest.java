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
package uk.ngs.ca.certificate;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import uk.ngs.ca.common.CaHttpClient;
import uk.ngs.ca.common.CaHttpException;
import uk.ngs.ca.common.CaHttpRequest;
import uk.ngs.ca.common.CaHttpResponse;
import uk.ngs.ca.common.SafeXml;
import uk.ngs.ca.tools.property.SysProperty;

import java.io.IOException;

/**
 * @author xw75 (Xiao Wang)
 */
public class OnlineUserCertRequest {

    private final String CSRURL = SysProperty.getValue("uk.ngs.ca.request.csr.url");
    private String MESSAGE = "";
    private boolean isCSRRequestSuccess = false;

    public OnlineUserCertRequest(String csrString, String pin, String email) {
        CaHttpRequest request = CaHttpRequest.post(CSRURL)
                .xmlBody(getRepresentation(csrString, pin, email))
                .build();

        CaHttpResponse response;
        try {
            response = CaHttpClient.getDefault().send(request);
        } catch (IOException ex) {
            MESSAGE = CaHttpException.submissionFailureMessage("certificate request", ex);
            isCSRRequestSuccess = false;
            return;
        }

        if (response.getStatusCode() == 201) {
            MESSAGE = "Your CSR has been submitted to the CA server successfully. \nIt is waiting for the approval and signing by an RA and CA operator.";
            isCSRRequestSuccess = true;
        } else if (response.getStatusCode() == 202) {
            try {
                MESSAGE = _getFormattedMessage(response);
                isCSRRequestSuccess = false;
            } catch (Exception ep) {
                ep.printStackTrace();
            }
        } else {

            MESSAGE = "A problem occurred during the submission process. This could be due to a Server side problem.\n"
                    + "Please try again later. If the problem persists, please contact the helpdesk support at \n"
                    + "support@grid-support.ac.uk";
            isCSRRequestSuccess = false;
        }
    }

    private String _getFormattedMessage(CaHttpResponse response) {
        String message = "";

        try {
            Document document = response.getBodyAsXml();
            document.getDocumentElement().normalize();
            NodeList nodeLst = document.getElementsByTagName("minor");

            for (int s = 0; s < nodeLst.getLength(); s++) {

                Node fstNode = nodeLst.item(s);

                if (fstNode.getNodeType() == Node.ELEMENT_NODE) {

                    Element fstElmnt = (Element) fstNode;
                    NodeList fstNmElmntLst = fstElmnt.getElementsByTagName("text");

                    Element fstNmElmnt = (Element) fstNmElmntLst.item(0);
                    NodeList fstNm = fstNmElmnt.getChildNodes();

                    message = (fstNm.item(0).getNodeValue());
                }
            }

            return message;
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }

    }

    public String getMessage() {
        return MESSAGE;
    }

    public boolean isCSRREquestSuccess() {
        return isCSRRequestSuccess;
    }

    private Document getRepresentation(String csrString, String pin, String email) {
        Document d = SafeXml.newDocument();

        Element rootElement = d.createElement("CSR");
        d.appendChild(rootElement);

        Element eltName = d.createElement("Request");
        eltName.appendChild(d.createTextNode(csrString));
        rootElement.appendChild(eltName);

        eltName = d.createElement("PIN");
        eltName.appendChild(d.createTextNode(pin));
        rootElement.appendChild(eltName);

        eltName = d.createElement("Email");
        eltName.appendChild(d.createTextNode(email));
        rootElement.appendChild(eltName);

        String _version = SysProperty.getValue("ngsca.certwizard.version");
        eltName = d.createElement("Version");
        eltName.appendChild(d.createTextNode(_version));
        rootElement.appendChild(eltName);

        d.normalizeDocument();
        return d;
    }
}
