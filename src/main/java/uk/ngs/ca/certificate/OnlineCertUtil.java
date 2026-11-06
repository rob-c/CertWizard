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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import uk.ngs.ca.common.CaHttpResponse;

/**
 * Common utility methods for processing CSR new and renew requests.
 *
 * @author David Meredith
 */
public class OnlineCertUtil {

    private static final Logger logger = LogManager.getLogger(OnlineCertUtil.class);

    /**
     * Try and parse the server error response XML doc (if any) and return a
     * message.
     */
    public static String getServerErrorMessage(CaHttpResponse response) {
        int status = response.getStatusCode();
        if (status == 202) {
            // 202 - This means that the server understood the request, but 
            // there were errors/problems. In this scenario, the server sends 
            // back an XML document that wraps the cause. 
            try {
                Document responseDoc = response.getBodyAsXml();
                if (responseDoc != null) {
                    NodeList allTextNodes = responseDoc.getElementsByTagName("text");
                    if (allTextNodes != null) {
                        Node node_minor_text = allTextNodes.item(1);
                        if (node_minor_text != null) {
                            return node_minor_text.getTextContent();
                        }
                    }
                }
            } catch (Exception ex) {
                logger.warn("Could not parse server error response XML doc", ex);
            }
        } else if (status == 404) {
            //404
            return "There is no such service. Please check system configure file.";
        } else if (status == 403) {
            //403
            return "Failed authentication. Please contact the helpdesk";
        } else if (status == 405) {
            //405
            return "Server does not support POST.";
        } else {
            return "A problem occurred submitting the request. Please contact the helpdesk.";
        }
        return "";
    }
}
