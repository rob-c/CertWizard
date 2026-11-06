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
package uk.ngs.ca.certificate.client;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.w3c.dom.Document;
import uk.ngs.ca.common.CaHttpClient;
import uk.ngs.ca.common.CaHttpRequest;
import uk.ngs.ca.common.CaHttpResponse;
import uk.ngs.ca.tools.property.SysProperty;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * @author xw75
 */
public class CertificateDownload {

    private static final Logger logger = LogManager.getLogger(CertificateDownload.class);

    Document document = null;

    public CertificateDownload(String certID) {
        try {
            String certURL = SysProperty.getValue("uk.ngs.ca.request.certificate.url");
            certURL = certURL + "/" + certID;
            CaHttpResponse response = CaHttpClient.getDefault().send(CaHttpRequest.get(certURL).build());
            document = response.getBodyAsXml();
        } catch (Exception ep) {
            logger.warn("Certificate download failed: " + ep.getMessage());
        }
    }

    public X509Certificate getCertificate() {
        X509Certificate certificate = null;
        if (document == null) {
            return null; // the download failed (already logged)
        }
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/certificate/X509Certificate");

            String result = (String) expr.evaluate(document, XPathConstants.STRING);

            InputStream inputStream = new ByteArrayInputStream(result.getBytes());

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            certificate = (X509Certificate) cf.generateCertificate(inputStream);
            inputStream.close();
        } catch (Exception ep) {
            logger.warn("Could not read the downloaded certificate: " + ep.getMessage());
        }
        return certificate;
    }

}
