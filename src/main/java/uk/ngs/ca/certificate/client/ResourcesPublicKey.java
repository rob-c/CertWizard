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
import org.w3c.dom.Element;
import uk.ngs.ca.common.CaHttpClient;
import uk.ngs.ca.common.CaHttpRequest;
import uk.ngs.ca.common.CaHttpResponse;
import uk.ngs.ca.common.EncryptUtil;
import uk.ngs.ca.common.SafeXml;
import uk.ngs.ca.tools.property.SysProperty;

import java.security.PublicKey;

/**
 * @author xw75 Xiao Wang
 */
public class ResourcesPublicKey {

    private static final Logger logger = LogManager.getLogger(ResourcesPublicKey.class);

    /* 
     * Returned Document has the form:
     <resources>
       <resource>
        <publickey>+z8uM1DvrAKc3VRSFmY7M/Whr9OTbuqv0AInjw4s6aVm/QG1EPU3pFwIDAQAB...elided...</publickey>
        <CSRs>
        </CSRs>
            <certificates>
              <certificate>
                <id>3510</id>
                <X509Certificate>-----BEGIN CERTIFICATE-----...elided...-----END CERTIFICATE-----</X509Certificate>
                <status>VALID</status>
                <useremail>some.body@stfc.ac.uk</useremail>
                <role>RA Operator</role>
                <RA><OU>CLRC</OU><L>DL</L></RA>
                <owner>CN=some body,L=DL,OU=CLRC,O=eScienceDev,C=UK</owner>
                <startdate>23/04/2013</startdate>
                <enddate>20/10/2013</enddate>
                <lifedays>171</lifedays>
                <renew>20/10/2013</renew>
              </certificate>
            </certificates>
        <CCRs/>
        <CRRs>...</CRRs>
        </resource>
     </resources>
     */
    private Document document = null;
    private String encodedPublicKey = null;

    public ResourcesPublicKey(PublicKey publicKey) {
        this.encodedPublicKey = EncryptUtil.getEncodedPublicKey(publicKey);
    }

    public boolean isExist() {
        Document _document;
        boolean isExist = false;
        try {

            // call CA server and ask 'do you know about a certficate with this pub key'
            // url = /resources/resource/publickey/<base64encodedpubkey>
            String resourceURL = SysProperty.getValue("uk.ngs.ca.request.resource.publickey");

            // We add a fake public key here as we're maintaining the same API endpoint for backwards compatibility with old clients
            resourceURL = resourceURL + "/pk";

            // A POST only so the key need not go in the URL: the lookup does not
            // change anything on the server, so it may be retried like a GET.
            CaHttpRequest request = CaHttpRequest.post(resourceURL)
                    .xmlBody(getRepresentation(this.encodedPublicKey))
                    .readOnlyQuery()
                    .build();

            CaHttpResponse response = CaHttpClient.getDefault().send(request);
            if (response.getStatusCode() == 200) {
                _document = response.getBodyAsXml();
                this.document = _document;
                isExist = true;
            } else {
                isExist = false;
            }

        } catch (Exception ep) {
            logger.warn("Public key lookup failed: " + ep.getMessage());
        }
        return !isExist;
    }

    public Document getDocument() {
        return this.document;
    }

    private Document getRepresentation(String base64EncodedPublicKey) {
        Document d = SafeXml.newDocument();

        Element rootElement = d.createElement("PublicKey");
        d.appendChild(rootElement);
        rootElement.appendChild(d.createTextNode(base64EncodedPublicKey));

        d.normalizeDocument();
        return d;
    }

}
