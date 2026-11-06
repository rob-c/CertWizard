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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import uk.ngs.ca.certificate.OnlineCertUtil;
import uk.ngs.ca.common.CaHttpClient;
import uk.ngs.ca.common.CaHttpException;
import uk.ngs.ca.common.CaHttpRequest;
import uk.ngs.ca.common.CaHttpResponse;
import uk.ngs.ca.common.SafeXml;
import uk.ngs.ca.tools.property.SysProperty;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Date;

import static uk.ngs.ca.common.CertUtil.asciiToHex;
import static uk.ngs.ca.common.CertUtil.getPrivateExponent;

/**
 * @author xw75 (Xiao Wang)
 */
public class RevokeRequest {

    private final String REVOKEURL = SysProperty.getValue("uk.ngs.ca.request.revoke.url");
    private long cert_id = -1;
    private String reason = null;
    private String MESSAGE = null;
    private final PrivateKey privateKey;

    public RevokeRequest(PrivateKey privateKey, long cert_id, String reason) {
        this.privateKey = privateKey;
        this.cert_id = cert_id;
        this.reason = reason;
    }

    public String getMessage() {
        return this.MESSAGE;
    }

    public boolean doPosts() {
        CaHttpRequest request = CaHttpRequest.post(REVOKEURL)
                .xmlBody(getRepresentation())
                .header("PPPK", "this is pppk")
                .build();

        CaHttpResponse response;
        try {
            response = CaHttpClient.getDefault().send(request);
        } catch (IOException ex) {
            this.MESSAGE = CaHttpException.challengeFailureMessage("revocation request", ex);
            return false;
        }

        //we will do second post
        if (response.getStatusCode() == 401) {
            String _realmP = response.getHeader("realm");
            String _nonceP = response.getHeader("nonce");
            String _keyidP = response.getHeader("keyid");
            String _opaqueP = response.getHeader("opaque");

            //we will do the response action from here.
            if (_opaqueP == null) {
                if (_nonceP == null || _keyidP == null) {
                    throw new IllegalStateException("Expected nonce and keyid headers from server");
                }
                String _keyid = _keyidP;
                int index = _keyid.indexOf(".");
                String m = _keyid.substring(0, index).toUpperCase();
                BigInteger q = getPrivateExponent(privateKey);

                String _nonce = _nonceP + ":" + new Date().getTime();
                _nonce = _nonce.toLowerCase();
                String c = asciiToHex(_nonce);
                c = c.toUpperCase();

                BigInteger b_c = new BigInteger(c, 16);
                BigInteger b_m = new BigInteger(m, 16);
                BigInteger b_response = b_c.modPow(q, b_m);
                String _response = b_response.toString(16);

                request = CaHttpRequest.post(REVOKEURL)
                        .xmlBody(getRepresentation())
                        .header("PPPK", "this is pppk")
                        .header("keyid", _keyid)
                        .header("realm", _realmP)
                        .header("response", _response)
                        .build();

            } else {
                //we will do cookie thing from here
                request = CaHttpRequest.post(REVOKEURL)
                        .xmlBody(getRepresentation())
                        .header("PPPK", "this is pppk")
                        .header("opaque", _opaqueP)
                        .build();
            }
            try {
                response = CaHttpClient.getDefault().send(request);
            } catch (IOException ex) {
                this.MESSAGE = CaHttpException.submissionFailureMessage("revocation request", ex);
                return false;
            }

            if (response.getStatusCode() == 201) {
                return true;   // 201
            } else {
                this.MESSAGE = OnlineCertUtil.getServerErrorMessage(response);
                return false;
            }

        } else {
            this.MESSAGE = "There appears to be a problem with submitting the revocation request.\n"
                    + "This could be either due to networking problems you are having or \n"
                    + "problem in the e-Science CA Server. If your connection is already up but still \n"
                    + "unable to complete the revocation submission, please contact the helpdesk.";
            return false;
        }
    }

    private Document getRepresentation() {
        String id = Long.toString(cert_id);
        Document d = SafeXml.newDocument();

        Element rootElement = d.createElement("Revoke");
        d.appendChild(rootElement);

        Element idElement = d.createElement("id");
        Element reasonElement = d.createElement("reason");
        idElement.appendChild(d.createTextNode(id));
        reasonElement.appendChild(d.createTextNode(this.reason));

        rootElement.appendChild(idElement);
        rootElement.appendChild(reasonElement);

        d.normalizeDocument();
        return d;
    }

}
