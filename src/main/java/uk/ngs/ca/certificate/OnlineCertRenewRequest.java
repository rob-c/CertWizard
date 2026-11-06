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
import uk.ngs.ca.common.*;
import uk.ngs.ca.tools.property.SysProperty;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Locale;
import java.util.Random;

import static uk.ngs.ca.common.CertUtil.asciiToHex;
import static uk.ngs.ca.common.CertUtil.getPrivateExponent;

/**
 * Create a PKCS#10 CSR renewal for the given Host or User cert and send it to
 * the server. Both the renewal cert and its corresponding private key must be
 * provided in order to authenticate the request using the PPPK protocol. The
 * renewal cert is not modified.
 *
 * @author Xiao Wang
 * @author David Meredith (some modifications)
 */
public class OnlineCertRenewRequest {

    public static final String CSRURL = SysProperty.getValue("uk.ngs.ca.request.csr.url");
    public static final String USERAGENT = SysProperty.getValue("uk.ngs.ca.request.useragent");
    //private static final String SIG_ALG = SysProperty.getValue("ngsca.cert.signature.algorithm");

    private final String email;
    private final X509Certificate authAndRenewCert;
    private final PrivateKey authPrivateKey;
    private final String pkcs10String;
    private final String attrOU, attrL, attrCN;

    /**
     * Create a new instance. After creation call {@link #doRenewal() }. No
     * validity checks are performed on the given certificate, it is up to the
     * calling client to test for expiry and yet to be valid.
     *
     * @param authAndRenewCertP The certificate that is to be renewed and used
     *                          for PPPK authentication. The DN of this certificate is extracted and used
     *                          to build the PKCS#10 DN.
     * @param authPrivateKeyP   Certificate private key (used for PPPK
     *                          authentication).
     * @param csrKeyPair        The key pair used to create the PKCS#10 request.
     * @param emailAddressP     Used to specify the email element in the CSR XML
     *                          document and is the email value that will be associated with the renewed
     *                          certificate.
     */
    public OnlineCertRenewRequest(X509Certificate authAndRenewCertP, PrivateKey authPrivateKeyP,
                                  KeyPair csrKeyPair, String emailAddressP) {

        this.authAndRenewCert = authAndRenewCertP;
        this.email = emailAddressP;
        this.authPrivateKey = authPrivateKeyP;
        if (this.authPrivateKey == null) {
            throw new NullPointerException("toRenewPrivateKey is null");
        }

        // Get the DN string from the X509Certificate. 
        // Use authCert.getSubjectX500Principal().toString() to ensure EMAILADDRESS is listed in DN string 
        // (this is not portable: authCert.getSubjectDN().getName() - is denigrated)
        // (this does not provide email attribute in x500: authCert.getSubjectX500Principal().getName()) 
        String dn = this.authAndRenewCert.getSubjectX500Principal().toString();
        dn = CertUtil.prepareDNforOpenCA(dn, true);  // will want to ask the user here.....
        this.attrCN = CertUtil.extractDnAttribute(dn, CertUtil.DNAttributeType.CN);
        this.attrOU = CertUtil.extractDnAttribute(dn, CertUtil.DNAttributeType.OU);
        this.attrL = CertUtil.extractDnAttribute(dn, CertUtil.DNAttributeType.L);

        // Create the PKCS#10 string. 
        CertificateRequestCreator csrCreator = new CertificateRequestCreator(dn, this.email);
        this.pkcs10String = csrCreator.createCertificateRequest(csrKeyPair.getPrivate(), csrKeyPair.getPublic());
    }

    public String getOU() {
        return this.attrOU;
    }

    public String getL() {
        return this.attrL;
    }

    public String getCN() {
        return this.attrCN;
    }

    /**
     * Call the server with the renewal request.
     *
     * @return A Pair object where <tt>Pair.first</tt> indicates if the CSR
     * renew request was successfully processed by the server (true for success
     * otherwise false). <tt>Pair.second</tt> provides a message returned by the
     * server (if any).
     */
    public Pair<Boolean, String> doRenewal() {
        CaHttpResponse response;
        try {
            response = this.doInitialRequest();
        } catch (IOException ex) {
            return Pair.create(false, CaHttpException.challengeFailureMessage("renewal request", ex));
        }
        try {
            return this.respondToPPPKChallenge(response);
        } catch (IOException ex) {
            return Pair.create(false, CaHttpException.submissionFailureMessage("renewal request", ex));
        }
    }

    /**
     * Send the initial request to the PPPK protected <tt>/CSRs</tt> resource.
     *
     * @return The response
     */
    private CaHttpResponse doInitialRequest() throws IOException {
        // First attempt to connect. Add the 'PPPK' header and provide the encoded 
        // public keyid in the request message payload/body. 
        // We subsequently expect a 401 response challenge. 
        CaHttpRequest request = CaHttpRequest.post(CSRURL)
                .xmlBody(getDomRepresentation())
                .header("PPPK", "this is pppk")
                .build();
        return CaHttpClient.getDefault().send(request);
    }

    /**
     * Process the initial response and complete the PPPK 401 challenge.
     *
     * @param response
     * @return A Pair object where <tt>Pair.first</tt> indicates if the CSR
     * request was processed by the server (true for success otherwise false).
     * <tt>Pair.second</tt> provides a message returned by the server (if any).
     */
    private Pair<Boolean, String> respondToPPPKChallenge(CaHttpResponse response) throws IOException {
        // We expect CLIENT_ERROR_UNAUTHORIZED as the response from the intial request. 
        if (response.getStatusCode() != 401) {
            return Pair.create(false, "UNAUTHORIZED");
        }

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
            String m = _keyid.substring(0, index).toUpperCase(Locale.ENGLISH);
            BigInteger q = getPrivateExponent(this.authPrivateKey);

            String _nonce = _nonceP + ":" + new Date().getTime();
            _nonce = _nonce.toLowerCase(Locale.ENGLISH);
            String c = asciiToHex(_nonce);
            c = c.toUpperCase(Locale.ENGLISH);
            BigInteger b_c = new BigInteger(c, 16);
            BigInteger b_m = new BigInteger(m, 16);
            BigInteger b_response = b_c.modPow(q, b_m);
            String _response = b_response.toString(16);

            // The body is rebuilt for the second request; note it carries a
            // new random PIN hash, exactly as the original client did.
            CaHttpRequest request = CaHttpRequest.post(CSRURL)
                    .xmlBody(getDomRepresentation())
                    .header("PPPK", "this is pppk")
                    .header("keyid", _keyid)
                    .header("realm", _realmP)
                    .header("response", _response)
                    .build();
            response = CaHttpClient.getDefault().send(request);

        } else {
            //we will do cookie thing from here
            CaHttpRequest request = CaHttpRequest.post(CSRURL)
                    .xmlBody(getDomRepresentation())
                    .header("PPPK", "this is pppk")
                    .header("opaque", _opaqueP)
                    .build();
            response = CaHttpClient.getDefault().send(request);
        }

        if (response.getStatusCode() == 201) {
            return Pair.create(true, "SUCCESS_CREATED");   // 201 

        } else {
            String detailError = OnlineCertUtil.getServerErrorMessage(response);
            return Pair.create(false, detailError + " [" + response.getStatusDescription() + "]");
        }
    }

    private Document getDomRepresentation() {
        Document d = SafeXml.newDocument();
        Element rootElement = d.createElement("CSR");
        d.appendChild(rootElement);

        Element eltName = d.createElement("Request");
        eltName.appendChild(d.createTextNode(this.pkcs10String));
        rootElement.appendChild(eltName);

        eltName = d.createElement("PIN");
        Random random = new Random();
        String pin = Long.toString(Math.abs(random.nextLong()), 36);
        eltName.appendChild(d.createTextNode(HashUtil.getHash(pin)));
        rootElement.appendChild(eltName);

        eltName = d.createElement("Email");
        eltName.appendChild(d.createTextNode(this.email)); // was getEmail()
        rootElement.appendChild(eltName);

        // We include the keyid string as the <PublicKey> element so that 
        // the server can then issue a 401 response challenge for this pubkey. 
        RSAPublicKey authRSAPublicKey = (RSAPublicKey) this.authAndRenewCert.getPublicKey();
        String modulusString = authRSAPublicKey.getModulus().toString(16);
        String exponentString = authRSAPublicKey.getPublicExponent().toString(16);
        String keyString = modulusString + "." + exponentString;
        eltName = d.createElement("PublicKey");
        eltName.appendChild(d.createTextNode(keyString));
        rootElement.appendChild(eltName);

        String _version = SysProperty.getValue("ngsca.certwizard.version");
        eltName = d.createElement("Version");
        eltName.appendChild(d.createTextNode(_version));
        rootElement.appendChild(eltName);

        d.normalizeDocument();

        return d;
    }
}
