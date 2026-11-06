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
package uk.ngs.ca.wire;

import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import uk.ngs.ca.certificate.OnlineCertRenewRequest;
import uk.ngs.ca.certificate.OnlineHostCertRequest;
import uk.ngs.ca.certificate.OnlineUserCertRequest;
import uk.ngs.ca.certificate.client.CAMotd;
import uk.ngs.ca.certificate.client.CertificateDownload;
import uk.ngs.ca.certificate.client.PingService;
import uk.ngs.ca.certificate.client.ResourcesPublicKey;
import uk.ngs.ca.certificate.client.RevokeRequest;
import uk.ngs.ca.common.EncryptUtil;
import uk.ngs.ca.common.Pair;
import uk.ngs.ca.common.SystemStatus;
import uk.ngs.ca.info.CAInfo;
import uk.ngs.ca.wire.RawHttpCaptureServer.Reply;

import javax.xml.xpath.XPathFactory;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Wire compatibility tests for every CA operation.
 * <p>
 * Each test drives the public client class against a local capture server,
 * compares the request(s) it sends with the golden fixtures recorded from
 * the original Restlet 3.0-M1 implementation (see {@link GoldenFixture} for
 * the comparison rules) and feeds back realistic server responses (several
 * captured from cwiz-live.ca.ngs.ac.uk, plus the server's XML error
 * document) to check that the parsed results are unchanged.
 */
public class WireCompatibilityTest {

    private static final String NONCE = "A1B2C3D4E5F6Nonce";
    private static final String REALM = "UK e-Science CA";
    private static final String OPAQUE = "opaque-cookie-0123456789";

    private RawHttpCaptureServer server;

    @Before
    public void setUp() {
        server = SharedCaptureServer.get();
    }

    // ------------------------------------------------------------------ ping

    @Test
    public void pingOk() throws Exception {
        server.enqueue(ok(response("pingservice.xml")));
        assertTrue(PingService.getPingService().isPingService());
        assertTrue(SystemStatus.getInstance().getIsOnline());
        GoldenFixture.check("ping", server.getCaptured(), false);
    }

    @Test
    public void pingServerError() throws Exception {
        server.enqueue(new Reply(500, "Internal Server Error"));
        assertFalse(PingService.getPingService().isPingService());
        assertFalse(SystemStatus.getInstance().getIsOnline());
        GoldenFixture.check("ping", server.getCaptured(), false);
    }

    // ------------------------------------------------------------------ motd / version

    @Test
    public void motdText() throws Exception {
        server.enqueue(ok(response("ca-motd-text.xml")));
        String text = new CAMotd().getText();
        assertEquals("Welcome to the UKeScience Certificate Authority (CA) API. The latestversion of Certwizard is 2.2.1 "
                + "Thank you for using the UKeScience CA API. This service enables secure and trusted access to digital "
                + "certificates for your e-Science needs across the Grid. If you need assistance or further information, "
                + "please visit our support portal: https://ca.grid-support.ac.uk/", text);
        GoldenFixture.check("motd-text", server.getCaptured(), false);
    }

    @Test
    public void latestVersion() throws Exception {
        server.enqueue(ok(response("ca.xml")));
        assertEquals("2.2.1", new CAMotd().getLatestVersion());
        GoldenFixture.check("ca-latest-version", server.getCaptured(), false);
    }

    @Test
    public void latestVersionNon200() throws Exception {
        server.enqueue(new Reply(503, "Service Unavailable").xml(response("ca.xml")));
        assertEquals("0.0.0", new CAMotd().getLatestVersion());
    }

    // ------------------------------------------------------------------ CA info (RA list)

    @Test
    public void caInfoRaList() throws Exception {
        server.enqueue(ok(response("ca.xml")));
        String[] ras = new CAInfo().getRAs();
        assertEquals(88, ras.length);
        assertEquals("Aberdeen DIT", ras[0]);
        assertEquals("CLRC DL", ras[17]);
        assertEquals("York ITServices", ras[ras.length - 1]);
        GoldenFixture.check("ca-info", server.getCaptured(), false);
    }

    @Test
    public void caInfoUtf8() throws Exception {
        server.enqueue(ok(response("ca-utf8.xml")));
        assertArrayEquals(new String[]{"Zürich Façade", "CLRC DL"}, new CAInfo().getRAs());
        assertEquals("9.1.0", latestVersionFrom("ca-utf8.xml"));
    }

    private String latestVersionFrom(String responseFile) throws IOException {
        server.reset();
        server.enqueue(ok(response(responseFile)));
        return new CAMotd().getLatestVersion();
    }

    // ------------------------------------------------------------------ public key lookup

    @Test
    public void publicKeyLookupFound() throws Exception {
        X509Certificate cert = TestKeyMaterial.authCert();
        server.enqueue(ok(response("resources-publickey.xml")));
        ResourcesPublicKey rpk = new ResourcesPublicKey(cert.getPublicKey());
        // isExist() returns true when the key is NOT known to the CA (historical naming)
        assertFalse(rpk.isExist());
        Document doc = rpk.getDocument();
        assertNotNull(doc);
        assertEquals("4242", XPathFactory.newInstance().newXPath()
                .evaluate("/resources/resource/certificates/certificate/id", doc));
        assertEquals("VALID", XPathFactory.newInstance().newXPath()
                .evaluate("/resources/resource/certificates/certificate/status", doc));
        GoldenFixture.check("public-key-lookup", server.getCaptured(), false);
        // the body carries the base64 SubjectPublicKeyInfo
        assertTrue(server.getCaptured().get(0).bodyAsString()
                .contains("<PublicKey>" + EncryptUtil.getEncodedPublicKey(cert.getPublicKey()) + "</PublicKey>"));
    }

    @Test
    public void publicKeyLookupNotFound() throws Exception {
        server.enqueue(new Reply(404, "Not Found"));
        ResourcesPublicKey rpk = new ResourcesPublicKey(TestKeyMaterial.authCert().getPublicKey());
        assertTrue(rpk.isExist());
        assertNull(rpk.getDocument());
        GoldenFixture.check("public-key-lookup", server.getCaptured(), false);
    }

    // ------------------------------------------------------------------ certificate download

    @Test
    public void certificateDownload() throws Exception {
        server.enqueue(ok(response("certificate.xml")));
        X509Certificate downloaded = new CertificateDownload("4242").getCertificate();
        assertEquals(TestKeyMaterial.authCert(), downloaded);
        GoldenFixture.check("certificate-download", server.getCaptured(), false);
    }

    @Test
    public void certificateDownloadNotFound() throws Exception {
        server.enqueue(new Reply(404, "Not Found"));
        assertNull(new CertificateDownload("4242").getCertificate());
    }

    // ------------------------------------------------------------------ user CSR

    private static final String USER_CSR = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBuserCSRtestData\n-----END CERTIFICATE REQUEST-----\n";
    private static final String PIN_HASH = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";

    @Test
    public void userCsrCreated() throws Exception {
        server.enqueue(new Reply(201, "Created"));
        OnlineUserCertRequest req = new OnlineUserCertRequest(USER_CSR, PIN_HASH, "golden.test@example.org");
        assertTrue(req.isCSRREquestSuccess());
        assertEquals("Your CSR has been submitted to the CA server successfully. \nIt is waiting for the approval "
                + "and signing by an RA and CA operator.", req.getMessage());
        GoldenFixture.check("csr-user", server.getCaptured(), false);
    }

    @Test
    public void userCsrRejectedWithErrorDocument() throws Exception {
        server.enqueue(new Reply(202, "Accepted").xml(response("error-202.xml")));
        OnlineUserCertRequest req = new OnlineUserCertRequest(USER_CSR, PIN_HASH, "golden.test@example.org");
        assertFalse(req.isCSRREquestSuccess());
        assertEquals("PIN does not match the pending request", req.getMessage());
        GoldenFixture.check("csr-user", server.getCaptured(), false);
    }

    @Test
    public void userCsrServerError() throws Exception {
        server.enqueue(new Reply(500, "Internal Server Error"));
        OnlineUserCertRequest req = new OnlineUserCertRequest(USER_CSR, PIN_HASH, "golden.test@example.org");
        assertFalse(req.isCSRREquestSuccess());
        assertEquals("A problem occurred during the submission process. This could be due to a Server side problem.\n"
                + "Please try again later. If the problem persists, please contact the helpdesk support at \n"
                + "support@grid-support.ac.uk", req.getMessage());
    }

    // ------------------------------------------------------------------ host CSR (/CSRs, "bulk")

    private static final String HOST_CSR = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBhostCSRtestData\n-----END CERTIFICATE REQUEST-----\n";

    @Test
    public void hostCsrPppkCreated() throws Exception {
        X509Certificate cert = TestKeyMaterial.authCert();
        server.enqueue(challenge(cert), new Reply(201, "Created"));
        long before = System.currentTimeMillis();
        Pair<Boolean, String> result = new OnlineHostCertRequest(cert, TestKeyMaterial.authKey(), HOST_CSR, PIN_HASH,
                "host.admin@example.org").doHostCSR();
        long after = System.currentTimeMillis();
        assertTrue(result.first);
        assertEquals("SUCCESS_CREATED", result.second);
        List<CapturedRequest> captured = server.getCaptured();
        GoldenFixture.check("csr-host-pppk", captured, false);
        assertValidPppkResponse(captured.get(1), cert, before, after);
    }

    @Test
    public void hostCsrPppkRejectedWithErrorDocument() throws Exception {
        X509Certificate cert = TestKeyMaterial.authCert();
        server.enqueue(challenge(cert), new Reply(202, "Accepted").xml(response("error-202.xml")));
        Pair<Boolean, String> result = new OnlineHostCertRequest(cert, TestKeyMaterial.authKey(), HOST_CSR, PIN_HASH,
                "host.admin@example.org").doHostCSR();
        assertFalse(result.first);
        assertStatusMessage("PIN does not match the pending request", 202, result.second);
        GoldenFixture.check("csr-host-pppk", server.getCaptured(), false);
    }

    @Test
    public void hostCsrNoChallenge() throws Exception {
        server.enqueue(new Reply(500, "Internal Server Error"));
        X509Certificate cert = TestKeyMaterial.authCert();
        Pair<Boolean, String> result = new OnlineHostCertRequest(cert, TestKeyMaterial.authKey(), HOST_CSR, PIN_HASH,
                "host.admin@example.org").doHostCSR();
        assertFalse(result.first);
        assertEquals("UNAUTHORIZED", result.second);
        assertEquals(1, server.getCaptured().size());
    }

    // ------------------------------------------------------------------ renewal

    @Test
    public void renewPppkCreated() throws Exception {
        X509Certificate cert = TestKeyMaterial.authCert();
        server.enqueue(challenge(cert), new Reply(201, "Created"));
        long before = System.currentTimeMillis();
        OnlineCertRenewRequest renew = new OnlineCertRenewRequest(cert, TestKeyMaterial.authKey(),
                TestKeyMaterial.csrKeyPair(), "golden.test@example.org");
        assertEquals("golden test user", renew.getCN());
        assertEquals("CLRC", renew.getOU());
        assertEquals("DL", renew.getL());
        Pair<Boolean, String> result = renew.doRenewal();
        long after = System.currentTimeMillis();
        assertTrue(result.first);
        assertEquals("SUCCESS_CREATED", result.second);
        List<CapturedRequest> captured = server.getCaptured();
        GoldenFixture.check("renew-pppk", captured, true);
        assertValidPppkResponse(captured.get(1), cert, before, after);
    }

    @Test
    public void renewOpaqueCreated() throws Exception {
        X509Certificate cert = TestKeyMaterial.authCert();
        server.enqueue(challenge(cert).header("opaque", OPAQUE), new Reply(201, "Created"));
        Pair<Boolean, String> result = new OnlineCertRenewRequest(cert, TestKeyMaterial.authKey(),
                TestKeyMaterial.csrKeyPair(), "golden.test@example.org").doRenewal();
        assertTrue(result.first);
        GoldenFixture.check("renew-opaque", server.getCaptured(), true);
    }

    @Test
    public void renewForbidden() throws Exception {
        X509Certificate cert = TestKeyMaterial.authCert();
        server.enqueue(challenge(cert), new Reply(403, "Forbidden"));
        Pair<Boolean, String> result = new OnlineCertRenewRequest(cert, TestKeyMaterial.authKey(),
                TestKeyMaterial.csrKeyPair(), "golden.test@example.org").doRenewal();
        assertFalse(result.first);
        assertStatusMessage("Failed authentication. Please contact the helpdesk", 403, result.second);
        GoldenFixture.check("renew-pppk", server.getCaptured(), true);
    }

    @Test
    public void renewErrorDocument() throws Exception {
        X509Certificate cert = TestKeyMaterial.authCert();
        server.enqueue(challenge(cert), new Reply(202, "Accepted").xml(response("error-202.xml")));
        Pair<Boolean, String> result = new OnlineCertRenewRequest(cert, TestKeyMaterial.authKey(),
                TestKeyMaterial.csrKeyPair(), "golden.test@example.org").doRenewal();
        assertFalse(result.first);
        assertStatusMessage("PIN does not match the pending request", 202, result.second);
    }

    @Test
    public void renewNoChallenge() throws Exception {
        server.enqueue(new Reply(503, "Service Unavailable"));
        Pair<Boolean, String> result = new OnlineCertRenewRequest(TestKeyMaterial.authCert(), TestKeyMaterial.authKey(),
                TestKeyMaterial.csrKeyPair(), "golden.test@example.org").doRenewal();
        assertFalse(result.first);
        assertEquals("UNAUTHORIZED", result.second);
        assertEquals(1, server.getCaptured().size());
    }

    // ------------------------------------------------------------------ revocation

    @Test
    public void revokePppkCreated() throws Exception {
        X509Certificate cert = TestKeyMaterial.authCert();
        server.enqueue(challenge(cert), new Reply(201, "Created"));
        long before = System.currentTimeMillis();
        RevokeRequest revoke = new RevokeRequest(TestKeyMaterial.authKey(), 4242L, "Key compromise");
        assertTrue(revoke.doPosts());
        long after = System.currentTimeMillis();
        assertNull(revoke.getMessage());
        List<CapturedRequest> captured = server.getCaptured();
        GoldenFixture.check("revoke-pppk", captured, false);
        assertValidPppkResponse(captured.get(1), cert, before, after);
    }

    @Test
    public void revokeOpaqueCreated() throws Exception {
        X509Certificate cert = TestKeyMaterial.authCert();
        server.enqueue(challenge(cert).header("opaque", OPAQUE), new Reply(201, "Created"));
        RevokeRequest revoke = new RevokeRequest(TestKeyMaterial.authKey(), 4242L, "Key compromise");
        assertTrue(revoke.doPosts());
        GoldenFixture.check("revoke-opaque", server.getCaptured(), false);
    }

    @Test
    public void revokeForbidden() throws Exception {
        X509Certificate cert = TestKeyMaterial.authCert();
        server.enqueue(challenge(cert), new Reply(403, "Forbidden"));
        RevokeRequest revoke = new RevokeRequest(TestKeyMaterial.authKey(), 4242L, "Key compromise");
        assertFalse(revoke.doPosts());
        assertEquals("Failed authentication. Please contact the helpdesk", revoke.getMessage());
        GoldenFixture.check("revoke-pppk", server.getCaptured(), false);
    }

    @Test
    public void revokeErrorDocument() throws Exception {
        X509Certificate cert = TestKeyMaterial.authCert();
        server.enqueue(challenge(cert), new Reply(202, "Accepted").xml(response("error-202.xml")));
        RevokeRequest revoke = new RevokeRequest(TestKeyMaterial.authKey(), 4242L, "Key compromise");
        assertFalse(revoke.doPosts());
        assertEquals("PIN does not match the pending request", revoke.getMessage());
    }

    @Test
    public void revokeNoChallenge() throws Exception {
        server.enqueue(new Reply(500, "Internal Server Error"));
        RevokeRequest revoke = new RevokeRequest(TestKeyMaterial.authKey(), 4242L, "Key compromise");
        assertFalse(revoke.doPosts());
        assertEquals("There appears to be a problem with submitting the revocation request.\n"
                + "This could be either due to networking problems you are having or \n"
                + "problem in the e-Science CA Server. If your connection is already up but still \n"
                + "unable to complete the revocation submission, please contact the helpdesk.", revoke.getMessage());
        assertEquals(1, server.getCaptured().size());
    }

    /** XML escaping and UTF-8 encoding of free text typed by the user. */
    @Test
    public void revokeReasonWithSpecialCharacters() throws Exception {
        server.enqueue(new Reply(500, "Internal Server Error"));
        RevokeRequest revoke = new RevokeRequest(TestKeyMaterial.authKey(), 4242L,
                "Key <compromised> & \"stolen\" 'laptop' café £€\nsecond line\tend");
        assertFalse(revoke.doPosts());
        GoldenFixture.check("revoke-special-chars", server.getCaptured(), false);
    }

    // ------------------------------------------------------------------ helpers

    private static Reply ok(String xml) {
        return new Reply(200, "OK").xml(xml);
    }

    /** The PPPK 401 challenge: lower-case realm/nonce/keyid headers. */
    private static Reply challenge(X509Certificate cert) {
        RSAPublicKey pk = (RSAPublicKey) cert.getPublicKey();
        String keyid = pk.getModulus().toString(16) + "." + pk.getPublicExponent().toString(16);
        return new Reply(401, "Unauthorized").header("realm", REALM).header("nonce", NONCE).header("keyid", keyid);
    }

    static String response(String name) throws IOException {
        try (InputStream in = WireCompatibilityTest.class.getResourceAsStream("/golden/responses/" + name)) {
            assertNotNull("missing response fixture " + name, in);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /**
     * The status suffix format of the result message changed with the HTTP
     * library, so only the server-derived detail and the status code are
     * asserted.
     */
    private static void assertStatusMessage(String detail, int status, String message) {
        assertTrue("message [" + message + "] should start with [" + detail + " [", message.startsWith(detail + " ["));
        assertTrue("message [" + message + "] should contain status " + status, message.contains(String.valueOf(status)));
        assertTrue(message.endsWith("]"));
    }

    /**
     * Verify the PPPK "response" header cryptographically: raising it to the
     * public exponent must give hex("nonce:timestamp") (lower-cased), proving
     * the challenge was signed with the private key matching the cert.
     */
    static void assertValidPppkResponse(CapturedRequest second, X509Certificate cert, long before, long after) {
        String response = second.header("response");
        assertNotNull(response);
        RSAPublicKey pk = (RSAPublicKey) cert.getPublicKey();
        String hex = new BigInteger(response, 16).modPow(pk.getPublicExponent(), pk.getModulus()).toString(16);
        StringBuilder decoded = new StringBuilder();
        for (int i = 0; i + 1 < hex.length(); i += 2) {
            decoded.append((char) Integer.parseInt(hex.substring(i, i + 2), 16));
        }
        String text = decoded.toString();
        String prefix = NONCE.toLowerCase() + ":";
        assertTrue("decoded PPPK response [" + text + "]", text.startsWith(prefix));
        long ts = Long.parseLong(text.substring(prefix.length()));
        assertTrue(ts >= before && ts <= after);
        RSAPublicKey key = (RSAPublicKey) cert.getPublicKey();
        assertEquals(key.getModulus().toString(16) + "." + key.getPublicExponent().toString(16), second.header("keyid"));
        assertEquals(REALM, second.header("realm"));
    }
}
