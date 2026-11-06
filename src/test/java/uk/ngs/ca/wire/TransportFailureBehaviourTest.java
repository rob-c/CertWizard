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
import uk.ngs.ca.certificate.OnlineCertRenewRequest;
import uk.ngs.ca.certificate.OnlineUserCertRequest;
import uk.ngs.ca.certificate.client.RevokeRequest;
import uk.ngs.ca.common.Pair;
import uk.ngs.ca.info.CAInfo;
import uk.ngs.ca.tools.property.SysProperty;
import uk.ngs.ca.wire.RawHttpCaptureServer.Reply;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * What the client classes report when no HTTP response arrives. The
 * original client turned every transport failure into a generic status;
 * the replacement says whether a submission may have reached the server.
 */
public class TransportFailureBehaviourTest {

    private RawHttpCaptureServer server;

    @Before
    public void setUp() {
        server = SharedCaptureServer.get();
    }

    private static String deadBaseUrl() throws IOException {
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return "http://127.0.0.1:" + s.getLocalPort();
        }
    }

    @Test
    public void userCsrToUnreachableServerIsReportedAsNotSent() throws Exception {
        String key = "uk.ngs.ca.request.csr.url";
        String original = SysProperty.getValue(key);
        TestConfig.set(key, deadBaseUrl() + "/CSR");
        try {
            OnlineUserCertRequest req = new OnlineUserCertRequest("csr", "pin", "a@b.c");
            assertFalse(req.isCSRREquestSuccess());
            assertTrue(req.getMessage(), req.getMessage().startsWith("The certificate request was not sent: Could not connect"));
        } finally {
            TestConfig.set(key, original);
        }
    }

    @Test
    public void caInfoFromUnreachableServerThrowsIOException() throws Exception {
        String key = "uk.ngs.ca.request.ca.url";
        String original = SysProperty.getValue(key);
        TestConfig.set(key, deadBaseUrl() + "/CA");
        try {
            new CAInfo();
            fail("expected IOException");
        } catch (IOException expected) {
            assertTrue(expected.getMessage().startsWith("Could not connect"));
        } finally {
            TestConfig.set(key, original);
        }
    }

    @Test
    public void caInfoErrorStatusThrowsIOException() throws Exception {
        server.enqueue(new Reply(503, "Service Unavailable"), new Reply(503, "Service Unavailable"),
                new Reply(503, "Service Unavailable"), new Reply(503, "Service Unavailable"));
        try {
            new CAInfo();
            fail("expected IOException");
        } catch (IOException expected) {
            assertTrue(expected.getMessage(), expected.getMessage().contains("Service Unavailable (503)"));
        }
    }

    @Test
    public void revokeDroppedAfterSignedRequestMayHaveBeenReceived() throws Exception {
        server.enqueue(challenge(TestKeyMaterial.authCert()), Reply.dropConnection());
        RevokeRequest revoke = new RevokeRequest(TestKeyMaterial.authKey(), 4242L, "Key compromise");
        assertFalse(revoke.doPosts());
        assertTrue(revoke.getMessage(), revoke.getMessage().contains("may still have received it"));
        // the signed request must not have been re-sent
        assertEquals(2, server.getCaptured().size());
    }

    @Test
    public void renewalDroppedBeforeChallengeSubmitsNothing() throws Exception {
        server.enqueue(Reply.dropConnection());
        Pair<Boolean, String> result = new OnlineCertRenewRequest(TestKeyMaterial.authCert(), TestKeyMaterial.authKey(),
                TestKeyMaterial.csrKeyPair(), "golden.test@example.org").doRenewal();
        assertFalse(result.first);
        assertTrue(result.second, result.second.contains("Nothing was submitted"));
        assertEquals(1, server.getCaptured().size());
    }

    @Test
    public void renewalDroppedAfterSignedRequestIsNotResent() throws Exception {
        server.enqueue(challenge(TestKeyMaterial.authCert()), Reply.dropConnection());
        Pair<Boolean, String> result = new OnlineCertRenewRequest(TestKeyMaterial.authCert(), TestKeyMaterial.authKey(),
                TestKeyMaterial.csrKeyPair(), "golden.test@example.org").doRenewal();
        assertFalse(result.first);
        assertTrue(result.second, result.second.contains("may still have received it"));
        assertEquals(2, server.getCaptured().size());
    }

    private static Reply challenge(X509Certificate cert) {
        RSAPublicKey pk = (RSAPublicKey) cert.getPublicKey();
        return new Reply(401, "Unauthorized").header("realm", "r").header("nonce", "n")
                .header("keyid", pk.getModulus().toString(16) + "." + pk.getPublicExponent().toString(16));
    }
}
