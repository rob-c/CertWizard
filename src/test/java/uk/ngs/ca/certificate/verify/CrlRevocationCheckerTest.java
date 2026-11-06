package uk.ngs.ca.certificate.verify;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import uk.ngs.ca.certificate.chain.BundledCaCertificates;
import uk.ngs.ca.certificate.chain.TestPki;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

public class CrlRevocationCheckerTest {

    private static final String CRL_URL = "http://crl.test.invalid/ca.crl";

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private static TestPki.Entity root;
    private static TestPki.Entity inter;
    private static TestPki.Entity leaf;
    private static TestPki.Entity revokedLeaf;

    @BeforeClass
    public static void pki() {
        root = TestPki.root("CRL Root");
        inter = TestPki.intermediate("CRL CA", root);
        leaf = TestPki.cert("CN=Good User,O=Test").issuedBy(inter).crlDp(CRL_URL).build();
        revokedLeaf = TestPki.cert("CN=Revoked User,O=Test").issuedBy(inter).crlDp(CRL_URL).build();
    }

    private static byte[] crl(X509Certificate issuer, KeyPair signer, Instant thisUpdate, Instant nextUpdate, BigInteger... revoked) throws Exception {
        X509v2CRLBuilder b = new X509v2CRLBuilder(X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded()), Date.from(thisUpdate));
        b.setNextUpdate(Date.from(nextUpdate));
        for (BigInteger serial : revoked) {
            b.addCRLEntry(serial, Date.from(thisUpdate.minus(Duration.ofHours(1))), CRLReason.keyCompromise);
        }
        return new JcaX509CRLConverter().getCRL(b.build(new JcaContentSignerBuilder("SHA256withRSA").build(signer.getPrivate()))).getEncoded();
    }

    private static byte[] currentCrl(BigInteger... revoked) throws Exception {
        Instant now = Instant.now();
        return crl(inter.cert, inter.keys, now.minus(Duration.ofDays(1)), now.plus(Duration.ofDays(29)), revoked);
    }

    private CrlRevocationChecker checker(byte[] body, boolean online, Path cache, AtomicInteger calls) {
        return new CrlRevocationChecker(cache, uri -> {
            if (calls != null) {
                calls.incrementAndGet();
            }
            assertEquals(URI.create(CRL_URL), uri);
            if (body == null) {
                throw new IOException("network is down");
            }
            return body;
        }, online, Clock.systemUTC());
    }

    @Test
    public void notRevokedIsGood() throws Exception {
        CrlRevocationChecker.Result r = checker(currentCrl(revokedLeaf.cert.getSerialNumber()), true, null, null).check(leaf.cert, inter.cert);
        assertEquals(r.getDetail(), CrlRevocationChecker.Status.GOOD, r.getStatus());
    }

    @Test
    public void revokedIsReported() throws Exception {
        CrlRevocationChecker.Result r = checker(currentCrl(revokedLeaf.cert.getSerialNumber()), true, null, null).check(revokedLeaf.cert, inter.cert);
        assertEquals(CrlRevocationChecker.Status.REVOKED, r.getStatus());
        assertTrue(r.getDetail(), r.getDetail().contains("KEY_COMPROMISE"));
    }

    @Test
    public void crlSignedByWrongKeyIsNotTrusted() throws Exception {
        Instant now = Instant.now();
        byte[] forged = crl(inter.cert, TestPki.rsa(), now.minus(Duration.ofDays(1)), now.plus(Duration.ofDays(29)));
        CrlRevocationChecker.Result r = checker(forged, true, null, null).check(leaf.cert, inter.cert);
        assertEquals(CrlRevocationChecker.Status.UNKNOWN, r.getStatus());
        assertTrue(r.getDetail().contains("signature"));
    }

    @Test
    public void staleCrlNeverSaysGood() throws Exception {
        Instant now = Instant.now();
        byte[] stale = crl(inter.cert, inter.keys, now.minus(Duration.ofDays(60)), now.minus(Duration.ofDays(30)));
        CrlRevocationChecker.Result r = checker(stale, true, null, null).check(leaf.cert, inter.cert);
        assertEquals(CrlRevocationChecker.Status.UNKNOWN, r.getStatus());
        assertTrue(r.getDetail().contains("expired"));
    }

    @Test
    public void revocationOnStaleCrlStillCounts() throws Exception {
        Instant now = Instant.now();
        byte[] stale = crl(inter.cert, inter.keys, now.minus(Duration.ofDays(60)), now.minus(Duration.ofDays(30)),
                revokedLeaf.cert.getSerialNumber());
        assertEquals(CrlRevocationChecker.Status.REVOKED,
                checker(stale, true, null, null).check(revokedLeaf.cert, inter.cert).getStatus());
    }

    @Test
    public void cachedCrlUsedWhenOfflineOrDownloadFails() throws Exception {
        Path cache = tmp.newFolder("crl-cache").toPath();
        assertEquals(CrlRevocationChecker.Status.GOOD,
                checker(currentCrl(), true, cache, null).check(leaf.cert, inter.cert).getStatus());

        AtomicInteger calls = new AtomicInteger();
        CrlRevocationChecker.Result offline = checker(null, false, cache, calls).check(leaf.cert, inter.cert);
        assertEquals(CrlRevocationChecker.Status.GOOD, offline.getStatus());
        assertTrue(offline.getDetail().contains("cached"));
        assertEquals("offline mode must not touch the network", 0, calls.get());

        CrlRevocationChecker.Result failing = checker(null, true, cache, calls).check(leaf.cert, inter.cert);
        assertEquals(CrlRevocationChecker.Status.GOOD, failing.getStatus());
        assertEquals(1, calls.get());
    }

    @Test
    public void offlineWithoutCacheIsUnknown() {
        CrlRevocationChecker.Result r = checker(null, false, null, null).check(leaf.cert, inter.cert);
        assertEquals(CrlRevocationChecker.Status.UNKNOWN, r.getStatus());
        assertTrue(r.getDetail().contains("offline"));
    }

    @Test
    public void noCrlLocationIsUnknown() {
        TestPki.Entity noDp = TestPki.leaf("No DP", inter);
        assertEquals(CrlRevocationChecker.Status.UNKNOWN, checker(null, true, null, null).check(noDp.cert, inter.cert).getStatus());
    }

    @Test
    public void knownCrlLocationsMatchTheRealBundledCaNames() {
        // Every bundled UK e-Science CA must have a known CRL URL, keyed by
        // exactly the DN that appears as "issuer" in the certs it signs.
        for (X509Certificate ca : BundledCaCertificates.all()) {
            assertTrue(ca.getSubjectX500Principal().getName(),
                    CrlRevocationChecker.KNOWN_CRLS.containsKey(ca.getSubjectX500Principal()));
        }
        assertEquals(4, CrlRevocationChecker.KNOWN_CRLS.size());
    }

    @Test
    public void verifierReportsRevocationPerCertificate() throws Exception {
        CertificateVerifier v = new CertificateVerifier(java.util.Collections.singletonList(root.cert),
                new uk.ngs.ca.certificate.chain.CertChainBuilder(java.util.Arrays.asList(root.cert, inter.cert), null, Clock.systemUTC()),
                checker(currentCrl(revokedLeaf.cert.getSerialNumber()), true, null, null),
                Clock.systemUTC(), Duration.ofDays(30), Duration.ofDays(365));
        VerificationReport r = v.verifyKeyEntry(revokedLeaf.keys.getPrivate(), new java.security.cert.Certificate[]{revokedLeaf.cert});
        assertEquals(r.toText(), VerificationReport.Severity.FAIL, r.overall());
        assertTrue(r.toText().contains("REVOKED"));
        // the intermediate has no CRL DP and no known location: unknown, not failed
        assertTrue(r.toText().contains("CA certificate 'CRL CA': revocation status unknown"));
    }
}
