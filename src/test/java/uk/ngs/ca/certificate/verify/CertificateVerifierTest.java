package uk.ngs.ca.certificate.verify;

import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.junit.BeforeClass;
import org.junit.Test;
import uk.ngs.ca.certificate.chain.CertChainBuilder;
import uk.ngs.ca.certificate.chain.TestPki;
import uk.ngs.ca.certificate.verify.VerificationReport.Severity;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;

public class CertificateVerifierTest {

    private static TestPki.Entity root;
    private static TestPki.Entity inter;
    private static TestPki.Entity leaf;

    @BeforeClass
    public static void pki() {
        root = TestPki.root("Verify Root");
        inter = TestPki.intermediate("Verify CA", root);
        leaf = TestPki.cert("CN=Verify User,O=Test").issuedBy(inter).eku(KeyPurposeId.id_kp_clientAuth).build();
    }

    private static CertificateVerifier verifier(List<X509Certificate> anchors, X509Certificate... known) {
        return new CertificateVerifier(anchors, new CertChainBuilder(Arrays.asList(known), null, Clock.systemUTC()),
                null, Clock.systemUTC(), Duration.ofDays(30), Duration.ofDays(365));
    }

    private static CertificateVerifier verifier() {
        return verifier(Collections.singletonList(root.cert), root.cert, inter.cert);
    }

    private static Severity worst(VerificationReport r, String check) {
        Severity w = null;
        for (VerificationReport.Finding f : r.findings(check)) {
            if (w == null || f.getSeverity().compareTo(w) > 0) {
                w = f.getSeverity();
            }
        }
        return w;
    }

    @Test
    public void goodEntryPassesEverything() {
        VerificationReport r = verifier().verifyKeyEntry(leaf.keys.getPrivate(),
                new Certificate[]{leaf.cert, inter.cert, root.cert});
        assertEquals(r.toText(), Severity.PASS, r.overall());
        for (String check : new String[]{"key-match", "chain", "trust", "path", "validity", "key-strength", "signature-algorithm", "usage"}) {
            assertEquals(check + "\n" + r.toText(), Severity.PASS, worst(r, check));
        }
    }

    @Test
    public void wrongPrivateKeyFails() {
        TestPki.Entity other = TestPki.leaf("Someone Else", inter);
        VerificationReport r = verifier().verifyKeyEntry(other.keys.getPrivate(), new Certificate[]{leaf.cert});
        assertEquals(Severity.FAIL, worst(r, "key-match"));
        assertEquals(Severity.FAIL, r.overall());
    }

    @Test
    public void leafOnlyStoredChainIsWarnedButBuildsFully() {
        VerificationReport r = verifier().verifyKeyEntry(leaf.keys.getPrivate(), new Certificate[]{leaf.cert});
        assertEquals(Severity.WARN, worst(r, "chain"));
        assertTrue(r.toText(), r.toText().contains("Full chain of 3 certificates"));
        assertTrue(r.toText(), r.toText().contains("has 1 of 3 certificates"));
        assertEquals(Severity.PASS, worst(r, "path"));
    }

    @Test
    public void missingIntermediateFails() {
        VerificationReport r = verifier(Collections.singletonList(root.cert), root.cert)
                .verifyKeyEntry(leaf.keys.getPrivate(), new Certificate[]{leaf.cert, root.cert});
        assertEquals(Severity.FAIL, worst(r, "chain"));
        assertTrue(r.toText().contains("CN=Verify CA"));
        assertNull("no trust verdict without a complete chain", worst(r, "trust"));
    }

    @Test
    public void untrustedRootIsWarned() {
        TestPki.Entity otherRoot = TestPki.root("Other Root");
        VerificationReport r = verifier(Collections.singletonList(otherRoot.cert), root.cert, inter.cert)
                .verifyKeyEntry(leaf.keys.getPrivate(), new Certificate[]{leaf.cert});
        assertEquals(Severity.WARN, worst(r, "trust"));
    }

    @Test
    public void expiredCertificateFailsValidityAndPath() {
        Instant now = Instant.now();
        TestPki.Entity old = TestPki.cert("CN=Expired User,O=Test").issuedBy(inter)
                .validity(now.minus(Duration.ofDays(400)), now.minus(Duration.ofDays(2))).build();
        VerificationReport r = verifier().verifyKeyEntry(old.keys.getPrivate(), new Certificate[]{old.cert});
        assertEquals(Severity.FAIL, worst(r, "validity"));
        assertTrue(r.toText().contains("expired on"));
        assertEquals(Severity.FAIL, worst(r, "path"));
    }

    @Test
    public void certificateExpiringSoonIsWarned() {
        Instant now = Instant.now();
        TestPki.Entity soon = TestPki.cert("CN=Soon User,O=Test").issuedBy(inter)
                .validity(now.minus(Duration.ofDays(300)), now.plus(Duration.ofDays(10))).build();
        VerificationReport r = verifier().verifyKeyEntry(soon.keys.getPrivate(), new Certificate[]{soon.cert});
        assertEquals(Severity.WARN, worst(r, "validity"));
        assertTrue(r.toText().contains("renew it now"));
    }

    @Test
    public void caCertificateExpiringWithinAYearIsWarnedByName() {
        Instant now = Instant.now();
        TestPki.Entity r2 = TestPki.root("Ageing Root");
        TestPki.Entity ageingCa = TestPki.cert("CN=Ageing CA,O=Test").ca(true).issuedBy(r2)
                .validity(now.minus(Duration.ofDays(3000)), now.plus(Duration.ofDays(200))).build();
        TestPki.Entity user = TestPki.cert("CN=Ageing User,O=Test").issuedBy(ageingCa)
                .validity(now.minus(Duration.ofDays(1)), now.plus(Duration.ofDays(150))).build();
        VerificationReport r = verifier(Collections.singletonList(r2.cert), r2.cert, ageingCa.cert)
                .verifyKeyEntry(user.keys.getPrivate(), new Certificate[]{user.cert});
        assertEquals(Severity.WARN, worst(r, "validity"));
        assertTrue(r.toText(), r.toText().contains("CA certificate 'Ageing CA' expires on"));
    }

    @Test
    public void weakRsaKeyFails() {
        TestPki.Entity weak = TestPki.cert("CN=Weak User,O=Test").issuedBy(inter).keys(TestPki.rsa(1024)).build();
        VerificationReport r = verifier().verifyKeyEntry(weak.keys.getPrivate(), new Certificate[]{weak.cert});
        assertEquals(Severity.FAIL, worst(r, "key-strength"));
    }

    @Test
    public void sha1SignatureIsWarned() {
        TestPki.Entity sha1 = TestPki.cert("CN=SHA1 User,O=Test").issuedBy(inter).sigAlg("SHA1withRSA").build();
        VerificationReport r = verifier().verifyKeyEntry(sha1.keys.getPrivate(), new Certificate[]{sha1.cert});
        assertEquals(Severity.WARN, worst(r, "signature-algorithm"));
    }

    @Test
    public void ekuWithoutTlsAuthIsWarned() {
        TestPki.Entity mail = TestPki.cert("CN=Mail User,O=Test").issuedBy(inter).eku(KeyPurposeId.id_kp_emailProtection).build();
        VerificationReport r = verifier().verifyKeyEntry(mail.keys.getPrivate(), new Certificate[]{mail.cert});
        assertEquals(Severity.WARN, worst(r, "usage"));
    }

    @Test
    public void caCertificateAsUserCertIsWarned() {
        VerificationReport r = verifier().verifyCertificate(inter.cert, null);
        assertEquals(Severity.WARN, worst(r, "usage"));
    }

    @Test
    public void pendingRequestPlaceholderIsInfoNotFailure() {
        TestPki.Entity placeholder = TestPki.cert("CN=Pending,O=Test").build();
        VerificationReport r = verifier().verifyKeyEntry(placeholder.keys.getPrivate(), new Certificate[]{placeholder.cert});
        assertEquals(Severity.INFO, worst(r, "chain"));
        assertEquals(Severity.PASS, worst(r, "key-match"));
        assertNotEquals(Severity.FAIL, r.overall());
    }

    @Test
    public void emptyEntryFails() {
        assertEquals(Severity.FAIL, verifier().verifyKeyEntry(null, new Certificate[0]).overall());
    }

    @Test
    public void reportRendersHtmlSafely() {
        VerificationReport r = new VerificationReport("CN=<script>");
        r.add(Severity.WARN, "x", "a < b & c");
        assertTrue(r.toHtml().contains("CN=&lt;script&gt;"));
        assertTrue(r.toHtml().contains("a &lt; b &amp; c"));
        assertEquals(Severity.WARN, r.overall());
    }
}
