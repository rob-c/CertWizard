package uk.ngs.ca.certificate.chain;

import org.junit.Test;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Checks the real bundled UK e-Science CA certificates.
 */
public class BundledCaCertificatesTest {

    private static X509Certificate byCn(String cn) {
        for (X509Certificate c : BundledCaCertificates.all()) {
            if (c.getSubjectX500Principal().getName().startsWith("CN=" + cn + ",")) {
                return c;
            }
        }
        throw new AssertionError("no bundled certificate with CN=" + cn);
    }

    @Test
    public void allFourCaCertificatesLoadAndMatchTheirPins() {
        List<X509Certificate> all = BundledCaCertificates.all();
        Map<String, String> pins = BundledCaCertificates.pinnedFingerprints();
        assertEquals(4, all.size());
        assertEquals(4, pins.size());
        int i = 0;
        for (String pin : pins.values()) {
            assertEquals(pin, BundledCaCertificates.sha256Fingerprint(all.get(i++)));
        }
    }

    @Test
    public void rootsAreTheTwoSelfSignedRoots() {
        List<X509Certificate> roots = BundledCaCertificates.roots();
        assertEquals(2, roots.size());
        assertTrue(roots.contains(byCn("UK e-Science Root")));
        assertTrue(roots.contains(byCn("UK e-Science Root 2026")));
    }

    @Test
    public void ca2bChainsToRoot2007() {
        CertChainBuilder.Result r = CertChainBuilder.offline().build(byCn("UK e-Science CA 2B"), (java.security.cert.Certificate[]) null);
        assertTrue(r.getProblems().toString(), r.isComplete());
        assertEquals(2, r.getChain().size());
        assertEquals(byCn("UK e-Science Root"), r.getChain().get(1));
    }

    @Test
    public void ca3bChainsToRoot2026() {
        CertChainBuilder.Result r = CertChainBuilder.offline().build(byCn("UK e-Science CA 3B"), (java.security.cert.Certificate[]) null);
        assertTrue(r.getProblems().toString(), r.isComplete());
        assertEquals(2, r.getChain().size());
        assertEquals(byCn("UK e-Science Root 2026"), r.getChain().get(1));
    }

    @Test
    public void rootsAreNotCrossLinked() {
        // 3B must not chain to the 2007 root nor 2B to the 2026 root.
        assertFalse(CertChainBuilder.isIssuerOf(byCn("UK e-Science Root"), byCn("UK e-Science CA 3B")));
        assertFalse(CertChainBuilder.isIssuerOf(byCn("UK e-Science Root 2026"), byCn("UK e-Science CA 2B")));
    }
}
