package uk.ngs.ca.certificate.chain;

import org.junit.BeforeClass;
import org.junit.Test;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

public class CertChainBuilderTest {

    private static TestPki.Entity root;
    private static TestPki.Entity inter;
    private static TestPki.Entity leaf;

    @BeforeClass
    public static void pki() {
        root = TestPki.root("Root");
        inter = TestPki.intermediate("Intermediate", root);
        leaf = TestPki.leaf("User", inter);
    }

    private static CertChainBuilder builder(X509Certificate... known) {
        return new CertChainBuilder(Arrays.asList(known), null, Clock.systemUTC());
    }

    private static List<X509Certificate> list(X509Certificate... certs) {
        return Arrays.asList(certs);
    }

    @Test
    public void leafOnlyStoredChainIsCompletedWithEveryParent() {
        CertChainBuilder.Result r = builder(root.cert, inter.cert).build(leaf.cert, new Certificate[]{leaf.cert});
        assertTrue(r.getProblems().toString(), r.isComplete());
        assertEquals(list(leaf.cert, inter.cert, root.cert), r.getChain());
        assertTrue(r.getProblems().isEmpty());
    }

    @Test
    public void leafPlusRootWithMiddleMissingGetsTheIntermediate() {
        // The historic CertWizard/browser export shape: user cert + root, no CA 2B/3B.
        CertChainBuilder.Result r = builder(inter.cert).build(leaf.cert, new Certificate[]{leaf.cert, root.cert});
        assertTrue(r.isComplete());
        assertEquals(list(leaf.cert, inter.cert, root.cert), r.getChain());
    }

    @Test
    public void unorderedInputIsOrderedLeafFirstRootLast() {
        CertChainBuilder.Result r = builder().build(leaf.cert, new Certificate[]{root.cert, leaf.cert, inter.cert});
        assertTrue(r.isComplete());
        assertEquals(list(leaf.cert, inter.cert, root.cert), r.getChain());
    }

    @Test
    public void deepChainKeepsEveryIntermediate() {
        TestPki.Entity i1 = TestPki.intermediate("Policy CA", root);
        TestPki.Entity i2 = TestPki.intermediate("Issuing CA", i1);
        TestPki.Entity user = TestPki.leaf("Deep User", i2);
        CertChainBuilder.Result r = builder(root.cert, i2.cert).build(user.cert, new Certificate[]{user.cert, i1.cert});
        assertTrue(r.isComplete());
        assertEquals(list(user.cert, i2.cert, i1.cert, root.cert), r.getChain());
    }

    @Test
    public void unknownIssuerGivesPartialChainAndSaysWhatIsMissing() {
        CertChainBuilder.Result r = builder().build(leaf.cert, new Certificate[]{leaf.cert});
        assertFalse(r.isComplete());
        assertEquals(list(leaf.cert), r.getChain());
        assertEquals(1, r.getProblems().size());
        assertTrue(r.getProblems().get(0), r.getProblems().get(0).contains("CN=Intermediate"));
    }

    @Test
    public void middleFoundButRootMissingIsIncomplete() {
        CertChainBuilder.Result r = builder(inter.cert).build(leaf.cert, (Certificate[]) null);
        assertFalse(r.isComplete());
        assertEquals(list(leaf.cert, inter.cert), r.getChain());
        assertTrue(r.getProblems().get(0).contains("CN=Root"));
    }

    @Test
    public void impostorWithSameNameButDifferentKeyIsRejected() {
        TestPki.Entity impostor = TestPki.intermediate("Intermediate", root); // same DN, new key
        CertChainBuilder.Result onlyImpostor = builder(impostor.cert, root.cert).build(leaf.cert, (Certificate[]) null);
        assertFalse(onlyImpostor.isComplete());
        assertEquals(list(leaf.cert), onlyImpostor.getChain());

        CertChainBuilder.Result both = builder(impostor.cert, inter.cert, root.cert).build(leaf.cert, (Certificate[]) null);
        assertEquals(list(leaf.cert, inter.cert, root.cert), both.getChain());
    }

    @Test
    public void certificateMarkedNonCaIsNeverUsedAsIssuer() {
        TestPki.Entity notCa = TestPki.cert("CN=Not A CA,O=Test").issuedBy(root).build(); // CA=false
        TestPki.Entity child = TestPki.leaf("Child", notCa);
        CertChainBuilder.Result r = builder(notCa.cert, root.cert).build(child.cert, (Certificate[]) null);
        assertFalse(r.isComplete());
        assertEquals(list(child.cert), r.getChain());
    }

    @Test
    public void prefersCurrentlyValidIssuerOverExpiredReissue() {
        TestPki.Entity r2 = TestPki.root("Root2");
        Instant now = Instant.now();
        TestPki.Entity expired = TestPki.cert("CN=Reissued CA,O=Test").ca(true).issuedBy(r2)
                .validity(now.minus(Duration.ofDays(800)), now.minus(Duration.ofDays(10))).build();
        TestPki.Entity current = TestPki.cert("CN=Reissued CA,O=Test").ca(true).issuedBy(r2).keys(expired.keys)
                .validity(now.minus(Duration.ofDays(5)), now.plus(Duration.ofDays(800))).build();
        TestPki.Entity user = TestPki.leaf("Reissue User", current);
        // expired listed first so a naive "first match" would pick it
        CertChainBuilder.Result r = builder(expired.cert, current.cert, r2.cert).build(user.cert, (Certificate[]) null);
        assertEquals(list(user.cert, current.cert, r2.cert), r.getChain());
    }

    @Test
    public void selfSignedPlaceholderIsCompleteButFlagged() {
        TestPki.Entity placeholder = TestPki.cert("CN=Pending CSR,O=Test").build();
        CertChainBuilder.Result r = builder(root.cert).build(placeholder.cert, (Certificate[]) null);
        assertTrue(r.isComplete());
        assertTrue(r.isLeafSelfSigned());
        assertEquals(1, r.getChain().size());
    }

    @Test
    public void fetcherOnlyConsultedWhenNothingLocalMatches() {
        AtomicInteger calls = new AtomicInteger();
        CertChainBuilder.IssuerFetcher fetcher = child -> {
            calls.incrementAndGet();
            return child.equals(leaf.cert) ? Collections.singletonList(inter.cert) : Collections.emptyList();
        };
        CertChainBuilder local = new CertChainBuilder(list(root.cert, inter.cert), fetcher, Clock.systemUTC());
        assertTrue(local.build(leaf.cert, (Certificate[]) null).isComplete());
        assertEquals(0, calls.get());

        CertChainBuilder remote = new CertChainBuilder(list(root.cert), fetcher, Clock.systemUTC());
        CertChainBuilder.Result r = remote.build(leaf.cert, (Certificate[]) null);
        assertTrue(r.isComplete());
        assertEquals(list(leaf.cert, inter.cert, root.cert), r.getChain());
        assertEquals(1, calls.get());
    }

    @Test
    public void fetchedForgeryCannotEnterTheChain() {
        TestPki.Entity forged = TestPki.intermediate("Intermediate", root);
        CertChainBuilder b = new CertChainBuilder(list(root.cert), child -> Collections.singletonList(forged.cert), Clock.systemUTC());
        CertChainBuilder.Result r = b.build(leaf.cert, (Certificate[]) null);
        assertFalse(r.isComplete());
        assertEquals(list(leaf.cert), r.getChain());
    }

    @Test
    public void ecdsaCaChainLikeRoot2026AndCa3B() {
        TestPki.Entity ecRoot = TestPki.cert("CN=EC Root,O=Test").ca(true).keys(TestPki.ecP384()).build();
        TestPki.Entity ecCa = TestPki.cert("CN=EC CA,O=Test").ca(true).keys(TestPki.ecP384()).issuedBy(ecRoot).build();
        TestPki.Entity rsaUser = TestPki.leaf("RSA User", ecCa);
        CertChainBuilder.Result r = builder(ecRoot.cert, ecCa.cert).build(rsaUser.cert, (Certificate[]) null);
        assertTrue(r.isComplete());
        assertEquals(list(rsaUser.cert, ecCa.cert, ecRoot.cert), r.getChain());
    }

    @Test
    public void worksWithoutKeyIdentifiers() {
        TestPki.Entity r = TestPki.cert("CN=Old Root,O=Test").ca(true).noKeyIdentifiers().build();
        TestPki.Entity i = TestPki.cert("CN=Old CA,O=Test").ca(true).noKeyIdentifiers().issuedBy(r).build();
        TestPki.Entity u = TestPki.cert("CN=Old User,O=Test").noKeyIdentifiers().issuedBy(i).build();
        assertEquals(list(u.cert, i.cert, r.cert), builder(r.cert, i.cert).build(u.cert, (Certificate[]) null).getChain());
    }

    @Test
    public void duplicatesAndUnrelatedCertsInInputAreIgnored() {
        TestPki.Entity unrelated = TestPki.root("Unrelated");
        List<Certificate> extras = new ArrayList<>(list(leaf.cert, unrelated.cert, inter.cert, inter.cert, root.cert, leaf.cert));
        CertChainBuilder.Result r = builder().build(leaf.cert, extras);
        assertEquals(list(leaf.cert, inter.cert, root.cert), r.getChain());
    }

    @Test(expected = IllegalArgumentException.class)
    public void nullLeafIsRejected() {
        builder().build(null, (Certificate[]) null);
    }
}
