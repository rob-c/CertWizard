package uk.ngs.ca.certificate.chain;

import org.junit.BeforeClass;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.*;

public class KeyStoreChainsTest {

    private static TestPki.Entity root;
    private static TestPki.Entity inter;
    private static TestPki.Entity leaf;
    private static CertChainBuilder builder;

    @BeforeClass
    public static void pki() {
        root = TestPki.root("KS Root");
        inter = TestPki.intermediate("KS CA", root);
        leaf = TestPki.leaf("KS User", inter);
        builder = new CertChainBuilder(Arrays.asList(root.cert, inter.cert), null, Clock.systemUTC());
    }

    @Test
    public void completeOrderedChainRecognised() {
        assertTrue(KeyStoreChains.isCompleteOrderedChain(new Certificate[]{leaf.cert, inter.cert, root.cert}));
        assertFalse(KeyStoreChains.isCompleteOrderedChain(new Certificate[]{leaf.cert}));
        assertFalse(KeyStoreChains.isCompleteOrderedChain(new Certificate[]{leaf.cert, root.cert}));
        assertFalse(KeyStoreChains.isCompleteOrderedChain(new Certificate[]{leaf.cert, root.cert, inter.cert}));
        assertFalse(KeyStoreChains.isCompleteOrderedChain(new Certificate[]{leaf.cert, inter.cert}));
        assertFalse(KeyStoreChains.isCompleteOrderedChain(null));
    }

    @Test
    public void leafOnlyAndMissingMiddleAreReplaced() {
        Certificate[] leafOnly = {leaf.cert};
        assertTrue(KeyStoreChains.shouldReplace(leafOnly, KeyStoreChains.complete(leafOnly, builder)));
        Certificate[] noMiddle = {leaf.cert, root.cert};
        CertChainBuilder.Result r = KeyStoreChains.complete(noMiddle, builder);
        assertTrue(KeyStoreChains.shouldReplace(noMiddle, r));
        assertEquals(Arrays.asList(leaf.cert, inter.cert, root.cert), r.getChain());
    }

    @Test
    public void completeChainIsLeftAlone() {
        Certificate[] full = {leaf.cert, inter.cert, root.cert};
        assertFalse(KeyStoreChains.shouldReplace(full, KeyStoreChains.complete(full, builder)));
    }

    @Test
    public void incompleteResultNeverReplaces() {
        CertChainBuilder empty = new CertChainBuilder(Collections.<X509Certificate>emptyList(), null, Clock.systemUTC());
        Certificate[] stored = {leaf.cert, root.cert};
        assertFalse(KeyStoreChains.shouldReplace(stored, KeyStoreChains.complete(stored, empty)));
    }

    @Test
    public void pendingCsrPlaceholderNeverReplaced() {
        TestPki.Entity placeholder = TestPki.cert("CN=Pending,O=Test").build();
        Certificate[] stored = {placeholder.cert};
        assertFalse(KeyStoreChains.shouldReplace(stored, KeyStoreChains.complete(stored, builder)));
    }

    @Test
    public void emptyOrNullChainGivesNullResult() {
        assertNull(KeyStoreChains.complete(null, builder));
        assertNull(KeyStoreChains.complete(new Certificate[0], builder));
    }

    @Test
    public void fullChainSurvivesBcPkcs12RoundTripWithoutExtraEntries() throws Exception {
        char[] pw = "test-pass".toCharArray();
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(null, null);
        ks.setKeyEntry("me", leaf.keys.getPrivate(), pw, new Certificate[]{leaf.cert, inter.cert, root.cert});
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ks.store(out, pw);

        KeyStore reloaded = KeyStore.getInstance("PKCS12", "BC");
        reloaded.load(new ByteArrayInputStream(out.toByteArray()), pw);
        assertEquals(Collections.singletonList("me"), Collections.list(reloaded.aliases()));
        assertArrayEquals(new Certificate[]{leaf.cert, inter.cert, root.cert}, reloaded.getCertificateChain("me"));
    }
}
