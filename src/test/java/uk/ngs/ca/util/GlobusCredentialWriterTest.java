package uk.ngs.ca.util;

import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import uk.ngs.ca.certificate.chain.TestPki;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class GlobusCredentialWriterTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private TestPki.Entity root;
    private TestPki.Entity inter;
    private TestPki.Entity leaf;
    private Path cert;
    private Path key;
    private final char[] password = "correct horse battery".toCharArray();

    @Before
    public void setUp() throws Exception {
        root = TestPki.root("Globus Root");
        inter = TestPki.intermediate("Globus CA", root);
        leaf = TestPki.leaf("Globus User", inter);
        Path globus = tmp.newFolder(".globus").toPath();
        cert = globus.resolve("usercert.pem");
        key = globus.resolve("userkey.pem");
    }

    private void write() throws Exception {
        GlobusCredentialWriter.write(cert, key, new X509Certificate[]{leaf.cert, inter.cert, root.cert},
                leaf.keys.getPrivate(), password);
    }

    private static boolean posix() {
        return FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
    }

    @Test
    public void usercertHoldsTheWholeChainInOrder() throws Exception {
        write();
        List<Certificate> certs = new ArrayList<>();
        try (InputStream in = new FileInputStream(cert.toFile())) {
            certs.addAll(CertificateFactory.getInstance("X.509").generateCertificates(in));
        }
        assertEquals(Arrays.<Certificate>asList(leaf.cert, inter.cert, root.cert), certs);
    }

    @Test
    public void userkeyIsEncryptedAndMatchesTheCertificate() throws Exception {
        write();
        String pem = new String(Files.readAllBytes(key), StandardCharsets.US_ASCII);
        assertTrue(pem.contains("Proc-Type: 4,ENCRYPTED"));
        assertTrue(pem.contains("DEK-Info: DES-EDE3-CBC"));
        PrivateKey decrypted;
        try (Reader r = Files.newBufferedReader(key, StandardCharsets.US_ASCII); PEMParser p = new PEMParser(r)) {
            Object o = p.readObject();
            assertTrue(o instanceof PEMEncryptedKeyPair);
            PEMKeyPair kp = ((PEMEncryptedKeyPair) o).decryptKeyPair(new JcePEMDecryptorProviderBuilder().build(password));
            decrypted = new JcaPEMKeyConverter().getPrivateKey(kp.getPrivateKeyInfo());
        }
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(decrypted);
        s.update("proof".getBytes(StandardCharsets.US_ASCII));
        byte[] sig = s.sign();
        s.initVerify(leaf.cert.getPublicKey());
        s.update("proof".getBytes(StandardCharsets.US_ASCII));
        assertTrue(s.verify(sig));
    }

    @Test
    public void userkeyIsOwnerReadOnly() throws Exception {
        Assume.assumeTrue(posix());
        write();
        assertEquals("r--------", PosixFilePermissions.toString(Files.getPosixFilePermissions(key)));
        assertEquals("r--r--r--", PosixFilePermissions.toString(Files.getPosixFilePermissions(cert)));
    }

    @Test
    public void replacesAPreviousReadOnlyInstall() throws Exception {
        write();
        TestPki.Entity newer = TestPki.leaf("Globus User Renewed", inter);
        GlobusCredentialWriter.write(cert, key, new X509Certificate[]{newer.cert, inter.cert, root.cert},
                newer.keys.getPrivate(), password);
        try (InputStream in = new FileInputStream(cert.toFile())) {
            assertEquals(newer.cert, CertificateFactory.getInstance("X.509").generateCertificate(in));
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void refusesToWriteAnUnencryptedKey() throws Exception {
        GlobusCredentialWriter.write(cert, key, new X509Certificate[]{leaf.cert}, leaf.keys.getPrivate(), new char[0]);
    }
}
