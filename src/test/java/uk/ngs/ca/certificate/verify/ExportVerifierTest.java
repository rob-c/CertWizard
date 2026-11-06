package uk.ngs.ca.certificate.verify;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import uk.ngs.ca.certificate.chain.TestPki;
import uk.ngs.ca.util.GlobusCredentialWriter;

import java.io.FileOutputStream;
import java.io.FileWriter;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class ExportVerifierTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private static TestPki.Entity root;
    private static TestPki.Entity inter;
    private static TestPki.Entity leaf;
    private static Certificate[] chain;
    private static final char[] PW = "export-pass".toCharArray();

    @BeforeClass
    public static void pki() {
        root = TestPki.root("Export Root");
        inter = TestPki.intermediate("Export CA", root);
        leaf = TestPki.leaf("Export User", inter);
        chain = new Certificate[]{leaf.cert, inter.cert, root.cert};
    }

    private Path pkcs12(Certificate[] stored) throws Exception {
        Path f = tmp.newFile("export.p12").toPath();
        KeyStore ks = KeyStore.getInstance("PKCS12"); // same provider as the real export
        ks.load(null, null);
        ks.setKeyEntry("me", leaf.keys.getPrivate(), PW, stored);
        try (FileOutputStream out = new FileOutputStream(f.toFile())) {
            ks.store(out, PW);
        }
        return f;
    }

    private Path pem(Certificate[] certs, boolean encrypt) throws Exception {
        Path f = tmp.newFile("export.pem").toPath();
        try (JcaPEMWriter w = new JcaPEMWriter(new FileWriter(f.toFile()))) {
            if (encrypt) {
                w.writeObject(leaf.keys.getPrivate(), new JcePEMEncryptorBuilder("DES-EDE3-CBC").setSecureRandom(new SecureRandom()).build(PW));
            } else {
                w.writeObject(leaf.keys.getPrivate());
            }
            for (Certificate c : certs) {
                w.writeObject(c);
            }
        }
        return f;
    }

    @Test
    public void goodPkcs12Verifies() throws Exception {
        assertEquals(List.of(), ExportVerifier.verifyPkcs12(pkcs12(chain), PW, chain, leaf.keys.getPrivate()));
    }

    @Test
    public void truncatedPkcs12ChainIsCaught() throws Exception {
        // (The JDK PKCS12 store refuses to write a chain with a gap such as
        // leaf+root, so a leaf-only file stands in for "truncated".)
        List<String> p = ExportVerifier.verifyPkcs12(pkcs12(new Certificate[]{leaf.cert}), PW, chain, leaf.keys.getPrivate());
        assertFalse(p.isEmpty());
        assertTrue(p.get(0), p.get(0).contains("chain differs"));
    }

    @Test
    public void pkcs12WithWrongPasswordIsCaught() throws Exception {
        assertFalse(ExportVerifier.verifyPkcs12(pkcs12(chain), "nope".toCharArray(), chain, leaf.keys.getPrivate()).isEmpty());
    }

    @Test
    public void goodEncryptedPemVerifies() throws Exception {
        assertEquals(List.of(), ExportVerifier.verifyPem(pem(chain, true), PW, chain, leaf.keys.getPrivate()));
    }

    @Test
    public void unencryptedKeyWhenPasswordChosenIsCaught() throws Exception {
        List<String> p = ExportVerifier.verifyPem(pem(chain, false), PW, chain, leaf.keys.getPrivate());
        assertTrue(p.toString(), p.toString().contains("UNENCRYPTED"));
    }

    @Test
    public void pemWithMiddleMissingIsCaught() throws Exception {
        List<String> p = ExportVerifier.verifyPem(pem(new Certificate[]{leaf.cert, root.cert}, true), PW, chain, leaf.keys.getPrivate());
        assertTrue(p.toString(), p.toString().contains("chain differs"));
    }

    @Test
    public void pemWithAnotherUsersKeyIsCaught() throws Exception {
        TestPki.Entity other = TestPki.leaf("Other", inter);
        Path f = pem(chain, true);
        List<String> p = ExportVerifier.verifyPem(f, PW, new Certificate[]{other.cert, inter.cert, root.cert}, other.keys.getPrivate());
        assertTrue(p.toString(), p.toString().contains("does not match the certificate") || p.toString().contains("chain differs"));
    }

    @Test
    public void pkcs7IsCheckedAsASet() throws Exception {
        Path f = tmp.newFile("export.p7b").toPath();
        CertPath cp = CertificateFactory.getInstance("X.509").generateCertPath(Arrays.asList((X509Certificate[]) new X509Certificate[]{leaf.cert, inter.cert, root.cert}));
        Files.write(f, cp.getEncoded("PKCS7"));
        assertEquals(List.of(), ExportVerifier.verifyPkcs7(f, chain));
        assertFalse(ExportVerifier.verifyPkcs7(f, new Certificate[]{leaf.cert, inter.cert}).isEmpty());
    }

    @Test
    public void globusPairVerifiesAndLoosePermissionsAreCaught() throws Exception {
        Path dir = tmp.newFolder(".globus").toPath();
        Path cert = dir.resolve("usercert.pem");
        Path key = dir.resolve("userkey.pem");
        X509Certificate[] x = {leaf.cert, inter.cert, root.cert};
        GlobusCredentialWriter.write(cert, key, x, leaf.keys.getPrivate(), PW);
        assertEquals(List.of(), ExportVerifier.verifyGlobus(cert, key, PW, chain, leaf.keys.getPrivate()));

        Assume.assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        Files.setPosixFilePermissions(key, PosixFilePermissions.fromString("rw-r--r--"));
        List<String> p = ExportVerifier.verifyGlobus(cert, key, PW, chain, leaf.keys.getPrivate());
        assertTrue(p.toString(), p.toString().contains("accessible to other users"));
    }
}
