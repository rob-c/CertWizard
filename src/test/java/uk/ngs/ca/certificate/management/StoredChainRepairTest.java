package uk.ngs.ca.certificate.management;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import uk.ngs.ca.certificate.chain.CertChainBuilder;
import uk.ngs.ca.certificate.chain.TestPki;
import uk.ngs.ca.common.SystemStatus;
import uk.ngs.ca.tools.property.SysProperty;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.time.Clock;
import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * End-to-end check of the startup repair: a keystore written by an older
 * CertWizard (leaf-only chain) is upgraded to the full chain, saved, and the
 * previous file is kept as the backup.
 * <p>
 * Runs entirely inside a temporary data directory. It must never touch the
 * user's real ~/.ca.
 */
public class StoredChainRepairTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    @Test
    public void leafOnlyEntriesAreUpgradedAndSavedWithBackup() throws Exception {
        File dataDir = tmp.newFolder("ca-data");
        SystemStatus.getInstance().setCwDataDirectory(dataDir);
        assertEquals(dataDir.getAbsolutePath(), SystemStatus.getInstance().getCwDataDirectory().getAbsolutePath());

        TestPki.Entity root = TestPki.root("Repair Root");
        TestPki.Entity inter = TestPki.intermediate("Repair CA", root);
        TestPki.Entity user = TestPki.leaf("Repair User", inter);
        TestPki.Entity placeholder = TestPki.cert("CN=Pending CSR,O=Test").build();
        char[] pw = "repair-test-pass".toCharArray();

        File ksFile = new File(dataDir, SysProperty.getValue("ngsca.key.keystore.file"));
        KeyStore old = KeyStore.getInstance("PKCS12", "BC");
        old.load(null, null);
        old.setKeyEntry("my cert", user.keys.getPrivate(), pw, new Certificate[]{user.cert});
        old.setKeyEntry("pending", placeholder.keys.getPrivate(), pw, new Certificate[]{placeholder.cert});
        try (FileOutputStream out = new FileOutputStream(ksFile)) {
            old.store(out, pw);
        }

        ClientKeyStoreCaServiceWrapper wrapper = ClientKeyStoreCaServiceWrapper.getInstance(pw);
        assertTrue("wrapper must be using the temporary keystore",
                wrapper.getClientKeyStore().getKeyStoreFilePath().startsWith(dataDir.getAbsolutePath()));

        CertChainBuilder builder = new CertChainBuilder(Arrays.asList(root.cert, inter.cert), null, Clock.systemUTC());
        assertEquals(1, wrapper.completeStoredCertificateChains(builder));
        // idempotent: nothing left to repair
        assertEquals(0, wrapper.completeStoredCertificateChains(builder));
        wrapper.getClientKeyStore().reStore();

        KeyStore saved = KeyStore.getInstance("PKCS12", "BC");
        try (FileInputStream in = new FileInputStream(ksFile)) {
            saved.load(in, pw);
        }
        assertArrayEquals(new Certificate[]{user.cert, inter.cert, root.cert}, saved.getCertificateChain("my cert"));
        assertArrayEquals(new Certificate[]{placeholder.cert}, saved.getCertificateChain("pending"));
        assertEquals(2, java.util.Collections.list(saved.aliases()).size());

        File backup = new File(new File(dataDir, "backup"), ksFile.getName() + ".backup");
        assertTrue("previous keystore kept as backup", backup.isFile());
        KeyStore previous = KeyStore.getInstance("PKCS12", "BC");
        try (FileInputStream in = new FileInputStream(backup)) {
            previous.load(in, pw);
        }
        assertArrayEquals(new Certificate[]{user.cert}, previous.getCertificateChain("my cert"));
    }
}
