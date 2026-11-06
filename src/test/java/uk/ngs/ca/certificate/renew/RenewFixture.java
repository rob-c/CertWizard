package uk.ngs.ca.certificate.renew;

import uk.ngs.ca.certificate.chain.TestPki;
import uk.ngs.ca.certificate.management.ClientKeyStoreCaServiceWrapper;
import uk.ngs.ca.certificate.management.KeyStoreEntryWrapper;
import uk.ngs.ca.certificate.management.TestCsrInfo;
import uk.ngs.ca.common.SystemStatus;
import uk.ngs.ca.tools.property.SysProperty;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A throwaway CA, a keystore in a temporary data directory with one user
 * certificate in it, and a fake CA server for renewal requests. Never talks to
 * the real CA and never touches the user's real data directory.
 */
final class RenewFixture {

    static final char[] PW = "renew-test-pass".toCharArray();
    static final String ALIAS = "my cert";
    static final String EMAIL = "user@example.ac.uk";

    final File dataDir;
    final TestPki.Entity root = TestPki.root("Renew Root");
    final TestPki.Entity inter = TestPki.intermediate("Renew CA", root);
    final TestPki.Entity user;
    final ClientKeyStoreCaServiceWrapper model;
    final KeyPair nextKeyPair = TestPki.rsa();
    final AtomicInteger requestsSent = new AtomicInteger();
    final List<String> emailsSent = new ArrayList<>();
    /**
     * What the fake CA answers; null = throw (unexpected failure mid-request).
     */
    RenewalSubmitter.Answer caAnswer = new RenewalSubmitter.Answer(RenewalSubmitter.Answer.Kind.ACCEPTED, "Renewal request received");

    RenewFixture(File dataDir, Duration validFor) throws Exception {
        this.dataDir = dataDir;
        Instant now = Instant.now();
        user = TestPki.cert("CN=Renew User,L=DL,OU=CLRC,O=eScience,C=UK").issuedBy(inter)
                .validity(now.minus(Duration.ofDays(300)), now.plus(validFor)).build();

        ClientKeyStoreCaServiceWrapper.resetForTesting();
        SystemStatus.getInstance().setCwDataDirectory(dataDir);
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(null, null);
        ks.setKeyEntry(ALIAS, user.keys.getPrivate(), PW, new Certificate[]{user.cert, inter.cert, root.cert});
        try (FileOutputStream out = new FileOutputStream(new File(dataDir, SysProperty.getValue("ngsca.key.keystore.file")))) {
            ks.store(out, PW);
        }
        model = ClientKeyStoreCaServiceWrapper.getInstance(PW);
        if (!model.getClientKeyStore().getKeyStoreFilePath().startsWith(dataDir.getAbsolutePath())) {
            throw new IllegalStateException("test keystore is not in the temporary directory");
        }
        entry(ALIAS).setServerCertificateCSRInfo(TestCsrInfo.of("VALID", EMAIL, "4242"));
    }

    KeyStoreEntryWrapper entry(String alias) {
        return model.getKeyStoreEntryMap().get(alias);
    }

    RenewalSubmitter submitter(java.time.Clock clock) {
        return new RenewalSubmitter(model, (cert, key, kp, email) -> new RenewalSubmitter.RenewalRequest() {
            @Override
            public RenewalSubmitter.Answer send() {
                requestsSent.incrementAndGet();
                emailsSent.add(email);
                if (caAnswer == null) {
                    throw new IllegalStateException("connection reset");
                }
                return caAnswer;
            }

            @Override
            public String getOU() {
                return "CLRC";
            }

            @Override
            public String getL() {
                return "DL";
            }

            @Override
            public String getCN() {
                return "Renew User";
            }
        }, () -> nextKeyPair, clock);
    }

    /**
     * Simulate the CA issuing the renewed certificate for <code>alias</code>
     * and the normal refresh path installing it with its chain.
     */
    void issue(String alias) throws Exception {
        TestPki.Entity renewed = TestPki.cert("CN=Renew User,L=DL,OU=CLRC,O=eScience,C=UK").issuedBy(inter)
                .keys(nextKeyPair).build();
        model.getClientKeyStore().setKeyEntry(alias, nextKeyPair.getPrivate(), PW,
                new Certificate[]{renewed.cert, inter.cert, root.cert});
        model.getClientKeyStore().reStore();
        model.getKeyStoreEntryMap().put(alias, model.createKSEntryWrapperInstanceFromEntry(alias));
        entry(alias).setServerCertificateCSRInfo(TestCsrInfo.of("VALID", EMAIL, "4343"));
    }
}
