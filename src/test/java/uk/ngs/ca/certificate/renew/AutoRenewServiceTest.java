package uk.ngs.ca.certificate.renew;

import org.junit.Assume;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import uk.ngs.ca.certificate.chain.BundledCaCertificates;
import uk.ngs.ca.certificate.chain.TestPki;
import uk.ngs.ca.certificate.management.KeyStoreEntryWrapper;
import uk.ngs.ca.util.GlobusCredentialWriter;

import java.io.InputStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

public class AutoRenewServiceTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    /**
     * Mutable clock for retry tests.
     */
    static final class TestClock extends Clock {
        Instant now = Instant.now();

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    final class FakeHost implements AutoRenewService.Host {
        boolean online = true;
        boolean busy = false;
        final List<String> notices = new ArrayList<>();
        int refreshes;
        String issueOnRefresh; // alias the "CA" issues on next refresh

        @Override
        public boolean isOnline() {
            return online;
        }

        @Override
        public boolean isBusy() {
            return busy;
        }

        @Override
        public void notifyUser(String title, String message, boolean problem) {
            notices.add(title + ": " + message);
        }

        @Override
        public void modelChanged() {
        }

        @Override
        public boolean refreshFromCa(KeyStoreEntryWrapper entry) throws Exception {
            refreshes++;
            if (entry.getAlias().equals(issueOnRefresh)) {
                fixture.issue(issueOnRefresh);
                issueOnRefresh = null;
                return true;
            }
            return false;
        }
    }

    private RenewFixture fixture;
    private FakeHost host;
    private TestClock clock;
    private AutoRenewSettings settings;
    private RenewalLedger ledger;
    private Path globus;

    private AutoRenewService service(Duration validFor, boolean enabled) throws Exception {
        fixture = new RenewFixture(tmp.newFolder("data"), validFor);
        host = new FakeHost();
        clock = new TestClock();
        settings = new AutoRenewSettings(AutoRenewService.settingsFile(fixture.dataDir));
        settings.setEnabled(enabled);
        ledger = new RenewalLedger(AutoRenewService.ledgerFile(fixture.dataDir));
        globus = tmp.newFolder(".globus").toPath();
        return new AutoRenewService(fixture.model, settings, ledger, fixture.submitter(clock), host, clock, globus);
    }

    private String fp() {
        return BundledCaCertificates.sha256Fingerprint(fixture.user.cert);
    }

    private String newAlias() {
        return ledger.get(fp()).newAlias;
    }

    @Test
    public void doesNothingWhenDisabledOfflineOrBusy() throws Exception {
        AutoRenewService s = service(Duration.ofDays(10), false);
        assertEquals(List.of("disabled"), s.runOnce());
        settings.setEnabled(true);
        host.online = false;
        assertTrue(s.runOnce().get(0).startsWith("offline"));
        host.online = true;
        host.busy = true;
        assertTrue(s.runOnce().get(0).startsWith("another online task"));
        assertEquals(0, fixture.requestsSent.get());
        assertEquals(0, host.refreshes);
    }

    @Test
    public void certificateNotDueIsLeftAloneWithoutContactingTheCa() throws Exception {
        AutoRenewService s = service(Duration.ofDays(200), true);
        List<String> log = s.runOnce();
        assertTrue(log.toString(), log.get(0).contains("not due until"));
        assertEquals(0, host.refreshes);
        assertEquals(0, fixture.requestsSent.get());
    }

    @Test
    public void dueCertificateIsRenewedExactlyOnce() throws Exception {
        AutoRenewService s = service(Duration.ofDays(10), true);
        s.runOnce();
        assertEquals(1, fixture.requestsSent.get());
        assertEquals(List.of(RenewFixture.EMAIL), fixture.emailsSent);
        assertEquals(RenewalLedger.State.SUBMITTED, ledger.get(fp()).state);
        assertTrue(fixture.model.getClientKeyStore().containsAlias(newAlias()));
        assertTrue(host.notices.get(0).startsWith("Certificate renewal requested"));

        // later runs (and a restart with a fresh ledger object) never resend
        s.runOnce();
        clock.now = clock.now.plus(Duration.ofDays(3));
        new AutoRenewService(fixture.model, settings, new RenewalLedger(AutoRenewService.ledgerFile(fixture.dataDir)),
                fixture.submitter(clock), host, clock, globus).runOnce();
        assertEquals(1, fixture.requestsSent.get());
    }

    @Test
    public void manualRenewalInKeystoreIsRespected() throws Exception {
        AutoRenewService s = service(Duration.ofDays(10), true);
        // a pending-renewal placeholder made by the Renew button (or an older CertWizard)
        TestPki.Entity placeholder = TestPki.cert("CN=Renew User CSR cert,L=DL,OU=CLRC,O=eScience,C=UK").build();
        fixture.model.getClientKeyStore().setKeyEntry("my cert_renew", placeholder.keys.getPrivate(), RenewFixture.PW,
                new Certificate[]{placeholder.cert});
        fixture.model.getKeyStoreEntryMap().put("my cert_renew", fixture.model.createKSEntryWrapperInstanceFromEntry("my cert_renew"));
        List<String> log = s.runOnce();
        assertTrue(log.toString(), log.toString().contains("already renewed (entry [my cert_renew])"));
        assertEquals(0, fixture.requestsSent.get());
    }

    @Test
    public void crashMidRequestIsNeverResent() throws Exception {
        AutoRenewService s = service(Duration.ofDays(10), true);
        ledger.put(fp(), RenewalLedger.State.ATTEMPTING, clock.now, "x", null, true);
        s.runOnce();
        s.runOnce();
        assertEquals(0, fixture.requestsSent.get());
        assertEquals("user told once per session", 1, host.notices.size());
        assertTrue(host.notices.get(0).contains("not resending"));
    }

    @Test
    public void caRefusalIsRetriedAfterADayThenGivenUp() throws Exception {
        AutoRenewService s = service(Duration.ofDays(20), true);
        fixture.caAnswer = new RenewalSubmitter.Answer(RenewalSubmitter.Answer.Kind.REFUSED, "try later");
        s.runOnce();
        assertEquals(1, fixture.requestsSent.get());
        assertEquals(RenewalLedger.State.FAILED, ledger.get(fp()).state);
        s.runOnce(); // too soon
        assertEquals(1, fixture.requestsSent.get());
        for (int i = 0; i < 4; i++) {
            clock.now = clock.now.plus(Duration.ofHours(25));
            s.runOnce();
        }
        assertEquals(AutoRenewPolicy.MAX_ATTEMPTS, fixture.requestsSent.get());
    }

    @Test
    public void droppedConnectionIsUncertainAndNotRetried() throws Exception {
        AutoRenewService s = service(Duration.ofDays(10), true);
        fixture.caAnswer = null;
        s.runOnce();
        clock.now = clock.now.plus(Duration.ofDays(2));
        s.runOnce();
        assertEquals(1, fixture.requestsSent.get());
        assertEquals(RenewalLedger.State.UNCERTAIN, ledger.get(fp()).state);
    }

    @Test
    public void unreachableCaConsumesNoAttemptAndIsRetriedNextRun() throws Exception {
        AutoRenewService s = service(Duration.ofDays(10), true);
        fixture.caAnswer = new RenewalSubmitter.Answer(RenewalSubmitter.Answer.Kind.NOT_SENT, "Could not connect");
        List<String> log = s.runOnce();
        assertTrue(log.toString(), log.toString().contains("nothing sent; will retry"));
        assertNull("no ledger record for an attempt that sent nothing", ledger.get(fp()));
        fixture.caAnswer = new RenewalSubmitter.Answer(RenewalSubmitter.Answer.Kind.ACCEPTED, "ok");
        s.runOnce();
        assertEquals(2, fixture.requestsSent.get());
        assertEquals(RenewalLedger.State.SUBMITTED, ledger.get(fp()).state);
        assertEquals(1, ledger.get(fp()).attempts);
    }

    @Test
    public void signedRequestThatMayHaveArrivedIsNeverResent() throws Exception {
        AutoRenewService s = service(Duration.ofDays(10), true);
        fixture.caAnswer = new RenewalSubmitter.Answer(RenewalSubmitter.Answer.Kind.MAYBE_SENT, "read timed out");
        s.runOnce();
        clock.now = clock.now.plus(Duration.ofDays(3));
        s.runOnce();
        assertEquals(1, fixture.requestsSent.get());
        assertEquals(RenewalLedger.State.UNCERTAIN, ledger.get(fp()).state);
    }

    @Test
    public void issuedRenewalIsInstalledAndGlobusUpdatedWithBackups() throws Exception {
        AutoRenewService s = service(Duration.ofDays(10), true);
        // ~/.globus currently holds the certificate being renewed
        GlobusCredentialWriter.write(globus.resolve("usercert.pem"), globus.resolve("userkey.pem"),
                new X509Certificate[]{fixture.user.cert, fixture.inter.cert, fixture.root.cert},
                fixture.user.keys.getPrivate(), RenewFixture.PW);
        s.runOnce();
        host.issueOnRefresh = newAlias();
        s.runOnce();

        assertEquals(RenewalLedger.State.INSTALLED, ledger.get(fp()).state);
        String notice = host.notices.get(host.notices.size() - 1);
        assertTrue(notice, notice.startsWith("Certificate renewed"));
        assertTrue(notice, notice.contains("now hold the renewed certificate and its full chain"));

        List<Certificate> installed;
        try (InputStream in = Files.newInputStream(globus.resolve("usercert.pem"))) {
            installed = new ArrayList<>(CertificateFactory.getInstance("X.509").generateCertificates(in));
        }
        assertEquals(3, installed.size());
        assertEquals(fixture.nextKeyPair.getPublic(), installed.get(0).getPublicKey());
        long backups;
        try (var files = Files.list(globus)) {
            backups = files.filter(p -> p.getFileName().toString().endsWith(".bak")).count();
        }
        assertEquals(2, backups);
        if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            assertEquals("r--------", PosixFilePermissions.toString(Files.getPosixFilePermissions(globus.resolve("userkey.pem"))));
        }
    }

    @Test
    public void globusHoldingSomeOtherCertificateIsLeftAlone() throws Exception {
        AutoRenewService s = service(Duration.ofDays(10), true);
        TestPki.Entity other = TestPki.leaf("Someone Else", fixture.inter);
        GlobusCredentialWriter.write(globus.resolve("usercert.pem"), globus.resolve("userkey.pem"),
                new X509Certificate[]{other.cert}, other.keys.getPrivate(), RenewFixture.PW);
        byte[] before = Files.readAllBytes(globus.resolve("usercert.pem"));
        s.runOnce();
        host.issueOnRefresh = newAlias();
        s.runOnce();
        assertEquals(RenewalLedger.State.INSTALLED, ledger.get(fp()).state);
        assertArrayEquals(before, Files.readAllBytes(globus.resolve("usercert.pem")));
    }

    @Test
    public void subjectKeyIgnoresPlaceholderSuffixAndRdnOrder() {
        TestPki.Entity a = TestPki.cert("CN=Jo Bloggs,L=DL,OU=CLRC,O=eScience,C=UK").build();
        TestPki.Entity b = TestPki.cert("C=UK,O=eScience,OU=CLRC,L=DL,CN=Jo Bloggs CSR cert").build();
        TestPki.Entity c = TestPki.cert("CN=Jo Bloggs,L=RAL,OU=CLRC,O=eScience,C=UK").build();
        assertEquals(AutoRenewService.subjectKey(a.cert), AutoRenewService.subjectKey(b.cert));
        assertNotEquals(AutoRenewService.subjectKey(a.cert), AutoRenewService.subjectKey(c.cert));
    }
}
