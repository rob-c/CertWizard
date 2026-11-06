package uk.ngs.ca.certificate.renew;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import uk.ngs.ca.certificate.chain.CertChainBuilder;
import uk.ngs.ca.certificate.management.TestCsrInfo;
import uk.ngs.ca.common.Pair;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;

import static org.junit.Assert.*;

public class RenewalSubmitterTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private RenewFixture fixture(Duration validFor) throws Exception {
        return new RenewFixture(tmp.newFolder("data"), validFor);
    }

    @Test
    public void acceptedRenewalStoresPlaceholderForTheNewKeyAndSaves() throws Exception {
        RenewFixture f = fixture(Duration.ofDays(10));
        RenewalSubmitter.Result r = f.submitter(Clock.systemUTC()).submit(f.entry(RenewFixture.ALIAS), RenewFixture.EMAIL, "renewed");
        assertEquals(r.getMessage(), RenewalSubmitter.Outcome.SUBMITTED, r.getOutcome());
        assertEquals(1, f.requestsSent.get());
        X509Certificate placeholder = f.model.getClientKeyStore().getX509Certificate("renewed");
        assertTrue(CertChainBuilder.isSelfSigned(placeholder));
        assertEquals(f.nextKeyPair.getPublic(), placeholder.getPublicKey());
        assertNotNull("in the model map", f.entry("renewed"));
        // saved to disk: a fresh load sees it
        java.security.KeyStore reloaded = f.model.getClientKeyStore().getKeyStoreCopy();
        assertTrue(reloaded.containsAlias("renewed"));
    }

    @Test
    public void caRefusalStoresNothing() throws Exception {
        RenewFixture f = fixture(Duration.ofDays(10));
        f.caAnswer = Pair.create(false, "Renewal not allowed");
        RenewalSubmitter.Result r = f.submitter(Clock.systemUTC()).submit(f.entry(RenewFixture.ALIAS), RenewFixture.EMAIL, "renewed");
        assertEquals(RenewalSubmitter.Outcome.REJECTED_BY_CA, r.getOutcome());
        assertEquals("Renewal not allowed", r.getMessage());
        assertFalse(f.model.getClientKeyStore().containsAlias("renewed"));
    }

    @Test
    public void dropMidRequestIsUncertain() throws Exception {
        RenewFixture f = fixture(Duration.ofDays(10));
        f.caAnswer = null;
        assertEquals(RenewalSubmitter.Outcome.UNCERTAIN,
                f.submitter(Clock.systemUTC()).submit(f.entry(RenewFixture.ALIAS), RenewFixture.EMAIL, "renewed").getOutcome());
    }

    @Test
    public void ineligibleEntriesSendNothing() throws Exception {
        RenewFixture f = fixture(Duration.ofDays(10));
        RenewalSubmitter s = f.submitter(Clock.systemUTC());
        assertEquals(RenewalSubmitter.Outcome.NOT_ELIGIBLE, s.submit(f.entry(RenewFixture.ALIAS), "not-an-email", "a").getOutcome());
        assertEquals(RenewalSubmitter.Outcome.NOT_ELIGIBLE, s.submit(f.entry(RenewFixture.ALIAS), RenewFixture.EMAIL, RenewFixture.ALIAS).getOutcome());
        f.entry(RenewFixture.ALIAS).setServerCertificateCSRInfo(TestCsrInfo.of("REVOKED", RenewFixture.EMAIL, "4242"));
        assertEquals(RenewalSubmitter.Outcome.NOT_ELIGIBLE, s.submit(f.entry(RenewFixture.ALIAS), RenewFixture.EMAIL, "b").getOutcome());
        assertEquals(0, f.requestsSent.get());
    }

    @Test
    public void expiredBeyondGracePeriodIsNotEligible() throws Exception {
        RenewFixture f = fixture(Duration.ofDays(10));
        Clock later = Clock.offset(Clock.systemUTC(), Duration.ofDays(10 + 31));
        String reason = f.submitter(later).ineligibilityReason(f.entry(RenewFixture.ALIAS), RenewFixture.EMAIL);
        assertNotNull(reason);
        assertTrue(reason.contains("expired more than 30 days ago"));
    }
}
