package uk.ngs.ca.certificate.renew;

import org.junit.Test;

import java.time.Duration;
import java.time.Instant;

import static org.junit.Assert.*;

public class AutoRenewPolicyTest {

    private final Instant now = Instant.parse("2026-11-06T12:00:00Z");
    private final AutoRenewPolicy policy = new AutoRenewPolicy(Duration.ofDays(30));

    private AutoRenewPolicy.Facts due() {
        return new AutoRenewPolicy.Facts().keyPair(true).serverStatus("VALID").notAfter(now.plus(Duration.ofDays(10)));
    }

    private static RenewalLedger.Record rec(RenewalLedger.State s, Instant t, int attempts) {
        return new RenewalLedger.Record(s, t, attempts, "new", "msg");
    }

    @Test
    public void renewsInsideTheWindow() {
        assertEquals(AutoRenewPolicy.Action.RENEW, policy.decide(due(), now).action);
    }

    @Test
    public void waitsUntilTheWindowOpens() {
        AutoRenewPolicy.Decision d = policy.decide(due().notAfter(now.plus(Duration.ofDays(90))), now);
        assertEquals(AutoRenewPolicy.Action.WAIT, d.action);
        assertEquals(now.plus(Duration.ofDays(60)), d.notBefore);
    }

    @Test
    public void renewsWithinTheGracePeriodButNotAfter() {
        assertEquals(AutoRenewPolicy.Action.RENEW, policy.decide(due().notAfter(now.minus(Duration.ofDays(29))), now).action);
        assertEquals(AutoRenewPolicy.Action.SKIP, policy.decide(due().notAfter(now.minus(Duration.ofDays(31))), now).action);
    }

    @Test
    public void onlyValidKeyPairCertificates() {
        assertEquals(AutoRenewPolicy.Action.SKIP, policy.decide(due().keyPair(false), now).action);
        assertEquals(AutoRenewPolicy.Action.SKIP, policy.decide(due().serverStatus("REVOKED"), now).action);
        assertEquals(AutoRenewPolicy.Action.SKIP, policy.decide(due().serverStatus(null), now).action);
        assertEquals(AutoRenewPolicy.Action.SKIP, policy.decide(due().notAfter(null), now).action);
    }

    @Test
    public void neverRenewsTwice() {
        assertEquals(AutoRenewPolicy.Action.SKIP, policy.decide(due().newerEntryAlias("mine (renewed)"), now).action);
        assertEquals(AutoRenewPolicy.Action.SKIP, policy.decide(due().ledger(rec(RenewalLedger.State.SUBMITTED, now, 1)), now).action);
        assertEquals(AutoRenewPolicy.Action.SKIP, policy.decide(due().ledger(rec(RenewalLedger.State.INSTALLED, now, 1)), now).action);
    }

    @Test
    public void uncertainOutcomeIsNeverRetriedAutomatically() {
        AutoRenewPolicy.Decision d = policy.decide(due().ledger(rec(RenewalLedger.State.UNCERTAIN, now.minus(Duration.ofDays(5)), 1)), now);
        assertEquals(AutoRenewPolicy.Action.SKIP, d.action);
        assertTrue(d.reason.contains("not resending"));
    }

    @Test
    public void caRefusalIsRetriedAfterADayAtMostThreeTimes() {
        assertEquals(AutoRenewPolicy.Action.WAIT,
                policy.decide(due().ledger(rec(RenewalLedger.State.FAILED, now.minus(Duration.ofHours(2)), 1)), now).action);
        assertEquals(AutoRenewPolicy.Action.RENEW,
                policy.decide(due().ledger(rec(RenewalLedger.State.FAILED, now.minus(Duration.ofHours(25)), 2)), now).action);
        assertEquals(AutoRenewPolicy.Action.SKIP,
                policy.decide(due().ledger(rec(RenewalLedger.State.FAILED, now.minus(Duration.ofDays(3)), 3)), now).action);
    }
}
