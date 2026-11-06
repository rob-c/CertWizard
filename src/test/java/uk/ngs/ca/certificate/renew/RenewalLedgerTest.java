package uk.ngs.ca.certificate.renew;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;

import static org.junit.Assert.*;

public class RenewalLedgerTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    @Test
    public void recordsSurviveARestart() throws Exception {
        Path f = tmp.getRoot().toPath().resolve("ledger.properties");
        Instant t = Instant.parse("2026-11-06T10:00:00Z");
        new RenewalLedger(f).put("abc", RenewalLedger.State.SUBMITTED, t, "new alias", "ok", true);
        RenewalLedger.Record r = new RenewalLedger(f).get("abc");
        assertEquals(RenewalLedger.State.SUBMITTED, r.state);
        assertEquals(t, r.time);
        assertEquals(1, r.attempts);
        assertEquals("new alias", r.newAlias);
        assertNull(new RenewalLedger(f).get("other"));
    }

    @Test
    public void attemptInterruptedByACrashReadsAsUncertain() throws Exception {
        Path f = tmp.getRoot().toPath().resolve("ledger.properties");
        new RenewalLedger(f).put("abc", RenewalLedger.State.ATTEMPTING, Instant.now(), "x", null, true);
        // "restart"
        assertEquals(RenewalLedger.State.UNCERTAIN, new RenewalLedger(f).get("abc").state);
    }

    @Test
    public void attemptsAccumulateAndAliasIsKept() throws Exception {
        Path f = tmp.getRoot().toPath().resolve("ledger.properties");
        RenewalLedger l = new RenewalLedger(f);
        Instant t = Instant.now();
        l.put("abc", RenewalLedger.State.ATTEMPTING, t, "first", null, true);
        l.put("abc", RenewalLedger.State.FAILED, t, null, "refused", false);
        l.put("abc", RenewalLedger.State.ATTEMPTING, t.plus(Duration.ofDays(1)), "second", null, true);
        RenewalLedger.Record r = new RenewalLedger(f).get("abc");
        assertEquals(2, r.attempts);
        assertEquals("second", r.newAlias);
        assertEquals(1, l.inState(RenewalLedger.State.UNCERTAIN).size()); // ATTEMPTING reads as UNCERTAIN
        assertTrue(l.inState(RenewalLedger.State.SUBMITTED).isEmpty());
    }
}
