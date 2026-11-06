/*
 * CertWizard - UK eScience CA Certificate Management Client
 * Copyright (C) 2021 UKRI-STFC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package uk.ngs.ca.common;

import org.junit.Test;
import uk.ngs.ca.common.ConnectivityMonitor.State;
import uk.ngs.ca.common.ConnectivityMonitor.Status;
import uk.ngs.ca.wire.RawHttpCaptureServer;
import uk.ngs.ca.wire.TestClients;

import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class ConnectivityMonitorTest {

    private static final Duration ONLINE = Duration.ofMinutes(10);
    private static final Duration INITIAL = Duration.ofSeconds(15);
    private static final Duration MAX = Duration.ofMinutes(10);

    /** A clock the test moves by hand. */
    static final class MutableClock extends Clock {
        Instant now = Instant.parse("2026-11-06T12:00:00Z");

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    /** Records scheduled tasks; the test runs them explicitly. */
    static final class ManualScheduler implements ConnectivityMonitor.Scheduler {
        final List<Runnable> tasks = new ArrayList<>();
        final List<Duration> delays = new ArrayList<>();
        final List<boolean[]> cancelled = new ArrayList<>();

        @Override
        public ConnectivityMonitor.Cancellable schedule(Runnable task, Duration delay) {
            boolean[] c = {false};
            tasks.add(task);
            delays.add(delay);
            cancelled.add(c);
            return () -> c[0] = true;
        }

        int live() {
            int n = 0;
            for (boolean[] c : cancelled) {
                if (!c[0]) {
                    n++;
                }
            }
            return n;
        }

        Duration lastDelay() {
            return delays.get(delays.size() - 1);
        }

        /** Run the most recent, non-cancelled task. */
        void runLatest() {
            int i = tasks.size() - 1;
            assertFalse("latest task was cancelled", cancelled.get(i)[0]);
            cancelled.get(i)[0] = true;
            tasks.get(i).run();
        }
    }

    private final MutableClock clock = new MutableClock();
    private final ManualScheduler scheduler = new ManualScheduler();
    private final List<Boolean> systemStatus = new ArrayList<>();
    private boolean reachable;
    private final AtomicInteger probes = new AtomicInteger();

    private ConnectivityMonitor monitor(ConnectivityMonitor.Probe probe) {
        return new ConnectivityMonitor(probe, scheduler, clock, ONLINE, INITIAL, MAX, systemStatus::add);
    }

    private ConnectivityMonitor monitor() {
        return monitor(() -> {
            probes.incrementAndGet();
            if (!reachable) {
                throw new ConnectException("Connection refused");
            }
            return true;
        });
    }

    @Test
    public void offlineBackoffSequence() {
        long[] expected = {15, 30, 60, 120, 240, 480, 600, 600, 600};
        for (int i = 0; i < expected.length; i++) {
            assertEquals(Duration.ofSeconds(expected[i]), ConnectivityMonitor.offlineDelay(i + 1, INITIAL, MAX));
        }
    }

    @Test
    public void backsOffWhileOfflineAndResetsWhenBackOnline() {
        ConnectivityMonitor m = monitor();
        m.start();
        assertEquals(Duration.ZERO, scheduler.lastDelay()); // immediate first check

        for (long secs : new long[]{15, 30, 60, 120, 240, 480, 600, 600}) {
            scheduler.runLatest();
            assertEquals(State.OFFLINE, m.getStatus().getState());
            assertEquals(Duration.ofSeconds(secs), scheduler.lastDelay());
            assertEquals(clock.now.plusSeconds(secs), m.getStatus().getNextCheck());
            assertEquals(1, scheduler.live());
        }

        reachable = true;
        scheduler.runLatest();
        assertEquals(State.ONLINE, m.getStatus().getState());
        assertEquals(ONLINE, scheduler.lastDelay()); // normal cadence again
        assertEquals(0, m.getStatus().getConsecutiveFailures());

        reachable = false;
        scheduler.runLatest();
        assertEquals(INITIAL, scheduler.lastDelay()); // backoff starts again from 15s
        assertFalse(systemStatus.get(0));
        assertTrue(systemStatus.contains(Boolean.TRUE));
    }

    @Test
    public void checkNowRunsImmediatelyAndReschedules() {
        ConnectivityMonitor m = monitor();
        m.start();
        scheduler.runLatest(); // offline, next in 15s
        assertEquals(1, scheduler.live());

        reachable = true;
        assertTrue(m.checkNow());
        assertEquals(State.ONLINE, m.getStatus().getState());
        assertEquals(1, scheduler.live()); // the pending 15s check was replaced
        assertEquals(ONLINE, scheduler.lastDelay());
        assertEquals(2, probes.get());
    }

    @Test
    public void statusReportsSecondsUntilNextRetry() {
        ConnectivityMonitor m = monitor();
        m.start();
        scheduler.runLatest();
        scheduler.runLatest(); // second failure: next in 30s
        clock.now = clock.now.plusMillis(4500);
        Status s = m.getStatus();
        assertEquals(26, s.secondsUntilNextCheck(clock.instant()));
        assertTrue(m.describeOffline(), m.describeOffline().contains("again automatically in 26s"));
        assertTrue(m.describeOffline(), m.describeOffline().contains("Connection refused"));
    }

    @Test
    public void notStartedMeansNoScheduling() {
        ConnectivityMonitor m = monitor();
        assertFalse(m.checkNow());
        assertTrue(scheduler.tasks.isEmpty());
        assertNull(m.getStatus().getNextCheck());
        assertEquals(-1, m.getStatus().secondsUntilNextCheck(clock.instant()));
    }

    @Test
    public void concurrentChecksShareOnePing() throws Exception {
        CountDownLatch inProbe = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        ConnectivityMonitor m = monitor(() -> {
            probes.incrementAndGet();
            inProbe.countDown();
            try {
                return release.await(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                throw new IOException(e);
            }
        });
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<Boolean> first = pool.submit(m::checkNow);
            assertTrue(inProbe.await(5, TimeUnit.SECONDS));
            assertTrue(m.getStatus().isChecking());
            Future<Boolean> second = pool.submit(m::checkNow);
            Thread.sleep(100);
            release.countDown();
            assertTrue(first.get(5, TimeUnit.SECONDS));
            assertTrue(second.get(5, TimeUnit.SECONDS));
            assertEquals(1, probes.get());
            assertFalse(m.getStatus().isChecking());
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    public void requestFailuresAndSuccessesUpdateTheState() {
        ConnectivityMonitor m = monitor();
        m.start();
        reachable = true;
        scheduler.runLatest();
        assertEquals(State.ONLINE, m.getStatus().getState());

        m.reportUnreachable("Could not connect to the CA server.");
        assertTrue(m.isKnownOffline());
        assertEquals(INITIAL, scheduler.lastDelay()); // re-check soon, not in 10 minutes
        assertEquals("Could not connect to the CA server.", m.getStatus().getLastError());
        assertEquals(Boolean.FALSE, systemStatus.get(systemStatus.size() - 1));

        // further failures while offline must not reset the backoff schedule
        int scheduled = scheduler.tasks.size();
        m.reportUnreachable("again");
        assertEquals(scheduled, scheduler.tasks.size());

        m.reportReachable();
        assertFalse(m.isKnownOffline());
        assertEquals(ONLINE, scheduler.lastDelay());
        assertEquals(Boolean.TRUE, systemStatus.get(systemStatus.size() - 1));
    }

    @Test
    public void anUnexpectedProbeErrorDoesNotWedgeTheMonitor() {
        boolean[] blowUp = {true};
        ConnectivityMonitor m = monitor(() -> {
            if (blowUp[0]) {
                throw new AssertionError("bug in probe");
            }
            return true;
        });
        try {
            m.checkNow();
            fail();
        } catch (AssertionError expected) {
            // propagated
        }
        assertFalse(m.getStatus().isChecking());
        blowUp[0] = false;
        assertTrue(m.checkNow());
    }

    @Test
    public void listenersSeeCheckingThenResult() {
        ConnectivityMonitor m = monitor();
        List<Status> seen = new ArrayList<>();
        m.addListener(seen::add);
        reachable = true;
        m.checkNow();
        assertTrue(seen.get(0).isChecking());
        Status last = seen.get(seen.size() - 1);
        assertFalse(last.isChecking());
        assertEquals(State.ONLINE, last.getState());
    }

    // ----------------------------------------------------------- with CaHttpClient

    @Test
    public void clientFailsFastWhileOfflineButStillProbes() throws Exception {
        ConnectivityMonitor m = monitor();
        m.start();
        TestClients.RecordingSleeper sleeper = new TestClients.RecordingSleeper();
        CaHttpClient client = TestClients.create(m, sleeper, clock);

        String dead;
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            dead = "http://127.0.0.1:" + s.getLocalPort();
        }
        try {
            client.send(CaHttpRequest.get(dead + "/CA").build());
            fail();
        } catch (CaHttpException e) {
            assertEquals(4, e.getAttempts());
        }
        assertTrue("an unreachable server marks the monitor offline", m.isKnownOffline());

        try (RawHttpCaptureServer server = new RawHttpCaptureServer()) {
            long t0 = System.nanoTime();
            try {
                client.send(CaHttpRequest.post(server.baseUrl() + "/CSR").build());
                fail("expected fail-fast");
            } catch (CaOfflineException e) {
                assertFalse(e.isRequestMayHaveBeenSent());
                assertTrue(e.getMessage(), e.getMessage().startsWith("The CA server cannot be reached at the moment"));
            }
            assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0) < 500);
            assertEquals("nothing may be sent while offline", 0, server.getCaptured().size());

            // the connectivity probe is never short-circuited
            server.enqueue(new RawHttpCaptureServer.Reply(200, "OK"));
            CaHttpRequest probe = CaHttpRequest.get(server.baseUrl() + "/pingservice").maxAttempts(1).connectivityProbe().build();
            assertEquals(200, client.send(probe).getStatusCode());
            assertEquals(1, server.getCaptured().size());
        }
    }

    @Test
    public void immediateRecheckRestoresServiceAfterFailingFast() throws IOException {
        try (RawHttpCaptureServer server = new RawHttpCaptureServer()) {
            // wired as in the application: the monitor pings through the client
            CaHttpClient[] client = new CaHttpClient[1];
            ConnectivityMonitor m = monitor(() -> client[0].send(CaHttpRequest.get(server.baseUrl() + "/pingservice")
                    .maxAttempts(1).connectivityProbe().build()).getStatusCode() == 200);
            client[0] = TestClients.create(m, new TestClients.RecordingSleeper(), clock);

            m.reportUnreachable("Could not connect to the CA server.");
            try {
                client[0].send(CaHttpRequest.get(server.baseUrl() + "/CA").build());
                fail("expected fail-fast");
            } catch (CaOfflineException expected) {
                assertEquals(0, server.getCaptured().size());
            }

            server.enqueue(new RawHttpCaptureServer.Reply(200, "OK"));
            assertTrue(m.checkNow());
            server.enqueue(new RawHttpCaptureServer.Reply(200, "OK"));
            assertEquals(200, client[0].send(CaHttpRequest.get(server.baseUrl() + "/CA").build()).getStatusCode());
            assertEquals(2, server.getCaptured().size());
        }
    }

    @Test
    public void anyHttpResponseMarksTheServerReachable() throws IOException {
        ConnectivityMonitor m = monitor();
        assertEquals(State.UNKNOWN, m.getStatus().getState());
        CaHttpClient client = TestClients.create(m, new TestClients.RecordingSleeper(), clock);
        try (RawHttpCaptureServer server = new RawHttpCaptureServer()) {
            server.enqueue(new RawHttpCaptureServer.Reply(404, "Not Found"));
            assertEquals(404, client.send(CaHttpRequest.get(server.baseUrl() + "/certificate/1").build()).getStatusCode());
        }
        assertEquals(State.ONLINE, m.getStatus().getState());
        assertEquals(Boolean.TRUE, systemStatus.get(systemStatus.size() - 1));
    }
}
