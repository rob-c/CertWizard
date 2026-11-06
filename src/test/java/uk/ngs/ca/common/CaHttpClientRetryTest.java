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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import uk.ngs.ca.wire.RawHttpCaptureServer;
import uk.ngs.ca.wire.TestClients;
import uk.ngs.ca.wire.TestClients.RecordingSleeper;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Retry, backoff and timeout behaviour of {@link CaHttpClient} against a
 * local HTTP server. Delays are recorded by an injected sleeper instead of
 * being slept, so the tests run fast; jitter is fixed at 0.5 (none).
 */
public class CaHttpClientRetryTest {

    /** A scripted reply: status, optional Retry-After, optional delay before answering. */
    private static final class Step {
        final int status;
        final String retryAfter;
        final long delayMillis;

        Step(int status, String retryAfter, long delayMillis) {
            this.status = status;
            this.retryAfter = retryAfter;
            this.delayMillis = delayMillis;
        }
    }

    private static Step status(int code) {
        return new Step(code, null, 0);
    }

    private HttpServer server;
    private final ConcurrentLinkedQueue<Step> script = new ConcurrentLinkedQueue<>();
    private final AtomicInteger hits = new AtomicInteger();
    private final List<String> methods = Collections.synchronizedList(new ArrayList<>());
    private final CountDownLatch shutdown = new CountDownLatch(1);
    private final RecordingSleeper sleeper = new RecordingSleeper();

    @Before
    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.setExecutor(Executors.newCachedThreadPool());
        server.createContext("/", this::handle);
        server.start();
    }

    @After
    public void stop() {
        shutdown.countDown();
        server.stop(0);
    }

    private void handle(HttpExchange ex) throws IOException {
        hits.incrementAndGet();
        methods.add(ex.getRequestMethod());
        ex.getRequestBody().readAllBytes();
        Step step = script.poll();
        if (step == null) {
            step = status(200);
        }
        if (step.delayMillis > 0) {
            try {
                shutdown.await(step.delayMillis, TimeUnit.MILLISECONDS);
            } catch (InterruptedException ignored) {
            }
        }
        if (step.retryAfter != null) {
            ex.getResponseHeaders().add("Retry-After", step.retryAfter);
        }
        byte[] body = ("<status>" + step.status + "</status>").getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(step.status, body.length);
        ex.getResponseBody().write(body);
        ex.close();
    }

    private String url() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/CA";
    }

    private CaHttpClient client() {
        return TestClients.withoutTracking(sleeper);
    }

    private static List<Duration> seconds(long... s) {
        List<Duration> out = new ArrayList<>();
        for (long x : s) {
            out.add(Duration.ofSeconds(x));
        }
        return out;
    }

    // ----------------------------------------------------------------- GET

    @Test
    public void getRetries503ThenSucceeds() throws Exception {
        script.addAll(Arrays.asList(status(503), status(503), status(200)));
        CaHttpResponse r = client().send(CaHttpRequest.get(url()).build());
        assertEquals(200, r.getStatusCode());
        assertEquals(3, hits.get());
        assertEquals(seconds(1, 2), sleeper.getSleeps());
    }

    @Test
    public void getGivesUpAfterFourAttemptsAndReturnsTheLastResponse() throws Exception {
        script.addAll(Arrays.asList(status(500), status(502), status(504), status(503), status(200)));
        CaHttpResponse r = client().send(CaHttpRequest.get(url()).build());
        assertEquals(503, r.getStatusCode());
        assertEquals(4, hits.get());
        assertEquals(seconds(1, 2, 4), sleeper.getSleeps());
    }

    @Test
    public void getHonoursRetryAfterSeconds() throws Exception {
        script.addAll(Arrays.asList(new Step(429, "3", 0), status(200)));
        assertEquals(200, client().send(CaHttpRequest.get(url()).build()).getStatusCode());
        assertEquals(seconds(3), sleeper.getSleeps());
    }

    @Test
    public void getHonoursRetryAfterHttpDate() throws Exception {
        Clock clock = Clock.fixed(Instant.parse("2026-11-06T15:00:00Z"), ZoneOffset.UTC);
        script.addAll(Arrays.asList(new Step(503, "Fri, 06 Nov 2026 15:00:12 GMT", 0), status(200)));
        CaHttpClient c = TestClients.create(null, sleeper, clock);
        assertEquals(200, c.send(CaHttpRequest.get(url()).build()).getStatusCode());
        assertEquals(seconds(12), sleeper.getSleeps());
    }

    @Test
    public void getDoesNotWaitForAnExcessiveRetryAfter() throws Exception {
        script.addAll(Arrays.asList(new Step(429, "3600", 0), status(200)));
        CaHttpResponse r = client().send(CaHttpRequest.get(url()).build());
        assertEquals(429, r.getStatusCode());
        assertEquals(1, hits.get());
        assertTrue(sleeper.getSleeps().isEmpty());
    }

    @Test
    public void getDoesNotRetryClientErrors() throws Exception {
        script.add(status(404));
        assertEquals(404, client().send(CaHttpRequest.get(url()).build()).getStatusCode());
        assertEquals(1, hits.get());
    }

    @Test
    public void getRetriesAfterASlowResponseTimesOut() throws Exception {
        script.addAll(Arrays.asList(new Step(200, null, 3000), status(200)));
        CaHttpClient c = new CaHttpClient(new CaHttpClient.Settings(Duration.ofSeconds(2), Duration.ofMillis(300),
                RetryPolicy.defaults()), null, sleeper, Clock.systemUTC(), () -> 0.5);
        assertEquals(200, c.send(CaHttpRequest.get(url()).build()).getStatusCode());
        assertEquals(2, hits.get());
        assertEquals(seconds(1), sleeper.getSleeps());
    }

    @Test
    public void getToARefusedPortGivesUpAfterFourAttempts() throws Exception {
        String dead = deadUrl();
        try {
            client().send(CaHttpRequest.get(dead).build());
            fail("expected failure");
        } catch (CaHttpException e) {
            assertEquals(4, e.getAttempts());
            assertFalse(e.isRequestMayHaveBeenSent());
            assertTrue(e.getMessage(), e.getMessage().endsWith("(gave up after 4 attempts)"));
        }
        assertEquals(seconds(1, 2, 4), sleeper.getSleeps());
    }

    @Test
    public void singleAttemptRequestIsNotRetried() throws Exception {
        script.addAll(Arrays.asList(status(503), status(200)));
        CaHttpRequest ping = CaHttpRequest.get(url()).maxAttempts(1).build();
        assertEquals(503, client().send(ping).getStatusCode());
        assertEquals(1, hits.get());
    }

    // ----------------------------------------------------------------- POST

    @Test
    public void postIsNeverRetriedOnAnErrorStatus() throws Exception {
        for (int code : new int[]{500, 502, 503, 504, 429}) {
            hits.set(0);
            script.clear();
            script.addAll(Arrays.asList(new Step(code, "1", 0), status(201)));
            CaHttpResponse r = client().send(CaHttpRequest.post(url()).build());
            assertEquals(code, r.getStatusCode());
            assertEquals("POST must be sent exactly once for " + code, 1, hits.get());
        }
        assertTrue(sleeper.getSleeps().isEmpty());
    }

    @Test
    public void postIsNotRetriedAfterATimeout() throws Exception {
        script.addAll(Arrays.asList(new Step(201, null, 3000), status(201)));
        CaHttpClient c = new CaHttpClient(new CaHttpClient.Settings(Duration.ofSeconds(2), Duration.ofMillis(300),
                RetryPolicy.defaults()), null, sleeper, Clock.systemUTC(), () -> 0.5);
        try {
            c.send(CaHttpRequest.post(url()).build());
            fail("expected timeout");
        } catch (CaHttpException e) {
            assertTrue(e.isRequestMayHaveBeenSent());
            assertEquals(1, e.getAttempts());
        }
        Thread.sleep(100);
        assertEquals(1, hits.get());
        assertTrue(sleeper.getSleeps().isEmpty());
    }

    @Test
    public void postIsNotRetriedWhenTheConnectionDropsAfterSending() throws Exception {
        try (RawHttpCaptureServer raw = new RawHttpCaptureServer()) {
            raw.enqueue(RawHttpCaptureServer.Reply.dropConnection(), new RawHttpCaptureServer.Reply(201, "Created"));
            try {
                client().send(CaHttpRequest.post(raw.baseUrl() + "/CSR").build());
                fail("expected failure");
            } catch (CaHttpException e) {
                assertTrue(e.isRequestMayHaveBeenSent());
            }
            assertEquals(1, raw.getCaptured().size());
        }
        assertTrue(sleeper.getSleeps().isEmpty());
    }

    @Test
    public void postIsRetriedWhenTheConnectionWasRefused() throws Exception {
        int port;
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            port = s.getLocalPort();
        }
        AtomicInteger received = new AtomicInteger();
        List<HttpServer> late = new ArrayList<>();
        final int thePort = port;
        // The server comes up during the first backoff, i.e. after the first
        // attempt was refused (and so provably never sent).
        CaHttpClient.Sleeper bringServerUp = d -> {
            sleeper.sleep(d);
            if (late.isEmpty()) {
                try {
                    HttpServer s = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), thePort), 0);
                    s.createContext("/", ex -> {
                        received.incrementAndGet();
                        ex.getRequestBody().readAllBytes();
                        ex.sendResponseHeaders(201, -1);
                        ex.close();
                    });
                    s.start();
                    late.add(s);
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            }
        };
        try {
            CaHttpClient c = TestClients.withoutTracking(bringServerUp);
            CaHttpResponse r = c.send(CaHttpRequest.post("http://127.0.0.1:" + port + "/CSR").build());
            assertEquals(201, r.getStatusCode());
            assertEquals(1, received.get());
            assertEquals(seconds(1), sleeper.getSleeps());
        } finally {
            late.forEach(s -> s.stop(0));
        }
    }

    @Test
    public void readOnlyPostIsRetriedLikeAGet() throws Exception {
        script.addAll(Arrays.asList(status(503), status(200)));
        CaHttpRequest lookup = CaHttpRequest.post(url()).readOnlyQuery().build();
        assertEquals(200, client().send(lookup).getStatusCode());
        assertEquals(Arrays.asList("POST", "POST"), methods);
    }

    // ----------------------------------------------------------------- cancellation

    @Test
    public void interruptDuringBackoffStopsRetrying() throws Exception {
        script.addAll(Arrays.asList(status(503), status(200)));
        CaHttpClient c = TestClients.withoutTracking(d -> {
            throw new InterruptedException("cancelled");
        });
        try {
            c.send(CaHttpRequest.get(url()).build());
            fail("expected InterruptedIOException");
        } catch (InterruptedIOException expected) {
            assertTrue(Thread.interrupted()); // flag restored (and cleared here)
        }
        assertEquals(1, hits.get());
    }

    private static String deadUrl() throws IOException {
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return "http://127.0.0.1:" + s.getLocalPort() + "/CA";
        }
    }
}
