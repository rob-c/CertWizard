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

import com.sun.net.httpserver.HttpServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import uk.ngs.ca.wire.TestConfig;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class CaHttpClientTimeoutTest {

    private HttpServer server;
    private final CountDownLatch release = new CountDownLatch(1);

    @Before
    public void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
        server.start();
    }

    @After
    public void stopServer() {
        release.countDown();
        server.stop(0);
    }

    private String url(String path) {
        return "http://127.0.0.1:" + server.getAddress().getPort() + path;
    }

    private static CaHttpClient client(Duration connect, Duration request) {
        return new CaHttpClient(new CaHttpClient.Settings(connect, request));
    }

    @Test
    public void slowResponseHitsTheRequestTimeout() throws Exception {
        server.createContext("/slow", ex -> {
            try {
                release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
            }
            ex.sendResponseHeaders(200, -1);
            ex.close();
        });
        long start = System.nanoTime();
        try {
            client(Duration.ofSeconds(5), Duration.ofMillis(300)).send(CaHttpRequest.get(url("/slow")).build());
            fail("expected a timeout");
        } catch (CaHttpException e) {
            long ms = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
            assertTrue("took " + ms + "ms", ms < 3000);
            assertTrue(e.getMessage(), e.getMessage().contains("did not respond in time"));
            // the request was written before the timeout fired
            assertTrue(e.isRequestMayHaveBeenSent());
        }
    }

    @Test
    public void connectionRefusedIsReportedAsNotSent() throws Exception {
        int deadPort;
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            deadPort = s.getLocalPort();
        }
        try {
            client(Duration.ofSeconds(2), Duration.ofSeconds(2))
                    .send(CaHttpRequest.post("http://127.0.0.1:" + deadPort + "/CSR").build());
            fail("expected a connection failure");
        } catch (CaHttpException e) {
            assertFalse(e.isRequestMayHaveBeenSent());
            assertTrue(e.getMessage(), e.getMessage().startsWith("Could not connect to the CA server"));
        }
    }

    @Test
    public void sendsAnImfFixdateDateHeaderAndDoesNotFollowRedirects() throws Exception {
        AtomicReference<String> date = new AtomicReference<>();
        server.createContext("/redirect", ex -> {
            date.set(ex.getRequestHeaders().getFirst("Date"));
            ex.getResponseHeaders().add("Location", url("/elsewhere"));
            ex.sendResponseHeaders(302, -1);
            ex.close();
        });
        Clock fixed = Clock.fixed(Instant.parse("2026-11-06T09:03:01Z"), ZoneOffset.UTC);
        CaHttpClient c = new CaHttpClient(new CaHttpClient.Settings(Duration.ofSeconds(2), Duration.ofSeconds(2)), fixed);
        CaHttpResponse r = c.send(CaHttpRequest.get(url("/redirect")).build());
        assertEquals(302, r.getStatusCode());
        assertEquals("Fri, 06 Nov 2026 09:03:01 GMT", date.get());
    }

    @Test
    public void timeoutsAreReadFromConfiguration() {
        CaHttpClient.Settings defaults = CaHttpClient.Settings.fromConfig();
        assertEquals(Duration.ofSeconds(10), defaults.getConnectTimeout());
        assertEquals(Duration.ofSeconds(30), defaults.getRequestTimeout());

        TestConfig.set("uk.ngs.ca.http.connect.timeout.secs", "3");
        TestConfig.set("uk.ngs.ca.http.request.timeout.secs", "7");
        try {
            CaHttpClient.Settings s = CaHttpClient.Settings.fromConfig();
            assertEquals(Duration.ofSeconds(3), s.getConnectTimeout());
            assertEquals(Duration.ofSeconds(7), s.getRequestTimeout());
        } finally {
            TestConfig.set("uk.ngs.ca.http.connect.timeout.secs", "10");
            TestConfig.set("uk.ngs.ca.http.request.timeout.secs", "30");
        }
    }
}
