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

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import java.io.EOFException;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpTimeoutException;
import java.security.cert.CertificateException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * The retry rules, stated as tests. The most important one: a request that
 * changes server state (CSR, renewal, revocation) is never re-sent once it
 * might have reached the server.
 */
public class RetryPolicyTest {

    private final RetryPolicy policy = RetryPolicy.defaults();

    private static final CaHttpRequest GET = CaHttpRequest.newBuilder("GET", "http://ca.example/CA").build();
    private static final CaHttpRequest HEAD = CaHttpRequest.newBuilder("HEAD", "http://ca.example/CA").build();
    private static final List<CaHttpRequest> NON_IDEMPOTENT = Arrays.asList(
            CaHttpRequest.newBuilder("POST", "http://ca.example/CSR").build(),
            CaHttpRequest.newBuilder("PUT", "http://ca.example/CSR").build(),
            CaHttpRequest.newBuilder("DELETE", "http://ca.example/CSR").build(),
            CaHttpRequest.newBuilder("PATCH", "http://ca.example/CSR").build());
    private static final CaHttpRequest READ_ONLY_POST =
            CaHttpRequest.newBuilder("POST", "http://ca.example/resources/resource/publickey/pk").readOnlyQuery().build();

    private static final List<IOException> NOT_SENT = Arrays.asList(
            new ConnectException("Connection refused"),
            new HttpConnectTimeoutException("HTTP connect timed out"),
            new UnknownHostException("cwiz-live.ca.ngs.ac.uk"),
            new NoRouteToHostException("No route to host"));

    private static final List<IOException> MAYBE_SENT = Arrays.asList(
            new HttpTimeoutException("request timed out"),
            new SocketException("Connection reset"),
            new EOFException("EOF reached while reading"),
            new IOException("HTTP/1.1 header parser received no bytes"),
            new SSLHandshakeException("Remote host terminated the handshake"),
            new IOException("wrapped", new ConnectException("Connection refused")));

    private static CaHttpResponse status(int code, String... headers) {
        Map<String, List<String>> h = new java.util.HashMap<>();
        for (int i = 0; i < headers.length; i += 2) {
            h.put(headers[i], Collections.singletonList(headers[i + 1]));
        }
        return new CaHttpResponse(code, h, new byte[0]);
    }

    @Test
    public void methodDecidesIdempotency() {
        assertTrue(GET.isIdempotent());
        assertTrue(HEAD.isIdempotent());
        for (CaHttpRequest r : NON_IDEMPOTENT) {
            assertFalse(r.getMethod(), r.isIdempotent());
        }
        assertTrue(READ_ONLY_POST.isIdempotent());
    }

    @Test
    public void nonIdempotentRequestsAreRetriedOnlyWhenProvablyNotSent() {
        for (CaHttpRequest r : NON_IDEMPOTENT) {
            for (IOException e : NOT_SENT) {
                assertTrue(r.getMethod() + " " + e, policy.mayRetry(r, e));
            }
            for (IOException e : MAYBE_SENT) {
                assertFalse(r.getMethod() + " " + e, policy.mayRetry(r, e));
            }
        }
    }

    @Test
    public void nonIdempotentRequestsAreNeverRetriedOnAnyResponse() {
        for (CaHttpRequest r : NON_IDEMPOTENT) {
            for (int code = 100; code <= 599; code++) {
                assertFalse(r.getMethod() + " " + code, policy.mayRetry(r, status(code)));
            }
            assertFalse(policy.mayRetry(r, status(503, "Retry-After", "1")));
        }
    }

    @Test
    public void idempotentRequestsAreRetriedOnTransientFailures() {
        for (CaHttpRequest r : Arrays.asList(GET, HEAD, READ_ONLY_POST)) {
            for (IOException e : NOT_SENT) {
                assertTrue(policy.mayRetry(r, e));
            }
            assertTrue(policy.mayRetry(r, new HttpTimeoutException("request timed out")));
            assertTrue(policy.mayRetry(r, new SocketException("Connection reset")));
            assertTrue(policy.mayRetry(r, new EOFException()));
            assertTrue(policy.mayRetry(r, new SSLHandshakeException("Remote host terminated the handshake")));
        }
    }

    @Test
    public void certificateFailuresAndCancellationAreNotRetried() {
        SSLHandshakeException badCert = new SSLHandshakeException("PKIX path building failed");
        badCert.initCause(new CertificateException("unable to find valid certification path"));
        assertFalse(policy.mayRetry(GET, badCert));
        assertFalse(policy.mayRetry(GET, new SSLPeerUnverifiedException("peer not authenticated")));
        assertFalse(policy.mayRetry(GET, new InterruptedIOException("Interrupted")));
    }

    @Test
    public void retryableStatuses() {
        for (int code : new int[]{429, 500, 502, 503, 504, 507, 599}) {
            assertTrue(String.valueOf(code), RetryPolicy.isRetryableStatus(code));
            assertTrue(policy.mayRetry(GET, status(code)));
        }
        for (int code : new int[]{200, 201, 202, 301, 400, 401, 403, 404, 405, 408, 501, 505}) {
            assertFalse(String.valueOf(code), RetryPolicy.isRetryableStatus(code));
            assertFalse(policy.mayRetry(GET, status(code)));
        }
    }

    @Test
    public void exponentialBackoffIsCapped() {
        // random 0.5 = no jitter
        assertEquals(Duration.ofSeconds(1), policy.backoff(1, 0.5));
        assertEquals(Duration.ofSeconds(2), policy.backoff(2, 0.5));
        assertEquals(Duration.ofSeconds(4), policy.backoff(3, 0.5));
        assertEquals(Duration.ofSeconds(8), policy.backoff(4, 0.5));
        assertEquals(Duration.ofSeconds(8), policy.backoff(10, 0.5));
        assertEquals(Duration.ofSeconds(8), policy.backoff(1000, 0.5));
    }

    @Test
    public void jitterStaysWithinTwentyPercentAndUnderTheCap() {
        assertEquals(Duration.ofMillis(800), policy.backoff(1, 0.0));
        assertEquals(Duration.ofMillis(1200), policy.backoff(1, 0.999999));
        assertEquals(Duration.ofMillis(3200), policy.backoff(3, 0.0));
        assertEquals(Duration.ofSeconds(8), policy.backoff(4, 0.999999)); // 9.6s capped to 8s
        for (double r = 0; r < 1; r += 0.01) {
            long ms = policy.backoff(2, r).toMillis();
            assertTrue(ms >= 1600 && ms <= 2400);
        }
    }

    @Test
    public void retryAfterSecondsAndHttpDate() {
        Clock clock = Clock.fixed(Instant.parse("2026-11-06T15:00:00Z"), ZoneOffset.UTC);
        assertEquals(Optional.of(Duration.ofSeconds(7)), RetryPolicy.retryAfter(status(503, "Retry-After", "7"), clock));
        assertEquals(Optional.of(Duration.ofSeconds(90)),
                RetryPolicy.retryAfter(status(503, "Retry-After", "Fri, 06 Nov 2026 15:01:30 GMT"), clock));
        assertEquals(Optional.of(Duration.ZERO),
                RetryPolicy.retryAfter(status(503, "Retry-After", "Fri, 06 Nov 2026 14:00:00 GMT"), clock));
        assertEquals(Optional.of(Duration.ZERO), RetryPolicy.retryAfter(status(429, "Retry-After", "-5"), clock));
        assertEquals(Optional.empty(), RetryPolicy.retryAfter(status(429, "Retry-After", "soon"), clock));
        assertEquals(Optional.empty(), RetryPolicy.retryAfter(status(429), clock));
    }

    @Test
    public void perRequestAttemptLimit() {
        assertEquals(4, policy.attemptsFor(GET));
        assertEquals(1, policy.attemptsFor(CaHttpRequest.newBuilder("GET", "http://x/").maxAttempts(1).build()));
        assertEquals(4, policy.attemptsFor(CaHttpRequest.newBuilder("GET", "http://x/").maxAttempts(9).build()));
        assertEquals(1, RetryPolicy.noRetries().attemptsFor(GET));
    }
}
