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

import uk.ngs.ca.tools.property.SysProperty;

import javax.net.ssl.SSLPeerUnverifiedException;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Optional;

/**
 * When, and after how long, a failed request to the CA server is retried.
 * <p>
 * <b>The rule.</b> A request is retried only if repeating it is harmless:
 * <ul>
 * <li><b>Idempotent requests</b> (GET/HEAD/OPTIONS, plus a POST explicitly
 * marked {@link CaHttpRequest.Builder#readOnlyQuery() read-only}) are retried
 * on any I/O failure (connection failures, timeouts, resets), except
 * certificate/trust failures which cannot heal by themselves, and on HTTP
 * 429 and 5xx responses other than 501 and 505.</li>
 * <li><b>Non-idempotent requests</b> (POST/PUT/DELETE: CSR submission,
 * renewal, revocation) are <em>never</em> retried once they might have
 * reached the server. They are retried only when the failure provably
 * happened before any of the request was sent - see
 * {@link NetworkFailures#isProvablyNotSent(IOException)} - and never on any
 * HTTP response, whatever its status.</li>
 * </ul>
 * Delays: exponential backoff ({@code initialBackoff}, doubling, capped at
 * {@code maxBackoff}) with +/-{@code jitter} randomisation. A
 * {@code Retry-After} header (seconds or HTTP-date) on a retryable response
 * replaces the backoff; if it asks for longer than {@code maxRetryAfter} the
 * response is returned instead of waiting.
 */
public final class RetryPolicy {

    private final int maxAttempts;
    private final Duration initialBackoff;
    private final Duration maxBackoff;
    private final double jitter;
    private final Duration maxRetryAfter;

    /**
     * @param maxAttempts    total attempts including the first (1 = no retries)
     * @param initialBackoff delay before the first retry
     * @param maxBackoff     cap for any backoff delay
     * @param jitter         fraction in [0, 1): each delay is scaled by a
     *                       random factor in [1 - jitter, 1 + jitter]
     * @param maxRetryAfter  longest Retry-After to honour
     */
    public RetryPolicy(int maxAttempts, Duration initialBackoff, Duration maxBackoff, double jitter, Duration maxRetryAfter) {
        if (maxAttempts < 1) {
            throw new IllegalArgumentException("maxAttempts must be >= 1");
        }
        if (jitter < 0 || jitter >= 1) {
            throw new IllegalArgumentException("jitter must be in [0, 1)");
        }
        this.maxAttempts = maxAttempts;
        this.initialBackoff = initialBackoff;
        this.maxBackoff = maxBackoff;
        this.jitter = jitter;
        this.maxRetryAfter = maxRetryAfter;
    }

    /** 4 attempts, 1s/2s/4s (+/-20%), capped at 8s, Retry-After up to 30s. */
    public static RetryPolicy defaults() {
        return new RetryPolicy(4, Duration.ofSeconds(1), Duration.ofSeconds(8), 0.2, Duration.ofSeconds(30));
    }

    /** A policy that never retries. */
    public static RetryPolicy noRetries() {
        return new RetryPolicy(1, Duration.ZERO, Duration.ZERO, 0, Duration.ZERO);
    }

    /** The policy from configure.properties (defaults as {@link #defaults()}). */
    public static RetryPolicy fromConfig() {
        return new RetryPolicy(
                Math.max(1, SysProperty.getInt("uk.ngs.ca.http.retry.max.attempts", 4)),
                Duration.ofMillis(Math.max(0, SysProperty.getInt("uk.ngs.ca.http.retry.initial.backoff.millis", 1000))),
                Duration.ofMillis(Math.max(0, SysProperty.getInt("uk.ngs.ca.http.retry.max.backoff.millis", 8000))),
                0.2,
                Duration.ofSeconds(Math.max(0, SysProperty.getInt("uk.ngs.ca.http.retry.after.max.secs", 30))));
    }

    public int getMaxAttempts() {
        return maxAttempts;
    }

    public Duration getMaxRetryAfter() {
        return maxRetryAfter;
    }

    /** Attempts allowed for this request (a per-request limit may lower it). */
    public int attemptsFor(CaHttpRequest request) {
        int perRequest = request.getMaxAttempts();
        return perRequest > 0 ? Math.min(perRequest, maxAttempts) : maxAttempts;
    }

    /** May the request be sent again after this transport failure? */
    public boolean mayRetry(CaHttpRequest request, IOException failure) {
        if (failure instanceof InterruptedIOException && !(failure instanceof java.net.SocketTimeoutException)) {
            return false; // the user/caller cancelled
        }
        if (!request.isIdempotent()) {
            return NetworkFailures.isProvablyNotSent(failure);
        }
        return !isPermanentTrustFailure(failure);
    }

    /** May the request be sent again after this HTTP response? */
    public boolean mayRetry(CaHttpRequest request, CaHttpResponse response) {
        return request.isIdempotent() && isRetryableStatus(response.getStatusCode());
    }

    /** 429 and 5xx, except 501 Not Implemented and 505 HTTP Version Not Supported. */
    public static boolean isRetryableStatus(int status) {
        return status == 429 || (status >= 500 && status <= 599 && status != 501 && status != 505);
    }

    /**
     * Backoff before retry number {@code retry} (1 for the first retry).
     *
     * @param random a uniformly distributed value in [0, 1)
     */
    public Duration backoff(int retry, double random) {
        long base = initialBackoff.toMillis();
        for (int i = 1; i < retry && base < maxBackoff.toMillis(); i++) {
            base *= 2;
        }
        base = Math.min(base, maxBackoff.toMillis());
        double factor = 1 - jitter + 2 * jitter * random;
        long millis = Math.min(Math.round(base * factor), maxBackoff.toMillis());
        return Duration.ofMillis(Math.max(0, millis));
    }

    /**
     * The delay requested by a Retry-After header (delta-seconds or
     * HTTP-date), or empty if absent/unparseable.
     */
    public static Optional<Duration> retryAfter(CaHttpResponse response, Clock clock) {
        String value = response.getHeader("Retry-After");
        if (value == null || value.trim().isEmpty()) {
            return Optional.empty();
        }
        value = value.trim();
        try {
            long seconds = Long.parseLong(value);
            return Optional.of(Duration.ofSeconds(Math.max(0, seconds)));
        } catch (NumberFormatException notSeconds) {
            try {
                Instant when = ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant();
                Duration d = Duration.between(clock.instant(), when);
                return Optional.of(d.isNegative() ? Duration.ZERO : d);
            } catch (DateTimeParseException notADate) {
                return Optional.empty();
            }
        }
    }

    /** TLS failures caused by certificate validation will not heal by retrying. */
    static boolean isPermanentTrustFailure(IOException e) {
        if (e instanceof SSLPeerUnverifiedException) {
            return true;
        }
        for (Throwable c = e; c != null; c = c.getCause()) {
            if (c instanceof GeneralSecurityException) { // CertificateException, CertPathValidatorException...
                return true;
            }
            if (c.getCause() == c) {
                break;
            }
        }
        return false;
    }
}
