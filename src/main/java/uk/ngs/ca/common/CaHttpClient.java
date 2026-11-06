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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.ngs.ca.tools.property.SysProperty;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.DoubleSupplier;

/**
 * The single HTTP client used to talk to the CA server, built on
 * {@link java.net.http.HttpClient} (HTTP/1.1, TLS trust from the
 * {@code javax.net.ssl.trustStore} system properties that CertWizardMain
 * sets, system proxy settings honoured, redirects not followed).
 * <ul>
 * <li>Timeouts: {@code uk.ngs.ca.http.connect.timeout.secs} (default 10)
 * and {@code uk.ngs.ca.http.request.timeout.secs} (default 30, per
 * attempt).</li>
 * <li>Retries: see {@link RetryPolicy} for exactly which failures are
 * retried - in short, idempotent requests are retried with exponential
 * backoff and jitter; CSR/renewal/revocation POSTs only when the connection
 * could not be established at all.</li>
 * <li>Offline: with a {@link ConnectivityTracker} (the default client uses
 * {@link ConnectivityMonitor}), requests fail fast with
 * {@link CaOfflineException} while the server is known to be unreachable,
 * and every outcome is reported back so the online status stays current.
 * The connectivity probe itself is never short-circuited.</li>
 * </ul>
 */
public class CaHttpClient {

    private static final Logger logger = LogManager.getLogger(CaHttpClient.class);

    /** RFC 1123 / IMF-fixdate, as the original client sent it. */
    private static final DateTimeFormatter HTTP_DATE =
            DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.US).withZone(ZoneOffset.UTC);

    private static volatile CaHttpClient defaultClient;

    private final Settings settings;
    private final ConnectivityTracker tracker;
    private final Sleeper sleeper;
    private final Clock clock;
    private final DoubleSupplier random;
    private volatile HttpClient httpClient;

    /** Waits between attempts; replaceable so tests need not really sleep. */
    @FunctionalInterface
    public interface Sleeper {

        Sleeper REAL = d -> {
            if (!d.isZero() && !d.isNegative()) {
                Thread.sleep(d.toMillis());
            }
        };

        void sleep(Duration duration) throws InterruptedException;
    }

    /** Timeouts and retry policy for a client. */
    public static final class Settings {

        final Duration connectTimeout;
        final Duration requestTimeout;
        final RetryPolicy retryPolicy;

        public Settings(Duration connectTimeout, Duration requestTimeout) {
            this(connectTimeout, requestTimeout, RetryPolicy.defaults());
        }

        public Settings(Duration connectTimeout, Duration requestTimeout, RetryPolicy retryPolicy) {
            this.connectTimeout = connectTimeout;
            this.requestTimeout = requestTimeout;
            this.retryPolicy = retryPolicy;
        }

        /** Settings from configure.properties (with defaults). */
        public static Settings fromConfig() {
            return new Settings(
                    Duration.ofSeconds(SysProperty.getInt("uk.ngs.ca.http.connect.timeout.secs", 10)),
                    Duration.ofSeconds(SysProperty.getInt("uk.ngs.ca.http.request.timeout.secs", 30)),
                    RetryPolicy.fromConfig());
        }

        public Duration getConnectTimeout() {
            return connectTimeout;
        }

        public Duration getRequestTimeout() {
            return requestTimeout;
        }

        public RetryPolicy getRetryPolicy() {
            return retryPolicy;
        }
    }

    /** A client with no connectivity tracking that really sleeps between retries. */
    public CaHttpClient(Settings settings) {
        this(settings, null, Sleeper.REAL, Clock.systemUTC(), () -> ThreadLocalRandom.current().nextDouble());
    }

    CaHttpClient(Settings settings, Clock clock) {
        this(settings, null, Sleeper.REAL, clock, () -> ThreadLocalRandom.current().nextDouble());
    }

    /**
     * @param settings timeouts and retry policy
     * @param tracker  online/offline state to consult and update, or null
     * @param sleeper  waits between attempts
     * @param clock    for the Date header and Retry-After dates
     * @param random   uniform values in [0, 1) for backoff jitter
     */
    public CaHttpClient(Settings settings, ConnectivityTracker tracker, Sleeper sleeper, Clock clock, DoubleSupplier random) {
        this.settings = settings;
        this.tracker = tracker;
        this.sleeper = sleeper;
        this.clock = clock;
        this.random = random;
    }

    /**
     * The shared client: configured from configure.properties and wired to
     * {@link ConnectivityMonitor#getInstance()}.
     */
    public static CaHttpClient getDefault() {
        CaHttpClient c = defaultClient;
        if (c == null) {
            synchronized (CaHttpClient.class) {
                c = defaultClient;
                if (c == null) {
                    c = new CaHttpClient(Settings.fromConfig(), ConnectivityMonitor.getInstance(), Sleeper.REAL,
                            Clock.systemUTC(), () -> ThreadLocalRandom.current().nextDouble());
                    defaultClient = c;
                }
            }
        }
        return c;
    }

    /**
     * Replace the shared client (for tests); null restores the configured
     * default on next use.
     */
    public static synchronized void setDefault(CaHttpClient client) {
        defaultClient = client;
    }

    public Settings getSettings() {
        return settings;
    }

    /**
     * Send the request, retrying as {@link RetryPolicy} allows, and read the
     * whole response.
     *
     * @return the final response, whatever its HTTP status
     * @throws CaOfflineException     at once, if the server is known to be
     *                                unreachable (nothing is sent)
     * @throws CaHttpException        if no HTTP response was received
     * @throws InterruptedIOException if the calling thread was interrupted
     */
    public CaHttpResponse send(CaHttpRequest request) throws IOException {
        NetworkGuard.checkAllowed(request.getUri());
        boolean tracked = tracker != null && !request.isConnectivityProbe();
        if (tracked && tracker.isKnownOffline()) {
            logger.info("{} not sent: the CA server is currently unreachable", request);
            throw new CaOfflineException(tracker.describeOffline());
        }
        RetryPolicy policy = settings.retryPolicy;
        int maxAttempts = policy.attemptsFor(request);
        boolean maybeSent = false;
        for (int attempt = 1; ; attempt++) {
            CaHttpResponse response;
            try {
                response = sendOnce(request);
            } catch (IOException e) {
                if (Thread.currentThread().isInterrupted()) {
                    throw e; // cancelled by the caller: no retry, no state change
                }
                maybeSent |= !NetworkFailures.isProvablyNotSent(e);
                if (attempt < maxAttempts && policy.mayRetry(request, e)) {
                    Duration delay = policy.backoff(attempt, random.getAsDouble());
                    logger.info("{} attempt {}/{} failed ({}); retrying in {} ms",
                            request, attempt, maxAttempts, e, delay.toMillis());
                    pause(delay);
                    continue;
                }
                logger.warn("{} failed after {} attempt(s): {}", request, attempt, e.toString());
                String message = NetworkFailures.describe(e, request.getUri().getHost());
                if (tracked && NetworkFailures.isConnectivityFailure(e)) {
                    tracker.reportUnreachable(message);
                }
                if (attempt > 1) {
                    message += " (gave up after " + attempt + " attempts)";
                }
                throw new CaHttpException(message, e, maybeSent, attempt);
            }

            if (attempt < maxAttempts && policy.mayRetry(request, response)) {
                Optional<Duration> retryAfter = RetryPolicy.retryAfter(response, clock);
                if (retryAfter.isPresent() && retryAfter.get().compareTo(policy.getMaxRetryAfter()) > 0) {
                    logger.info("{} -> {}; Retry-After of {}s is too long, not retrying",
                            request, response.getStatusCode(), retryAfter.get().getSeconds());
                } else {
                    Duration delay = retryAfter.isPresent()
                            ? retryAfter.get()
                            : policy.backoff(attempt, random.getAsDouble());
                    logger.info("{} attempt {}/{} -> {}; retrying in {} ms",
                            request, attempt, maxAttempts, response.getStatusCode(), delay.toMillis());
                    pause(delay);
                    continue;
                }
            }
            if (tracked) {
                tracker.reportReachable();
            }
            return response;
        }
    }

    private void pause(Duration delay) throws InterruptedIOException {
        try {
            sleeper.sleep(delay);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            InterruptedIOException iioe = new InterruptedIOException("Interrupted while waiting to retry");
            iioe.initCause(e);
            throw iioe;
        }
    }

    /** One attempt, no retries. */
    private CaHttpResponse sendOnce(CaHttpRequest request) throws IOException {
        try {
            HttpResponse<byte[]> r = http().send(toHttpRequest(request), HttpResponse.BodyHandlers.ofByteArray());
            logger.debug("{} -> {}", request, r.statusCode());
            return new CaHttpResponse(r.statusCode(), r.headers().map(), r.body());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            InterruptedIOException iioe = new InterruptedIOException("Interrupted while contacting the CA server");
            iioe.initCause(e);
            throw iioe;
        }
    }

    HttpRequest toHttpRequest(CaHttpRequest request) {
        HttpRequest.Builder b = HttpRequest.newBuilder(request.getUri())
                .timeout(settings.requestTimeout)
                .header("Date", HTTP_DATE.format(clock.instant()));
        for (String[] h : request.getHeaders()) {
            b.header(h[0], h[1]);
        }
        byte[] body = request.getBody();
        HttpRequest.BodyPublisher publisher = body == null
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofByteArray(body);
        return b.method(request.getMethod(), publisher).build();
    }

    private HttpClient http() {
        HttpClient c = httpClient;
        if (c == null) {
            synchronized (this) {
                c = httpClient;
                if (c == null) {
                    // Built lazily so that the javax.net.ssl.trustStore system
                    // properties set at start-up are in place before the
                    // default SSLContext is created.
                    HttpClient.Builder b = HttpClient.newBuilder()
                            .version(HttpClient.Version.HTTP_1_1)
                            .connectTimeout(settings.connectTimeout)
                            .followRedirects(HttpClient.Redirect.NEVER);
                    ProxySelector proxySelector = ProxySelector.getDefault();
                    if (proxySelector != null) {
                        b.proxy(proxySelector); // honours http(s).proxyHost etc.
                    }
                    c = b.build();
                    httpClient = c;
                }
            }
        }
        return c;
    }
}
