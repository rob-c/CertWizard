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

/**
 * The single HTTP client used to talk to the CA server, built on
 * {@link java.net.http.HttpClient} (HTTP/1.1, TLS trust from the
 * {@code javax.net.ssl.trustStore} system properties that CertWizardMain
 * sets, system proxy settings honoured, redirects not followed).
 * <p>
 * Timeouts are read from configure.properties:
 * {@code uk.ngs.ca.http.connect.timeout.secs} (default 10) and
 * {@code uk.ngs.ca.http.request.timeout.secs} (default 30).
 */
public class CaHttpClient {

    private static final Logger logger = LogManager.getLogger(CaHttpClient.class);

    /** RFC 1123 / IMF-fixdate, as the original client sent it. */
    private static final DateTimeFormatter HTTP_DATE =
            DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.US).withZone(ZoneOffset.UTC);

    private static volatile CaHttpClient defaultClient;

    private final Settings settings;
    private final Clock clock;
    private volatile HttpClient httpClient;

    /** Timeouts (and, later, the retry policy) for a client. */
    public static final class Settings {

        final Duration connectTimeout;
        final Duration requestTimeout;

        public Settings(Duration connectTimeout, Duration requestTimeout) {
            this.connectTimeout = connectTimeout;
            this.requestTimeout = requestTimeout;
        }

        /** Settings from configure.properties (with defaults). */
        public static Settings fromConfig() {
            return new Settings(
                    Duration.ofSeconds(SysProperty.getInt("uk.ngs.ca.http.connect.timeout.secs", 10)),
                    Duration.ofSeconds(SysProperty.getInt("uk.ngs.ca.http.request.timeout.secs", 30)));
        }

        public Duration getConnectTimeout() {
            return connectTimeout;
        }

        public Duration getRequestTimeout() {
            return requestTimeout;
        }
    }

    public CaHttpClient(Settings settings) {
        this(settings, Clock.systemUTC());
    }

    CaHttpClient(Settings settings, Clock clock) {
        this.settings = settings;
        this.clock = clock;
    }

    /** The shared client, configured from configure.properties. */
    public static CaHttpClient getDefault() {
        CaHttpClient c = defaultClient;
        if (c == null) {
            synchronized (CaHttpClient.class) {
                c = defaultClient;
                if (c == null) {
                    c = new CaHttpClient(Settings.fromConfig());
                    defaultClient = c;
                }
            }
        }
        return c;
    }

    public Settings getSettings() {
        return settings;
    }

    /**
     * Send the request and read the whole response.
     *
     * @return the response, whatever its HTTP status
     * @throws CaHttpException         if no HTTP response was received
     * @throws InterruptedIOException  if the calling thread was interrupted
     */
    public CaHttpResponse send(CaHttpRequest request) throws IOException {
        try {
            HttpResponse<byte[]> r = http().send(toHttpRequest(request), HttpResponse.BodyHandlers.ofByteArray());
            logger.debug("{} -> {}", request, r.statusCode());
            return new CaHttpResponse(r.statusCode(), r.headers().map(), r.body());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            InterruptedIOException iioe = new InterruptedIOException("Interrupted while contacting the CA server");
            iioe.initCause(e);
            throw iioe;
        } catch (IOException e) {
            logger.warn("{} failed: {}", request, e.toString());
            throw new CaHttpException(NetworkFailures.describe(e, request.getUri().getHost()), e,
                    !NetworkFailures.isProvablyNotSent(e), 1);
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
