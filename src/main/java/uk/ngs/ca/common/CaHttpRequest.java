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

import org.w3c.dom.Document;
import uk.ngs.ca.tools.property.SysProperty;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * An immutable request to the CA server.
 * <p>
 * {@link #get(String)} and {@link #post(String)} pre-populate the headers
 * every CertWizard request has always carried: {@code Accept: *}{@code /*},
 * {@code User-Agent} (from {@code uk.ngs.ca.request.useragent}) and
 * {@code LocalHost} (the canonical local host name, empty if it cannot be
 * resolved; cached for 10 minutes because the reverse DNS lookup can stall
 * for seconds when the network is down). {@link CaHttpClient} adds a
 * {@code Date} header when sending.
 * Header names keep their case exactly as given.
 */
public final class CaHttpRequest {

    /** Content type of every XML request body. */
    public static final String XML_CONTENT_TYPE = "application/xml; charset=UTF-8";

    private static final long HOST_NAME_TTL_NANOS = TimeUnit.MINUTES.toNanos(10);
    private static volatile String cachedHostName;
    private static volatile long cachedHostNameAt;

    private final String method;
    private final URI uri;
    private final List<String[]> headers;
    private final byte[] body;
    private final Boolean idempotentOverride;
    private final int maxAttempts;
    private final boolean connectivityProbe;

    private CaHttpRequest(Builder b) {
        this.method = b.method;
        this.uri = b.uri;
        this.headers = Collections.unmodifiableList(new ArrayList<>(b.headers));
        this.body = b.body;
        this.idempotentOverride = b.idempotentOverride;
        this.maxAttempts = b.maxAttempts;
        this.connectivityProbe = b.connectivityProbe;
    }

    /** A GET request with the standard CertWizard headers. */
    public static Builder get(String url) {
        return new Builder("GET", url).standardHeaders();
    }

    /** A POST request with the standard CertWizard headers. */
    public static Builder post(String url) {
        return new Builder("POST", url).standardHeaders();
    }

    /** The local host name for the LocalHost header (null if unresolvable). */
    static String localHostName() {
        String name = cachedHostName;
        long now = System.nanoTime();
        if (name != null && now - cachedHostNameAt < HOST_NAME_TTL_NANOS) {
            return name;
        }
        name = ClientHostName.getHostName();
        if (name != null) {
            cachedHostName = name;
            cachedHostNameAt = now;
        }
        return name;
    }

    /** A request with no headers pre-populated. */
    public static Builder newBuilder(String method, String url) {
        return new Builder(method, url);
    }

    public String getMethod() {
        return method;
    }

    public URI getUri() {
        return uri;
    }

    /** Headers as {name, value} pairs in insertion order. */
    public List<String[]> getHeaders() {
        return headers;
    }

    /** The first value of the named header (case-insensitive), or null. */
    public String getHeader(String name) {
        for (String[] h : headers) {
            if (h[0].equalsIgnoreCase(name)) {
                return h[1];
            }
        }
        return null;
    }

    /** Request body, or null for none. */
    public byte[] getBody() {
        return body == null ? null : body.clone();
    }

    /**
     * Whether repeating this request is harmless. By default this follows the
     * HTTP method: GET, HEAD and OPTIONS are idempotent; POST, PUT, DELETE and
     * everything else are not. See {@link Builder#readOnlyQuery()}.
     */
    public boolean isIdempotent() {
        if (idempotentOverride != null) {
            return idempotentOverride;
        }
        return "GET".equals(method) || "HEAD".equals(method) || "OPTIONS".equals(method);
    }

    /** Per-request attempt limit, or 0 to use the client's retry policy. */
    public int getMaxAttempts() {
        return maxAttempts;
    }

    /**
     * True for the connectivity check itself (the ping): it is never
     * short-circuited when the server is known to be unreachable.
     */
    public boolean isConnectivityProbe() {
        return connectivityProbe;
    }

    @Override
    public String toString() {
        return method + " " + uri;
    }

    public static final class Builder {

        private final String method;
        private final URI uri;
        private final List<String[]> headers = new ArrayList<>();
        private byte[] body;
        private Boolean idempotentOverride;
        private int maxAttempts;
        private boolean connectivityProbe;

        private Builder(String method, String url) {
            this.method = method;
            this.uri = URI.create(url);
        }

        private Builder standardHeaders() {
            header("Accept", "*/*");
            header("User-Agent", SysProperty.getValue("uk.ngs.ca.request.useragent"));
            header("LocalHost", localHostName());
            return this;
        }

        /**
         * Set a header, replacing any existing header of the same name
         * (compared case-insensitively). The name's case is sent as given. A
         * null value is sent as an empty value, as the original client did.
         */
        public Builder header(String name, String value) {
            String v = value == null ? "" : value;
            for (String[] h : headers) {
                if (h[0].equalsIgnoreCase(name)) {
                    h[0] = name;
                    h[1] = v;
                    return this;
                }
            }
            headers.add(new String[]{name, v});
            return this;
        }

        /** Use the serialised document as the body, with the XML content type. */
        public Builder xmlBody(Document document) {
            this.body = SafeXml.serialize(document);
            return header("Content-Type", XML_CONTENT_TYPE);
        }

        /**
         * Mark a POST that only reads server state (the public-key lookup) as
         * safe to repeat, so it gets the same retry treatment as a GET. Never
         * use this for a request that creates or changes anything.
         */
        public Builder readOnlyQuery() {
            this.idempotentOverride = Boolean.TRUE;
            return this;
        }

        /** Limit the number of attempts for this request (1 = no retries). */
        public Builder maxAttempts(int attempts) {
            if (attempts < 1) {
                throw new IllegalArgumentException("attempts must be >= 1");
            }
            this.maxAttempts = attempts;
            return this;
        }

        /** Mark this request as the connectivity check (see {@link #isConnectivityProbe()}). */
        public Builder connectivityProbe() {
            this.connectivityProbe = true;
            return this;
        }

        public CaHttpRequest build() {
            return new CaHttpRequest(this);
        }
    }
}
