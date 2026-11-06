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

/**
 * An immutable request to the CA server.
 * <p>
 * {@link #get(String)} and {@link #post(String)} pre-populate the headers
 * every CertWizard request has always carried: {@code Accept: *}{@code /*},
 * {@code User-Agent} (from {@code uk.ngs.ca.request.useragent}) and
 * {@code LocalHost} (the canonical local host name, empty if it cannot be
 * resolved). {@link CaHttpClient} adds a {@code Date} header when sending.
 * Header names keep their case exactly as given.
 */
public final class CaHttpRequest {

    /** Content type of every XML request body. */
    public static final String XML_CONTENT_TYPE = "application/xml; charset=UTF-8";

    private final String method;
    private final URI uri;
    private final List<String[]> headers;
    private final byte[] body;

    private CaHttpRequest(Builder b) {
        this.method = b.method;
        this.uri = b.uri;
        this.headers = Collections.unmodifiableList(new ArrayList<>(b.headers));
        this.body = b.body;
    }

    /** A GET request with the standard CertWizard headers. */
    public static Builder get(String url) {
        return new Builder("GET", url).standardHeaders();
    }

    /** A POST request with the standard CertWizard headers. */
    public static Builder post(String url) {
        return new Builder("POST", url).standardHeaders();
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
     * Whether repeating this request is harmless: GET, HEAD and OPTIONS are
     * idempotent; POST, PUT, DELETE and everything else are not.
     */
    public boolean isIdempotent() {
        return "GET".equals(method) || "HEAD".equals(method) || "OPTIONS".equals(method);
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

        private Builder(String method, String url) {
            this.method = method;
            this.uri = URI.create(url);
        }

        private Builder standardHeaders() {
            header("Accept", "*/*");
            header("User-Agent", SysProperty.getValue("uk.ngs.ca.request.useragent"));
            header("LocalHost", ClientHostName.getHostName());
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

        public CaHttpRequest build() {
            return new CaHttpRequest(this);
        }
    }
}
