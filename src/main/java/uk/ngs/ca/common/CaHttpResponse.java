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

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * A fully-read response from the CA server.
 */
public final class CaHttpResponse {

    private final int statusCode;
    private final Map<String, List<String>> headers;
    private final byte[] body;

    public CaHttpResponse(int statusCode, Map<String, List<String>> headers, byte[] body) {
        this.statusCode = statusCode;
        Map<String, List<String>> h = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        h.putAll(headers);
        this.headers = Collections.unmodifiableMap(h);
        this.body = body == null ? new byte[0] : body;
    }

    public int getStatusCode() {
        return statusCode;
    }

    /** First value of the named response header (case-insensitive), or null. */
    public String getHeader(String name) {
        List<String> values = headers.get(name);
        return values == null || values.isEmpty() ? null : values.get(0);
    }

    public Map<String, List<String>> getHeaders() {
        return headers;
    }

    public byte[] getBody() {
        return body.clone();
    }

    /** The charset parameter of the Content-Type header, or null. */
    public String getCharset() {
        String ct = getHeader("Content-Type");
        if (ct == null) {
            return null;
        }
        for (String param : ct.split(";")) {
            String p = param.trim();
            if (p.toLowerCase(Locale.ROOT).startsWith("charset=")) {
                return p.substring("charset=".length()).trim().replace("\"", "");
            }
        }
        return null;
    }

    /** Body decoded with the Content-Type charset (UTF-8 if none is given). */
    public String getBodyAsText() {
        Charset cs = StandardCharsets.UTF_8;
        String name = getCharset();
        if (name != null) {
            try {
                cs = Charset.forName(name);
            } catch (IllegalArgumentException ignored) {
                // unknown charset: fall back to UTF-8
            }
        }
        return new String(body, cs);
    }

    /**
     * Parse the body as XML with the hardened parser (no DOCTYPE / external
     * entities).
     *
     * @throws IOException if the body is not well-formed XML
     */
    public Document getBodyAsXml() throws IOException {
        return SafeXml.parse(body, getCharset());
    }

    /** e.g. "Forbidden (403)". */
    public String getStatusDescription() {
        return reasonPhrase(statusCode) + " (" + statusCode + ")";
    }

    static String reasonPhrase(int code) {
        switch (code) {
            case 200: return "OK";
            case 201: return "Created";
            case 202: return "Accepted";
            case 204: return "No Content";
            case 301: return "Moved Permanently";
            case 302: return "Found";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 408: return "Request Timeout";
            case 409: return "Conflict";
            case 429: return "Too Many Requests";
            case 500: return "Internal Server Error";
            case 501: return "Not Implemented";
            case 502: return "Bad Gateway";
            case 503: return "Service Unavailable";
            case 504: return "Gateway Timeout";
            default: return "HTTP status";
        }
    }

    @Override
    public String toString() {
        return getStatusDescription();
    }
}
