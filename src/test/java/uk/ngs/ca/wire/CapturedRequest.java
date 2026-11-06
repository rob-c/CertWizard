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
package uk.ngs.ca.wire;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * One HTTP request exactly as it arrived on the wire: request line, header
 * lines in arrival order with their original name case, and the de-framed
 * body (chunked transfer coding removed).
 */
public final class CapturedRequest {

    public final String method;
    public final String target;
    public final String httpVersion;
    /** Each entry is {name, value} with the name's case preserved. */
    public final List<String[]> headers;
    public final byte[] body;

    public CapturedRequest(String method, String target, String httpVersion, List<String[]> headers, byte[] body) {
        this.method = method;
        this.target = target;
        this.httpVersion = httpVersion;
        this.headers = Collections.unmodifiableList(new ArrayList<>(headers));
        this.body = body;
    }

    public String path() {
        int q = target.indexOf('?');
        return q < 0 ? target : target.substring(0, q);
    }

    public String query() {
        int q = target.indexOf('?');
        return q < 0 ? null : target.substring(q + 1);
    }

    /** First header value matching the name case-insensitively, or null. */
    public String header(String name) {
        for (String[] h : headers) {
            if (h[0].equalsIgnoreCase(name)) {
                return h[1];
            }
        }
        return null;
    }

    public String bodyAsString() {
        return new String(body, StandardCharsets.UTF_8);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(method).append(' ').append(target).append(' ').append(httpVersion).append('\n');
        for (String[] h : headers) {
            sb.append(h[0]).append(": ").append(h[1]).append('\n');
        }
        sb.append('\n').append(bodyAsString());
        return sb.toString();
    }
}
