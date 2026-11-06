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

import org.junit.Test;
import uk.ngs.ca.common.ClientHostName;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Proves the golden comparison is strict where it matters: it must reject a
 * missing header, a header whose name differs only in case, an extra header,
 * a changed value and a changed body, while ignoring the documented
 * transport-level differences.
 */
public class GoldenFixtureSelfTest {

    private static final String FIXTURE = "POST /revoke HTTP/1.1\n"
            + "Date: ${DATE}\n"
            + "Content-Type: application/xml; charset=UTF-8\n"
            + "Accept: */*\n"
            + "Host: 127.0.0.1:${PORT}\n"
            + "User-Agent: NGS-CertWizard/2.2.0\n"
            + "LocalHost: ${LOCALHOST}\n"
            + "PPPK: this is pppk\n"
            + "Transfer-Encoding: chunked\n"
            + "Connection: Keep-Alive\n"
            + "\n"
            + "<Revoke><id>1</id></Revoke>";

    private static List<String[]> goodHeaders() {
        List<String[]> h = new ArrayList<>();
        // different order, Content-Length instead of chunked, no Connection
        h.add(new String[]{"Content-Length", "27"});
        h.add(new String[]{"Host", "127.0.0.1:1234"});
        h.add(new String[]{"Accept", "*/*"});
        h.add(new String[]{"Content-Type", "application/xml; charset=UTF-8"});
        h.add(new String[]{"Date", "Fri, 06 Nov 2026 15:43:51 GMT"});
        h.add(new String[]{"LocalHost", String.valueOf(ClientHostName.getHostName())});
        h.add(new String[]{"PPPK", "this is pppk"});
        h.add(new String[]{"User-Agent", "NGS-CertWizard/2.2.0"});
        return h;
    }

    private static CapturedRequest request(List<String[]> headers, String body) {
        return new CapturedRequest("POST", "/revoke", "HTTP/1.1", headers, body.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void acceptsTransportLevelDifferences() {
        GoldenFixture.assertMatches("self", FIXTURE, request(goodHeaders(), "<Revoke><id>1</id></Revoke>"));
    }

    @Test
    public void rejectsMissingHeader() {
        List<String[]> h = goodHeaders();
        h.removeIf(x -> x[0].equals("PPPK"));
        expectMismatch(request(h, "<Revoke><id>1</id></Revoke>"), "PPPK");
    }

    @Test
    public void rejectsHeaderNameCaseChange() {
        List<String[]> h = goodHeaders();
        for (String[] x : h) {
            if (x[0].equals("LocalHost")) {
                x[0] = "Localhost";
            }
        }
        expectMismatch(request(h, "<Revoke><id>1</id></Revoke>"), "LocalHost");
    }

    @Test
    public void rejectsExtraHeader() {
        List<String[]> h = goodHeaders();
        h.add(new String[]{"Accept-Encoding", "gzip"});
        expectMismatch(request(h, "<Revoke><id>1</id></Revoke>"), "Accept-Encoding");
    }

    @Test
    public void rejectsChangedValue() {
        List<String[]> h = goodHeaders();
        for (String[] x : h) {
            if (x[0].equals("User-Agent")) {
                x[1] = "Java-http-client/25";
            }
        }
        expectMismatch(request(h, "<Revoke><id>1</id></Revoke>"), "User-Agent");
    }

    @Test
    public void rejectsMalformedDate() {
        List<String[]> h = goodHeaders();
        for (String[] x : h) {
            if (x[0].equals("Date")) {
                x[1] = "Fri, 6 Nov 2026 15:43:51 GMT"; // day not zero-padded
            }
        }
        expectMismatch(request(h, "<Revoke><id>1</id></Revoke>"), "Date");
    }

    @Test
    public void rejectsChangedBody() {
        expectMismatch(request(goodHeaders(), "<Revoke><id>2</id></Revoke>"), "body differs");
    }

    private static void expectMismatch(CapturedRequest actual, String expectedInMessage) {
        try {
            GoldenFixture.assertMatches("self", FIXTURE, actual);
        } catch (AssertionError e) {
            assertTrue(e.getMessage(), e.getMessage().contains(expectedInMessage));
            return;
        }
        fail("comparison should have failed");
    }
}
