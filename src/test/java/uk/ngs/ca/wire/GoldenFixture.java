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

import uk.ngs.ca.common.ClientHostName;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

/**
 * Golden request fixtures: one {@code .http} file per request, holding the
 * request line, header lines (original order and name case) and the exact
 * de-chunked body, with run-specific values replaced by placeholders.
 * <p>
 * Run with {@code -Dgolden.record=true} to (re)write the fixtures from
 * whatever implementation is currently on the classpath. The fixtures in
 * the repository were recorded from the Restlet 3.0-M1 implementation, and
 * must not be re-recorded from any other implementation.
 * <p>
 * Comparison rules:
 * <ul>
 * <li>method, request target (path and query) and HTTP version must be
 * identical;</li>
 * <li>the body must be byte-identical (after placeholder substitution and
 * CRLF/LF normalisation, which only matters for PEM text produced with the
 * platform line separator);</li>
 * <li>every header must be present with the same name (case-sensitive) and
 * the same value, and no extra headers may be sent, <em>except</em> the
 * transport-level headers in {@link #IGNORED_TRANSPORT_HEADERS}. Header order
 * is not compared.</li>
 * </ul>
 */
public final class GoldenFixture {

    public static final boolean RECORD = Boolean.getBoolean("golden.record");

    /**
     * Headers that only describe message framing / connection management and
     * carry no application meaning. Differences in these are deliberately
     * ignored (names compared case-insensitively):
     * <ul>
     * <li>Host - always the authority from the request URL; only its
     * formatting differs between clients.</li>
     * <li>Connection - Restlet sent "Keep-Alive"; persistent connections are
     * the HTTP/1.1 default and java.net.http does not allow setting it.</li>
     * <li>Transfer-Encoding / Content-Length - Restlet streamed bodies with
     * chunked transfer coding; java.net.http sends a Content-Length. Both
     * deliver the identical body bytes.</li>
     * </ul>
     */
    public static final Set<String> IGNORED_TRANSPORT_HEADERS = caseInsensitiveSet(
            "Host", "Connection", "Transfer-Encoding", "Content-Length");

    private static final String RESOURCE_DIR = "/golden/requests/";

    private GoldenFixture() {
    }

    /** Values that legitimately vary between runs/machines. */
    static final class Placeholders {
        static final String PORT = "${PORT}";
        static final String LOCALHOST = "${LOCALHOST}";
        static final String DATE = "${DATE}";
        static final String PPPK_RESPONSE = "${PPPK_RESPONSE}";
        static final String RANDOM_PIN_HASH = "${RANDOM_PIN_HASH}";
    }

    /**
     * Compare (or, in record mode, write) the captured requests of one
     * scenario against {@code <scenario>.<n>.http}.
     *
     * @param randomPin true if the request body carries a random PIN hash
     *                  (the renewal request), which is replaced by a
     *                  placeholder.
     */
    public static void check(String scenario, List<CapturedRequest> captured, boolean randomPin) throws IOException {
        if (RECORD) {
            Path dir = Paths.get(System.getProperty("user.dir"), "src", "test", "resources", "golden", "requests");
            Files.createDirectories(dir);
            for (int i = 0; i < captured.size(); i++) {
                Files.write(dir.resolve(scenario + "." + (i + 1) + ".http"),
                        render(captured.get(i), randomPin).getBytes(StandardCharsets.UTF_8));
            }
            return;
        }
        int expectedCount = 0;
        while (GoldenFixture.class.getResource(RESOURCE_DIR + scenario + "." + (expectedCount + 1) + ".http") != null) {
            expectedCount++;
        }
        if (expectedCount == 0) {
            fail("No golden fixture for scenario '" + scenario + "'. Record with -Dgolden.record=true "
                    + "(only from the original Restlet implementation).");
        }
        assertEquals("number of requests sent for scenario " + scenario, expectedCount, captured.size());
        for (int i = 0; i < expectedCount; i++) {
            String name = scenario + "." + (i + 1) + ".http";
            assertMatches(name, load(name), captured.get(i));
        }
    }

    static String load(String name) throws IOException {
        try (InputStream in = GoldenFixture.class.getResourceAsStream(RESOURCE_DIR + name)) {
            assertNotNull("missing fixture " + name, in);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /** Render a captured request in fixture form. */
    static String render(CapturedRequest r, boolean randomPin) {
        String localHost = ClientHostName.getHostName();
        StringBuilder sb = new StringBuilder();
        sb.append(r.method).append(' ').append(r.target).append(' ').append(r.httpVersion).append('\n');
        for (String[] h : r.headers) {
            String value = h[1];
            if (h[0].equalsIgnoreCase("Host")) {
                value = value.replaceFirst(":\\d+$", Matcher.quoteReplacement(":" + Placeholders.PORT));
            } else if (h[0].equals("LocalHost") && value.equals(localHost)) {
                value = Placeholders.LOCALHOST;
            } else if (h[0].equalsIgnoreCase("Date")) {
                value = Placeholders.DATE;
            } else if (h[0].equals("response")) {
                value = Placeholders.PPPK_RESPONSE;
            }
            sb.append(h[0]).append(": ").append(value).append('\n');
        }
        sb.append('\n');
        String body = r.bodyAsString();
        if (randomPin) {
            body = body.replaceAll("<PIN>[0-9A-F]{40}</PIN>", "<PIN>" + Matcher.quoteReplacement(Placeholders.RANDOM_PIN_HASH) + "</PIN>");
        }
        sb.append(body);
        return sb.toString();
    }

    /** Parsed form of a fixture file. */
    static final class Parsed {
        String requestLine;
        final List<String[]> headers = new ArrayList<>();
        String body;
    }

    static Parsed parse(String fixture) {
        Parsed p = new Parsed();
        int split = fixture.indexOf("\n\n");
        String head = split < 0 ? fixture : fixture.substring(0, split);
        p.body = split < 0 ? "" : fixture.substring(split + 2);
        String[] lines = head.split("\n");
        p.requestLine = lines[0];
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            p.headers.add(new String[]{lines[i].substring(0, colon), lines[i].substring(colon + 1).trim()});
        }
        return p;
    }

    static void assertMatches(String name, String fixture, CapturedRequest actual) {
        Parsed expected = parse(fixture);
        List<String> problems = new ArrayList<>();

        String actualLine = actual.method + " " + actual.target + " " + actual.httpVersion;
        if (!expected.requestLine.equals(actualLine)) {
            problems.add("request line: expected [" + expected.requestLine + "] but was [" + actualLine + "]");
        }

        List<String[]> remaining = new ArrayList<>();
        for (String[] h : actual.headers) {
            if (!IGNORED_TRANSPORT_HEADERS.contains(h[0])) {
                remaining.add(h);
            }
        }
        for (String[] eh : expected.headers) {
            if (IGNORED_TRANSPORT_HEADERS.contains(eh[0])) {
                continue;
            }
            Pattern valuePattern = toPattern(eh[1]);
            String[] match = null;
            for (String[] ah : remaining) {
                if (ah[0].equals(eh[0]) && valuePattern.matcher(ah[1]).matches()) {
                    match = ah;
                    break;
                }
            }
            if (match == null) {
                problems.add("missing/different header [" + eh[0] + ": " + eh[1] + "]; actual headers: " + describe(actual.headers));
            } else {
                remaining.remove(match);
            }
        }
        for (String[] extra : remaining) {
            problems.add("unexpected extra header [" + extra[0] + ": " + extra[1] + "]");
        }

        String actualBody = actual.bodyAsString().replace("\r\n", "\n");
        String expectedBody = expected.body.replace("\r\n", "\n");
        if (!toPattern(expectedBody).matcher(actualBody).matches()) {
            problems.add("body differs:\n  expected: " + expectedBody + "\n  actual:   " + actualBody);
        }

        if (!problems.isEmpty()) {
            fail("Request does not match golden fixture " + name + ":\n - " + String.join("\n - ", problems)
                    + "\n--- actual request ---\n" + actual);
        }
    }

    private static String describe(List<String[]> headers) {
        StringBuilder sb = new StringBuilder();
        for (String[] h : headers) {
            sb.append('[').append(h[0]).append(": ").append(h[1]).append(']');
        }
        return sb.toString();
    }

    private static final Pattern PLACEHOLDER = Pattern.compile("\\$\\{([A-Z_]+)}");

    /** Literal text with ${...} placeholders replaced by their value patterns. */
    static Pattern toPattern(String template) {
        StringBuilder regex = new StringBuilder();
        Matcher m = PLACEHOLDER.matcher(template);
        int last = 0;
        while (m.find()) {
            regex.append(Pattern.quote(template.substring(last, m.start())));
            regex.append(placeholderRegex(m.group(1)));
            last = m.end();
        }
        regex.append(Pattern.quote(template.substring(last)));
        return Pattern.compile(regex.toString(), Pattern.DOTALL);
    }

    private static String placeholderRegex(String name) {
        switch (name) {
            case "PORT":
                return "\\d+";
            case "LOCALHOST":
                return Pattern.quote(String.valueOf(ClientHostName.getHostName()));
            case "DATE":
                // RFC 1123 date, e.g. "Fri, 06 Nov 2026 15:43:51 GMT"
                return "[A-Z][a-z]{2}, \\d{2} [A-Z][a-z]{2} \\d{4} \\d{2}:\\d{2}:\\d{2} GMT";
            case "PPPK_RESPONSE":
                return "[0-9a-f]+";
            case "RANDOM_PIN_HASH":
                return "[0-9A-F]{40}";
            default:
                throw new IllegalArgumentException("unknown placeholder " + name);
        }
    }

    private static Set<String> caseInsensitiveSet(String... names) {
        Set<String> s = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        s.addAll(Arrays.asList(names));
        return s;
    }
}
