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

import java.net.URI;
import java.util.Locale;

/**
 * Safety net for the test suite: when the system property
 * {@value #PROPERTY} is "true" (the Maven build sets it for every test run),
 * outbound HTTP is only allowed to loopback addresses and reserved test
 * domains. Tests must never be able to send a CSR, renewal or revocation to
 * the real CA, whatever order they run in. Inert in the application, where
 * the property is not set.
 */
public final class NetworkGuard {

    public static final String PROPERTY = "certwizard.network.loopbackOnly";

    private NetworkGuard() {
    }

    /**
     * @param uri destination about to be contacted
     * @throws IllegalStateException if the guard is on and the host is not a
     *                               loopback or reserved test host
     */
    public static void checkAllowed(URI uri) {
        if (!Boolean.getBoolean(PROPERTY)) {
            return;
        }
        String host = uri.getHost();
        if (host != null && isLoopbackOrReserved(host)) {
            return;
        }
        throw new IllegalStateException("Refusing to contact " + uri.getScheme() + "://" + host + ": " + PROPERTY
                + " is set, so only loopback and reserved test hosts may be contacted. Tests must never reach a real server.");
    }

    /**
     * Pure string check; never resolves names.
     */
    static boolean isLoopbackOrReserved(String host) {
        String h = host.toLowerCase(Locale.ROOT);
        if (h.startsWith("[") && h.endsWith("]")) {
            h = h.substring(1, h.length() - 1);
        }
        if (h.equals("localhost") || h.endsWith(".localhost")) {
            return true;
        }
        if (h.matches("127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}") || h.equals("::1") || h.equals("0:0:0:0:0:0:0:1")) {
            return true;
        }
        // RFC 2606 / RFC 6761 reserved names that can never be a real server.
        return h.endsWith(".test") || h.endsWith(".example") || h.endsWith(".invalid")
                || h.equals("test") || h.equals("example") || h.equals("invalid");
    }
}
