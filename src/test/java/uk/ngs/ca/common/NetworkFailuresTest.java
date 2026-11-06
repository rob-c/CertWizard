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

import org.junit.Test;

import javax.net.ssl.SSLHandshakeException;
import java.io.EOFException;
import java.io.IOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpTimeoutException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * The "provably not sent" rule decides whether a non-idempotent request
 * (CSR, renewal, revocation) may ever be retried, so it is pinned down
 * exhaustively here.
 */
public class NetworkFailuresTest {

    @Test
    public void connectionEstablishmentFailuresAreProvablyNotSent() {
        assertTrue(NetworkFailures.isProvablyNotSent(new ConnectException("Connection refused")));
        assertTrue(NetworkFailures.isProvablyNotSent(new HttpConnectTimeoutException("HTTP connect timed out")));
        assertTrue(NetworkFailures.isProvablyNotSent(new UnknownHostException("cwiz-live.ca.ngs.ac.uk")));
        assertTrue(NetworkFailures.isProvablyNotSent(new NoRouteToHostException("No route to host")));
    }

    @Test
    public void everythingElseMayHaveBeenSent() {
        assertFalse(NetworkFailures.isProvablyNotSent(new HttpTimeoutException("request timed out")));
        assertFalse(NetworkFailures.isProvablyNotSent(new SocketTimeoutException("Read timed out")));
        assertFalse(NetworkFailures.isProvablyNotSent(new SocketException("Connection reset")));
        assertFalse(NetworkFailures.isProvablyNotSent(new EOFException("EOF reached while reading")));
        assertFalse(NetworkFailures.isProvablyNotSent(new IOException("HTTP/1.1 header parser received no bytes")));
        // a TLS handshake can also be a renegotiation after the request was written
        assertFalse(NetworkFailures.isProvablyNotSent(new SSLHandshakeException("Remote host terminated the handshake")));
    }

    @Test
    public void onlyTheTopLevelExceptionTypeIsTrusted() {
        assertFalse(NetworkFailures.isProvablyNotSent(new IOException("wrapped", new ConnectException("Connection refused"))));
    }

    @Test
    public void descriptionsAreReadable() {
        assertTrue(NetworkFailures.describe(new ConnectException(), "ca.example").startsWith("Could not connect to the CA server (ca.example)"));
        assertTrue(NetworkFailures.describe(new HttpConnectTimeoutException("x"), null).startsWith("Timed out connecting to the CA server"));
        assertTrue(NetworkFailures.describe(new HttpTimeoutException("x"), null).startsWith("The CA server did not respond in time"));
        assertTrue(NetworkFailures.describe(new UnknownHostException("x"), "h").contains("host name could not be resolved"));
    }
}
