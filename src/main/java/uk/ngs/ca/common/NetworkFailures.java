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

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.UnknownHostException;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpTimeoutException;
import java.nio.channels.UnresolvedAddressException;

/**
 * Classifies transport failures from {@link java.net.http.HttpClient}.
 */
public final class NetworkFailures {

    private NetworkFailures() {
    }

    /**
     * True only if the failure provably happened before any byte of the
     * request was written: the TCP connection (or name resolution) failed.
     * Only the top-level exception type is trusted; java.net.http reports
     * refused/unresolvable/unreachable connections as {@link ConnectException}
     * and connect timeouts as {@link HttpConnectTimeoutException}. Anything
     * else (read timeouts, resets, TLS errors - including TLS
     * renegotiation, which can happen after the request was sent) is treated
     * as "may have been sent".
     */
    public static boolean isProvablyNotSent(IOException e) {
        return e instanceof ConnectException
                || e instanceof HttpConnectTimeoutException
                || e instanceof UnknownHostException
                || e instanceof NoRouteToHostException;
    }

    /** True if the failure means the server could not be reached at all. */
    public static boolean isConnectivityFailure(IOException e) {
        return isProvablyNotSent(e);
    }

    /** A short, user-readable description of the failure. */
    public static String describe(IOException e, String host) {
        String server = "the CA server" + (host == null ? "" : " (" + host + ")");
        if (e instanceof HttpConnectTimeoutException) {
            return "Timed out connecting to " + server + ".";
        }
        if (e instanceof HttpTimeoutException) {
            return server.substring(0, 1).toUpperCase() + server.substring(1) + " did not respond in time.";
        }
        if (e instanceof UnknownHostException || hasCause(e, UnresolvedAddressException.class)) {
            return "Could not find " + server + " - the host name could not be resolved. "
                    + "Please check your Internet connection.";
        }
        if (e instanceof ConnectException || e instanceof NoRouteToHostException) {
            return "Could not connect to " + server + ". Please check your Internet connection "
                    + "and firewall settings.";
        }
        if (e instanceof SSLException) {
            return "A secure connection to " + server + " could not be established: " + e.getMessage();
        }
        String detail = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
        return "Communication with " + server + " failed: " + detail;
    }

    private static boolean hasCause(Throwable t, Class<? extends Throwable> type) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (type.isInstance(c)) {
                return true;
            }
            if (c.getCause() == c) {
                break;
            }
        }
        return false;
    }
}
