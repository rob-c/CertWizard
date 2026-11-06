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

import java.io.IOException;

/**
 * A request to the CA server failed without an HTTP response. The message
 * is suitable for showing to the user.
 */
public class CaHttpException extends IOException {

    private final boolean requestMayHaveBeenSent;
    private final int attempts;

    public CaHttpException(String message, Throwable cause, boolean requestMayHaveBeenSent, int attempts) {
        super(message, cause);
        this.requestMayHaveBeenSent = requestMayHaveBeenSent;
        this.attempts = attempts;
    }

    /**
     * False only when the failure provably happened before any of the request
     * was sent (e.g. the connection could not be established). When true, a
     * non-idempotent request (CSR, renewal, revocation) may have been
     * received and processed by the server.
     */
    public boolean isRequestMayHaveBeenSent() {
        return requestMayHaveBeenSent;
    }

    /** Number of attempts made before giving up. */
    public int getAttempts() {
        return attempts;
    }

    /**
     * A message for a failure of the first leg of a PPPK-authenticated
     * submission. The server only acts on the second, signed request, so
     * nothing has been submitted.
     */
    public static String challengeFailureMessage(String what, IOException e) {
        return "The " + what + " could not be completed: " + e.getMessage() + "\n"
                + "Nothing was submitted to the CA. Please try again when the connection is available.";
    }

    /**
     * A message for a failed submission (CSR, renewal, revocation): explains
     * whether the server may nevertheless have received it.
     */
    public static String submissionFailureMessage(String what, IOException e) {
        boolean maybeSent = !(e instanceof CaHttpException) || ((CaHttpException) e).isRequestMayHaveBeenSent();
        if (maybeSent) {
            return "The " + what + " could not be completed: " + e.getMessage() + "\n"
                    + "The CA server may still have received it. Please refresh your certificates to check "
                    + "its status before submitting it again.";
        }
        return "The " + what + " was not sent: " + e.getMessage() + "\n"
                + "Please check your Internet connection and try again.";
    }
}
