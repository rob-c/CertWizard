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
package uk.ngs.ca.certificate.renew;

import java.time.Duration;
import java.time.Instant;

/**
 * Decides whether auto-renew should submit a renewal for one certificate.
 * Pure function of its inputs, so every rule is unit tested.
 */
public final class AutoRenewPolicy {

    /**
     * Give up automatic retries after this many CA refusals.
     */
    public static final int MAX_ATTEMPTS = 3;
    /**
     * Minimum gap between automatic attempts after a CA refusal.
     */
    public static final Duration RETRY_AFTER = Duration.ofHours(24);

    /**
     * What to do.
     */
    public enum Action {
        RENEW, WAIT, SKIP
    }

    /**
     * Decision with reason.
     */
    public static final class Decision {
        public final Action action;
        public final String reason;
        /**
         * For WAIT: earliest time to reconsider.
         */
        public final Instant notBefore;

        Decision(Action action, String reason, Instant notBefore) {
            this.action = action;
            this.reason = reason;
            this.notBefore = notBefore;
        }

        @Override
        public String toString() {
            return action + ": " + reason;
        }
    }

    /**
     * Facts about one keystore entry.
     */
    public static final class Facts {
        boolean keyPair;
        String serverStatus;
        Instant notAfter;
        /**
         * Alias of another entry for the same DN that is newer (an issued
         * renewal or a pending renewal placeholder), or null.
         */
        String newerEntryAlias;
        RenewalLedger.Record ledger;

        public Facts keyPair(boolean v) {
            keyPair = v;
            return this;
        }

        public Facts serverStatus(String v) {
            serverStatus = v;
            return this;
        }

        public Facts notAfter(Instant v) {
            notAfter = v;
            return this;
        }

        public Facts newerEntryAlias(String v) {
            newerEntryAlias = v;
            return this;
        }

        public Facts ledger(RenewalLedger.Record v) {
            ledger = v;
            return this;
        }
    }

    private final Duration window;

    /**
     * @param window renew when the certificate expires within this window
     */
    public AutoRenewPolicy(Duration window) {
        this.window = window;
    }

    public Duration getWindow() {
        return window;
    }

    public Decision decide(Facts f, Instant now) {
        if (!f.keyPair) {
            return skip("not a certificate with a private key");
        }
        if (!"VALID".equals(f.serverStatus)) {
            return skip("the CA reports status " + f.serverStatus);
        }
        if (f.notAfter == null) {
            return skip("expiry date unknown");
        }
        if (now.isAfter(f.notAfter.plus(RenewalSubmitter.GRACE_PERIOD))) {
            return skip("expired more than " + RenewalSubmitter.GRACE_PERIOD.toDays() + " days ago; renew by applying again");
        }
        if (f.newerEntryAlias != null) {
            return skip("already renewed (entry [" + f.newerEntryAlias + "])");
        }
        RenewalLedger.Record r = f.ledger;
        if (r != null) {
            switch (r.state) {
                case SUBMITTED:
                case INSTALLED:
                    return skip("renewal already submitted on " + r.time
                            + (r.newAlias != null ? " as [" + r.newAlias + "]" : ""));
                case UNCERTAIN:
                case ATTEMPTING:
                    return skip("an earlier automatic renewal may have reached the CA (" + r.message
                            + "); not resending - refresh, then renew manually if needed");
                case FAILED:
                    if (r.attempts >= MAX_ATTEMPTS) {
                        return skip("the CA refused " + r.attempts + " automatic renewals (last: " + r.message
                                + "); renew manually");
                    }
                    Instant retry = r.time.plus(RETRY_AFTER);
                    if (now.isBefore(retry)) {
                        return new Decision(Action.WAIT, "the CA refused the last attempt (" + r.message + "); retrying after " + retry, retry);
                    }
                    break;
                default:
                    break;
            }
        }
        Instant windowOpens = f.notAfter.minus(window);
        if (now.isBefore(windowOpens)) {
            return new Decision(Action.WAIT, "renewal window opens " + windowOpens, windowOpens);
        }
        return new Decision(Action.RENEW, "expires " + f.notAfter, null);
    }

    private static Decision skip(String why) {
        return new Decision(Action.SKIP, why, null);
    }
}
