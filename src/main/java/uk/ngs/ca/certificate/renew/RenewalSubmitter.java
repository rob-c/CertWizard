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

import org.apache.commons.validator.routines.EmailValidator;
import uk.ngs.ca.certificate.OnlineCertRenewRequest;
import uk.ngs.ca.certificate.management.ClientKeyStoreCaServiceWrapper;
import uk.ngs.ca.certificate.management.KeyStoreEntryWrapper;
import uk.ngs.ca.common.CAKeyPair;
import uk.ngs.ca.common.CertUtil;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.function.Supplier;

/**
 * Submits a certificate renewal to the CA without any user interaction. Used
 * by the Renew button (after its confirmation dialogs) and by auto-renew.
 * <p>
 * Renewal works by proof of possession: a fresh key pair is generated, a
 * PKCS#10 request for the same DN is signed, and the request is authenticated
 * with the private key of the certificate being renewed. On success a
 * self-signed placeholder for the new key is stored in the keystore under the
 * new alias, and the keystore is saved. The CA-issued certificate replaces
 * the placeholder (with its full chain) once the CA has approved the request
 * and the entry is next refreshed.
 */
public final class RenewalSubmitter {

    /**
     * The CA accepts renewals of certificates that expired at most this long ago.
     */
    public static final Duration GRACE_PERIOD = Duration.ofDays(30);

    /**
     * What happened.
     */
    public enum Outcome {
        /**
         * The CA accepted the renewal request.
         */
        SUBMITTED,
        /**
         * The CA answered and refused the request.
         */
        REJECTED_BY_CA,
        /**
         * Nothing was sent: the certificate cannot be renewed (reason in message).
         */
        NOT_ELIGIBLE,
        /**
         * The CA could not be reached; nothing that could create a renewal
         * was received by it. Safe to try again later.
         */
        NOT_SENT,
        /**
         * Something failed while talking to the CA. The request may or may not
         * have reached it, so it must not be resent automatically.
         */
        UNCERTAIN
    }

    /**
     * Result of a submission.
     */
    public static final class Result {
        private final Outcome outcome;
        private final String newAlias;
        private final String message;

        Result(Outcome outcome, String newAlias, String message) {
            this.outcome = outcome;
            this.newAlias = newAlias;
            this.message = message;
        }

        public Outcome getOutcome() {
            return outcome;
        }

        /**
         * @return alias of the new placeholder entry (SUBMITTED only), else null.
         */
        public String getNewAlias() {
            return newAlias;
        }

        public String getMessage() {
            return message;
        }
    }

    /**
     * The CA's answer to a renewal request.
     */
    public static final class Answer {
        /**
         * What the CA may have received.
         */
        public enum Kind {
            ACCEPTED, REFUSED, NOT_SENT, MAYBE_SENT
        }

        public final Kind kind;
        public final String message;

        public Answer(Kind kind, String message) {
            this.kind = kind;
            this.message = message;
        }
    }

    /**
     * One renewal request to the CA (abstracted so tests need no server).
     */
    public interface RenewalRequest {
        /**
         * Send the request.
         *
         * @return the answer; implementations should not throw
         */
        Answer send();

        String getOU();

        String getL();

        String getCN();
    }

    /**
     * Creates renewal requests.
     */
    public interface RenewalRequestFactory {
        RenewalRequest create(X509Certificate toRenew, PrivateKey toRenewKey, KeyPair newKeyPair, String email);
    }

    /**
     * Factory for the real CA server.
     */
    public static final RenewalRequestFactory ONLINE = (cert, key, kp, email) -> {
        OnlineCertRenewRequest r = new OnlineCertRenewRequest(cert, key, kp, email);
        return new RenewalRequest() {
            @Override
            public Answer send() {
                OnlineCertRenewRequest.Result result = r.renew();
                return new Answer(Answer.Kind.valueOf(result.status.name()), result.message);
            }

            @Override
            public String getOU() {
                return r.getOU();
            }

            @Override
            public String getL() {
                return r.getL();
            }

            @Override
            public String getCN() {
                return r.getCN();
            }
        };
    };

    private final ClientKeyStoreCaServiceWrapper model;
    private final RenewalRequestFactory factory;
    private final Supplier<KeyPair> keyPairs;
    private final Clock clock;

    /**
     * @param model    keystore model
     * @param factory  request factory ({@link #ONLINE} for the real CA)
     * @param keyPairs source of new key pairs
     * @param clock    clock
     */
    public RenewalSubmitter(ClientKeyStoreCaServiceWrapper model, RenewalRequestFactory factory,
                            Supplier<KeyPair> keyPairs, Clock clock) {
        this.model = model;
        this.factory = factory;
        this.keyPairs = keyPairs;
        this.clock = clock;
    }

    /**
     * @param model keystore model
     * @return submitter for the real CA
     */
    public static RenewalSubmitter online(ClientKeyStoreCaServiceWrapper model) {
        return new RenewalSubmitter(model, ONLINE, CAKeyPair::getNewKeyPair, Clock.systemUTC());
    }

    /**
     * Check that an entry can be renewed, without sending anything.
     *
     * @param entry entry (its server info should be freshly refreshed)
     * @param email email to send with the request
     * @return null if eligible, otherwise the reason it is not
     */
    public String ineligibilityReason(KeyStoreEntryWrapper entry, String email) {
        try {
            if (entry == null
                    || !KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY.equals(entry.getEntryType())
                    || entry.getServerCertificateCSRInfo() == null
                    || !"VALID".equals(entry.getServerCertificateCSRInfo().getStatus())) {
                return "Only VALID certificates known by the UK CA can be renewed.";
            }
            X509Certificate cert = model.getClientKeyStore().getX509Certificate(entry.getAlias());
            if (cert == null) {
                return "The entry has no certificate.";
            }
            Instant now = clock.instant();
            if (now.isBefore(cert.getNotBefore().toInstant())) {
                return "The certificate is not yet valid.";
            }
            if (now.isAfter(cert.getNotAfter().toInstant().plus(GRACE_PERIOD))) {
                return "The certificate expired more than " + GRACE_PERIOD.toDays() + " days ago and can no longer be renewed.";
            }
            if (email == null || !EmailValidator.getInstance().isValid(email)) {
                return "The email associated with this certificate is invalid. This is due to a known issue on the CA server; "
                        + "please report it to support@grid-support.ac.uk with DN [" + entry.getX500PrincipalName()
                        + "] and CertId [" + entry.getServerCertificateCSRInfo().getId() + "].";
            }
            // If the DN carries an EMAILADDRESS it must match the email sent.
            String dnEmail = CertUtil.extractDnAttribute(cert.getSubjectX500Principal().toString(),
                    CertUtil.DNAttributeType.EMAILADDRESS);
            if (dnEmail != null && !dnEmail.isEmpty() && !dnEmail.equals(email)) {
                return "The email encoded in the certificate DN [" + dnEmail + "] differs from the email [" + email
                        + "]. This is due to a known issue on the CA server; please report it to support@grid-support.ac.uk "
                        + "with DN [" + entry.getX500PrincipalName() + "] and CertId [" + entry.getServerCertificateCSRInfo().getId() + "].";
            }
            if (model.getClientKeyStore().getPrivateKey(entry.getAlias()) == null) {
                return "The private key for this certificate is missing.";
            }
            return null;
        } catch (Exception e) {
            return "The entry cannot be read: " + e.getMessage();
        }
    }

    /**
     * Submit a renewal for <code>entry</code>.
     *
     * @param entry    entry to renew (its server info should be freshly refreshed)
     * @param email    email to send with the request
     * @param newAlias alias for the new entry; must not already exist
     * @return result; never throws
     */
    public Result submit(KeyStoreEntryWrapper entry, String email, String newAlias) {
        String reason = ineligibilityReason(entry, email);
        if (reason != null) {
            return new Result(Outcome.NOT_ELIGIBLE, null, reason);
        }
        try {
            if (newAlias == null || newAlias.isEmpty() || model.getClientKeyStore().containsAlias(newAlias)) {
                return new Result(Outcome.NOT_ELIGIBLE, null, "The alias [" + newAlias + "] is empty or already in use.");
            }
        } catch (Exception e) {
            return new Result(Outcome.NOT_ELIGIBLE, null, "The keystore cannot be read: " + e.getMessage());
        }

        RenewalRequest request;
        KeyPair csrKeyPair;
        try {
            X509Certificate toRenew = model.getClientKeyStore().getX509Certificate(entry.getAlias());
            PrivateKey toRenewKey = model.getClientKeyStore().getPrivateKey(entry.getAlias());
            csrKeyPair = keyPairs.get();
            request = factory.create(toRenew, toRenewKey, csrKeyPair, email);
        } catch (Exception e) {
            // Failed before anything was sent.
            return new Result(Outcome.NOT_ELIGIBLE, null, "The renewal request could not be built: " + e.getMessage());
        }

        Answer answer;
        try {
            answer = request.send();
        } catch (RuntimeException e) {
            return new Result(Outcome.UNCERTAIN, null, "Communication with the CA failed part-way: " + e.getMessage());
        }
        if (answer == null) {
            return new Result(Outcome.UNCERTAIN, null, "The CA gave no answer.");
        }
        switch (answer.kind) {
            case ACCEPTED:
                break;
            case REFUSED:
                return new Result(Outcome.REJECTED_BY_CA, null, answer.message);
            case NOT_SENT:
                return new Result(Outcome.NOT_SENT, null, answer.message);
            default:
                return new Result(Outcome.UNCERTAIN, null, answer.message);
        }

        // Accepted: keep the new key with a self-signed placeholder until the
        // CA issues the certificate. If this fails we must say so loudly: the
        // CA has a request whose key we would otherwise lose.
        try {
            X509Certificate placeholder = CAKeyPair.createSelfSignedCertificate(csrKeyPair,
                    request.getOU(), request.getL(), request.getCN());
            model.getClientKeyStore().setKeyEntry(newAlias, csrKeyPair.getPrivate(), model.getPassword(),
                    new X509Certificate[]{placeholder});
            model.getClientKeyStore().reStore();
            model.getKeyStoreEntryMap().put(newAlias, model.createKSEntryWrapperInstanceFromEntry(newAlias));
        } catch (Exception e) {
            return new Result(Outcome.UNCERTAIN, null, "The CA accepted the renewal but saving the new key failed: "
                    + e.getMessage() + ". Do not delete anything; contact support@grid-support.ac.uk.");
        }
        return new Result(Outcome.SUBMITTED, newAlias, answer.message);
    }
}
