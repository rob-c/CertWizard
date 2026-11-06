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
package uk.ngs.ca.certificate.verify;

import uk.ngs.ca.certificate.chain.BundledCaCertificates;
import uk.ngs.ca.certificate.chain.CertChainBuilder;
import uk.ngs.ca.certificate.chain.KeyStoreChains;
import uk.ngs.ca.certificate.verify.VerificationReport.Severity;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.text.SimpleDateFormat;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TimeZone;

/**
 * Runs every check CertWizard knows about against a certificate, its chain
 * and (optionally) its private key, and reports each one with a severity.
 * <p>
 * Checks (ids in brackets):
 * <ul>
 * <li>[key-match] the private key really belongs to the certificate (a
 * signature made with the key verifies with the certificate's public key)</li>
 * <li>[chain] the full chain to a self-signed root can be built, and whether
 * the chain as stored is missing any parents</li>
 * <li>[trust] the root is one of the bundled UK e-Science roots</li>
 * <li>[path] RFC 5280 path validation (PKIX) against that root</li>
 * <li>[validity] every certificate is within its validity period; warns
 * before the user certificate or any CA certificate expires</li>
 * <li>[key-strength] the user key is not weak</li>
 * <li>[signature-algorithm] no MD2/MD5/SHA-1 signatures in the chain</li>
 * <li>[usage] the user certificate is not a CA and can do TLS client auth</li>
 * <li>[revocation] (optional) no certificate in the chain is revoked</li>
 * </ul>
 */
public final class CertificateVerifier {

    private static final String OID_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
    private static final String OID_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
    private static final String OID_ANY_EKU = "2.5.29.37.0";

    private final List<X509Certificate> trustAnchors;
    private final CertChainBuilder builder;
    private final CrlRevocationChecker revocation;
    private final Clock clock;
    private final Duration userExpiryWarning;
    private final Duration caExpiryWarning;

    /**
     * @param trustAnchors      trusted self-signed roots
     * @param builder           chain builder
     * @param revocation        revocation checker, or null to skip revocation
     * @param clock             clock
     * @param userExpiryWarning warn when the user certificate expires within this
     * @param caExpiryWarning   warn when a CA certificate in the chain expires within this
     */
    public CertificateVerifier(Collection<X509Certificate> trustAnchors, CertChainBuilder builder,
                               CrlRevocationChecker revocation, Clock clock,
                               Duration userExpiryWarning, Duration caExpiryWarning) {
        this.trustAnchors = new ArrayList<>(trustAnchors);
        this.builder = builder;
        this.revocation = revocation;
        this.clock = clock == null ? Clock.systemUTC() : clock;
        this.userExpiryWarning = userExpiryWarning;
        this.caExpiryWarning = caExpiryWarning;
    }

    /**
     * @param revocation revocation checker, or null to skip revocation
     * @return verifier trusting the bundled UK e-Science roots, warning 30
     * days before the user certificate and 365 days before a CA certificate
     * expires.
     */
    public static CertificateVerifier standard(CrlRevocationChecker revocation) {
        return new CertificateVerifier(BundledCaCertificates.roots(), CertChainBuilder.standard(), revocation,
                Clock.systemUTC(), Duration.ofDays(30), Duration.ofDays(365));
    }

    /**
     * Verify a keystore key entry.
     *
     * @param key         the private key (may be null to skip the key check)
     * @param storedChain the chain as stored (leaf first)
     * @return report
     */
    public VerificationReport verifyKeyEntry(PrivateKey key, Certificate[] storedChain) {
        if (storedChain == null || storedChain.length == 0 || !(storedChain[0] instanceof X509Certificate)) {
            VerificationReport r = new VerificationReport("(no certificate)");
            r.add(Severity.FAIL, "chain", "The entry has no X.509 certificate.");
            return r;
        }
        return verify((X509Certificate) storedChain[0], key, storedChain);
    }

    /**
     * Verify a certificate with no private key.
     *
     * @param cert  certificate
     * @param extra other certificates that may help build the chain (may be null)
     * @return report
     */
    public VerificationReport verifyCertificate(X509Certificate cert, Certificate[] extra) {
        return verify(cert, null, extra);
    }

    private VerificationReport verify(X509Certificate leaf, PrivateKey key, Certificate[] stored) {
        VerificationReport r = new VerificationReport(leaf.getSubjectX500Principal().getName());
        Date now = Date.from(clock.instant());

        if (key != null) {
            checkKeyMatch(r, key, leaf);
        }

        CertChainBuilder.Result built = builder.build(leaf, stored == null ? null : Arrays.asList(stored));
        if (built.isLeafSelfSigned()) {
            r.add(Severity.INFO, "chain", "Self-signed certificate. CertWizard stores one of these as a placeholder "
                    + "while a certificate request is pending; there is no CA chain to check yet.");
            checkValidity(r, Collections.singletonList(leaf), now);
            return r;
        }
        List<X509Certificate> chain = built.getChain();
        if (built.isComplete()) {
            r.add(Severity.PASS, "chain", "Full chain of " + chain.size() + " certificates: " + describe(chain));
        } else {
            r.add(Severity.FAIL, "chain", "Incomplete chain (" + describe(chain) + ").\n"
                    + String.join("\n", built.getProblems()));
        }
        if (stored != null && stored.length > 0 && built.isComplete() && !KeyStoreChains.isCompleteOrderedChain(stored)) {
            r.add(Severity.WARN, "chain", "The chain stored with this entry has " + stored.length + " of "
                    + chain.size() + " certificates or is out of order. Exports and the .globus install write the "
                    + "full chain, and CertWizard repairs the stored chain when the keystore is next opened.");
        }

        X509Certificate root = built.isComplete() ? chain.get(chain.size() - 1) : null;
        boolean trusted = root != null && trustAnchors.contains(root);
        if (root != null) {
            if (trusted) {
                r.add(Severity.PASS, "trust", "Chains to the trusted root '" + cn(root) + "'.");
            } else {
                r.add(Severity.WARN, "trust", "Chains to '" + root.getSubjectX500Principal().getName()
                        + "', which is not one of the UK e-Science roots bundled with CertWizard.");
            }
            checkPath(r, chain, root, now);
        }

        checkValidity(r, chain, now);
        checkKeyStrength(r, leaf);
        checkSignatureAlgorithms(r, chain);
        checkUsage(r, leaf);
        if (revocation != null) {
            checkRevocation(r, chain);
        }
        return r;
    }

    private static void checkKeyMatch(VerificationReport r, PrivateKey key, X509Certificate cert) {
        String alg = signatureAlgorithmFor(key);
        if (alg == null) {
            r.add(Severity.INFO, "key-match", "Cannot test a " + key.getAlgorithm() + " key against the certificate.");
            return;
        }
        try {
            byte[] challenge = new byte[64];
            new SecureRandom().nextBytes(challenge);
            Signature s = Signature.getInstance(alg);
            s.initSign(key);
            s.update(challenge);
            byte[] sig = s.sign();
            s.initVerify(cert.getPublicKey());
            s.update(challenge);
            if (s.verify(sig)) {
                r.add(Severity.PASS, "key-match", "The private key matches the certificate.");
            } else {
                r.add(Severity.FAIL, "key-match", "The private key does NOT match this certificate's public key.");
            }
        } catch (Exception e) {
            r.add(Severity.FAIL, "key-match", "The private key could not be tested against the certificate: " + e.getMessage());
        }
    }

    static String signatureAlgorithmFor(PrivateKey key) {
        switch (key.getAlgorithm()) {
            case "RSA":
                return "SHA256withRSA";
            case "EC":
            case "ECDSA":
                return "SHA256withECDSA";
            case "DSA":
                return "SHA256withDSA";
            case "Ed25519":
            case "Ed448":
            case "EdDSA":
                return key.getAlgorithm();
            default:
                return null;
        }
    }

    private void checkPath(VerificationReport r, List<X509Certificate> chain, X509Certificate root, Date now) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            CertPath path = cf.generateCertPath(chain.subList(0, chain.size() - 1));
            Set<TrustAnchor> anchors = new HashSet<>();
            anchors.add(new TrustAnchor(root, null));
            PKIXParameters params = new PKIXParameters(anchors);
            params.setRevocationEnabled(false); // revocation is its own check
            params.setDate(now);
            CertPathValidator.getInstance("PKIX").validate(path, params);
            r.add(Severity.PASS, "path", "RFC 5280 path validation succeeded.");
        } catch (CertPathValidatorException e) {
            String where = e.getIndex() >= 0 && e.getIndex() < chain.size()
                    ? " at '" + cn(chain.get(e.getIndex())) + "'" : "";
            r.add(Severity.FAIL, "path", "Path validation failed" + where + ": " + e.getMessage());
        } catch (Exception e) {
            r.add(Severity.FAIL, "path", "Path validation could not run: " + e);
        }
    }

    private void checkValidity(VerificationReport r, List<X509Certificate> chain, Date now) {
        for (int i = 0; i < chain.size(); i++) {
            X509Certificate c = chain.get(i);
            boolean isUser = i == 0;
            String who = isUser ? "Certificate" : "CA certificate '" + cn(c) + "'";
            if (now.before(c.getNotBefore())) {
                r.add(Severity.FAIL, "validity", who + " is not valid until " + fmt(c.getNotBefore()) + ".");
                continue;
            }
            if (now.after(c.getNotAfter())) {
                r.add(Severity.FAIL, "validity", who + " expired on " + fmt(c.getNotAfter()) + ".");
                continue;
            }
            long daysLeft = Duration.between(now.toInstant(), c.getNotAfter().toInstant()).toDays();
            Duration warn = isUser ? userExpiryWarning : caExpiryWarning;
            if (Duration.between(now.toInstant(), c.getNotAfter().toInstant()).compareTo(warn) <= 0) {
                r.add(Severity.WARN, "validity", who + " expires on " + fmt(c.getNotAfter()) + " (" + daysLeft + " days)"
                        + (isUser ? "; renew it now." : "; certificates that chain through it stop validating then."));
            } else if (isUser) {
                r.add(Severity.PASS, "validity", "Valid until " + fmt(c.getNotAfter()) + " (" + daysLeft + " days).");
            }
        }
        X509Certificate user = chain.get(0);
        for (int i = 1; i < chain.size(); i++) {
            if (user.getNotAfter().after(chain.get(i).getNotAfter())) {
                r.add(Severity.WARN, "validity", "Certificate outlives CA certificate '" + cn(chain.get(i))
                        + "' (" + fmt(chain.get(i).getNotAfter()) + "); it cannot be validated after that date.");
            }
        }
    }

    private static void checkKeyStrength(VerificationReport r, X509Certificate leaf) {
        PublicKey pk = leaf.getPublicKey();
        if (pk instanceof RSAKey) {
            int bits = ((RSAKey) pk).getModulus().bitLength();
            if (bits < 2048) {
                r.add(Severity.FAIL, "key-strength", "RSA key is only " + bits + " bits (minimum 2048).");
            } else {
                r.add(Severity.PASS, "key-strength", "RSA " + bits + "-bit key.");
            }
        } else if (pk instanceof ECKey) {
            int bits = ((ECKey) pk).getParams().getCurve().getField().getFieldSize();
            if (bits < 256) {
                r.add(Severity.FAIL, "key-strength", "EC key is only " + bits + " bits (minimum 256).");
            } else {
                r.add(Severity.PASS, "key-strength", "EC " + bits + "-bit key.");
            }
        } else if (pk instanceof DSAKey) {
            r.add(Severity.WARN, "key-strength", "DSA keys are deprecated.");
        } else {
            r.add(Severity.INFO, "key-strength", pk.getAlgorithm() + " key.");
        }
    }

    private static void checkSignatureAlgorithms(VerificationReport r, List<X509Certificate> chain) {
        boolean ok = true;
        // The root's self-signature is not relied upon (trust comes from the
        // root being a trust anchor), so only check certificates below it.
        int last = CertChainBuilder.isSelfSigned(chain.get(chain.size() - 1)) ? chain.size() - 1 : chain.size();
        for (int i = 0; i < last; i++) {
            X509Certificate c = chain.get(i);
            String alg = c.getSigAlgName().toUpperCase(Locale.ROOT);
            if (alg.contains("MD5") || alg.contains("MD2")) {
                r.add(Severity.FAIL, "signature-algorithm", "'" + cn(c) + "' is signed with broken " + c.getSigAlgName() + ".");
                ok = false;
            } else if (alg.contains("SHA1")) {
                r.add(Severity.WARN, "signature-algorithm", "'" + cn(c) + "' is signed with deprecated " + c.getSigAlgName() + ".");
                ok = false;
            }
        }
        if (ok) {
            List<String> algs = new ArrayList<>();
            for (int i = 0; i < last; i++) {
                algs.add(chain.get(i).getSigAlgName());
            }
            r.add(Severity.PASS, "signature-algorithm", "Signature algorithms: " + String.join(", ", algs) + ".");
        }
    }

    private static void checkUsage(VerificationReport r, X509Certificate leaf) {
        if (leaf.getBasicConstraints() >= 0) {
            r.add(Severity.WARN, "usage", "This is a CA certificate, not a user or host certificate.");
            return; // end-entity usage checks do not apply to a CA
        }
        boolean[] ku = leaf.getKeyUsage();
        if (ku != null && ku.length > 0 && !ku[0]) {
            r.add(Severity.WARN, "usage", "Key usage does not include digitalSignature; TLS client authentication will fail.");
        }
        try {
            List<String> eku = leaf.getExtendedKeyUsage();
            if (eku != null && !eku.contains(OID_ANY_EKU)) {
                if (!eku.contains(OID_CLIENT_AUTH) && !eku.contains(OID_SERVER_AUTH)) {
                    r.add(Severity.WARN, "usage", "Extended key usage allows neither TLS client nor server authentication.");
                } else {
                    List<String> names = new ArrayList<>();
                    if (eku.contains(OID_CLIENT_AUTH)) {
                        names.add("TLS client authentication");
                    }
                    if (eku.contains(OID_SERVER_AUTH)) {
                        names.add("TLS server authentication");
                    }
                    r.add(Severity.PASS, "usage", "Usable for " + String.join(" and ", names) + ".");
                }
            }
        } catch (Exception e) {
            r.add(Severity.WARN, "usage", "Extended key usage could not be parsed: " + e.getMessage());
        }
    }

    private void checkRevocation(VerificationReport r, List<X509Certificate> chain) {
        for (int i = 0; i + 1 < chain.size(); i++) {
            X509Certificate c = chain.get(i);
            CrlRevocationChecker.Result res = revocation.check(c, chain.get(i + 1));
            String who = i == 0 ? "Certificate" : "CA certificate '" + cn(c) + "'";
            switch (res.getStatus()) {
                case GOOD:
                    r.add(Severity.PASS, "revocation", who + " " + res.getDetail() + ".");
                    break;
                case REVOKED:
                    r.add(Severity.FAIL, "revocation", who + " has been REVOKED: " + res.getDetail() + ".");
                    break;
                default:
                    r.add(Severity.WARN, "revocation", who + ": revocation status unknown.\n" + res.getDetail());
            }
        }
    }

    private static String describe(List<X509Certificate> chain) {
        List<String> names = new ArrayList<>();
        for (X509Certificate c : chain) {
            names.add(cn(c));
        }
        return String.join(" → ", names);
    }

    static String cn(X509Certificate c) {
        String dn = c.getSubjectX500Principal().getName();
        for (String part : dn.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)")) {
            if (part.trim().startsWith("CN=")) {
                return part.trim().substring(3);
            }
        }
        return dn;
    }

    private static String fmt(Date d) {
        SimpleDateFormat f = new SimpleDateFormat("d MMM yyyy HH:mm 'UTC'", Locale.UK);
        f.setTimeZone(TimeZone.getTimeZone("UTC"));
        return f.format(d);
    }
}
