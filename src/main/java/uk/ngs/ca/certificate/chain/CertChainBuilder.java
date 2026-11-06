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
package uk.ngs.ca.certificate.chain;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;

/**
 * Builds the complete, ordered certificate chain for a certificate:
 * <pre>
 *   [0] the certificate itself (leaf)
 *   [1] its issuer
 *   ...
 *   [n] the self-signed root
 * </pre>
 * Every parent certificate is included. Nothing in the middle is skipped and
 * the root is always included when it can be found.
 * <p>
 * An issuer candidate is accepted only if:
 * <ul>
 * <li>its subject DN equals the child's issuer DN (canonical comparison),</li>
 * <li>its Subject Key Identifier matches the child's Authority Key Identifier
 * when both are present,</li>
 * <li>it is not explicitly marked as a non-CA (basicConstraints CA=false),</li>
 * <li>the child's signature verifies with its public key.</li>
 * </ul>
 * The signature check makes the result safe to use with certificates fetched
 * over unauthenticated channels such as AIA http URLs. A forged "issuer" cannot
 * verify the child's signature. Whether the root that is reached is
 * <em>trusted</em> is a separate question, answered by chain validation, not
 * by this class.
 * <p>
 * Candidate issuers are drawn from, in order: certificates supplied by the
 * caller (e.g. the chain already stored in the keystore or the chain inside
 * an imported PKCS#12), the bundled UK e-Science CA certificates, and finally
 * the optional {@link IssuerFetcher}, which is consulted only when nothing
 * local matches.
 */
public final class CertChainBuilder {

    /**
     * Source of issuer certificates that are not available locally, typically
     * the AIA caIssuers URL embedded in the child certificate.
     */
    public interface IssuerFetcher {

        /**
         * @param child certificate whose issuer is wanted.
         * @return candidate issuer certificates; never null (empty if none).
         */
        List<X509Certificate> fetchIssuerCandidates(X509Certificate child);
    }

    /**
     * Upper bound on chain length, protects against pathological input.
     */
    static final int MAX_DEPTH = 10;

    private final List<X509Certificate> knownCaCerts;
    private final IssuerFetcher fetcher;
    private final Clock clock;

    /**
     * @param knownCaCerts CA certificates that may be used as issuers (e.g. the
     *                     bundled UK e-Science CA certificates).
     * @param fetcher      optional fetcher for issuers that are not available
     *                     locally; may be null.
     * @param clock        clock used to prefer currently-valid issuers.
     */
    public CertChainBuilder(Collection<X509Certificate> knownCaCerts, IssuerFetcher fetcher, Clock clock) {
        this.knownCaCerts = new ArrayList<>(knownCaCerts == null ? Collections.<X509Certificate>emptyList() : knownCaCerts);
        this.fetcher = fetcher;
        this.clock = clock == null ? Clock.systemUTC() : clock;
    }

    /**
     * @return a builder using only the bundled CA certificates. Never touches
     * the network, so it is safe to use on any thread.
     */
    public static CertChainBuilder offline() {
        return new CertChainBuilder(BundledCaCertificates.all(), null, Clock.systemUTC());
    }

    /**
     * @return a builder using the bundled CA certificates and falling back to
     * AIA caIssuers download for issuers it does not know.
     */
    public static CertChainBuilder standard() {
        return new CertChainBuilder(BundledCaCertificates.all(), AiaIssuerFetcher.shared(), Clock.systemUTC());
    }

    /**
     * Build the full chain for <code>leaf</code>.
     *
     * @param leaf       the end-entity (or any) certificate to build a chain for.
     * @param extraCerts additional certificates that may contain issuers (any
     *                   order, may contain the leaf itself, unrelated
     *                   certificates and duplicates; non-X.509 certificates are ignored). May be null.
     * @return the chain and whether it reaches a self-signed root.
     */
    public Result build(X509Certificate leaf, Collection<? extends Certificate> extraCerts) {
        if (leaf == null) {
            throw new IllegalArgumentException("leaf certificate is null");
        }
        List<X509Certificate> pool = new ArrayList<>();
        if (extraCerts != null) {
            for (Certificate c : extraCerts) {
                if (c instanceof X509Certificate) {
                    addDistinct(pool, (X509Certificate) c);
                }
            }
        }
        for (X509Certificate c : knownCaCerts) {
            addDistinct(pool, c);
        }

        List<X509Certificate> chain = new ArrayList<>();
        List<String> problems = new ArrayList<>();
        chain.add(leaf);
        X509Certificate current = leaf;
        boolean complete = false;

        while (true) {
            if (isSelfSigned(current)) {
                complete = true;
                break;
            }
            if (chain.size() >= MAX_DEPTH) {
                problems.add("Certificate chain is longer than " + MAX_DEPTH + " certificates; stopped at '"
                        + current.getSubjectX500Principal().getName() + "'");
                break;
            }
            X509Certificate issuer = selectIssuer(current, pool, chain);
            if (issuer == null && fetcher != null) {
                List<X509Certificate> fetched = fetcher.fetchIssuerCandidates(current);
                if (fetched != null) {
                    for (X509Certificate f : fetched) {
                        addDistinct(pool, f);
                    }
                }
                issuer = selectIssuer(current, pool, chain);
            }
            if (issuer == null) {
                problems.add("No issuer certificate found for '" + current.getSubjectX500Principal().getName()
                        + "' (issued by '" + current.getIssuerX500Principal().getName() + "')");
                break;
            }
            chain.add(issuer);
            current = issuer;
        }
        return new Result(chain, complete, problems);
    }

    /**
     * Convenience overload.
     *
     * @param leaf       the leaf certificate.
     * @param extraCerts extra certificates, may be null.
     * @return result
     */
    public Result build(X509Certificate leaf, Certificate[] extraCerts) {
        return build(leaf, extraCerts == null ? null : Arrays.asList(extraCerts));
    }

    private X509Certificate selectIssuer(X509Certificate child, List<X509Certificate> pool, List<X509Certificate> chainSoFar) {
        List<X509Certificate> candidates = new ArrayList<>();
        for (X509Certificate candidate : pool) {
            if (chainSoFar.contains(candidate)) {
                continue; // loop protection
            }
            if (isIssuerOf(candidate, child)) {
                candidates.add(candidate);
            }
        }
        if (candidates.isEmpty()) {
            return null;
        }
        final Date now = Date.from(clock.instant());
        // Prefer: currently valid, then the one that expires last. The sort is
        // stable, so on a tie the earlier pool position (caller-supplied first,
        // then bundled) wins.
        candidates.sort(Comparator
                .comparing((X509Certificate c) -> !isValidAt(c, now))
                .thenComparing(X509Certificate::getNotAfter, Comparator.reverseOrder()));
        return candidates.get(0);
    }

    /**
     * @param candidate possible issuer
     * @param child     certificate
     * @return true if <code>candidate</code> issued <code>child</code>, in
     * the sense described in the class documentation.
     */
    public static boolean isIssuerOf(X509Certificate candidate, X509Certificate child) {
        if (!candidate.getSubjectX500Principal().equals(child.getIssuerX500Principal())) {
            return false;
        }
        if (isExplicitlyNotCa(candidate)) {
            return false;
        }
        byte[] aki = authorityKeyIdentifier(child);
        byte[] ski = subjectKeyIdentifier(candidate);
        if (aki != null && ski != null && !Arrays.equals(aki, ski)) {
            return false;
        }
        try {
            child.verify(candidate.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * @param cert certificate
     * @return true if the certificate's subject equals its issuer AND its
     * signature verifies with its own public key.
     */
    public static boolean isSelfSigned(X509Certificate cert) {
        if (!cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
            return false;
        }
        try {
            cert.verify(cert.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean isExplicitlyNotCa(X509Certificate cert) {
        return cert.getExtensionValue(Extension.basicConstraints.getId()) != null
                && cert.getBasicConstraints() < 0;
    }

    private static boolean isValidAt(X509Certificate cert, Date when) {
        return !when.before(cert.getNotBefore()) && !when.after(cert.getNotAfter());
    }

    static byte[] authorityKeyIdentifier(X509Certificate cert) {
        try {
            byte[] ext = cert.getExtensionValue(Extension.authorityKeyIdentifier.getId());
            if (ext == null) {
                return null;
            }
            ASN1Primitive p = JcaX509ExtensionUtils.parseExtensionValue(ext);
            return AuthorityKeyIdentifier.getInstance(p).getKeyIdentifier();
        } catch (Exception e) {
            return null;
        }
    }

    static byte[] subjectKeyIdentifier(X509Certificate cert) {
        try {
            byte[] ext = cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());
            if (ext == null) {
                return null;
            }
            ASN1Primitive p = JcaX509ExtensionUtils.parseExtensionValue(ext);
            return SubjectKeyIdentifier.getInstance(p).getKeyIdentifier();
        } catch (Exception e) {
            return null;
        }
    }

    private static void addDistinct(List<X509Certificate> list, X509Certificate cert) {
        if (cert != null && !list.contains(cert)) {
            list.add(cert);
        }
    }

    /**
     * Outcome of {@link #build}.
     */
    public static final class Result {

        private final List<X509Certificate> chain;
        private final boolean complete;
        private final List<String> problems;

        Result(List<X509Certificate> chain, boolean complete, List<String> problems) {
            this.chain = Collections.unmodifiableList(new ArrayList<>(chain));
            this.complete = complete;
            this.problems = Collections.unmodifiableList(new ArrayList<>(problems));
        }

        /**
         * @return ordered chain, leaf first, root (if found) last. Never empty.
         */
        public List<X509Certificate> getChain() {
            return chain;
        }

        /**
         * @return the chain as an array, leaf first.
         */
        public X509Certificate[] toArray() {
            return chain.toArray(new X509Certificate[0]);
        }

        /**
         * @return true if the chain ends with a self-signed root certificate.
         */
        public boolean isComplete() {
            return complete;
        }

        /**
         * @return true if the leaf is itself self-signed (e.g. the placeholder
         * certificate CertWizard stores alongside a pending CSR).
         */
        public boolean isLeafSelfSigned() {
            return complete && chain.size() == 1;
        }

        /**
         * @return human readable descriptions of why the chain is incomplete;
         * empty when complete.
         */
        public List<String> getProblems() {
            return problems;
        }
    }
}
