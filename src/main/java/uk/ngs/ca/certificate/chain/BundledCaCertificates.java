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

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The UK e-Science CA certificates shipped inside CertWizard.
 * <p>
 * Every bundled certificate is pinned by the SHA-256 fingerprint of its DER
 * encoding. A resource that does not match its pin is treated as corrupt or
 * tampered with and loading fails: we would rather refuse to start than build
 * chains from, or trust, the wrong CA certificate.
 * <p>
 * Fingerprints were cross-checked against two independent publications: the
 * IGTF accredited classic distribution (v1.147) and the CA's own page at
 * https://ca.grid-support.ac.uk/cacerts/ .
 */
public final class BundledCaCertificates {

    /**
     * Resource name to expected SHA-256 fingerprint (lower-case hex, DER).
     * Keep the two original resource names unchanged - other code loads them
     * directly.
     */
    private static final Map<String, String> PINNED = new LinkedHashMap<>();

    static {
        // C=UK, O=eScienceRoot, OU=Authority, CN=UK e-Science Root (2007-2027, RSA)
        PINNED.put("/escience-root.pem", "76f3a5942e22012d7e10e11b416fb2eea21d8f4583f2d2fc799bd4ced0210323");
        // C=UK, O=eScienceCA, OU=Authority, CN=UK e-Science CA 2B (2011-2027, RSA), issued by Root (2007)
        PINNED.put("/escience-2b.pem", "b6d140a765d165d8917bb9941f7ab21ff89c04155a4dce52cad345862c3e686e");
        // C=UK, O=eScienceRoot, OU=Authority, CN=UK e-Science Root 2026 (2026-2046, ECDSA)
        PINNED.put("/escience-root-2026.pem", "565c16e7d6ff0f602aefca2a585634c190d7d9da411c7750d79cac6b351ffffa");
        // C=UK, O=eScienceCA, OU=Authority, CN=UK e-Science CA 3B (2026-2046, ECDSA), issued by Root 2026
        PINNED.put("/escience-3b.pem", "16383860bc6e61488ffb945e961963967c4fe8d73d2b2e9641d0b535cca4b845");
    }

    private static volatile List<X509Certificate> cached;

    private BundledCaCertificates() {
    }

    /**
     * @return all bundled CA certificates (roots and intermediates), in a
     * stable order. The list is unmodifiable.
     * @throws IllegalStateException if a bundled resource is missing,
     *                               unparsable, or does not match its pinned fingerprint.
     */
    public static List<X509Certificate> all() {
        List<X509Certificate> result = cached;
        if (result == null) {
            synchronized (BundledCaCertificates.class) {
                result = cached;
                if (result == null) {
                    result = Collections.unmodifiableList(load());
                    cached = result;
                }
            }
        }
        return result;
    }

    /**
     * @return the self-signed roots among the bundled certificates; these are
     * the trust anchors for chain validation.
     */
    public static List<X509Certificate> roots() {
        List<X509Certificate> roots = new ArrayList<>();
        for (X509Certificate c : all()) {
            if (CertChainBuilder.isSelfSigned(c)) {
                roots.add(c);
            }
        }
        return Collections.unmodifiableList(roots);
    }

    /**
     * @return the pinned resource names and fingerprints (for diagnostics and tests).
     */
    public static Map<String, String> pinnedFingerprints() {
        return Collections.unmodifiableMap(PINNED);
    }

    /**
     * @param cert certificate
     * @return lower-case hex SHA-256 of the DER encoding.
     */
    public static String sha256Fingerprint(X509Certificate cert) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static List<X509Certificate> load() {
        List<X509Certificate> certs = new ArrayList<>();
        CertificateFactory cf;
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new IllegalStateException(e);
        }
        for (Map.Entry<String, String> pin : PINNED.entrySet()) {
            try (InputStream in = BundledCaCertificates.class.getResourceAsStream(pin.getKey())) {
                if (in == null) {
                    throw new IllegalStateException("Bundled CA certificate is missing: " + pin.getKey());
                }
                X509Certificate cert = (X509Certificate) cf.generateCertificate(in);
                String actual = sha256Fingerprint(cert);
                if (!actual.equals(pin.getValue())) {
                    throw new IllegalStateException("Bundled CA certificate " + pin.getKey()
                            + " does not match its pinned SHA-256 fingerprint (expected "
                            + pin.getValue() + ", got " + actual + ")");
                }
                certs.add(cert);
            } catch (IOException | CertificateException e) {
                throw new IllegalStateException("Cannot load bundled CA certificate " + pin.getKey(), e);
            }
        }
        return certs;
    }
}
