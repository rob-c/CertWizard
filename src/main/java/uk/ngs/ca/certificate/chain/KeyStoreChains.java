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

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * Helpers for working with the certificate chains of keystore key entries.
 */
public final class KeyStoreChains {

    private KeyStoreChains() {
    }

    /**
     * Complete the chain stored with a key entry: the first certificate (the
     * one belonging to the private key) followed by every issuer up to and
     * including the root.
     *
     * @param stored  chain as stored in the keystore (leaf first, possibly
     *                truncated, unordered after the leaf, or containing
     *                unrelated certificates).
     * @param builder builder to use.
     * @return the build result, or null if <code>stored</code> is empty or its
     * first element is not an X.509 certificate.
     */
    public static CertChainBuilder.Result complete(Certificate[] stored, CertChainBuilder builder) {
        if (stored == null || stored.length == 0 || !(stored[0] instanceof X509Certificate)) {
            return null;
        }
        return builder.build((X509Certificate) stored[0], Arrays.asList(stored));
    }

    /**
     * @param chain a certificate chain
     * @return true if <code>chain</code> is already leaf-first, every element
     * is issued by the next one, and it ends with a self-signed root.
     */
    public static boolean isCompleteOrderedChain(Certificate[] chain) {
        if (chain == null || chain.length == 0) {
            return false;
        }
        for (int i = 0; i < chain.length; i++) {
            if (!(chain[i] instanceof X509Certificate)) {
                return false;
            }
        }
        for (int i = 0; i + 1 < chain.length; i++) {
            if (!CertChainBuilder.isIssuerOf((X509Certificate) chain[i + 1], (X509Certificate) chain[i])) {
                return false;
            }
        }
        return CertChainBuilder.isSelfSigned((X509Certificate) chain[chain.length - 1]);
    }

    /**
     * Decide whether a stored key-entry chain should be replaced by a newly
     * built one. Never replaces a chain that is already complete and ordered,
     * never replaces with an incomplete result, and ignores self-signed
     * placeholder certificates (pending CSRs).
     *
     * @param stored chain currently stored
     * @param built  newly built result (may be null)
     * @return true if the stored chain should be replaced by <code>built</code>.
     */
    public static boolean shouldReplace(Certificate[] stored, CertChainBuilder.Result built) {
        if (built == null || !built.isComplete() || built.isLeafSelfSigned()) {
            return false;
        }
        if (isCompleteOrderedChain(stored)) {
            return false;
        }
        return !Arrays.equals(stored, built.toArray());
    }
}
