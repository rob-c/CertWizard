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

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import java.io.InputStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Reads back a file CertWizard has just written and checks that it contains
 * exactly what was intended: the full certificate chain, and a private key
 * that decrypts with the chosen password and matches the certificate.
 * <p>
 * Every method returns a list of problems; an empty list means the file is
 * good. They never throw for a bad file. A file that cannot be read is itself
 * a problem.
 */
public final class ExportVerifier {

    private ExportVerifier() {
    }

    /**
     * @param file     exported PKCS#12 file
     * @param password password it was written with
     * @param chain    the chain that should be in it, leaf first
     * @param key      the private key that should be in it
     * @return problems, empty if the file is good
     */
    public static List<String> verifyPkcs12(Path file, char[] password, Certificate[] chain, PrivateKey key) {
        List<String> problems = new ArrayList<>();
        try (InputStream in = Files.newInputStream(file)) {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(in, password);
            List<String> keyAliases = new ArrayList<>();
            for (String alias : Collections.list(ks.aliases())) {
                if (ks.isKeyEntry(alias)) {
                    keyAliases.add(alias);
                }
            }
            if (keyAliases.size() != 1) {
                problems.add("expected exactly one private key entry, found " + keyAliases.size());
                return problems;
            }
            String alias = keyAliases.get(0);
            Certificate[] got = ks.getCertificateChain(alias);
            if (!Arrays.equals(chain, got)) {
                problems.add("certificate chain differs: expected " + chain.length + " certificates, file has "
                        + (got == null ? 0 : got.length));
            }
            Key k = ks.getKey(alias, password);
            checkKey(problems, k instanceof PrivateKey ? (PrivateKey) k : null, chain, key);
        } catch (Exception e) {
            problems.add("cannot be read back with the chosen password: " + e.getMessage());
        }
        return problems;
    }

    /**
     * @param file     exported PEM file (private key + certificates)
     * @param password password the key was encrypted with (empty = unencrypted)
     * @param chain    expected chain, leaf first, in file order
     * @param key      expected private key
     * @return problems, empty if the file is good
     */
    public static List<String> verifyPem(Path file, char[] password, Certificate[] chain, PrivateKey key) {
        List<String> problems = new ArrayList<>();
        List<X509Certificate> certs = new ArrayList<>();
        PrivateKey readKey = null;
        int keys = 0;
        try (Reader r = Files.newBufferedReader(file, StandardCharsets.US_ASCII); PEMParser p = new PEMParser(r)) {
            JcaPEMKeyConverter conv = new JcaPEMKeyConverter();
            Object o;
            while ((o = p.readObject()) != null) {
                if (o instanceof X509CertificateHolder) {
                    certs.add(new JcaX509CertificateConverter().getCertificate((X509CertificateHolder) o));
                } else if (o instanceof PEMEncryptedKeyPair) {
                    keys++;
                    if (password == null || password.length == 0) {
                        problems.add("private key is encrypted but no password was set");
                    } else {
                        PEMKeyPair kp = ((PEMEncryptedKeyPair) o).decryptKeyPair(new JcePEMDecryptorProviderBuilder().build(password));
                        readKey = conv.getPrivateKey(kp.getPrivateKeyInfo());
                    }
                } else if (o instanceof PEMKeyPair) {
                    keys++;
                    if (password != null && password.length > 0) {
                        problems.add("private key was written UNENCRYPTED although a password was chosen");
                    }
                    readKey = conv.getPrivateKey(((PEMKeyPair) o).getPrivateKeyInfo());
                } else if (o instanceof PrivateKeyInfo) {
                    keys++;
                    if (password != null && password.length > 0) {
                        problems.add("private key was written UNENCRYPTED although a password was chosen");
                    }
                    readKey = conv.getPrivateKey((PrivateKeyInfo) o);
                }
            }
        } catch (Exception e) {
            problems.add("cannot be read back: " + e.getMessage());
            return problems;
        }
        if (keys != 1) {
            problems.add("expected exactly one private key, found " + keys);
        }
        if (!certs.equals(Arrays.asList(chain))) {
            problems.add("certificate chain differs: expected " + chain.length + " certificates in order, file has " + certs.size());
        }
        if (keys == 1 && problems.isEmpty()) {
            checkKey(problems, readKey, chain, key);
        }
        return problems;
    }

    /**
     * @param file  exported PKCS#7 file
     * @param chain expected certificates. PKCS#7 stores certificates as a SET,
     *              so order is not significant.
     * @return problems, empty if the file is good
     */
    public static List<String> verifyPkcs7(Path file, Certificate[] chain) {
        List<String> problems = new ArrayList<>();
        try (InputStream in = Files.newInputStream(file)) {
            Collection<? extends Certificate> got = CertificateFactory.getInstance("X.509").generateCertificates(in);
            Set<Certificate> expected = new HashSet<>(Arrays.asList(chain));
            if (!expected.equals(new HashSet<>(got)) || got.size() != chain.length) {
                problems.add("expected the " + chain.length + " chain certificates, file has " + got.size() + " (or different ones)");
            }
        } catch (Exception e) {
            problems.add("cannot be read back: " + e.getMessage());
        }
        return problems;
    }

    /**
     * @param certFile usercert.pem
     * @param keyFile  userkey.pem
     * @param password key password
     * @param chain    expected chain, leaf first
     * @param key      expected private key
     * @return problems, empty if the pair is good
     */
    public static List<String> verifyGlobus(Path certFile, Path keyFile, char[] password, Certificate[] chain, PrivateKey key) {
        List<String> problems = new ArrayList<>();
        try (InputStream in = Files.newInputStream(certFile)) {
            List<Certificate> got = new ArrayList<>(CertificateFactory.getInstance("X.509").generateCertificates(in));
            if (!got.equals(Arrays.asList(chain))) {
                problems.add("usercert.pem: expected the " + chain.length + "-certificate chain in order, file has " + got.size());
            }
        } catch (Exception e) {
            problems.add("usercert.pem cannot be read back: " + e.getMessage());
        }
        List<String> keyProblems = verifyPem(keyFile, password, new Certificate[0], key);
        // verifyPem also compares certificates; userkey.pem holds none, so
        // only its key-related findings matter here.
        for (String p : keyProblems) {
            if (!p.startsWith("certificate chain differs")) {
                problems.add("userkey.pem: " + p);
            }
        }
        if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            try {
                Set<PosixFilePermission> perms = Files.getPosixFilePermissions(keyFile);
                perms.remove(PosixFilePermission.OWNER_READ);
                perms.remove(PosixFilePermission.OWNER_WRITE);
                if (!perms.isEmpty()) {
                    problems.add("userkey.pem is accessible to other users " + perms + "; grid tools will refuse it");
                }
            } catch (Exception e) {
                problems.add("userkey.pem permissions cannot be read: " + e.getMessage());
            }
        }
        return problems;
    }

    private static void checkKey(List<String> problems, PrivateKey readKey, Certificate[] chain, PrivateKey expected) {
        if (readKey == null) {
            problems.add("no private key could be recovered");
            return;
        }
        if (expected != null && !Arrays.equals(readKey.getEncoded(), expected.getEncoded())
                && !sameKeyPair(readKey, expected)) {
            problems.add("private key differs from the one in the keystore");
        }
        if (chain.length > 0 && !matches(readKey, chain[0])) {
            problems.add("private key does not match the certificate");
        }
    }

    private static boolean sameKeyPair(PrivateKey a, PrivateKey b) {
        // Encodings may legitimately differ (e.g. optional attributes); fall
        // back to comparing what a signature over random data proves.
        String alg = CertificateVerifier.signatureAlgorithmFor(a);
        if (alg == null || !a.getAlgorithm().equals(b.getAlgorithm())) {
            return false;
        }
        try {
            byte[] data = new byte[32];
            new SecureRandom().nextBytes(data);
            Signature s1 = Signature.getInstance(alg);
            s1.initSign(a);
            s1.update(data);
            byte[] sig1 = s1.sign();
            Signature s2 = Signature.getInstance(alg);
            s2.initSign(b);
            s2.update(data);
            byte[] sig2 = s2.sign();
            // RSA PKCS#1 v1.5 signatures are deterministic; for (EC)DSA compare by
            // cross-verification is not possible without the public key, so treat
            // as same only when deterministic signatures agree.
            return Arrays.equals(sig1, sig2);
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean matches(PrivateKey key, Certificate cert) {
        String alg = CertificateVerifier.signatureAlgorithmFor(key);
        if (alg == null) {
            return true; // cannot test; not evidence of a mismatch
        }
        try {
            byte[] data = new byte[32];
            new SecureRandom().nextBytes(data);
            Signature s = Signature.getInstance(alg);
            s.initSign(key);
            s.update(data);
            byte[] sig = s.sign();
            s.initVerify(cert.getPublicKey());
            s.update(data);
            return s.verify(sig);
        } catch (Exception e) {
            return false;
        }
    }
}
