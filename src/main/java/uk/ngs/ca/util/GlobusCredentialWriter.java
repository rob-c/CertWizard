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
package uk.ngs.ca.util;

import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;

import java.io.File;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.channels.Channels;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.EnumSet;
import java.util.Set;

/**
 * Writes a Globus-style credential pair: <code>usercert.pem</code> and
 * <code>userkey.pem</code>.
 * <ul>
 * <li><code>usercert.pem</code> holds the user certificate followed by every
 * issuer certificate up to and including the root, in order. Tools that only
 * need the user certificate read the first PEM block. Tools that need the
 * chain find it there.</li>
 * <li><code>userkey.pem</code> holds the private key, encrypted (traditional
 * OpenSSL PEM, DES-EDE3-CBC, for compatibility with grid tooling), and is
 * created owner-only from the start and ends at mode 0400, so no other user
 * can read the file at any point. grid-proxy-init and voms-proxy-init refuse a
 * key file with group/other permissions.</li>
 * </ul>
 */
public final class GlobusCredentialWriter {

    private static final Set<PosixFilePermission> OWNER_RW = PosixFilePermissions.fromString("rw-------");
    private static final Set<PosixFilePermission> OWNER_R = PosixFilePermissions.fromString("r--------");
    private static final Set<PosixFilePermission> CERT_FINAL = PosixFilePermissions.fromString("r--r--r--");

    private GlobusCredentialWriter() {
    }

    /**
     * Write the certificate chain and encrypted private key. Existing files
     * are replaced.
     *
     * @param certFile destination for the certificate chain
     * @param keyFile  destination for the private key
     * @param chain    leaf-first certificate chain (at least the leaf)
     * @param key      private key matching <code>chain[0]</code>
     * @param password password used to encrypt the key (must not be empty)
     * @throws IOException on any I/O or encoding failure
     */
    public static void write(Path certFile, Path keyFile, X509Certificate[] chain, PrivateKey key, char[] password)
            throws IOException {
        if (chain == null || chain.length == 0) {
            throw new IllegalArgumentException("certificate chain is empty");
        }
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("refusing to write an unencrypted private key");
        }
        deleteEvenIfReadOnly(certFile);
        deleteEvenIfReadOnly(keyFile);

        // Certificate chain: public data.
        try (Writer w = Files.newBufferedWriter(certFile, StandardCharsets.US_ASCII,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
             JcaPEMWriter pem = new JcaPEMWriter(w)) {
            for (X509Certificate c : chain) {
                pem.writeObject(c);
            }
        }
        setPermissions(certFile, CERT_FINAL, false);

        // Private key: owner-only from the moment the file exists.
        PEMEncryptor encryptor = new JcePEMEncryptorBuilder("DES-EDE3-CBC")
                .setSecureRandom(new SecureRandom()).build(password);
        try (SeekableByteChannel ch = createOwnerOnly(keyFile);
             Writer w = new OutputStreamWriter(Channels.newOutputStream(ch), StandardCharsets.US_ASCII);
             JcaPEMWriter pem = new JcaPEMWriter(w)) {
            pem.writeObject(key, encryptor);
        }
        setPermissions(keyFile, OWNER_R, true);
    }

    private static void deleteEvenIfReadOnly(Path file) throws IOException {
        if (Files.exists(file, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            // A previous install leaves the files read-only; on Windows a
            // read-only file cannot be deleted until it is made writable.
            file.toFile().setWritable(true, true);
            Files.delete(file);
        }
    }

    private static boolean isPosix() {
        return FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
    }

    private static SeekableByteChannel createOwnerOnly(Path file) throws IOException {
        EnumSet<StandardOpenOption> opts = EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        if (isPosix()) {
            return Files.newByteChannel(file, opts, PosixFilePermissions.asFileAttribute(OWNER_RW));
        }
        SeekableByteChannel ch = Files.newByteChannel(file, opts);
        File f = file.toFile();
        f.setReadable(false, false);
        f.setReadable(true, true);
        f.setWritable(false, false);
        f.setWritable(true, true);
        return ch;
    }

    private static void setPermissions(Path file, Set<PosixFilePermission> posix, boolean ownerOnly) throws IOException {
        if (isPosix()) {
            Files.setPosixFilePermissions(file, posix);
            return;
        }
        File f = file.toFile();
        f.setExecutable(false, false);
        f.setWritable(false, false);
        if (ownerOnly) {
            f.setReadable(false, false);
            f.setReadable(true, true);
        } else {
            f.setReadable(true, false);
        }
    }
}
