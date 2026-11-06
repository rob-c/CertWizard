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
package uk.ngs.ca.certificate.management;

import uk.ngs.ca.common.FileUtils;
import uk.ngs.ca.common.SystemStatus;
import uk.ngs.ca.tools.property.SysProperty;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.logging.Level;

/**
 * A thread safe singleton that wraps the managed
 * <tt>'$HOME/.ca/cakeystore.pkcs12'</tt> KeyStore file.
 * <p>
 * It provides thread safe methods for adding/creating/deleting entries from the
 * managed keyStore file. Access to the managed keyStore object is guarded by
 * the singleton <code>this</code> instance.
 * <p>
 * Visibility of <code>getInstance()</code> is limited to package-protected so
 * that retrieval can be managed by other higher level classes in this package.
 * <p>
 * Importantly, the keyStore is <b>NEVER reStored to disk</b> by any of the
 * methods. This is delegated to the calling client with manual invocations of {@link #reStore()
 * }.
 *
 * @author xw75 (Xiao Wang)
 * @author David Meredith (refactoring - still lots to fix)
 * @todo DM: Lots, more refactoring is needed, especially all the exception
 * swallowing to fix
 */
public final class ClientKeyStore {

    // keyStore is an in-mem object that represents shared mutable state and 
    // so access to its entries must by synchronized in order to;  
    // a) prevent one thread from modifying the state of the object when 
    // another thread is using it, and 
    // b) prevent dirty reads by different threads (visiblity) 
    // The keyStore is confined to this object, it is never leaked/published. 
    private volatile KeyStore keyStore;
    private final String keyStoreFilePath;
    private final String backupKeyStoreFilePath;
    private final String backupDir;
    private char[] PASSPHRASE = null;
    private static ClientKeyStore clientKeyStore = null;

    /**
     * Get a shared singleton <code>ClientKeyStore</code> instance for the
     * <tt>'$HOME/.ca/cakeystore.pkcs12'</tt> keyStore file.
     *
     * @param passphrase used to protect the keyStore.
     * @return
     * @throws IllegalStateException if there is problem creating or loading the
     *                               KeyStore
     */
    static synchronized ClientKeyStore getClientkeyStore(char[] passphrase) throws KeyStoreException, IOException, CertificateException {
        // Static factory method allows us to choose whether we return the same instance
        // or create a new instance (easy to remove the if statement below so that
        // each invocation of this method will create/return a new keyStore
        // which replicates the previous public constructor).
        //
        // Check if keyStore has already been created succesfully,
        // (a composite action, i.e. check if null then act, but this is ok
        // provided this method is synchronized). Lets create the keystore only
        // if it has not been created yet or if the password has changed.
        if (clientKeyStore == null) {//|| (passphrase != null && !Arrays.equals(passphrase,clientKeyStore.PASSPHRASE))) {
            clientKeyStore = new ClientKeyStore(passphrase);
        }
        return clientKeyStore;
    }

    /**
     * Forget the shared instance. For tests only: lets each test load its own
     * keystore from its own temporary data directory.
     */
    static synchronized void resetForTesting() {
        clientKeyStore = null;
    }

    /**
     * Force non-instantiation with private constructor
     * <p>
     * If $HOME/.ca/cakeystore.pkcs12 already exists, load it otherwise create
     * an empty pkcs12 file.
     *
     * @param passphrase
     * @throws IllegalStateException if the KeyStore cannot be initialized.
     */
    private ClientKeyStore(char[] passphrase) throws KeyStoreException, IOException, CertificateException {
        String caDir = SystemStatus.getInstance().getCwDataDirectory().toString();
        this.PASSPHRASE = passphrase;
        this.keyStoreFilePath = caDir + File.separator + SysProperty.getValue("ngsca.key.keystore.file");
        this.backupDir = caDir + File.separator + "backup";
        this.backupKeyStoreFilePath = backupDir + File.separator + SysProperty.getValue("ngsca.key.keystore.file") + ".backup";
        this.keyStore = this.getKeyStoreCopy();
    }

    /**
     * Change the keyStore password and persist to file.
     *
     * @param passphrase
     */
    public synchronized void reStorePassword(char[] passphrase) throws IOException, KeyStoreException, CertificateException {
        this.PASSPHRASE = passphrase;
        this.reStore();
    }

    /**
     * @return the full path of the managed keyStore file
     */
    public String getKeyStoreFilePath() {
        return this.keyStoreFilePath;
    }

    /**
     * Create a new KeyStore instance by loading state from the
     * <tt>'$HOME/.ca/cakeystore.pkcs12'</tt> file. If file does not exist, then
     * load an empty keyStore. This newly created KeyStore object is a copy of
     * the KeyStore that is managed in this class. Important: the keyStore is
     * NOT reStored to disk (so if an initial keyStore does not exist, the file
     * is not created on disk).
     *
     * @return A newly created KeyStore
     */
    public KeyStore getKeyStoreCopy() throws KeyStoreException, IOException, CertificateException {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
            FileInputStream fis = null;
            try {
                File f = new File(this.keyStoreFilePath);
                if (f.exists() && f.length() != 0L) {
                    fis = new FileInputStream(keyStoreFilePath);
                    ks.load(fis, this.PASSPHRASE);
                } else {
                    ks.load(null, null);
                }
                return ks;
            } finally {
                try {
                    if (fis != null) {
                        fis.close();
                    }
                } catch (IOException ex) {
                    java.util.logging.Logger.getLogger(ClientKeyStore.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        } catch (NoSuchProviderException | NoSuchAlgorithmException ke) {
            throw new IllegalStateException(ke);
        }
    }

    /**
     * Save the managed keyStore file to its default location and re-init the
     * managed key store <code>this.keyStore</code>.
     *
     * @throws IOException
     * @throws KeyStoreException
     * @throws CertificateException
     */
    public synchronized void reStore() throws IOException, KeyStoreException, CertificateException {
        // must first create a swap file incase anything goes wrong 
        File srcFile = new File(this.keyStoreFilePath);
        File swpFile = new File(this.keyStoreFilePath + ".swp");
        File bckFile = new File(this.backupKeyStoreFilePath);
        // create the backup dir if don't already exist. 
        File fbackupDir = new File(this.backupDir);
        if (!fbackupDir.exists()) {
            fbackupDir.mkdir();
        }

        if (srcFile.exists() && srcFile.length() > 0L) {
            // create swap file first 
            FileUtils.copyFile(srcFile, swpFile, true);
            // now update backup file 
            FileUtils.copyFile(srcFile, bckFile, true);
        }

        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(srcFile);
            // store will overwrite the file if it already exists
            this.keyStore.store(fos, PASSPHRASE);

            // We Need to re-load this.keyStore object from file - 
            // the act of persisting then reloading seems to re-organize the
            // keystore entries so that Trusted certs that exist in an
            // imported cert chain are also stored as standalone entries in the
            // keyStore file? 
            this.keyStore = this.getKeyStoreCopy();

        } catch (NoSuchAlgorithmException ex) {
            // Thrown when a particular cryptographic algorithm is
            // requested but is not available in the environment. Since we know
            // what algorithms we are using via BC, it should probably be considered a coding error
            throw new IllegalStateException(ex);
        } finally {
            try {
                if (fos != null) {
                    fos.close();
                }
            } catch (IOException ex) {
                java.util.logging.Logger.getLogger(ClientKeyStore.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        // Now delete the swap file (we don't want to leave around copies of 
        // the user's keyStore on disk). 
        if (swpFile != null && swpFile.exists()) {
            swpFile.delete();
        }
    }

    public synchronized PrivateKey getPrivateKey(PublicKey publicKey) {
        try {
            Enumeration<String> aliases = this.keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (this.keyStore.isKeyEntry(alias)) {
                    X509Certificate cert = (X509Certificate) this.keyStore.getCertificate(alias);
                    if (cert.getPublicKey().equals(publicKey)) {
                        // Use the alias we just matched. Re-deriving it with
                        // getCertificateAlias() returns the *first* alias holding
                        // this certificate, which need not be this one, and can
                        // also resolve to a trustedCertEntry that has no key.
                        return (PrivateKey) this.keyStore.getKey(alias, PASSPHRASE);
                    }
                }
            }
        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }
        return null;
    }

    /**
     * Get the x509 certificate for the keyStore entry with the requested alias
     * or null if alias does not represent an x509 cert.
     *
     * @param alias
     * @return certificate or null.
     * @throws KeyStoreException
     */
    public synchronized X509Certificate getX509Certificate(String alias) throws KeyStoreException {
        if (this.keyStore.getCertificate(alias) != null) {
            if (this.keyStore.getCertificate(alias) instanceof X509Certificate) {
                return (X509Certificate) this.keyStore.getCertificate(alias);
            }
        }
        return null;
    }

    public synchronized PrivateKey getPrivateKey(String alias) {
        try {
            return (PrivateKey) this.keyStore.getKey(alias, PASSPHRASE);
        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }
        return null;
    }

    /**
     * @see java.security.KeyStore#deleteEntry(java.lang.String)
     */
    public synchronized void deleteEntry(String alias) throws KeyStoreException {
        this.keyStore.deleteEntry(alias);
    }

    /**
     * @see java.security.KeyStore#isCertificateEntry(java.lang.String)
     */
    public synchronized boolean isCertificateEntry(String alias) throws KeyStoreException {
        return this.keyStore.isCertificateEntry(alias);
    }

    /**
     * @see java.security.KeyStore#isKeyEntry(java.lang.String)
     */
    public synchronized boolean isKeyEntry(String alias) throws KeyStoreException {
        return this.keyStore.isKeyEntry(alias);
    }

    /**
     * @see java.security.KeyStore#aliases()
     */
    public synchronized Enumeration<String> aliases() throws KeyStoreException {
        return this.keyStore.aliases();
    }

    /**
     * @see java.security.KeyStore#getCertificate(java.lang.String)
     */
    public synchronized java.security.cert.Certificate getCertificate(String alias) throws KeyStoreException {
        return this.keyStore.getCertificate(alias);
    }

    /**
     * @see java.security.KeyStore#getCertificateChain(java.lang.String)
     */
    public synchronized java.security.cert.Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        return this.keyStore.getCertificateChain(alias);
    }

    /**
     * @see java.security.KeyStore#getCreationDate(java.lang.String)
     */
    public synchronized Date getCreationDate(String alias) throws KeyStoreException {
        return this.keyStore.getCreationDate(alias);
    }

    /**
     * @see java.security.KeyStore#getKey(java.lang.String, char[])
     */
    public synchronized Key getKey(String alias, char[] pass) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return this.keyStore.getKey(alias, pass);
    }

    /**
     * @see java.security.KeyStore#setKeyEntry(java.lang.String, byte[],
     * java.security.cert.Certificate[])
     */
    public synchronized void setKeyEntry(String alias, Key key, char[] password, java.security.cert.Certificate[] chain) throws KeyStoreException {
        this.keyStore.setKeyEntry(alias, key, password, chain);
    }

    /**
     * @see java.security.KeyStore#containsAlias(java.lang.String)
     */
    public synchronized boolean containsAlias(String alias) throws KeyStoreException {
        return this.keyStore.containsAlias(alias);
    }

    /**
     * @see java.security.KeyStore#setCertificateEntry(java.lang.String,
     * java.security.cert.Certificate)
     */
    public synchronized void setCertificateEntry(String alias, java.security.cert.Certificate cert) throws KeyStoreException {
        this.keyStore.setCertificateEntry(alias, cert);
    }

}
