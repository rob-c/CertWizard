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

import net.sf.portecle.DGetAlias;
import net.sf.portecle.DImportKeyPair;
import net.sf.portecle.FPortecle;
import net.sf.portecle.FileChooserFactory;
import net.sf.portecle.crypto.CryptoException;
import net.sf.portecle.crypto.KeyStoreType;
import net.sf.portecle.crypto.KeyStoreUtil;
import net.sf.portecle.crypto.X509CertUtil;
import net.sf.portecle.gui.SwingHelper;
import net.sf.portecle.gui.error.DThrowable;
import net.sf.portecle.gui.password.DGetPassword;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PasswordFinder;
import uk.ngs.ca.certificate.chain.CertChainBuilder;
import uk.ngs.ca.certificate.chain.KeyStoreChains;
import uk.ngs.ca.certificate.management.ClientKeyStoreCaServiceWrapper;
import uk.ngs.ca.certificate.management.KeyStoreEntryWrapper;
import uk.ngs.ca.common.SystemStatus;
import uk.ngs.certwizard.gui.FilePicker;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.ResourceBundle;

/**
 * Helper class for assisting users with importing of certificates into the
 * applications managed keyStore. The methods invoked by this class present GUI
 * components during their processing.
 *
 * @author David Meredith
 */
public class CertificateImportGuiHelper {

    /**
     * Portecle Resource bundle base name
     */
    private static final String RB_BASENAME = FPortecle.class.getPackage().getName() + "/resources";
    /**
     * Portecle Resource bundle
     */
    public static final ResourceBundle RB = ResourceBundle.getBundle(RB_BASENAME);
    private final Component parentCompoent;
    private final ClientKeyStoreCaServiceWrapper caKeyStoreModel;
    //private char[] PASSPHRASE;

    public CertificateImportGuiHelper(Component parentCompoent, ClientKeyStoreCaServiceWrapper caKeyStoreModel) {
        this.parentCompoent = parentCompoent;
        this.caKeyStoreModel = caKeyStoreModel;
    }

    /**
     * Let the user import a key pair a PKCS #12 keystore or a PEM bundle. Based
     * on Portecle.
     *
     * @see FPortecle#importKeyPair()
     */
    public String doImportCertificateAction() throws KeyStoreException, CryptoException, IOException, CertificateException {

        // Let the user choose a file to import from
        File fKeyPairFile = chooseImportFileHelper();
        if (fKeyPairFile == null) {
            return null; // user cancelled
        }

        // Not a file?
        if (!fKeyPairFile.isFile()) {
            JOptionPane.showMessageDialog(parentCompoent,
                    MessageFormat.format(RB.getString("FPortecle.NotFile.message"), fKeyPairFile),
                    RB.getString("FPortecle.ImportKeyPair.Title"), JOptionPane.WARNING_MESSAGE);
            return null;
        }

        // log all the exceptions that may occur
        ArrayList<Exception> exceptions = new ArrayList<>();
        KeyStore tempStore = null;
        PEMParser reader = null;
        try {
            PasswordFinder passwordFinder = new PasswordFinder() {

                private int passwordNumber = 1;

                @Override
                public char[] getPassword() {
                    // Get the user to enter the private key password
                    DGetPassword dGetPassword
                            = new DGetPassword(null, MessageFormat.format(
                            RB.getString("FPortecle.PrivateKeyPassword.Title"),
                            String.valueOf(passwordNumber)));
                    dGetPassword.setLocationRelativeTo(parentCompoent);
                    SwingHelper.showAndWait(dGetPassword);
                    char[] cPassword = dGetPassword.getPassword();
                    passwordNumber++;
                    return cPassword;
                }
            };

            reader = new PEMParser(new FileReader(fKeyPairFile.getPath()));
            tempStore = KeyStoreUtil.loadEntries(reader, passwordFinder);
            if (tempStore.size() == 0) {
                tempStore = null;
            }
        } catch (Exception e) {
            exceptions.add(e);
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException ignored) {
                }
            }
        }

        // Treat as PKCS #12 keystore
        if (tempStore == null) {

            // Get the user to enter the PKCS #12 keystore's password
            DGetPassword dGetPassword
                    = new DGetPassword(null, RB.getString("FPortecle.Pkcs12Password.Title"));
            dGetPassword.setLocationRelativeTo(parentCompoent);
            SwingHelper.showAndWait(dGetPassword);
            char[] cPkcs12Password = dGetPassword.getPassword();
            if (cPkcs12Password == null) {
                return null;
            }

            // Load the PKCS #12 keystore
            // DM: important note, the KeyStoreUtil.java class has been modified
            // so that it uses the unlimited strength pkcs12 provider so that
            // unlimited length passwords can be used (circumvents manually
            // installing the unlimited strength Jurisdiction policy files from
            // oracle). 
            try {
                tempStore = KeyStoreUtil.loadKeyStore(fKeyPairFile, cPkcs12Password, KeyStoreType.PKCS12);
            } catch (Exception e) {
                exceptions.add(e);
            }
        }

        if (tempStore == null && !exceptions.isEmpty()) {
            int iSelected
                    = SwingHelper.showConfirmDialog(parentCompoent,
                    MessageFormat.format(RB.getString("FPortecle.NoOpenKeyPairFile.message"), fKeyPairFile),
                    RB.getString("FPortecle.ImportKeyPairFile.Title"));
            if (iSelected == JOptionPane.YES_OPTION) {
                for (Exception e : exceptions) {
                    DThrowable.showAndWait(null, null, e);
                }
            }
            return null;
        }

        // Display the import key pair dialog supplying the PKCS #12 keystore to it
        DImportKeyPair dImportKeyPair = new DImportKeyPair(null, tempStore);
        dImportKeyPair.setLocationRelativeTo(parentCompoent);
        SwingHelper.showAndWait(dImportKeyPair);

        // Get the private key and certificate chain of the key pair
        Key privateKey = dImportKeyPair.getPrivateKey();
        Certificate[] certChain = dImportKeyPair.getCertificateChain();

        if (privateKey == null || certChain == null) {
            // User did not select a key pair for import
            return null;
        }

        // PKCS#12 files often carry a partial or unordered chain (e.g. user
        // cert + root with the intermediate missing). Store the full ordered
        // chain - user cert, every intermediate, root - whenever it can be
        // completed. Otherwise keep exactly what the file contained.
        CertChainBuilder.Result completed = KeyStoreChains.complete(certChain, CertChainBuilder.standard());
        if (KeyStoreChains.shouldReplace(certChain, completed)) {
            certChain = completed.toArray();
        }

        // Get an alias for the new keystore entry
        //String newHeadCertImportAlias = dImportKeyPair.getAlias();
        //if (newHeadCertImportAlias == null) {
        String newHeadCertImportAlias = X509CertUtil.getCertificateAlias(X509CertUtil.convertCertificate(certChain[0]));
        //}
        if (newHeadCertImportAlias == null) {
            newHeadCertImportAlias = "My imported certificate";
        }

        newHeadCertImportAlias = getNewEntryAliasHelper(newHeadCertImportAlias, "FPortecle.KeyPairEntryAlias.Title", false);
        if (newHeadCertImportAlias == null) {
            return null;
        }

        // Check entry does not already exist in the keystore
        // TODO - can do better than just return here if the alias does exist. 
        if (this.caKeyStoreModel.getClientKeyStore().containsAlias(newHeadCertImportAlias)) {
            JOptionPane.showMessageDialog(
                    parentCompoent,
                    MessageFormat.format("The keystore already contains an entry with the alias " + newHeadCertImportAlias + "\n"
                            + "Please enter a unique alias", newHeadCertImportAlias),
                    RB.getString("FPortecle.RenameEntry.Title"), JOptionPane.ERROR_MESSAGE);
            return null;
        }
        try {
            this.parentCompoent.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));

            // get a list of aliases that exist in the keyStore before we import.   
            ArrayList<String> preImportAliases = Collections.list(this.caKeyStoreModel.getClientKeyStore().aliases());

            // Add a new key entry to the keystore (private key and CERT CHAIN)
            // and reStore (save the keystore to file and reload from file) 
            this.caKeyStoreModel.getClientKeyStore().setKeyEntry(newHeadCertImportAlias, privateKey, this.caKeyStoreModel.getPassword(), certChain);
            this.caKeyStoreModel.getClientKeyStore().reStore();

            // Note, the reStore above reloads the keyStore object from file. 
            // If the keyStore object is NOT reloaded from file, then 
            // enumerating all the aliases excludes any TRUSTED certs imported 
            // as part of a chain? (I would expect that importing a certChain 
            // would mean the list of trust cert aliases would also be included
            // without having to reload the keyStore object from file - but 
            // this may be a java issue?). 
            //Enumeration<String> aliases = this.caKeyStoreModel.getClientKeyStore().aliases();
            //while(aliases.hasMoreElements()){System.out.println("alias "+aliases.nextElement()); }
            // get a list of aliases that now exist after the import 
            ArrayList<String> postImportAliases = Collections.list(this.caKeyStoreModel.getClientKeyStore().aliases());

            // Create new entires only for the newly imported aliases that 
            // did not previously exist before the import. 
            for (String postImportAlias : postImportAliases) {
                if (!preImportAliases.contains(postImportAlias)) {
                    KeyStoreEntryWrapper newImport = this.caKeyStoreModel.createKSEntryWrapperInstanceFromEntry(postImportAlias);
                    this.caKeyStoreModel.getKeyStoreEntryMap().put(postImportAlias, newImport);
                }
            }

            if (SystemStatus.getInstance().getIsOnline()) {
                KeyStoreEntryWrapper kew = caKeyStoreModel.getKeyStoreEntryMap().get(newHeadCertImportAlias);
                if (caKeyStoreModel.onlineUpdateKeyStoreEntry(kew)) {
                    // we don't need to reStore (no online state is saved to keystore file)
                    //caKeyStoreModel.getClientKeyStore().reStore(); 
                }
            }

            return newHeadCertImportAlias;
        } finally {
            this.parentCompoent.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
        }
    }

    /**
     * Let the user choose a file to import from. Based on Portecle.
     *
     * @return The chosen file or null if none was chosen
     * @see FPortecle#chooseImportFile()
     */
    private File chooseImportFileHelper() {
        return FilePicker.openFile(parentCompoent, RB.getString("FPortecle.ImportKeyPairFile.Title"),
                RB.getString("FPortecle.ImportKeyPairFile.button"), FileChooserFactory.getKeyPairFilter());
    }

    /**
     * Gets a new entry alias from user, handling overwrite issues. Based on
     * Portecle.
     *
     * @param sAlias         suggested alias
     * @param dialogTitleKey message key for dialog titles
     * @param selectAlias    whether to pre-select alias text in text field
     * @return alias for new entry, null if user cancels the operation
     * @see FPortecle#getNewEntryAlias(java.security.KeyStore, java.lang.String,
     * java.lang.String, boolean)
     */
    private String getNewEntryAliasHelper(String sAlias, String dialogTitleKey,
                                          boolean selectAlias) {
        while (true) {
            // Get the alias for the new entry
            DGetAlias dGetAlias
                    = new DGetAlias(null, RB.getString(dialogTitleKey), sAlias.toLowerCase(), selectAlias);
            dGetAlias.setLocationRelativeTo(parentCompoent);
            SwingHelper.showAndWait(dGetAlias);

            sAlias = dGetAlias.getAlias();

            return sAlias;

        }
    }
}
