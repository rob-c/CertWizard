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
package uk.ngs.certwizard.gui;

import com.vdurmont.semver4j.Semver;
import net.sf.portecle.DGetAlias;
import net.sf.portecle.DViewCertificate;
import net.sf.portecle.FPortecle;
import net.sf.portecle.crypto.X509CertUtil;
import net.sf.portecle.gui.SwingHelper;
import net.sf.portecle.gui.error.DThrowable;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import uk.ngs.ca.certificate.client.CAMotd;
import uk.ngs.ca.certificate.client.PingService;
import uk.ngs.ca.certificate.management.ClientKeyStoreCaServiceWrapper;
import uk.ngs.ca.certificate.management.KeyStoreEntryWrapper;
import uk.ngs.ca.certificate.management.KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE;
import uk.ngs.ca.common.CertUtil;
import uk.ngs.ca.common.ConnectivityMonitor;
import uk.ngs.ca.common.GuiExecutor;
import uk.ngs.ca.common.OffEdt;
import uk.ngs.ca.common.SystemStatus;
import uk.ngs.ca.task.OnlineUpdateKeyStoreEntriesSwingWorker;
import uk.ngs.ca.tools.property.SysProperty;
import uk.ngs.ca.util.CertificateExportGuiHelper;
import uk.ngs.ca.util.CertificateImportGuiHelper;
import uk.ngs.ca.util.CertificateRenewRevokeGuiHelper;

import javax.security.auth.x500.X500Principal;
import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.Format;
import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * GUI for displaying the keyStore entries in the user's
 * <tt>'$HOME/.ca/cakeystore.pkcs12'</tt> file. This class also manages
 * importing, exporting, deleting requesting, renewing certificates.
 *
 * @author Xiao Wang
 * @author David Meredith (refactoring, javadoc)
 */
public class MainWindowPanel extends javax.swing.JPanel implements Observer {

    private ImageIcon[] images;
    private String stringMotD = "Message of the Day";
    private final CAMotd motd = new CAMotd();
    private char[] PASSPHRASE;
    private ClientKeyStoreCaServiceWrapper caKeyStoreModel = null;
    private final String stringMotDOffline = "You are working offline.\n\nYou will not be able to apply-for, renew or revoke "
            + "your certificates until a connection has been established. "
            + "Hit the Refresh button to try and reconnect.\n\nFor more information, see:\nhttps://ca.grid-support.ac.uk/certwizard/";
    /**
     * Portecle Resource bundle base name
     */
    private static final String RB_BASENAME = FPortecle.class.getPackage().getName() + "/resources";
    /**
     * Portecle Resource bundle
     */
    public static final ResourceBundle RB = ResourceBundle.getBundle(RB_BASENAME);
    private final ExecutorService invokeOnceBackgroundExec = Executors.newSingleThreadExecutor();
    private OnlineUpdateKeyStoreEntriesSwingWorker onlineUpdateTask = new OnlineUpdateKeyStoreEntriesSwingWorker(null, null, null);
    private final ScheduledExecutorService messageOfDayExecutor = Executors.newSingleThreadScheduledExecutor();

    /**
     * Creates new form MainWindowPanel
     *
     * @param passphrase
     */
    public MainWindowPanel(char[] passphrase) {
        super();
        this.PASSPHRASE = passphrase;
        System.setProperty(
                SysProperty.getValue("uk.ngs.ca.immegration.password.property"),
                this.PASSPHRASE.toString());

        initComponents();
        loadImages();
        this.jComboBox1.setRenderer(new ComboBoxRenderer());
        this.jComboBox1.setMaximumRowCount(20);
        try {
            // Load the model (the CA keyStore). 
            this.caKeyStoreModel = ClientKeyStoreCaServiceWrapper.getInstance(this.PASSPHRASE);
        } catch (KeyStoreException ex) {
            Logger.getLogger(MainWindowPanel.class.getName()).log(Level.SEVERE, null, ex);
            DThrowable.showAndWait(null, "KeyStoreException CA keyStore file", ex);
        } catch (IOException ex) {
            Logger.getLogger(MainWindowPanel.class.getName()).log(Level.SEVERE, null, ex);
            DThrowable.showAndWait(null, "IOException CA keyStore file", ex);
        } catch (CertificateException ex) {
            Logger.getLogger(MainWindowPanel.class.getName()).log(Level.SEVERE, null, ex);
            DThrowable.showAndWait(null, "CertificateException CA keyStore file", ex);
        }

        this.updateKeyStoreGuiFromModel();
        this.setComboFirstCertEntry();
    }

    /**
     * Do some post object construction checks. Shows modal message dialogs if
     * there are no certificates in the managed CA keystore and if a newer
     * version of the certificate wizard is available. Also start background
     * certificate status task.
     */
    public void doPostConstruct() {
        // Start the background tasks before we show any dialogs. 
        messageOfDayExecutor.scheduleWithFixedDelay(new MessageOfDayTask(), 0, 30, TimeUnit.MINUTES);
        onlineUpdateTask = new OnlineUpdateKeyStoreEntriesSwingWorker(
                caKeyStoreModel.getKeyStoreEntryMap(), caKeyStoreModel, this);
        onlineUpdateTask.addPropertyChangeListener(onlineUpdateTaskPropertyListener);
        onlineUpdateTask.execute();

        // Check if we have an empty keystore. 
        if (this.caKeyStoreModel.getKeyStoreEntryMap().isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "You have no certificates. Please either:\n"
                            + "a) Apply for a certificate with the [Apply For New Cert] button or\n"
                            + "b) Import an existing certificate from a backup file with the [Import Cert From File] button\n\n"
                            + "(Note, you can export your certificate as a backup file from your web browser)",
                    "No Certificates Found",
                    JOptionPane.INFORMATION_MESSAGE);

        }
        // Check the version in background thread (todo - need to add a menu
        //  item so that user can check for updates when the choose to). 
        this.invokeOnceBackgroundExec.execute(new VersionUpdateTask());
    }

    /**
     * Check with the server for the latest cwiz version and enqueue a dialog to
     * display in the AWT event dispatch thread if a new version exists.
     */
    private class VersionUpdateTask implements Runnable {

        private String latestVersion;

        @Override
        public void run() {
            latestVersion = motd.getLatestVersion();
            // MUST update the gui in the AWT event dispatch thread. 
            GuiExecutor.instance().execute(() -> {
                String certWizardVersion = SysProperty.getValue("ngsca.certwizard.versionNumber");
                Semver ourVersion = new Semver(certWizardVersion);
                Semver serverVersion = new Semver(latestVersion);
                if (serverVersion.isGreaterThan(ourVersion)) {
                    JOptionPane.showMessageDialog(null, "A new version of the Certificate Wizard is available!\n"
                                    + "Please go to https://ca.grid-support.ac.uk/certwizard/ in order to obtain the latest version",
                            "New Version of Certificate Wizard", JOptionPane.INFORMATION_MESSAGE);
                }
            });
        }
    }

    /**
     * Check with the server for the latest message of the day an enqueue an
     * update to the GUI on the AWT event dispatch thread.
     */
    private class MessageOfDayTask implements Runnable {

        private String motdtext;

        @Override
        public void run() {
            // Try to download motd and latest version only if online. 
            if (SystemStatus.getInstance().getIsOnline()) {
                motdtext = motd.getText();
                // MUST update the gui in the AWT event dispatch thread. 
                GuiExecutor.instance().execute(() -> {
                    if (motdtext != null) {
                        stringMotD = motdtext;
                        setMOD(motdtext);
                    }
                });
            }
        }
    }

    /**
     * Handle onlineUpdateTask property changes (runs in AWT Event thread)
     */
    private final PropertyChangeListener onlineUpdateTaskPropertyListener = new PropertyChangeListener() {

        @Override
        public void propertyChange(PropertyChangeEvent e) {
            String propertyName = e.getPropertyName();
            if ("progress".equals(propertyName)) {
                // not handled currently 
            } else if ("state".equals(propertyName)) {
                //System.out.println("state change is: "+onlineUpdateTask.getState());
                if (SwingWorker.StateValue.DONE.equals(onlineUpdateTask.getState())) {
                    updateOnlineUpdateComponents(false);
                } else if (SwingWorker.StateValue.PENDING.equals(onlineUpdateTask.getState())) {
                    updateOnlineUpdateComponents(true);
                } else updateOnlineUpdateComponents(SwingWorker.StateValue.STARTED.equals(onlineUpdateTask.getState()));
            }
        }

        private void updateOnlineUpdateComponents(boolean running) {
            if (running) {
                btnCancelOnlineUpdate.setEnabled(true);
                jProgressBar1.setEnabled(true);
                jProgressBar1.setIndeterminate(true);
                labelOnlineUpdate.setText("Updating...");
                btnRefreshAll.setEnabled(false);
                btnNewCertificateRequest.setEnabled(false);
                btnRevoke.setEnabled(false);
                btnImportCertificate.setEnabled(false);
                btnRenew.setEnabled(false);
                btnChangeAlias.setEnabled(false);
                btnInstall.setEnabled(false);
                //btnExport.setEnabled(false); // uses a snapshot copy of keystore
                btnDelete.setEnabled(false);
            } else {
                btnCancelOnlineUpdate.setEnabled(false);
                jProgressBar1.setEnabled(false);
                jProgressBar1.setIndeterminate(false);
                jProgressBar1.setValue(100);
                labelOnlineUpdate.setText("");
                btnRefreshAll.setEnabled(true);
                btnNewCertificateRequest.setEnabled(true);
                btnRevoke.setEnabled(true);
                btnImportCertificate.setEnabled(true);
                btnRenew.setEnabled(true);
                btnChangeAlias.setEnabled(true);
                btnInstall.setEnabled(true);
                //btnExport.setEnabled(true); 
                btnDelete.setEnabled(true);
            }
        }
    };

    /**
     * The keyStore GUI components are updated when invoked by an observable.
     *
     * @param observable the observable object.
     * @param obj        an argument passed to the <code>notifyObservers</code> method.
     */
    @Override
    public void update(Observable observable, Object obj) {
        /*
         * if (observable != null && observable instanceof
         * OnlineUpdateKeyStoreEntries) {}
         */
        this.updateKeyStoreGuiFromModel();
    }

    /**
     * Load the images used in the GUI
     */
    private void loadImages() {
        //Load the pet images and create an array of indexes.
        images = new ImageIcon[7];
        images[0] = createImageIcon("/uk/ngs/ca/images/certificate_node.gif");
        images[0].setDescription("Trusted certificate");

        images[1] = createImageIcon("/uk/ngs/ca/images/key_node.gif");
        images[1].setDescription("Key");

        images[2] = createImageIcon("/uk/ngs/ca/images/keypair_node.gif");
        images[2].setDescription("Key Pair (public and private keys)");

        images[3] = createImageIcon("/uk/ngs/ca/images/group_key.png");
        images[3].setDescription("User Key Pair (public and private keys)");

        images[4] = createImageIcon("/uk/ngs/ca/images/server_key.png");
        images[4].setDescription("Host Key Pair (public and private keys)");

        images[5] = createImageIcon("/uk/ngs/ca/images/key_go.png");
        images[5].setDescription("Certificate Signing Request");

        images[6] = createImageIcon("/uk/ngs/ca/images/key_delete.png");
        images[6].setDescription("Self Signed Certificate");
    }

    /**
     * Returns an ImageIcon, or null if the path was invalid.
     */
    private ImageIcon createImageIcon(String path) {
        java.net.URL imgURL = MainWindowPanel.class.getResource(path);
        if (imgURL != null) {
            return new ImageIcon(imgURL);
        } else {
            System.err.println("Couldn't find file: " + path);
            return null;
        }
    }

    /**
     * Update the GUI according to the current state of
     * <code>this.caKeyStoreModel</code>. Important, there is no reStore/reload
     * of keyStore. The update of the GUI components is guaranteed to be
     * executed in the AWT event thread.
     */
    public final void updateKeyStoreGuiFromModel() {
        GuiExecutor.instance().execute(() -> {
            reloadComboFromModel();
            updateGUIPanel();
        });
    }

    /**
     * Reload combo from      <code>this.caKeyStoreModel.getKeyStoreEntryMap()
     * <code>
     * (note, no reload of keystore !). Combo elements are rendered with CombBoxRenderer inner class.
     */
    private void reloadComboFromModel() {
        int preSelectedIndex = this.jComboBox1.getSelectedIndex();
        this.jComboBox1.removeAllItems();
        Collection<KeyStoreEntryWrapper> keyStoreEntries = this.caKeyStoreModel.getKeyStoreEntryMap().values();
        for (KeyStoreEntryWrapper keyStoreEntry : keyStoreEntries) {
            this.jComboBox1.addItem(keyStoreEntry);
        }
        if (this.jComboBox1.getItemCount() > 0) {
            // show the previously selected index. 
            if (preSelectedIndex < this.jComboBox1.getItemCount()) {
                this.jComboBox1.setSelectedIndex(preSelectedIndex);
            } else {
                this.jComboBox1.setSelectedIndex(0);
            }
        } else {
            this.jComboBox1.setSelectedItem(null);
        }
    }

    /**
     * Set the selected combo item according to the given alias.
     */
    private void setComboSelectedItemByAlias(String alias) {
        // first ensure we have all the model entries in the combo 
        this.reloadComboFromModel();
        for (int index = 0; index < this.jComboBox1.getItemCount(); index++) {
            KeyStoreEntryWrapper selectedKSEWComboBox = (KeyStoreEntryWrapper) this.jComboBox1.getItemAt(index);
            if (alias.equals(selectedKSEWComboBox.getAlias())) {
                this.jComboBox1.setSelectedIndex(index);
                break;
            }
        }
    }

    /**
     * Get the number of certificate/keY entries (e.g. exclude trust root
     * certs).
     */
    private int getComboCertEntryCount() {
        int count = 0;
        if (!this.caKeyStoreModel.getKeyStoreEntryMap().isEmpty()) {
            for (int index = 0; index < this.jComboBox1.getItemCount(); index++) {
                KeyStoreEntryWrapper selectedKSEWComboBox = (KeyStoreEntryWrapper) this.jComboBox1.getItemAt(index);
                if (KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY.equals(selectedKSEWComboBox.getEntryType())) {
                    ++count;
                }
            }
        }
        return count;
    }

    /**
     * Set to the first visible cert/key entry (rather than showing e.g. trust
     * root cert).
     */
    private void setComboFirstCertEntry() {
        if (!this.caKeyStoreModel.getKeyStoreEntryMap().isEmpty()) {
            for (int index = 0; index < this.jComboBox1.getItemCount(); index++) {
                KeyStoreEntryWrapper selectedKSEWComboBox = (KeyStoreEntryWrapper) this.jComboBox1.getItemAt(index);
                if (KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY.equals(selectedKSEWComboBox.getEntryType())) {
                    this.jComboBox1.setSelectedIndex(index);
                    break;
                }
            }
        }
    }

    /**
     * Update other GUI components based on selected combo item (note, no reload
     * of keystore !).
     */
    private void updateGUIPanel() {
        // nullify/clear the gui components first
        this.textFieldSerialNumber.setText("");
        //this.textFieldSerialNumber.setEnabled(false); 
        this.vFromTo.setText("");
        //this.vTo.setText("");
        this.subjectDnTextField.setText("");
        this.issuerDnTextField.setText("");
        this.rDue.setText("");
        this.dRemaining.setText("");
        this.caCertStatusTextField.setText("Unknown (offline or certificate not recognized by UK CA)");
        // set to default color first
        this.caCertStatusTextField.setForeground(this.getColorFromState(null, null));
        this.certEmailTextField.setText("");
        this.aliasTextField.setText("");
        this.certificateTypeLabel.setText("");
        this.certificateTypeLabel.setIconTextGap(10);
        this.certificateTypeLabel.setIcon(null);

        this.pnlAllDetails.setBorder(new TitledBorder("Selected Certificate Details"));

        // now udpate 
        KeyStoreEntryWrapper selectedKeyStoreEntry = (KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem();
        // could be null if we have an empty keystore !
        if (this.jComboBox1.getSelectedIndex() != -1 && selectedKeyStoreEntry != null) {
            String alias = selectedKeyStoreEntry.getAlias();
            this.subjectDnTextField.setText(selectedKeyStoreEntry.getX500PrincipalName());
            this.issuerDnTextField.setText(selectedKeyStoreEntry.getIssuerName());
            this.aliasTextField.setText(alias);

            if (KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_ENTRY.equals(selectedKeyStoreEntry.getEntryType())) {
                this.certificateTypeLabel.setText("Key");
                this.certificateTypeLabel.setIcon(this.images[1]);
                this.pnlAllDetails.setBorder(new TitledBorder("Selected Key Details"));

            } else if (KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY.equals(selectedKeyStoreEntry.getEntryType())) {
                try {
                    X509Certificate x509Cert = this.caKeyStoreModel.getClientKeyStore().getX509Certificate(alias);
                    if (x509Cert != null) {
                        String serialNumber = x509Cert.getSerialNumber().toString();
                        if (!"123456789".equals(serialNumber)) {
                            this.textFieldSerialNumber.setText(serialNumber);
                        }
                        //this.labelSerialNumber.setEnabled(true);
                    }
                } catch (Exception ignore) {
                    DThrowable.showAndWait(null, "Problem", ignore);
                }
                if (selectedKeyStoreEntry.isCSR()) {
                    this.certificateTypeLabel.setText("Cert Signing Request");
                    this.certificateTypeLabel.setIcon(images[5]);
                    this.pnlAllDetails.setBorder(new TitledBorder("Selected Certificate Signing Request Details"));
                } else if (selectedKeyStoreEntry.getIssuerName().equals(selectedKeyStoreEntry.getX500PrincipalName())) {
                    this.certificateTypeLabel.setText("Self Signed Certificate");
                    this.certificateTypeLabel.setIcon(images[6]);
                } else if (selectedKeyStoreEntry.getX500PrincipalName().equals(selectedKeyStoreEntry.getIssuerName())) {
                    this.certificateTypeLabel.setText("Self Signed Cert");
                    this.certificateTypeLabel.setIcon(images[5]);
                } else if (selectedKeyStoreEntry.getX500PrincipalName().contains(".")) {
                    this.certificateTypeLabel.setText("Host Cert + Private Key");
                    this.certificateTypeLabel.setIcon(images[4]);
                } else {
                    this.certificateTypeLabel.setText("User Cert + Private Key");
                    this.certificateTypeLabel.setIcon(images[3]);
                }
            } else if (KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.TRUST_CERT_ENTRY.equals(selectedKeyStoreEntry.getEntryType())) {
                this.certificateTypeLabel.setText("Trusted Third Party Certificate");
                this.certificateTypeLabel.setIcon(this.images[0]);
            }

            Format formatter;
            // Display only - never parsed, stored or sent, so British rendering
            // is deliberate even though it writes "Sept" where the certificate
            // itself says "Sep". Do not "correct" this to Locale.US. Pinned
            // rather than left to the default so the panel reads the same on a
            // machine configured for, say, th-TH (Buddhist calendar) or ar-SA.
            formatter = new SimpleDateFormat("EEE MMM dd HH:mm yyyy", Locale.UK);
            if (selectedKeyStoreEntry.getNotBefore() != null) {
                this.vFromTo.setText(formatter.format(selectedKeyStoreEntry.getNotBefore())
                        + " / "
                        + formatter.format(selectedKeyStoreEntry.getNotAfter()));
            } else {
                this.vFromTo.setText("N/A");
            }

            // First, get the date info from the keystore entry 
            Date certNotAfter = selectedKeyStoreEntry.getNotAfter();
            Calendar todaysDate = Calendar.getInstance();

            // If the CertificateCSRInfo member object of the selected
            // keyStoreEntryWrapper is null, then we did not retrieve
            // the CA server info for this cert (maybe offline or an unrecognized
            // certificate not issued by our CA).
            if (selectedKeyStoreEntry.getServerCertificateCSRInfo() != null) {
                String state = selectedKeyStoreEntry.getServerCertificateCSRInfo().getStatus();
                this.caCertStatusTextField.setText(state + " " + this.getExtraLabelTextFromState(state));
                this.caCertStatusTextField.setForeground(this.getColorFromState(state, certNotAfter));
                this.certEmailTextField.setText(selectedKeyStoreEntry.getServerCertificateCSRInfo().getUserEmail());
            }

            //Remaining time / tolerance time modifications 
            if (certNotAfter.after(todaysDate.getTime())) {
                // Not expired 
                // endDate is after today (hence we have time left) 
                long diffDays = (certNotAfter.getTime() - todaysDate.getTimeInMillis()) / (24 * 60 * 60 * 1000);
                this.dRemaining.setText(String.valueOf(diffDays));
            } else {
                // Expired  
                // test to see if we expired within 30 days ago 
                Calendar dateThirtyDaysAgo = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
                dateThirtyDaysAgo.add(Calendar.DAY_OF_MONTH, -30);
                if (certNotAfter.after(dateThirtyDaysAgo.getTime())) {
                    // we are within 30 day rewew tolerance ! 
                    this.dRemaining.setText("0");
                    this.caCertStatusTextField.setText("Expired but you can still renew (within 30 day tolerance period)");
                } else {
                    this.dRemaining.setText("0");
                    // this is required because the CA server returned state will be 
                    // valid even if the state is Expired (i.e. it is up to the 
                    // client to check the time remaining and set set state accordingly). 
                    this.caCertStatusTextField.setText("Expired" + " " + this.getExtraLabelTextFromState("Expired"));
                }
            }

            //Renewal Due
            Calendar renewalDue = Calendar.getInstance();
            renewalDue.setTime(certNotAfter);
            renewalDue.add(Calendar.MONTH, -1);
            this.rDue.setText(formatter.format(renewalDue.getTime()));
            if (todaysDate.after(renewalDue)) {
                this.rDue.setForeground(new RenewalDueColor());
            } else {
                this.rDue.setForeground(Color.black);
            }

        }
        //((TitledBorder)this.jPanel2.getBorder()).setTitle("Your Certificates and Requests ("+this.jComboBox1.getItemCount()+" entries)");
    }

    /**
     * Renderer class for KeyStoreEntryWrapper objects for the combo box.
     */
    class ComboBoxRenderer extends JLabel implements ListCellRenderer {

        public ComboBoxRenderer() {
            setOpaque(true);
        }

        @Override
        public Component getListCellRendererComponent(JList list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
            //Get the selected index. (The index param isn't always valid, so just use the value.)
            //int selectedIndex = ((Integer)value).intValue();

            if (isSelected) {
                setBackground(list.getSelectionBackground());
                setForeground(list.getSelectionForeground());
            } else {
                setBackground(list.getBackground());
                setForeground(list.getForeground());
            }

            // Can assume that we are dealing with KeyStoreEntryWrapper objects.
            KeyStoreEntryWrapper keyStoreEntry = (KeyStoreEntryWrapper) value;
            // can be null if the keyStore is empty ! 
            if (keyStoreEntry != null) {
                String x500PrincipalName = keyStoreEntry.getX500PrincipalName();
                String cn = CertUtil.extractDnAttribute(x500PrincipalName, CertUtil.DNAttributeType.CN);
                String displayText = "[" + keyStoreEntry.getAlias() + "]   [" + cn + "]";
                this.setText(displayText);

                // want to display the modified date too
                //keyStoreEntry.getCreationDate();
                // Display an approprate icon dependng on keystore entry type
                // server_key.png, group_key.png, key_go.png (CSR)
                if (KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_ENTRY.equals(keyStoreEntry.getEntryType())) {
                    this.setIcon(images[1]);
                } else if (KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.TRUST_CERT_ENTRY.equals(keyStoreEntry.getEntryType())) {
                    this.setIcon(images[0]);
                } else if (KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY.equals(keyStoreEntry.getEntryType())) {
                    //this.setIcon(images[2]);                
                    if (keyStoreEntry.isCSR()) {
                        this.setIcon(images[5]); // CSR 
                    } else if (keyStoreEntry.getX500PrincipalName().equals(keyStoreEntry.getIssuerName())) {
                        this.setIcon(images[6]); // Self signed cert 
                    } else if (keyStoreEntry.getX500PrincipalName().contains(".")) {
                        this.setIcon(images[4]); // Host cert (not self signed) 
                    } else {
                        this.setIcon(images[3]); // User cert (not self signed)  
                    }
                } else {
                    // could set an unknown default
                }

                // Set the server status colour (if known). This info will only
                // be fetched if the info could be retrieved from the CA server.
                if (keyStoreEntry.getServerCertificateCSRInfo() != null) {
                    String state = keyStoreEntry.getServerCertificateCSRInfo().getStatus();
                    this.setForeground(getColorFromState(state, keyStoreEntry.getNotAfter()));
                } else {
                    this.setForeground(Color.DARK_GRAY);
                }
            } else {
                this.setText("No Key Store Entries");
                this.setIcon(null);
            }
            return this;
        }
    }

    /**
     * Return the appropriate display colour according to the given state
     * string. If state is null or not recognised, then return
     * <code>Color.DARK_GRAY</code> as default. If State is equal to 'VALID' and
     * the endDate is not null, then test to see if the end date is before
     * today, if true, we are actually expired. This is required because the CA
     * server returns the 'VALID' state even if the certificate's end date is in
     * the past (i.e. it is valid in that it is recognised by our CA server, but
     * it has actually expired).
     *
     * @param state   Optional end date / not after date of keystore entry
     *                (nullable).
     * @param endDate
     * @return The colour that is appropriate to given state
     */
    private Color getColorFromState(String state, Date endDate) {
        if ("VALID".equals(state)) {
            if (endDate != null) {
                Calendar todaysDate = Calendar.getInstance();
                if (endDate.before(todaysDate.getTime())) {
                    // End date is BEFORE today, hence we are Expired. 
                    // TODO: If end date is more than 30 days before today, set to 
                    // ExpiredForeverCertColor, otherwise there may be a chance to 
                    // renew within next 30 day threshold. 
                    return new ExpiredCertColor();
                }
            }
            return new ValidCertColor();

        } else if ("REVOKED".equals(state)) {
            return new RevokedCertColor();
        } else if ("NEW".equals(state)) {
            // Your certificate request has been submitted and is waiting for approval.
            return new PendingColor();
        } else if ("SUSPENDED".equals(state)) {
            return new SuspendCertColor();
        } else if ("RENEW".equals(state)) {
            // Your renewal certificate request has been submitted and is waiting for approval.
            return new RenewalDueColor();
        } else if ("APPROVED".equals(state)) {
            // Your certificate has been approved by your RA and is waiting for CA signing.
            return new SuspendCertColor();
        } else if ("ARCHIVED".equals(state)) {
            return new ValidCertColor();
        } else if ("DELETED".equals(state)) {
            return new RevokedCertColor();
        } else if ("Expired".equals(state)) {
            return new ExpiredCertColor();
        } else {
            return Color.DARK_GRAY;
        }
    }

    /**
     * Return any extra label text that is appropriate to the given state.
     */
    private String getExtraLabelTextFromState(String state) {
        if ("VALID".equals(state)) {
            return "";
        } else if ("REVOKED".equals(state)) {
            return "";
        } else if ("NEW".equals(state)) {
            return "(Your certificate request is waiting for approval)";
        } else if ("SUSPENDED".equals(state)) {
            return "(Your certificate revocation request is waiting to be processed)";
        } else if ("RENEW".equals(state)) {
            return "(Your renewal certificate is waiting for approval)";
        } else if ("APPROVED".equals(state)) {
            return "(Your certificate is now waiting for CA signing)";
        } else if ("ARCHIVED".equals(state)) {
            return "";
        } else if ("DELETED".equals(state)) {
            return "";
        } else if ("Expired".equals(state)) {
            return "";
        } else {
            return "";
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    // The next 4 methods (renew, revoke, import, applyForNew) all require  
    // contacting the CA service online
    ///////////////////////////////////////////////////////////////////////////

    /**
     * Called by the Renew button.
     */
    private void doRenewAction() {
        if (this.confirmBackgroundTaskRunning()) {
            return;
        }

        if (this.jComboBox1.getSelectedIndex() == -1) {
            JOptionPane.showMessageDialog(this, "Please select a certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        if (!isOnlinePing()) {
            return;
        }

        try {
            // Can only renew key_pairs types issued by our CA
            KeyStoreEntryWrapper selectedKSEW = (KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem();
            CertificateRenewRevokeGuiHelper renewUtil = new CertificateRenewRevokeGuiHelper(this, this.caKeyStoreModel);
            String newCsrRenewalAlias = renewUtil.doRenew(selectedKSEW);
            if (newCsrRenewalAlias != null) {
                // reload the combo entries before we select the selected entry
                this.reloadComboFromModel();
                this.setComboSelectedItemByAlias(newCsrRenewalAlias);
                KeyStoreEntryWrapper kew = (KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem();
                if (OffEdt.call(this, "Updating the certificate status from the CA server...",
                        () -> caKeyStoreModel.onlineUpdateKeyStoreEntry(kew))) {
                    // we don't need to reStore (no online state is saved to keystore file)
                }
            }
        } catch (Exception ex) {
            DThrowable.showAndWait(null, "Problem Applying for Certificate", ex);
        }
        this.updateKeyStoreGuiFromModel();
    }

    /**
     * Called by the Revoke button.
     */
    private void doRevokeAction() {
        if (this.confirmBackgroundTaskRunning()) {
            return;
        }
        if (this.jComboBox1.getSelectedIndex() == -1) {
            JOptionPane.showMessageDialog(this, "Please select a certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        if (!isOnlinePing()) {
            return;
        }
        try {
            // Can only revoke key_pairs types issued by our CA
            KeyStoreEntryWrapper selectedKSEW = (KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem();
            CertificateRenewRevokeGuiHelper util = new CertificateRenewRevokeGuiHelper(this, this.caKeyStoreModel);
            util.doRevoke(selectedKSEW);
        } catch (Exception ex) {
            DThrowable.showAndWait(null, "Problem Revoking Certificate", ex);
        }
        this.updateKeyStoreGuiFromModel();
    }

    /**
     * Let the user import a key pair a PKCS #12 keystore or a PEM bundle. Based
     * on Portecle.
     *
     * @see FPortecle#importKeyPair()
     */
    private void doImportCertificateAction() {
        // prevent import when background thread is refreshing. 
        if (this.confirmBackgroundTaskRunning()) {
            return;
        }
        try {
            CertificateImportGuiHelper util = new CertificateImportGuiHelper(this, this.caKeyStoreModel);
            String newHeadCertImportAlias = util.doImportCertificateAction();
            if (newHeadCertImportAlias != null) {
                this.setComboSelectedItemByAlias(newHeadCertImportAlias);
            }
        } catch (Exception ex) {
            DThrowable.showAndWait(null, "Problem Importing Certificate", ex);
        }
        this.updateKeyStoreGuiFromModel();
    }

    /**
     * Called by the Apply button.
     */
    private void doApplyForNewCertificateAction() {
        if (this.confirmBackgroundTaskRunning()) {
            return;
        }

        KeyStoreEntryWrapper selectedEntry = null;
        boolean userRequest = true;
        boolean ask = true;

        // Apply for Host or User cert. 
        // First check an item has been selected 
        if (this.jComboBox1.getSelectedIndex() != -1 && this.jComboBox1.getSelectedItem() != null) {
            selectedEntry = (KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem();

            // Second check that the item is a VALID user cert 
            if (selectedEntry.getServerCertificateCSRInfo() != null
                    && "VALID".equals(selectedEntry.getServerCertificateCSRInfo().getStatus())
                    && !selectedEntry.getX500PrincipalName().contains(".")) {
                // A VALID User cert is selected; show a dialog to ask if they 
                // want to apply for a user or host cert (inform that the selected user 
                // user cert will be used to authenticate the request if applying for host cert). 

                Object[] options = {"User", "Host", "Cancel"};
                int n = JOptionPane.showOptionDialog(this,
                        "Do you want to apply for a new User or Host certificate?\n\n"
                                + "If you select Host, your currently selected User "
                                + "certificate will authenticate your application: \n"
                                + "[" + selectedEntry.getAlias() + "]" + "  [" + selectedEntry.getX500PrincipalName() + "]",
                        "Request New User or Host Certificate",
                        JOptionPane.YES_NO_CANCEL_OPTION,
                        JOptionPane.QUESTION_MESSAGE,
                        null,
                        options,
                        options[0]);
                if (JOptionPane.YES_OPTION == n) {
                    userRequest = true;
                    ask = false;
                } else if (JOptionPane.NO_OPTION == n) {
                    userRequest = false;
                    ask = false;
                } else {
                    return;
                }
            }
        }

        if (userRequest && ask) {
            // Either this is the first user cert application or a VALID user 
            // cert is NOT selected; therefore show a dialog to confirm 
            // that they are applying for a new User cert, and if they want to 
            // apply for a host cert, then go back and select which user cert to 
            // authenticate with. 
            String message;
            if (this.jComboBox1.getItemCount() > 0) {
                message = "<html>You are about to apply for a new <font color=red>User</font> certificate<br/><br/>"
                        + "If you wish to apply for a HOST certificate, cancel and<br/>"
                        + "select a <font color=green>[VALID]</font> User certificate from your pull down list.</html>";
            } else {
                message = "<html>You are about to apply for a new <font color=red>User</font> certificate<br/><br/>"
                        + "If you wish to apply for a HOST certificate, you must first Import<br/>"
                        + "or Apply for a valid UK e-Science User certificate.</html>";
            }
            Object[] options = {"Continue", "Cancel"};
            int n = JOptionPane.showOptionDialog(this, message,
                    "Confirm User certificate application",
                    JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.INFORMATION_MESSAGE,
                    null,
                    options,
                    options[0]);

            if (JOptionPane.OK_OPTION == n) {
                userRequest = true;
            } else {
                return;
            }
        }
        //boolean userRequest = true; // remove and uncomment above when ready to deploy host cert support.    
        try {
            if (isOnlinePing()) {
                Apply apply;
                if (userRequest) {
                    apply = new Apply(this.caKeyStoreModel, Apply.CERT_TYPE.USER_CERT, null);
                } else {
                    apply = new Apply(this.caKeyStoreModel, Apply.CERT_TYPE.HOST_CERT, selectedEntry.getAlias());
                }

                apply.setModal(true);
                apply.setVisible(true);

                // if a new CSR entry was added to the keystore, set as selected
                if (apply.getStoredAlias() != null) {

                    // reload the combo entries before we select the selected entry
                    this.reloadComboFromModel();
                    this.setComboSelectedItemByAlias(apply.getStoredAlias());

                    KeyStoreEntryWrapper kew = (KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem();
                    if (OffEdt.call(this, "Updating the certificate status from the CA server...",
                            () -> caKeyStoreModel.onlineUpdateKeyStoreEntry(kew))) {
                        // we don't need to reStore (no online state is saved to keystore file)
                        //caKeyStoreModel.getClientKeyStore().reStore(); 
                    }

                }
                this.updateKeyStoreGuiFromModel();
            }
        } catch (Exception ex) {
            DThrowable.showAndWait(null, "Problem Applying for Certificate", ex);
        }
    }

    public boolean confirmBackgroundTaskRunning() {
        if (this.onlineUpdateTask != null && !this.onlineUpdateTask.isDone()) {
            //if(this.onlineUpdateTaskRunning.get()){
            JOptionPane.showMessageDialog(this,
                    "Cannot run task while executing background online update task. "
                            + "\nCancel the task or wait for its completion.",
                    "Executing background task", JOptionPane.WARNING_MESSAGE);
            return true;
        } else {
            return false;
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    // The next 6 methods (changeKeyStorePW, delete, viewDetails, export, install, change alias)
    // are generic keystore actions that do not require the CA service.
    ///////////////////////////////////////////////////////////////////////////

    /**
     * Change the keyStore password.
     */
    private void doChangePasswdAction() {
        KeyStorePropertiesJDialog dialog = new KeyStorePropertiesJDialog(null, true, this, caKeyStoreModel);
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);
        if (dialog.getPassphase() != null) {
            this.PASSPHRASE = dialog.getPassphase();
        }
    }

    /**
     * Delete selected keyStore entry (not revocation).
     */
    private void doDeleteAction() {
        if (this.confirmBackgroundTaskRunning()) {
            return;
        }
        if (this.jComboBox1.getSelectedIndex() == -1) {
            JOptionPane.showMessageDialog(this, "Please select a certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
        } else {
            int delete = JOptionPane.showConfirmDialog(this, "Are you sure you want to delete this KeyStore entry ?", "Delete KeyStore Entry", JOptionPane.OK_CANCEL_OPTION);
            if (delete == JOptionPane.OK_OPTION) {
                try {
                    // delete calls reStore 
                    this.caKeyStoreModel.deleteEntry(((KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem()).getAlias());
                    this.caKeyStoreModel.getClientKeyStore().reStore();
                    this.updateKeyStoreGuiFromModel();
                } catch (Exception ex) {
                    //JOptionPane.showMessageDialog(this, "Unable to delete KeyStore entry: " + ex.getMessage(), "Unable to delete KeyStore entry", JOptionPane.ERROR_MESSAGE);
                    DThrowable.showAndWait(null, "Problem deleting KeyStore entry", ex);
                }
            }
        }
    }

    /**
     * Let the user see the certificate details of the selected keystore entry.
     * Based on Portecle.
     *
     * @see FPortecle#showSelectedEntry()
     */
    private void doViewCertificateDetailsAction() {
        // check that a certificate is selected
        if (this.jComboBox1.getSelectedIndex() == -1) {
            JOptionPane.showMessageDialog(this, "Please select a certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        KeyStoreEntryWrapper selectedKSEW = (KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem();
        KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE selectedType = selectedKSEW.getEntryType();
        if (selectedType == null || selectedType.equals(KEYSTORE_ENTRY_TYPE.KEY_ENTRY)) {
            JOptionPane.showMessageDialog(this, "Please select a certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String sAlias = selectedKSEW.getAlias();

        try {
            // Get snapshot of the keystore (prevents interferance from background update thread)
            KeyStore keyStoreCopy = this.caKeyStoreModel.getClientKeyStore().getKeyStoreCopy();
            // Get the entry's certificates
            X509Certificate[] certs;
            if (this.caKeyStoreModel.getClientKeyStore().isKeyEntry(sAlias)) {
                // If entry is a key pair
                certs = X509CertUtil.convertCertificates(keyStoreCopy.getCertificateChain(sAlias));
            } else {
                // If entry is a trusted certificate
                certs = new X509Certificate[1];
                certs[0] = X509CertUtil.convertCertificate(keyStoreCopy.getCertificate(sAlias));
            }

            // Supply the certificates to the view certificate dialog
            DViewCertificate dViewCertificate
                    = new DViewCertificate(null, MessageFormat.format(
                    RB.getString("FPortecle.CertDetailsEntry.Title"), sAlias), certs);
            dViewCertificate.setLocationRelativeTo(this);
            SwingHelper.showAndWait(dViewCertificate);

        } catch (Exception ex) {
            DThrowable.showAndWait(null, "Problem Viewing Certificate", ex);
        }
    }

    /**
     * Let the user export the selected entry. Based on Portecle.
     *
     * @return True if the export is successful, false otherwise
     * @see FPortecle#exportSelectedEntry()
     */
    private boolean doExportAction() {
        // check that a certificate is selected
        if (this.jComboBox1.getSelectedIndex() == -1) {
            JOptionPane.showMessageDialog(this, "Please select a certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
            return false;
        }
        KeyStoreEntryWrapper selectedKSEW = (KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem();
        KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE selectedType = selectedKSEW.getEntryType();
        if (selectedType == null || selectedType.equals(KEYSTORE_ENTRY_TYPE.KEY_ENTRY)) {
            JOptionPane.showMessageDialog(this, "Please select a certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
            return false;
        }
        // Provide a warning if user is trying to export a self signed cert (e.g CSR) 
        try {
            X509Certificate cert = this.caKeyStoreModel.getClientKeyStore().getX509Certificate(selectedKSEW.getAlias());
            if (cert != null) {
                X500Principal subject = cert.getSubjectX500Principal();
                X500Principal issuer = cert.getIssuerX500Principal();
                if (subject.equals(issuer)) {
                    String selfSignedMessageType = "This is a self signed certificate.";
                    if (selectedKSEW.isCSR()) {
                        selfSignedMessageType = "This is a self signed certificate signing request (CSR)";
                    }
                    String message = selfSignedMessageType + "\nAre you sure you want to export?";
                    int n = JOptionPane.showConfirmDialog(this, message,
                            "Confirm Export", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
                    if (JOptionPane.YES_OPTION != n) {
                        return false;
                    }
                }
            }
        } catch (KeyStoreException ex) {
            DThrowable.showAndWait(null, "Problem Testing for Self Signed Cert when Exporting", ex);
            return false;
        }

        // Get the entry
        String sAlias = selectedKSEW.getAlias();
        try {
            CertificateExportGuiHelper certExportUtil = new CertificateExportGuiHelper(this, this.caKeyStoreModel);
            return certExportUtil.doExportAction(sAlias);
        } catch (Exception ex) {
            DThrowable.showAndWait(null, "Problem Exporting Certificate", ex);
        }
        return false;
    }

    /**
     * Install the selected cert as '$HOME/.globus/usercert.pem' and
     * '$HOME/.globus/userkey.pem' for subsequent globus usage. TODO - move
     * logic into new class to reduce size of this class
     */
    private void doInstallPemsSelectedCertificateAction() {
        // check that a certificate is selected
        if (this.jComboBox1.getSelectedIndex() == -1) {
            JOptionPane.showMessageDialog(this, "Please select a certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        KeyStoreEntryWrapper selectedKSEW = (KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem();
        KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE selectedType = selectedKSEW.getEntryType();
        if (selectedType == null || !selectedType.equals(KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY)) {
            JOptionPane.showMessageDialog(this, "Please select a certificate and key pair!", "No certificate key pair selected", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        FileOutputStream certfos = null;

        try {
            // work with a snapshot of the keystore at this point in time. 
            KeyStore keyStoreCopy = this.caKeyStoreModel.getClientKeyStore().getKeyStoreCopy();
            // prevent install of self signed certs (CSRs)
            X509Certificate testValidCertificateToExport = (X509Certificate) keyStoreCopy.getCertificate(selectedKSEW.getAlias());
            if (testValidCertificateToExport.getIssuerDN().toString().equals(testValidCertificateToExport.getSubjectDN().toString())) {
                JOptionPane.showMessageDialog(this, "You cannot install a certificate request.\n"
                        + "If you have requested a new or a renewal request, please wait until the\n"
                        + "certificate has been approved and signed by e-Science CA before\n"
                        + "installing it.", "Cannot install certificate", JOptionPane.ERROR_MESSAGE);
                return;
            }

            // check online status before installing 
            if (selectedKSEW.getServerCertificateCSRInfo() == null) {
                int ret = JOptionPane.showConfirmDialog(this, "You are either offline or this certificate cannot be validated by our CA\n"
                        + "Are you sure you want to install this certificate ?");
                if (ret != JOptionPane.YES_OPTION) {
                    return;
                }
            } else {
                if (!"VALID".equals(selectedKSEW.getServerCertificateCSRInfo().getStatus())) {
                    int ret = JOptionPane.showConfirmDialog(this, "According to our CA this certificate is not VALID\n"
                            + "Are you sure you want to install this certificate ?");
                    if (ret != JOptionPane.YES_OPTION) {
                        return;
                    }
                }
            }

            // ok, install the selected cert
            String certPemFile = System.getProperty("user.home") + File.separator + ".globus" + File.separator + "usercert.pem";
            String keyPemFile = System.getProperty("user.home") + File.separator + ".globus" + File.separator + "userkey.pem";
            File fCertFile = new File(certPemFile);
            File fKeyFile = new File(keyPemFile);
            // check usercert.pem and userkey.pem do not already exist.
            String overwriteWarning = "";
            boolean oneExists = false;
            if (fKeyFile.isFile()) {
                oneExists = true;
                overwriteWarning += "Local Key file already exists: \n     [" + keyPemFile + "]\n\n";
            }
            if (fCertFile.isFile()) {
                oneExists = true;
                overwriteWarning += "Local Certificate file already exists: \n    [" + certPemFile + "]\n";
            }
            if (oneExists) {
                overwriteWarning += "\nAre you sure you want to overwrite these files ?";
                int ret = JOptionPane.showConfirmDialog(this, overwriteWarning, "Certificate/Key Installation", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
                if (JOptionPane.YES_OPTION != ret) {
                    return;
                }
            }
            // ok, here we can export the cert and key as pem files.

            // first, delete files (if they already exist) 
            fCertFile.delete();
            fKeyFile.delete();
            // get X509Cert and Private key of selected alias 
            String alias = selectedKSEW.getAlias();
            X509Certificate certificate = (X509Certificate) keyStoreCopy.getCertificate(alias);
            PrivateKey privateKey = (PrivateKey) keyStoreCopy.getKey(alias, PASSPHRASE);
            // Write the certificate 
            JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(fCertFile));
            pemWriter.writeObject(certificate);
            pemWriter.close();

            fCertFile.setReadable(true, true);
            fCertFile.setExecutable(false, false);
            fCertFile.setWritable(false, false);

            JcaPEMWriter pw = new JcaPEMWriter(new FileWriter(fKeyFile));
            SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
            PEMEncryptor encryptor = new JcePEMEncryptorBuilder("DES-EDE3-CBC").setSecureRandom(rand).build(PASSPHRASE);
            pw.writeObject(privateKey, encryptor);
            pw.close();

            fKeyFile.setReadable(true, false);
            fKeyFile.setExecutable(false, false);
            fKeyFile.setWritable(false, false);

            JOptionPane.showMessageDialog(this, "[usercert.pem] and [userkey.pem] installed OK to '$USER_HOME/.globus/'",
                    "Install usercert.pem userkey.pem", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            DThrowable.showAndWait(null, null, ex);
        }
    }

    /**
     * Let the user change the alias for the selected keypair or trusted
     * certificate entry. Based on Portecle.
     *
     * @see FPortecle#renameSelectedEntry()
     */
    private void doChangeAliasAction() {
        if (this.confirmBackgroundTaskRunning()) {
            return;
        }
        if (this.jComboBox1.getSelectedIndex() == -1) {
            JOptionPane.showMessageDialog(this, "Please select a certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        KeyStoreEntryWrapper selectedKSEW = (KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem();
        KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE selectedType = selectedKSEW.getEntryType();
        if (selectedType == null || selectedType.equals(KEYSTORE_ENTRY_TYPE.KEY_ENTRY)) {
            JOptionPane.showMessageDialog(this, "Please select a certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        // Get the entry
        String sAliasOld = selectedKSEW.getAlias();
        //KeyStore keyStore = this.keyStoreCaWrapper.getClientKeyStore().getKeyStoreCopy();

        try {
            //retrieve the new alias from the user
            String sAliasNew = getNewEntryAliasHelper(sAliasOld, "FPortecle.KeyPairEntryAlias.Title", false);
            if (sAliasNew == null) {
                return;
            }
            if (sAliasNew.trim().equals(sAliasOld)) {
                return;
            }
            if (sAliasNew.trim().equals("")) {
                JOptionPane.showMessageDialog(this, "You cannot have empty alias name. Please enter a unique friendly name",
                        "No Alias Entered", JOptionPane.ERROR_MESSAGE);
                return;
            }

            // Check entry does not already exist in the keystore
            if (this.caKeyStoreModel.getClientKeyStore().containsAlias(sAliasNew)) {
                JOptionPane.showMessageDialog(
                        this,
                        MessageFormat.format("The keystore already contains an entry with the alias " + sAliasNew + "\n"
                                + "Please enter a unique alias", sAliasNew),
                        RB.getString("FPortecle.RenameEntry.Title"), JOptionPane.ERROR_MESSAGE);
                return;
            }
            //WaitDialog.showDialog("General");

            // Create the new entry with the new name and copy the old entry across
            // If the entry is a key pair...
            if (this.caKeyStoreModel.getClientKeyStore().isKeyEntry(sAliasOld)) {
                // Do the copy
                Key key = this.caKeyStoreModel.getClientKeyStore().getKey(sAliasOld, this.PASSPHRASE);
                Certificate[] certs = this.caKeyStoreModel.getClientKeyStore().getCertificateChain(sAliasOld);
                this.caKeyStoreModel.getClientKeyStore().setKeyEntry(sAliasNew, key, this.PASSPHRASE, certs);

            } else {
                // ...if the entry is a trusted certificate
                // Do the copy
                Certificate cert = this.caKeyStoreModel.getClientKeyStore().getCertificate(sAliasOld);
                this.caKeyStoreModel.getClientKeyStore().setCertificateEntry(sAliasNew, cert);
            }

            // Delete the old entry
            this.caKeyStoreModel.getClientKeyStore().deleteEntry(sAliasOld);

            // Update the frame's components and title
            KeyStoreEntryWrapper changedKSEW = this.caKeyStoreModel.getKeyStoreEntryMap().get(sAliasOld);
            changedKSEW.setAlias(sAliasNew);
            this.caKeyStoreModel.getKeyStoreEntryMap().remove(sAliasOld);
            this.caKeyStoreModel.getKeyStoreEntryMap().put(sAliasNew, changedKSEW);
            this.caKeyStoreModel.getClientKeyStore().reStore();
            this.updateKeyStoreGuiFromModel();
            //WaitDialog.hideDialog();

        } catch (Exception ex) {
            DThrowable.showAndWait(null, "Problem Chaning Alias", ex);
        } finally {
            WaitDialog.hideDialog();
        }
    }

    /**
     * Start a background task to online update the keyStore entries and update
     * GUI.
     *
     * @param all if true updates all entries, otherwise will only attempt to
     *            update the currently selected entry.
     */
    private void doRefreshActionAsBackgroundTask(boolean all) {
        if (this.confirmBackgroundTaskRunning()) {
            return;
        }

        if (this.jComboBox1.getSelectedIndex() == -1) {
            //JOptionPane.showMessageDialog(this, "There are no certificates in the keystore", "No certificate in the keystore!", JOptionPane.WARNING_MESSAGE);
        } else {
            Map<String, KeyStoreEntryWrapper> updateEntries;
            if (all) {
                updateEntries = this.caKeyStoreModel.getKeyStoreEntryMap();
            } else {
                KeyStoreEntryWrapper selectedKSEW = (KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem();
                updateEntries = new HashMap<>(1);
                updateEntries.put(selectedKSEW.getAlias(), selectedKSEW);
            }
            this.onlineUpdateTask = new OnlineUpdateKeyStoreEntriesSwingWorker(
                    updateEntries, caKeyStoreModel, this);
            this.onlineUpdateTask.addPropertyChangeListener(onlineUpdateTaskPropertyListener);
            this.onlineUpdateTask.execute();
            this.btnRefreshAll.setEnabled(false);
        }
    }

    /**
     * Cancel the background online update task (if running)
     */
    private void doCancelOnlineUpdateAction() {
        if (this.onlineUpdateTask != null) {
            this.onlineUpdateTask.cancel(true);
        }
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
            dGetAlias.setLocationRelativeTo(this);
            SwingHelper.showAndWait(dGetAlias);

            sAlias = dGetAlias.getAlias();
            return sAlias;
        }
    }

    /**
     * Re-check the connection to the CA server now (off the EDT, behind a
     * wait dialog) before a user-initiated online action, and explain the
     * problem if it cannot be reached.
     */
    private boolean isOnlinePing() {
        boolean online = OffEdt.call(this, "Checking the connection to the CA server...",
                () -> PingService.getPingService().isPingService());
        if (!online) {
            String detail = ConnectivityMonitor.getInstance().getStatus().getLastError();
            JOptionPane.showMessageDialog(this, "Cannot connect to the CA Server. Please ensure that you are connected to the Internet.\n"
                    + "If you are connected to the Internet but still unable to connect to the CA Server, please check your firewall\n"
                    + "settings and ensure you allow Java to access to the Internet. If problem still persists, please contact\n"
                    + "the helpdesk at support@grid-support.ac.uk."
                    + (detail == null ? "" : "\n\nDetails: " + detail), "Server Connection Fault", JOptionPane.ERROR_MESSAGE);
            setRedMOD(stringMotDOffline);
        }
        return online;
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel1 = new javax.swing.JPanel();
        btnNewCertificateRequest = new javax.swing.JButton();
        btnImportCertificate = new javax.swing.JButton();
        pnlAllDetails = new javax.swing.JPanel();
        subjectDnTextField = new javax.swing.JTextField();
        jLabel1 = new javax.swing.JLabel();
        jLabel8 = new javax.swing.JLabel();
        issuerDnTextField = new javax.swing.JTextField();
        caCertStatusTextField = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        aliasTextField = new javax.swing.JTextField();
        jLabel9 = new javax.swing.JLabel();
        jLabel10 = new javax.swing.JLabel();
        certificateTypeLabel = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        vFromTo = new javax.swing.JTextField();
        jLabel5 = new javax.swing.JLabel();
        dRemaining = new javax.swing.JTextField();
        jLabel6 = new javax.swing.JLabel();
        rDue = new javax.swing.JTextField();
        btnRenew = new javax.swing.JButton();
        btnRevoke = new javax.swing.JButton();
        btnChangeAlias = new javax.swing.JButton();
        btnInstall = new javax.swing.JButton();
        btnExport = new javax.swing.JButton();
        btnDelete = new javax.swing.JButton();
        viewCertDetailsButton = new javax.swing.JButton();
        jLabel12 = new javax.swing.JLabel();
        jLabel7 = new javax.swing.JLabel();
        textFieldSerialNumber = new javax.swing.JTextField();
        certEmailTextField = new javax.swing.JTextField();
        jLabel11 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        TextMOD = new javax.swing.JTextArea();
        jPanel2 = new javax.swing.JPanel();
        btnChangePasswd = new javax.swing.JButton();
        jComboBox1 = new javax.swing.JComboBox();
        btnRefreshAll = new javax.swing.JButton();
        btnCancelOnlineUpdate = new javax.swing.JButton();
        labelOnlineUpdate = new javax.swing.JLabel();
        jProgressBar1 = new javax.swing.JProgressBar();

        setMinimumSize(new java.awt.Dimension(0, 0));

        jPanel1.setBorder(javax.swing.BorderFactory.createTitledBorder("Add Certificate to Keystore"));

        btnNewCertificateRequest.setText("Apply For Cert");
        btnNewCertificateRequest.setToolTipText("Apply for a new certificate from the UK eScience CA. The certificate will be added to your keystore. ");
        btnNewCertificateRequest.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                btnNewCertificateRequestMouseEntered(evt);
            }

            public void mouseExited(java.awt.event.MouseEvent evt) {
                btnNewCertificateRequestMouseExited(evt);
            }
        });
        btnNewCertificateRequest.addActionListener(this::btnNewCertificateRequestActionPerformed);

        btnImportCertificate.setText("Import Cert");
        btnImportCertificate.setToolTipText("Import an existing certificate from a .p12/.pfx file (this file is normally exported from a web browser). ");
        btnImportCertificate.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                btnImportCertificateMouseEntered(evt);
            }

            public void mouseExited(java.awt.event.MouseEvent evt) {
                btnImportCertificateMouseExited(evt);
            }
        });
        btnImportCertificate.addActionListener(this::btnImportCertificateActionPerformed);

        org.jdesktop.layout.GroupLayout jPanel1Layout = new org.jdesktop.layout.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
                jPanel1Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                        .add(jPanel1Layout.createSequentialGroup()
                                .addContainerGap()
                                .add(jPanel1Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                                        .add(btnImportCertificate, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                                        .add(btnNewCertificateRequest, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
                jPanel1Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                        .add(jPanel1Layout.createSequentialGroup()
                                .addContainerGap()
                                .add(btnNewCertificateRequest)
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(btnImportCertificate)
                                .addContainerGap(13, Short.MAX_VALUE))
        );

        jPanel1Layout.linkSize(new java.awt.Component[]{btnImportCertificate, btnNewCertificateRequest}, org.jdesktop.layout.GroupLayout.VERTICAL);

        pnlAllDetails.setBorder(javax.swing.BorderFactory.createTitledBorder("Selected Certificate Details"));

        subjectDnTextField.setEditable(false);
        subjectDnTextField.setAutoscrolls(true);
        subjectDnTextField.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));
        subjectDnTextField.setMaximumSize(new java.awt.Dimension(2, 18));

        jLabel1.setText("Subject DN:");

        jLabel8.setText("Issuer DN:");

        issuerDnTextField.setEditable(false);
        issuerDnTextField.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));

        caCertStatusTextField.setEditable(false);
        caCertStatusTextField.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
        caCertStatusTextField.setText("Unknown");
        caCertStatusTextField.setToolTipText("Status of selected certificate with the UK eScience CA");
        caCertStatusTextField.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));

        jLabel2.setText("Status:");
        jLabel2.setToolTipText("Status of selected certificate with the UK eScience CA");

        aliasTextField.setEditable(false);
        aliasTextField.setToolTipText("An Alias is a simple display name for your certificate, e.g. 'myGridCert1'");
        aliasTextField.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));

        jLabel9.setText("Alias:");
        jLabel9.setToolTipText("An Alias is a simple display name for your certificate, e.g. 'myGridCert1'");

        jLabel10.setText("Type:");

        certificateTypeLabel.setText("CertificateType");

        jLabel3.setText("Valid From/To:");

        vFromTo.setEditable(false);
        vFromTo.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));

        jLabel5.setText("Days Left:");

        dRemaining.setEditable(false);
        dRemaining.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));

        jLabel6.setText("Renew From:");

        rDue.setEditable(false);
        rDue.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));

        btnRenew.setIcon(new javax.swing.ImageIcon(getClass().getResource("/icon_renew.GIF"))); // NOI18N
        btnRenew.setText("Renew");
        btnRenew.setToolTipText("Renew the selected certificate");
        btnRenew.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                btnRenewMouseEntered(evt);
            }

            public void mouseExited(java.awt.event.MouseEvent evt) {
                btnRenewMouseExited(evt);
            }
        });
        btnRenew.addActionListener(this::btnRenewActionPerformed);

        btnRevoke.setIcon(new javax.swing.ImageIcon(getClass().getResource("/revoke.png"))); // NOI18N
        btnRevoke.setText("Revoke");
        btnRevoke.setToolTipText("Revoke the selected certificate");
        btnRevoke.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                btnRevokeMouseEntered(evt);
            }

            public void mouseExited(java.awt.event.MouseEvent evt) {
                btnRevokeMouseExited(evt);
            }
        });
        btnRevoke.addActionListener(this::btnRevokeActionPerformed);

        btnChangeAlias.setIcon(new javax.swing.ImageIcon(getClass().getResource("/edit_icon.gif"))); // NOI18N
        btnChangeAlias.setText("Change Alias");
        btnChangeAlias.setToolTipText("Change the Alias of the selected certificate (a user friendly name)");
        btnChangeAlias.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                btnChangeAliasMouseEntered(evt);
            }

            public void mouseExited(java.awt.event.MouseEvent evt) {
                btnChangeAliasMouseExited(evt);
            }
        });
        btnChangeAlias.addActionListener(this::btnChangeAliasActionPerformed);

        btnInstall.setIcon(new javax.swing.ImageIcon(getClass().getResource("/install.PNG"))); // NOI18N
        btnInstall.setText("Install");
        btnInstall.setToolTipText("Install the selected certifcate so grid applications can use it.");
        btnInstall.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                btnInstallMouseEntered(evt);
            }

            public void mouseExited(java.awt.event.MouseEvent evt) {
                btnInstallMouseExited(evt);
            }
        });
        btnInstall.addActionListener(this::btnInstallActionPerformed);

        btnExport.setIcon(new javax.swing.ImageIcon(getClass().getResource("/icon_exportBib.gif"))); // NOI18N
        btnExport.setText("Export");
        btnExport.setToolTipText("Export the selected certificate as a backup file.");
        btnExport.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                btnExportMouseEntered(evt);
            }

            public void mouseExited(java.awt.event.MouseEvent evt) {
                btnExportMouseExited(evt);
            }
        });
        btnExport.addActionListener(this::btnExportActionPerformed);

        btnDelete.setIcon(new javax.swing.ImageIcon(getClass().getResource("/delete_icon.png"))); // NOI18N
        btnDelete.setText("Delete");
        btnDelete.setToolTipText("Delete the selected certificate from you keystore.");
        btnDelete.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                btnDeleteMouseEntered(evt);
            }

            public void mouseExited(java.awt.event.MouseEvent evt) {
                btnDeleteMouseExited(evt);
            }
        });
        btnDelete.addActionListener(this::btnDeleteActionPerformed);

        viewCertDetailsButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/view_icon.gif"))); // NOI18N
        viewCertDetailsButton.setToolTipText("View the selected certificate details");
        viewCertDetailsButton.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                viewCertDetailsButtonMouseEntered(evt);
            }

            public void mouseExited(java.awt.event.MouseEvent evt) {
                viewCertDetailsButtonMouseExited(evt);
            }
        });
        viewCertDetailsButton.addActionListener(this::viewCertDetailsButtonActionPerformed);

        jLabel12.setText("Actions:");

        jLabel7.setText("Serial:");

        textFieldSerialNumber.setEditable(false);
        textFieldSerialNumber.setToolTipText("");

        certEmailTextField.setEditable(false);
        certEmailTextField.setToolTipText("The email associated with your certificate and known to the CA. ");

        jLabel11.setText("Email:");
        jLabel11.setToolTipText("The email associated with your certificate and known to the CA. ");

        org.jdesktop.layout.GroupLayout pnlAllDetailsLayout = new org.jdesktop.layout.GroupLayout(pnlAllDetails);
        pnlAllDetails.setLayout(pnlAllDetailsLayout);
        pnlAllDetailsLayout.setHorizontalGroup(
                pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                        .add(pnlAllDetailsLayout.createSequentialGroup()
                                .addContainerGap()
                                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                                        .add(pnlAllDetailsLayout.createSequentialGroup()
                                                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                                                        .add(jLabel8)
                                                        .add(jLabel2)
                                                        .add(jLabel1)
                                                        .add(jLabel9)
                                                        .add(jLabel10)
                                                        .add(jLabel3)
                                                        .add(jLabel11))
                                                .add(29, 29, 29)
                                                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                                                        .add(pnlAllDetailsLayout.createSequentialGroup()
                                                                .add(vFromTo)
                                                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                                                .add(jLabel6)
                                                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                                                .add(rDue, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 144, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                                                        .add(org.jdesktop.layout.GroupLayout.TRAILING, caCertStatusTextField)
                                                        .add(subjectDnTextField, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                        .add(issuerDnTextField)
                                                        .add(org.jdesktop.layout.GroupLayout.TRAILING, pnlAllDetailsLayout.createSequentialGroup()
                                                                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                                                                        .add(pnlAllDetailsLayout.createSequentialGroup()
                                                                                .add(certificateTypeLabel, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                                                .add(45, 45, 45))
                                                                        .add(pnlAllDetailsLayout.createSequentialGroup()
                                                                                .add(certEmailTextField)
                                                                                .add(18, 18, 18)))
                                                                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                                                                        .add(jLabel5)
                                                                        .add(jLabel7))
                                                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                                                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING, false)
                                                                        .add(pnlAllDetailsLayout.createSequentialGroup()
                                                                                .add(textFieldSerialNumber, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 100, Short.MAX_VALUE)
                                                                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.UNRELATED)
                                                                                .add(viewCertDetailsButton, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 32, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                                                                .add(2, 2, 2))
                                                                        .add(dRemaining)))
                                                        .add(aliasTextField)))
                                        .add(pnlAllDetailsLayout.createSequentialGroup()
                                                .add(jLabel12)
                                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED, 96, Short.MAX_VALUE)
                                                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                                                        .add(pnlAllDetailsLayout.createSequentialGroup()
                                                                .add(btnInstall, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 106, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                                                .add(btnExport, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 106, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                                                .add(btnDelete, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 106, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                                                        .add(pnlAllDetailsLayout.createSequentialGroup()
                                                                .add(btnRenew, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 106, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                                                .add(btnRevoke, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 104, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                                                .add(btnChangeAlias, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 131, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))))))
        );

        pnlAllDetailsLayout.linkSize(new java.awt.Component[]{btnChangeAlias, btnDelete, btnExport, btnInstall, btnRenew, btnRevoke}, org.jdesktop.layout.GroupLayout.HORIZONTAL);

        pnlAllDetailsLayout.setVerticalGroup(
                pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                        .add(pnlAllDetailsLayout.createSequentialGroup()
                                .addContainerGap(22, Short.MAX_VALUE)
                                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                                        .add(subjectDnTextField, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 22, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                        .add(jLabel1))
                                .add(6, 6, 6)
                                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                                        .add(issuerDnTextField, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 22, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                        .add(jLabel8))
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                                        .add(caCertStatusTextField, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 22, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                        .add(jLabel2))
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.TRAILING)
                                        .add(jLabel9)
                                        .add(aliasTextField, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 22, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                                        .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                                                .add(jLabel10)
                                                .add(certificateTypeLabel)
                                                .add(textFieldSerialNumber, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                                .add(jLabel7))
                                        .add(org.jdesktop.layout.GroupLayout.TRAILING, viewCertDetailsButton))
                                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                                        .add(pnlAllDetailsLayout.createSequentialGroup()
                                                .add(5, 5, 5)
                                                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                                                        .add(dRemaining, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                                        .add(jLabel5)))
                                        .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                                                .add(certEmailTextField, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                                .add(jLabel11)))
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                                        .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                                                .add(jLabel6)
                                                .add(rDue, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                                        .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                                                .add(jLabel3)
                                                .add(vFromTo, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 23, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)))
                                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                                        .add(pnlAllDetailsLayout.createSequentialGroup()
                                                .add(39, 39, 39)
                                                .add(jLabel12)
                                                .add(61, 61, 61))
                                        .add(org.jdesktop.layout.GroupLayout.TRAILING, pnlAllDetailsLayout.createSequentialGroup()
                                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                                                        .add(btnRenew, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 26, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                                        .add(btnRevoke, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 27, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                                        .add(btnChangeAlias, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 27, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                                                        .add(btnInstall, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 27, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                                        .add(btnExport, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 26, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                                        .add(btnDelete, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 26, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                                                .add(28, 28, 28))))
        );

        pnlAllDetailsLayout.linkSize(new java.awt.Component[]{issuerDnTextField, subjectDnTextField}, org.jdesktop.layout.GroupLayout.VERTICAL);

        pnlAllDetailsLayout.linkSize(new java.awt.Component[]{dRemaining, rDue, textFieldSerialNumber, vFromTo}, org.jdesktop.layout.GroupLayout.VERTICAL);

        pnlAllDetailsLayout.linkSize(new java.awt.Component[]{btnDelete, btnExport, btnInstall, btnRenew, btnRevoke}, org.jdesktop.layout.GroupLayout.VERTICAL);

        pnlAllDetailsLayout.linkSize(new java.awt.Component[]{btnChangeAlias, viewCertDetailsButton}, org.jdesktop.layout.GroupLayout.VERTICAL);

        pnlAllDetailsLayout.linkSize(new java.awt.Component[]{aliasTextField, certEmailTextField}, org.jdesktop.layout.GroupLayout.VERTICAL);

        TextMOD.setColumns(20);
        TextMOD.setWrapStyleWord(true);
        TextMOD.setLineWrap(true);
        TextMOD.setRows(5);
        jScrollPane1.setViewportView(TextMOD);

        jPanel2.setBorder(javax.swing.BorderFactory.createTitledBorder("Certificates in my Keystore"));

        btnChangePasswd.setIcon(new javax.swing.ImageIcon(getClass().getResource("/view_icon.gif"))); // NOI18N
        btnChangePasswd.setToolTipText("View details of your password protected keystore file.");
        btnChangePasswd.setActionCommand("Change KeyStore Password");
        btnChangePasswd.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                btnChangePasswdMouseEntered(evt);
            }

            public void mouseExited(java.awt.event.MouseEvent evt) {
                btnChangePasswdMouseExited(evt);
            }
        });
        btnChangePasswd.addActionListener(this::btnChangePasswdActionPerformed);

        jComboBox1.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                jComboBox1MouseEntered(evt);
            }

            public void mouseExited(java.awt.event.MouseEvent evt) {
                jComboBox1MouseExited(evt);
            }
        });
        jComboBox1.addItemListener(this::jComboBox1ItemStateChanged);
        jComboBox1.addActionListener(this::jComboBox1ActionPerformed);

        btnRefreshAll.setIcon(new javax.swing.ImageIcon(getClass().getResource("/ajax-refresh-icon.gif"))); // NOI18N
        btnRefreshAll.setToolTipText("Refresh all/selected keystore certificates");
        btnRefreshAll.setEnabled(false);
        btnRefreshAll.addActionListener(this::btnRefreshAllActionPerformed);

        org.jdesktop.layout.GroupLayout jPanel2Layout = new org.jdesktop.layout.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
                jPanel2Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                        .add(jPanel2Layout.createSequentialGroup()
                                .addContainerGap()
                                .add(btnChangePasswd, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 33, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.UNRELATED)
                                .add(jComboBox1, 0, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(btnRefreshAll, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 37, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
        );
        jPanel2Layout.setVerticalGroup(
                jPanel2Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                        .add(org.jdesktop.layout.GroupLayout.TRAILING, jPanel2Layout.createSequentialGroup()
                                .addContainerGap()
                                .add(jPanel2Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                                        .add(btnRefreshAll)
                                        .add(jPanel2Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                                                .add(jComboBox1, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 28, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                                .add(btnChangePasswd)))
                                .addContainerGap(org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        btnCancelOnlineUpdate.setIcon(new javax.swing.ImageIcon(getClass().getResource("/stopRedCrossIcon.gif"))); // NOI18N
        btnCancelOnlineUpdate.setToolTipText("Cancel online update with CA");
        btnCancelOnlineUpdate.setBorderPainted(false);
        btnCancelOnlineUpdate.setEnabled(false);
        btnCancelOnlineUpdate.addActionListener(this::btnCancelOnlineUpdateActionPerformed);

        labelOnlineUpdate.setText("...");
        labelOnlineUpdate.setToolTipText("");

        jProgressBar1.setToolTipText("Online certificate update task");

        org.jdesktop.layout.GroupLayout layout = new org.jdesktop.layout.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
                layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                        .add(layout.createSequentialGroup()
                                .addContainerGap()
                                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                                        .add(layout.createSequentialGroup()
                                                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING, false)
                                                        .add(jScrollPane1, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                                                        .add(jPanel1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.UNRELATED)
                                                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                                                        .add(pnlAllDetails, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                        .add(layout.createSequentialGroup()
                                                                .add(0, 0, Short.MAX_VALUE)
                                                                .add(labelOnlineUpdate, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 111, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                                                .add(jProgressBar1, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 56, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.UNRELATED)
                                                                .add(btnCancelOnlineUpdate, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 19, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))))
                                        .add(jPanel2, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                .add(13, 13, 13))
        );
        layout.setVerticalGroup(
                layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                        .add(layout.createSequentialGroup()
                                .add(12, 12, 12)
                                .add(jPanel2, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                                        .add(layout.createSequentialGroup()
                                                .add(jPanel1, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                                .add(jScrollPane1))
                                        .add(layout.createSequentialGroup()
                                                .add(pnlAllDetails, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING, false)
                                                        .add(org.jdesktop.layout.GroupLayout.TRAILING, jProgressBar1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                        .add(org.jdesktop.layout.GroupLayout.TRAILING, labelOnlineUpdate, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 14, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                                        .add(org.jdesktop.layout.GroupLayout.TRAILING, btnCancelOnlineUpdate, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 14, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                                                .add(0, 8, Short.MAX_VALUE)))
                                .add(8, 8, 8))
        );

        layout.linkSize(new java.awt.Component[]{btnCancelOnlineUpdate, jProgressBar1}, org.jdesktop.layout.GroupLayout.VERTICAL);

    }// </editor-fold>//GEN-END:initComponents

    private void jComboBox1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jComboBox1ActionPerformed
        this.updateGUIPanel();
    }//GEN-LAST:event_jComboBox1ActionPerformed

    private void btnNewCertificateRequestActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnNewCertificateRequestActionPerformed
        this.doApplyForNewCertificateAction();
    }//GEN-LAST:event_btnNewCertificateRequestActionPerformed

    private void btnImportCertificateActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnImportCertificateActionPerformed
        this.doImportCertificateAction();
    }//GEN-LAST:event_btnImportCertificateActionPerformed

    private void btnExportActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnExportActionPerformed
        this.doExportAction();
    }//GEN-LAST:event_btnExportActionPerformed

    private void btnRenewActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRenewActionPerformed
        this.doRenewAction();
    }//GEN-LAST:event_btnRenewActionPerformed

    private void btnRevokeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRevokeActionPerformed
        this.doRevokeAction();
    }//GEN-LAST:event_btnRevokeActionPerformed

    private void btnDeleteActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnDeleteActionPerformed
        this.doDeleteAction();
    }//GEN-LAST:event_btnDeleteActionPerformed

    private void btnNewCertificateRequestMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnNewCertificateRequestMouseEntered
        setMOD("Request a new user or host certificate"); // todo - replace with Request a new user or host certificate. 
    }//GEN-LAST:event_btnNewCertificateRequestMouseEntered

    private void btnNewCertificateRequestMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnNewCertificateRequestMouseExited
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnNewCertificateRequestMouseExited

    private void btnImportCertificateMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnImportCertificateMouseEntered
        setMOD("Import an existing certificate file into the certificate wizard.");
    }//GEN-LAST:event_btnImportCertificateMouseEntered

    private void jComboBox1MouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jComboBox1MouseEntered
        setMOD("Your current certificates and certificate requests.");
    }//GEN-LAST:event_jComboBox1MouseEntered

    private void btnRenewMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnRenewMouseEntered
        setMOD("Renew the selected certificate 30 days before it expires (the certificate must be valid).");
    }//GEN-LAST:event_btnRenewMouseEntered

    private void btnExportMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnExportMouseEntered
        setMOD("Export the selected certificate to a file for back up, or for use in other tools."
                + "You will be prompted to create a password to protect your exported certificate");
    }//GEN-LAST:event_btnExportMouseEntered

    private void btnRevokeMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnRevokeMouseEntered
        setMOD("Revoke your certificate if it is compromised or invalid.");
    }//GEN-LAST:event_btnRevokeMouseEntered

    private void btnDeleteMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnDeleteMouseEntered
        setMOD("Remove your certificate from the tool. "
                + "This will not delete any other copies of the certificate from your computer.");
    }//GEN-LAST:event_btnDeleteMouseEntered

    private void btnInstallActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnInstallActionPerformed
        this.doInstallPemsSelectedCertificateAction();
    }//GEN-LAST:event_btnInstallActionPerformed

    private void btnInstallMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnInstallMouseEntered
        setMOD("Install the selected certificate to local PEM files: \n\n"
                + "'$HOME/.globus/usercert.pem' \n"
                + "'$HOME/.globus/usercert.pem' ");
    }//GEN-LAST:event_btnInstallMouseEntered

    private void btnInstallMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnInstallMouseExited
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnInstallMouseExited

    private void btnImportCertificateMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnImportCertificateMouseExited
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnImportCertificateMouseExited

    private void mouseExitedActionPerformed(java.awt.event.MouseEvent evt) {
        if (SystemStatus.getInstance().getIsOnline()) {
            setMOD(stringMotD);
        } else {
            setRedMOD(stringMotDOffline);
        }
    }

    private void jComboBox1MouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jComboBox1MouseExited
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_jComboBox1MouseExited

    private void btnRenewMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnRenewMouseExited
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnRenewMouseExited

    private void btnExportMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnExportMouseExited
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnExportMouseExited

    private void btnRevokeMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnRevokeMouseExited
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnRevokeMouseExited

    private void btnDeleteMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnDeleteMouseExited
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnDeleteMouseExited

    private void jComboBox1ItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_jComboBox1ItemStateChanged
        // TODO add your handling code here:
    }//GEN-LAST:event_jComboBox1ItemStateChanged

    private void viewCertDetailsButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_viewCertDetailsButtonActionPerformed
        this.doViewCertificateDetailsAction();
    }//GEN-LAST:event_viewCertDetailsButtonActionPerformed

    private void btnChangeAliasActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnChangeAliasActionPerformed
        this.doChangeAliasAction();
    }//GEN-LAST:event_btnChangeAliasActionPerformed

    private void btnChangePasswdActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnChangePasswdActionPerformed
        this.doChangePasswdAction();
    }//GEN-LAST:event_btnChangePasswdActionPerformed

    private void btnChangePasswdMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnChangePasswdMouseEntered
        setMOD("View your keyStore file details and change the password used to protect this keyStore");
    }//GEN-LAST:event_btnChangePasswdMouseEntered

    private void btnChangePasswdMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnChangePasswdMouseExited
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnChangePasswdMouseExited

    private void btnChangeAliasMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnChangeAliasMouseExited
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnChangeAliasMouseExited

    private void viewCertDetailsButtonMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_viewCertDetailsButtonMouseExited
        this.mouseExitedActionPerformed(evt);

    }//GEN-LAST:event_viewCertDetailsButtonMouseExited

    private void btnChangeAliasMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnChangeAliasMouseEntered
        setMOD("Give the selected certificate a unique user friendly name (Alias)");
    }//GEN-LAST:event_btnChangeAliasMouseEntered

    private void viewCertDetailsButtonMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_viewCertDetailsButtonMouseEntered
        setMOD("View further details of the selected certificate. If you have imported and selected a certificate chain, "
                + "you will be able to view details of the individual certificates contained in the certificate chain.");
    }//GEN-LAST:event_viewCertDetailsButtonMouseEntered

    private void btnRefreshAllActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRefreshAllActionPerformed
        int keyPairCount = getComboCertEntryCount();
        if (keyPairCount > 0) {
            if (keyPairCount == 1) {
                doRefreshActionAsBackgroundTask(true); // boolean all 
            } else {
                //Custom button text
                Object[] options = {"All", "Selected Only", "Cancel"};
                int n = JOptionPane.showOptionDialog(this,
                        "Refresh all certificates or selected certificate only ",
                        "Refresh certificate status with UK CA",
                        JOptionPane.YES_NO_OPTION,
                        JOptionPane.QUESTION_MESSAGE,
                        null,
                        options,
                        options[1]);
                if (JOptionPane.YES_OPTION == n) {
                    // All 
                    doRefreshActionAsBackgroundTask(true); // all == true
                } else if (JOptionPane.NO_OPTION == n) {
                    // Selected Only 
                    doRefreshActionAsBackgroundTask(false); // all == false
                } else {
                    // Cancel (do nothing)  
                }
            }
        }
    }//GEN-LAST:event_btnRefreshAllActionPerformed

    private void btnCancelOnlineUpdateActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCancelOnlineUpdateActionPerformed
        doCancelOnlineUpdateAction();
    }//GEN-LAST:event_btnCancelOnlineUpdateActionPerformed

    private void setRedMOD(String text) {
        TextMOD.setForeground(Color.RED);
        TextMOD.setText(text);
    }

    private void setMOD(String text) {
        TextMOD.setForeground(Color.BLACK);
        TextMOD.setText(text);
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextArea TextMOD;
    private javax.swing.JTextField aliasTextField;
    private javax.swing.JButton btnCancelOnlineUpdate;
    private javax.swing.JButton btnChangeAlias;
    private javax.swing.JButton btnChangePasswd;
    private javax.swing.JButton btnDelete;
    private javax.swing.JButton btnExport;
    private javax.swing.JButton btnImportCertificate;
    private javax.swing.JButton btnInstall;
    private javax.swing.JButton btnNewCertificateRequest;
    private javax.swing.JButton btnRefreshAll;
    private javax.swing.JButton btnRenew;
    private javax.swing.JButton btnRevoke;
    private javax.swing.JTextField caCertStatusTextField;
    private javax.swing.JTextField certEmailTextField;
    private javax.swing.JLabel certificateTypeLabel;
    private javax.swing.JTextField dRemaining;
    private javax.swing.JTextField issuerDnTextField;
    private javax.swing.JComboBox jComboBox1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel11;
    private javax.swing.JLabel jLabel12;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JProgressBar jProgressBar1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JLabel labelOnlineUpdate;
    private javax.swing.JPanel pnlAllDetails;
    private javax.swing.JTextField rDue;
    private javax.swing.JTextField subjectDnTextField;
    private javax.swing.JTextField textFieldSerialNumber;
    private javax.swing.JTextField vFromTo;
    private javax.swing.JButton viewCertDetailsButton;
    // End of variables declaration//GEN-END:variables
}
