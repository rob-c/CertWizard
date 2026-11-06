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

import net.sf.portecle.gui.error.DThrowable;
import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.EmailValidator;
import uk.ngs.ca.certificate.CertificateRequestCreator;
import uk.ngs.ca.certificate.OnlineHostCertRequest;
import uk.ngs.ca.certificate.OnlineUserCertRequest;
import uk.ngs.ca.certificate.client.PingService;
import uk.ngs.ca.certificate.management.ClientKeyStoreCaServiceWrapper;
import uk.ngs.ca.certificate.management.KeyStoreEntryWrapper;
import uk.ngs.ca.common.CAKeyPair;
import uk.ngs.ca.common.HashUtil;
import uk.ngs.ca.common.OffEdt;
import uk.ngs.ca.common.Pair;
import uk.ngs.ca.info.CAInfo;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.regex.Pattern;

/**
 * Modal dialog for requesting new host and user certificates.
 *
 * @author Xiao Wang
 * @author David Meredith (modifications, javadoc)
 */
public class Apply extends javax.swing.JDialog {

    private final String startInfo = "Please enter all the information";
    private final String readyInfo = "Your input is ready, please click Apply button to request certificate or click Cancel button to cancel";
    private final String[] RAs;
    //private final Pattern emailPattern = Pattern.compile("[-\\.a-zA-Z0-9_]+@[-a-zA-Z0-9\\.]+\\.[a-z]+");
    private String storedAlias;
    private final X509Certificate authCert;
    private final PrivateKey authKey;
    private final ClientKeyStoreCaServiceWrapper model;
    private final Pattern userCN_Pattern = Pattern.compile("[-()a-zA-Z0-9\\s]+");
    private final javax.swing.ImageIcon errorIcon = new javax.swing.ImageIcon(getClass().getResource("/help_panel_html/images/error.png"));
    private final javax.swing.ImageIcon acceptIcon = new javax.swing.ImageIcon(getClass().getResource("/help_panel_html/images/accept.png"));

    //private ProgressMonitor progressMonitor;

    /**
     * Options for the type of certificate application.
     */
    public enum CERT_TYPE {

        HOST_CERT, USER_CERT
    }

    private CERT_TYPE certType = CERT_TYPE.USER_CERT;

    /**
     * Create a new Apply dialog.
     *
     * @param model                        CertWizard data model
     * @param certType                     Apply for either host or user cert
     * @param keyStoreAliasToAuthHostApply If a host cert is requested, this is
     *                                     the alias of the keyStore entry that will be used to authenticate the
     *                                     request. Can be null for user cert requests. When requesting host cert,
     *                                     if this value does not reference a valid user certificate in the
     *                                     keyStore, then a {@link IllegalArgumentException} is thrown.
     * @throws IOException If an error occurs when contact the remote server.
     */
    public Apply(ClientKeyStoreCaServiceWrapper model, CERT_TYPE certType, String keyStoreAliasToAuthHostApply)
            throws IOException, KeyStoreException {
        this.certType = certType;
        this.model = model;
        initComponents();

        if (CERT_TYPE.HOST_CERT.equals(this.certType)) {
            if (keyStoreAliasToAuthHostApply == null || keyStoreAliasToAuthHostApply.trim().equals("")) {
                throw new IllegalArgumentException("Invaild keyStore alias");
            }
            this.authCert = model.getClientKeyStore().getX509Certificate(keyStoreAliasToAuthHostApply);
            if (this.authCert == null) {
                throw new IllegalArgumentException("Invaild keyStore alias - given alias does not refer to X509Certificate");
            }
            this.authKey = model.getClientKeyStore().getPrivateKey(authCert.getPublicKey());

        } else {
            this.authCert = null;
            this.authKey = null;
        }

        CAInfo caInfo = OffEdt.call(null, "Fetching the list of RAs from the CA server...", CAInfo::new);
        RAs = caInfo.getRAs(); // concat of: "OU+" "+L"   
        javax.swing.DefaultComboBoxModel m = new javax.swing.DefaultComboBoxModel(RAs);
        cmbSelectRA.setModel(m);
        cmbSelectRA.insertItemAt("Select your RA...", 0);
        cmbSelectRA.setSelectedIndex(0);

        URL iconURL = getClass().getResource("/ngs-icon.png");
        if (iconURL != null) {
            this.setIconImage(Toolkit.getDefaultToolkit().getImage(iconURL));
        }
        this.getRootPane().setDefaultButton(btnApply);
        jLabel5.setText(startInfo);
        jLabel6.setVisible(false); //hide 10 chars min label 

        if (CERT_TYPE.HOST_CERT.equals(this.certType)) {
            this.labEmail.setText("Host Admin Email");
            this.labCN.setText("Host (DNS) name");
            this.setTitle("Host Certificate Application");
            this.txtDN.setText(authCert.getSubjectX500Principal().getName());
        } else {
            this.labEmail.setText("User Email");
            this.labCN.setText("Common Name");
            this.setTitle("User Certificate Application");
            this.txtDN.setText("N/A");
        }
    }

    /**
     * Apply button pressed.
     */
    private void doApplyButton() {
        if (!this.isInputReadyUpdateGUI()) {
            return;
        }

        // Some extra checks that we don't want to do every time a key is pressed. 
        boolean complete = true;
        String text = "";

        // Check alias is already present
        try {
            if (model.getClientKeyStore().containsAlias(this.aliasTextField.getText())) {
                complete = false;
                text = text + "\nAlias already exits - please enter another alias";
            }
        } catch (KeyStoreException ex) {
            DThrowable.showAndWait(this, "Problem checking if alias already exists", ex);
            return;
        }

        if (!complete) {
            jLabel5.setForeground(Color.RED);
            jLabel5.setText(text);

        } else {
            if (!OffEdt.call(this, "Checking the connection to the CA server...",
                    () -> PingService.getPingService().isPingService())) {
                JOptionPane.showMessageDialog(this, "Cannot connect to the CA Server. Please ensure that you are connected to the Internet.\n"
                        + "If you are connected to the Internet but still unable to connect to the CA Server, please check your firewall\n"
                        + "settings and ensure you allow Java to access to the Internet. If problem still persists, please contact\n"
                        + "the helpdesk at support@grid-support.ac.uk.", "Server Connection Fault", JOptionPane.ERROR_MESSAGE);
                return;
            }

            setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
            try {
                if (CERT_TYPE.USER_CERT.equals(this.certType)) {
                    this.processCertApplication(model, CertificateRequestCreator.TYPE.USER);
                } else {
                    this.processCertApplication(model, CertificateRequestCreator.TYPE.HOST);
                }

            } catch (Exception ex) {
                setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
                DThrowable.showAndWait(this, "Problem Processing CSR Application", ex);
            } finally {
                setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
            }
        }
    }

    /**
     * Process a User or a Host CSR application.
     */
    private void processCertApplication(ClientKeyStoreCaServiceWrapper model,
                                        CertificateRequestCreator.TYPE type) throws KeyStoreException, IOException, CertificateException {
        String newAlias = this.aliasTextField.getText();
        // Note that same email is value is used to create PKCS#10 request and 
        // specify in the CSR email XML element. This is required otherwise the 
        // server will complain that emails don't match. 
        String email = this.txtEmail.getText();
        String cn = this.txtName.getText().toLowerCase();
        cn = cn.replaceAll("\\s", " ");  // replace all interleaved whitespace with single whitespace
        cn = cn.trim(); // replace leading and trailing whitespace 
        char[] pin = this.txtPin.getPassword();
        String RA = ((String) this.cmbSelectRA.getSelectedItem());
        String[] ou_l = RA.trim().split("[,\\s]+");
        String ou = ou_l[0];
        String l = ou_l[1];
        String c = uk.ngs.ca.tools.property.SysProperty.getValue("ngsca.cert.c").trim();
        String o = uk.ngs.ca.tools.property.SysProperty.getValue("ngsca.cert.o").trim();
        // validation. 

        String attrDN = ("CN=" + cn + ", L=" + l + ", OU=" + ou + ", O=" + o + ", C=" + c);

        // Create a new key pair for new cert 
        KeyPair csrKeyPair = CAKeyPair.getNewKeyPair();

        // Create a PKCS#10 CSR string from keys and DN info  
        // TODO - need to allow for CNs with the service/hostname format, e.g: 'host/davehost1.dl.ac.uk'
        //CertificateRequestCreator csrCreator = new CertificateRequestCreator(type, CN, OU, L, email, false);
        CertificateRequestCreator csrCreator = new CertificateRequestCreator(attrDN, email);
        String pkcs10 = csrCreator.createCertificateRequest(csrKeyPair.getPrivate(), csrKeyPair.getPublic());
        //if(true){  System.out.println(pkcs10); WaitDialog.hideDialog(); return;}

        // send PKCS#10 to server
        boolean success;
        String message;
        if (CertificateRequestCreator.TYPE.USER.equals(type)) {
            OnlineUserCertRequest csrRequest = OffEdt.call(this, "Submitting your certificate request...",
                    () -> new OnlineUserCertRequest(pkcs10, HashUtil.getHash(String.valueOf(pin)), email));
            message = csrRequest.getMessage();
            success = csrRequest.isCSRREquestSuccess();
        } else {
            // Send PKCS#10 CSR to server. Provide authCert/Key for PPPK . 
            OnlineHostCertRequest onlineHostCertReq = new OnlineHostCertRequest(authCert, authKey,
                    pkcs10, HashUtil.getHash(String.valueOf(pin)), email);
            Pair<Boolean, String> result = OffEdt.call(this, "Submitting your host certificate request...",
                    onlineHostCertReq::doHostCSR);
            message = result.second;
            success = result.first;
        }
        //WaitDialog.hideDialog();

        // If submitted ok, save a new self-signed cert in the keyStore and ReStore. 
        if (success) {
            X509Certificate cert = CAKeyPair.createSelfSignedCertificate(csrKeyPair, ou, l, cn);
            X509Certificate[] certs = {cert};

            // First - reStore the keystore 
            model.getClientKeyStore().setKeyEntry(newAlias, csrKeyPair.getPrivate(), model.getPassword(), certs);
            model.getClientKeyStore().reStore();
            // Second - add the new entry to the model map
            KeyStoreEntryWrapper newCsrEntry = model.createKSEntryWrapperInstanceFromEntry(newAlias);
            model.getKeyStoreEntryMap().put(newAlias, newCsrEntry);
            // Third - update this.storedAlias so that calling code can 
            // determine if request was successful or not. 
            this.storedAlias = newAlias;
            GeneralMessageDialog.showAndWait(this, "Request Successful", "Request Successful", JOptionPane.INFORMATION_MESSAGE);
            this.dispose();

        } else {
            GeneralMessageDialog.showAndWait(this, "Server responded an error: " + message, "CSR Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Check that the given user CN is valid for display. Note, this is not the
     * fully validated CN (just that the display DN is OK for further
     * preparation such as making lowercase, trimming etc).
     *
     * @param cn
     * @return
     */
    private boolean isDisplayUserCNValid(String cn) {
        if (cn == null) {
            return false;
        }
        if (!userCN_Pattern.matcher(this.txtName.getText()).matches()) {
            return false;
        }

        String[] names = cn.split("\\s");
        // Must be at least TWO names 
        if (names.length < 2) {
            return false;
        }
        // At least TWO of these names must have length TWO OR MORE
        int ii = 0;
        for (String name : names) {
            if (name.length() >= 2) {
                ++ii;
            }
        }
        return ii >= 2;
    }

    private boolean isInputReadyUpdateGUI() {
        boolean complete = true;
        StringBuilder text = new StringBuilder();

        // RA   
        if (this.cmbSelectRA.getSelectedIndex() == -1 || this.cmbSelectRA.getSelectedIndex() == 0) {
            this.raValidLabel.setIcon(this.errorIcon);
            complete = false;
        } else {
            String testRA = (String) this.cmbSelectRA.getSelectedItem();
            if (testRA == null || testRA.trim().length() == 0) {
                this.raValidLabel.setIcon(this.errorIcon);
                complete = false;
            } else {
                String[] ou_l = testRA.trim().split("[,\\s]+");
                if (ou_l.length != 2) {
                    complete = false;
                    text.append("ERROR - Invalid RA provided. Please contact support@grid-support.ac.uk and report this problem\n");
                    this.raValidLabel.setIcon(this.errorIcon);
                } else {
                    this.raValidLabel.setIcon(this.acceptIcon);
                }
            }
        }

        // Common Name 
        if (CERT_TYPE.USER_CERT.equals(this.certType)) {
            if (!this.isDisplayUserCNValid(this.txtName.getText())) {
                complete = false;
                this.cnValidLabel.setIcon(this.errorIcon);
            } else {
                this.txtName.setText(this.txtName.getText().toLowerCase());
                this.cnValidLabel.setIcon(this.acceptIcon);
            }
        } else {
            // TODO: have to cope with 'service/host.domain.ac.uk'
            if (!DomainValidator.getInstance().isValid(this.txtName.getText())) {
                complete = false;
                this.cnValidLabel.setIcon(this.errorIcon);
            } else {
                this.txtName.setText(this.txtName.getText().toLowerCase());
                this.cnValidLabel.setIcon(this.acceptIcon);
            }
        }

        // Email 
        if (!EmailValidator.getInstance().isValid(this.txtEmail.getText())) {
            this.emailValidLabel.setIcon(this.errorIcon);
            complete = false;
        } else {
            this.emailValidLabel.setIcon(this.acceptIcon);
        }

        // Pin and confirmation 
        String pin = new String(txtPin.getPassword());
        String confirm = new String(txtConfirm.getPassword());
        if (!pin.equals(confirm)) {
            this.pinValidLabel.setIcon(this.errorIcon);
            complete = false;
        } else if (this.txtPin.getPassword().length < 10) {
            this.pinValidLabel.setIcon(this.errorIcon);
            complete = false;
        } else {
            this.pinValidLabel.setIcon(this.acceptIcon);
        }

        // Alias
        if (this.aliasTextField.getText().isEmpty()) {
            this.aliasValidPinLabel.setIcon(this.errorIcon);
            complete = false;
        } else {
            this.aliasValidPinLabel.setIcon(this.acceptIcon);
        }

        // Finally enable/disable the Apply button accordingly 
        this.btnApply.setEnabled(complete);
        if (!complete) {
            jLabel5.setForeground(Color.RED);
            jLabel5.setText(text.toString());
        } else {
            jLabel5.setForeground(Color.BLACK);
            jLabel5.setText(readyInfo);
        }
        return complete;
    }

    /**
     * @return If the application was successful, return the alias of the CSR
     * that is newly stored in the keyStore, otherwise return null.
     */
    public String getStoredAlias() {
        return this.storedAlias;
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jDesktopPane1 = new javax.swing.JDesktopPane();
        cmbSelectRA = new javax.swing.JComboBox();
        labCN = new javax.swing.JLabel();
        txtName = new javax.swing.JTextField();
        labEmail = new javax.swing.JLabel();
        txtEmail = new javax.swing.JTextField();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        btnApply = new javax.swing.JButton();
        btnCancel = new javax.swing.JButton();
        txtPin = new javax.swing.JPasswordField();
        txtConfirm = new javax.swing.JPasswordField();
        jLabel6 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        jLabel5 = new javax.swing.JTextArea();
        jLabel7 = new javax.swing.JLabel();
        jLabel8 = new javax.swing.JLabel();
        aliasTextField = new javax.swing.JTextField();
        labelRequestorId = new javax.swing.JLabel();
        txtDN = new javax.swing.JTextField();
        raValidLabel = new javax.swing.JLabel();
        cnValidLabel = new javax.swing.JLabel();
        emailValidLabel = new javax.swing.JLabel();
        aliasValidPinLabel = new javax.swing.JLabel();
        pinValidLabel = new javax.swing.JLabel();

        jDesktopPane1.setName("jDesktopPane1"); // NOI18N

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setTitle("Apply for certificate");
        setName("Form"); // NOI18N
        setResizable(false);

        cmbSelectRA.setName("cmbSelectRA"); // NOI18N
        cmbSelectRA.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                cmbSelectRAMouseEntered(evt);
            }

            public void mouseExited(java.awt.event.MouseEvent evt) {
                cmbSelectRAMouseExited(evt);
            }
        });
        cmbSelectRA.addActionListener(this::cmbSelectRAActionPerformed);

        labCN.setText("Common Name");
        labCN.setName("labCN"); // NOI18N

        txtName.setName("txtName"); // NOI18N
        txtName.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                txtNameMouseEntered(evt);
            }

            public void mouseExited(java.awt.event.MouseEvent evt) {
                txtNameMouseExited(evt);
            }
        });
        txtName.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                txtNameKeyReleased(evt);
            }
        });

        labEmail.setText("Email Address");
        labEmail.setName("labEmail"); // NOI18N

        txtEmail.setName("txtEmail"); // NOI18N
        txtEmail.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                txtEmailMouseEntered(evt);
            }

            public void mouseExited(java.awt.event.MouseEvent evt) {
                txtEmailMouseExited(evt);
            }
        });
        txtEmail.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                txtEmailKeyReleased(evt);
            }
        });

        jLabel3.setText("PIN");
        jLabel3.setName("jLabel3"); // NOI18N

        jLabel4.setText("Confirm PIN");
        jLabel4.setName("jLabel4"); // NOI18N

        btnApply.setText("Apply");
        btnApply.setEnabled(false);
        btnApply.setName("btnApply"); // NOI18N
        btnApply.addActionListener(this::btnApplyActionPerformed);

        btnCancel.setText("Cancel");
        btnCancel.setName("btnCancel"); // NOI18N
        btnCancel.addActionListener(this::btnCancelActionPerformed);

        txtPin.setName("txtPin"); // NOI18N
        txtPin.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                txtPinMouseEntered(evt);
            }

            public void mouseExited(java.awt.event.MouseEvent evt) {
                txtPinMouseExited(evt);
            }
        });
        txtPin.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusGained(java.awt.event.FocusEvent evt) {
                txtPinFocusGained(evt);
            }

            public void focusLost(java.awt.event.FocusEvent evt) {
                txtPinFocusLost(evt);
            }
        });
        txtPin.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                txtPinKeyReleased(evt);
            }
        });

        txtConfirm.setName("txtConfirm"); // NOI18N
        txtConfirm.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                txtConfirmMouseEntered(evt);
            }

            public void mouseExited(java.awt.event.MouseEvent evt) {
                txtConfirmMouseExited(evt);
            }
        });
        txtConfirm.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                txtConfirmKeyReleased(evt);
            }
        });

        jLabel6.setText("10 characters min.");
        jLabel6.setName("jLabel6"); // NOI18N

        jScrollPane1.setName("jScrollPane1"); // NOI18N

        jLabel5.setBackground(javax.swing.UIManager.getDefaults().getColor("Label.background"));
        jLabel5.setColumns(20);
        jLabel5.setLineWrap(true);
        jLabel5.setRows(5);
        jLabel5.setText("Please enter all information");
        jLabel5.setWrapStyleWord(true);
        jLabel5.setCaretColor(new java.awt.Color(255, 51, 51));
        jLabel5.setName("jLabel5"); // NOI18N
        jScrollPane1.setViewportView(jLabel5);

        jLabel7.setText("Registration Authority");
        jLabel7.setName("jLabel7"); // NOI18N

        jLabel8.setText("Alias (display name)");
        jLabel8.setName("jLabel8"); // NOI18N

        aliasTextField.setName("aliasTextField"); // NOI18N
        aliasTextField.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                aliasTextFieldMouseEntered(evt);
            }
        });
        aliasTextField.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                aliasTextFieldKeyReleased(evt);
            }
        });

        labelRequestorId.setText("Requestor Identitiy");
        labelRequestorId.setName("labelRequestorId"); // NOI18N

        txtDN.setEditable(false);
        txtDN.setName("txtDN"); // NOI18N

        raValidLabel.setIcon(new javax.swing.ImageIcon(getClass().getResource("/error.png"))); // NOI18N
        raValidLabel.setName("raValidLabel"); // NOI18N

        cnValidLabel.setIcon(new javax.swing.ImageIcon(getClass().getResource("/error.png"))); // NOI18N
        cnValidLabel.setName("cnValidLabel"); // NOI18N

        emailValidLabel.setIcon(new javax.swing.ImageIcon(getClass().getResource("/error.png"))); // NOI18N
        emailValidLabel.setName("emailValidLabel"); // NOI18N

        aliasValidPinLabel.setIcon(new javax.swing.ImageIcon(getClass().getResource("/error.png"))); // NOI18N
        aliasValidPinLabel.setName("aliasValidPinLabel"); // NOI18N

        pinValidLabel.setIcon(new javax.swing.ImageIcon(getClass().getResource("/error.png"))); // NOI18N
        pinValidLabel.setName("pinValidLabel"); // NOI18N

        org.jdesktop.layout.GroupLayout layout = new org.jdesktop.layout.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
                layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                        .add(layout.createSequentialGroup()
                                .addContainerGap()
                                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                                        .add(org.jdesktop.layout.GroupLayout.TRAILING, layout.createSequentialGroup()
                                                .add(btnApply)
                                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                                .add(btnCancel))
                                        .add(org.jdesktop.layout.GroupLayout.TRAILING, jScrollPane1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 617, Short.MAX_VALUE)
                                        .add(layout.createSequentialGroup()
                                                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                                                        .add(jLabel3)
                                                        .add(jLabel4)
                                                        .add(jLabel7)
                                                        .add(labCN)
                                                        .add(labEmail)
                                                        .add(jLabel8)
                                                        .add(labelRequestorId))
                                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                                                        .add(txtDN)
                                                        .add(org.jdesktop.layout.GroupLayout.TRAILING, layout.createSequentialGroup()
                                                                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.TRAILING)
                                                                        .add(org.jdesktop.layout.GroupLayout.LEADING, layout.createSequentialGroup()
                                                                                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.TRAILING, false)
                                                                                        .add(org.jdesktop.layout.GroupLayout.LEADING, txtPin, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 104, Short.MAX_VALUE)
                                                                                        .add(org.jdesktop.layout.GroupLayout.LEADING, txtConfirm)
                                                                                        .add(org.jdesktop.layout.GroupLayout.LEADING, aliasTextField))
                                                                                .add(18, 18, 18)
                                                                                .add(jLabel6)
                                                                                .add(0, 0, Short.MAX_VALUE))
                                                                        .add(org.jdesktop.layout.GroupLayout.LEADING, txtEmail)
                                                                        .add(org.jdesktop.layout.GroupLayout.LEADING, txtName)
                                                                        .add(org.jdesktop.layout.GroupLayout.LEADING, cmbSelectRA, 0, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                                                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                                                                        .add(layout.createSequentialGroup()
                                                                                .add(21, 21, 21)
                                                                                .add(cnValidLabel))
                                                                        .add(org.jdesktop.layout.GroupLayout.TRAILING, layout.createSequentialGroup()
                                                                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                                                                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                                                                                        .add(org.jdesktop.layout.GroupLayout.TRAILING, emailValidLabel)
                                                                                        .add(org.jdesktop.layout.GroupLayout.TRAILING, aliasValidPinLabel)
                                                                                        .add(org.jdesktop.layout.GroupLayout.TRAILING, raValidLabel)
                                                                                        .add(org.jdesktop.layout.GroupLayout.TRAILING, pinValidLabel))))))))
                                .addContainerGap())
        );
        layout.setVerticalGroup(
                layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                        .add(layout.createSequentialGroup()
                                .addContainerGap(org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                                        .add(org.jdesktop.layout.GroupLayout.TRAILING, labelRequestorId)
                                        .add(org.jdesktop.layout.GroupLayout.TRAILING, txtDN, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                                        .add(org.jdesktop.layout.GroupLayout.TRAILING, raValidLabel)
                                        .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                                                .add(cmbSelectRA, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                                .add(jLabel7)))
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                                        .add(txtName, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                        .add(labCN)
                                        .add(cnValidLabel))
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                                        .add(emailValidLabel)
                                        .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                                                .add(txtEmail, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                                .add(labEmail)))
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                                        .add(jLabel3)
                                        .add(txtPin, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                        .add(jLabel6)
                                        .add(pinValidLabel))
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                                        .add(jLabel4)
                                        .add(txtConfirm, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                                        .add(aliasTextField, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                        .add(jLabel8)
                                        .add(aliasValidPinLabel))
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(jScrollPane1, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                                        .add(btnCancel)
                                        .add(btnApply))
                                .addContainerGap())
        );

        pack();
        setLocationRelativeTo(null);
    }// </editor-fold>//GEN-END:initComponents

    private void btnCancelActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCancelActionPerformed
        this.dispose();
    }//GEN-LAST:event_btnCancelActionPerformed

    private void btnApplyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnApplyActionPerformed
        // 
        this.doApplyButton();
    }//GEN-LAST:event_btnApplyActionPerformed

    private void txtPinFocusGained(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_txtPinFocusGained
        jLabel6.setVisible(true);
    }//GEN-LAST:event_txtPinFocusGained

    private void cmbSelectRAMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_cmbSelectRAMouseEntered
        jLabel5.setForeground(Color.black);
        jLabel5.setText("Select your local RA operator");
    }//GEN-LAST:event_cmbSelectRAMouseEntered

    private void cmbSelectRAMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_cmbSelectRAMouseExited
        //this.isInputReadyUpdateGUI(); 
    }//GEN-LAST:event_cmbSelectRAMouseExited

    private void txtNameMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_txtNameMouseEntered
        jLabel5.setForeground(Color.black);
        jLabel5.setText("Specify a Common Name value - lowercase \"firstname lastname\" (provide at least TWO given names with a minimum of TWO chars each)\n");

    }//GEN-LAST:event_txtNameMouseEntered

    private void txtNameMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_txtNameMouseExited
        //this.isInputReadyUpdateGUI();
    }//GEN-LAST:event_txtNameMouseExited

    private void txtEmailMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_txtEmailMouseEntered
        jLabel5.setForeground(Color.black);
        jLabel5.setText("Enter a valid email address. This will be used to "
                + "send you information regarding your certificate.");
    }//GEN-LAST:event_txtEmailMouseEntered

    private void txtEmailMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_txtEmailMouseExited
        //this.isInputReadyUpdateGUI();
    }//GEN-LAST:event_txtEmailMouseExited

    private void txtPinMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_txtPinMouseEntered
        jLabel5.setForeground(Color.black);
        jLabel5.setText("Enter and confirm a 10 character pin to help identify "
                + "yourself to an RA Operator");
    }//GEN-LAST:event_txtPinMouseEntered

    private void txtPinMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_txtPinMouseExited
        //this.isInputReadyUpdateGUI();
    }//GEN-LAST:event_txtPinMouseExited

    private void txtPinFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_txtPinFocusLost
        jLabel6.setVisible(false);
    }//GEN-LAST:event_txtPinFocusLost

    private void txtConfirmMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_txtConfirmMouseEntered
        jLabel5.setForeground(Color.black);
        jLabel5.setText("Please enter your pin again for confirmation");
    }//GEN-LAST:event_txtConfirmMouseEntered

    private void txtConfirmMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_txtConfirmMouseExited
        //this.isInputReadyUpdateGUI();
    }//GEN-LAST:event_txtConfirmMouseExited

    private void txtNameKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txtNameKeyReleased
        // TODO add your handling code here:
        this.isInputReadyUpdateGUI();
    }//GEN-LAST:event_txtNameKeyReleased

    private void txtEmailKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txtEmailKeyReleased
        // TODO add your handling code here:
        this.isInputReadyUpdateGUI();
    }//GEN-LAST:event_txtEmailKeyReleased

    private void txtPinKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txtPinKeyReleased
        // TODO add your handling code here:
        this.isInputReadyUpdateGUI();
    }//GEN-LAST:event_txtPinKeyReleased

    private void txtConfirmKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txtConfirmKeyReleased
        // TODO add your handling code here:
        this.isInputReadyUpdateGUI();
    }//GEN-LAST:event_txtConfirmKeyReleased

    private void aliasTextFieldKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_aliasTextFieldKeyReleased
        // TODO add your handling code here:
        this.isInputReadyUpdateGUI();
    }//GEN-LAST:event_aliasTextFieldKeyReleased

    private void cmbSelectRAActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cmbSelectRAActionPerformed
        // TODO add your handling code here:
        this.isInputReadyUpdateGUI();
    }//GEN-LAST:event_cmbSelectRAActionPerformed

    private void aliasTextFieldMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_aliasTextFieldMouseEntered
        // TODO add your handling code here:
        jLabel5.setForeground(Color.black);
        jLabel5.setText("Enter an alias for this certificate (i.e. a simple display name such as \"myGridCert 1\")");
    }//GEN-LAST:event_aliasTextFieldMouseEntered

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextField aliasTextField;
    private javax.swing.JLabel aliasValidPinLabel;
    private javax.swing.JButton btnApply;
    private javax.swing.JButton btnCancel;
    private javax.swing.JComboBox cmbSelectRA;
    private javax.swing.JLabel cnValidLabel;
    private javax.swing.JLabel emailValidLabel;
    private javax.swing.JDesktopPane jDesktopPane1;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JTextArea jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JLabel labCN;
    private javax.swing.JLabel labEmail;
    private javax.swing.JLabel labelRequestorId;
    private javax.swing.JLabel pinValidLabel;
    private javax.swing.JLabel raValidLabel;
    private javax.swing.JPasswordField txtConfirm;
    private javax.swing.JTextField txtDN;
    private javax.swing.JTextField txtEmail;
    private javax.swing.JTextField txtName;
    private javax.swing.JPasswordField txtPin;
    // End of variables declaration//GEN-END:variables

}
