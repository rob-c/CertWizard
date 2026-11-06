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

import uk.ngs.ca.common.SystemStatus;
import uk.ngs.ca.tools.property.SysProperty;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * The main frame class.
 *
 * @author Xiao Wang
 * @author David Meredith (modifications)
 */
public class CertWizardMain extends javax.swing.JFrame {

    private final OnlineStatus onlineStatusPanel = new OnlineStatus();
    private final JTabbedPane tabbedPane = new JTabbedPane();

    /**
     * Creates new form CertWizardMainFrame
     */
    public CertWizardMain(String dataDirectoryLocationOverride) {
        initComponents();
        setupFrame(dataDirectoryLocationOverride);
    }

    private void setupFrame(String bootstrapDirectoryLocationOverride) {
        this.setLayout(new BorderLayout());
        URL iconURL = CertWizardMain.class.getResource("/ngs-icon.png");
        if (iconURL != null) {
            this.setIconImage(Toolkit.getDefaultToolkit().getImage(iconURL));
        }
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        String title = SysProperty.getValue("ngsca.certwizard.version");
        this.setTitle(title);

        this.createGlobusDirIfNotExistsShowWarnings();
        this.setupDataDirectory(bootstrapDirectoryLocationOverride);

        try {
            SysProperty.setupTrustStore(); // throws IllegalStateException if prob
            String trustStoreFile = SysProperty.getValue("ngsca.truststore.file");
            String trustStorePath = SystemStatus.getInstance().getCwDataDirectory().getAbsolutePath();
            trustStorePath = trustStorePath + System.getProperty("file.separator") + trustStoreFile;
            System.out.println("trustStore file path [" + trustStorePath + "]");

            String password = SysProperty.getValue("ngsca.cert.truststore.password");
            System.setProperty("javax.net.ssl.trustStore", trustStorePath);
            System.setProperty("javax.net.ssl.trustStorePassword", password);

            // check files exist and are readable
            File truststore = new File(trustStorePath);
            if (!truststore.exists() || !truststore.canRead()) {
                throw new IllegalStateException("Trustore cannot be read");
            }

        } catch (Exception ex) {
            ex.printStackTrace();
            JOptionPane.showMessageDialog(null, ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            System.exit(0);
        }

        this.initTabbedPane();

        // Here we start the ping task in the background so we need to: 
        // 1) maybe read a file for the webproxy host/port/username/password
        // 2) if file is not present, attempt to determine webproxy settings automatically (vole) 
        // 3) Can always fallback to a dialox  
        // 
        // This needs the proxy settings to be set correctly . 
        //System.setProperty("http.proxyHost", "wwwnotexist.tr.ld");
        //System.setProperty("http.proxyHost", "wwwcache.dl.ac.uk");     
        // Run ping check in a new thread so we don't block while it tries to connect.
        onlineStatusPanel.startScheduledPingCheckTask();

        this.getContentPane().add(BorderLayout.CENTER, this.tabbedPane);
        this.getContentPane().add(BorderLayout.SOUTH, this.onlineStatusPanel);
        this.pack();
    }

    private void setupDataDirectory(String bootstrapDirectoryLocationOverride) {
        Path dataDirectory;
        GetBootstrapDir bootDia = new GetBootstrapDir(this, true, bootstrapDirectoryLocationOverride);
        bootDia.setLocationRelativeTo(null);
        bootDia.setVisible(true);
        dataDirectory = bootDia.getBootDir();
        if (dataDirectory == null) {
            System.exit(0);
        }
        SystemStatus.getInstance().setCwDataDirectory(dataDirectory.toFile());
    }

    private void createGlobusDirIfNotExistsShowWarnings() {
        // Java 1.6 compatible

        // create home.globus dir as a precaution
        File globusDir = new File(System.getProperty("user.home") + System.getProperty("file.separator") + ".globus");
        if (!globusDir.exists()) {
            globusDir.mkdir();
        }

        boolean isDir = globusDir.isDirectory();

        // See if the HOME/.globus directory is writable 
        boolean writableDir = globusDir.canWrite();
        // Also need to create a tmp file to see if this dir is writable (can't just rely on
        // caDir.canWrite() as this is not reliable due to java bug: 
        // http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=4787931 
        File tmp = null;
        try {
            tmp = File.createTempFile("cwiztouchtmp", ".tmp", globusDir);
            writableDir = true;
        } catch (IOException ex) {
            writableDir = false;
        } finally {
            try {
                if (tmp != null) {
                    tmp.delete();
                }
            } catch (Exception ex) {
            }
        }

        if (!writableDir || !isDir) {
            JOptionPane.showMessageDialog(null,
                    "Can't write to 'HOME/.globus' directory. "
                            + "Globus needs to store configuration in the following dir: \n[" + globusDir.getAbsolutePath() + "]\n"
                            + "You will not be able to use MyProxy or grid-proxy-init. Please add this directory manually, provide write permissions and restart.",
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void initTabbedPane() {
        JPanel tabPanelManageCerts = new JPanel();
        tabbedPane.addTab("Apply For/Manage Your Certificate", tabPanelManageCerts);

        // Tidy up ComponentSettingsPanel and DoActionsPanel since no longer needed
        // First, create the settings/setup panel and the doActions panel.
        final PasswordPanel pp = new PasswordPanel(tabPanelManageCerts);
        tabPanelManageCerts.add(pp);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setName("frame"); // NOI18N

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGap(0, 678, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGap(0, 431, Short.MAX_VALUE)
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    /**
     * @param args the command line arguments: an optional data directory
     *             override, or {@code --self-test} to run the headless start-up
     *             check in {@link SelfTest} and exit without showing any GUI
     */
    public static void main(String[] args) {
        if (java.util.Arrays.asList(args).contains(SelfTest.FLAG)) {
            System.exit(SelfTest.run(System.out, System.err));
        }
        String dataDirectoryLocationOverride = "";
        if (args.length > 0) {
            dataDirectoryLocationOverride = args[0];
        }
        /*
         * Set the Nimbus look and feel
         */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /*
         * If Nimbus (introduced in Java SE 6) is not available, stay with the
         * default look and feel. For details see
         * http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html
         */
        //</editor-fold>

        /*
         * Create and display the form
         */
        String finalDataDirectoryLocationOverride = dataDirectoryLocationOverride;
        java.awt.EventQueue.invokeLater(() -> {
            CertWizardMain cw = new CertWizardMain(finalDataDirectoryLocationOverride);
            cw.setLocationRelativeTo(null);
            cw.setVisible(true);
        });
    }
    // Variables declaration - do not modify//GEN-BEGIN:variables
    // End of variables declaration//GEN-END:variables
}
