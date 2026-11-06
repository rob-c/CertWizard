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

import uk.ngs.ca.certificate.management.ClientKeyStore;
import uk.ngs.ca.certificate.verify.CertificateVerifier;
import uk.ngs.ca.certificate.verify.CrlRevocationChecker;
import uk.ngs.ca.certificate.verify.VerificationReport;
import uk.ngs.ca.common.SystemStatus;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.security.Key;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutionException;

/**
 * "Verify" button: runs every {@link CertificateVerifier} check, including
 * revocation, against the selected keystore entry on a background thread and
 * shows the report.
 */
final class VerifyCertificateAction {

    private VerifyCertificateAction() {
    }

    static void run(Component parent, ClientKeyStore keyStore, String alias, char[] password) {
        final Certificate[] chain;
        final PrivateKey key;
        try {
            if (keyStore.isKeyEntry(alias)) {
                chain = keyStore.getCertificateChain(alias);
                Key k = keyStore.getKey(alias, password);
                key = k instanceof PrivateKey ? (PrivateKey) k : null;
            } else {
                Certificate c = keyStore.getCertificate(alias);
                chain = c == null ? null : new Certificate[]{c};
                key = null;
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(parent, "Cannot read the selected entry: " + e.getMessage(),
                    "Verify certificate", JOptionPane.ERROR_MESSAGE);
            return;
        }
        if (chain == null || chain.length == 0 || !(chain[0] instanceof X509Certificate)) {
            JOptionPane.showMessageDialog(parent, "The selected entry has no certificate to verify.",
                    "Verify certificate", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        final File cache = new File(SystemStatus.getInstance().getCwDataDirectory(), "crl-cache");
        final boolean online = SystemStatus.getInstance().getIsOnline();
        parent.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));

        new SwingWorker<VerificationReport, Void>() {
            @Override
            protected VerificationReport doInBackground() {
                CertificateVerifier v = CertificateVerifier.standard(CrlRevocationChecker.http(cache.toPath(), online));
                return key != null ? v.verifyKeyEntry(key, chain) : v.verifyCertificate((X509Certificate) chain[0], chain);
            }

            @Override
            protected void done() {
                parent.setCursor(Cursor.getDefaultCursor());
                try {
                    show(parent, get());
                } catch (InterruptedException | ExecutionException e) {
                    JOptionPane.showMessageDialog(parent, "Verification failed to run: " + e.getMessage(),
                            "Verify certificate", JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    private static void show(Component parent, VerificationReport report) {
        JEditorPane pane = new JEditorPane("text/html", report.toHtml());
        pane.setEditable(false);
        pane.setCaretPosition(0);
        JScrollPane scroll = new JScrollPane(pane);
        scroll.setPreferredSize(new Dimension(720, 420));
        int type;
        switch (report.overall()) {
            case FAIL:
                type = JOptionPane.ERROR_MESSAGE;
                break;
            case WARN:
                type = JOptionPane.WARNING_MESSAGE;
                break;
            default:
                type = JOptionPane.INFORMATION_MESSAGE;
        }
        JOptionPane.showMessageDialog(parent, scroll, "Certificate verification: " + report.overall(), type);
    }
}
