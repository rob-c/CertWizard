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
import net.sf.portecle.FPortecle;
import net.sf.portecle.gui.SwingHelper;
import org.apache.commons.validator.routines.EmailValidator;
import uk.ngs.ca.certificate.chain.BundledCaCertificates;
import uk.ngs.ca.certificate.client.RevokeRequest;
import uk.ngs.ca.certificate.management.ClientKeyStoreCaServiceWrapper;
import uk.ngs.ca.certificate.management.KeyStoreEntryWrapper;
import uk.ngs.ca.certificate.renew.AutoRenewService;
import uk.ngs.ca.certificate.renew.RenewalLedger;
import uk.ngs.ca.certificate.renew.RenewalSubmitter;
import uk.ngs.ca.common.OffEdt;
import uk.ngs.ca.common.SystemStatus;
import uk.ngs.certwizard.gui.GeneralMessageDialog;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.time.Instant;
import java.util.Calendar;
import java.util.Date;
import java.util.ResourceBundle;
import java.util.TimeZone;
import java.util.regex.Pattern;

/**
 * Helper class for performing certificate renewals and revocations. The methods
 * invoked by this class present GUI components during their processing.
 *
 * @author David Meredith
 */
public class CertificateRenewRevokeGuiHelper {

    private final ClientKeyStoreCaServiceWrapper caKeyStoreModel;
    private final Component parentComponent;
    private final Pattern alphaNumericPattern = Pattern.compile("[0-9A-Za-z\\s_.,]+");

    /**
     * Portecle Resource bundle base name
     */
    private static final String RB_BASENAME = FPortecle.class.getPackage().getName() + "/resources";
    public static final ResourceBundle RB = ResourceBundle.getBundle(RB_BASENAME);

    public CertificateRenewRevokeGuiHelper(Component parentCompoent, ClientKeyStoreCaServiceWrapper caKeyStoreModel) {
        this.parentComponent = parentCompoent;
        this.caKeyStoreModel = caKeyStoreModel;
    }

    /**
     * Lead the user through the revocation process for the given keyStore
     * entry. The method generates GUI components during its processing. The
     * method does not make any changes to the application's keyStore file.
     *
     * @param selectedKSEW
     * @return true if revoked, otherwise false.
     */
    public boolean doRevoke(KeyStoreEntryWrapper selectedKSEW) throws KeyStoreException, IOException, CertificateException {
        // First MUST refresh the online status of the selected keyStoreEntryWrapper
        // to guard against TOCTAU attacks and stale data (when was the online status last fetched). 
        try {
            parentComponent.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
            if (onlineUpdate(selectedKSEW)) {
                caKeyStoreModel.getClientKeyStore().reStore();
            }
        } finally {
            parentComponent.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
        }

        if (selectedKSEW == null
                || !KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY.equals(selectedKSEW.getEntryType())
                || selectedKSEW.getServerCertificateCSRInfo() == null
                || !"VALID".equals(selectedKSEW.getServerCertificateCSRInfo().getStatus())) {

            JOptionPane.showMessageDialog(parentComponent, "Only VALID certificates known by the UK CA can be revoked",
                    "Suitable certificate not selected", JOptionPane.WARNING_MESSAGE);
            return false;

        }

        if (JOptionPane.showConfirmDialog(parentComponent,
                "Are you sure you want to revoke the selected certificate?\n\n"
                        + "Alias: [" + selectedKSEW.getAlias() + "]\n"
                        + "DN: [" + selectedKSEW.getX500PrincipalName() + "]\n"
                        + "Email: [" + selectedKSEW.getServerCertificateCSRInfo().getUserEmail() + "]",
                "Renew Certificate", JOptionPane.YES_NO_OPTION)
                != JOptionPane.YES_OPTION) {
            return false;
        }

        String reason = this.getNewRevocationReasonHelper("");
        if (reason == null) {
            return false;
        }
        try {
            parentComponent.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));

            final long cert_id = Long.parseLong(selectedKSEW.getServerCertificateCSRInfo().getId());
            RevokeRequest revokeRequest = new RevokeRequest(
                    this.caKeyStoreModel.getClientKeyStore().getPrivateKey(selectedKSEW.getAlias()),
                    cert_id, reason);
            // do the revokation with the CA and block (note, this has 
            // no interaction with the keystore) 
            final boolean revoked = OffEdt.call(parentComponent, "Submitting the revocation request...",
                    revokeRequest::doPosts);

            // Just reload the selected entry rather than refreshing all   
            if (onlineUpdate(selectedKSEW)) {
                // Don't need to reStore (no online state is saved to file)
            }

            parentComponent.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));

            if (revoked) {
                String message = revokeRequest.getMessage() != null ? revokeRequest.getMessage()
                        : "Your revocation request has been submitted to the CA.";
                JOptionPane.showMessageDialog(parentComponent, message, "Certificate revoked", JOptionPane.INFORMATION_MESSAGE);
                return true;
            } else {
                GeneralMessageDialog.showAndWait(parentComponent, "The revocation request failed: " + revokeRequest.getMessage(),
                        "Revocation Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }
        } finally {
            parentComponent.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
        }
    }

    /**
     * Lead the user through the renewal process for the given keyStore entry.
     * The method generates GUI components during its processing. The method
     * creates and persists a new CSR certificate in the application's keyStore
     * file.
     *
     * @param selectedKSEW
     * @return the keyStore alias of the newly added renewal CSR or null if
     * cancelled or not added for whatever reason.
     */
    public String doRenew(KeyStoreEntryWrapper selectedKSEW)
            throws KeyStoreException, IOException, CertificateException, SecurityException {
        // First MUST refresh the online status of the selected keyStoreEntryWrapper
        // to guard against TOCTAU attacks and stale data (when was the online status last fetched). 
        try {
            parentComponent.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
            if (onlineUpdate(selectedKSEW)) {
                caKeyStoreModel.getClientKeyStore().reStore();
            }
        } finally {
            parentComponent.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
        }

        // Now test that the selected keyStoreEntryWrapper is eligible for renewal. 
        if (selectedKSEW == null
                || !KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY.equals(selectedKSEW.getEntryType())
                || selectedKSEW.getServerCertificateCSRInfo() == null
                || !("VALID".equals(selectedKSEW.getServerCertificateCSRInfo().getStatus()))
                //||"Expired".equals(selectedKSEW.getServerCertificateCSRInfo().getStatus()))
                || this.caKeyStoreModel.getClientKeyStore().getX509Certificate(selectedKSEW.getAlias()) == null) {
            // Can only renew key_pairs types issued by our CA    
            JOptionPane.showMessageDialog(parentComponent, "Only VALID or recently Expired certificates known by the UK CA can be renewed",
                    "Suitable certificate not selected", JOptionPane.WARNING_MESSAGE);
            return null;
        }
        System.out.println("DEBUG: " + selectedKSEW.getServerCertificateCSRInfo().getStatus());

        // Check we are renewing a cert that is valid or within the 30 day 
        // tolerance period 
        Calendar todaysDate = Calendar.getInstance();
        Date certExpireDate = selectedKSEW.getNotAfter();
        if (!certExpireDate.after(todaysDate.getTime())) {
            // Expired 
            // Prevent if cert has been expired for more than 30 days. 
            // JK: best not to use a magic number - maybe we can even have a config value here for occasional use
            // We'd then need to change the words to refer to "grace period" rather than 30 days
            Calendar dateThirtyDaysAgo = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
            dateThirtyDaysAgo.add(Calendar.DAY_OF_MONTH, -30);
            if (!certExpireDate.after(dateThirtyDaysAgo.getTime())) {
                JOptionPane.showMessageDialog(parentComponent, "Invalid Renewal",
                        "Can't renew expired certificate", JOptionPane.ERROR_MESSAGE);
                return null;
            }
        }
        // Status = VALID or Expired 
        // Cert is Not-Expired or within 30 day tolerance 
        long diffDays = (certExpireDate.getTime() - todaysDate.getTimeInMillis()) / (24 * 60 * 60 * 1000);

        int messageType;
        String renewMessagePrefix;
        if (diffDays > 56) {
            messageType = JOptionPane.WARNING_MESSAGE;
            renewMessagePrefix = "There is more than 8 weeks validity left. Are you sure you want to renew?\n";
        } else {
            messageType = JOptionPane.INFORMATION_MESSAGE;
            renewMessagePrefix = "Are you sure you want to renew this certificate?\n";
        }
        if (JOptionPane.showConfirmDialog(parentComponent,
                renewMessagePrefix + "Alias: [" + selectedKSEW.getAlias() + "]\n"
                        + "DN: [" + selectedKSEW.getX500PrincipalName() + "]\n"
                        + "Email: [" + selectedKSEW.getServerCertificateCSRInfo().getUserEmail() + "]",
                "Renew Certificate", JOptionPane.YES_NO_OPTION, messageType)
                != JOptionPane.YES_OPTION) {
            return null; // user pressed no. 
        }

        // Get and assert valid email. 
        // There are instances where we have no email address recorded against 
        // a host certificate in the CA db (this is due to unrelated CA issues). 
        // Must code defensively to ensure that an email is always provided. 
        String email = selectedKSEW.getServerCertificateCSRInfo().getUserEmail();
        if (email == null || !EmailValidator.getInstance().isValid(email)) {
            // In the future, we will want to provide the opportunity to change the 
            // email on renew, but for now we have to barf and ask for it to be reported. 
            //email = this.getNewEmailHelper(email);
            String message = "Unable to renew. The email associated with this certificate is invalid.\n"
                    + "This is due to a known issue on our CA server.\n"
                    + "Please report this to the helpdesk (support@grid-support.ac.uk) and copy the following:\n"
                    + "DN: [" + selectedKSEW.getX500PrincipalName() + "]\n"
                    + "CertId: [" + selectedKSEW.getServerCertificateCSRInfo().getId() + "]\n"
                    + "Email: [" + selectedKSEW.getServerCertificateCSRInfo().getUserEmail() + "]\n";
            GeneralMessageDialog.showAndWait(parentComponent, message, "Renew Error", JOptionPane.ERROR_MESSAGE);
            return null;
        } else {
            // TODO In future - The email currently recorded against this certificate is ... 
            // Do you want to update the email? (will need to remove email equality check below) 
            // JK uncommented it to give it a go ... and it seems to work OK ... at least with a correct email address for a personal cert
            email = this.getNewEmailHelper(email);
        }
        if (email == null) {
            return null; // user hit cancel 
        }
        //if(true) return null; 

        // Re-check now that the (possibly long-open) dialogs are done: the
        // certificate may have expired meanwhile (TOCTOU), and an EMAILADDRESS
        // in the DN must match the email being sent.
        RenewalSubmitter submitter = RenewalSubmitter.online(caKeyStoreModel);
        String reason = submitter.ineligibilityReason(selectedKSEW, email);
        if (reason != null) {
            GeneralMessageDialog.showAndWait(parentComponent, reason, "Cannot renew", JOptionPane.ERROR_MESSAGE);
            return null;
        }

        // Ask user for a new alias for the renewal (provide suitable suggestion)
        JOptionPane.showMessageDialog(parentComponent, "You will now be prompted to enter a new unique alias.\n"
                + "This is simply a memorable display name/tag for your new certificate.", "Certificate Renewal", JOptionPane.INFORMATION_MESSAGE);
        String newCsrRenewalAlias = getNewEntryAliasHelper(selectedKSEW.getAlias() + "_renew", "FPortecle.KeyPairEntryAlias.Title", false);
        if (newCsrRenewalAlias == null) {
            return null; //user hit cancel
        }

        X509Certificate toRenewCert = this.caKeyStoreModel.getClientKeyStore().getX509Certificate(selectedKSEW.getAlias());
        try {
            parentComponent.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
            // New key pair, PKCS#10 signed for the same DN, authenticated with
            // the current key; on success a placeholder entry is saved.
            final String chosenAlias = newCsrRenewalAlias;
            final String chosenEmail = email;
            RenewalSubmitter.Result result = OffEdt.call(parentComponent, "Submitting the renewal request...",
                    () -> submitter.submit(selectedKSEW, chosenEmail, chosenAlias));
            recordInRenewalLedger(toRenewCert, result);
            parentComponent.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
            switch (result.getOutcome()) {
                case SUBMITTED:
                    JOptionPane.showMessageDialog(parentComponent, "The renewal request has been submitted", "Renewal request successful", JOptionPane.INFORMATION_MESSAGE);
                    return result.getNewAlias();
                case REJECTED_BY_CA:
                    GeneralMessageDialog.showAndWait(this.parentComponent, "Server responded an error: " + result.getMessage(), "CSR Renew Error", JOptionPane.ERROR_MESSAGE);
                    return null;
                case NOT_SENT:
                    GeneralMessageDialog.showAndWait(this.parentComponent, result.getMessage()
                            + "\nNothing was submitted; please try again when the CA can be reached.", "CSR Renew Error", JOptionPane.ERROR_MESSAGE);
                    return null;
                case UNCERTAIN:
                    GeneralMessageDialog.showAndWait(this.parentComponent, result.getMessage()
                            + "\nThe request may or may not have reached the CA. Use Refresh before trying again.", "CSR Renew Error", JOptionPane.ERROR_MESSAGE);
                    return null;
                default:
                    GeneralMessageDialog.showAndWait(this.parentComponent, result.getMessage(), "Cannot renew", JOptionPane.ERROR_MESSAGE);
                    return null;
            }
        } finally {
            parentComponent.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
        }
    }

    /**
     * Record a manual renewal in the auto-renew ledger so that auto-renew
     * follows it up (installing the issued certificate) and never submits a
     * second renewal for the same certificate.
     */
    private void recordInRenewalLedger(X509Certificate renewed, RenewalSubmitter.Result result) {
        RenewalLedger.State state;
        switch (result.getOutcome()) {
            case SUBMITTED:
                state = RenewalLedger.State.SUBMITTED;
                break;
            case UNCERTAIN:
                state = RenewalLedger.State.UNCERTAIN;
                break;
            default:
                return;
        }
        try {
            new RenewalLedger(AutoRenewService.ledgerFile(SystemStatus.getInstance().getCwDataDirectory()))
                    .put(BundledCaCertificates.sha256Fingerprint(renewed), state, Instant.now(),
                            result.getNewAlias(), result.getMessage(), true);
        } catch (Exception e) {
            java.util.logging.Logger.getLogger(CertificateRenewRevokeGuiHelper.class.getName())
                    .log(java.util.logging.Level.WARNING, "Could not record renewal in the auto-renew ledger", e);
        }
    }

    /**
     * Refresh the entry's status from the CA without blocking the EDT.
     */
    private boolean onlineUpdate(KeyStoreEntryWrapper entry) throws KeyStoreException {
        return OffEdt.call(parentComponent, "Updating the certificate status from the CA server...",
                () -> caKeyStoreModel.onlineUpdateKeyStoreEntry(entry));
    }

    /**
     * Gets a new entry alias from user, handling overwrite/unique alias issues.
     * Based on Portecle.
     *
     * @param sAlias         suggested alias
     * @param dialogTitleKey message key for dialog titles
     * @param selectAlias    whether to pre-select alias text in text field
     * @return alias for new entry, null if user cancels the operation
     * @see FPortecle#getNewEntryAlias(java.security.KeyStore, java.lang.String,
     * java.lang.String, boolean)
     */
    private String getNewEntryAliasHelper(String sAlias, String dialogTitleKey,
                                          boolean selectAlias) throws KeyStoreException {

        // Get the alias for the new entry
        DGetAlias dGetAlias
                = new DGetAlias(null, RB.getString(dialogTitleKey), sAlias.toLowerCase(), selectAlias);
        dGetAlias.setLocationRelativeTo(parentComponent);
        SwingHelper.showAndWait(dGetAlias);

        sAlias = dGetAlias.getAlias();
        if (sAlias == null) {
            return null;
        }

        if (this.caKeyStoreModel.getClientKeyStore().containsAlias(sAlias)) {
            JOptionPane.showMessageDialog(
                    parentComponent,
                    MessageFormat.format("The keystore already contains an entry with the alias " + sAlias + "\n"
                            + "Please enter a unique alias", sAlias),
                    RB.getString("FPortecle.RenameEntry.Title"), JOptionPane.ERROR_MESSAGE);
            // recurse  
            return getNewEntryAliasHelper(sAlias, dialogTitleKey, selectAlias);
        } else {
            return sAlias;
        }
    }

    /**
     * Gets a new valid email address or null if user cancels.
     *
     * @param sEmail
     * @return valid email or null if canceled.
     */
    private String getNewEmailHelper(String sEmail) {
        if (sEmail == null) {
            sEmail = "";
        }
        sEmail = JOptionPane.showInputDialog(parentComponent, "Enter Email:", sEmail);
        if (sEmail == null) {
            return null;
        }

        if (!EmailValidator.getInstance().isValid(sEmail)) {
            JOptionPane.showMessageDialog(parentComponent,
                    "Invalid Email - Please enter a valid email value",
                    "Invalid Email", JOptionPane.ERROR_MESSAGE);
            // recurse  
            return getNewEmailHelper(sEmail);
        } else {
            return sEmail;
        }
    }

    /**
     * Gets a new reason for revocation or null if user cancels.
     *
     * @param sReason
     * @return reason or null if cancelled.
     */
    private String getNewRevocationReasonHelper(String sReason) {
        if (sReason == null) {
            sReason = "";
        }
        sReason = JOptionPane.showInputDialog(parentComponent, "Reason to Revoke:", sReason);
        if (sReason == null) {
            return null;
        }

        if (sReason.trim().length() < 5 || !alphaNumericPattern.matcher(sReason).matches()) {
            JOptionPane.showMessageDialog(parentComponent,
                    "Invalid Revocation Reason - Please enter a reason for revocation (min 5 chars, alphanumerics only)",
                    "Invalid Revocation", JOptionPane.ERROR_MESSAGE);
            // recurse  
            return getNewRevocationReasonHelper(sReason);
        } else {
            return sReason;
        }
    }
}
