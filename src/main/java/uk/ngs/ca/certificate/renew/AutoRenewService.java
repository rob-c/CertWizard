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
package uk.ngs.ca.certificate.renew;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import uk.ngs.ca.certificate.chain.BundledCaCertificates;
import uk.ngs.ca.certificate.chain.CertChainBuilder;
import uk.ngs.ca.certificate.chain.KeyStoreChains;
import uk.ngs.ca.certificate.management.ClientKeyStoreCaServiceWrapper;
import uk.ngs.ca.certificate.management.KeyStoreEntryWrapper;
import uk.ngs.ca.certificate.verify.ExportVerifier;
import uk.ngs.ca.util.GlobusCredentialWriter;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Automatic certificate renewal while CertWizard is running.
 * <p>
 * Every run (shortly after start-up, then periodically, and whenever the user
 * switches auto-renew on):
 * <ol>
 * <li>follows up renewals it submitted earlier: refreshes the new entry, and
 * once the CA has issued the certificate (installed with its full chain by
 * the normal refresh path) tells the user and, if
 * <code>~/.globus/usercert.pem</code> held the old certificate, replaces
 * usercert.pem/userkey.pem with the new pair (keeping the old files as
 * backups, verifying the new ones and restoring the old ones if
 * verification fails);</li>
 * <li>for every certificate that enters its renewal window, refreshes its
 * status with the CA, asks {@link AutoRenewPolicy} whether to renew, and if
 * so submits exactly one renewal through {@link RenewalSubmitter},
 * recording it in the {@link RenewalLedger} first.</li>
 * </ol>
 * Nothing runs while auto-renew is off, while offline (the next run retries),
 * or while CertWizard's own background refresh is running.
 */
public final class AutoRenewService {

    private static final Logger LOG = LogManager.getLogger(AutoRenewService.class);

    /**
     * What the service needs from the GUI.
     */
    public interface Host {
        boolean isOnline();

        boolean isBusy();

        /**
         * Tell the user something (non-blocking).
         */
        void notifyUser(String title, String message, boolean problem);

        /**
         * The keystore model changed; refresh the display.
         */
        void modelChanged();

        /**
         * Refresh an entry's state from the CA (status, email, and download
         * of a newly issued certificate). The GUI implements this with
         * {@link ClientKeyStoreCaServiceWrapper#onlineUpdateKeyStoreEntry}.
         *
         * @return true if the keystore was changed
         */
        boolean refreshFromCa(KeyStoreEntryWrapper entry) throws Exception;
    }

    private final ClientKeyStoreCaServiceWrapper model;
    private final AutoRenewSettings settings;
    private final RenewalLedger ledger;
    private final RenewalSubmitter submitter;
    private final Host host;
    private final Clock clock;
    private final Path globusDir;
    private final Set<String> warnedThisSession = new HashSet<>();
    private ScheduledExecutorService executor;

    public AutoRenewService(ClientKeyStoreCaServiceWrapper model, AutoRenewSettings settings, RenewalLedger ledger,
                            RenewalSubmitter submitter, Host host, Clock clock, Path globusDir) {
        this.model = model;
        this.settings = settings;
        this.ledger = ledger;
        this.submitter = submitter;
        this.host = host;
        this.clock = clock;
        this.globusDir = globusDir;
    }

    /**
     * @param dataDir CertWizard data directory
     * @return the ledger file location
     */
    public static Path ledgerFile(File dataDir) {
        return dataDir.toPath().resolve("auto-renew-ledger.properties");
    }

    /**
     * @param dataDir CertWizard data directory
     * @return the settings file location
     */
    public static Path settingsFile(File dataDir) {
        return dataDir.toPath().resolve("certwizard-settings.properties");
    }

    /**
     * Start periodic runs on a background daemon thread.
     *
     * @param initialDelay delay before the first run
     * @param period       time between runs
     */
    public synchronized void start(Duration initialDelay, Duration period) {
        if (executor != null) {
            return;
        }
        executor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "certwizard-auto-renew");
            t.setDaemon(true);
            return t;
        });
        executor.scheduleWithFixedDelay(this::runSafely, initialDelay.toMillis(), period.toMillis(), TimeUnit.MILLISECONDS);
    }

    /**
     * Run as soon as possible on the background thread (e.g. when the user
     * switches auto-renew on).
     */
    public synchronized void runSoon() {
        if (executor != null) {
            executor.execute(this::runSafely);
        }
    }

    public synchronized void stop() {
        if (executor != null) {
            executor.shutdownNow();
            executor = null;
        }
    }

    private void runSafely() {
        try {
            for (String line : runOnce()) {
                LOG.info("auto-renew: " + line);
            }
        } catch (Throwable t) {
            LOG.error("auto-renew run failed", t);
        }
    }

    /**
     * One pass. Synchronous; public for tests.
     *
     * @return a log of what was decided, one line per entry considered
     */
    public synchronized List<String> runOnce() {
        List<String> log = new ArrayList<>();
        if (!settings.isEnabled()) {
            log.add("disabled");
            return log;
        }
        if (!host.isOnline()) {
            log.add("offline; will try again on the next run");
            return log;
        }
        if (host.isBusy()) {
            log.add("another online task is running; will try again on the next run");
            return log;
        }
        followUpSubmitted(log);
        considerRenewals(log);
        return log;
    }

    private void followUpSubmitted(List<String> log) {
        for (String fp : ledger.inState(RenewalLedger.State.SUBMITTED)) {
            RenewalLedger.Record rec = ledger.get(fp);
            KeyStoreEntryWrapper entry = rec.newAlias == null ? null : model.getKeyStoreEntryMap().get(rec.newAlias);
            if (entry == null) {
                log.add("[" + rec.newAlias + "] renewal entry no longer in the keystore; stopped following it");
                record(fp, RenewalLedger.State.INSTALLED, rec.newAlias, "renewal entry removed by user", false);
                continue;
            }
            try {
                if (host.refreshFromCa(entry)) {
                    model.getClientKeyStore().reStore();
                    host.modelChanged();
                }
                X509Certificate issued = model.getClientKeyStore().getX509Certificate(rec.newAlias);
                if (issued == null || CertChainBuilder.isSelfSigned(issued)) {
                    String status = entry.getServerCertificateCSRInfo() == null ? "unknown" : entry.getServerCertificateCSRInfo().getStatus();
                    log.add("[" + rec.newAlias + "] waiting for the CA (status " + status + ")");
                    continue;
                }
                record(fp, RenewalLedger.State.INSTALLED, rec.newAlias, null, false);
                String msg = "Your renewed certificate [" + rec.newAlias + "] has been issued and installed in CertWizard, "
                        + "valid until " + issued.getNotAfter() + ".";
                if (settings.isUpdateGlobus()) {
                    msg += updateGlobusIfItHolds(fp, rec.newAlias);
                }
                log.add("[" + rec.newAlias + "] issued and installed");
                host.notifyUser("Certificate renewed", msg, false);
            } catch (Exception e) {
                log.add("[" + rec.newAlias + "] follow-up failed: " + e.getMessage());
            }
        }
    }

    private void considerRenewals(List<String> log) {
        Instant now = clock.instant();
        AutoRenewPolicy policy = new AutoRenewPolicy(settings.getWindow());
        for (KeyStoreEntryWrapper entry : new ArrayList<>(model.getKeyStoreEntryMap().values())) {
            String alias = entry.getAlias();
            try {
                if (!KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY.equals(entry.getEntryType())) {
                    continue;
                }
                X509Certificate cert = model.getClientKeyStore().getX509Certificate(alias);
                if (cert == null || CertChainBuilder.isSelfSigned(cert)) {
                    continue; // placeholder for a pending request
                }
                String fp = BundledCaCertificates.sha256Fingerprint(cert);
                RenewalLedger.Record rec = ledger.get(fp);
                Instant notAfter = cert.getNotAfter().toInstant();
                // Cheap local pre-checks so we only contact the CA about
                // certificates that could actually be renewed now.
                if (rec != null && rec.state != RenewalLedger.State.FAILED) {
                    String status = entry.getServerCertificateCSRInfo() == null ? null : entry.getServerCertificateCSRInfo().getStatus();
                    AutoRenewPolicy.Decision d = policy.decide(new AutoRenewPolicy.Facts().keyPair(true)
                            .serverStatus(status == null ? "VALID" : status).notAfter(notAfter).ledger(rec), now);
                    log.add("[" + alias + "] " + d);
                    if (rec.state == RenewalLedger.State.UNCERTAIN && warnedThisSession.add(fp)) {
                        host.notifyUser("Automatic renewal needs attention", "Certificate [" + alias + "]: " + d.reason, true);
                    }
                    continue;
                }
                if (now.isBefore(notAfter.minus(policy.getWindow()))) {
                    log.add("[" + alias + "] not due until " + notAfter.minus(policy.getWindow()));
                    continue;
                }
                // Refresh the CA's view of this certificate (status, email)
                // immediately before deciding - never act on stale data.
                if (host.refreshFromCa(entry)) {
                    model.getClientKeyStore().reStore();
                    host.modelChanged();
                }
                String status = entry.getServerCertificateCSRInfo() == null ? null : entry.getServerCertificateCSRInfo().getStatus();
                AutoRenewPolicy.Decision d = policy.decide(new AutoRenewPolicy.Facts()
                        .keyPair(true).serverStatus(status).notAfter(notAfter)
                        .newerEntryAlias(findNewerEntryFor(alias, cert)).ledger(rec), now);
                log.add("[" + alias + "] " + d);
                if (d.action == AutoRenewPolicy.Action.RENEW) {
                    submit(entry, fp, log);
                }
            } catch (Exception e) {
                log.add("[" + alias + "] skipped: " + e.getMessage());
            }
        }
    }

    private void submit(KeyStoreEntryWrapper entry, String fp, List<String> log) throws Exception {
        String alias = entry.getAlias();
        String email = entry.getServerCertificateCSRInfo().getUserEmail();
        String reason = submitter.ineligibilityReason(entry, email);
        if (reason != null) {
            log.add("[" + alias + "] cannot be renewed automatically: " + reason);
            if (warnedThisSession.add(fp)) {
                host.notifyUser("Automatic renewal not possible", "Certificate [" + alias + "] is due for renewal but: "
                        + reason + "\n\nPlease renew it manually.", true);
            }
            return;
        }
        String newAlias = uniqueAlias(alias + " (renewed " + DateTimeFormatter.ISO_LOCAL_DATE.withZone(ZoneOffset.UTC)
                .format(clock.instant()) + ")");
        // Durable marker BEFORE anything is sent.
        record(fp, RenewalLedger.State.ATTEMPTING, newAlias, null, true);
        RenewalSubmitter.Result result = submitter.submit(entry, email, newAlias);
        switch (result.getOutcome()) {
            case SUBMITTED:
                record(fp, RenewalLedger.State.SUBMITTED, newAlias, result.getMessage(), false);
                log.add("[" + alias + "] renewal submitted as [" + newAlias + "]");
                host.modelChanged();
                host.notifyUser("Certificate renewal requested",
                        "Certificate [" + alias + "] is due to expire, so CertWizard has requested its renewal.\n"
                                + "The new certificate will appear as [" + newAlias + "] and be installed automatically "
                                + "once the CA has approved it.", false);
                break;
            case REJECTED_BY_CA:
                record(fp, RenewalLedger.State.FAILED, newAlias, result.getMessage(), false);
                log.add("[" + alias + "] CA refused the renewal: " + result.getMessage());
                host.notifyUser("Automatic renewal refused", "The CA refused the renewal of [" + alias + "]: "
                        + result.getMessage() + "\nCertWizard will try again in "
                        + AutoRenewPolicy.RETRY_AFTER.toHours() + " hours (at most " + AutoRenewPolicy.MAX_ATTEMPTS + " times).", true);
                break;
            case NOT_ELIGIBLE:
                record(fp, RenewalLedger.State.FAILED, newAlias, result.getMessage(), false);
                log.add("[" + alias + "] not submitted: " + result.getMessage());
                break;
            default:
                record(fp, RenewalLedger.State.UNCERTAIN, newAlias, result.getMessage(), false);
                warnedThisSession.add(fp);
                log.add("[" + alias + "] renewal outcome uncertain: " + result.getMessage());
                host.notifyUser("Automatic renewal needs attention", "While renewing [" + alias + "]: " + result.getMessage()
                        + "\nThe request may or may not have reached the CA, so CertWizard will not resend it. "
                        + "Use Refresh, and renew manually if no renewal appears.", true);
        }
    }

    private void record(String fp, RenewalLedger.State state, String alias, String message, boolean attempt) {
        try {
            ledger.put(fp, state, clock.instant(), alias, message, attempt);
        } catch (Exception e) {
            throw new IllegalStateException("cannot record auto-renew state: " + e.getMessage(), e);
        }
    }

    /**
     * @return alias of another key entry for the same person/host whose
     * certificate (or pending-request placeholder) is newer than
     * <code>cert</code>, or null.
     */
    String findNewerEntryFor(String alias, X509Certificate cert) throws Exception {
        Set<String> me = subjectKey(cert);
        for (KeyStoreEntryWrapper other : model.getKeyStoreEntryMap().values()) {
            if (other.getAlias().equals(alias)
                    || !KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY.equals(other.getEntryType())) {
                continue;
            }
            X509Certificate oc = model.getClientKeyStore().getX509Certificate(other.getAlias());
            if (oc != null && oc.getNotBefore().after(cert.getNotBefore()) && subjectKey(oc).equals(me)) {
                return other.getAlias();
            }
        }
        return null;
    }

    /**
     * CN (without the " CSR cert" suffix CertWizard adds to request
     * placeholders), OU and L of a certificate's subject.
     */
    static Set<String> subjectKey(X509Certificate cert) {
        Set<String> key = new HashSet<>();
        X500Name name = X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
        for (ASN1ObjectIdentifier type : new ASN1ObjectIdentifier[]{BCStyle.CN, BCStyle.OU, BCStyle.L}) {
            for (RDN rdn : name.getRDNs(type)) {
                String v = IETFUtils.valueToString(rdn.getFirst().getValue()).trim();
                if (type.equals(BCStyle.CN) && v.endsWith(" CSR cert")) {
                    v = v.substring(0, v.length() - " CSR cert".length());
                }
                key.add(BCStyle.INSTANCE.oidToDisplayName(type) + "=" + v);
            }
        }
        return key;
    }

    private String uniqueAlias(String base) throws Exception {
        String candidate = base;
        for (int i = 2; model.getClientKeyStore().containsAlias(candidate); i++) {
            candidate = base + " " + i;
        }
        return candidate;
    }

    /**
     * If ~/.globus/usercert.pem holds the certificate that was just renewed,
     * replace usercert.pem/userkey.pem with the renewed pair.
     *
     * @return sentence to append to the user notification ("" if nothing done)
     */
    String updateGlobusIfItHolds(String oldFingerprint, String newAlias) {
        Path certFile = globusDir.resolve("usercert.pem");
        Path keyFile = globusDir.resolve("userkey.pem");
        if (!Files.isRegularFile(certFile) || !Files.isRegularFile(keyFile)) {
            return "";
        }
        try (InputStream in = Files.newInputStream(certFile)) {
            X509Certificate installed = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
            if (!BundledCaCertificates.sha256Fingerprint(installed).equals(oldFingerprint)) {
                return ""; // ~/.globus holds some other certificate - leave it alone
            }
        } catch (Exception e) {
            return "";
        }
        String stamp = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(ZoneOffset.UTC).format(clock.instant());
        Path certBackup = globusDir.resolve("usercert.pem." + stamp + ".bak");
        Path keyBackup = globusDir.resolve("userkey.pem." + stamp + ".bak");
        try {
            Files.copy(certFile, certBackup, StandardCopyOption.COPY_ATTRIBUTES);
            Files.copy(keyFile, keyBackup, StandardCopyOption.COPY_ATTRIBUTES);
            CertChainBuilder.Result chain = KeyStoreChains.complete(
                    model.getClientKeyStore().getCertificateChain(newAlias), CertChainBuilder.standard());
            PrivateKey key = model.getClientKeyStore().getPrivateKey(newAlias);
            GlobusCredentialWriter.write(certFile, keyFile, chain.toArray(), key, model.getPassword());
            List<String> problems = ExportVerifier.verifyGlobus(certFile, keyFile, model.getPassword(), chain.toArray(), key);
            if (!problems.isEmpty()) {
                restore(certBackup, certFile);
                restore(keyBackup, keyFile);
                return "\n\nUpdating ~/.globus failed verification (" + String.join("; ", problems)
                        + "), so the previous usercert.pem/userkey.pem were restored. Use Install to try again.";
            }
            return "\n\n~/.globus/usercert.pem and userkey.pem now hold the renewed certificate"
                    + (chain.isComplete() ? " and its full chain" : "") + ". The previous files were kept as "
                    + certBackup.getFileName() + " and " + keyBackup.getFileName() + ".";
        } catch (Exception e) {
            try {
                if (Files.exists(certBackup)) {
                    restore(certBackup, certFile);
                }
                if (Files.exists(keyBackup)) {
                    restore(keyBackup, keyFile);
                }
            } catch (Exception ignored) {
                // reported below
            }
            return "\n\nUpdating ~/.globus failed (" + e.getMessage() + "); use Install to do it manually.";
        }
    }

    private static void restore(Path backup, Path target) throws Exception {
        if (Files.exists(target)) {
            target.toFile().setWritable(true, true);
        }
        Files.copy(backup, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
    }
}
