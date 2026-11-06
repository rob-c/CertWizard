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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.Properties;

/**
 * Durable record of automatic renewal attempts, keyed by the SHA-256
 * fingerprint of the certificate being renewed. It is what stops auto-renew
 * from ever submitting two renewals for the same certificate, across
 * restarts and crashes.
 * <p>
 * An attempt is recorded as {@link State#ATTEMPTING} <em>before</em> the
 * request is sent. If CertWizard dies mid-request that record survives and is
 * treated as {@link State#UNCERTAIN}: the request may have reached the CA, so
 * it is never resent automatically.
 */
public final class RenewalLedger {

    /**
     * Per-certificate state.
     */
    public enum State {
        /**
         * Request about to be / being sent (crash-safety marker).
         */
        ATTEMPTING,
        /**
         * CA accepted the renewal; waiting for it to be issued.
         */
        SUBMITTED,
        /**
         * The renewed certificate has been issued and installed.
         */
        INSTALLED,
        /**
         * The CA refused the request; may be retried later.
         */
        FAILED,
        /**
         * The request may or may not have reached the CA; never retried automatically.
         */
        UNCERTAIN
    }

    /**
     * Immutable snapshot of one record.
     */
    public static final class Record {
        public final State state;
        public final Instant time;
        public final int attempts;
        public final String newAlias;
        public final String message;

        Record(State state, Instant time, int attempts, String newAlias, String message) {
            this.state = state;
            this.time = time;
            this.attempts = attempts;
            this.newAlias = newAlias;
            this.message = message;
        }
    }

    private final Path file;
    private final Properties props = new Properties();

    /**
     * @param file ledger file (created on first write)
     * @throws IOException if an existing ledger cannot be read
     */
    public RenewalLedger(Path file) throws IOException {
        this.file = file;
        if (Files.isRegularFile(file)) {
            try (InputStream in = Files.newInputStream(file)) {
                props.load(in);
            }
        }
    }

    /**
     * @param fingerprint certificate fingerprint
     * @return the record, or null if there is none. A stale ATTEMPTING record
     * (left by a crash) is reported as UNCERTAIN.
     */
    public synchronized Record get(String fingerprint) {
        String s = props.getProperty(fingerprint + ".state");
        if (s == null) {
            return null;
        }
        State state;
        try {
            state = State.valueOf(s);
        } catch (IllegalArgumentException e) {
            state = State.UNCERTAIN;
        }
        if (state == State.ATTEMPTING) {
            state = State.UNCERTAIN;
        }
        Instant time = Instant.ofEpochMilli(Long.parseLong(props.getProperty(fingerprint + ".time", "0")));
        int attempts = Integer.parseInt(props.getProperty(fingerprint + ".attempts", "0"));
        return new Record(state, time, attempts, props.getProperty(fingerprint + ".alias"),
                props.getProperty(fingerprint + ".message"));
    }

    /**
     * Record a state change and persist it immediately (atomically).
     *
     * @param fingerprint  certificate fingerprint
     * @param state        new state
     * @param time         when
     * @param newAlias     alias of the renewal entry (may be null)
     * @param message      CA/diagnostic message (may be null)
     * @param countAttempt whether this is a new submission attempt
     * @throws IOException if the ledger cannot be saved
     */
    public synchronized void put(String fingerprint, State state, Instant time, String newAlias, String message,
                                 boolean countAttempt) throws IOException {
        int attempts = Integer.parseInt(props.getProperty(fingerprint + ".attempts", "0"));
        props.setProperty(fingerprint + ".state", state.name());
        props.setProperty(fingerprint + ".time", Long.toString(time.toEpochMilli()));
        props.setProperty(fingerprint + ".attempts", Integer.toString(countAttempt ? attempts + 1 : attempts));
        setOrRemove(fingerprint + ".alias", newAlias != null ? newAlias : props.getProperty(fingerprint + ".alias"));
        setOrRemove(fingerprint + ".message", message);
        save();
    }

    /**
     * Forget a certificate's record (used when an attempt provably sent
     * nothing, so it should not count).
     *
     * @param fingerprint certificate fingerprint
     * @throws IOException if the ledger cannot be saved
     */
    public synchronized void remove(String fingerprint) throws IOException {
        for (String suffix : new String[]{".state", ".time", ".attempts", ".alias", ".message"}) {
            props.remove(fingerprint + suffix);
        }
        save();
    }

    /**
     * @return fingerprints with a record in the given state
     */
    public synchronized java.util.List<String> inState(State state) {
        java.util.List<String> out = new java.util.ArrayList<>();
        for (String k : props.stringPropertyNames()) {
            if (k.endsWith(".state")) {
                String fp = k.substring(0, k.length() - ".state".length());
                Record r = get(fp);
                if (r != null && r.state == state) {
                    out.add(fp);
                }
            }
        }
        return out;
    }

    private void setOrRemove(String key, String value) {
        if (value == null) {
            props.remove(key);
        } else {
            props.setProperty(key, value);
        }
    }

    private void save() throws IOException {
        Path dir = file.toAbsolutePath().getParent();
        Files.createDirectories(dir);
        Path tmp = Files.createTempFile(dir, "auto-renew", ".tmp");
        try (OutputStream out = Files.newOutputStream(tmp)) {
            props.store(out, "CertWizard automatic renewal ledger - do not edit while CertWizard is running");
        }
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
}
