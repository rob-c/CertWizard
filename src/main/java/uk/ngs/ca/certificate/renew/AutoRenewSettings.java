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
import java.time.Duration;
import java.util.Properties;

/**
 * Auto-renew preferences, stored in the CertWizard data directory.
 */
public final class AutoRenewSettings {

    private static final String ENABLED = "autorenew.enabled";
    private static final String WINDOW_DAYS = "autorenew.windowDays";
    private static final String UPDATE_GLOBUS = "autorenew.updateGlobus";

    private final Path file;
    private final Properties props = new Properties();

    public AutoRenewSettings(Path file) {
        this.file = file;
        if (Files.isRegularFile(file)) {
            try (InputStream in = Files.newInputStream(file)) {
                props.load(in);
            } catch (IOException ignored) {
                // fall back to defaults
            }
        }
    }

    /**
     * @return whether auto-renew is on (default off: it sends requests to the CA).
     */
    public synchronized boolean isEnabled() {
        return Boolean.parseBoolean(props.getProperty(ENABLED, "false"));
    }

    /**
     * @return how long before expiry to renew (default 30 days, clamped to 7..56).
     */
    public synchronized Duration getWindow() {
        int days;
        try {
            days = Integer.parseInt(props.getProperty(WINDOW_DAYS, "30").trim());
        } catch (NumberFormatException e) {
            days = 30;
        }
        return Duration.ofDays(Math.max(7, Math.min(56, days)));
    }

    /**
     * @return whether to refresh ~/.globus/usercert.pem and userkey.pem when they
     * hold the certificate that was renewed (default on).
     */
    public synchronized boolean isUpdateGlobus() {
        return Boolean.parseBoolean(props.getProperty(UPDATE_GLOBUS, "true"));
    }

    public synchronized void setEnabled(boolean enabled) throws IOException {
        props.setProperty(ENABLED, Boolean.toString(enabled));
        save();
    }

    private void save() throws IOException {
        Path dir = file.toAbsolutePath().getParent();
        Files.createDirectories(dir);
        Path tmp = Files.createTempFile(dir, "settings", ".tmp");
        try (OutputStream out = Files.newOutputStream(tmp)) {
            props.store(out, "CertWizard settings");
        }
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
}
