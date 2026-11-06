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
package uk.ngs.ca.tools.property;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.ngs.ca.certificate.chain.BundledCaCertificates;
import uk.ngs.ca.common.SystemStatus;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Properties;

/**
 * This class manages the attributes which recorded in the property file.
 *
 * @author xw75
 */
public class SysProperty {

    private static final Logger myLogger = LogManager.getLogger(SysProperty.class);
    private static final String PROP_FILE = "/configure.properties";
    private static boolean isInitialized = false;
    private static final Properties properties = new Properties();

    private static final int timeoutMilliSecs = 5000;

    /**
     * Get the timeout in millisecs for the http(s) connections.
     *
     * @return
     */
    public static int getTimeoutMilliSecs() {
        return timeoutMilliSecs;
    }

    /**
     * Returns property value
     *
     * @param key property key
     * @return value of the key
     */
    public static String getValue(String key) {
        if (!SysProperty.isInitialized) {
            SysProperty.init();
        }

        String value = properties.getProperty(key);
        if (value == null) {
            throw new IllegalStateException("[SysProperty] could not find out the value of " + key + " in your property file.");
        }
        return value;
    }

    /**
     * Returns an optional property value.
     *
     * @param key          property key
     * @param defaultValue returned when the key is absent or blank
     * @return value of the key, or the default
     */
    public static String getValue(String key, String defaultValue) {
        if (!SysProperty.isInitialized) {
            SysProperty.init();
        }
        String value = properties.getProperty(key);
        return value == null || value.trim().isEmpty() ? defaultValue : value.trim();
    }

    /**
     * Returns an optional integer property value.
     *
     * @param key          property key
     * @param defaultValue returned when the key is absent, blank or not an
     *                     integer
     * @return value of the key, or the default
     */
    public static int getInt(String key, int defaultValue) {
        String value = getValue(key, null);
        if (value == null) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            myLogger.warn("[SysProperty] ignoring non-integer value '" + value + "' for " + key);
            return defaultValue;
        }
    }

    /**
     * Create the truststore.jks file on disk (typically under
     * '$USER_HOME/.ca/truststore.jks' unless otherwise specified in the
     * configure.properties file). This KeyStore is used to establish SSL with
     * the CA rest server.
     *
     * @throws IllegalStateException if any problem occurs creating and
     *                               deploying the trustore.jks file.
     */
    public static void setupTrustStore() {

        // create a keystore file used to hold the CA server's hostcert.
        // and load with the root cert
        // ==================================================================
        KeyStore keyStore = null;
        try {
            // All bundled UK e-Science CA certificates (Root 2007 + CA 2B,
            // Root 2026 + CA 3B), each checked against its pinned fingerprint.
            keyStore = KeyStore.getInstance("JKS", "SUN");
            keyStore.load(null, null);
            for (X509Certificate caCert : BundledCaCertificates.all()) {
                keyStore.setCertificateEntry(trustStoreAlias(caCert), caCert);
            }
        } catch (Exception ep) {
            throw new IllegalStateException("Error creating a trustStore.", ep);
        }

        // Always overwrite the file: ~/.ca/truststore.jks with the newly
        // created keystore.
        // ==================================================================
        String key = "ngsca.truststore.file";   // 'truststore.jks'
        String value = SysProperty.getValue(key);
        if (value == null) {
            throw new IllegalStateException("There is no trust store file name. Please check out config.properties.");
        }
        String homePath = SystemStatus.getInstance().getCwDataDirectory().getAbsolutePath();
        homePath = homePath + System.getProperty("file.separator") + value;

        String keyStoreFile = homePath; // ~/.ca/truststore.jks
        FileOutputStream fos = null;
        try {
            File f = new File(keyStoreFile);
            if (f.exists()) {
                if (!f.delete()) {
                    throw new IllegalStateException("Could not remove existing trustore file");
                }
            }
            f = new File(keyStoreFile); // re-create the file.
            fos = new FileOutputStream(f);
            keyStore.store(fos, SysProperty.getValue("ngsca.cert.truststore.password").toCharArray());
        } catch (Exception ep) {
            throw new IllegalStateException("A wrong happens when create a trustStore on the USER_HOME/.ca/", ep);
        } finally {
            try {
                fos.close();
            } catch (IOException ignored) {
            }
        }
    }

    /**
     * Alias for a CA certificate in the truststore. The two original entries
     * keep their historical aliases.
     */
    private static String trustStoreAlias(X509Certificate caCert) {
        String cn = caCert.getSubjectX500Principal().getName();
        if (cn.contains("CN=UK e-Science Root,")) {
            return "eScienceRoot";
        }
        if (cn.contains("CN=UK e-Science CA 2B,")) {
            return "eScienceRoot2B";
        }
        return "bundled-" + BundledCaCertificates.sha256Fingerprint(caCert).substring(0, 16);
    }

    private static void init() {
        myLogger.debug("[SysProperty] init...");
        try {
            InputStream input = SysProperty.class.getResourceAsStream(PROP_FILE);
            properties.load(input);
            input.close();
            isInitialized = true;
        } catch (IOException ioe) {
            ioe.printStackTrace();
            myLogger.error("[SysProperty] Property file is failed to load.");
        }
    }

}
