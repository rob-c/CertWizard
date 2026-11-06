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
package uk.ngs.ca.wire;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import uk.ngs.ca.certificate.client.CAMotd;
import uk.ngs.ca.certificate.client.PingService;
import uk.ngs.ca.common.CaHttpClient;
import uk.ngs.ca.info.CAInfo;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Opt-in smoke test against the real CA server, using only the read-only GET
 * operations (ping, message of the day, latest version, CA info / RA list).
 * It never sends POST/PUT/DELETE. Run it on its own, so that no other test
 * has redirected the endpoints or initialised TLS first:
 * <pre>mvn test -Dtest=LiveCaServerReadOnlyTest -Dlive.ca=true</pre>
 * TLS trust is set up exactly as CertWizardMain does it: a JKS containing
 * the e-Science Root and CA 2B certificates via the javax.net.ssl.trustStore
 * system properties.
 */
public class LiveCaServerReadOnlyTest {

    @BeforeClass
    public static void trustTheEScienceRoots() throws Exception {
        Assume.assumeTrue("live CA test disabled (enable with -Dlive.ca=true)", Boolean.getBoolean("live.ca"));
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        for (String pem : Arrays.asList("/escience-root.pem", "/escience-2b.pem")) {
            try (InputStream in = LiveCaServerReadOnlyTest.class.getResourceAsStream(pem)) {
                ks.setCertificateEntry(pem, cf.generateCertificate(in));
            }
        }
        Path trustStore = Files.createTempFile("certwizard-truststore", ".jks");
        trustStore.toFile().deleteOnExit();
        try (OutputStream out = new FileOutputStream(trustStore.toFile())) {
            ks.store(out, "passwd".toCharArray());
        }
        System.setProperty("javax.net.ssl.trustStore", trustStore.toString());
        System.setProperty("javax.net.ssl.trustStorePassword", "passwd");
        CaHttpClient.setDefault(null); // the configured production client
    }

    @Test
    public void pingSucceeds() throws Exception {
        assertTrue(PingService.getPingService().ping());
    }

    @Test
    public void motdAndLatestVersionParse() {
        String motd = new CAMotd().getText();
        assertNotNull(motd);
        assertTrue(motd, motd.length() > 10);
        String latest = new CAMotd().getLatestVersion();
        assertTrue(latest, latest.matches("\\d+\\.\\d+\\.\\d+"));
        System.out.println("Live CA: latest CertWizard version " + latest + "; MOTD: " + motd);
    }

    @Test
    public void raListParses() throws Exception {
        String[] ras = new CAInfo().getRAs();
        assertTrue(ras.length > 10);
        assertEquals(2, ras[0].split(" ").length);
        System.out.println("Live CA: " + ras.length + " RAs, first [" + ras[0] + "], last [" + ras[ras.length - 1] + "]");
    }
}
