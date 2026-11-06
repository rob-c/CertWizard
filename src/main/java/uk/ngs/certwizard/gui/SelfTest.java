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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import uk.ngs.ca.certificate.chain.BundledCaCertificates;
import uk.ngs.ca.common.SystemStatus;
import uk.ngs.ca.tools.property.SysProperty;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Comparator;
import java.util.stream.Stream;

/**
 * Headless start-up check, run as {@code CertWizard --self-test}.
 * <p>
 * The macOS packaging build and CI launch the signed app bundle with this flag
 * to prove it can actually start: a bundle signed with the hardened runtime
 * but without the JIT entitlements dies in {@code JNI_CreateJavaVM}
 * (stfc/CertWizard#67), and nothing else exercises the packaged launcher.
 * <p>
 * It never opens a window and never touches the user's data directory
 * ({@code ~/.ca}): the truststore is built in a temporary directory that is
 * deleted afterwards.
 */
final class SelfTest {

    static final String FLAG = "--self-test";


    private SelfTest() {
    }

    /**
     * Run the self-test.
     *
     * @return the process exit status: 0 if every check passed, 1 otherwise
     */
    static int run(PrintStream out, PrintStream err) {
        SystemStatus status = SystemStatus.getInstance();
        File userDataDirectory = status.getCwDataDirectory();
        Path scratch = null;
        try {
            Security.addProvider(new BouncyCastleProvider());
            Provider bc = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
            if (bc == null) {
                throw new IllegalStateException("BouncyCastle provider is not registered");
            }

            String version = SysProperty.getValue("ngsca.certwizard.version");

            // Every bundled CA certificate, each checked against its pinned
            // SHA-256 fingerprint (throws if any is missing or altered).
            java.util.List<X509Certificate> caCerts = BundledCaCertificates.all();

            scratch = Files.createTempDirectory("certwizard-self-test");
            status.setCwDataDirectory(scratch.toFile());
            SysProperty.setupTrustStore();
            Path trustStoreFile = scratch.resolve(SysProperty.getValue("ngsca.truststore.file"));
            KeyStore trustStore = KeyStore.getInstance("JKS");
            try (InputStream in = Files.newInputStream(trustStoreFile)) {
                trustStore.load(in, SysProperty.getValue("ngsca.cert.truststore.password").toCharArray());
            }
            for (X509Certificate caCert : caCerts) {
                if (trustStore.getCertificateAlias(caCert) == null) {
                    throw new IllegalStateException("truststore is missing " + caCert.getSubjectX500Principal());
                }
            }

            String vmInfo = System.getProperty("java.vm.info", "");
            if (vmInfo.contains("interpreted mode")) {
                throw new IllegalStateException("JVM is running without a JIT compiler (" + vmInfo + ")");
            }
            long start = System.nanoTime();
            long checksum = exerciseJit();
            long jitMillis = (System.nanoTime() - start) / 1_000_000;

            out.printf("CertWizard self-test OK: %s; Java %s on %s %s (%s); %s %s; truststore holds %d CA certs; JIT loop %d ms (%x)%n",
                    version, System.getProperty("java.runtime.version"),
                    System.getProperty("os.name"), System.getProperty("os.arch"), vmInfo,
                    bc.getName(), bc.getVersionStr(), trustStore.size(), jitMillis, checksum);
            return 0;
        } catch (Throwable t) {
            err.println("CertWizard self-test FAILED: " + t);
            t.printStackTrace(err);
            return 1;
        } finally {
            status.setCwDataDirectory(userDataDirectory);
            deleteRecursively(scratch, err);
        }
    }

    /**
     * Hot loop: called enough times, and iterating enough, that HotSpot
     * compiles it (C1 and then C2) rather than only interpreting it.
     */
    private static long exerciseJit() {
        long acc = 0;
        for (int i = 1; i <= 2_000; i++) {
            acc += xorShift(i, 10_000);
        }
        return acc;
    }

    private static long xorShift(long seed, int rounds) {
        long x = seed;
        for (int i = 0; i < rounds; i++) {
            x ^= x << 13;
            x ^= x >>> 7;
            x ^= x << 17;
        }
        return x;
    }

    private static void deleteRecursively(Path dir, PrintStream err) {
        if (dir == null) {
            return;
        }
        try (Stream<Path> paths = Files.walk(dir)) {
            paths.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        } catch (IOException e) {
            err.println("CertWizard self-test: could not delete " + dir + ": " + e);
        }
    }
}
