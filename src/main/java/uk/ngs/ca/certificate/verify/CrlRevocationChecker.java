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
package uk.ngs.ca.certificate.verify;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Checks whether a certificate has been revoked, using its issuer's CRL.
 * <p>
 * CRL locations come from the certificate's CRL Distribution Points
 * extension, falling back to the URLs the UK e-Science CA publishes for its
 * CAs (IGTF .crl_url / https://ca.grid-support.ac.uk/cacerts/). Downloaded
 * CRLs are cached on disk so revocation can still be checked offline while
 * the cached CRL is current. A CRL is only used if its issuer matches and its
 * signature verifies with the issuer certificate's key. A stale CRL (past
 * nextUpdate) never yields "not revoked", only "unknown".
 */
public final class CrlRevocationChecker {

    /**
     * Revocation outcome.
     */
    public enum Status {
        GOOD, REVOKED, UNKNOWN
    }

    /**
     * Result with a human-readable explanation.
     */
    public static final class Result {
        private final Status status;
        private final String detail;

        Result(Status status, String detail) {
            this.status = status;
            this.detail = detail;
        }

        public Status getStatus() {
            return status;
        }

        public String getDetail() {
            return detail;
        }
    }

    /**
     * Fetches CRL bytes; injectable for tests.
     */
    public interface CrlSource {
        /**
         * @param uri CRL URL
         * @return encoded CRL
         * @throws IOException on any failure
         */
        byte[] fetch(URI uri) throws IOException;
    }

    /**
     * Published CRL URLs for the UK e-Science CAs, keyed by the CA subject DN.
     */
    static final Map<X500Principal, String> KNOWN_CRLS = new HashMap<>();

    static {
        KNOWN_CRLS.put(new X500Principal("CN=UK e-Science CA 2B, OU=Authority, O=eScienceCA, C=UK"),
                "http://crl.ca.ngs.ac.uk/crl/escience2b.crl");
        KNOWN_CRLS.put(new X500Principal("CN=UK e-Science CA 3B, OU=Authority, O=eScienceCA, C=UK"),
                "http://crl.ca.ngs.ac.uk/crl/escience3b.crl");
        KNOWN_CRLS.put(new X500Principal("CN=UK e-Science Root, OU=Authority, O=eScienceRoot, C=UK"),
                "http://crl.ca.ngs.ac.uk/crl/root-crl.der");
        KNOWN_CRLS.put(new X500Principal("CN=UK e-Science Root 2026, OU=Authority, O=eScienceRoot, C=UK"),
                "http://crl.ca.ngs.ac.uk/crl/uk-root-crl.der");
    }

    static final int MAX_CRL_BYTES = 16 << 20;

    private final Path cacheDir;
    private final CrlSource source;
    private final boolean online;
    private final Clock clock;

    /**
     * @param cacheDir directory for cached CRLs (created if needed); may be
     *                 null to disable caching
     * @param source   where to fetch CRLs from
     * @param online   if false, only the cache is consulted
     * @param clock    clock
     */
    public CrlRevocationChecker(Path cacheDir, CrlSource source, boolean online, Clock clock) {
        this.cacheDir = cacheDir;
        this.source = source;
        this.online = online;
        this.clock = clock == null ? Clock.systemUTC() : clock;
    }

    /**
     * @param cacheDir cache directory (may be null)
     * @param online   whether downloads are allowed
     * @return checker that downloads over HTTP with short timeouts.
     */
    public static CrlRevocationChecker http(Path cacheDir, boolean online) {
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NORMAL).build();
        CrlSource src = uri -> {
            try {
                HttpResponse<InputStream> r = client.send(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(15)).GET().build(),
                        HttpResponse.BodyHandlers.ofInputStream());
                try (InputStream in = r.body()) {
                    if (r.statusCode() != 200) {
                        throw new IOException("HTTP " + r.statusCode());
                    }
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    byte[] buf = new byte[8192];
                    int n;
                    while ((n = in.read(buf)) != -1) {
                        if (out.size() + n > MAX_CRL_BYTES) {
                            throw new IOException("CRL larger than " + MAX_CRL_BYTES + " bytes");
                        }
                        out.write(buf, 0, n);
                    }
                    return out.toByteArray();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted", e);
            }
        };
        return new CrlRevocationChecker(cacheDir, src, online, Clock.systemUTC());
    }

    /**
     * @param cert   certificate to check
     * @param issuer the certificate that issued it
     * @return revocation status
     */
    public Result check(X509Certificate cert, X509Certificate issuer) {
        List<String> urls = crlUrls(cert);
        if (urls.isEmpty()) {
            return new Result(Status.UNKNOWN, "no CRL location is known for issuer '"
                    + cert.getIssuerX500Principal().getName() + "'");
        }
        List<String> why = new ArrayList<>();
        for (String url : urls) {
            X509CRL crl;
            boolean fromCache = false;
            String fetchError = null;
            try {
                crl = online ? download(url) : null;
                if (crl == null) {
                    crl = cached(url);
                    fromCache = crl != null;
                    if (crl == null) {
                        why.add(url + ": offline and no cached CRL");
                        continue;
                    }
                }
            } catch (IOException | RuntimeException e) {
                fetchError = e.getMessage();
                crl = cached(url);
                fromCache = crl != null;
                if (crl == null) {
                    why.add(url + ": " + fetchError);
                    continue;
                }
            }
            if (!crl.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                why.add(url + ": CRL is issued by '" + crl.getIssuerX500Principal().getName() + "', not the certificate's issuer");
                continue;
            }
            try {
                crl.verify(issuer.getPublicKey());
            } catch (Exception e) {
                why.add(url + ": CRL signature does not verify with the issuer's key");
                continue;
            }
            Date now = Date.from(clock.instant());
            X509CRLEntry entry = crl.getRevokedCertificate(cert);
            if (entry != null) {
                // A revocation is a revocation, even on a stale CRL.
                String reason = entry.getRevocationReason() == null ? "unspecified" : entry.getRevocationReason().toString();
                return new Result(Status.REVOKED, "revoked on " + entry.getRevocationDate() + " (reason: " + reason + ")");
            }
            if (crl.getNextUpdate() != null && now.after(crl.getNextUpdate())) {
                why.add(url + ": CRL expired on " + crl.getNextUpdate()
                        + (fromCache ? " (cached copy" + (fetchError != null ? "; download failed: " + fetchError : "; offline") + ")" : ""));
                continue;
            }
            String src = fromCache ? "cached CRL" : "CRL";
            return new Result(Status.GOOD, "not revoked (" + src + " issued " + crl.getThisUpdate()
                    + (crl.getNextUpdate() != null ? ", next update " + crl.getNextUpdate() : "") + ")");
        }
        return new Result(Status.UNKNOWN, String.join("\n", why));
    }

    /**
     * @param cert certificate
     * @return http(s) CRL URLs: from its CRL DP extension, then the known
     * UK e-Science CA location for its issuer.
     */
    static List<String> crlUrls(X509Certificate cert) {
        List<String> urls = new ArrayList<>();
        byte[] ext = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (ext != null) {
            try {
                ASN1Primitive p = JcaX509ExtensionUtils.parseExtensionValue(ext);
                for (DistributionPoint dp : CRLDistPoint.getInstance(p).getDistributionPoints()) {
                    DistributionPointName name = dp.getDistributionPoint();
                    if (name == null || name.getType() != DistributionPointName.FULL_NAME) {
                        continue;
                    }
                    for (GeneralName gn : GeneralNames.getInstance(name.getName()).getNames()) {
                        if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                            String u = gn.getName().toString();
                            String lower = u.toLowerCase(Locale.ROOT);
                            if ((lower.startsWith("http://") || lower.startsWith("https://")) && !urls.contains(u)) {
                                urls.add(u);
                            }
                        }
                    }
                }
            } catch (IOException | IllegalArgumentException ignored) {
                // fall through to known locations
            }
        }
        String known = KNOWN_CRLS.get(cert.getIssuerX500Principal());
        if (known != null && !urls.contains(known)) {
            urls.add(known);
        }
        return urls;
    }

    private X509CRL download(String url) throws IOException {
        byte[] bytes = source.fetch(URI.create(url));
        X509CRL crl = parse(bytes);
        if (cacheDir != null) {
            try {
                Files.createDirectories(cacheDir);
                Path tmp = Files.createTempFile(cacheDir, "crl", ".tmp");
                Files.write(tmp, bytes);
                Files.move(tmp, cacheFile(url), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (IOException ignored) {
                // caching is best effort
            }
        }
        return crl;
    }

    private X509CRL cached(String url) {
        if (cacheDir == null) {
            return null;
        }
        try {
            Path f = cacheFile(url);
            return Files.isRegularFile(f) ? parse(Files.readAllBytes(f)) : null;
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    private Path cacheFile(String url) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(url.getBytes(StandardCharsets.UTF_8));
            return cacheDir.resolve(HexFormat.of().formatHex(h).substring(0, 32) + ".crl");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static X509CRL parse(byte[] bytes) throws IOException {
        try {
            return (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(bytes));
        } catch (Exception e) {
            throw new IOException("not a valid CRL: " + e.getMessage(), e);
        }
    }
}
