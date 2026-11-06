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
package uk.ngs.ca.certificate.chain;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Downloads issuer certificates from the "CA Issuers" URLs in a certificate's
 * Authority Information Access extension (RFC 5280 4.2.2.1).
 * <p>
 * Only http and https URLs are followed, responses are size-limited, and
 * timeouts are short because this may be called while the user waits. Results,
 * including failures, are cached per URL for the life of the process so an
 * unreachable server costs at most one timeout. Downloaded certificates are
 * not trusted by virtue of being downloaded: {@link CertChainBuilder} only uses
 * one if the child's signature verifies with it.
 */
public final class AiaIssuerFetcher implements CertChainBuilder.IssuerFetcher {

    private static final Logger LOG = LogManager.getLogger(AiaIssuerFetcher.class);
    private static final String CA_ISSUERS_OID = "1.3.6.1.5.5.7.48.2";
    static final int MAX_RESPONSE_BYTES = 1 << 20;

    private static final AiaIssuerFetcher SHARED = new AiaIssuerFetcher(Duration.ofSeconds(3), Duration.ofSeconds(5));

    private final HttpClient client;
    private final Duration requestTimeout;
    private final Map<URI, List<X509Certificate>> cache = new ConcurrentHashMap<>();

    /**
     * @param connectTimeout TCP connect timeout
     * @param requestTimeout whole-request timeout
     */
    public AiaIssuerFetcher(Duration connectTimeout, Duration requestTimeout) {
        this.client = HttpClient.newBuilder()
                .connectTimeout(connectTimeout)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        this.requestTimeout = requestTimeout;
    }

    /**
     * @return process-wide instance with short default timeouts.
     */
    public static AiaIssuerFetcher shared() {
        return SHARED;
    }

    @Override
    public List<X509Certificate> fetchIssuerCandidates(X509Certificate child) {
        List<X509Certificate> result = new ArrayList<>();
        for (URI uri : caIssuerUris(child)) {
            result.addAll(cache.computeIfAbsent(uri, this::download));
        }
        return result;
    }

    /**
     * @param cert certificate
     * @return the http(s) CA Issuers URLs from its AIA extension, in order;
     * empty if there are none.
     */
    public static List<URI> caIssuerUris(X509Certificate cert) {
        byte[] ext = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (ext == null) {
            return Collections.emptyList();
        }
        List<URI> uris = new ArrayList<>();
        try {
            ASN1Primitive p = JcaX509ExtensionUtils.parseExtensionValue(ext);
            for (AccessDescription ad : AuthorityInformationAccess.getInstance(p).getAccessDescriptions()) {
                if (!CA_ISSUERS_OID.equals(ad.getAccessMethod().getId())) {
                    continue;
                }
                GeneralName loc = ad.getAccessLocation();
                if (loc.getTagNo() != GeneralName.uniformResourceIdentifier) {
                    continue;
                }
                URI uri = URI.create(loc.getName().toString());
                String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
                if (scheme.equals("http") || scheme.equals("https")) {
                    uris.add(uri);
                }
            }
        } catch (IOException | IllegalArgumentException e) {
            LOG.warn("Ignoring unparsable AIA extension in '" + cert.getSubjectX500Principal().getName() + "': " + e);
        }
        return uris;
    }

    private List<X509Certificate> download(URI uri) {
        uk.ngs.ca.common.NetworkGuard.checkAllowed(uri);
        try {
            HttpRequest request = HttpRequest.newBuilder(uri).timeout(requestTimeout).GET().build();
            HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream body = response.body()) {
                if (response.statusCode() != 200) {
                    LOG.warn("AIA issuer download from " + uri + " failed: HTTP " + response.statusCode());
                    return Collections.emptyList();
                }
                byte[] bytes = readLimited(body, MAX_RESPONSE_BYTES);
                return parseCertificates(bytes);
            }
        } catch (IOException e) {
            LOG.warn("AIA issuer download from " + uri + " failed: " + e);
            return Collections.emptyList();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Collections.emptyList();
        }
    }

    /**
     * Parse DER or PEM certificate(s), or a PKCS#7 certs-only bundle (.p7c).
     *
     * @param bytes encoded certificate data
     * @return X.509 certificates found; empty if unparsable
     */
    static List<X509Certificate> parseCertificates(byte[] bytes) {
        List<X509Certificate> certs = new ArrayList<>();
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            for (Certificate c : cf.generateCertificates(new ByteArrayInputStream(bytes))) {
                if (c instanceof X509Certificate) {
                    certs.add((X509Certificate) c);
                }
            }
        } catch (Exception e) {
            LOG.warn("Could not parse downloaded issuer certificate(s): " + e);
        }
        return certs;
    }

    private static byte[] readLimited(InputStream in, int limit) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            if (out.size() + n > limit) {
                throw new IOException("response larger than " + limit + " bytes");
            }
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }
}
