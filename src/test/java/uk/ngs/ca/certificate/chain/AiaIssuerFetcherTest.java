package uk.ngs.ca.certificate.chain;

import com.sun.net.httpserver.HttpServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.cert.Certificate;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

public class AiaIssuerFetcherTest {

    private HttpServer server;
    private String base;
    private final AtomicInteger hits = new AtomicInteger();
    private TestPki.Entity root;
    private TestPki.Entity inter;

    @Before
    public void start() throws Exception {
        root = TestPki.root("AIA Root");
        inter = TestPki.intermediate("AIA CA", root);
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/ca.der", ex -> {
            hits.incrementAndGet();
            byte[] body;
            try {
                body = inter.cert.getEncoded();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            ex.sendResponseHeaders(200, body.length);
            try (OutputStream o = ex.getResponseBody()) {
                o.write(body);
            }
        });
        server.createContext("/missing", ex -> {
            hits.incrementAndGet();
            ex.sendResponseHeaders(404, -1);
            ex.close();
        });
        server.createContext("/huge", ex -> {
            hits.incrementAndGet();
            ex.sendResponseHeaders(200, 0);
            try (OutputStream o = ex.getResponseBody()) {
                byte[] junk = new byte[64 * 1024];
                for (int i = 0; i < 40; i++) {
                    o.write(junk); // 2.5 MiB > limit
                }
            } catch (Exception ignored) {
                // client aborts once over the limit
            }
        });
        server.start();
        base = "http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":" + server.getAddress().getPort();
    }

    @After
    public void stop() {
        server.stop(0);
    }

    private AiaIssuerFetcher fetcher() {
        return new AiaIssuerFetcher(Duration.ofSeconds(2), Duration.ofSeconds(5));
    }

    @Test
    public void parsesCaIssuersUrlFromAia() {
        TestPki.Entity user = TestPki.cert("CN=AIA User,O=Test").issuedBy(inter).aia(base + "/ca.der").build();
        assertEquals(Collections.singletonList(URI.create(base + "/ca.der")), AiaIssuerFetcher.caIssuerUris(user.cert));
        assertTrue(AiaIssuerFetcher.caIssuerUris(root.cert).isEmpty());
    }

    @Test
    public void builderCompletesChainViaAiaDownload() {
        TestPki.Entity user = TestPki.cert("CN=AIA User,O=Test").issuedBy(inter).aia(base + "/ca.der").build();
        CertChainBuilder b = new CertChainBuilder(Collections.singletonList(root.cert), fetcher(), Clock.systemUTC());
        CertChainBuilder.Result r = b.build(user.cert, (Certificate[]) null);
        assertTrue(r.getProblems().toString(), r.isComplete());
        assertEquals(Arrays.asList(user.cert, inter.cert, root.cert), r.getChain());
    }

    @Test
    public void resultsAreCachedIncludingFailures() {
        AiaIssuerFetcher f = fetcher();
        TestPki.Entity ok = TestPki.cert("CN=Cached,O=Test").issuedBy(inter).aia(base + "/ca.der").build();
        TestPki.Entity bad = TestPki.cert("CN=Missing,O=Test").issuedBy(inter).aia(base + "/missing").build();
        assertEquals(1, f.fetchIssuerCandidates(ok.cert).size());
        assertEquals(1, f.fetchIssuerCandidates(ok.cert).size());
        assertTrue(f.fetchIssuerCandidates(bad.cert).isEmpty());
        assertTrue(f.fetchIssuerCandidates(bad.cert).isEmpty());
        assertEquals(2, hits.get());
    }

    @Test
    public void oversizedResponseIsRejected() {
        TestPki.Entity user = TestPki.cert("CN=Huge,O=Test").issuedBy(inter).aia(base + "/huge").build();
        assertTrue(fetcher().fetchIssuerCandidates(user.cert).isEmpty());
    }

    @Test
    public void unreachableServerIsHandled() {
        TestPki.Entity user = TestPki.cert("CN=Down,O=Test").issuedBy(inter).aia("http://127.0.0.1:1/ca.der").build();
        assertTrue(fetcher().fetchIssuerCandidates(user.cert).isEmpty());
    }

    @Test
    public void nonHttpUrlsAreIgnored() {
        TestPki.Entity user = TestPki.cert("CN=Ldap,O=Test").issuedBy(inter).aia("ldap://example.invalid/cn=ca").build();
        assertTrue(AiaIssuerFetcher.caIssuerUris(user.cert).isEmpty());
    }
}
