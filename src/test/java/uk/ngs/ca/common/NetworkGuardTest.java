package uk.ngs.ca.common;

import org.junit.Test;

import java.net.URI;

import static org.junit.Assert.*;

public class NetworkGuardTest {

    @Test
    public void guardIsActiveForTheWholeTestSuite() {
        assertTrue("the Maven build must run tests with -D" + NetworkGuard.PROPERTY + "=true so no test can reach the real CA",
                Boolean.getBoolean(NetworkGuard.PROPERTY));
    }

    @Test
    public void realCaIsRefused() {
        for (String u : new String[]{"https://cwiz-live.ca.ngs.ac.uk/CSR", "http://crl.ca.ngs.ac.uk/crl/escience3b.crl",
                "https://10.0.0.1/x", "https://localhost.evil.com/"}) {
            try {
                NetworkGuard.checkAllowed(URI.create(u));
                fail("should refuse " + u);
            } catch (IllegalStateException expected) {
                assertTrue(expected.getMessage().contains("Refusing to contact"));
            }
        }
    }

    @Test
    public void loopbackAndReservedHostsAreAllowed() {
        for (String u : new String[]{"http://127.0.0.1:8080/CSR", "http://127.1.2.3/", "http://localhost:1/",
                "http://[::1]:9/", "http://crl.test.invalid/ca.crl", "http://ca.example/CA", "http://x.test/"}) {
            NetworkGuard.checkAllowed(URI.create(u));
        }
    }
}
