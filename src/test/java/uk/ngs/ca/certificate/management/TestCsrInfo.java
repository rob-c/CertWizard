package uk.ngs.ca.certificate.management;

/**
 * Builds the CA-side status record (normally parsed from the CA server's
 * reply) for tests in other packages.
 */
public final class TestCsrInfo {

    private TestCsrInfo() {
    }

    public static CertificateCSRInfo of(String status, String email, String id) {
        CertificateCSRInfo info = new CertificateCSRInfo();
        info.setStatus(status);
        info.setUserEmail(email);
        info.setId(id);
        return info;
    }
}
