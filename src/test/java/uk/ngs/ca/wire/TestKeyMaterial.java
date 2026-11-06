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

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Fixed, throw-away RSA key material used to make the recorded requests
 * deterministic. These keys were generated with openssl solely for these
 * tests and protect nothing. They live in test source (not
 * src/test/resources) so that they are never bundled into the application
 * jar.
 */
public final class TestKeyMaterial {

    private TestKeyMaterial() {
    }

    /** Self-signed "user" certificate (serial 4242) used for PPPK auth / renewal. */
    static final String AUTH_CERT_PEM =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIDXjCCAkagAwIBAgICEJIwDQYJKoZIhvcNAQELBQAwVzELMAkGA1UEBhMCVUsx\n" +
            "ETAPBgNVBAoMCGVTY2llbmNlMQ0wCwYDVQQLDARDTFJDMQswCQYDVQQHDAJETDEZ\n" +
            "MBcGA1UEAwwQZ29sZGVuIHRlc3QgdXNlcjAgFw0yNjExMDYxNTQwNDVaGA8yMTI2\n" +
            "MTAxMzE1NDA0NVowVzELMAkGA1UEBhMCVUsxETAPBgNVBAoMCGVTY2llbmNlMQ0w\n" +
            "CwYDVQQLDARDTFJDMQswCQYDVQQHDAJETDEZMBcGA1UEAwwQZ29sZGVuIHRlc3Qg\n" +
            "dXNlcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN+TggYMurpLaClZ\n" +
            "CqSyBDNXJnpGkeXHF1/xfYUpq9dYD/pqkzRD+6CBOcjxyIhD5ZErpqPn8K9CPA0u\n" +
            "02aiSVqFRPIYj/mdfdmbLSEPDnyPx9qtovR2MGo+0ZmWVCgP6PN7Un79OaXuYR1Y\n" +
            "CKfZBjt/NlaAZZ94aO0mLhSxhim1+IfRZR8Jm7Lj+dXmaRLVAUdnZ0Pxy3bnyFK4\n" +
            "SgeppgF6NXzunAG3oO6aKZ7UMfRGK9O0+ityaCEOYiWIyYdMze3D0uNfFJshHZw9\n" +
            "MG2X6nxVdQCyM5//WOUuOc52jEttwljGgzzgjs2P58o0FPVsf57GFQrMEuKmxQmV\n" +
            "9QWRl1ECAwEAAaMyMDAwHQYDVR0OBBYEFAZNnP6KyInM/bQLXt39lIBmJ3IIMA8G\n" +
            "A1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBANjx6CMFjZiv92wdZQox\n" +
            "giplMMTs6yeWW+3w/GTAG6xyykHEKjNVNuUJGX8mjHcVPAW5a2ArIufWcnCO2poO\n" +
            "vrfDXi3SwckhIOMKwnJxdvliOZYkdE5FNEv6T0Tbuy2TSbXxzlxIFB7j74+G/acR\n" +
            "8jR49qe2gv8kkaRq7eLyHHqN7h7fpRmhYuzwLSRSUR2XK2cyLmn4pw1glIR6thC/\n" +
            "BGsn4YhugRd7p7QBBEzoJ7Ack+dk7sgd9ahz9rtr8xyWKrV1OlmAXdnAd9qdahUF\n" +
            "1JiMXY2NwOMCpojUZFHfnGJtCmHPXsKKWcQSbTh4XhvgeT/jE61VEH0CmSPhiXFS\n" +
            "Cl0=\n" +
            "-----END CERTIFICATE-----\n";

    /** Private key matching {@link #AUTH_CERT_PEM}. */
    static final String AUTH_KEY_PEM =
            "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDfk4IGDLq6S2gp\n" +
            "WQqksgQzVyZ6RpHlxxdf8X2FKavXWA/6apM0Q/uggTnI8ciIQ+WRK6aj5/CvQjwN\n" +
            "LtNmoklahUTyGI/5nX3Zmy0hDw58j8faraL0djBqPtGZllQoD+jze1J+/Tml7mEd\n" +
            "WAin2QY7fzZWgGWfeGjtJi4UsYYptfiH0WUfCZuy4/nV5mkS1QFHZ2dD8ct258hS\n" +
            "uEoHqaYBejV87pwBt6Dumime1DH0RivTtPorcmghDmIliMmHTM3tw9LjXxSbIR2c\n" +
            "PTBtl+p8VXUAsjOf/1jlLjnOdoxLbcJYxoM84I7Nj+fKNBT1bH+exhUKzBLipsUJ\n" +
            "lfUFkZdRAgMBAAECggEAPR8J6lZ7i+eGi9s8VicWj+SQ79ewFiW2BbQy0P9B68a2\n" +
            "44pUQPMe7NO3NPCollwde/D3hxKnEXqliSMWhxXxwM3zOc4uOhrsp1tNXJ7Noo76\n" +
            "H5XdmUBgXwNacMcQrb0fvcSmmnHm2y6OnSOOhjiGBCj0dXR3k7+qy75m1aBsoaUL\n" +
            "hDRjMX6K/nopphWXxFwma18Vf86/ZFJU2knf4/TfLmOsgqHX7NNDLkJNBelNnkiX\n" +
            "/fgR9XyHWEXjlSy0oxCOdfaZpQL0eelc2ctNF3giywWqFxwmJyhRxX90xuJZ11tF\n" +
            "FV6V2wHx7dPnsRVC32mptZPPH5QA7noz8VJuK4aFwwKBgQDvbpOFs+bqrD31MRvx\n" +
            "yWJucbyy+0Xk7Lyq3yzxCynm6es5F/zG0p9GZSBikaqB82aNDw61g+QgHCFshhhy\n" +
            "ipuXRcZqTbyzzSxAPtYd+5G3xk6g738RXdmw/iHN5BVdN5iop7g24ZWc1w+FKI4I\n" +
            "ZhsWnc7/vF74EuGlofMY/M0NTwKBgQDvDA4FoK2luwnkmviiXg9V/m6PAbfoPTM/\n" +
            "9qjX+lLK+BySeCEKiOrJm8A+klzeVvzAIYRItFnwE4oXm2ttX5Dg1P9vmw//7iwX\n" +
            "2kSH/joXFs968iPn2YjBO0TUIYu0CUO1YmNY7d35i9NuBtVWZnzz4KFI99JeAr4J\n" +
            "ZnHkligpXwKBgDaJqXC7Gc46jaJcHVFl3dXqcmESe0k543/IdiQxtsmyXrISlLF1\n" +
            "KHKQdl/9bilLmABpfaA6+quVvMdLhCYTDH3Ylul/64vJIFtB9OO/eeGyehaOdxMt\n" +
            "nXiDao/LdFJXZ56DFaLqn3mqQw7BvhiLqX/tUklOTxOSuXNRAF6gttRhAoGAcCk5\n" +
            "0w4nK+HsrGTCUHzNuU2eVl86CS/eAh8b7eq4Oh/cWCUha63+bAY2V6WZCYHLKeMQ\n" +
            "DIUCxhCE9Lqp1zHF6phGGfmpsi3wZmi1SxHP89FyHH/MtRZugivrCZWL1Tebm1nE\n" +
            "v48sXdBrre5q3xVLf6pgQrp07ENhI0v8GIMT6QUCgYB1NZEzK1ehcmctw9JZW6zK\n" +
            "K2DJfSPKRJ69cGHqUrEIf4ZYz4dXayegAb9CMJvvLmBFwvcT89HHQkcY1XeT+s7P\n" +
            "1iDFLF7n7pArzVc4hE0EOllowDCGrOEOqYPst0hsui68zQbHACM3AR2loR3zLWSi\n" +
            "kMdw1ltHrZLppGQuxy2zCw==\n" +
            "-----END PRIVATE KEY-----\n";

    /** Key pair used to build the renewal PKCS#10 request. */
    static final String CSR_KEY_PEM =
            "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC3sOm/SyvA189L\n" +
            "lfWI3ta18zO7T3C5LrL4J3lwIX5MRuAbbavb0N0rINATQB7LcYBWghyBG1xU59XT\n" +
            "T9fN7XtDTkpQRWd0EOCHuJiI4QBbNBk6u1m5fZsddyqpQyYILvifp14BWXuUwYri\n" +
            "cKNzyFOLEZb5wZMfs9YHNsMQgnOL1uzp91KZj6hotNrr/JPZoX1K4ZMfaXwyDkt4\n" +
            "dEPfhCzTZc+ufE9Y90zZEA/lZXI9Luv6Sw/54fXQXlaSq92tmpFn2vLJMSju0dY6\n" +
            "dct7cBqLaJySvsCHPG4GxZAL5+cZwc/P97AiipsSzmZ+kweODm4AKacFSUBgGb9f\n" +
            "s7lx/j4JAgMBAAECggEABUO0e0dF/n2g4wdt9Ul/qVDKSYK+FgyU1ABbnl9TXY/F\n" +
            "cfvLal4azJbg58BVcZqz5SbO9tNIKuXHDsqRwoTdHMF0Z0cJ7z1hlfowIvIh3rtI\n" +
            "QtLmQCbtqGNHLXkvcJoaBYdYLh04qbt/RbyZLqMN4+Ux6MAHvaebiXLkFcfLVHVc\n" +
            "wEisABdI0q30CSp0RJrcI9dzFIjS6v1rl2aA7AP35uX8J2d5gNJtM9AN/PznyMod\n" +
            "ecPJZoHDFy+/w+GaDiOfhIR69MHpDJ7MWcfPPxxBi+EVV6Sr0N+Yu5sqvBJQvgzh\n" +
            "hBKgRTVXzftS9iwKcjy1uh+IN4BSZpWwKSI0qv/nFQKBgQDZlEX5+pwomZh8rD3J\n" +
            "SGYr8PINy5WzzHsOZZnhcrPOW2Rkq9BiOo8nlWg6U3CGO6fQ93p/G+NilmRdd6az\n" +
            "Dlblo0W2a9WcUmvbf2zM/wot0b5VWb+rpBhZHQfnFSih/rnUWLxNL2+76VhY91hA\n" +
            "CGgzIUTf0AtesGD9fB7kChf5NQKBgQDYILe/WmOUzb6IR8nFr8dl1iiA7x3mnKlG\n" +
            "BooPwh3mNGrnoplEI1tuutiwmACbOS9LRsqL2jCmp+NJQ7kWWWNFQNojODNm660H\n" +
            "OaIew+K3pzaZlVX5/yC6WZ7PeCeHS88I/+Jwos9/Zy+pwmHYsRKgBp9+Lqj9ia7G\n" +
            "NOaa1pjgBQKBgQCwM+XfpdblAk59WLfI1Dr6Buzfwyl/LG/TnvBZpZx714OcC5B8\n" +
            "nFPmiJaZ9YzBCHrFPkYTvjANXSH2l7mGdGxnGCySqQ2axRzX63/fHAPQS3XKhR42\n" +
            "EHQvZtVJjNcVKcawcxQ7pdjk4vpLQjRT1vsbvSub3U335vsFDYmuv4XeqQKBgFxf\n" +
            "54le7c8M/RGsdT4MOlJ5bUhma0ZE0Ui/xMSleDgLUWH9qjpoTk0OiU05OpEdqOwo\n" +
            "rquFr2ObwFZxHqvBut8/r7x76eRkeMjsxjEWElHio0CThnLaq7daVLliJqr6KNw0\n" +
            "2ijAPaW7ibCqBz4huM8y5Xp+IPZ0oYHP3HxzmlWtAoGAeUnQNJenAJE9SqmRmdW8\n" +
            "X3wnSdFDnzFhhnT0mQyaUDzeMtpSFmLcylWHtZJDk/pt4oUUflonSpt3tzG9gnPG\n" +
            "09QDhtqEYsprzzOsI9Jm5kfusngDCtCc5+cI8SqBjv93BaDCwwg1ZNXV5OmHkvDq\n" +
            "YykvmVsrT0+PXCaJoGP47to=\n" +
            "-----END PRIVATE KEY-----\n";

    public static X509Certificate authCert() throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(AUTH_CERT_PEM.getBytes(StandardCharsets.US_ASCII)));
    }

    public static PrivateKey authKey() throws Exception {
        return privateKey(AUTH_KEY_PEM);
    }

    public static KeyPair csrKeyPair() throws Exception {
        PrivateKey priv = privateKey(CSR_KEY_PEM);
        java.security.interfaces.RSAPrivateCrtKey crt = (java.security.interfaces.RSAPrivateCrtKey) priv;
        java.security.PublicKey pub = KeyFactory.getInstance("RSA").generatePublic(
                new java.security.spec.RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent()));
        return new KeyPair(pub, priv);
    }

    private static PrivateKey privateKey(String pem) throws Exception {
        String b64 = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(b64)));
    }
}
