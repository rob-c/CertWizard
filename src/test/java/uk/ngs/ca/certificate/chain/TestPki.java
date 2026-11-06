package uk.ngs.ca.certificate.chain;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Throwaway PKI for tests: builds roots, intermediates and leaves with real
 * signatures. Nothing here touches the network or the user's files.
 */
public final class TestPki {

    private static final AtomicLong SERIAL = new AtomicLong(1000);

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * A certificate and its key pair.
     */
    public static final class Entity {
        public final X509Certificate cert;
        public final KeyPair keys;

        Entity(X509Certificate cert, KeyPair keys) {
            this.cert = cert;
            this.keys = keys;
        }
    }

    /**
     * Fluent certificate spec.
     */
    public static final class Spec {
        String subject;
        Entity issuer; // null = self-signed
        KeyPair keys;
        boolean ca;
        boolean basicConstraints = true;
        boolean keyIds = true;
        Instant notBefore = Instant.now().minus(Duration.ofDays(1));
        Instant notAfter = Instant.now().plus(Duration.ofDays(365));
        String aiaCaIssuersUrl;
        String crlDpUrl;
        boolean validitySet;
        String sigAlg;
        org.bouncycastle.asn1.x509.KeyPurposeId[] eku;

        public Spec issuedBy(Entity e) {
            this.issuer = e;
            return this;
        }

        public Spec ca(boolean ca) {
            this.ca = ca;
            return this;
        }

        public Spec keys(KeyPair kp) {
            this.keys = kp;
            return this;
        }

        public Spec noBasicConstraints() {
            this.basicConstraints = false;
            return this;
        }

        public Spec noKeyIdentifiers() {
            this.keyIds = false;
            return this;
        }

        public Spec validity(Instant from, Instant to) {
            this.notBefore = from;
            this.notAfter = to;
            this.validitySet = true;
            return this;
        }

        public Spec aia(String url) {
            this.aiaCaIssuersUrl = url;
            return this;
        }

        public Spec crlDp(String url) {
            this.crlDpUrl = url;
            return this;
        }

        public Spec sigAlg(String alg) {
            this.sigAlg = alg;
            return this;
        }

        public Spec eku(org.bouncycastle.asn1.x509.KeyPurposeId... purposes) {
            this.eku = purposes;
            return this;
        }

        public Entity build() {
            try {
                KeyPair kp = keys != null ? keys : rsa();
                if (ca && !validitySet) {
                    // CAs outlive the certificates they issue, as in real life.
                    notAfter = Instant.now().plus(Duration.ofDays(3650));
                }
                KeyPair signer = issuer == null ? kp : issuer.keys;
                X500Name issuerName = issuer == null ? new X500Name(subject)
                        : X500Name.getInstance(issuer.cert.getSubjectX500Principal().getEncoded());
                X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(issuerName,
                        BigInteger.valueOf(SERIAL.incrementAndGet()), Date.from(notBefore), Date.from(notAfter),
                        new X500Name(subject), kp.getPublic());
                JcaX509ExtensionUtils u = new JcaX509ExtensionUtils();
                if (basicConstraints) {
                    b.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
                }
                if (ca) {
                    b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
                } else {
                    b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
                }
                if (keyIds) {
                    b.addExtension(Extension.subjectKeyIdentifier, false, u.createSubjectKeyIdentifier(kp.getPublic()));
                    b.addExtension(Extension.authorityKeyIdentifier, false,
                            u.createAuthorityKeyIdentifier(signer.getPublic()));
                }
                if (aiaCaIssuersUrl != null) {
                    b.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(
                            new AccessDescription(AccessDescription.id_ad_caIssuers,
                                    new GeneralName(GeneralName.uniformResourceIdentifier, aiaCaIssuersUrl))));
                }
                if (crlDpUrl != null) {
                    GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, crlDpUrl);
                    b.addExtension(Extension.cRLDistributionPoints, false, new org.bouncycastle.asn1.x509.CRLDistPoint(
                            new org.bouncycastle.asn1.x509.DistributionPoint[]{new org.bouncycastle.asn1.x509.DistributionPoint(
                                    new org.bouncycastle.asn1.x509.DistributionPointName(new org.bouncycastle.asn1.x509.GeneralNames(gn)), null, null)}));
                }
                if (eku != null) {
                    b.addExtension(Extension.extendedKeyUsage, false, new org.bouncycastle.asn1.x509.ExtendedKeyUsage(eku));
                }
                String alg = sigAlg != null ? sigAlg
                        : signer.getPrivate().getAlgorithm().startsWith("EC") ? "SHA384withECDSA" : "SHA256withRSA";
                X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC")
                        .getCertificate(b.build(new JcaContentSignerBuilder(alg).setProvider("BC").build(signer.getPrivate())));
                return new Entity(cert, kp);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    private TestPki() {
    }

    public static Spec cert(String subject) {
        Spec s = new Spec();
        s.subject = subject;
        return s;
    }

    public static Entity root(String cn) {
        return cert("CN=" + cn + ",O=Test").ca(true).build();
    }

    public static Entity intermediate(String cn, Entity issuer) {
        return cert("CN=" + cn + ",O=Test").ca(true).issuedBy(issuer).build();
    }

    public static Entity leaf(String cn, Entity issuer) {
        return cert("CN=" + cn + ",O=Test").issuedBy(issuer).build();
    }

    public static KeyPair rsa() {
        return rsa(2048);
    }

    public static KeyPair rsa(int bits) {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(bits);
            return g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static KeyPair ecP384() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp384r1"));
            return g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
