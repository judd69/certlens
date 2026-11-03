package certlens;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

/** Turns an X509Certificate into a CertInfo. The reference instant is injectable for tests. */
public final class Analyzer {
    private Analyzer() {}

    public static CertInfo analyze(X509Certificate cert, Instant reference) {
        return analyze(cert, reference, null, false);
    }

    /**
     * @param hostname expected hostname, or null when no hostname check applies
     * @param isLeaf   only the leaf of a served chain is checked against the hostname
     */
    public static CertInfo analyze(X509Certificate cert, Instant reference,
                                   String hostname, boolean isLeaf) {
        Instant notBefore = cert.getNotBefore().toInstant();
        Instant notAfter = cert.getNotAfter().toInstant();
        boolean expired = !reference.isBefore(notAfter);
        boolean notYetValid = reference.isBefore(notBefore);
        long daysRemaining = Math.floorDiv(notAfter.getEpochSecond() - reference.getEpochSecond(), 86400L);

        List<String> dns = new ArrayList<>();
        List<String> ips = new ArrayList<>();
        try {
            if (cert.getSubjectAlternativeNames() != null) {
                for (List<?> entry : cert.getSubjectAlternativeNames()) {
                    Integer type = (Integer) entry.get(0);
                    String value = String.valueOf(entry.get(1));
                    if (type == 2) {
                        dns.add(value);
                    } else if (type == 7) {
                        ips.add(value);
                    }
                }
            }
        } catch (CertificateParsingException e) {
            // unparseable SAN extension: report none rather than failing the run
        }

        String sigAlg = cert.getSigAlgName();
        PublicKey key = cert.getPublicKey();
        String keyType = key.getAlgorithm();
        int keySize = keySizeOf(key);

        boolean selfSigned = cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
        if (selfSigned) {
            try {
                cert.verify(key);
            } catch (Exception e) {
                selfSigned = false; // claims self-signed but its own key does not verify it
            }
        }

        List<String> flags = weakFlags(sigAlg, keyType, keySize, expired, notYetValid, false);
        if (isLeaf && hostname != null) {
            String cn = commonName(cert.getSubjectX500Principal().getName());
            if (!HostnameMatcher.matches(hostname, dns, cn)) {
                flags.add("hostname mismatch for " + hostname);
            }
        }

        return new CertInfo(
                cert.getSubjectX500Principal().getName(),
                cert.getIssuerX500Principal().getName(),
                cert.getSerialNumber().toString(16),
                notBefore, notAfter, daysRemaining, dns, ips,
                sigAlg, keyType, keySize, selfSigned, flags, expired, notYetValid);
    }

    /**
     * Pure weak-flag logic, unit-testable without constructing exotic certificates.
     * MD5/SHA1 signatures, RSA &lt; 2048, EC &lt; 224, any DSA, expired,
     * not-yet-valid and hostname mismatch are all flagged.
     */
    public static List<String> weakFlags(String sigAlg, String keyType, int keySize,
                                         boolean expired, boolean notYetValid,
                                         boolean hostnameMismatch) {
        List<String> flags = new ArrayList<>();
        String alg = sigAlg == null ? "" : sigAlg.toUpperCase(java.util.Locale.ROOT);
        if (alg.contains("MD5")) {
            flags.add("weak signature algorithm: " + sigAlg);
        } else if (alg.contains("SHA1") || alg.contains("SHA-1")) {
            flags.add("weak signature algorithm: " + sigAlg);
        }
        String kt = keyType == null ? "" : keyType.toUpperCase(java.util.Locale.ROOT);
        if ("RSA".equals(kt) && keySize >= 0 && keySize < 2048) {
            flags.add("small RSA key: " + keySize + " bits (minimum 2048)");
        } else if ("EC".equals(kt) && keySize >= 0 && keySize < 224) {
            flags.add("small EC key: " + keySize + " bits (minimum 224)");
        } else if ("DSA".equals(kt)) {
            flags.add("DSA public key (deprecated for TLS)");
        }
        if (expired) {
            flags.add("expired");
        }
        if (notYetValid) {
            flags.add("not yet valid");
        }
        if (hostnameMismatch) {
            flags.add("hostname mismatch");
        }
        return flags;
    }

    static int keySizeOf(PublicKey key) {
        try {
            if (key instanceof RSAPublicKey) {
                return ((RSAPublicKey) key).getModulus().bitLength();
            }
            if (key instanceof ECPublicKey) {
                return ((ECPublicKey) key).getParams().getOrder().bitLength();
            }
            if (key instanceof DSAPublicKey) {
                BigInteger p = ((DSAPublicKey) key).getParams().getP();
                return p == null ? -1 : p.bitLength();
            }
        } catch (Exception e) {
            // fall through to unknown size
        }
        return -1;
    }

    /** First CN from a DN string, or null. Uses LdapName so escaped commas are handled. */
    public static String commonName(String dn) {
        if (dn == null) {
            return null;
        }
        try {
            for (Rdn rdn : new LdapName(dn).getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    return String.valueOf(rdn.getValue());
                }
            }
        } catch (InvalidNameException e) {
            // fall through
        }
        return null;
    }

    /** Verdict for one target (one input's certificate list). The first cert is the leaf. */
    public static Verdict verdictFor(List<CertInfo> certs, String hostname, int warnDays) {
        boolean anyExpired = false;
        boolean anyWeak = false;
        for (CertInfo c : certs) {
            if (c.expired) {
                anyExpired = true;
            }
            if (!c.weakFlags.isEmpty()) {
                anyWeak = true;
            }
        }
        if (anyExpired) {
            return Verdict.EXPIRED;
        }
        if (anyWeak) {
            return Verdict.WEAK;
        }
        if (!certs.isEmpty()) {
            long leafDays = certs.get(0).daysRemaining;
            if (leafDays <= warnDays) {
                return Verdict.EXPIRING;
            }
        }
        return Verdict.HEALTHY;
    }
}
