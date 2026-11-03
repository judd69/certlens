package certlens;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Analysis of one X.509 certificate, relative to a reference instant. */
public final class CertInfo {
    public final String subject;
    public final String issuer;
    public final String serialHex;
    public final Instant notBefore;
    public final Instant notAfter;
    /** Whole days from the reference instant to notAfter, floored (negative when expired). */
    public final long daysRemaining;
    public final List<String> sansDns;
    public final List<String> sansIp;
    public final String signatureAlgorithm;
    public final String publicKeyType;
    /** Key size in bits, or -1 when not applicable (e.g. EdDSA). */
    public final int publicKeySize;
    public final boolean selfSigned;
    public final List<String> weakFlags;
    public final boolean expired;
    public final boolean notYetValid;

    public CertInfo(String subject, String issuer, String serialHex,
                    Instant notBefore, Instant notAfter, long daysRemaining,
                    List<String> sansDns, List<String> sansIp,
                    String signatureAlgorithm, String publicKeyType, int publicKeySize,
                    boolean selfSigned, List<String> weakFlags,
                    boolean expired, boolean notYetValid) {
        this.subject = subject;
        this.issuer = issuer;
        this.serialHex = serialHex;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
        this.daysRemaining = daysRemaining;
        this.sansDns = Collections.unmodifiableList(new ArrayList<>(sansDns));
        this.sansIp = Collections.unmodifiableList(new ArrayList<>(sansIp));
        this.signatureAlgorithm = signatureAlgorithm;
        this.publicKeyType = publicKeyType;
        this.publicKeySize = publicKeySize;
        this.selfSigned = selfSigned;
        this.weakFlags = Collections.unmodifiableList(new ArrayList<>(weakFlags));
        this.expired = expired;
        this.notYetValid = notYetValid;
    }
}
