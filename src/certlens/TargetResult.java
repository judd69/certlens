package certlens;

import java.util.List;

/** One analysed input: a file, a keystore, or a live host. */
public final class TargetResult {
    public final String label;
    public final String kind; // "file", "keystore", or "host"
    public final List<CertInfo> certs;
    public final String error; // non-null when this target could not be analysed
    public final Verdict verdict;

    public TargetResult(String label, String kind, List<CertInfo> certs, Verdict verdict) {
        this.label = label;
        this.kind = kind;
        this.certs = certs;
        this.error = null;
        this.verdict = verdict;
    }

    public TargetResult(String label, String kind, String error) {
        this.label = label;
        this.kind = kind;
        this.certs = List.of();
        this.error = error;
        this.verdict = null;
    }

    public boolean failed() {
        return error != null;
    }
}
