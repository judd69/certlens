package certlens;

/** Overall health verdict for one target, or for a whole run. Ordered worst-first. */
public enum Verdict {
    EXPIRED,
    WEAK,
    EXPIRING,
    HEALTHY;

    /** Severity rank: higher means worse. Used for overall verdicts and --fail-on gates. */
    public int severity() {
        switch (this) {
            case EXPIRED: return 3;
            case WEAK: return 2;
            case EXPIRING: return 1;
            default: return 0;
        }
    }

    public static Verdict worst(Verdict a, Verdict b) {
        return a.severity() >= b.severity() ? a : b;
    }
}
