package certlens;

import java.util.List;

/**
 * Hostname matching for TLS certificates: SAN DNS names win over the CN,
 * matching is case-insensitive, and a wildcard "*." matches exactly one label.
 */
public final class HostnameMatcher {
    private HostnameMatcher() {}

    /** Returns true when {@code hostname} is covered by the SAN list, or by the CN if no SANs exist. */
    public static boolean matches(String hostname, List<String> sansDns, String cn) {
        if (hostname == null || hostname.isEmpty()) {
            return true; // no hostname to check against
        }
        String host = hostname.toLowerCase(java.util.Locale.ROOT);
        if (sansDns != null && !sansDns.isEmpty()) {
            for (String san : sansDns) {
                if (matchesPattern(host, san)) {
                    return true;
                }
            }
            return false;
        }
        if (cn != null && !cn.isEmpty()) {
            return matchesPattern(host, cn);
        }
        return false;
    }

    static boolean matchesPattern(String host, String pattern) {
        String p = pattern.toLowerCase(java.util.Locale.ROOT).trim();
        if (p.startsWith("*.")) {
            String suffix = p.substring(1); // ".example.com"
            if (!host.endsWith(suffix)) {
                return false;
            }
            String left = host.substring(0, host.length() - suffix.length());
            return !left.isEmpty() && !left.contains(".");
        }
        return host.equals(p);
    }
}
