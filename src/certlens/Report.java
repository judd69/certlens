package certlens;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;

/** Renders analysed targets as coloured text, JSON, or a self-contained HTML report. */
public final class Report {
    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'").withZone(ZoneId.of("UTC"));

    private Report() {}

    // ---- shared helpers -------------------------------------------------

    public static String escapeJson(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }

    static String escapeHtml(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;");
    }

    static String verdictColor(Verdict v, boolean color) {
        if (!color) {
            return "";
        }
        switch (v) {
            case EXPIRED: return "\u001B[1;31m";
            case WEAK: return "\u001B[31m";
            case EXPIRING: return "\u001B[33m";
            default: return "\u001B[32m";
        }
    }

    static final String RESET = "\u001B[0m";

    // ---- text -----------------------------------------------------------

    public static String text(List<TargetResult> targets, Verdict overall,
                              int warnDays, boolean color) {
        StringBuilder out = new StringBuilder();
        out.append("CertLens report - ").append(targets.size()).append(" target(s), ")
                .append("overall: ");
        if (color) {
            out.append(verdictColor(overall, true));
        }
        out.append(overall);
        if (color) {
            out.append(RESET);
        }
        out.append(" (warn within ").append(warnDays).append(" days)\n");
        for (TargetResult t : targets) {
            out.append("\nTARGET ").append(t.kind).append(": ").append(t.label).append(" - ");
            if (t.failed()) {
                out.append("ERROR: ").append(t.error).append("\n");
                continue;
            }
            if (color) {
                out.append(verdictColor(t.verdict, true));
            }
            out.append(t.verdict);
            if (color) {
                out.append(RESET);
            }
            out.append("\n");
            for (int i = 0; i < t.certs.size(); i++) {
                CertInfo c = t.certs.get(i);
                out.append("  [").append(i + 1).append("] ").append(c.subject).append("\n");
                out.append("      Issuer:  ").append(c.issuer).append("\n");
                out.append("      Serial:  ").append(c.serialHex).append("\n");
                out.append("      Valid:   ").append(FMT.format(c.notBefore)).append(" -> ")
                        .append(FMT.format(c.notAfter));
                if (c.daysRemaining >= 0) {
                    out.append(" (").append(c.daysRemaining).append(" days left)");
                } else {
                    out.append(" (expired ").append(-c.daysRemaining).append(" days ago)");
                }
                out.append("\n");
                out.append("      SANs:    DNS=").append(c.sansDns)
                        .append(" IP=").append(c.sansIp).append("\n");
                out.append("      Key:     ").append(c.publicKeyType);
                if (c.publicKeySize > 0) {
                    out.append(" ").append(c.publicKeySize).append(" bits");
                }
                out.append(" | Sig: ").append(c.signatureAlgorithm)
                        .append(" | Self-signed: ").append(c.selfSigned ? "yes" : "no").append("\n");
                out.append("      Flags:   ")
                        .append(c.weakFlags.isEmpty() ? "none" : String.join("; ", c.weakFlags))
                        .append("\n");
            }
        }
        return out.toString();
    }

    // ---- JSON -----------------------------------------------------------

    public static String json(List<TargetResult> targets, Verdict overall,
                              Instant reference, int warnDays) {
        StringBuilder out = new StringBuilder();
        out.append("{\n  \"tool\": \"certlens\",\n");
        out.append("  \"referenceTime\": \"").append(reference).append("\",\n");
        out.append("  \"warnDays\": ").append(warnDays).append(",\n");
        out.append("  \"overallVerdict\": \"").append(overall).append("\",\n");
        out.append("  \"targets\": [");
        for (int ti = 0; ti < targets.size(); ti++) {
            TargetResult t = targets.get(ti);
            if (ti > 0) {
                out.append(",");
            }
            out.append("\n    {\"label\": \"").append(escapeJson(t.label)).append("\", ");
            out.append("\"kind\": \"").append(escapeJson(t.kind)).append("\", ");
            if (t.failed()) {
                out.append("\"error\": \"").append(escapeJson(t.error)).append("\"}");
                continue;
            }
            out.append("\"verdict\": \"").append(t.verdict).append("\", \"certificates\": [");
            for (int ci = 0; ci < t.certs.size(); ci++) {
                CertInfo c = t.certs.get(ci);
                if (ci > 0) {
                    out.append(", ");
                }
                out.append("\n      {\"subject\": \"").append(escapeJson(c.subject)).append("\", ");
                out.append("\"issuer\": \"").append(escapeJson(c.issuer)).append("\", ");
                out.append("\"serial\": \"").append(escapeJson(c.serialHex)).append("\", ");
                out.append("\"notBefore\": \"").append(c.notBefore).append("\", ");
                out.append("\"notAfter\": \"").append(c.notAfter).append("\", ");
                out.append("\"daysRemaining\": ").append(c.daysRemaining).append(", ");
                out.append("\"sansDns\": ").append(stringListJson(c.sansDns)).append(", ");
                out.append("\"sansIp\": ").append(stringListJson(c.sansIp)).append(", ");
                out.append("\"signatureAlgorithm\": \"").append(escapeJson(c.signatureAlgorithm)).append("\", ");
                out.append("\"publicKeyType\": \"").append(escapeJson(c.publicKeyType)).append("\", ");
                out.append("\"publicKeySize\": ").append(c.publicKeySize).append(", ");
                out.append("\"selfSigned\": ").append(c.selfSigned).append(", ");
                out.append("\"weakFlags\": ").append(stringListJson(c.weakFlags)).append("}");
            }
            out.append("]}");
        }
        out.append(targets.isEmpty() ? "]" : "\n  ]");
        out.append("\n}\n");
        return out.toString();
    }

    private static String stringListJson(List<String> items) {
        StringBuilder out = new StringBuilder("[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) {
                out.append(", ");
            }
            out.append("\"").append(escapeJson(items.get(i))).append("\"");
        }
        return out.append("]").toString();
    }

    // ---- HTML -----------------------------------------------------------
    // Self-contained by construction: inline CSS and JS only, no external
    // references of any kind. Keep it that way - the test suite checks for it.

    public static String html(List<TargetResult> targets, Verdict overall,
                              Instant reference, int warnDays) {
        StringBuilder out = new StringBuilder();
        out.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
        out.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
        out.append("<title>CertLens report - ").append(overall).append("</title>\n<style>\n");
        out.append("body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;"
                + "margin:0;background:#fff;color:#0E151C}"
                + "header{padding:32px;max-width:1100px;margin:0 auto}"
                + "h1{font-size:44px;letter-spacing:-1px;margin:0 0 8px;text-transform:uppercase}"
                + ".meta{color:#5b6770}"
                + ".cards{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0}"
                + ".card{border-radius:28px;padding:20px 24px;background:#F1F3F5;flex:1;min-width:200px}"
                + ".card b{font-size:26px;display:block}"
                + ".card.EXPIRED,.card.WEAK{background:#F80048;color:#fff}"
                + ".card.EXPIRING{background:#F9C5D5}"
                + ".controls{padding:0 32px 12px;max-width:1100px;margin:0 auto;display:flex;gap:10px;flex-wrap:wrap}"
                + ".controls input,.controls select{padding:10px 14px;border-radius:999px;border:1px solid #d5dade;font-size:15px}"
                + "table{width:100%;border-collapse:collapse;max-width:1100px;margin:0 auto 40px}"
                + "th,td{text-align:left;padding:12px 16px;border-bottom:1px solid #e4e8eb;font-size:14px;vertical-align:top}"
                + "th{cursor:pointer;white-space:nowrap}"
                + ".pill{display:inline-block;padding:4px 12px;border-radius:999px;font-weight:700;font-size:12px;background:#F1F3F5}"
                + ".pill.EXPIRED,.pill.WEAK{background:#F80048;color:#fff}"
                + ".pill.EXPIRING{background:#F9C5D5}"
                + ".bar{height:10px;border-radius:999px;background:#F1F3F5;overflow:hidden;min-width:120px}"
                + ".bar i{display:block;height:100%;background:#0E151C}"
                + ".bar.EXPIRED i,.bar.WEAK i{background:#F80048}"
                + ".bar.EXPIRING i{background:#F9C5D5}"
                + ".err{color:#F80048;font-weight:700}"
                + "@media(max-width:700px){h1{font-size:30px}table{font-size:12px}}"
                + "\n</style>\n</head>\n<body>\n<header>\n<h1>CertLens report</h1>\n");
        out.append("<p class=\"meta\">Reference time ").append(escapeHtml(reference.toString()))
                .append(" | warn within ").append(warnDays).append(" days</p>\n");
        out.append("<div class=\"cards\">\n");
        out.append("<div class=\"card ").append(overall).append("\"><span>OVERALL VERDICT</span><b>")
                .append(overall).append("</b></div>\n");
        int total = 0;
        for (TargetResult t : targets) {
            total += t.certs.size();
        }
        out.append("<div class=\"card\"><span>TARGETS</span><b>").append(targets.size()).append("</b></div>\n");
        out.append("<div class=\"card\"><span>CERTIFICATES</span><b>").append(total).append("</b></div>\n");
        out.append("</div>\n</header>\n");
        out.append("<div class=\"controls\">"
                + "<input id=\"q\" placeholder=\"Filter certificates…\">"
                + "<select id=\"vf\"><option value=\"\">All verdicts</option>"
                + "<option>HEALTHY</option><option>EXPIRING</option>"
                + "<option>WEAK</option><option>EXPIRED</option></select></div>\n");
        out.append("<table id=\"t\"><thead><tr>"
                + "<th data-k=\"0\">Target</th><th data-k=\"1\">Subject</th>"
                + "<th data-k=\"2\">Valid to</th><th data-k=\"3\">Days left</th>"
                + "<th data-k=\"4\">Key / Sig</th><th data-k=\"5\">Flags</th>"
                + "<th>Timeline</th></tr></thead>\n<tbody>\n");
        for (TargetResult t : targets) {
            if (t.failed()) {
                out.append("<tr><td>").append(escapeHtml(t.label)).append("</td>"
                        + "<td colspan=\"6\" class=\"err\">ERROR: ").append(escapeHtml(t.error))
                        .append("</td></tr>\n");
                continue;
            }
            for (CertInfo c : t.certs) {
                Verdict row = c.expired ? Verdict.EXPIRED
                        : (!c.weakFlags.isEmpty() ? Verdict.WEAK : t.verdict);
                int pct = (int) Math.max(0, Math.min(100, (c.daysRemaining * 100L) / 365L));
                String barClass = c.expired ? "EXPIRED" : (c.daysRemaining <= warnDays ? "EXPIRING" : "");
                out.append("<tr data-v=\"").append(row).append("\">");
                out.append("<td>").append(escapeHtml(t.label)).append("</td>");
                out.append("<td>").append(escapeHtml(c.subject)).append("</td>");
                out.append("<td>").append(escapeHtml(FMT.format(c.notAfter))).append("</td>");
                out.append("<td>").append(c.daysRemaining).append("</td>");
                out.append("<td>").append(escapeHtml(c.publicKeyType)).append(" ")
                        .append(c.publicKeySize > 0 ? c.publicKeySize + " bits" : "")
                        .append(" | ").append(escapeHtml(c.signatureAlgorithm)).append("</td>");
                out.append("<td><span class=\"pill ").append(row).append("\">").append(row).append("</span> ")
                        .append(escapeHtml(String.join("; ", c.weakFlags))).append("</td>");
                out.append("<td><div class=\"bar ").append(barClass).append("\"><i style=\"width:")
                        .append(c.expired ? 100 : pct).append("%\"></i></div></td>");
                out.append("</tr>\n");
            }
        }
        out.append("</tbody></table>\n<script>\n");
        out.append("var q=document.getElementById('q'),vf=document.getElementById('vf'),"
                + "rows=[].slice.call(document.querySelectorAll('#t tbody tr'));\n"
                + "function apply(){var needle=q.value.toLowerCase();"
                + "rows.forEach(function(r){var ok=(!vf.value||r.getAttribute('data-v')===vf.value)"
                + "&&r.textContent.toLowerCase().indexOf(needle)>=0;"
                + "r.style.display=ok?'':'none';});}\n"
                + "q.addEventListener('input',apply);vf.addEventListener('change',apply);\n"
                + "document.querySelectorAll('#t th[data-k]').forEach(function(th){"
                + "th.addEventListener('click',function(){var k=+th.getAttribute('data-k'),"
                + "tb=document.querySelector('#t tbody'),list=[].slice.call(tb.children);"
                + "list.sort(function(a,b){return a.children[k].textContent.localeCompare(b.children[k].textContent);});"
                + "list.forEach(function(r){tb.appendChild(r);});});});\n");
        out.append("</script>\n</body>\n</html>\n");
        return out.toString();
    }
}
