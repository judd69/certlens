package certlens;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * CertLens — X-ray X.509 certificates before they take a service down.
 *
 * Usage: certlens &lt;file...&gt; | --host host[:port]
 *        [--keystore file --storepass pass] [--format text|json|html]
 *        [--output file] [--warn-days N] [--fail-on expiring|expired|weak]
 *        [--no-color]
 * Exit codes: 0 ok, 1 gate tripped (--fail-on condition met), 2 usage/IO error.
 */
public final class Main {
    public static final String VERSION = "certlens 1.0.0";

    private Main() {}

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err, Instant.now()));
    }

    /** Runs the CLI against the given streams and reference instant; returns the exit code. */
    public static int run(String[] args, PrintStream out, PrintStream err, Instant reference) {
        List<String> files = new ArrayList<>();
        List<String> hosts = new ArrayList<>();
        List<String> keystores = new ArrayList<>();
        String storepass = "";
        String format = "text";
        String output = null;
        int warnDays = 30;
        String failOn = null;
        boolean color = true;

        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "--help":
                    out.print(usage());
                    return 0;
                case "--version":
                    out.println(VERSION);
                    return 0;
                case "--host":
                    if (++i >= args.length) {
                        return usageError(err, "--host needs a value");
                    }
                    hosts.add(args[i]);
                    break;
                case "--keystore":
                    if (++i >= args.length) {
                        return usageError(err, "--keystore needs a value");
                    }
                    keystores.add(args[i]);
                    break;
                case "--storepass":
                    if (++i >= args.length) {
                        return usageError(err, "--storepass needs a value");
                    }
                    storepass = args[i];
                    break;
                case "--format":
                    if (++i >= args.length) {
                        return usageError(err, "--format needs a value");
                    }
                    format = args[i];
                    if (!format.equals("text") && !format.equals("json") && !format.equals("html")) {
                        return usageError(err, "unknown format: " + format);
                    }
                    break;
                case "--output":
                    if (++i >= args.length) {
                        return usageError(err, "--output needs a value");
                    }
                    output = args[i];
                    break;
                case "--warn-days":
                    if (++i >= args.length) {
                        return usageError(err, "--warn-days needs a number");
                    }
                    try {
                        warnDays = Integer.parseInt(args[i]);
                    } catch (NumberFormatException e) {
                        return usageError(err, "--warn-days needs a number, got: " + args[i]);
                    }
                    if (warnDays < 0) {
                        return usageError(err, "--warn-days must not be negative");
                    }
                    break;
                case "--fail-on":
                    if (++i >= args.length) {
                        return usageError(err, "--fail-on needs a value");
                    }
                    failOn = args[i];
                    if (!failOn.equals("expiring") && !failOn.equals("weak") && !failOn.equals("expired")) {
                        return usageError(err, "unknown --fail-on value: " + failOn);
                    }
                    break;
                case "--no-color":
                    color = false;
                    break;
                default:
                    if (a.startsWith("--")) {
                        return usageError(err, "unknown option: " + a);
                    }
                    files.add(a);
            }
        }

        if (files.isEmpty() && hosts.isEmpty() && keystores.isEmpty()) {
            return usageError(err, "no input: give certificate files, --host, or --keystore");
        }

        List<TargetResult> targets = new ArrayList<>();
        for (String f : files) {
            Path path = Path.of(f);
            if (!Files.exists(path)) {
                err.println("error: file not found: " + f);
                return 2;
            }
            try {
                List<X509Certificate> certs = Loader.loadFile(path);
                targets.add(analyseTarget("file", f, certs, null, warnDays, reference));
            } catch (Exception e) {
                err.println("error: could not read " + f + ": " + messageOf(e));
                return 2;
            }
        }
        for (String ks : keystores) {
            Path path = Path.of(ks);
            if (!Files.exists(path)) {
                err.println("error: keystore not found: " + ks);
                return 2;
            }
            try {
                List<X509Certificate> certs = Loader.loadKeystore(path, storepass.toCharArray());
                targets.add(analyseTarget("keystore", ks, certs, null, warnDays, reference));
            } catch (Exception e) {
                err.println("error: could not read keystore " + ks + ": " + messageOf(e));
                return 2;
            }
        }
        for (String h : hosts) {
            String host = h;
            int port = 443;
            int colon = h.lastIndexOf(':');
            if (colon > 0 && h.substring(colon + 1).matches("[0-9]+")) {
                host = h.substring(0, colon);
                port = Integer.parseInt(h.substring(colon + 1));
            }
            try {
                List<X509Certificate> certs = Loader.loadHost(host, port);
                targets.add(analyseTarget("host", h, certs, host, warnDays, reference));
            } catch (Exception e) {
                // A failed host must not fail the whole run: record it and carry on.
                targets.add(new TargetResult(h, "host", messageOf(e)));
            }
        }

        Verdict overall = Verdict.HEALTHY;
        int succeeded = 0;
        for (TargetResult t : targets) {
            if (!t.failed()) {
                succeeded++;
                overall = Verdict.worst(overall, t.verdict);
            }
        }
        if (succeeded == 0) {
            for (TargetResult t : targets) {
                err.println("error: " + t.label + ": " + t.error);
            }
            return 2;
        }

        String rendered;
        switch (format) {
            case "json":
                rendered = Report.json(targets, overall, reference, warnDays);
                break;
            case "html":
                rendered = Report.html(targets, overall, reference, warnDays);
                break;
            default:
                rendered = Report.text(targets, overall, warnDays, color);
        }
        try {
            if (output != null) {
                Files.writeString(Path.of(output), rendered);
                out.println("Wrote " + format + " report to " + output + " (overall: " + overall + ")");
            } else {
                out.print(rendered);
            }
        } catch (IOException e) {
            err.println("error: could not write output: " + messageOf(e));
            return 2;
        }

        if (failOn != null) {
            int threshold = failOn.equals("expiring") ? 1 : failOn.equals("weak") ? 2 : 3;
            if (overall.severity() >= threshold) {
                err.println("gate tripped: overall verdict " + overall
                        + " meets --fail-on " + failOn);
                return 1;
            }
        }
        return 0;
    }

    static TargetResult analyseTarget(String kind, String label, List<X509Certificate> certs,
                                      String hostname, int warnDays, Instant reference) {
        List<CertInfo> infos = new ArrayList<>();
        for (int i = 0; i < certs.size(); i++) {
            infos.add(Analyzer.analyze(certs.get(i), reference, hostname, i == 0));
        }
        return new TargetResult(label, kind, infos, Analyzer.verdictFor(infos, hostname, warnDays));
    }

    static String messageOf(Exception e) {
        String m = e.getMessage();
        return m == null || m.isEmpty() ? e.getClass().getSimpleName() : m;
    }

    static int usageError(PrintStream err, String problem) {
        err.println("error: " + problem);
        err.print(usage());
        return 2;
    }

    static String usage() {
        return "Usage: certlens <file...> | --host host[:port]\n"
                + "       [--keystore file --storepass pass] [--format text|json|html]\n"
                + "       [--output file] [--warn-days N] [--fail-on expiring|expired|weak]\n"
                + "       [--no-color]\n"
                + "\n"
                + "Inputs: PEM files (bundles included), DER files, Java keystores,\n"
                + "        or a live host checked over a real TLS handshake.\n"
                + "Exit codes: 0 ok, 1 gate tripped, 2 usage/IO error.\n"
                + "Options:\n"
                + "  --help, --version  show help / version\n"
                + "  --warn-days N      leaf expiry warning window (default 30)\n"
                + "  --fail-on LEVEL    exit 1 when the overall verdict reaches LEVEL\n";
    }
}
