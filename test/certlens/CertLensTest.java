package certlens;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class CertLensTest {

    private static final Path EXAMPLES = Path.of("examples");
    private static final Path FIXTURES = Path.of("test", "fixtures");

    private static X509Certificate loadPem(Path p) throws Exception {
        try (var in = java.nio.file.Files.newInputStream(p)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    private static CertInfo info(long daysRemaining, List<String> flags, boolean expired) {
        Instant now = Instant.now();
        return new CertInfo("CN=test", "CN=test", "01", now, now.plusSeconds(daysRemaining * 86400L),
                daysRemaining, List.of(), List.of(), "SHA256withRSA", "RSA", 2048,
                false, flags, expired, false);
    }

    private static String runCli(int[] code, String... args) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        PrintStream out = new PrintStream(buf, true, StandardCharsets.UTF_8);
        ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
        code[0] = Main.run(args, out, new PrintStream(errBuf, true, StandardCharsets.UTF_8), Instant.now());
        return buf.toString(StandardCharsets.UTF_8);
    }

    // ---- loading -------------------------------------------------------

    @Test void pemBundleParsesEveryCert() throws Exception {
        List<X509Certificate> certs = Loader.loadFile(EXAMPLES.resolve("bundle.pem"));
        assertEquals(2, certs.size());
    }

    @Test void pemSingleParses() throws Exception {
        assertEquals(1, Loader.loadFile(EXAMPLES.resolve("soon-expiring.pem")).size());
    }

    @Test void derParses() throws Exception {
        List<X509Certificate> certs = Loader.loadFile(EXAMPLES.resolve("soon-expiring.der"));
        assertEquals(1, certs.size());
        assertTrue(certs.get(0).getSubjectX500Principal().getName().contains("soon.certlens.example"));
    }

    @Test void keystoreLoadsAliasCerts() throws Exception {
        List<X509Certificate> certs = Loader.loadKeystore(FIXTURES.resolve("keystore.jks"), "changeit".toCharArray());
        assertEquals(2, certs.size());
        assertTrue(certs.stream().anyMatch(
                c -> c.getSubjectX500Principal().getName().contains("leaf.certlens.test")));
    }

    // ---- weak flags ----------------------------------------------------

    @Test void weakFlagsSha1RealCert() throws Exception {
        CertInfo c = Analyzer.analyze(loadPem(FIXTURES.resolve("sha1.pem")), Instant.now());
        assertTrue(c.signatureAlgorithm.toUpperCase().contains("SHA1"));
        assertTrue(c.weakFlags.stream().anyMatch(f -> f.contains("SHA1")),
                "expected a SHA1 weak flag, got: " + c.weakFlags);
    }

    @Test void weakFlagsSmallRsaRealCert() throws Exception {
        CertInfo c = Analyzer.analyze(loadPem(FIXTURES.resolve("small.pem")), Instant.now());
        assertEquals(1024, c.publicKeySize);
        assertTrue(c.weakFlags.stream().anyMatch(f -> f.contains("1024")),
                "expected a small-RSA flag, got: " + c.weakFlags);
    }

    @Test void weakFlagsMd5Logic() {
        List<String> flags = Analyzer.weakFlags("MD5withRSA", "RSA", 2048, false, false, false);
        assertTrue(flags.stream().anyMatch(f -> f.contains("MD5")));
    }

    @Test void weakFlagsSha1Logic() {
        assertFalse(Analyzer.weakFlags("SHA1withRSA", "RSA", 2048, false, false, false).isEmpty());
    }

    @Test void weakFlagsEcSmallAndDsa() {
        assertTrue(Analyzer.weakFlags("SHA256withECDSA", "EC", 160, false, false, false)
                .stream().anyMatch(f -> f.contains("160")));
        assertTrue(Analyzer.weakFlags("SHA256withECDSA", "EC", 256, false, false, false).isEmpty());
        assertTrue(Analyzer.weakFlags("SHA256withDSA", "DSA", 2048, false, false, false)
                .stream().anyMatch(f -> f.contains("DSA")));
    }

    @Test void strongRsaHasNoFlags() {
        assertTrue(Analyzer.weakFlags("SHA256withRSA", "RSA", 2048, false, false, false).isEmpty());
        assertTrue(Analyzer.weakFlags("SHA384withRSA", "RSA", 4096, false, false, false).isEmpty());
    }

    // ---- self-signed ---------------------------------------------------

    @Test void selfSignedDetected() throws Exception {
        CertInfo c = Analyzer.analyze(loadPem(EXAMPLES.resolve("soon-expiring.pem")), Instant.now());
        assertTrue(c.selfSigned);
    }

    @Test void caSignedLeafIsNotSelfSigned() throws Exception {
        CertInfo c = Analyzer.analyze(loadPem(FIXTURES.resolve("leaf.pem")), Instant.now());
        assertFalse(c.selfSigned);
        assertTrue(c.issuer.contains("CertLens Test CA"), "issuer: " + c.issuer);
    }

    // ---- days-remaining math -------------------------------------------

    @Test void daysRemainingPositiveAndBoundary() throws Exception {
        X509Certificate cert = loadPem(EXAMPLES.resolve("soon-expiring.pem"));
        Instant notAfter = cert.getNotAfter().toInstant();
        assertEquals(5, Analyzer.analyze(cert, notAfter.minusSeconds(5 * 86400L)).daysRemaining);
        assertEquals(0, Analyzer.analyze(cert, notAfter).daysRemaining);
    }

    @Test void daysRemainingNegativeWhenExpired() throws Exception {
        CertInfo c = Analyzer.analyze(loadPem(EXAMPLES.resolve("expired.pem")), Instant.now());
        assertTrue(c.daysRemaining < 0, "daysRemaining: " + c.daysRemaining);
        assertTrue(c.expired);
        assertTrue(c.weakFlags.contains("expired"));
    }

    @Test void notYetValidFlag() {
        List<String> flags = Analyzer.weakFlags("SHA256withRSA", "RSA", 2048, false, true, false);
        assertTrue(flags.contains("not yet valid"));
    }

    // ---- hostname matching ---------------------------------------------

    @Test void hostnameExactAndCaseInsensitive() {
        assertTrue(HostnameMatcher.matches("Example.COM", List.of("example.com"), null));
        assertFalse(HostnameMatcher.matches("other.com", List.of("example.com"), null));
    }

    @Test void hostnameWildcardOneLabelOnly() {
        assertTrue(HostnameMatcher.matches("api.example.com", List.of("*.example.com"), null));
        assertFalse(HostnameMatcher.matches("example.com", List.of("*.example.com"), null));
        assertFalse(HostnameMatcher.matches("a.b.example.com", List.of("*.example.com"), null));
    }

    @Test void hostnameSanBeatsCn() {
        // SAN present but not matching: CN must NOT rescue it.
        assertFalse(HostnameMatcher.matches("leaf.certlens.test", List.of("other.test"), "leaf.certlens.test"));
        // No SANs: CN is used.
        assertTrue(HostnameMatcher.matches("leaf.certlens.test", List.of(), "leaf.certlens.test"));
    }

    @Test void hostnameMismatchFlagOnLeafOnly() throws Exception {
        X509Certificate leaf = loadPem(FIXTURES.resolve("leaf.pem"));
        CertInfo ok = Analyzer.analyze(leaf, Instant.now(), "leaf.certlens.test", true);
        assertTrue(ok.weakFlags.stream().noneMatch(f -> f.contains("mismatch")));
        CertInfo bad = Analyzer.analyze(leaf, Instant.now(), "wrong.example.com", true);
        assertTrue(bad.weakFlags.stream().anyMatch(f -> f.contains("mismatch")));
        CertInfo notLeaf = Analyzer.analyze(leaf, Instant.now(), "wrong.example.com", false);
        assertTrue(notLeaf.weakFlags.stream().noneMatch(f -> f.contains("mismatch")));
    }

    // ---- verdicts ------------------------------------------------------

    @Test void verdictOrderingExpiredBeatsWeak() {
        assertEquals(Verdict.EXPIRED, Analyzer.verdictFor(
                List.of(info(-3, List.of("expired"), true), info(100, List.of("weak signature"), false)), null, 30));
    }

    @Test void verdictOrderingWeakBeatsExpiring() {
        assertEquals(Verdict.WEAK, Analyzer.verdictFor(
                List.of(info(5, List.of("small RSA key"), false)), null, 30));
    }

    @Test void verdictExpiringAndHealthy() {
        assertEquals(Verdict.EXPIRING, Analyzer.verdictFor(List.of(info(10, List.of(), false)), null, 30));
        assertEquals(Verdict.HEALTHY, Analyzer.verdictFor(List.of(info(100, List.of(), false)), null, 30));
    }

    @Test void warnDaysBoundary() {
        assertEquals(Verdict.EXPIRING, Analyzer.verdictFor(List.of(info(30, List.of(), false)), null, 30));
        assertEquals(Verdict.HEALTHY, Analyzer.verdictFor(List.of(info(31, List.of(), false)), null, 30));
    }

    // ---- output formats -------------------------------------------------

    @Test void jsonEscapingAndStructure() throws Exception {
        assertEquals("a\\\"b\\\\c\\nd", Report.escapeJson("a\"b\\c\nd"));
        CertInfo c = Analyzer.analyze(loadPem(EXAMPLES.resolve("expired.pem")), Instant.now());
        String json = Report.json(
                List.of(new TargetResult("file", "expired.pem", List.of(c), Verdict.EXPIRED)),
                Verdict.EXPIRED, Instant.now(), 30);
        assertTrue(json.contains("\"overallVerdict\": \"EXPIRED\""));
        assertTrue(json.contains("\"daysRemaining\": " + c.daysRemaining));
        assertTrue(json.contains("\"sansDns\""));
    }

    @Test void htmlIsSelfContained() throws Exception {
        int[] code = new int[1];
        String html = runCli(code, "--format", "html", "--no-color",
                EXAMPLES.resolve("soon-expiring.pem").toString(),
                EXAMPLES.resolve("expired.pem").toString());
        assertEquals(0, code[0]);
        assertFalse(html.contains("http://"), "HTML must not reference http://");
        assertFalse(html.contains("https://"), "HTML must not reference https://");
        assertFalse(html.contains("src="), "HTML must not load external resources");
        assertTrue(html.contains("CertLens report"));
        assertTrue(html.contains("EXPIRED"));
    }

    @Test void htmlContainsVerdictCardsAndTable() throws Exception {
        CertInfo c = Analyzer.analyze(loadPem(EXAMPLES.resolve("expired.pem")), Instant.now());
        String html = Report.html(
                List.of(new TargetResult("file", "expired.pem", List.of(c), Verdict.EXPIRED)),
                Verdict.EXPIRED, Instant.now(), 30);
        assertTrue(html.contains("OVERALL VERDICT"));
        assertTrue(html.contains("id=\"q\"")); // filter input
        assertTrue(html.contains("bar")); // timeline bars
    }

    // ---- CLI exit codes -------------------------------------------------

    @Test void cliHelpAndVersion() {
        int[] code = new int[1];
        String help = runCli(code, "--help");
        assertEquals(0, code[0]);
        assertTrue(help.contains("Usage: certlens"));
        String version = runCli(code, "--version");
        assertEquals(0, code[0]);
        assertTrue(version.contains("certlens 1.0.0"));
    }

    @Test void cliMissingFileExit2() {
        int[] code = new int[1];
        runCli(code, "does-not-exist.pem");
        assertEquals(2, code[0]);
    }

    @Test void cliUnknownFlagExit2() {
        int[] code = new int[1];
        runCli(code, "--bogus");
        assertEquals(2, code[0]);
    }

    @Test void cliGateTrippedExit1() {
        int[] code = new int[1];
        runCli(code, "--fail-on", "expired", EXAMPLES.resolve("expired.pem").toString());
        assertEquals(1, code[0]);
    }

    @Test void cliGateNotTrippedExit0() {
        int[] code = new int[1];
        runCli(code, "--fail-on", "expired", FIXTURES.resolve("leaf.pem").toString());
        assertEquals(0, code[0]);
    }

    @Test void cliHealthyExit0AndNoColor() {
        int[] code = new int[1];
        String out = runCli(code, "--no-color", FIXTURES.resolve("leaf.pem").toString());
        assertEquals(0, code[0]);
        assertTrue(out.contains("HEALTHY"));
        assertFalse(out.contains("\u001B"), "no-color output must not contain ANSI escapes");
    }

    @Test void cliKeystoreExit0() {
        int[] code = new int[1];
        String out = runCli(code, "--no-color",
                "--keystore", FIXTURES.resolve("keystore.jks").toString(),
                "--storepass", "changeit");
        assertEquals(0, code[0]);
        assertTrue(out.contains("HEALTHY"));
    }

    @Test void cliJsonOutput() {
        int[] code = new int[1];
        String out = runCli(code, "--format", "json", EXAMPLES.resolve("expired.pem").toString());
        assertEquals(0, code[0]);
        assertTrue(out.contains("\"overallVerdict\": \"EXPIRED\""));
    }

    @Test void cliLabelsKindsInRightOrder() {
        int[] code = new int[1];
        String out = runCli(code, "--no-color", EXAMPLES.resolve("soon-expiring.pem").toString());
        assertEquals(0, code[0]);
        assertTrue(out.contains("TARGET file: " + EXAMPLES.resolve("soon-expiring.pem")));
        String json = runCli(code, "--format", "json", EXAMPLES.resolve("soon-expiring.pem").toString());
        assertTrue(json.contains("\"label\": \"" + EXAMPLES.resolve("soon-expiring.pem") + "\""));
        assertTrue(json.contains("\"kind\": \"file\""));
    }

    @Test void cliTextOutputShowsRealFields() throws Exception {
        int[] code = new int[1];
        String out = runCli(code, "--no-color", EXAMPLES.resolve("soon-expiring.pem").toString());
        assertEquals(0, code[0]);
        assertTrue(out.contains("soon.certlens.example"));
        assertTrue(out.contains("SHA384withRSA") || out.contains("SHA256withRSA"));
        assertTrue(out.contains("2048 bits"));
    }
}
