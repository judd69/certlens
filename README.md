# CertLens

CertLens X-rays X.509 certificates before they take a service down.

Expired certificates are one of the most avoidable production outages there
is: the cert is sitting on disk, its expiry date is public, and nobody looked.
CertLens looks — at files, keystores, and live hosts — and answers with one
verdict per target, plus the evidence behind it.

## What it does

Inputs:

- **PEM files**, including multi-certificate bundles / chains (every cert in
  the file is parsed)
- **DER files**
- **Java keystores** (JKS / PKCS12 via `--keystore` + `--storepass`, one entry
  per alias)
- **Live hosts** (`--host example.com[:443]`), capturing the served chain over
  a real TLS handshake. If the handshake fails, that target is reported as an
  error and the rest of the run still completes. If an `https_proxy` /
  `HTTPS_PROXY` environment variable is set, the handshake is tunnelled through
  it with an HTTP CONNECT request.

Analysis per certificate: subject and issuer DN, serial, validity window
(notBefore / notAfter), days remaining relative to the run time, SANs
(DNS + IP), signature algorithm, public-key type and size (RSA / EC / DSA),
and a self-signed flag (subject == issuer *and* the signature verifies with
its own key).

Weak flags: MD5 or SHA1 signature, RSA under 2048 bits, EC under 224 bits,
any DSA key, expired, not yet valid, and hostname mismatch in `--host` mode
(SANs checked first, then CN; wildcard-aware, case-insensitive, and only the
leaf is checked against the hostname).

Verdict per target: **EXPIRED** if any cert is expired, else **WEAK** if any
weak flag is present, else **EXPIRING** if the leaf expires within
`--warn-days` (default 30), else **HEALTHY**. The overall verdict is the worst
across targets: EXPIRED > WEAK > EXPIRING > HEALTHY.

## Outputs

- Coloured text by default (`--no-color` to disable)
- JSON: `--format json`
- A single self-contained HTML report: `--format html --output report.html`
  (inline CSS/JS only — no external assets, so the file works anywhere)

## Usage

```
certlens <file...> | --host host[:port]
       [--keystore file --storepass pass] [--format text|json|html]
       [--output file] [--warn-days N] [--fail-on expiring|expired|weak]
       [--no-color]
```

Exit codes: `0` ok, `1` gate tripped (`--fail-on` condition met), `2`
usage / IO error (no stack trace).

## Build

Requires JDK 21+. Zero shipped dependencies — pure `javac`.

```sh
./build.sh   # compiles, runs the test suite, packages build/certlens.jar
java -jar build/certlens.jar --help
```

The JUnit 5 console jar used only for tests lives in `lib/` (gitignored, never
shipped). If it is missing, copy `junit-platform-console-standalone-1.11.4.jar`
there and re-run `./build.sh`.

## Real example output

Run on 30 Oct 2026 against the shipped examples (see below for how they were
generated):

```
$ java -jar build/certlens.jar --no-color examples/soon-expiring.pem examples/expired.pem
CertLens report - 2 target(s), overall: EXPIRED (warn within 30 days)

TARGET file: examples/soon-expiring.pem - EXPIRING
  [1] CN=soon.certlens.example,O=CertLens Examples
      Issuer:  CN=soon.certlens.example,O=CertLens Examples
      Serial:  863c1625bcc1152a
      Valid:   2026-10-30 02:30 UTC -> 2026-11-09 02:30 UTC (9 days left)
      SANs:    DNS=[soon.certlens.example] IP=[]
      Key:     RSA 2048 bits | Sig: SHA384withRSA | Self-signed: yes
      Flags:   none

TARGET file: examples/expired.pem - EXPIRED
  [1] CN=expired.certlens.example,O=CertLens Examples
      Issuer:  CN=expired.certlens.example,O=CertLens Examples
      Serial:  f93b498dbdeef78d
      Valid:   2025-01-01 02:30 UTC -> 2025-01-31 02:30 UTC (expired 638 days ago)
      SANs:    DNS=[expired.certlens.example] IP=[]
      Key:     RSA 2048 bits | Sig: SHA384withRSA | Self-signed: yes
      Flags:   expired
```

More real runs from the same session:

```
$ java -jar build/certlens.jar --no-color --keystore examples/example.jks --storepass changeit
CertLens report - 1 target(s), overall: EXPIRING (warn within 30 days)

TARGET keystore: examples/example.jks - EXPIRING
  [1] CN=soon.certlens.example,O=CertLens Examples
      Valid:   2026-10-30 02:30 UTC -> 2026-11-09 02:30 UTC (9 days left)
      Key:     RSA 2048 bits | Sig: SHA384withRSA | Self-signed: yes
      Flags:   none

$ java -jar build/certlens.jar --no-color examples/soon-expiring.pem --host nonexistent.invalid
CertLens report - 2 target(s), overall: EXPIRING (warn within 30 days)
TARGET file: examples/soon-expiring.pem - EXPIRING
  ...
TARGET host: nonexistent.invalid - ERROR: could not complete a TLS handshake with nonexistent.invalid:443 (Connection reset)
```

(The `...` above replaces the repeated soon-expiring cert block, shown in full
in the first example. The bad-host run exits 0 because one target succeeded;
a run where *every* target fails exits 2. In the sandbox the handshake error
reads "Connection reset" because Java sockets are network-policy-blocked
there — see Known limitation.)

Gate example — fail CI when anything is expired:

```
$ java -jar build/certlens.jar --fail-on expired examples/expired.pem
# ... report ...
# gate tripped: overall verdict EXPIRED meets --fail-on expired
$ echo $?
1
```

## Examples

`examples/` ships two generated certificates plus a bundle, a DER copy, and a
keystore (all throwaway keys, password `changeit` — demo fixtures only):

- `soon-expiring.pem` — self-signed, valid 10 days from generation
- `expired.pem` — self-signed with a genuinely past validity window
  (2025-01-01 to 2025-01-31, via `keytool -startdate "2025/01/01"`)
- `bundle.pem` — both certs concatenated
- `soon-expiring.der` — the soon-expiring cert in DER form
- `example.jks` — keystore holding the soon-expiring cert

Regenerate them with `sh examples/generate-examples.sh` (requires `keytool`).
Test fixtures in `test/fixtures/` (SHA1-signed cert, 1024-bit RSA cert,
CA-signed leaf, keystore) are generated by `sh test/generate-fixtures.sh`.
No certificate dates are faked anywhere in code: the expired example really
expired, and tests use reference instants derived from the certs themselves.

## Tests

36 JUnit 5 tests, all green in the build session, covering: PEM bundle and
DER parsing, keystore loading, SHA1 / small-RSA weak flags on real
certificates, MD5 / EC / DSA flag logic, self-signed detection (true and
CA-signed false), days-remaining math including negative and boundary cases,
hostname matching (exact, wildcard, too-deep wildcard, SAN-beats-CN, leaf
only), verdict ordering and the warn-days boundary, JSON escaping and
structure, HTML self-containment (no `http://`, `https://`, or `src=`), and
CLI exit codes (0 ok, 1 gate tripped, 2 usage/IO error).

## Known limitation

In the sandboxed build environment, Java's direct TCP connections are blocked
by a sandbox network policy (the sandbox answers Java sockets with a policy
message instead of the real network), so a successful live `--host` handshake
could not be demonstrated there — the error path, however, was verified
end-to-end (clean per-target error, run continues, exit codes as documented).
On a normal machine, `java -jar build/certlens.jar --host example.com`
performs a real handshake and reports the served chain. The hostname-mismatch
logic itself is covered by unit tests.

## License

MIT — see LICENSE.
