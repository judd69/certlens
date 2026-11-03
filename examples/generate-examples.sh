#!/bin/sh
# Generates the example certificates shipped in examples/ and the test fixtures
# in test/fixtures/. Everything here uses throwaway keys and the password
# "changeit" — these are demo fixtures, never real credentials.
# Requires keytool from any JDK 11+.
set -e
cd "$(dirname "$0")"

PASS=changeit
rm -f examples-tmp.jks soon.jks expired.jks
rm -f soon-expiring.pem expired.pem bundle.pem soon-expiring.der

# (a) Self-signed cert expiring soon: valid 10 days from generation time.
keytool -genkeypair -alias soon -keyalg RSA -keysize 2048 \
  -dname "CN=soon.certlens.example, O=CertLens Examples" \
  -ext "SAN=dns:soon.certlens.example" -validity 10 \
  -keystore soon.jks -storepass $PASS -keypass $PASS -noprompt
keytool -exportcert -alias soon -rfc -file soon-expiring.pem \
  -keystore soon.jks -storepass $PASS -noprompt
keytool -exportcert -alias soon -file soon-expiring.der \
  -keystore soon.jks -storepass $PASS -noprompt

# (b) Genuinely expired cert: validity window entirely in the past.
# keytool -startdate accepts a past date, so this cert really expired 2025-01-31.
keytool -genkeypair -alias expired -keyalg RSA -keysize 2048 \
  -dname "CN=expired.certlens.example, O=CertLens Examples" \
  -ext "SAN=dns:expired.certlens.example" \
  -startdate "2025/01/01" -validity 30 \
  -keystore expired.jks -storepass $PASS -keypass $PASS -noprompt
keytool -exportcert -alias expired -rfc -file expired.pem \
  -keystore expired.jks -storepass $PASS -noprompt

# Multi-cert bundle: the soon-expiring cert followed by the expired one.
cat soon-expiring.pem expired.pem > bundle.pem

# Keep the soon keystore as the keystore example (password: changeit).
cp soon.jks example.jks
rm -f soon.jks expired.jks examples-tmp.jks
echo "Generated: soon-expiring.pem, expired.pem, bundle.pem, soon-expiring.der, example.jks"
