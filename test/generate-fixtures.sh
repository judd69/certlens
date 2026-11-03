#!/bin/sh
# Generates test fixtures in test/fixtures/ with keytool.
# Throwaway keys, password "changeit" — demo fixtures only, never real credentials.
set -e
cd "$(dirname "$0")"
mkdir -p fixtures
cd fixtures
PASS=changeit

# SHA1-signed RSA cert (weak signature algorithm).
keytool -genkeypair -alias sha1 -keyalg RSA -keysize 2048 -sigalg SHA1withRSA \
  -dname "CN=sha1.certlens.test" -validity 365 \
  -keystore sha1.jks -storepass $PASS -keypass $PASS -noprompt
keytool -exportcert -alias sha1 -rfc -file sha1.pem -keystore sha1.jks -storepass $PASS -noprompt

# Small RSA key (1024 bits).
keytool -genkeypair -alias small -keyalg RSA -keysize 1024 \
  -dname "CN=small.certlens.test" -validity 365 \
  -keystore small.jks -storepass $PASS -keypass $PASS -noprompt
keytool -exportcert -alias small -rfc -file small.pem -keystore small.jks -storepass $PASS -noprompt

# A CA plus a leaf it signed, so the leaf is NOT self-signed (healthy cert).
keytool -genkeypair -alias ca -keyalg RSA -keysize 2048 \
  -dname "CN=CertLens Test CA" -ext "BC:c" -validity 365 \
  -keystore ca.jks -storepass $PASS -keypass $PASS -noprompt
keytool -genkeypair -alias leaf -keyalg RSA -keysize 2048 \
  -dname "CN=leaf.certlens.test" -ext "SAN=dns:leaf.certlens.test" -validity 365 \
  -keystore leaf.jks -storepass $PASS -keypass $PASS -noprompt
keytool -certreq -alias leaf -file leaf.csr -keystore leaf.jks -storepass $PASS -noprompt
keytool -gencert -alias ca -infile leaf.csr -outfile leaf.cer -validity 365 \
  -keystore ca.jks -storepass $PASS -noprompt
keytool -exportcert -alias ca -rfc -file ca.pem -keystore ca.jks -storepass $PASS -noprompt
keytool -importcert -alias ca -file ca.pem -keystore leaf.jks -storepass $PASS -noprompt
keytool -importcert -alias leaf -file leaf.cer -keystore leaf.jks -storepass $PASS -noprompt
keytool -exportcert -alias leaf -rfc -file leaf.pem -keystore leaf.jks -storepass $PASS -noprompt
# Keystore fixture for the keystore-loading test (contains the CA-signed leaf).
cp leaf.jks keystore.jks
rm -f leaf.csr leaf.cer ca.jks sha1.jks small.jks leaf.jks
echo "Fixtures generated in test/fixtures/"
