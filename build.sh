#!/bin/sh
# CertLens build: compile, run the JUnit 5 suite, package build/certlens.jar.
# Fails loudly (non-zero exit) if any test fails. Zero shipped dependencies;
# the JUnit jar in lib/ is a test dependency only and is gitignored.
set -e
cd "$(dirname "$0")"

if [ -z "$JAVA_HOME" ] && [ -d "$HOME/workspace/tools/jdk-21.0.12.1+1" ]; then
  JAVA_HOME="$HOME/workspace/tools/jdk-21.0.12.1+1"
fi
if [ -n "$JAVA_HOME" ]; then
  PATH="$JAVA_HOME/bin:$PATH"
fi
command -v java >/dev/null || { echo "error: java not found (set JAVA_HOME to a JDK 21+)"; exit 2; }
command -v javac >/dev/null || { echo "error: javac not found (set JAVA_HOME to a JDK 21+)"; exit 2; }

JUNIT_JAR="lib/junit-platform-console-standalone-1.11.4.jar"
[ -f "$JUNIT_JAR" ] || { echo "error: $JUNIT_JAR missing — see README for where it comes from"; exit 2; }

rm -rf build
mkdir -p build/classes build/test-classes
echo "== compile =="
find src -name '*.java' > build/sources.txt
javac -d build/classes @build/sources.txt
echo "== compile tests =="
find test -name '*.java' > build/test-sources.txt
javac -cp "build/classes:$JUNIT_JAR" -d build/test-classes @build/test-sources.txt
echo "== run tests =="
java -jar "$JUNIT_JAR" execute \
  --class-path "build/classes:build/test-classes:test" \
  --scan-class-path build/test-classes
echo "== package =="
jar --create --file build/certlens.jar --main-class certlens.Main -C build/classes .
echo "Built build/certlens.jar — run it with: java -jar build/certlens.jar --help"
