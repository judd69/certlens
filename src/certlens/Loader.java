package certlens;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/** Loads certificates from PEM/DER files, Java keystores, and live TLS handshakes. */
public final class Loader {
    private Loader() {}

    /** Parses a file: PEM bundle (every cert in the file) or a single DER certificate. */
    public static List<X509Certificate> loadFile(Path path) throws Exception {
        byte[] bytes = Files.readAllBytes(path);
        String text = new String(bytes, StandardCharsets.US_ASCII);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        if (text.contains("-----BEGIN CERTIFICATE-----")) {
            List<X509Certificate> certs = new ArrayList<>();
            int idx = 0;
            while (true) {
                int begin = text.indexOf("-----BEGIN CERTIFICATE-----", idx);
                if (begin < 0) {
                    break;
                }
                int end = text.indexOf("-----END CERTIFICATE-----", begin);
                if (end < 0) {
                    throw new IOException("truncated PEM block in " + path);
                }
                String block = text.substring(begin, end + "-----END CERTIFICATE-----".length());
                try (ByteArrayInputStream in = new ByteArrayInputStream(
                        block.getBytes(StandardCharsets.US_ASCII))) {
                    certs.add((X509Certificate) factory.generateCertificate(in));
                }
                idx = end + 1;
            }
            if (certs.isEmpty()) {
                throw new IOException("no certificates found in " + path);
            }
            return certs;
        }
        // Otherwise treat the whole file as one DER certificate.
        try (ByteArrayInputStream in = new ByteArrayInputStream(bytes)) {
            return List.of((X509Certificate) factory.generateCertificate(in));
        } catch (Exception e) {
            throw new IOException("not a PEM bundle or DER certificate: " + path, e);
        }
    }

    /** Lists every alias certificate in a JKS or PKCS12 keystore (type auto-detected). */
    public static List<X509Certificate> loadKeystore(Path path, char[] password) throws Exception {
        KeyStore store = KeyStore.getInstance(path.toFile(), password);
        List<X509Certificate> certs = new ArrayList<>();
        Enumeration<String> aliases = store.aliases();
        while (aliases.hasMoreElements()) {
            Certificate c = store.getCertificate(aliases.nextElement());
            if (c instanceof X509Certificate) {
                certs.add((X509Certificate) c);
            }
        }
        if (certs.isEmpty()) {
            throw new IOException("no certificates found in keystore " + path);
        }
        return certs;
    }

    /** Captures the certificate chain a live host serves, without trusting it. */
    public static List<X509Certificate> loadHost(String host, int port) throws Exception {
        List<X509Certificate> captured = new ArrayList<>();
        TrustManager[] managers = new TrustManager[]{new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}
            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                captured.clear();
                for (X509Certificate c : chain) {
                    captured.add(c);
                }
            }
            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }};
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, managers, null);
        SSLSocketFactory factory = context.getSocketFactory();
        try (SSLSocket socket = openTlsSocket(factory, host, port)) {
            socket.setSoTimeout(10_000);
            SSLParameters params = socket.getSSLParameters();
            params.setServerNames(List.of(new javax.net.ssl.SNIHostName(host)));
            socket.setSSLParameters(params);
            socket.startHandshake();
        } catch (IOException e) {
            throw new IOException("could not complete a TLS handshake with "
                    + host + ":" + port + " (" + e.getMessage() + ")", e);
        }
        if (captured.isEmpty()) {
            throw new IOException("host " + host + ":" + port + " served no certificates");
        }
        return captured;
    }

    /** Opens a TLS socket, tunnelling through an HTTP CONNECT proxy when one is configured. */
    private static SSLSocket openTlsSocket(SSLSocketFactory factory, String host, int port) throws Exception {
        URI proxy = proxyFromEnv(host);
        if (proxy == null) {
            SSLSocket socket = (SSLSocket) factory.createSocket();
            socket.connect(new InetSocketAddress(host, port), 10_000);
            return socket;
        }
        Socket tunnel = new Socket();
        tunnel.connect(new InetSocketAddress(proxy.getHost(), proxy.getPort()), 10_000);
        tunnel.setSoTimeout(10_000);
        StringBuilder req = new StringBuilder();
        req.append("CONNECT ").append(host).append(":").append(port).append(" HTTP/1.1\r\n");
        req.append("Host: ").append(host).append(":").append(port).append("\r\n");
        if (proxy.getUserInfo() != null) {
            req.append("Proxy-Authorization: Basic ")
                    .append(Base64.getEncoder().encodeToString(
                            proxy.getUserInfo().getBytes(StandardCharsets.UTF_8)))
                    .append("\r\n");
        }
        req.append("\r\n");
        OutputStream out = tunnel.getOutputStream();
        out.write(req.toString().getBytes(StandardCharsets.US_ASCII));
        out.flush();
        // Read the proxy's response headers (up to a blank line); require a 2xx status.
        InputStream in = tunnel.getInputStream();
        StringBuilder headers = new StringBuilder();
        int b;
        while (headers.length() < 8192
                && (b = in.read()) != -1
                && !headers.toString().endsWith("\r\n\r\n")) {
            headers.append((char) b);
        }
        String statusLine = headers.toString().split("\r\n", 2)[0];
        if (!statusLine.matches("HTTP/\\S+ 2\\d\\d.*")) {
            tunnel.close();
            throw new IOException("proxy refused CONNECT to " + host + ":" + port + " (" + statusLine + ")");
        }
        SSLSocket socket = (SSLSocket) factory.createSocket(tunnel, host, port, true);
        socket.setSoTimeout(10_000);
        return socket;
    }

    /** https_proxy/HTTPS_PROXY from the environment, or null for direct connections. */
    static URI proxyFromEnv(String host) {
        if (host == null || host.equals("localhost") || host.equals("127.0.0.1") || host.equals("::1")) {
            return null;
        }
        String raw = System.getenv("https_proxy");
        if (raw == null || raw.isEmpty()) {
            raw = System.getenv("HTTPS_PROXY");
        }
        if (raw == null || raw.isEmpty()) {
            return null;
        }
        try {
            URI uri = new URI(raw);
            if (uri.getHost() == null || uri.getPort() <= 0) {
                return null;
            }
            return uri;
        } catch (Exception e) {
            return null;
        }
    }
}
