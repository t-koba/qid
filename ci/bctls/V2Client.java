/*
 * Independent RFC 6961 v2 client for qid-tls interop. Driven by
 * qid-tls/tests/bctls_v2_interop.rs over line-oriented hex records on
 * stdin/stdout; no sockets are used.
 *
 * Bouncy Castle is distributed under the permissive Bouncy Castle licence
 * (MIT-style). CI pins the exact bcprov/bcutil/bctls jar versions.
 */

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Arrays;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.AbstractTlsClient;
import org.bouncycastle.tls.CertificateStatus;
import org.bouncycastle.tls.CertificateStatusRequestItemV2;
import org.bouncycastle.tls.CertificateStatusType;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.OCSPStatusRequest;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

public final class V2Client {
    private static final int SUITE = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;

    private static final class StatusProtocol extends TlsClientProtocol {
        private CertificateStatus captured;

        @Override
        protected void cleanupHandshake() {
            if (this.certificateStatus != null) {
                this.captured = this.certificateStatus;
            }
            super.cleanupHandshake();
        }

        CertificateStatus capturedStatus() {
            return this.captured;
        }
    }

    private static final class V2TlsClient extends AbstractTlsClient {
        V2TlsClient(TlsCrypto crypto) {
            super(crypto);
        }

        @Override
        protected ProtocolVersion[] getSupportedVersions() {
            return new ProtocolVersion[] { ProtocolVersion.TLSv12 };
        }

        @Override
        protected int[] getSupportedCipherSuites() {
            return new int[] { SUITE };
        }

        @Override
        protected Vector getMultiCertStatusRequest() {
            Vector items = new Vector();
            items.addElement(new CertificateStatusRequestItemV2(
                    CertificateStatusType.ocsp_multi, new OCSPStatusRequest(null, null)));
            return items;
        }

        @Override
        public void notifySecureRenegotiation(boolean secureRenegotiation) {
            // The Rust parent owns the SCSV/renegotiation policy for this fixture.
        }

        @Override
        public TlsAuthentication getAuthentication() {
            return new TlsAuthentication() {
                public void notifyServerCertificate(
                        org.bouncycastle.tls.TlsServerCertificate serverCertificate) {
                    // The qid fixture uses an ephemeral test CA; the Rust parent
                    // owns trust decisions. BC only parses and verifies the
                    // ServerKeyExchange signature over the certificate key.
                }

                public TlsCredentials getClientCredentials(
                        org.bouncycastle.tls.CertificateRequest certificateRequest) {
                    return null;
                }
            };
        }
    }

    public static void main(String[] args) {
        PrintWriter out = new PrintWriter(new BufferedWriter(
                new OutputStreamWriter(System.out, StandardCharsets.US_ASCII)), true);
        try {
            run(out);
        } catch (Throwable failure) {
            out.println("ERR " + failure);
            out.flush();
            System.exit(1);
        }
    }

    private static void run(PrintWriter out) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        TlsCrypto crypto = new JcaTlsCryptoProvider().setProvider("BC").create(null);
        StatusProtocol protocol = new StatusProtocol();
        protocol.connect(new V2TlsClient(crypto));

        BufferedReader in = new BufferedReader(
                new InputStreamReader(System.in, StandardCharsets.US_ASCII));
        byte[] buffer = new byte[32768];
        for (int round = 0; round < 64 && !protocol.isConnected(); ++round) {
            drain(protocol, out, buffer);
            String line = in.readLine();
            if (line == null) {
                throw new IOException("parent closed stdin before handshake completed");
            }
            if (line.startsWith("S ")) {
                protocol.offerInput(unhex(line.substring(2)));
            } else {
                throw new IOException("unexpected parent line: " + line);
            }
        }
        drain(protocol, out, buffer);
        if (!protocol.isConnected()) {
            throw new IOException("handshake did not complete in 64 rounds");
        }

        CertificateStatus status = protocol.capturedStatus();
        if (status == null || status.getStatusType() != CertificateStatusType.ocsp_multi) {
            throw new IOException("no ocsp_multi CertificateStatus received");
        }
        Vector responses = status.getOCSPResponseList();
        if (responses.size() != 2) {
            throw new IOException("expected two staples, got " + responses.size());
        }
        out.println("DONE " + status.getStatusType() + " " + responses.size()
                + " " + stapleHex(responses.elementAt(0))
                + " " + stapleHex(responses.elementAt(1)));
        out.flush();
    }

    private static void drain(StatusProtocol protocol, PrintWriter out, byte[] buffer)
            throws IOException {
        int count;
        while ((count = protocol.readOutput(buffer, 0, buffer.length)) > 0) {
            out.println("C " + hex(Arrays.copyOf(buffer, count)));
        }
        while ((count = protocol.readInput(buffer, 0, buffer.length)) > 0) {
            // Discard application plaintext; this harness asserts handshake state.
        }
    }

    private static String stapleHex(Object response) throws IOException {
        if (response == null) {
            return "-";
        }
        return hex(((OCSPResponse) response).getEncoded(ASN1Encoding.DER));
    }

    private static String hex(byte[] bytes) {
        StringBuilder text = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            text.append(Character.forDigit((value >> 4) & 0xF, 16));
            text.append(Character.forDigit(value & 0xF, 16));
        }
        return text.toString();
    }

    private static byte[] unhex(String text) throws IOException {
        if ((text.length() & 1) != 0) {
            throw new IOException("odd-length hex record");
        }
        byte[] bytes = new byte[text.length() / 2];
        for (int i = 0; i < bytes.length; ++i) {
            int high = Character.digit(text.charAt(2 * i), 16);
            int low = Character.digit(text.charAt(2 * i + 1), 16);
            if (high < 0 || low < 0) {
                throw new IOException("invalid hex record");
            }
            bytes[i] = (byte) ((high << 4) | low);
        }
        return bytes;
    }
}
