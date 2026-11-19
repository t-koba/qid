/* Test-only TLS 1.3 TLS-POK peer for qid-tls's ignored interop test.
 *
 * This file is built by build.sh against a temporary wolfSSL installation;
 * no wolfSSL source or binaries are stored in this repository.
 */
#define _POSIX_C_SOURCE 200809L

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define RAW_PUBLIC_KEY 2
#define PSK_CIPHER_NAME "TLS13-AES128-GCM-SHA256"
#define IANA_CIPHER_NAME "TLS_AES_128_GCM_SHA256"
#define PSK_HEX_LEN 64
#define TLS13_WIRE_VERSION 0x0304

static unsigned char imported_psk[PSK_HEX_LEN / 2];
static word32 imported_psk_len;
static char psk_cipher_name[64] = PSK_CIPHER_NAME;

static void emit_error(const char* message)
{
    printf("ERR %s\n", message);
    fflush(stdout);
}

int decode_hex(const char* hex, unsigned char** out, size_t* out_len)
{
    size_t length = strlen(hex);
    unsigned char* bytes;
    size_t i;

    if (length == 0 || length % 2 != 0) {
        return -1;
    }
    bytes = (unsigned char*)malloc(length / 2);
    if (bytes == NULL) {
        return -1;
    }
    for (i = 0; i < length / 2; ++i) {
        unsigned int high;
        unsigned int low;
        if (sscanf(&hex[2 * i], "%1x%1x", &high, &low) != 2) {
            free(bytes);
            return -1;
        }
        bytes[i] = (unsigned char)((high << 4) | low);
    }
    *out = bytes;
    *out_len = length / 2;
    return 0;
}

/* The server callbacks see only the imported identity bytes; all TLS-POK
 * peers in this test share the one fixed EPSK-derived PSK. */
static unsigned int copy_imported_psk(unsigned char* psk,
                                      unsigned int psk_max_len)
{
    if (psk == NULL || psk_max_len < imported_psk_len) {
        return 0;
    }
    XMEMCPY(psk, imported_psk, imported_psk_len);
    return imported_psk_len;
}

static unsigned int psk_server_cb(WOLFSSL* ssl, const char* identity,
                                  unsigned char* psk, unsigned int psk_max_len,
                                  const char** cipher_suite)
{
    unsigned int length;

    (void)ssl;
    (void)identity;

    if (cipher_suite == NULL) {
        return 0;
    }
    length = copy_imported_psk(psk, psk_max_len);
    if (length != 0) {
        *cipher_suite = psk_cipher_name;
    }
    return length;
}

/* wolfSSL's legacy setter takes four arguments; the TLS 1.3 setter takes
 * five. Keep the two callback signatures distinct. */
static unsigned int psk_server_legacy_cb(WOLFSSL* ssl, const char* identity,
                                         unsigned char* psk,
                                         unsigned int psk_max_len)
{
    (void)ssl;
    (void)identity;
    return copy_imported_psk(psk, psk_max_len);
}

static char* read_line(FILE* stream)
{
    char* line = NULL;
    size_t capacity = 0;
    ssize_t length = getline(&line, &capacity, stream);

    if (length < 0) {
        free(line);
        return NULL;
    }
    while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r')) {
        line[--length] = '\0';
    }
    return line;
}

static void emit_server_bytes(const unsigned char* bytes, size_t length)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    putchar('S');
    putchar(' ');
    for (i = 0; i < length; ++i) {
        putchar(digits[bytes[i] >> 4]);
        putchar(digits[bytes[i] & 0x0f]);
    }
    putchar('\n');
    fflush(stdout);
}

/* Every byte wolfSSL writes to the memory BIO is a complete TLS record (or a
 * concatenation of them); the Rust driver splits them by record header. */
static void drain_bio(WOLFSSL_BIO* bio)
{
    unsigned char buffer[16384];
    int count;

    while ((count = wolfSSL_BIO_read(bio, buffer, (int)sizeof(buffer))) > 0) {
        emit_server_bytes(buffer, (size_t)count);
    }
}

static int push_peer_record(WOLFSSL_BIO* bio, const char* line)
{
    unsigned char* bytes = NULL;
    size_t length = 0;
    int written;
    int result = -1;

    if (strncmp(line, "F ", 2) != 0 || decode_hex(line + 2, &bytes, &length) != 0) {
        return -1;
    }
    written = wolfSSL_BIO_write(bio, bytes, (int)length);
    if (written == (int)length) {
        result = 0;
    }
    free(bytes);
    return result;
}

#ifndef QID_WOLFSSL_HELPER_NO_MAIN
int main(int argc, char** argv)
{
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    WOLFSSL_BIO* bio = NULL;
    WOLFSSL_BIO* peer_bio = NULL;
    unsigned char* client_spki = NULL;
    unsigned char* psk_bytes = NULL;
    size_t client_spki_len = 0;
    size_t psk_hex_len = 0;
    int status = 1;

    if (argc != 5) {
        emit_error("usage: server <server_cert_der> <server_key_der> <imported_psk_hex> <client_spki_der_hex>");
        return 2;
    }
    if (decode_hex(argv[3], &psk_bytes, &psk_hex_len) != 0 ||
        psk_hex_len == 0 || psk_hex_len > sizeof(imported_psk)) {
        emit_error("invalid imported PSK hex");
        goto cleanup;
    }
    memcpy(imported_psk, psk_bytes, psk_hex_len);
    imported_psk_len = (word32)psk_hex_len;
    if (decode_hex(argv[4], &client_spki, &client_spki_len) != 0 ||
        client_spki_len == 0) {
        emit_error("invalid client SPKI hex");
        goto cleanup;
    }

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    wolfSSL_Debugging_ON();
    if (ctx == NULL) {
        emit_error("cannot allocate TLS 1.3 server context");
        goto cleanup;
    }
    if (wolfSSL_CTX_set_min_proto_version(ctx, TLS13_WIRE_VERSION) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_set1_curves_list(ctx, "secp256r1") != WOLFSSL_SUCCESS) {
        emit_error("cannot configure TLS 1.3 and P-256");
        goto cleanup;
    }
    if (wolfSSL_CTX_set_cipher_list(ctx, PSK_CIPHER_NAME) != WOLFSSL_SUCCESS) {
        if (wolfSSL_CTX_set_cipher_list(ctx, IANA_CIPHER_NAME) != WOLFSSL_SUCCESS) {
            emit_error("cannot configure AES-128-GCM");
            goto cleanup;
        }
        XMEMCPY(psk_cipher_name, IANA_CIPHER_NAME, sizeof(IANA_CIPHER_NAME));
    }
    /* wolfSSL cert+PSK examples register both callbacks; the TLS 1.3
     * callback alone is not sufficient for all server paths. */
    wolfSSL_CTX_set_psk_server_callback(ctx, psk_server_legacy_cb);
    wolfSSL_CTX_set_psk_server_tls13_callback(ctx, psk_server_cb);
    {
        const char rpk = (const char)RAW_PUBLIC_KEY;
        if (wolfSSL_CTX_set_client_cert_type(ctx, &rpk, 1) != WOLFSSL_SUCCESS) {
            emit_error("cannot set client certificate type to RawPublicKey");
            goto cleanup;
        }
        if (wolfSSL_CTX_set_server_cert_type(ctx, &rpk, 1) != WOLFSSL_SUCCESS) {
            emit_error("cannot set server certificate type to RawPublicKey");
            goto cleanup;
        }
        if (wolfSSL_CTX_set_expected_rpk(ctx, client_spki, (word32)client_spki_len) !=
            WOLFSSL_SUCCESS) {
            emit_error("cannot pin the client RawPublicKey");
            goto cleanup;
        }
        if (wolfSSL_CTX_set_cert_with_extern_psk(ctx, 1) != WOLFSSL_SUCCESS) {
            emit_error("cannot enable certificate with external PSK");
            goto cleanup;
        }
        /* This API reports success as 0, unlike the wolfSSL setters above. */
        if (wolfSSL_CTX_require_psk(ctx) != 0) {
            emit_error("cannot require an external PSK");
            goto cleanup;
        }
    }
    if (wolfSSL_CTX_use_certificate_file(ctx, argv[1], SSL_FILETYPE_ASN1) !=
            WOLFSSL_SUCCESS ||
        wolfSSL_CTX_use_PrivateKey_file(ctx, argv[2], SSL_FILETYPE_ASN1) !=
            WOLFSSL_SUCCESS) {
        emit_error("cannot load server DER certificate or key");
        goto cleanup;
    }
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                           NULL);

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL ||
        wolfSSL_BIO_new_bio_pair(&bio, 65536, &peer_bio, 65536) != WOLFSSL_SUCCESS) {
        emit_error("cannot allocate TLS session or memory BIO pair");
        goto cleanup;
    }
    wolfSSL_set_bio(ssl, bio, bio);
    bio = NULL; /* owned by ssl */

    for (;;) {
        char* line = read_line(stdin);
        if (line == NULL) {
            emit_error("client closed before handshake completed");
            goto cleanup;
        }
        if (push_peer_record(peer_bio, line) != 0) {
            free(line);
            emit_error("invalid F line");
            goto cleanup;
        }
        free(line);

        for (;;) {
            int result = wolfSSL_accept(ssl);
            int error = wolfSSL_get_error(ssl, result);
            char error_text[256] = {0};
            const char* file = NULL;
            const char* data = NULL;
            int line = 0;
            int flags = 0;
            unsigned long queued =
                wolfSSL_ERR_get_error_line_data(&file, &line, &data, &flags);

            wolfSSL_ERR_error_string_n((unsigned long)error, error_text,
                                       sizeof(error_text));
            fprintf(stderr,
                    "accept result=%d error=%d (%s) state=%d pending=%d "
                    "queued=%lu file=%s line=%d data=%s\n",
                    result, error, error_text, (int)wolfSSL_get_state(ssl),
                    wolfSSL_BIO_pending(peer_bio), queued,
                    file != NULL ? file : "none", line,
                    data != NULL ? data : "none");
            drain_bio(peer_bio);
            if (result == WOLFSSL_SUCCESS) {
                const char* cipher = wolfSSL_get_cipher_name(ssl);
                int client_cert_type = -1;
                int server_cert_type = -1;
                wolfSSL_get_negotiated_client_cert_type(ssl, &client_cert_type);
                wolfSSL_get_negotiated_server_cert_type(ssl, &server_cert_type);
                printf("OK %s %d %d\n", cipher != NULL ? cipher : "unknown",
                       client_cert_type, server_cert_type);
                fflush(stdout);
                status = 0;
                goto cleanup;
            }
            error = wolfSSL_get_error(ssl, result);
            if (error != WOLFSSL_ERROR_WANT_READ &&
                error != WOLFSSL_ERROR_WANT_WRITE) {
                printf("ERR wolfSSL_accept failed (%d)\n", error);
                fflush(stdout);
                goto cleanup;
            }
            break; /* need the next F line */
        }
    }

cleanup:
    if (bio != NULL) {
        wolfSSL_BIO_free(bio);
    }
    if (peer_bio != NULL) {
        wolfSSL_BIO_free(peer_bio);
    }
    if (ssl != NULL) {
        wolfSSL_free(ssl);
    }
    if (ctx != NULL) {
        wolfSSL_CTX_free(ctx);
    }
    free(client_spki);
    free(psk_bytes);
    return status;
}
#endif /* QID_WOLFSSL_HELPER_NO_MAIN */
