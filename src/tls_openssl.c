/* tls_openssl.c
** strophe XMPP client library -- TLS abstraction openssl impl.
**
** Copyright (C) 2005-008 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT and GPLv3 licenses.
*/

/** @file
 *  TLS implementation with OpenSSL.
 */

#include <errno.h>   /* EINTR */
#include <string.h>

#include <sys/select.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "common.h"
#include "tls.h"
#include "sock.h"

struct _tls {
    xmpp_ctx_t *ctx;
    sock_t sock;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    int lasterror;
};

enum {
    TLS_SHUTDOWN_MAX_RETRIES = 10,
    TLS_TIMEOUT_SEC = 0,
    TLS_TIMEOUT_USEC = 100000,
};

static void _tls_sock_wait(tls_t *tls, int error);
static void _tls_set_error(tls_t *tls, int error);
static void _tls_log_error(xmpp_ctx_t *ctx);

void tls_initialize(void)
{
    SSL_library_init();
    SSL_load_error_strings();
}

void tls_shutdown(void)
{
    return;
}

int tls_error(tls_t *tls)
{
    return tls->lasterror;
}

int
convert_ASN1TIME(ASN1_TIME *ansi_time, char* buf, size_t len)
{
    BIO *bio = BIO_new(BIO_s_mem());
    int rc = ASN1_TIME_print(bio, ansi_time);
    if (rc <= 0) {
        BIO_free(bio);
        return 0;
    }
    rc = BIO_gets(bio, buf, len);
    if (rc <= 0) {
        BIO_free(bio);
        return 0;
    }
    BIO_free(bio);
    return 1;
}

static xmpp_ctx_t *_xmppctx;
xmpp_certfail_handler _certfail_handler;
static int _cert_handled;
static int _last_cb_res;

static void _hex_encode(unsigned char* readbuf, void *writebuf, size_t len)
{
    size_t i;
    for(i=0; i < len; i++) {
        char *l = (char*) (2*i + ((intptr_t) writebuf));
        sprintf(l, "%02x", readbuf[i]);
    }
}

static void _print_certificate(X509* cert) {
    char subject[1024+1];
    char issuer[1024+1];
    X509_NAME_oneline(X509_get_subject_name(cert), subject, 1024);
    X509_NAME_oneline(X509_get_issuer_name(cert), issuer, 1024);
    xmpp_debug(_xmppctx, "TLS", "SUBJECT : %s", subject);
    xmpp_debug(_xmppctx, "TLS", "ISSUER  : %s", issuer);
}

static struct _tlscert_t *_x509_to_tlscert(xmpp_ctx_t *ctx, X509 *cert)
{
    if (!cert) {
        return NULL;
    }

    struct _tlscert_t *tlscert = xmpp_alloc(ctx, sizeof(*tlscert));

    tlscert->subjectname = NULL;
    X509_NAME *subject = X509_get_subject_name(cert);
    char *subjectline = X509_NAME_oneline(subject, NULL, 0);
    if (subjectline) {
        tlscert->subjectname = xmpp_strdup(ctx, subjectline);
        OPENSSL_free(subjectline);
    }

    tlscert->issuername = NULL;
    X509_NAME *issuer = X509_get_issuer_name(cert);
    char *issuerline = X509_NAME_oneline(issuer, NULL, 0);
    if (issuerline) {
        tlscert->issuername = xmpp_strdup(ctx, issuerline);
        OPENSSL_free(issuerline);
    }

    tlscert->notbefore = NULL;
    ASN1_TIME *notbefore = X509_get_notBefore(cert);
    char notbefore_str[128];
    int res = convert_ASN1TIME(notbefore, notbefore_str, 128);
    if (res) {
        tlscert->notbefore = xmpp_strdup(ctx, notbefore_str);
    }

    tlscert->notafter = NULL;
    ASN1_TIME *notafter = X509_get_notAfter(cert);
    char notafter_str[128];
    res = convert_ASN1TIME(notafter, notafter_str, 128);
    if (res) {
        tlscert->notafter = xmpp_strdup(ctx, notafter_str);
    }

    tlscert->fingerprint = NULL;
    const EVP_MD *digest = EVP_sha1();
    unsigned char buf[20];
    unsigned len;
    int rc = X509_digest(cert, digest, (unsigned char*) buf, &len);
    if (rc != 0 && len == 20) {
        char fingerprint[2*20+1];
        _hex_encode(buf, fingerprint, 20);
        tlscert->fingerprint = xmpp_strdup(ctx, fingerprint);
    }

    tlscert->version = ((int) X509_get_version(cert)) + 1;

    tlscert->serialnumber = NULL;
	ASN1_INTEGER *serial = X509_get_serialNumber(cert);
	BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
	if (bn) {
        char *serialnumber = BN_bn2dec(bn);
        if (serialnumber) {
            tlscert->serialnumber = xmpp_strdup(ctx, serialnumber);
            OPENSSL_free(serialnumber);
        } else {
            OPENSSL_free(serialnumber);
        }
        BN_free(bn);
	}

    tlscert->keyalg = NULL;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	int alg_nid = OBJ_obj2nid(cert->cert_info->key->algor->algorithm);
#else
	X509_PUBKEY *pubkey = X509_get_X509_PUBKEY(cert);
	ASN1_OBJECT *ppkalg;
	// FIXME: handle 0 on error.
	X509_PUBKEY_get0_param(&ppkalg, NULL, NULL, NULL, NULL);
	int alg_nid = OBJ_obj2nid(ppkalg);
#endif
	if (alg_nid != NID_undef) {
        const char* keyalg = OBJ_nid2ln(alg_nid);
        if (keyalg) {
            tlscert->keyalg = xmpp_strdup(ctx, keyalg);
        }
    }

    tlscert->sigalg = NULL;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	alg_nid = OBJ_obj2nid(cert->sig_alg->algorithm);
#else
	const X509_ALGOR *palg;
	X509_get0_signature(NULL, &palg, cert);
	alg_nid = OBJ_obj2nid(palg->algorithm);
#endif
	if (alg_nid != NID_undef) {
        const char* sigalg = OBJ_nid2ln(alg_nid);
        if (sigalg) {
            tlscert->sigalg = xmpp_strdup(ctx, sigalg);
        }
    }

    return tlscert;
}

static int
verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    const STACK_OF(X509) *sk = X509_STORE_CTX_get1_chain(x509_ctx);
    int slen = sk_X509_num(sk);
    unsigned i;
    X509 *certsk;
    xmpp_debug(_xmppctx, "TLS", "STACK");
    for(i=0; i<slen; i++) {
        certsk = sk_X509_value(sk, i);
        _print_certificate(certsk);
    }
    xmpp_debug(_xmppctx, "TLS", "ENDSTACK");

    if (preverify_ok) {
        sk_X509_pop_free(sk, X509_free);
        return 1;
    } else if (_cert_handled) {
        if (_last_cb_res == 0) {
            X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_APPLICATION_VERIFICATION);
        }
        sk_X509_pop_free(sk, X509_free);
        return _last_cb_res;
    } else {
        int err = X509_STORE_CTX_get_error(x509_ctx);
        const char *errstr = X509_verify_cert_error_string(err);
        xmpp_debug(_xmppctx, "TLS", "ERROR: %s", errstr);

        X509 *user_cert = sk_X509_value(sk, 0);
        struct _tlscert_t *tlscert = _x509_to_tlscert(_xmppctx, user_cert);
        int cb_res = 0;
        if (_certfail_handler) {
            cb_res = _certfail_handler(tlscert, errstr);
        }
        xmpp_conn_free_tlscert(_xmppctx, tlscert);

        _cert_handled = 1;
        _last_cb_res = cb_res;

        if (cb_res == 0) {
            X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_APPLICATION_VERIFICATION);
        }

        sk_X509_pop_free(sk, X509_free);
        return cb_res;
    }
}

struct _tlscert_t *tls_peer_cert(xmpp_conn_t *conn)
{
    if (conn && conn->tls && conn->tls->ssl) {
        X509 *cert = SSL_get_peer_certificate(conn->tls->ssl);
        struct _tlscert_t *tlscert = _x509_to_tlscert(conn->ctx, cert);
        return tlscert;
    } else {
        return NULL;
    }
}

tls_t *tls_new(xmpp_ctx_t *ctx, sock_t sock, xmpp_certfail_handler certfail_handler, char *tls_cert_path)
{
    _xmppctx = ctx;
    _certfail_handler = certfail_handler;
    _cert_handled = 0;
    _last_cb_res = 0;
    tls_t *tls = xmpp_alloc(ctx, sizeof(*tls));

    xmpp_debug(ctx, "TLS", "OpenSSL version: %s", SSLeay_version(SSLEAY_VERSION));

    if (tls) {
        int ret;
        memset(tls, 0, sizeof(*tls));

        tls->ctx = ctx;
        tls->sock = sock;
        tls->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
        if (tls->ssl_ctx == NULL)
            goto err;

        SSL_CTX_set_client_cert_cb(tls->ssl_ctx, NULL);
        SSL_CTX_set_mode(tls->ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
        SSL_CTX_set_verify(tls->ssl_ctx, SSL_VERIFY_PEER, verify_callback);
        if (tls_cert_path) {
            SSL_CTX_load_verify_locations(tls->ssl_ctx, NULL, tls_cert_path);
        }
        tls->ssl = SSL_new(tls->ssl_ctx);
        if (tls->ssl == NULL)
            goto err_free_ctx;

        ret = SSL_set_fd(tls->ssl, sock);
        if (ret <= 0)
            goto err_free_ssl;
    }

    return tls;

err_free_ssl:
    SSL_free(tls->ssl);
err_free_ctx:
    SSL_CTX_free(tls->ssl_ctx);
err:
    xmpp_free(ctx, tls);
    _tls_log_error(ctx);
    return NULL;
}

void tls_free(tls_t *tls)
{
    SSL_free(tls->ssl);
    SSL_CTX_free(tls->ssl_ctx);
    xmpp_free(tls->ctx, tls);
}

int tls_set_credentials(tls_t *tls, const char *cafilename)
{
    return -1;
}

int tls_start(tls_t *tls)
{
    int error;
    int ret;

    /* Since we're non-blocking, loop the connect call until it
       succeeds or fails */
    while (1) {
        ret = SSL_connect(tls->ssl);
        error = ret <= 0 ? SSL_get_error(tls->ssl, ret) : 0;

        if (ret == -1 && tls_is_recoverable(error)) {
            /* wait for something to happen on the sock before looping back */
            _tls_sock_wait(tls, error);
            continue;
        }

        /* success or fatal error */
        break;
    }
    _tls_set_error(tls, error);

    return ret <= 0 ? 0 : 1;
}

int tls_stop(tls_t *tls)
{
    int retries = 0;
    int error;
    int ret;

    while (1) {
        ++retries;
        ret = SSL_shutdown(tls->ssl);
        error = ret < 0 ? SSL_get_error(tls->ssl, ret) : 0;
        if (ret == 1 || !tls_is_recoverable(error) ||
            retries >= TLS_SHUTDOWN_MAX_RETRIES) {
            break;
        }
        _tls_sock_wait(tls, error);
    }
    _tls_set_error(tls, error);

    return ret <= 0 ? 0 : 1;
}

int tls_is_recoverable(int error)
{
    return (error == SSL_ERROR_NONE || error == SSL_ERROR_WANT_READ
            || error == SSL_ERROR_WANT_WRITE
            || error == SSL_ERROR_WANT_CONNECT
            || error == SSL_ERROR_WANT_ACCEPT);
}

int tls_pending(tls_t *tls)
{
    return SSL_pending(tls->ssl);
}

int tls_read(tls_t *tls, void * const buff, const size_t len)
{
    int ret;

    ret = SSL_read(tls->ssl, buff, len);
    _tls_set_error(tls, ret <= 0 ? SSL_get_error(tls->ssl, ret) : 0);

    return ret;
}

int tls_write(tls_t *tls, const void * const buff, const size_t len)
{
    int ret;

    ret = SSL_write(tls->ssl, buff, len);
    _tls_set_error(tls, ret <= 0 ? SSL_get_error(tls->ssl, ret) : 0);

    return ret;
}

int tls_clear_pending_write(tls_t *tls)
{
    return 0;
}

static void _tls_sock_wait(tls_t *tls, int error)
{
    struct timeval tv;
    fd_set rfds;
    fd_set wfds;
    int nfds;
    int ret;

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    if (error == SSL_ERROR_WANT_READ)
        FD_SET(tls->sock, &rfds);
    if (error == SSL_ERROR_WANT_WRITE)
        FD_SET(tls->sock, &wfds);
    nfds = (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) ?
           tls->sock + 1 : 0;
    do {
        tv.tv_sec = TLS_TIMEOUT_SEC;
        tv.tv_usec = TLS_TIMEOUT_USEC;
        ret = select(nfds, &rfds, &wfds, NULL, &tv);
    } while (ret == -1 && errno == EINTR);
}

static void _tls_set_error(tls_t *tls, int error)
{
    if (error != 0 && !tls_is_recoverable(error)) {
        _tls_log_error(tls->ctx);
    }
    tls->lasterror = error;
}

static void _tls_log_error(xmpp_ctx_t *ctx)
{
    unsigned long e;
    char buf[256];

    do {
        e = ERR_get_error();
        if (e != 0) {
            ERR_error_string_n(e, buf, sizeof(buf));
            xmpp_debug(ctx, "tls", "%s", buf);
        }
    } while (e != 0);
}
