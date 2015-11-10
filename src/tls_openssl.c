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

#include <string.h>

#include <sys/select.h>

#include <openssl/ssl.h>
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

static xmpp_conn_t *_xmppconn;
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
    char subj[1024+1];
    char issuer[1024+1];
    X509_NAME_oneline(X509_get_subject_name(cert), subj, 1024);
    X509_NAME_oneline(X509_get_issuer_name(cert), issuer, 1024);
    xmpp_debug(_xmppconn->ctx, "TLS", "SUBJECT : %s", subj);
    xmpp_debug(_xmppconn->ctx, "TLS", "ISSUER  : %s", issuer);
}

static struct _tlscert_t *_x509_to_tlscert(xmpp_ctx_t *ctx, X509 *cert)
{
    if (!cert) {
        return NULL;
    }

    struct _tlscert_t *tlscert = xmpp_alloc(ctx, sizeof(*tlscert));

    X509_NAME *usersubject = X509_get_subject_name(cert);
    char *usersubjectname = X509_NAME_oneline(usersubject, NULL, 0);
    tlscert->subjectname = xmpp_strdup(ctx, usersubjectname);
    OPENSSL_free(usersubjectname);

    ASN1_TIME *user_not_before = X509_get_notBefore(cert);
    char user_not_before_str[128];
    int user_not_before_res = convert_ASN1TIME(user_not_before, user_not_before_str, 128);
    tlscert->notbefore = xmpp_strdup(ctx, user_not_before_str);

    ASN1_TIME *user_not_after = X509_get_notAfter(cert);
    char user_not_after_str[128];
    int user_not_after_res = convert_ASN1TIME(user_not_after, user_not_after_str, 128);
    tlscert->notafter = xmpp_strdup(ctx, user_not_after_str);

    unsigned char buf[20];
    const EVP_MD *digest = EVP_sha1();
    unsigned len;
    int rc = X509_digest(cert, digest, (unsigned char*) buf, &len);
    char strbuf[2*20+1];
    if (rc != 0 && len == 20) {
        _hex_encode(buf, strbuf, 20);
        tlscert->fp = xmpp_strdup(ctx, strbuf);
    } else {
        tlscert->fp = NULL;
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
    xmpp_debug(_xmppconn->ctx, "TLS", "STACK");
    for(i=0; i<slen; i++) {
        certsk = sk_X509_value(sk, i);
        _print_certificate(certsk);
    }
    xmpp_debug(_xmppconn->ctx, "TLS", "ENDSTACK");

    if (preverify_ok) {
        return 1;
    } else if (_cert_handled) {
        if (_last_cb_res == 0) {
            X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_APPLICATION_VERIFICATION);
        }
        return _last_cb_res;
    } else {
        int err = X509_STORE_CTX_get_error(x509_ctx);
        const char *errstr = X509_verify_cert_error_string(err);
        xmpp_debug(_xmppconn->ctx, "TLS", "ERROR: %s", errstr);

        X509 *user_cert = sk_X509_value(sk, 0);
        struct _tlscert_t *tlscert = _x509_to_tlscert(_xmppconn->ctx, user_cert);
        int cb_res = _xmppconn->certfail_handler(tlscert, errstr);
        xmpp_conn_free_tlscert(_xmppconn->ctx, tlscert);

        _cert_handled = 1;
        _last_cb_res = cb_res;

        if (cb_res == 0) {
            X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_APPLICATION_VERIFICATION);
        }

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

tls_t *tls_new(xmpp_conn_t *conn)
{
    _xmppconn = conn;
    _cert_handled = 0;
    _last_cb_res = 0;
    tls_t *tls = xmpp_alloc(conn->ctx, sizeof(*tls));

    if (tls) {
        int ret;
        memset(tls, 0, sizeof(*tls));

        tls->ctx = conn->ctx;
        tls->sock = conn->sock;
        tls->ssl_ctx = SSL_CTX_new(SSLv23_client_method());

        SSL_CTX_set_client_cert_cb(tls->ssl_ctx, NULL);
        SSL_CTX_set_mode (tls->ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
        SSL_CTX_set_verify (tls->ssl_ctx, SSL_VERIFY_PEER, verify_callback);
        if (conn->tls_cert_path) {
            SSL_CTX_load_verify_locations(tls->ssl_ctx, NULL, conn->tls_cert_path);
        }
        tls->ssl = SSL_new(tls->ssl_ctx);

        ret = SSL_set_fd(tls->ssl, conn->sock);
        if (ret <= 0) {
            tls->lasterror = SSL_get_error(tls->ssl, ret);
            tls_error(tls);
            tls_free(tls);
            tls = NULL;
        }
    }

    return tls;
}

void tls_free(tls_t *tls)
{
    SSL_free(tls->ssl);
    SSL_CTX_free(tls->ssl_ctx);
    xmpp_free(tls->ctx, tls);
    return;
}

int tls_set_credentials(tls_t *tls, const char *cafilename)
{
    return -1;
}

int tls_start(tls_t *tls)
{
    fd_set fds;
    struct timeval tv;
    int error;
    int ret;

    /* Since we're non-blocking, loop the connect call until it
       succeeds or fails */
    while (1) {
        ret = SSL_connect(tls->ssl);
        error = ret <= 0 ? SSL_get_error(tls->ssl, ret) : 0;

        if (ret == -1 && tls_is_recoverable(error)) {
            /* wait for something to happen on the sock before looping back */
            tv.tv_sec = 0;
            tv.tv_usec = 1000;

            FD_ZERO(&fds);
            FD_SET(tls->sock, &fds);

            if (error == SSL_ERROR_WANT_READ)
                select(tls->sock + 1, &fds, NULL, NULL, &tv);
            else
                select(tls->sock + 1, NULL, &fds, NULL, &tv);
            continue;
        }

        /* success or fatal error */
        break;
    }
    tls->lasterror = error;

    return ret <= 0 ? 0 : 1;

}

int tls_stop(tls_t *tls)
{
    int ret;

    ret = SSL_shutdown(tls->ssl);
    tls->lasterror = ret <= 0 ? SSL_get_error(tls->ssl, ret) : 0;

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
    int ret = SSL_read(tls->ssl, buff, len);

    if (ret <= 0) {
        tls->lasterror = SSL_get_error(tls->ssl, ret);
    }

    return ret;
}

int tls_write(tls_t *tls, const void * const buff, const size_t len)
{
    int ret = SSL_write(tls->ssl, buff, len);

    if (ret <= 0) {
        tls->lasterror = SSL_get_error(tls->ssl, ret);
    }

    return ret;
}

int tls_clear_pending_write(tls_t *tls)
{
    return 0;
}
