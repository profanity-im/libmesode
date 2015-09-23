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

void
hex_encode(unsigned char* readbuf, void *writebuf, size_t len)
{
    size_t i;
    for(i=0; i < len; i++) {
        char *l = (char*) (2*i + ((intptr_t) writebuf));
        sprintf(l, "%02x", readbuf[i]);
    }
}

static xmpp_ctx_t *xmppctx;
static int cert_handled;
static int last_cb_res;

static void
print_certificate(X509* cert) {
    char subj[1024+1];
    char issuer[1024+1];
    X509_NAME_oneline(X509_get_subject_name(cert), subj, 1024);
    X509_NAME_oneline(X509_get_issuer_name(cert), issuer, 1024);
    xmpp_debug(xmppctx, "TLS", "SUBJECT : %s", subj);
    xmpp_debug(xmppctx, "TLS", "ISSUER  : %s", issuer);
}

static int
verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    const STACK_OF(X509) *sk = X509_STORE_CTX_get1_chain(x509_ctx);
    int slen = sk_num((const _STACK *)sk);
    unsigned i;
    X509 *certsk;
    xmpp_debug(xmppctx, "TLS", "STACK");
    for(i=0; i<slen; i++) {
        certsk = (X509*) sk_value((const _STACK *)sk, i);
        print_certificate(certsk);
    }
    xmpp_debug(xmppctx, "TLS", "ENDSTACK");

    if (preverify_ok) {
        return 1;
    } else if (cert_handled) {
        return last_cb_res;
    } else {
        int err = X509_STORE_CTX_get_error(x509_ctx);
        const char *errstr = X509_verify_cert_error_string(err);
        xmpp_debug(xmppctx, "TLS", "ERROR: %s", errstr);

        X509 *user_cert;
        user_cert = (X509*) sk_value((const _STACK *)sk, 0);
        X509_NAME *usersubject = X509_get_subject_name(user_cert);
        char *usersubjectname = X509_NAME_oneline(usersubject, NULL, 0);

        ASN1_TIME *user_not_before = X509_get_notBefore(user_cert);
        char user_not_before_str[128];
        int user_not_before_res = convert_ASN1TIME(user_not_before, user_not_before_str, 128);

        ASN1_TIME *user_not_after = X509_get_notAfter(user_cert);
        char user_not_after_str[128];
        int user_not_after_res = convert_ASN1TIME(user_not_after, user_not_after_str, 128);

        char buf[20];
        const EVP_MD *digest = EVP_sha1();
        unsigned len;
        int rc = X509_digest(user_cert, digest, (unsigned char*) buf, &len);
        char strbuf[2*20+1];
        if (rc != 0 && len == 20) {
            hex_encode(buf, strbuf, 20);
        }

        int cb_res = xmppctx->connlist->conn->certfail_handler(
            usersubjectname,
            strbuf,
            user_not_before_str,
            user_not_after_str,
            errstr);
        OPENSSL_free(usersubjectname);

        cert_handled = 1;
        last_cb_res = cb_res;
        return cb_res;
    }
}

tls_t *tls_new(xmpp_ctx_t *ctx, sock_t sock)
{
    xmppctx = ctx;
    cert_handled = 0;
    last_cb_res = 0;
    tls_t *tls = xmpp_alloc(ctx, sizeof(*tls));

    if (tls) {
        int ret;
        memset(tls, 0, sizeof(*tls));

        tls->ctx = ctx;
        tls->sock = sock;
        tls->ssl_ctx = SSL_CTX_new(SSLv23_client_method());

        SSL_CTX_set_client_cert_cb(tls->ssl_ctx, NULL);
        SSL_CTX_set_mode (tls->ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
        SSL_CTX_set_verify (tls->ssl_ctx, SSL_VERIFY_PEER, verify_callback);
        if (xmppctx->connlist->conn->tls_cert_path) {
            SSL_CTX_load_verify_locations(tls->ssl_ctx, NULL, xmppctx->connlist->conn->tls_cert_path);
        }
        tls->ssl = SSL_new(tls->ssl_ctx);

        ret = SSL_set_fd(tls->ssl, sock);
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
    int ret = -1;

    /* Since we're non-blocking, loop the connect call until it
    succeeds or fails */
    while (ret < 0) {
        ret = SSL_connect(tls->ssl);
        int err = SSL_get_error(tls->ssl, ret);
        int recoverable = tls_is_recoverable(err);

        // continue if recoverable
        if (recoverable) {
            fd_set fds;
            struct timeval tv;

            tv.tv_sec = 0;
            tv.tv_usec = 1000;

            FD_ZERO(&fds);
            FD_SET(tls->sock, &fds);

            select(tls->sock + 1, &fds, &fds, NULL, &tv);
        } else {
            ret = 1;
        }
    }

    if (ret <= 0) {
        tls->lasterror = SSL_get_error(tls->ssl, ret);
        return 0;
    }

    return 1;
}

int tls_stop(tls_t *tls)
{
    int ret;

    ret = SSL_shutdown(tls->ssl);

    if (ret <= 0) {
        tls->lasterror = SSL_get_error(tls->ssl, ret);
        return 0;
    }

    return 1;
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
