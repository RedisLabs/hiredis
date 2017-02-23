#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <sys/socket.h>
#include <string.h>
#include "hiredis_ssl.h"

extern redisContext *redisContextInit(void);

static void sslRedisFree(redisContext *c){
    if (!c) return;
    if (c->ssl) {
        if (c->ssl->bio) {
            BIO_free(c->ssl->bio);
            c->ssl->bio = NULL;
        }
        if (c->ssl->owner) {
            SSL_CTX_free(c->ssl->ctx);
            c->ssl->ctx = NULL;
        };
        free(c->ssl);
        c->ssl = NULL;
    }
    c->fd = -1;
    c->free_cb = NULL;
    redisFree(c);
}

static inline ssize_t hiredis_ssl_write(redisContext *c, void *buf, size_t len) {
    return BIO_write(c->ssl->bio, buf,len);
}

static inline ssize_t hiredis_ssl_read(redisContext *c, void *buf, size_t len) {
    return BIO_read(c->ssl->bio, buf,len);
}


redisContext *redisConnectSSLWithTimeout(SSL_CTX *sslctx, int owner, const char *hostname, int port, int timeout) {
    redisContext *c = redisContextInit();
    c->read_cb = hiredis_ssl_read;
    c->write_cb = hiredis_ssl_write;
    c->free_cb = sslRedisFree;
    c->fd = -1;
    c->ssl = calloc(1, sizeof(struct redisSSLData));
    if (!c->ssl) {
        redisFree(c);
        return NULL;
    }

    c->ssl->ctx = sslctx;
    c->ssl->owner = owner;
    SSL_CTX_set_timeout(c->ssl->ctx, timeout);
    c->flags |= REDIS_BLOCK;
    char address[1024];
    snprintf(address, sizeof(address)-1, "%s:%i", hostname, port);
    c->ssl->bio = BIO_new_ssl_connect(c->ssl->ctx);
    if (c->ssl->bio == NULL)
        goto err;
    if (BIO_set_conn_hostname(c->ssl->bio, address) != 1) {
        goto err;
    }
    if (BIO_do_connect(c->ssl->bio) <= 0) {
        goto err;
    }
    c->fd = BIO_get_fd(c->ssl->bio, NULL);
    c->flags |= REDIS_CONNECTED;
    return c;
err:
    c->ssl->owner = 0;
    sslRedisFree(c);
    return NULL;
}
