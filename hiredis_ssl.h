#ifndef _HIREDISSSL_H_
#define _HIREDISSSL_H_

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include "hiredis.h"

typedef struct redisSSLData {
    BIO *bio;
    SSL_CTX* ctx;
    int owner;
} redisSSLData;

redisContext *redisConnectSSLWithTimeout(SSL_CTX *sslctx, int owner, const char *hostname, int port, int timeout);

#endif
