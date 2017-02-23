#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hiredis_ssl.h>
#include <errno.h>
#include <ctype.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

static BIO *bio_err = NULL;

static int verify_depth = 0;
static int verify_quiet = 0;
static int verify_error = X509_V_OK;
static int verify_return_error = 0;

static void nodes_print(BIO *out, const char *name,
                        STACK_OF(X509_POLICY_NODE) *nodes)
{
    X509_POLICY_NODE *node;
    int i;
    BIO_printf(out, "%s Policies:", name);
    if (nodes) {
        BIO_puts(out, "\n");
        for (i = 0; i < sk_X509_POLICY_NODE_num(nodes); i++) {
            node = sk_X509_POLICY_NODE_value(nodes, i);
            X509_POLICY_NODE_print(out, node, 2);
        }
    } else
        BIO_puts(out, " <empty>\n");
}

static void policies_print(BIO *out, X509_STORE_CTX *ctx)
{
    X509_POLICY_TREE *tree;
    int explicit_policy;
    int free_out = 0;
    if (out == NULL) {
        out = BIO_new_fp(stderr, BIO_NOCLOSE);
        free_out = 1;
    }
    tree = X509_STORE_CTX_get0_policy_tree(ctx);
    explicit_policy = X509_STORE_CTX_get_explicit_policy(ctx);

    BIO_printf(out, "Require explicit Policy: %s\n",
               explicit_policy ? "True" : "False");

    nodes_print(out, "Authority", X509_policy_tree_get0_policies(tree));
    nodes_print(out, "User", X509_policy_tree_get0_user_policies(tree));
    if (free_out)
        BIO_free(out);
}

static int verify_callback(int ok, X509_STORE_CTX *ctx)
{
    X509 *err_cert;
    int err, depth;

    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    if (!verify_quiet || !ok) {
        //BIO_printf(bio_err, "depth=%d ", depth); ?
        if (err_cert) {
            /*X509_NAME_print_ex(bio_err,
                               X509_get_subject_name(err_cert),
                               0, XN_FLAG_ONELINE);
            */
            //BIO_puts(bio_err, "\n");
        } else {
            //BIO_puts(bio_err, "<no cert>\n");
        }
    }
    if (!ok) {
        //BIO_printf(bio_err, "verify error:num=%d:%s\n", err,
        //           X509_verify_cert_error_string(err));
        if (verify_depth >= depth) {
            if (!verify_return_error)
                ok = 1;
            verify_error = X509_V_OK;
        } else {
            ok = 0;
            verify_error = X509_V_ERR_CERT_CHAIN_TOO_LONG;
        }
    }
    switch (err) {
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        BIO_puts(bio_err, "issuer= ");
        X509_NAME_print_ex(bio_err, X509_get_issuer_name(err_cert),
                           0, XN_FLAG_ONELINE);
        BIO_puts(bio_err, "\n");
        break;
    case X509_V_ERR_CERT_NOT_YET_VALID:
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
        //BIO_printf(bio_err, "notBefore=");
        //ASN1_TIME_print(bio_err, X509_get_notBefore(err_cert));
        //BIO_printf(bio_err, "\n");
        break;
    case X509_V_ERR_CERT_HAS_EXPIRED:
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
        //BIO_printf(bio_err, "notAfter=");
        //ASN1_TIME_print(bio_err, X509_get_notAfter(err_cert));
        //BIO_printf(bio_err, "\n");
        break;
    case X509_V_ERR_NO_EXPLICIT_POLICY:
        if (!verify_quiet)
            policies_print(bio_err, ctx);
        break;
    }
    if (err == X509_V_OK && ok == 2 && !verify_quiet)
        policies_print(bio_err, ctx);
    if (ok && !verify_quiet)
        BIO_printf(bio_err, "verify return:%d\n", ok);
    return ok;
}

/* ssl code */
static void ssl_globals_init(void) {
    SSL_library_init ();
    ERR_load_crypto_strings();
    SSL_load_error_strings ();
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
}

static SSL_CTX *sslContextInit(const char *keyfile, const char *cert_file, const char *caFile) {
    fprintf(stderr, "sslContextInit with keyfile=%s, cert_file = %s, caFile = %s\n", keyfile, cert_file, caFile);
    const SSL_METHOD *meth;
    SSL_CTX *ctx;
    if (bio_err == NULL) {
        /* Global system initialization*/
        /* An error write context */
        bio_err = BIO_new_fp (stderr, BIO_NOCLOSE);
    }
    /* Create our context*/
    meth = TLSv1_client_method();
    ctx = SSL_CTX_new(meth);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3|SSL_OP_NO_SSLv2);//SAFETY ISSUES
    /* Load our keys and certificates*/
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "error loading cert_file : %s\n", cert_file);
        exit(2);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "error loading keyfile : %s\n", keyfile);
        exit(2);
    }
    /* Load the CAs we trust*/
    if (SSL_CTX_load_verify_locations (ctx, caFile, NULL) != 1) {
        fprintf(stderr, "error loading caFile : %s\n", caFile);
        exit(2);
    }

    SSL_CTX_set_verify(ctx,
                       SSL_VERIFY_PEER,
                       verify_callback);
    return ctx;
}

int main(int argc, char **argv) {
    unsigned int j;
    redisContext *c;
    redisReply *reply;
    if (argc != 6) {
        printf("usage: %s <hostname> <port> <keyfile> <cert_file> <caFile>\n", argv[0]);
        exit(1);
    }
    const char *hostname =  argv[1];
    int port = (argc > 2) ? atoi(argv[2]) : 6379;
    const char *keyfile = argv[3];
    const char *cert_file = argv[4];
    const char *caFile = argv[5];
//    struct timeval timeout = { 1, 500000 }; // 1.5 seconds
    // init globals of openssl and crypt
    ssl_globals_init();
    SSL_CTX *ssl_ctx = sslContextInit(keyfile, cert_file, caFile);
    c = redisConnectSSLWithTimeout(ssl_ctx, 1, hostname, port, 2);

    if (c == NULL || c->err) {
        ERR_print_errors_fp (stderr);
        if (c) {
            printf("Connection error: %s\n", c->errstr);
            redisFree(c);
        } else {
            printf("Connection error: can't allocate redis context\n");
        }
        exit(1);
    }

    /* PING server */
    reply = redisCommand(c,"PING");
    if (reply == NULL || reply->str == NULL) {
        exit(1);
    }
    printf("PING: %s\n", reply->str);
    freeReplyObject(reply);

    /* Set a key */
    reply = redisCommand(c,"SET %s %s", "foo", "hello world");
    printf("SET: %s\n", reply->str);
    freeReplyObject(reply);

    /* Set a key using binary safe API */
    reply = redisCommand(c,"SET %b %b", "bar", (size_t) 3, "hello", (size_t) 5);
    printf("SET (binary API): %s\n", reply->str);
    freeReplyObject(reply);

    /* Try a GET and two INCR */
    reply = redisCommand(c,"GET foo");
    printf("GET foo: %s\n", reply->str);
    freeReplyObject(reply);

    reply = redisCommand(c,"INCR counter");
    printf("INCR counter: %lld\n", reply->integer);
    freeReplyObject(reply);
    /* again ... */
    reply = redisCommand(c,"INCR counter");
    printf("INCR counter: %lld\n", reply->integer);
    freeReplyObject(reply);

    /* Create a list of numbers, from 0 to 9 */
    reply = redisCommand(c,"DEL mylist");
    freeReplyObject(reply);
    for (j = 0; j < 10; j++) {
        char buf[64];

        snprintf(buf,64,"%u",j);
        reply = redisCommand(c,"LPUSH mylist element-%s", buf);
        freeReplyObject(reply);
    }

    /* Let's check what we have inside the list */
    reply = redisCommand(c,"LRANGE mylist 0 -1");
    if (reply->type == REDIS_REPLY_ARRAY) {
        for (j = 0; j < reply->elements; j++) {
            printf("%u) %s\n", j, reply->element[j]->str);
        }
    }
    freeReplyObject(reply);

    /* Disconnects and frees the context */
    redisFree(c);

    return 0;
}
