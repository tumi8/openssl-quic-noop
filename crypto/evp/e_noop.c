#include "internal/cryptlib.h"
#include <string.h>
#include <openssl/evp.h>
#include "evp_local.h"
#include "crypto/evp.h"


#define NOOP_KEYLEN 32
#define NOOP_BLKLEN 1
#define NOOP_IVLEN 12
#define NOOP_MAX_IVLEN 12
#define NOOP_TAGLEN 16


typedef struct {
    unsigned char tag[NOOP_TAGLEN];
    unsigned char tls_aad[NOOP_TAGLEN];
    int mac_inited, tag_len, nonce_len;
    size_t tls_payload_length;
} EVP_NOOP_AEAD_CTX;


#define NO_TLS_PAYLOAD_LENGTH ((size_t)-1)
#define aead_data(ctx)        ((EVP_NOOP_AEAD_CTX *)(ctx)->cipher_data)


static int noop_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *inkey, const unsigned char *iv, int enc) {
    EVP_NOOP_AEAD_CTX *actx = aead_data(ctx);

    if (!inkey && !iv)
        return 1;

    actx->mac_inited = 0;
    actx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;

    return 1;
}

static int noop_tls_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                        const unsigned char *in, size_t len)
{
    EVP_NOOP_AEAD_CTX *actx = aead_data(ctx);
    size_t plen = actx->tls_payload_length;

    if (len != plen + NOOP_TAGLEN)
        return -1;

    actx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;

    if (in != out) {
        memcpy(out, in, plen);
    }

    out += plen;

    if (ctx->encrypt) {
        memset(actx->tag, 42, NOOP_TAGLEN);
        memcpy(out, actx->tag, NOOP_TAGLEN);
    }

    return len;
}


static int noop_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t len) {
    EVP_NOOP_AEAD_CTX *actx = aead_data(ctx);
    size_t plen = actx->tls_payload_length;

    if (!actx->mac_inited) {
        if (plen != NO_TLS_PAYLOAD_LENGTH && out != NULL)
            return noop_tls_cipher(ctx, out, in, len);

        actx->mac_inited = 1;
    }

    if (in) { /* aad or text */
        if (out == NULL) { /* aad */
            return len;
        } else { /* plain- or ciphertext */
            actx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;
            if (plen == NO_TLS_PAYLOAD_LENGTH)
                plen = len;
            else if (len != plen + NOOP_TAGLEN)
                return -1;

            if (in != out) {
                memcpy(out, in, plen);
            }
            in += plen;
            out += plen;
        }
    }
    if (in == NULL                              /* explicit final */
        || plen != len) {                       /* or tls mode */

        if (ctx->encrypt) {
            memset(actx->tag, 42, actx->tag_len);
        }
        actx->mac_inited = 0;

        if (in != NULL && len != plen) {        /* tls mode */
            if (ctx->encrypt) {
                memcpy(out, actx->tag, NOOP_TAGLEN);
            }
        }
    }
    return len;
}


static int noop_cleanup(EVP_CIPHER_CTX *ctx) {
    EVP_NOOP_AEAD_CTX *actx = aead_data(ctx);
    if (actx)
        OPENSSL_cleanse(ctx->cipher_data, sizeof(*actx));
    return 1;
}


static int noop_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr) {
    EVP_NOOP_AEAD_CTX *actx = aead_data(ctx);

    switch(type) {
        case EVP_CTRL_INIT:
            if (actx == NULL)
                actx = ctx->cipher_data = OPENSSL_zalloc(sizeof(*actx));
            if (actx == NULL) {
                EVPerr(EVP_F_CHACHA20_POLY1305_CTRL, EVP_R_INITIALIZATION_ERROR);
                return 0;
            }
            actx->mac_inited = 0;
            actx->tag_len = 0;
            actx->nonce_len = NOOP_IVLEN;
            actx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;
            memset(actx->tls_aad, 0, NOOP_TAGLEN);
            return 1;

        case EVP_CTRL_COPY:
            if (actx) {
                EVP_CIPHER_CTX *dst = (EVP_CIPHER_CTX *)ptr;

                dst->cipher_data =
                    OPENSSL_memdup(actx, sizeof(*actx));
                if (dst->cipher_data == NULL) {
                    EVPerr(EVP_F_CHACHA20_POLY1305_CTRL, EVP_R_COPY_ERROR);
                    return 0;
                }
            }
            return 1;

        case EVP_CTRL_GET_IVLEN:
            *(int *)ptr = actx->nonce_len;
            return 1;

        case EVP_CTRL_AEAD_SET_IVLEN:
            if (arg <= 0 || arg > NOOP_MAX_IVLEN)
                return 0;
            actx->nonce_len = arg;
            return 1;

        case EVP_CTRL_AEAD_SET_IV_FIXED:
            if (arg != NOOP_IVLEN)
                return 0;
            return 1;

        case EVP_CTRL_AEAD_SET_TAG:
            if (arg <= 0 || arg > NOOP_TAGLEN)
                return 0;
            if (ptr != NULL) {
                memcpy(actx->tag, ptr, arg);
                actx->tag_len = arg;
            }
            return 1;

        case EVP_CTRL_AEAD_GET_TAG:
            if (arg <= 0 || arg > NOOP_TAGLEN || !ctx->encrypt)
                return 0;
            memcpy(ptr, actx->tag, arg);
            return 1;

        case EVP_CTRL_AEAD_TLS1_AAD:
            if (arg != EVP_AEAD_TLS1_AAD_LEN)
                return 0;
            {
                unsigned int len;
                unsigned char *aad = ptr;

                memcpy(actx->tls_aad, ptr, EVP_AEAD_TLS1_AAD_LEN);
                len = aad[EVP_AEAD_TLS1_AAD_LEN - 2] << 8 | aad[EVP_AEAD_TLS1_AAD_LEN - 1];
                aad = actx->tls_aad;
                if (!ctx->encrypt) {
                    if (len < NOOP_TAGLEN)
                        return 0;
                    len -= NOOP_TAGLEN;     /* discount attached tag */
                    aad[EVP_AEAD_TLS1_AAD_LEN - 2] = (unsigned char)(len >> 8);
                    aad[EVP_AEAD_TLS1_AAD_LEN - 1] = (unsigned char)len;
                }
                actx->tls_payload_length = len;

                actx->mac_inited = 0;

                return NOOP_TAGLEN;         /* tag length */
            }

        case EVP_CTRL_AEAD_SET_MAC_KEY:
            /* no-op */
            return 1;

        default:
            return -1;

    }
}


static const EVP_CIPHER aead_noop = {
        42424242,
        NOOP_BLKLEN,     /* block_size */
        NOOP_KEYLEN,     /* key_len */
        NOOP_IVLEN,      /* iv_len */
        EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_CUSTOM_IV |
        EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT |
        EVP_CIPH_CUSTOM_COPY | EVP_CIPH_FLAG_CUSTOM_CIPHER |
        EVP_CIPH_CUSTOM_IV_LENGTH,
        noop_init_key,
        noop_cipher,
        noop_cleanup,
        0,          /* 0 moves context-specific structure allocation to ctrl */
        NULL,       /* set_asn1_parameters */
        NULL,       /* get_asn1_parameters */
        noop_ctrl,
        NULL        /* app_data */
};

const EVP_CIPHER *EVP_noop(void) {
    return &aead_noop;
}
