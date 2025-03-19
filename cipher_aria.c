/*
/* 19 Mar 2025, Chul-Woong Yang
*/
/* My ARIA (MARIA) cipher */

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/provider.h>

#include "cipher_common.h"

typedef struct prov_aria_ctx_st {
    EVP_CIPHER_CTX *ctx;        // master ctx
    int enc;
    int len;
} PROV_ARIA_CTX;

static OSSL_FUNC_cipher_newctx_fn aria_256_cbc_newctx;
static OSSL_FUNC_cipher_freectx_fn aria_freectx;
static OSSL_FUNC_cipher_dupctx_fn aria_dupctx;
static OSSL_FUNC_cipher_get_params_fn aria_256_cbc_get_params;

static void * aria_newctx(void *provctx)
{
     PROV_ARIA_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
     if (ctx == NULL)
         return NULL;
     
     ctx->ctx = EVP_CIPHER_CTX_new();
     if (ctx->ctx == NULL) {
         OPENSSL_free(ctx);
         return NULL;
     }
     return ctx;
}

static void aria_freectx(void *vctx)
{
    PROV_ARIA_CTX *ctx = (PROV_ARIA_CTX *)vctx;

    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx->ctx);
    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

static void *aria_dupctx(void *ctx)
{
    PROV_ARIA_CTX *in = (PROV_ARIA_CTX *)ctx;
    PROV_ARIA_CTX *ret;

    ret = OPENSSL_malloc(sizeof(*ret));
    if (ret == NULL)
        return NULL;
    ret->ctx = EVP_CIPHER_CTX_dup(in->ctx);
    ret->enc = in->enc;
    
    return ret;
}

static int aria_einit(void *vctx, const EVP_CIPHER *cipher,
                      const unsigned char *key,
                      size_t keylen, const unsigned char *iv,
                      size_t ivlen, const OSSL_PARAM params[], int enc)
{
    PROV_ARIA_CTX *pactx = (PROV_ARIA_CTX *)vctx;
    EVP_CIPHER_CTX *ctx = pactx->ctx;
    
    if (enc) {
        if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv))
            return 0;
    } else {
        if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv))
            return 0;
    }
    pactx->enc = enc;
    return 1;
}

#define DEFINE_ARIA_INITS(bits,mode)                                    \
    static int aria_##bits##_##mode##_einit(void *vctx, const unsigned char *key, \
                                            size_t keylen, const unsigned char *iv, \
                                            size_t ivlen, const OSSL_PARAM params[]) { \
        return aria_einit(vctx, EVP_aria_##bits##_##mode(), key, keylen, iv, ivlen, params, 1); \
    }                                                                   \
    static int aria_##bits##_##mode##_dinit(void *vctx, const unsigned char *key, \
                                            size_t keylen, const unsigned char *iv, \
                                            size_t ivlen, const OSSL_PARAM params[]) { \
        return aria_einit(vctx, EVP_aria_##bits##_##mode(), key, keylen, iv, ivlen, params, 0); \
    }
DEFINE_ARIA_INITS(128, cbc);
DEFINE_ARIA_INITS(192, cbc);
DEFINE_ARIA_INITS(256, cbc);

static int aria_block_update(void *vctx, unsigned char *out,
                      size_t *outl, size_t outsize,
                      const unsigned char *in, size_t inl)
{
    PROV_ARIA_CTX *pactx = (PROV_ARIA_CTX *)vctx;
    EVP_CIPHER_CTX *ctx = pactx->ctx;
    int ret, _outl, _inl = inl;
    if (pactx->enc)
        ret = EVP_EncryptUpdate(ctx, out, &_outl, in, _inl);
    else
        ret = EVP_DecryptUpdate(ctx, out, &_outl, in, _inl);        
    if (1 != ret)
        return 0;
    *outl = _outl;
    pactx->len += *outl;
    return 1;
}
static int aria_block_final(void *vctx, unsigned char *out,
                            size_t *outl, size_t outsize)
{
    PROV_ARIA_CTX *pactx = (PROV_ARIA_CTX *)vctx;
    EVP_CIPHER_CTX *ctx = pactx->ctx;
    int _outl, ret;
    if (pactx->enc)
        ret = EVP_EncryptFinal_ex(ctx, out, &_outl);
    else
        ret = EVP_DecryptFinal_ex(ctx, out, &_outl);
    
    if (1 != ret) {
        ret = 0;
        goto here;
    }
    *outl = _outl;
    pactx->len += *outl;
here:
    EVP_CIPHER_CTX_free(ctx);   // early free
    pactx->ctx = NULL;
    return ret;
}

int aria_cipher(void *vctx, unsigned char *out, size_t *outl,
                size_t outsize, const unsigned char *in,
                size_t inl)
{
    DIE("Not Yet Implemented");
}

static int aria_get_params(OSSL_PARAM params[], unsigned int md,
                           size_t kbits, size_t blkbits, size_t ivbits)
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, md)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, kbits / 8)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blkbits / 8)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ivbits / 8)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
#if 0
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_AEAD) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_CUSTOM_IV) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CTS);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_CTS) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_TLS1_MULTIBLOCK) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_HAS_RAND_KEY);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_RAND_KEY) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
#endif
    return 1;
}

static int aria_256_cbc_get_params(OSSL_PARAM params[]) 
{
    return aria_get_params(params, EVP_CIPH_CBC_MODE, 256, 128, 128);
}
static int aria_192_cbc_get_params(OSSL_PARAM params[]) 
{
    return aria_get_params(params, EVP_CIPH_CBC_MODE, 192, 128, 128);
}
static int aria_128_cbc_get_params(OSSL_PARAM params[]) 
{
    return aria_get_params(params, EVP_CIPH_CBC_MODE, 128, 128, 128);
}

#define DECLARE_ARIA_DISPATCHER                                         \
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void)) aria_newctx },          \
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) aria_freectx },        \
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void)) aria_dupctx },          \
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))aria_block_update },     \
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))aria_block_final },       \
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))aria_cipher },           \
    OSSL_DISPATCH_END
#if 0    
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
      (void (*)(void))aria_get_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
      (void (*)(void))aria_set_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
      (void (*)(void))aria_gettable_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
      (void (*)(void))aria_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
     (void (*)(void))aria_settable_ctx_params },
#endif

#define DEFINE_ARIA_FUNCTIONS(bits,mode)  \
    const OSSL_DISPATCH my_aria##bits##mode##_functions[] = {           \
        { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void)) aria_##bits##_##mode##_get_params }, \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))aria_##bits##_##mode##_einit }, \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))aria_##bits##_##mode##_dinit }, \
        DECLARE_ARIA_DISPATCHER,                                        \
        OSSL_DISPATCH_END                                               \
    };

DEFINE_ARIA_FUNCTIONS(128, cbc)
DEFINE_ARIA_FUNCTIONS(192, cbc)
DEFINE_ARIA_FUNCTIONS(256, cbc)

/* The table of ciphers this provider offers */
#define ALG(NAMES, FUNC) { NAMES, "provider=ariacipher", FUNC }
#define PROV_NAMES_ARIA_256_CBC "MARIA-256-CBC:MARIA256" //:1.2.410.200046.1.1.12"
#define PROV_NAMES_ARIA_192_CBC "MARIA-192-CBC:MARIA192" //:1.2.410.200046.1.1.7"
#define PROV_NAMES_ARIA_128_CBC "MARIA-128-CBC:MARIA128" //:1.2.410.200046.1.1.2"

static const OSSL_ALGORITHM my_ciphers[] = {
    ALG(PROV_NAMES_ARIA_256_CBC, my_aria256cbc_functions),
    ALG(PROV_NAMES_ARIA_192_CBC, my_aria192cbc_functions),
    ALG(PROV_NAMES_ARIA_128_CBC, my_aria128cbc_functions),
    { NULL, NULL, NULL }
};

/* The function that returns the appropriate algorithm table per operation */
static const OSSL_ALGORITHM *my_prov_operation(void *provctx,
                                               int operation_id,
                                               int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_CIPHER:
        return my_ciphers;
    }
    return NULL;
}

static const OSSL_ITEM reason_strings[] = {
    { 0, NULL }
};

static const OSSL_ITEM *my_prov_get_reason_strings(void *provctx)
{
    return reason_strings;
}

static int my_prov_get_params(void *provctx, OSSL_PARAM *params)
{
    DIE(get_params);
    return 1;
}

/* The function that tears down this provider */
static void my_prov_teardown(void *provctx)
{
    /* teardown resources */
}

/* The base dispatch table */
typedef void (*funcptr_t)(void);
static const OSSL_DISPATCH provider_functions[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN,              (funcptr_t)my_prov_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION,       (funcptr_t)my_prov_operation },
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,    (funcptr_t)my_prov_get_reason_strings },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,            (funcptr_t)my_prov_get_params },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    *out = provider_functions;
    /* do 3rd party init and keep the handle */
    *provctx = (void *)handle;

    OSSL_PROVIDER *deflt = OSSL_PROVIDER_load(NULL, "default");
    if (deflt == NULL) {
        printf("Failed to load Default provider\n");
        return 0;
    }
    return 1;
}
    
