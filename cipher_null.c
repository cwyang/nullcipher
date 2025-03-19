#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>

#define ERR_raise(x,y) (void)0
static const OSSL_ITEM reason_strings[] = {
    { 0, NULL }
};

static OSSL_FUNC_provider_query_operation_fn my_prov_operation;
static OSSL_FUNC_provider_get_params_fn my_prov_get_params;
static OSSL_FUNC_provider_get_reason_strings_fn my_prov_get_reason_strings;

static OSSL_FUNC_cipher_newctx_fn my_newctx;
static OSSL_FUNC_cipher_encrypt_init_fn my_encrypt_init;
static OSSL_FUNC_cipher_decrypt_init_fn my_decrypt_init;
static OSSL_FUNC_cipher_update_fn my_update;
static OSSL_FUNC_cipher_final_fn my_final;
static OSSL_FUNC_cipher_dupctx_fn my_dupctx;
static OSSL_FUNC_cipher_freectx_fn my_freectx;
static OSSL_FUNC_cipher_get_params_fn my_get_params;
static OSSL_FUNC_cipher_gettable_params_fn my_gettable_params;
static OSSL_FUNC_cipher_set_ctx_params_fn my_set_ctx_params;
static OSSL_FUNC_cipher_get_ctx_params_fn my_get_ctx_params;
static OSSL_FUNC_cipher_settable_ctx_params_fn my_settable_ctx_params;
static OSSL_FUNC_cipher_gettable_ctx_params_fn my_gettable_ctx_params;

struct my_ctx_st {
    void *provctx;
    /* more to come */
};

static void *my_newctx(void *provctx)
{
    struct my_ctx_st *ctx = malloc(sizeof(*ctx));

    if (ctx != NULL) {
        memset(ctx, 0, sizeof(*ctx));
        ctx->provctx = provctx;
    }
    return ctx;
}

static void my_cleanctx(void *_ctx)
{
    struct my_ctx_st *ctx = _ctx;

    if (ctx == NULL)
        return;
}

static void *my_dupctx(void *ctx)
{
    struct my_ctx_st *src = ctx;
    struct my_ctx_st *dst = NULL;

    if (src == NULL
        || (dst = my_newctx(NULL)) == NULL)

    dst->provctx = src->provctx;
    return dst;
}

static void my_freectx(void *_ctx)
{
    struct my_ctx_st *ctx = _ctx;

    ctx->provctx = NULL;
    my_cleanctx(ctx);
    free(ctx);
}

static int my_encrypt_init(void *_ctx,
                                 const unsigned char *key,
                                 size_t keyl,
                                 const unsigned char *iv_unused,
                                 size_t ivl_unused,
                                 const OSSL_PARAM params[])
{
    struct my_ctx_st *ctx = _ctx;
    
    return 1;
}

static int my_decrypt_init(void *_ctx,
                                 const unsigned char *key,
                                 size_t keyl,
                                 const unsigned char *iv_unused,
                                 size_t ivl_unused,
                                 const OSSL_PARAM params[])
{
    struct my_ctx_st *ctx = _ctx;
    return 1;
}

static int my_update(void *_ctx,
                           unsigned char *out, size_t *outl, size_t outsz,
                           const unsigned char *in, size_t inl)
{
    struct my_ctx_st *ctx = _ctx;

    assert(outsz >= inl);
    assert(out != NULL);
    assert(outl != NULL);

    if (out == NULL)
        return 0;

    for (*outl = 0; inl-- > 0; (*outl)++)
        *out++ = *in++;

    return 1;
}

static int my_final(void *_ctx,
                    unsigned char *out, size_t *outl, size_t outsz)
{
    struct my_ctx_st *ctx = _ctx;

    *outl = 0;

    return 1;
}

static const OSSL_PARAM *my_gettable_params(void *provctx)
{
    static const OSSL_PARAM table[] = {
        { OSSL_CIPHER_PARAM_BLOCK_SIZE, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { OSSL_CIPHER_PARAM_KEYLEN, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { NULL, 0, NULL, 0, 0 },
    };

    return table;
}

static int my_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 1)) {    /* 1 block. no use */
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 4)) {   /* keylen 4. no use */
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return 1;
}

static const OSSL_PARAM *my_gettable_ctx_params(void *cctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        { NULL, 0, NULL, 0, 0 },
    };
    
    return table;
}

static int my_get_ctx_params(void *_ctx, OSSL_PARAM params[])
{
    struct my_ctx_st *ctx = _ctx;
    
    return 1;
}

/* Parameters that libcrypto can send to this implementation */
static const OSSL_PARAM *my_settable_ctx_params(void *cctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        { NULL, 0, NULL, 0, 0 },
    };
    
    return table;
}

static int my_set_ctx_params(void *_ctx, const OSSL_PARAM params[])
{
    struct my_ctx_st *ctx = _ctx;

    return 1;
}


typedef void (*funcptr_t)(void);
static const OSSL_DISPATCH my_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (funcptr_t)my_newctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (funcptr_t)my_encrypt_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (funcptr_t)my_decrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE, (funcptr_t)my_update },
    { OSSL_FUNC_CIPHER_FINAL, (funcptr_t)my_final },
    { OSSL_FUNC_CIPHER_DUPCTX, (funcptr_t)my_dupctx },
    { OSSL_FUNC_CIPHER_FREECTX, (funcptr_t)my_freectx },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (funcptr_t)my_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (funcptr_t)my_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (funcptr_t)my_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
      (funcptr_t)my_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (funcptr_t)my_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
      (funcptr_t)my_settable_ctx_params },
    { 0, NULL }
};

/* The table of ciphers this provider offers */
static const OSSL_ALGORITHM my_ciphers[] = {
    { "NULL", "x.author='" AUTHOR "'",
      my_functions },
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

static const OSSL_ITEM *my_prov_get_reason_strings(void *provctx)
{
    return reason_strings;
}

static int my_prov_get_params(void *provctx, OSSL_PARAM *params)
{
    
    return 1;
}

/* The function that tears down this provider */
static void my_prov_teardown(void *provctx)
{
    /* teardown resources */
}

/* The base dispatch table */
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
    return 1;
}
