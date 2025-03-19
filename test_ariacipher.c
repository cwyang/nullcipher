#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/core.h>
#include <openssl/provider.h>

static const unsigned char plaintext[] = "Quick Brown Fox Jumps over the Little Lazy Do";
static unsigned char key[32];
static unsigned char iv[32];

static void init_key_iv() 
{
    int i;

    for (i = 0; i < 32; i ++)
        key[i] = iv[i] = i;
}
static unsigned char ciphertext[sizeof(plaintext)+1024];
static unsigned char plaintext2[sizeof(plaintext)+1024];

#define T(e)                                    \
    if (!(e)) {                                 \
        ERR_print_errors_fp(stderr);            \
        OPENSSL_die(#e, __FILE__, __LINE__);    \
    }
#define TF(e)                                   \
    if ((e)) {                                  \
        ERR_print_errors_fp(stderr);            \
    } else {                                    \
        OPENSSL_die(#e, __FILE__, __LINE__);    \
    }
#define TEST_ASSERT(e)                          \
    {                                           \
        int ee = (e);                           \
        if (!(test |= ee))                      \
            printf("FAILED\n");                 \
        else                                    \
            printf("passed\n");                 \
        test |= ee;                             \
    }

void hexdump(const void *ptr, size_t len)
{
    const unsigned char *p = ptr;
    size_t i, j;

    for (i = 0; i < len; i += j) {
        for (j = 0; j < 16 && i + j < len; j++)
            printf("%s%02x", j? "" : " ", p[i + j]);
    }
    printf("\n\t\t");
    for (i = 0; i < len; i += j) {
        for (j = 0; j < 16 && i + j < len; j++)
            printf("%c", isprint(p[i+j])? p[i + j] : '-');
    }
    printf("\n");
}

int main()
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *prov = NULL;
    OSSL_PROVIDER *defprov = NULL;
    EVP_CIPHER *cipher_maria = NULL;
    EVP_CIPHER *cipher_aria = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int outl = 0, outlf = 0;
    int outl2 = 0, outl2f = 0;
    int test = 0;

    init_key_iv();
    
    // load custom null cipher
    // T((c = EVP_CIPHER_fetch(libctx, "NULL", NULL)) == NULL);
    printf("Loading ariacipher provider...\n");
    T((prov = OSSL_PROVIDER_load(libctx, "ariacipher")) != NULL);
    printf("Loading default provider...\n");
    T((defprov = OSSL_PROVIDER_load(libctx, "default")) != NULL);
    T((cipher_maria = EVP_CIPHER_fetch(libctx, "MARIA256", NULL)) != NULL);
    T((cipher_aria = EVP_CIPHER_fetch(libctx, "ARIA256", NULL)) != NULL);    
    T((ctx = EVP_CIPHER_CTX_new()) != NULL);
    
    printf("Encrypting..\n");
    // Encryption
    T(EVP_CipherInit(ctx, cipher_aria, key, iv, 1));
    T(EVP_CipherUpdate(ctx, ciphertext, &outl, plaintext, sizeof(plaintext)));
    T(EVP_CipherFinal(ctx, ciphertext + outl, &outlf));
    printf("Encrypting %ld bytes to %d bytes (%d)\n", sizeof(plaintext), outl + outlf, ciphertext[outl + outlf]);
    printf("Ciphertext[%d] = ", outl + outlf);
    hexdump(ciphertext, outl + outlf);
    printf("Decrypting..\n");
    // Decryption
    T(EVP_CipherInit(ctx, cipher_maria, key, iv, 0));
    T(EVP_CipherUpdate(ctx, plaintext2, &outl2, ciphertext, outl+outlf));
    printf("Decrypting %d bytes to %d bytes\n", outl+outlf, outl2);
    T(EVP_CipherFinal(ctx, plaintext2 + outl2, &outl2f));
  
    printf("Plaintext[%zu]  = ", sizeof(plaintext));
    hexdump(plaintext, sizeof(plaintext));
    printf("Key[%zu]        = ", sizeof(key));
    hexdump(key, sizeof(key));
    printf("Ciphertext[%d] = ", outl + outlf);
    hexdump(ciphertext, outl + outlf);
    printf("Plaintext2[%d] = ", outl2 + outl2f);
    hexdump(plaintext2, outl2 + outl2f);

    printf("Enc & Decrypting plaintext should return itself.. (%ld, %d)", sizeof(plaintext), outl2+outl2f);
    TEST_ASSERT(sizeof(plaintext) == outl2 + outl2f
                && memcmp(plaintext, plaintext2, sizeof(plaintext)) == 0);

  
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher_aria);
    EVP_CIPHER_free(cipher_maria);
    OSSL_PROVIDER_unload(prov);
    OSSL_PROVIDER_unload(defprov);

    return !test;
}

