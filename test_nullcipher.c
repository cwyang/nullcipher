#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/core.h>
#include <openssl/provider.h>

static const unsigned char plaintext[] = "Quick Brown Fox Jumps over the Little Lazy Dog";
static const unsigned char key[] = { 'D', 'E', 'A', 'D', 'B', 'E', 'E', 'F'};
static unsigned char ciphertext[sizeof(plaintext)];
static unsigned char plaintext2[sizeof(plaintext)];

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
    EVP_CIPHER *c = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int outl = 0, outlf = 0;
    int outl2 = 0, outl2f = 0;
    int test = 0;
  
    // load custom null cipher
    // T((c = EVP_CIPHER_fetch(libctx, "NULL", NULL)) == NULL);
    printf("Loading nullcipher provider...\n");
    T((prov = OSSL_PROVIDER_load(libctx, "nullcipher")) != NULL);
    T((c = EVP_CIPHER_fetch(libctx, "NULL", NULL)) != NULL);
    T((ctx = EVP_CIPHER_CTX_new()) != NULL);
    // Encryption
    T(EVP_CipherInit(ctx, c, NULL, NULL, 1));
    T(EVP_CipherUpdate(ctx, ciphertext, &outl, plaintext, sizeof(plaintext)));
    T(EVP_CipherFinal(ctx, ciphertext + outl, &outlf));
    // Decryption
    T(EVP_CipherInit(ctx, NULL, key, NULL, 0));
    T(EVP_CipherUpdate(ctx, plaintext2, &outl2, ciphertext, outl));
    T(EVP_CipherFinal(ctx, plaintext2 + outl2, &outl2f));
  
    printf("Plaintext[%zu]  = ", sizeof(plaintext));
    hexdump(plaintext, sizeof(plaintext));
    printf("Key[%zu]        = ", sizeof(key));
    hexdump(key, sizeof(key));
    printf("Ciphertext[%d] = ", outl + outlf);
    hexdump(ciphertext, outl + outlf);
    printf("Plaintext2[%d] = ", outl2 + outl2f);
    hexdump(plaintext2, outl2 + outl2f);

    printf("Encrypting plaintext should return itself..");
    TEST_ASSERT(sizeof(plaintext) == outl + outlf
                && memcmp(plaintext, ciphertext, sizeof(plaintext)) == 0);
    
    printf("Decrypting ciphertext should return itself..");
    TEST_ASSERT(sizeof(plaintext2) == outl2 + outl2f
                && memcmp(plaintext, plaintext2, sizeof(plaintext)) == 0);

  
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
    OSSL_PROVIDER_unload(prov);
}

