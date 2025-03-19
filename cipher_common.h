/*
 * 19 Mar 2025, Chul-Woong Yang
 * from openssl-3.4.1/providers/implementations/include/prov/ciphercommon.h
*/

#ifndef MY_PROV_CIPHERCOMMON_H
# define MY_PROV_CIPHERCOMMON_H
# include <openssl/params.h>
# include <openssl/core_dispatch.h>
# include <openssl/core_names.h>
# include <openssl/modes.h>
# include <openssl/evp.h>
# include <openssl/err.h>

#define DIE(e)                                  \
    do {                                        \
        ERR_print_errors_fp(stderr);            \
        OPENSSL_die(#e, __FILE__, __LINE__);    \
    } while (0)

#endif
