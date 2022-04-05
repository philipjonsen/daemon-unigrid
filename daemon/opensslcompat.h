#ifndef _SWIPP_OPENSSLCOMPAT_H_
#define _SWIPP_OPENSSLCOMPAT_H_

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#include <openssl/ecdh.h>

#define DEF_BIGNUM BIGNUM
#define DEF_BN_init(a) BN_init(&a)
#define DEF_HMAC_CTX HMAC_CTX
#define DEF_HMAC_CTX_init(a) HMAC_CTX_init(&a)
#define DEF_HMAC_CTX_cleanup(a) HMAC_CTX_init(&a)
#define DEF_EVP_CIPHER_CTX EVP_CIPHER_CTX
#define DEF_EVP_CHIPER_CTX_init(a) EVP_CIPHER_CTX_init(&a)
#define DEF_ECDHKEY_set_method(a) ECDH_set_method(a, ECDH_OpenSSL())
#define SSL_ADDR(a) &a

#else

#include <openssl/ec.h>

#define DEF_BIGNUM BIGNUM *
#define DEF_BN_init(a) a = BN_new()
#define DEF_HMAC_CTX HMAC_CTX *
#define DEF_HMAC_CTX_init(a) a = HMAC_CTX_new()
#define DEF_HMAC_CTX_cleanup(a) HMAC_CTX_free(a)
#define DEF_EVP_CHIPER_CTX EVP_CHIPER_CTX *
#define DEF_EVP_CHIPER_CTX_init(a) a = EVP_CHIPER_CTX_new()
#define DEF_ECDHKEY_set_method(a) EC_KEY_set_method(a, EC_KEY_OpenSSL());
#define SSL_ADDR(a) a

#endif

extern "C" BIGNUM *ECDSA_SIG_getr(const ECDSA_SIG *sig);
extern "C" BIGNUM *ECDSA_SIG_gets(const ECDSA_SIG *sig);

#endif