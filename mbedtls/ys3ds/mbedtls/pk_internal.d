/**
 * \file pk_internal.h
 *
 * \brief Public Key abstraction layer: wrapper functions
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

extern (C):

struct mbedtls_pk_info_t_
{
    /** Public key type */
    mbedtls_pk_type_t type;

    /** Type name */
    const(char)* name;

    /** Get key size in bits */
    size_t function (const(void)*) get_bitlen;

    /** Tell if the context implements this type (e.g. ECKEY can do ECDSA) */
    int function (mbedtls_pk_type_t type) can_do;

    /** Verify signature */
    int function (
        void* ctx,
        mbedtls_md_type_t md_alg,
        const(ubyte)* hash,
        size_t hash_len,
        const(ubyte)* sig,
        size_t sig_len) verify_func;

    /** Make signature */
    int function (
        void* ctx,
        mbedtls_md_type_t md_alg,
        const(ubyte)* hash,
        size_t hash_len,
        ubyte* sig,
        size_t* sig_len,
        int function (void*, ubyte*, size_t) f_rng,
        void* p_rng) sign_func;

    /** Verify signature (restartable) */

    /** Make signature (restartable) */

    /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

    /** Decrypt message */
    int function (
        void* ctx,
        const(ubyte)* input,
        size_t ilen,
        ubyte* output,
        size_t* olen,
        size_t osize,
        int function (void*, ubyte*, size_t) f_rng,
        void* p_rng) decrypt_func;

    /** Encrypt message */
    int function (
        void* ctx,
        const(ubyte)* input,
        size_t ilen,
        ubyte* output,
        size_t* olen,
        size_t osize,
        int function (void*, ubyte*, size_t) f_rng,
        void* p_rng) encrypt_func;

    /** Check public-private key pair */
    int function (const(void)* pub, const(void)* prv) check_pair_func;

    /** Allocate a new context */
    void* function () ctx_alloc_func;

    /** Free the given context */
    void function (void* ctx) ctx_free_func;

    /** Allocate the restart context */

    /** Free the restart context */

    /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

    /** Interface with the debug module */
    void function (const(void)* ctx, mbedtls_pk_debug_item* items) debug_func;
}

/* Container for RSA-alt */
struct mbedtls_rsa_alt_context
{
    void* key;
    mbedtls_pk_rsa_alt_decrypt_func decrypt_func;
    mbedtls_pk_rsa_alt_sign_func sign_func;
    mbedtls_pk_rsa_alt_key_len_func key_len_func;
}

extern __gshared const mbedtls_pk_info_t mbedtls_rsa_info;

extern __gshared const mbedtls_pk_info_t mbedtls_eckey_info;
extern __gshared const mbedtls_pk_info_t mbedtls_eckeydh_info;

extern __gshared const mbedtls_pk_info_t mbedtls_ecdsa_info;

extern __gshared const mbedtls_pk_info_t mbedtls_rsa_alt_info;

/* MBEDTLS_PK_WRAP_H */
