/**
 * \file cipher_internal.h
 *
 * \brief Cipher wrappers.
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

extern (C):

/* MBEDTLS_USE_PSA_CRYPTO */

/**
 * Base cipher information. The non-mode specific functions and values.
 */
struct mbedtls_cipher_base_t_
{
    /** Base Cipher type (e.g. MBEDTLS_CIPHER_ID_AES) */
    mbedtls_cipher_id_t cipher;

    /** Encrypt using ECB */
    int function (
        void* ctx,
        mbedtls_operation_t mode,
        const(ubyte)* input,
        ubyte* output) ecb_func;

    /** Encrypt using CBC */
    int function (
        void* ctx,
        mbedtls_operation_t mode,
        size_t length,
        ubyte* iv,
        const(ubyte)* input,
        ubyte* output) cbc_func;

    /** Encrypt using CFB (Full length) */
    int function (
        void* ctx,
        mbedtls_operation_t mode,
        size_t length,
        size_t* iv_off,
        ubyte* iv,
        const(ubyte)* input,
        ubyte* output) cfb_func;

    /** Encrypt using OFB (Full length) */
    int function (
        void* ctx,
        size_t length,
        size_t* iv_off,
        ubyte* iv,
        const(ubyte)* input,
        ubyte* output) ofb_func;

    /** Encrypt using CTR */
    int function (
        void* ctx,
        size_t length,
        size_t* nc_off,
        ubyte* nonce_counter,
        ubyte* stream_block,
        const(ubyte)* input,
        ubyte* output) ctr_func;

    /** Encrypt or decrypt using XTS. */
    int function (
        void* ctx,
        mbedtls_operation_t mode,
        size_t length,
        const(ubyte)[16] data_unit,
        const(ubyte)* input,
        ubyte* output) xts_func;

    /** Encrypt using STREAM */
    int function (
        void* ctx,
        size_t length,
        const(ubyte)* input,
        ubyte* output) stream_func;

    /** Set key for encryption purposes */
    int function (
        void* ctx,
        const(ubyte)* key,
        uint key_bitlen) setkey_enc_func;

    /** Set key for decryption purposes */
    int function (
        void* ctx,
        const(ubyte)* key,
        uint key_bitlen) setkey_dec_func;

    /** Allocate a new context */
    void* function () ctx_alloc_func;

    /** Free the given context */
    void function (void* ctx) ctx_free_func;
}

struct mbedtls_cipher_definition_t
{
    mbedtls_cipher_type_t type;
    const(mbedtls_cipher_info_t)* info;
}

/* Used for PSA-based cipher contexts which */
/* use raw key material internally imported */
/* as a volatile key, and which hence need  */
/* to destroy that key when the context is  */
/* freed.                                   */
/* Used for PSA-based cipher contexts   */
/* which use a key provided by the      */
/* user, and which hence will not be    */
/* destroyed when the context is freed. */

/* MBEDTLS_USE_PSA_CRYPTO */

extern __gshared const(mbedtls_cipher_definition_t)[] mbedtls_cipher_definitions;

extern __gshared int[] mbedtls_cipher_supported;

/* MBEDTLS_CIPHER_WRAP_H */
