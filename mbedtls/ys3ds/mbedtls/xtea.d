/**
 * \file xtea.h
 *
 * \brief XTEA block cipher (32-bit)
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

extern (C):

enum MBEDTLS_XTEA_ENCRYPT = 1;
enum MBEDTLS_XTEA_DECRYPT = 0;

/** The data input has an invalid length. */
enum MBEDTLS_ERR_XTEA_INVALID_INPUT_LENGTH = -0x0028;

/* MBEDTLS_ERR_XTEA_HW_ACCEL_FAILED is deprecated and should not be used. */
/** XTEA hardware accelerator failed. */
enum MBEDTLS_ERR_XTEA_HW_ACCEL_FAILED = -0x0029;

// Regular implementation
//

/**
 * \brief          XTEA context structure
 */
struct mbedtls_xtea_context
{
    uint[4] k; /*!< key */
}

/* MBEDTLS_XTEA_ALT */

/* MBEDTLS_XTEA_ALT */

/**
 * \brief          Initialize XTEA context
 *
 * \param ctx      XTEA context to be initialized
 */
void mbedtls_xtea_init (mbedtls_xtea_context* ctx);

/**
 * \brief          Clear XTEA context
 *
 * \param ctx      XTEA context to be cleared
 */
void mbedtls_xtea_free (mbedtls_xtea_context* ctx);

/**
 * \brief          XTEA key schedule
 *
 * \param ctx      XTEA context to be initialized
 * \param key      the secret key
 */
void mbedtls_xtea_setup (mbedtls_xtea_context* ctx, ref const(ubyte)[16] key);

/**
 * \brief          XTEA cipher function
 *
 * \param ctx      XTEA context
 * \param mode     MBEDTLS_XTEA_ENCRYPT or MBEDTLS_XTEA_DECRYPT
 * \param input    8-byte input block
 * \param output   8-byte output block
 *
 * \return         0 if successful
 */
int mbedtls_xtea_crypt_ecb (
    mbedtls_xtea_context* ctx,
    int mode,
    ref const(ubyte)[8] input,
    ref ubyte[8] output);

/**
 * \brief          XTEA CBC cipher function
 *
 * \param ctx      XTEA context
 * \param mode     MBEDTLS_XTEA_ENCRYPT or MBEDTLS_XTEA_DECRYPT
 * \param length   the length of input, multiple of 8
 * \param iv       initialization vector for CBC mode
 * \param input    input block
 * \param output   output block
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_XTEA_INVALID_INPUT_LENGTH if the length % 8 != 0
 */
int mbedtls_xtea_crypt_cbc (
    mbedtls_xtea_context* ctx,
    int mode,
    size_t length,
    ref ubyte[8] iv,
    const(ubyte)* input,
    ubyte* output);
/* MBEDTLS_CIPHER_MODE_CBC */

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */

/* MBEDTLS_SELF_TEST */

/* xtea.h */
