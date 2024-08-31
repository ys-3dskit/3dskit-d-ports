/**
 * \file aesni.h
 *
 * \brief AES-NI for hardware AES acceleration on some Intel processors
 *
 * \warning These functions are only for internal use by other library
 *          functions; you must not call them directly.
 */

import ys3ds.mbedtls.aes;

extern (C):

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

enum MBEDTLS_AESNI_AES = 0x02000000u;
enum MBEDTLS_AESNI_CLMUL = 0x00000002u;

/* Can we do AESNI with intrinsics?
 * (Only implemented with certain compilers, only for certain targets.)
 *
 * NOTE: MBEDTLS_AESNI_HAVE_INTRINSICS and MBEDTLS_AESNI_HAVE_CODE are internal
 *       macros that may change in future releases.
 */

/* Visual Studio supports AESNI intrinsics since VS 2008 SP1. We only support
 * VS 2013 and up for other reasons anyway, so no need to check the version. */

/* GCC-like compilers: currently, we only support intrinsics if the requisite
 * target flag is enabled when building the library (e.g. `gcc -mpclmul -msse2`
 * or `clang -maes -mpclmul`). */

/* Choose the implementation of AESNI, if one is available. */

/* To minimize disruption when releasing the intrinsics-based implementation,
 * favor the assembly-based implementation if it's available. We intend to
 * revise this in a later release of Mbed TLS 3.x. In the long run, we will
 * likely remove the assembly implementation. */
/* Can we do AESNI with inline assembly?
 * (Only implemented with gas syntax, only for 64-bit.)
 */
enum MBEDTLS_AESNI_HAVE_CODE = 1; // via assembly

// via intrinsics

/**
 * \brief          Internal function to detect the AES-NI feature in CPUs.
 *
 * \note           This function is only for internal use by other library
 *                 functions; you must not call it directly.
 *
 * \param what     The feature to detect
 *                 (MBEDTLS_AESNI_AES or MBEDTLS_AESNI_CLMUL)
 *
 * \return         1 if CPU has support for the feature, 0 otherwise
 */
int mbedtls_aesni_has_support (uint what);

/**
 * \brief          Internal AES-NI AES-ECB block encryption and decryption
 *
 * \note           This function is only for internal use by other library
 *                 functions; you must not call it directly.
 *
 * \param ctx      AES context
 * \param mode     MBEDTLS_AES_ENCRYPT or MBEDTLS_AES_DECRYPT
 * \param input    16-byte input block
 * \param output   16-byte output block
 *
 * \return         0 on success (cannot fail)
 */
int mbedtls_aesni_crypt_ecb (
    mbedtls_aes_context* ctx,
    int mode,
    ref const(ubyte)[16] input,
    ref ubyte[16] output);

/**
 * \brief          Internal GCM multiplication: c = a * b in GF(2^128)
 *
 * \note           This function is only for internal use by other library
 *                 functions; you must not call it directly.
 *
 * \param c        Result
 * \param a        First operand
 * \param b        Second operand
 *
 * \note           Both operands and result are bit strings interpreted as
 *                 elements of GF(2^128) as per the GCM spec.
 */
void mbedtls_aesni_gcm_mult (
    ref ubyte[16] c,
    ref const(ubyte)[16] a,
    ref const(ubyte)[16] b);

/**
 * \brief           Internal round key inversion. This function computes
 *                  decryption round keys from the encryption round keys.
 *
 * \note            This function is only for internal use by other library
 *                  functions; you must not call it directly.
 *
 * \param invkey    Round keys for the equivalent inverse cipher
 * \param fwdkey    Original round keys (for encryption)
 * \param nr        Number of rounds (that is, number of round keys minus one)
 */
void mbedtls_aesni_inverse_key (ubyte* invkey, const(ubyte)* fwdkey, int nr);

/**
 * \brief           Internal key expansion for encryption
 *
 * \note            This function is only for internal use by other library
 *                  functions; you must not call it directly.
 *
 * \param rk        Destination buffer where the round keys are written
 * \param key       Encryption key
 * \param bits      Key size in bits (must be 128, 192 or 256)
 *
 * \return          0 if successful, or MBEDTLS_ERR_AES_INVALID_KEY_LENGTH
 */
int mbedtls_aesni_setkey_enc (ubyte* rk, const(ubyte)* key, size_t bits);

/* MBEDTLS_AESNI_HAVE_CODE */
/* MBEDTLS_AESNI_C && (MBEDTLS_HAVE_X86_64 || MBEDTLS_HAVE_X86) */

/* MBEDTLS_AESNI_H */
