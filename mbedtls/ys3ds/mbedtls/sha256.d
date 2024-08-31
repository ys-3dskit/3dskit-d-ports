/**
 * \file sha256.h
 *
 * \brief This file contains SHA-224 and SHA-256 definitions and functions.
 *
 * The Secure Hash Algorithms 224 and 256 (SHA-224 and SHA-256) cryptographic
 * hash functions are defined in <em>FIPS 180-4: Secure Hash Standard (SHS)</em>.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

extern (C) @nogc nothrow:

/* MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED is deprecated and should not be used. */
/** SHA-256 hardware accelerator failed */
enum MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED = -0x0037;
/** SHA-256 input data was malformed. */
enum MBEDTLS_ERR_SHA256_BAD_INPUT_DATA = -0x0074;

// Regular implementation
//

/**
 * \brief          The SHA-256 context structure.
 *
 *                 The structure is used both for SHA-256 and for SHA-224
 *                 checksum calculations. The choice between these two is
 *                 made in the call to mbedtls_sha256_starts_ret().
 */
struct mbedtls_sha256_context
{
    uint[2] total; /*!< The number of Bytes processed.  */
    uint[8] state; /*!< The intermediate digest state.  */
    ubyte[64] buffer; /*!< The data block being processed. */
    int is224; /*!< Determines which function to use:
         0: Use SHA-256, or 1: Use SHA-224. */
}

/* MBEDTLS_SHA256_ALT */

/* MBEDTLS_SHA256_ALT */

/**
 * \brief          This function initializes a SHA-256 context.
 *
 * \param ctx      The SHA-256 context to initialize. This must not be \c NULL.
 */
void mbedtls_sha256_init (mbedtls_sha256_context* ctx);

/**
 * \brief          This function clears a SHA-256 context.
 *
 * \param ctx      The SHA-256 context to clear. This may be \c NULL, in which
 *                 case this function returns immediately. If it is not \c NULL,
 *                 it must point to an initialized SHA-256 context.
 */
void mbedtls_sha256_free (mbedtls_sha256_context* ctx);

/**
 * \brief          This function clones the state of a SHA-256 context.
 *
 * \param dst      The destination context. This must be initialized.
 * \param src      The context to clone. This must be initialized.
 */
void mbedtls_sha256_clone (
    mbedtls_sha256_context* dst,
    const(mbedtls_sha256_context)* src);

/**
 * \brief          This function starts a SHA-224 or SHA-256 checksum
 *                 calculation.
 *
 * \param ctx      The context to use. This must be initialized.
 * \param is224    This determines which function to use. This must be
 *                 either \c 0 for SHA-256, or \c 1 for SHA-224.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_sha256_starts_ret (mbedtls_sha256_context* ctx, int is224);

/**
 * \brief          This function feeds an input buffer into an ongoing
 *                 SHA-256 checksum calculation.
 *
 * \param ctx      The SHA-256 context. This must be initialized
 *                 and have a hash operation started.
 * \param input    The buffer holding the data. This must be a readable
 *                 buffer of length \p ilen Bytes.
 * \param ilen     The length of the input data in Bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_sha256_update_ret (
    mbedtls_sha256_context* ctx,
    const(ubyte)* input,
    size_t ilen);

/**
 * \brief          This function finishes the SHA-256 operation, and writes
 *                 the result to the output buffer.
 *
 * \param ctx      The SHA-256 context. This must be initialized
 *                 and have a hash operation started.
 * \param output   The SHA-224 or SHA-256 checksum result.
 *                 This must be a writable buffer of length \c 32 Bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_sha256_finish_ret (
    mbedtls_sha256_context* ctx,
    ref ubyte[32] output);

/**
 * \brief          This function processes a single data block within
 *                 the ongoing SHA-256 computation. This function is for
 *                 internal use only.
 *
 * \param ctx      The SHA-256 context. This must be initialized.
 * \param data     The buffer holding one block of data. This must
 *                 be a readable buffer of length \c 64 Bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_internal_sha256_process (
    mbedtls_sha256_context* ctx,
    ref const(ubyte)[64] data);

/**
 * \brief          This function starts a SHA-224 or SHA-256 checksum
 *                 calculation.
 *
 * \deprecated     Superseded by mbedtls_sha256_starts_ret() in 2.7.0.
 *
 * \param ctx      The context to use. This must be initialized.
 * \param is224    Determines which function to use. This must be
 *                 either \c 0 for SHA-256, or \c 1 for SHA-224.
 */
void mbedtls_sha256_starts (mbedtls_sha256_context* ctx, int is224);

/**
 * \brief          This function feeds an input buffer into an ongoing
 *                 SHA-256 checksum calculation.
 *
 * \deprecated     Superseded by mbedtls_sha256_update_ret() in 2.7.0.
 *
 * \param ctx      The SHA-256 context to use. This must be
 *                 initialized and have a hash operation started.
 * \param input    The buffer holding the data. This must be a readable
 *                 buffer of length \p ilen Bytes.
 * \param ilen     The length of the input data in Bytes.
 */
void mbedtls_sha256_update (
    mbedtls_sha256_context* ctx,
    const(ubyte)* input,
    size_t ilen);

/**
 * \brief          This function finishes the SHA-256 operation, and writes
 *                 the result to the output buffer.
 *
 * \deprecated     Superseded by mbedtls_sha256_finish_ret() in 2.7.0.
 *
 * \param ctx      The SHA-256 context. This must be initialized and
 *                 have a hash operation started.
 * \param output   The SHA-224 or SHA-256 checksum result. This must be
 *                 a writable buffer of length \c 32 Bytes.
 */
void mbedtls_sha256_finish (mbedtls_sha256_context* ctx, ref ubyte[32] output);

/**
 * \brief          This function processes a single data block within
 *                 the ongoing SHA-256 computation. This function is for
 *                 internal use only.
 *
 * \deprecated     Superseded by mbedtls_internal_sha256_process() in 2.7.0.
 *
 * \param ctx      The SHA-256 context. This must be initialized.
 * \param data     The buffer holding one block of data. This must be
 *                 a readable buffer of size \c 64 Bytes.
 */
void mbedtls_sha256_process (
    mbedtls_sha256_context* ctx,
    ref const(ubyte)[64] data);

/* !MBEDTLS_DEPRECATED_REMOVED */

/**
 * \brief          This function calculates the SHA-224 or SHA-256
 *                 checksum of a buffer.
 *
 *                 The function allocates the context, performs the
 *                 calculation, and frees the context.
 *
 *                 The SHA-256 result is calculated as
 *                 output = SHA-256(input buffer).
 *
 * \param input    The buffer holding the data. This must be a readable
 *                 buffer of length \p ilen Bytes.
 * \param ilen     The length of the input data in Bytes.
 * \param output   The SHA-224 or SHA-256 checksum result. This must
 *                 be a writable buffer of length \c 32 Bytes.
 * \param is224    Determines which function to use. This must be
 *                 either \c 0 for SHA-256, or \c 1 for SHA-224.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_sha256_ret (
    const(ubyte)* input,
    size_t ilen,
    ref ubyte[32] output,
    int is224);

/**
 * \brief          This function calculates the SHA-224 or SHA-256 checksum
 *                 of a buffer.
 *
 *                 The function allocates the context, performs the
 *                 calculation, and frees the context.
 *
 *                 The SHA-256 result is calculated as
 *                 output = SHA-256(input buffer).
 *
 * \deprecated     Superseded by mbedtls_sha256_ret() in 2.7.0.
 *
 * \param input    The buffer holding the data. This must be a readable
 *                 buffer of length \p ilen Bytes.
 * \param ilen     The length of the input data in Bytes.
 * \param output   The SHA-224 or SHA-256 checksum result. This must be
 *                 a writable buffer of length \c 32 Bytes.
 * \param is224    Determines which function to use. This must be either
 *                 \c 0 for SHA-256, or \c 1 for SHA-224.
 */
void mbedtls_sha256 (
    const(ubyte)* input,
    size_t ilen,
    ref ubyte[32] output,
    int is224);

/* !MBEDTLS_DEPRECATED_REMOVED */

/**
 * \brief          The SHA-224 and SHA-256 checkup routine.
 *
 * \return         \c 0 on success.
 * \return         \c 1 on failure.
 */

/* MBEDTLS_SELF_TEST */

/* mbedtls_sha256.h */
