/**
 * \file sha512.h
 * \brief This file contains SHA-384 and SHA-512 definitions and functions.
 *
 * The Secure Hash Algorithms 384 and 512 (SHA-384 and SHA-512) cryptographic
 * hash functions are defined in <em>FIPS 180-4: Secure Hash Standard (SHS)</em>.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

extern (C):

/* MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED is deprecated and should not be used. */
/** SHA-512 hardware accelerator failed */
enum MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED = -0x0039;
/** SHA-512 input data was malformed. */
enum MBEDTLS_ERR_SHA512_BAD_INPUT_DATA = -0x0075;

// Regular implementation
//

/**
 * \brief          The SHA-512 context structure.
 *
 *                 The structure is used both for SHA-384 and for SHA-512
 *                 checksum calculations. The choice between these two is
 *                 made in the call to mbedtls_sha512_starts_ret().
 */
struct mbedtls_sha512_context
{
    ulong[2] total; /*!< The number of Bytes processed. */
    ulong[8] state; /*!< The intermediate digest state. */
    ubyte[128] buffer; /*!< The data block being processed. */

    int is384; /*!< Determines which function to use:
         0: Use SHA-512, or 1: Use SHA-384. */
}

/* MBEDTLS_SHA512_ALT */

/* MBEDTLS_SHA512_ALT */

/**
 * \brief          This function initializes a SHA-512 context.
 *
 * \param ctx      The SHA-512 context to initialize. This must
 *                 not be \c NULL.
 */
void mbedtls_sha512_init (mbedtls_sha512_context* ctx);

/**
 * \brief          This function clears a SHA-512 context.
 *
 * \param ctx      The SHA-512 context to clear. This may be \c NULL,
 *                 in which case this function does nothing. If it
 *                 is not \c NULL, it must point to an initialized
 *                 SHA-512 context.
 */
void mbedtls_sha512_free (mbedtls_sha512_context* ctx);

/**
 * \brief          This function clones the state of a SHA-512 context.
 *
 * \param dst      The destination context. This must be initialized.
 * \param src      The context to clone. This must be initialized.
 */
void mbedtls_sha512_clone (
    mbedtls_sha512_context* dst,
    const(mbedtls_sha512_context)* src);

/**
 * \brief          This function starts a SHA-384 or SHA-512 checksum
 *                 calculation.
 *
 * \param ctx      The SHA-512 context to use. This must be initialized.
 * \param is384    Determines which function to use. This must be
 *                 either \c 0 for SHA-512, or \c 1 for SHA-384.
 *
 * \note           When \c MBEDTLS_SHA512_NO_SHA384 is defined, \p is384 must
 *                 be \c 0, or the function will return
 *                 #MBEDTLS_ERR_SHA512_BAD_INPUT_DATA.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_sha512_starts_ret (mbedtls_sha512_context* ctx, int is384);

/**
 * \brief          This function feeds an input buffer into an ongoing
 *                 SHA-512 checksum calculation.
 *
 * \param ctx      The SHA-512 context. This must be initialized
 *                 and have a hash operation started.
 * \param input    The buffer holding the input data. This must
 *                 be a readable buffer of length \p ilen Bytes.
 * \param ilen     The length of the input data in Bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_sha512_update_ret (
    mbedtls_sha512_context* ctx,
    const(ubyte)* input,
    size_t ilen);

/**
 * \brief          This function finishes the SHA-512 operation, and writes
 *                 the result to the output buffer.
 *
 * \param ctx      The SHA-512 context. This must be initialized
 *                 and have a hash operation started.
 * \param output   The SHA-384 or SHA-512 checksum result.
 *                 This must be a writable buffer of length \c 64 Bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_sha512_finish_ret (
    mbedtls_sha512_context* ctx,
    ref ubyte[64] output);

/**
 * \brief          This function processes a single data block within
 *                 the ongoing SHA-512 computation.
 *                 This function is for internal use only.
 *
 * \param ctx      The SHA-512 context. This must be initialized.
 * \param data     The buffer holding one block of data. This
 *                 must be a readable buffer of length \c 128 Bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_internal_sha512_process (
    mbedtls_sha512_context* ctx,
    ref const(ubyte)[128] data);

/**
 * \brief          This function starts a SHA-384 or SHA-512 checksum
 *                 calculation.
 *
 * \deprecated     Superseded by mbedtls_sha512_starts_ret() in 2.7.0
 *
 * \param ctx      The SHA-512 context to use. This must be initialized.
 * \param is384    Determines which function to use. This must be either
 *                 \c 0 for SHA-512 or \c 1 for SHA-384.
 *
 * \note           When \c MBEDTLS_SHA512_NO_SHA384 is defined, \p is384 must
 *                 be \c 0, or the function will fail to work.
 */
void mbedtls_sha512_starts (mbedtls_sha512_context* ctx, int is384);

/**
 * \brief          This function feeds an input buffer into an ongoing
 *                 SHA-512 checksum calculation.
 *
 * \deprecated     Superseded by mbedtls_sha512_update_ret() in 2.7.0.
 *
 * \param ctx      The SHA-512 context. This must be initialized
 *                 and have a hash operation started.
 * \param input    The buffer holding the data. This must be a readable
 *                 buffer of length \p ilen Bytes.
 * \param ilen     The length of the input data in Bytes.
 */
void mbedtls_sha512_update (
    mbedtls_sha512_context* ctx,
    const(ubyte)* input,
    size_t ilen);

/**
 * \brief          This function finishes the SHA-512 operation, and writes
 *                 the result to the output buffer.
 *
 * \deprecated     Superseded by mbedtls_sha512_finish_ret() in 2.7.0.
 *
 * \param ctx      The SHA-512 context. This must be initialized
 *                 and have a hash operation started.
 * \param output   The SHA-384 or SHA-512 checksum result. This must
 *                 be a writable buffer of size \c 64 Bytes.
 */
void mbedtls_sha512_finish (mbedtls_sha512_context* ctx, ref ubyte[64] output);

/**
 * \brief          This function processes a single data block within
 *                 the ongoing SHA-512 computation. This function is for
 *                 internal use only.
 *
 * \deprecated     Superseded by mbedtls_internal_sha512_process() in 2.7.0.
 *
 * \param ctx      The SHA-512 context. This must be initialized.
 * \param data     The buffer holding one block of data. This must be
 *                 a readable buffer of length \c 128 Bytes.
 */
void mbedtls_sha512_process (
    mbedtls_sha512_context* ctx,
    ref const(ubyte)[128] data);

/* !MBEDTLS_DEPRECATED_REMOVED */

/**
 * \brief          This function calculates the SHA-512 or SHA-384
 *                 checksum of a buffer.
 *
 *                 The function allocates the context, performs the
 *                 calculation, and frees the context.
 *
 *                 The SHA-512 result is calculated as
 *                 output = SHA-512(input buffer).
 *
 * \param input    The buffer holding the input data. This must be
 *                 a readable buffer of length \p ilen Bytes.
 * \param ilen     The length of the input data in Bytes.
 * \param output   The SHA-384 or SHA-512 checksum result.
 *                 This must be a writable buffer of length \c 64 Bytes.
 * \param is384    Determines which function to use. This must be either
 *                 \c 0 for SHA-512, or \c 1 for SHA-384.
 *
 * \note           When \c MBEDTLS_SHA512_NO_SHA384 is defined, \p is384 must
 *                 be \c 0, or the function will return
 *                 #MBEDTLS_ERR_SHA512_BAD_INPUT_DATA.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_sha512_ret (
    const(ubyte)* input,
    size_t ilen,
    ref ubyte[64] output,
    int is384);

/**
 * \brief          This function calculates the SHA-512 or SHA-384
 *                 checksum of a buffer.
 *
 *                 The function allocates the context, performs the
 *                 calculation, and frees the context.
 *
 *                 The SHA-512 result is calculated as
 *                 output = SHA-512(input buffer).
 *
 * \deprecated     Superseded by mbedtls_sha512_ret() in 2.7.0
 *
 * \param input    The buffer holding the data. This must be a
 *                 readable buffer of length \p ilen Bytes.
 * \param ilen     The length of the input data in Bytes.
 * \param output   The SHA-384 or SHA-512 checksum result. This must
 *                 be a writable buffer of length \c 64 Bytes.
 * \param is384    Determines which function to use. This must be either
 *                 \c 0 for SHA-512, or \c 1 for SHA-384.
 *
 * \note           When \c MBEDTLS_SHA512_NO_SHA384 is defined, \p is384 must
 *                 be \c 0, or the function will fail to work.
 */
void mbedtls_sha512 (
    const(ubyte)* input,
    size_t ilen,
    ref ubyte[64] output,
    int is384);

/* !MBEDTLS_DEPRECATED_REMOVED */

/**
 * \brief          The SHA-384 or SHA-512 checkup routine.
 *
 * \return         \c 0 on success.
 * \return         \c 1 on failure.
 */

/* MBEDTLS_SELF_TEST */

/* mbedtls_sha512.h */
