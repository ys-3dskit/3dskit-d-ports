/**
 * \file ripemd160.h
 *
 * \brief RIPE MD-160 message digest
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

extern (C) @nogc nothrow:

/* MBEDTLS_ERR_RIPEMD160_HW_ACCEL_FAILED is deprecated and should not be used.
 */
/** RIPEMD160 hardware accelerator failed */
enum MBEDTLS_ERR_RIPEMD160_HW_ACCEL_FAILED = -0x0031;

// Regular implementation
//

/**
 * \brief          RIPEMD-160 context structure
 */
struct mbedtls_ripemd160_context
{
    uint[2] total; /*!< number of bytes processed  */
    uint[5] state; /*!< intermediate digest state  */
    ubyte[64] buffer; /*!< data block being processed */
}

/* MBEDTLS_RIPEMD160_ALT */

/* MBEDTLS_RIPEMD160_ALT */

/**
 * \brief          Initialize RIPEMD-160 context
 *
 * \param ctx      RIPEMD-160 context to be initialized
 */
void mbedtls_ripemd160_init (mbedtls_ripemd160_context* ctx);

/**
 * \brief          Clear RIPEMD-160 context
 *
 * \param ctx      RIPEMD-160 context to be cleared
 */
void mbedtls_ripemd160_free (mbedtls_ripemd160_context* ctx);

/**
 * \brief          Clone (the state of) a RIPEMD-160 context
 *
 * \param dst      The destination context
 * \param src      The context to be cloned
 */
void mbedtls_ripemd160_clone (
    mbedtls_ripemd160_context* dst,
    const(mbedtls_ripemd160_context)* src);

/**
 * \brief          RIPEMD-160 context setup
 *
 * \param ctx      context to be initialized
 *
 * \return         0 if successful
 */
int mbedtls_ripemd160_starts_ret (mbedtls_ripemd160_context* ctx);

/**
 * \brief          RIPEMD-160 process buffer
 *
 * \param ctx      RIPEMD-160 context
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 *
 * \return         0 if successful
 */
int mbedtls_ripemd160_update_ret (
    mbedtls_ripemd160_context* ctx,
    const(ubyte)* input,
    size_t ilen);

/**
 * \brief          RIPEMD-160 final digest
 *
 * \param ctx      RIPEMD-160 context
 * \param output   RIPEMD-160 checksum result
 *
 * \return         0 if successful
 */
int mbedtls_ripemd160_finish_ret (
    mbedtls_ripemd160_context* ctx,
    ref ubyte[20] output);

/**
 * \brief          RIPEMD-160 process data block (internal use only)
 *
 * \param ctx      RIPEMD-160 context
 * \param data     buffer holding one block of data
 *
 * \return         0 if successful
 */
int mbedtls_internal_ripemd160_process (
    mbedtls_ripemd160_context* ctx,
    ref const(ubyte)[64] data);

/**
 * \brief          RIPEMD-160 context setup
 *
 * \deprecated     Superseded by mbedtls_ripemd160_starts_ret() in 2.7.0
 *
 * \param ctx      context to be initialized
 */
void mbedtls_ripemd160_starts (mbedtls_ripemd160_context* ctx);

/**
 * \brief          RIPEMD-160 process buffer
 *
 * \deprecated     Superseded by mbedtls_ripemd160_update_ret() in 2.7.0
 *
 * \param ctx      RIPEMD-160 context
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 */
void mbedtls_ripemd160_update (
    mbedtls_ripemd160_context* ctx,
    const(ubyte)* input,
    size_t ilen);

/**
 * \brief          RIPEMD-160 final digest
 *
 * \deprecated     Superseded by mbedtls_ripemd160_finish_ret() in 2.7.0
 *
 * \param ctx      RIPEMD-160 context
 * \param output   RIPEMD-160 checksum result
 */
void mbedtls_ripemd160_finish (
    mbedtls_ripemd160_context* ctx,
    ref ubyte[20] output);

/**
 * \brief          RIPEMD-160 process data block (internal use only)
 *
 * \deprecated     Superseded by mbedtls_internal_ripemd160_process() in 2.7.0
 *
 * \param ctx      RIPEMD-160 context
 * \param data     buffer holding one block of data
 */
void mbedtls_ripemd160_process (
    mbedtls_ripemd160_context* ctx,
    ref const(ubyte)[64] data);

/* !MBEDTLS_DEPRECATED_REMOVED */

/**
 * \brief          Output = RIPEMD-160( input buffer )
 *
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 * \param output   RIPEMD-160 checksum result
 *
 * \return         0 if successful
 */
int mbedtls_ripemd160_ret (
    const(ubyte)* input,
    size_t ilen,
    ref ubyte[20] output);

/**
 * \brief          Output = RIPEMD-160( input buffer )
 *
 * \deprecated     Superseded by mbedtls_ripemd160_ret() in 2.7.0
 *
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 * \param output   RIPEMD-160 checksum result
 */
void mbedtls_ripemd160 (const(ubyte)* input, size_t ilen, ref ubyte[20] output);

/* !MBEDTLS_DEPRECATED_REMOVED */

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */

/* MBEDTLS_SELF_TEST */

/* mbedtls_ripemd160.h */
