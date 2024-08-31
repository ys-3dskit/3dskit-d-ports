/**
 * \file md2.h
 *
 * \brief MD2 message digest algorithm (hash function)
 *
 * \warning MD2 is considered a weak message digest and its use constitutes a
 *          security risk. We recommend considering stronger message digests
 *          instead.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 *
 */

extern (C):

/* MBEDTLS_ERR_MD2_HW_ACCEL_FAILED is deprecated and should not be used. */
/** MD2 hardware accelerator failed */
enum MBEDTLS_ERR_MD2_HW_ACCEL_FAILED = -0x002B;

// Regular implementation
//

/**
 * \brief          MD2 context structure
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
struct mbedtls_md2_context
{
    ubyte[16] cksum; /*!< checksum of the data block */
    ubyte[48] state; /*!< intermediate digest state  */
    ubyte[16] buffer; /*!< data block being processed */
    size_t left; /*!< amount of data in buffer   */
}

/* MBEDTLS_MD2_ALT */

/* MBEDTLS_MD2_ALT */

/**
 * \brief          Initialize MD2 context
 *
 * \param ctx      MD2 context to be initialized
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
void mbedtls_md2_init (mbedtls_md2_context* ctx);

/**
 * \brief          Clear MD2 context
 *
 * \param ctx      MD2 context to be cleared
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
void mbedtls_md2_free (mbedtls_md2_context* ctx);

/**
 * \brief          Clone (the state of) an MD2 context
 *
 * \param dst      The destination context
 * \param src      The context to be cloned
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
void mbedtls_md2_clone (
    mbedtls_md2_context* dst,
    const(mbedtls_md2_context)* src);

/**
 * \brief          MD2 context setup
 *
 * \param ctx      context to be initialized
 *
 * \return         0 if successful
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
int mbedtls_md2_starts_ret (mbedtls_md2_context* ctx);

/**
 * \brief          MD2 process buffer
 *
 * \param ctx      MD2 context
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 *
 * \return         0 if successful
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
int mbedtls_md2_update_ret (
    mbedtls_md2_context* ctx,
    const(ubyte)* input,
    size_t ilen);

/**
 * \brief          MD2 final digest
 *
 * \param ctx      MD2 context
 * \param output   MD2 checksum result
 *
 * \return         0 if successful
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
int mbedtls_md2_finish_ret (mbedtls_md2_context* ctx, ref ubyte[16] output);

/**
 * \brief          MD2 process data block (internal use only)
 *
 * \param ctx      MD2 context
 *
 * \return         0 if successful
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
int mbedtls_internal_md2_process (mbedtls_md2_context* ctx);

/**
 * \brief          MD2 context setup
 *
 * \deprecated     Superseded by mbedtls_md2_starts_ret() in 2.7.0
 *
 * \param ctx      context to be initialized
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
void mbedtls_md2_starts (mbedtls_md2_context* ctx);

/**
 * \brief          MD2 process buffer
 *
 * \deprecated     Superseded by mbedtls_md2_update_ret() in 2.7.0
 *
 * \param ctx      MD2 context
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
void mbedtls_md2_update (
    mbedtls_md2_context* ctx,
    const(ubyte)* input,
    size_t ilen);

/**
 * \brief          MD2 final digest
 *
 * \deprecated     Superseded by mbedtls_md2_finish_ret() in 2.7.0
 *
 * \param ctx      MD2 context
 * \param output   MD2 checksum result
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
void mbedtls_md2_finish (mbedtls_md2_context* ctx, ref ubyte[16] output);

/**
 * \brief          MD2 process data block (internal use only)
 *
 * \deprecated     Superseded by mbedtls_internal_md2_process() in 2.7.0
 *
 * \param ctx      MD2 context
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
void mbedtls_md2_process (mbedtls_md2_context* ctx);

/* !MBEDTLS_DEPRECATED_REMOVED */

/**
 * \brief          Output = MD2( input buffer )
 *
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 * \param output   MD2 checksum result
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
int mbedtls_md2_ret (const(ubyte)* input, size_t ilen, ref ubyte[16] output);

/**
 * \brief          Output = MD2( input buffer )
 *
 * \deprecated     Superseded by mbedtls_md2_ret() in 2.7.0
 *
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 * \param output   MD2 checksum result
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
void mbedtls_md2 (const(ubyte)* input, size_t ilen, ref ubyte[16] output);

/* !MBEDTLS_DEPRECATED_REMOVED */

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */

/* MBEDTLS_SELF_TEST */

/* mbedtls_md2.h */
