/**
 * \file pem.h
 *
 * \brief Privacy Enhanced Mail (PEM) decoding
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

extern (C):

/**
 * \name PEM Error codes
 * These error codes are returned in case of errors reading the
 * PEM data.
 * \{
 */
/** No PEM header or footer found. */
enum MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT = -0x1080;
/** PEM string is not as expected. */
enum MBEDTLS_ERR_PEM_INVALID_DATA = -0x1100;
/** Failed to allocate memory. */
enum MBEDTLS_ERR_PEM_ALLOC_FAILED = -0x1180;
/** RSA IV is not in hex-format. */
enum MBEDTLS_ERR_PEM_INVALID_ENC_IV = -0x1200;
/** Unsupported key encryption algorithm. */
enum MBEDTLS_ERR_PEM_UNKNOWN_ENC_ALG = -0x1280;
/** Private key password can't be empty. */
enum MBEDTLS_ERR_PEM_PASSWORD_REQUIRED = -0x1300;
/** Given private key password does not allow for correct decryption. */
enum MBEDTLS_ERR_PEM_PASSWORD_MISMATCH = -0x1380;
/** Unavailable feature, e.g. hashing/encryption combination. */
enum MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE = -0x1400;
/** Bad input parameters to function. */
enum MBEDTLS_ERR_PEM_BAD_INPUT_DATA = -0x1480;
/** \} name PEM Error codes */

/**
 * \brief       PEM context structure
 */
struct mbedtls_pem_context
{
    ubyte* buf; /*!< buffer for decoded data             */
    size_t buflen; /*!< length of the buffer                */
    ubyte* info; /*!< buffer for extra header information */
}

/**
 * \brief       PEM context setup
 *
 * \param ctx   context to be initialized
 */
void mbedtls_pem_init (mbedtls_pem_context* ctx);

/**
 * \brief       Read a buffer for PEM information and store the resulting
 *              data into the specified context buffers.
 *
 * \param ctx       context to use
 * \param header    header string to seek and expect
 * \param footer    footer string to seek and expect
 * \param data      source data to look in (must be nul-terminated)
 * \param pwd       password for decryption (can be NULL)
 * \param pwdlen    length of password
 * \param use_len   destination for total length used (set after header is
 *                  correctly read, so unless you get
 *                  MBEDTLS_ERR_PEM_BAD_INPUT_DATA or
 *                  MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT, use_len is
 *                  the length to skip)
 *
 * \note            Attempts to check password correctness by verifying if
 *                  the decrypted text starts with an ASN.1 sequence of
 *                  appropriate length
 *
 * \return          0 on success, or a specific PEM error code
 */
int mbedtls_pem_read_buffer (
    mbedtls_pem_context* ctx,
    const(char)* header,
    const(char)* footer,
    const(ubyte)* data,
    const(ubyte)* pwd,
    size_t pwdlen,
    size_t* use_len);

/**
 * \brief       PEM context memory freeing
 *
 * \param ctx   context to be freed
 */
void mbedtls_pem_free (mbedtls_pem_context* ctx);
/* MBEDTLS_PEM_PARSE_C */

/**
 * \brief           Write a buffer of PEM information from a DER encoded
 *                  buffer.
 *
 * \param header    The header string to write.
 * \param footer    The footer string to write.
 * \param der_data  The DER data to encode.
 * \param der_len   The length of the DER data \p der_data in Bytes.
 * \param buf       The buffer to write to.
 * \param buf_len   The length of the output buffer \p buf in Bytes.
 * \param olen      The address at which to store the total length written
 *                  or required (if \p buf_len is not enough).
 *
 * \note            You may pass \c NULL for \p buf and \c 0 for \p buf_len
 *                  to request the length of the resulting PEM buffer in
 *                  `*olen`.
 *
 * \note            This function may be called with overlapping \p der_data
 *                  and \p buf buffers.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL if \p buf isn't large
 *                  enough to hold the PEM buffer. In  this case, `*olen` holds
 *                  the required minimum size of \p buf.
 * \return          Another PEM or BASE64 error code on other kinds of failure.
 */
int mbedtls_pem_write_buffer (
    const(char)* header,
    const(char)* footer,
    const(ubyte)* der_data,
    size_t der_len,
    ubyte* buf,
    size_t buf_len,
    size_t* olen);
/* MBEDTLS_PEM_WRITE_C */

/* pem.h */
