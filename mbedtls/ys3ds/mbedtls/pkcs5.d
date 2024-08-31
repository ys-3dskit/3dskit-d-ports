/**
 * \file pkcs5.h
 *
 * \brief PKCS#5 functions
 *
 * \author Mathias Olsson <mathias@kompetensum.com>
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

import ys3ds.mbedtls.md;
import ys3ds.mbedtls.asn1;

extern (C):

/** Bad input parameters to function. */
enum MBEDTLS_ERR_PKCS5_BAD_INPUT_DATA = -0x2f80;
/** Unexpected ASN.1 data. */
enum MBEDTLS_ERR_PKCS5_INVALID_FORMAT = -0x2f00;
/** Requested encryption or digest alg not available. */
enum MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE = -0x2e80;
/** Given private key password does not allow for correct decryption. */
enum MBEDTLS_ERR_PKCS5_PASSWORD_MISMATCH = -0x2e00;

enum MBEDTLS_PKCS5_DECRYPT = 0;
enum MBEDTLS_PKCS5_ENCRYPT = 1;

/**
 * \brief          PKCS#5 PBES2 function
 *
 * \note           When encrypting, #MBEDTLS_CIPHER_PADDING_PKCS7 must
 *                 be enabled at compile time.
 *
 * \warning        When decrypting:
 *                 - if #MBEDTLS_CIPHER_PADDING_PKCS7 is enabled at compile
 *                   time, this function validates the CBC padding and returns
 *                   #MBEDTLS_ERR_PKCS5_PASSWORD_MISMATCH if the padding is
 *                   invalid. Note that this can help active adversaries
 *                   attempting to brute-forcing the password. Note also that
 *                   there is no guarantee that an invalid password will be
 *                   detected (the chances of a valid padding with a random
 *                   password are about 1/255).
 *                 - if #MBEDTLS_CIPHER_PADDING_PKCS7 is disabled at compile
 *                   time, this function does not validate the CBC padding.
 *
 * \param pbe_params the ASN.1 algorithm parameters
 * \param mode       either #MBEDTLS_PKCS5_DECRYPT or #MBEDTLS_PKCS5_ENCRYPT
 * \param pwd        password to use when generating key
 * \param pwdlen     length of password
 * \param data       data to process
 * \param datalen    length of data
 * \param output     Output buffer.
 *                   On success, it contains the encrypted or decrypted data,
 *                   possibly followed by the CBC padding.
 *                   On failure, the content is indeterminate.
 *                   For decryption, there must be enough room for \p datalen
 *                   bytes.
 *                   For encryption, there must be enough room for
 *                   \p datalen + 1 bytes, rounded up to the block size of
 *                   the block cipher identified by \p pbe_params.
 *
 * \returns        0 on success, or a MBEDTLS_ERR_XXX code if verification fails.
 */
int mbedtls_pkcs5_pbes2 (
    const(mbedtls_asn1_buf)* pbe_params,
    int mode,
    const(ubyte)* pwd,
    size_t pwdlen,
    const(ubyte)* data,
    size_t datalen,
    ubyte* output);

/**
 * \brief          PKCS#5 PBES2 function
 *
 * \warning        When decrypting:
 *                 - This function validates the CBC padding and returns
 *                   #MBEDTLS_ERR_PKCS5_PASSWORD_MISMATCH if the padding is
 *                   invalid. Note that this can help active adversaries
 *                   attempting to brute-forcing the password. Note also that
 *                   there is no guarantee that an invalid password will be
 *                   detected (the chances of a valid padding with a random
 *                   password are about 1/255).
 *
 * \param pbe_params the ASN.1 algorithm parameters
 * \param mode       either #MBEDTLS_PKCS5_DECRYPT or #MBEDTLS_PKCS5_ENCRYPT
 * \param pwd        password to use when generating key
 * \param pwdlen     length of password
 * \param data       data to process
 * \param datalen    length of data
 * \param output     Output buffer.
 *                   On success, it contains the decrypted data.
 *                   On failure, the content is indetermidate.
 *                   For decryption, there must be enough room for \p datalen
 *                   bytes.
 *                   For encryption, there must be enough room for
 *                   \p datalen + 1 bytes, rounded up to the block size of
 *                   the block cipher identified by \p pbe_params.
 * \param output_size size of output buffer.
 *                    This must be big enough to accommodate for output plus
 *                    padding data.
 * \param output_len On success, length of actual data written to the output buffer.
 *
 * \returns        0 on success, or a MBEDTLS_ERR_XXX code if parsing or decryption fails.
 */
int mbedtls_pkcs5_pbes2_ext (
    const(mbedtls_asn1_buf)* pbe_params,
    int mode,
    const(ubyte)* pwd,
    size_t pwdlen,
    const(ubyte)* data,
    size_t datalen,
    ubyte* output,
    size_t output_size,
    size_t* output_len);

/* MBEDTLS_CIPHER_PADDING_PKCS7 */

/* MBEDTLS_ASN1_PARSE_C */

/**
 * \brief          PKCS#5 PBKDF2 using HMAC
 *
 * \param ctx      Generic HMAC context
 * \param password Password to use when generating key
 * \param plen     Length of password
 * \param salt     Salt to use when generating key
 * \param slen     Length of salt
 * \param iteration_count       Iteration count
 * \param key_length            Length of generated key in bytes
 * \param output   Generated key. Must be at least as big as key_length
 *
 * \returns        0 on success, or a MBEDTLS_ERR_XXX code if verification fails.
 */
int mbedtls_pkcs5_pbkdf2_hmac (
    mbedtls_md_context_t* ctx,
    const(ubyte)* password,
    size_t plen,
    const(ubyte)* salt,
    size_t slen,
    uint iteration_count,
    uint key_length,
    ubyte* output);

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */

/* MBEDTLS_SELF_TEST */

/* pkcs5.h */
