/**
 * \file pkcs11.h
 *
 * \brief Wrapper for PKCS#11 library libpkcs11-helper
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 */

extern (C) @nogc nothrow:

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/**
 * Context for PKCS #11 private keys.
 */

/**
 * Initialize a mbedtls_pkcs11_context.
 * (Just making memory references valid.)
 *
 * \deprecated          This function is deprecated and will be removed in a
 *                      future version of the library.
 */

/**
 * Fill in a Mbed TLS certificate, based on the given PKCS11 helper certificate.
 *
 * \deprecated          This function is deprecated and will be removed in a
 *                      future version of the library.
 *
 * \param cert          X.509 certificate to fill
 * \param pkcs11h_cert  PKCS #11 helper certificate
 *
 * \return              0 on success.
 */

/**
 * Set up a mbedtls_pkcs11_context storing the given certificate. Note that the
 * mbedtls_pkcs11_context will take over control of the certificate, freeing it when
 * done.
 *
 * \deprecated          This function is deprecated and will be removed in a
 *                      future version of the library.
 *
 * \param priv_key      Private key structure to fill.
 * \param pkcs11_cert   PKCS #11 helper certificate
 *
 * \return              0 on success
 */

/**
 * Free the contents of the given private key context. Note that the structure
 * itself is not freed.
 *
 * \deprecated          This function is deprecated and will be removed in a
 *                      future version of the library.
 *
 * \param priv_key      Private key structure to cleanup
 */

/**
 * \brief          Do an RSA private key decrypt, then remove the message
 *                 padding
 *
 * \deprecated     This function is deprecated and will be removed in a future
 *                 version of the library.
 *
 * \param ctx      PKCS #11 context
 * \param mode     must be MBEDTLS_RSA_PRIVATE, for compatibility with rsa.c's signature
 * \param input    buffer holding the encrypted data
 * \param output   buffer that will hold the plaintext
 * \param olen     will contain the plaintext length
 * \param output_max_len    maximum length of the output buffer
 *
 * \return         0 if successful, or an MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The output buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used) otherwise
 *                 an error is thrown.
 */

/**
 * \brief          Do a private RSA to sign a message digest
 *
 * \deprecated     This function is deprecated and will be removed in a future
 *                 version of the library.
 *
 * \param ctx      PKCS #11 context
 * \param mode     must be MBEDTLS_RSA_PRIVATE, for compatibility with rsa.c's signature
 * \param md_alg   a MBEDTLS_MD_XXX (use MBEDTLS_MD_NONE for signing raw data)
 * \param hashlen  message digest length (for MBEDTLS_MD_NONE only)
 * \param hash     buffer holding the message digest
 * \param sig      buffer that will hold the ciphertext
 *
 * \return         0 if the signing operation was successful,
 *                 or an MBEDTLS_ERR_RSA_XXX error code
 *
 * \note           The "sig" buffer must be as large as the size
 *                 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 */

/**
 * SSL/TLS wrappers for PKCS#11 functions
 *
 * \deprecated     This function is deprecated and will be removed in a future
 *                 version of the library.
 */

/**
 * \brief          This function signs a message digest using RSA.
 *
 * \deprecated     This function is deprecated and will be removed in a future
 *                 version of the library.
 *
 * \param ctx      The PKCS #11 context.
 * \param f_rng    The RNG function. This parameter is unused.
 * \param p_rng    The RNG context. This parameter is unused.
 * \param mode     The operation to run. This must be set to
 *                 MBEDTLS_RSA_PRIVATE, for compatibility with rsa.c's
 *                 signature.
 * \param md_alg   The message digest algorithm. One of the MBEDTLS_MD_XXX
 *                 must be passed to this function and MBEDTLS_MD_NONE can be
 *                 used for signing raw data.
 * \param hashlen  The message digest length (for MBEDTLS_MD_NONE only).
 * \param hash     The buffer holding the message digest.
 * \param sig      The buffer that will hold the ciphertext.
 *
 * \return         \c 0 if the signing operation was successful.
 * \return         A non-zero error code on failure.
 *
 * \note           The \p sig buffer must be as large as the size of
 *                 <code>ctx->N</code>. For example, 128 bytes if RSA-1024 is
 *                 used.
 */

/**
 * This function gets the length of the private key.
 *
 * \deprecated     This function is deprecated and will be removed in a future
 *                 version of the library.
 *
 * \param ctx      The PKCS #11 context.
 *
 * \return         The length of the private key.
 */

/* MBEDTLS_DEPRECATED_REMOVED */

/* MBEDTLS_PKCS11_C */

/* MBEDTLS_PKCS11_H */
