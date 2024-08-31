/**
 * \file psa_util.h
 *
 * \brief Utility functions for the use of the PSA Crypto library.
 *
 * \warning This function is not part of the public API and may
 *          change at any time.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

import ys3ds.mbedtls.ctr_drbg;

extern (C):

/* Translations for symmetric crypto. */

/* ARIA not yet supported in PSA. */
/* case MBEDTLS_CIPHER_ARIA_128_CCM:
   case MBEDTLS_CIPHER_ARIA_192_CCM:
   case MBEDTLS_CIPHER_ARIA_256_CCM:
   case MBEDTLS_CIPHER_ARIA_128_GCM:
   case MBEDTLS_CIPHER_ARIA_192_GCM:
   case MBEDTLS_CIPHER_ARIA_256_GCM:
   case MBEDTLS_CIPHER_ARIA_128_CBC:
   case MBEDTLS_CIPHER_ARIA_192_CBC:
   case MBEDTLS_CIPHER_ARIA_256_CBC:
       return( PSA_KEY_TYPE_ARIA ); */

/* Translations for hashing. */

/* Translations for ECC. */

/* MBEDTLS_ECP_DP_SECP192R1_ENABLED */

/* MBEDTLS_ECP_DP_SECP224R1_ENABLED */

/* MBEDTLS_ECP_DP_SECP256R1_ENABLED */

/* MBEDTLS_ECP_DP_SECP384R1_ENABLED */

/* MBEDTLS_ECP_DP_SECP521R1_ENABLED */

/* MBEDTLS_ECP_DP_SECP192K1_ENABLED */

/* MBEDTLS_ECP_DP_SECP224K1_ENABLED */

/* MBEDTLS_ECP_DP_SECP256K1_ENABLED */

/* MBEDTLS_ECP_DP_BP256R1_ENABLED */

/* MBEDTLS_ECP_DP_BP384R1_ENABLED */

/* MBEDTLS_ECP_DP_BP512R1_ENABLED */

/* MBEDTLS_ECP_DP_SECP192R1_ENABLED */

/* MBEDTLS_ECP_DP_SECP224R1_ENABLED */

/* MBEDTLS_ECP_DP_SECP256R1_ENABLED */

/* MBEDTLS_ECP_DP_SECP384R1_ENABLED */

/* MBEDTLS_ECP_DP_SECP521R1_ENABLED */

/* MBEDTLS_ECP_DP_SECP192K1_ENABLED */

/* MBEDTLS_ECP_DP_SECP224K1_ENABLED */

/* MBEDTLS_ECP_DP_SECP256K1_ENABLED */

/* MBEDTLS_ECP_DP_BP256R1_ENABLED */

/* MBEDTLS_ECP_DP_BP384R1_ENABLED */

/* MBEDTLS_ECP_DP_BP512R1_ENABLED */

/* Translations for PK layer */

/* All other failures */

/* We return the same as for the 'other failures',
 * but list them separately nonetheless to indicate
 * which failure conditions we have considered. */

/* Translations for ECC */

/* This function transforms an ECC group identifier from
 * https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
 * into a PSA ECC group identifier. */

/* MBEDTLS_ECP_C */

/* This function takes a buffer holding an EC public key
 * exported through psa_export_public_key(), and converts
 * it into an ECPoint structure to be put into a ClientKeyExchange
 * message in an ECDHE exchange.
 *
 * Both the present and the foreseeable future format of EC public keys
 * used by PSA have the ECPoint structure contained in the exported key
 * as a subbuffer, and the function merely selects this subbuffer instead
 * of making a copy.
 */

/* This function takes a buffer holding an ECPoint structure
 * (as contained in a TLS ServerKeyExchange message for ECDHE
 * exchanges) and converts it into a format that the PSA key
 * agreement API understands.
 */

/* MBEDTLS_USE_PSA_CRYPTO */

/* Expose whatever RNG the PSA subsystem uses to applications using the
 * mbedtls_xxx API. The declarations and definitions here need to be
 * consistent with the implementation in library/psa_crypto_random_impl.h.
 * See that file for implementation documentation. */

/* The type of a `f_rng` random generator function that many library functions
 * take.
 *
 * This type name is not part of the Mbed TLS stable API. It may be renamed
 * or moved without warning.
 */
alias mbedtls_f_rng_t = int function (void* p_rng, ubyte* output, size_t output_size);

/** The random generator function for the PSA subsystem.
 *
 * This function is suitable as the `f_rng` random generator function
 * parameter of many `mbedtls_xxx` functions. Use #MBEDTLS_PSA_RANDOM_STATE
 * to obtain the \p p_rng parameter.
 *
 * The implementation of this function depends on the configuration of the
 * library.
 *
 * \note Depending on the configuration, this may be a function or
 *       a pointer to a function.
 *
 * \note This function may only be used if the PSA crypto subsystem is active.
 *       This means that you must call psa_crypto_init() before any call to
 *       this function, and you must not call this function after calling
 *       mbedtls_psa_crypto_free().
 *
 * \param p_rng         The random generator context. This must be
 *                      #MBEDTLS_PSA_RANDOM_STATE. No other state is
 *                      supported.
 * \param output        The buffer to fill. It must have room for
 *                      \c output_size bytes.
 * \param output_size   The number of bytes to write to \p output.
 *                      This function may fail if \p output_size is too
 *                      large. It is guaranteed to accept any output size
 *                      requested by Mbed TLS library functions. The
 *                      maximum request size depends on the library
 *                      configuration.
 *
 * \return              \c 0 on success.
 * \return              An `MBEDTLS_ERR_ENTROPY_xxx`,
 *                      `MBEDTLS_ERR_PLATFORM_xxx,
 *                      `MBEDTLS_ERR_CTR_DRBG_xxx` or
 *                      `MBEDTLS_ERR_HMAC_DRBG_xxx` on error.
 */

/** The random generator state for the PSA subsystem.
 *
 * This macro expands to an expression which is suitable as the `p_rng`
 * random generator state parameter of many `mbedtls_xxx` functions.
 * It must be used in combination with the random generator function
 * mbedtls_psa_get_random().
 *
 * The implementation of this macro depends on the configuration of the
 * library. Do not make any assumption on its nature.
 */

/* !defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG) */

alias mbedtls_psa_drbg_context_t = mbedtls_ctr_drbg_context;
extern __gshared const int function () mbedtls_psa_get_random;

extern __gshared mbedtls_psa_drbg_context_t* mbedtls_psa_random_state;

auto MBEDTLS_PSA_RANDOM_STATE() { return mbedtls_psa_random_state; }

/* !defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG) */

/* MBEDTLS_PSA_CRYPTO_C */

/* MBEDTLS_PSA_UTIL_H */
