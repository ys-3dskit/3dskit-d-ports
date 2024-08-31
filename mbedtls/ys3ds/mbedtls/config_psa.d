/**
 * \file mbedtls/config_psa.h
 * \brief PSA crypto configuration options (set of defines)
 *
 *  This set of compile-time options takes settings defined in
 *  include/mbedtls/config.h and include/psa/crypto_config.h and uses
 *  those definitions to define symbols used in the library code.
 *
 *  Users and integrators should not edit this file, please edit
 *  include/mbedtls/config.h for MBEDTLS_XXX settings or
 *  include/psa/crypto_config.h for PSA_WANT_XXX settings.
 */

extern (C) @nogc nothrow:

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/* defined(MBEDTLS_PSA_CRYPTO_CONFIG) */

/****************************************************************/
/* De facto synonyms */
/****************************************************************/

/****************************************************************/
/* Require built-in implementations based on PSA requirements */
/****************************************************************/

/* !MBEDTLS_PSA_ACCEL_ALG_DETERMINISTIC_ECDSA */
/* PSA_WANT_ALG_DETERMINISTIC_ECDSA */

/* !MBEDTLS_PSA_ACCEL_ALG_ECDH */
/* PSA_WANT_ALG_ECDH */

/* !MBEDTLS_PSA_ACCEL_ALG_ECDSA */
/* PSA_WANT_ALG_ECDSA */

/*
 * The PSA implementation has its own implementation of HKDF, separate from
 * hkdf.c. No need to enable MBEDTLS_HKDF_C here.
 */

/* !MBEDTLS_PSA_ACCEL_ALG_HKDF */
/* PSA_WANT_ALG_HKDF */

/* !MBEDTLS_PSA_ACCEL_ALG_HMAC */
/* PSA_WANT_ALG_HMAC */

/* !MBEDTLS_PSA_ACCEL_ALG_RSA_OAEP */
/* PSA_WANT_ALG_RSA_OAEP */

/* !MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_CRYPT */
/* PSA_WANT_ALG_RSA_PKCS1V15_CRYPT */

/* !MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_SIGN */
/* PSA_WANT_ALG_RSA_PKCS1V15_SIGN */

/* !MBEDTLS_PSA_ACCEL_ALG_RSA_PSS */
/* PSA_WANT_ALG_RSA_PSS */

/* !MBEDTLS_PSA_ACCEL_ALG_TLS12_PRF */
/* PSA_WANT_ALG_TLS12_PRF */

/* !MBEDTLS_PSA_ACCEL_ALG_TLS12_PSK_TO_MS */
/* PSA_WANT_ALG_TLS12_PSK_TO_MS */

/* !MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR */
/* PSA_WANT_KEY_TYPE_ECC_KEY_PAIR */

/* !MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY */
/* PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY */

/* !MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR */
/* PSA_WANT_KEY_TYPE_RSA_KEY_PAIR */

/* !MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_PUBLIC_KEY */
/* PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY */

/* If any of the block modes are requested that don't have an
 * associated HW assist, define PSA_HAVE_SOFT_BLOCK_MODE for checking
 * in the block cipher key types. */

/* !MBEDTLS_PSA_ACCEL_KEY_TYPE_AES */

/* PSA_HAVE_SOFT_KEY_TYPE_AES || PSA_HAVE_SOFT_BLOCK_MODE */
/* PSA_WANT_KEY_TYPE_AES */

/*!MBEDTLS_PSA_ACCEL_KEY_TYPE_ARC4 */
/* PSA_WANT_KEY_TYPE_ARC4 */

/* !MBEDTLS_PSA_ACCEL_KEY_TYPE_ARIA */

/* PSA_HAVE_SOFT_KEY_TYPE_ARIA || PSA_HAVE_SOFT_BLOCK_MODE */
/* PSA_WANT_KEY_TYPE_ARIA */

/* !MBEDTLS_PSA_ACCEL_KEY_TYPE_CAMELLIA */

/* PSA_HAVE_SOFT_KEY_TYPE_CAMELLIA || PSA_HAVE_SOFT_BLOCK_MODE */
/* PSA_WANT_KEY_TYPE_CAMELLIA */

/* !MBEDTLS_PSA_ACCEL_KEY_TYPE_DES */

/*PSA_HAVE_SOFT_KEY_TYPE_DES || PSA_HAVE_SOFT_BLOCK_MODE */
/* PSA_WANT_KEY_TYPE_DES */

/*!MBEDTLS_PSA_ACCEL_KEY_TYPE_CHACHA20 */
/* PSA_WANT_KEY_TYPE_CHACHA20 */

/* If any of the software block ciphers are selected, define
 * PSA_HAVE_SOFT_BLOCK_CIPHER, which can be used in any of these
 * situations. */

/* PSA_WANT_ALG_STREAM_CIPHER */

/* !MBEDTLS_PSA_ACCEL_ALG_CBC_MAC */
/* PSA_WANT_ALG_CBC_MAC */

/* !MBEDTLS_PSA_ACCEL_ALG_CMAC */
/* PSA_WANT_ALG_CMAC */

/* PSA_WANT_ALG_CTR */

/* PSA_WANT_ALG_CFB */

/* PSA_WANT_ALG_OFB */

/* PSA_WANT_ALG_CBC_NO_PADDING */

/* PSA_WANT_ALG_CBC_PKCS7 */

/* PSA_WANT_ALG_CCM */

/* PSA_WANT_ALG_GCM */

/* PSA_WANT_KEY_TYPE_CHACHA20 */
/* !MBEDTLS_PSA_ACCEL_ALG_CHACHA20_POLY1305 */
/* PSA_WANT_ALG_CHACHA20_POLY1305 */

/* !MBEDTLS_PSA_ACCEL_ECC_BRAINPOOL_P_R1_256 */
/* PSA_WANT_ECC_BRAINPOOL_P_R1_256 */

/* !MBEDTLS_PSA_ACCEL_ECC_BRAINPOOL_P_R1_384 */
/* PSA_WANT_ECC_BRAINPOOL_P_R1_384 */

/* !MBEDTLS_PSA_ACCEL_ECC_BRAINPOOL_P_R1_512 */
/* PSA_WANT_ECC_BRAINPOOL_P_R1_512 */

/* !MBEDTLS_PSA_ACCEL_ECC_MONTGOMERY_255 */
/* PSA_WANT_ECC_MONTGOMERY_255 */

/*
 * Curve448 is not yet supported via the PSA API in Mbed TLS
 * (https://github.com/Mbed-TLS/mbedtls/issues/4249).
 */

/* !MBEDTLS_PSA_ACCEL_ECC_MONTGOMERY_448 */
/* PSA_WANT_ECC_MONTGOMERY_448 */

/* !MBEDTLS_PSA_ACCEL_ECC_SECP_R1_192 */
/* PSA_WANT_ECC_SECP_R1_192 */

/* !MBEDTLS_PSA_ACCEL_ECC_SECP_R1_224 */
/* PSA_WANT_ECC_SECP_R1_224 */

/* !MBEDTLS_PSA_ACCEL_ECC_SECP_R1_256 */
/* PSA_WANT_ECC_SECP_R1_256 */

/* !MBEDTLS_PSA_ACCEL_ECC_SECP_R1_384 */
/* PSA_WANT_ECC_SECP_R1_384 */

/* !MBEDTLS_PSA_ACCEL_ECC_SECP_R1_521 */
/* PSA_WANT_ECC_SECP_R1_521 */

/* !MBEDTLS_PSA_ACCEL_ECC_SECP_K1_192 */
/* PSA_WANT_ECC_SECP_K1_192 */

/*
 * SECP224K1 is buggy via the PSA API in Mbed TLS
 * (https://github.com/Mbed-TLS/mbedtls/issues/3541).
 */

/* !MBEDTLS_PSA_ACCEL_ECC_SECP_K1_224 */
/* PSA_WANT_ECC_SECP_K1_224 */

/* !MBEDTLS_PSA_ACCEL_ECC_SECP_K1_256 */
/* PSA_WANT_ECC_SECP_K1_256 */

/****************************************************************/
/* Infer PSA requirements from Mbed TLS capabilities */
/****************************************************************/

/* MBEDTLS_PSA_CRYPTO_CONFIG */

/*
 * Ensure PSA_WANT_* defines are setup properly if MBEDTLS_PSA_CRYPTO_CONFIG
 * is not defined
 */

/* MBEDTLS_CCM_C */

/* MBEDTLS_CMAC_C */

/* MBEDTLS_ECDH_C */

// Only add in DETERMINISTIC support if ECDSA is also enabled

/* MBEDTLS_ECDSA_DETERMINISTIC */

/* MBEDTLS_ECDSA_C */

/* MBEDTLS_ECP_C */

/* MBEDTLS_GCM_C */

/* MBEDTLS_HKDF_C */

/* MBEDTLS_MD_C */

/* MBEDTLS_PKCS1_V15 */

/* MBEDTLS_PKCS1_V21 */

/* MBEDTLS_RSA_C */

/* Curve448 is not yet supported via the PSA API (https://github.com/Mbed-TLS/mbedtls/issues/4249) */

/* SECP224K1 is buggy via the PSA API (https://github.com/Mbed-TLS/mbedtls/issues/3541) */

/* MBEDTLS_PSA_CRYPTO_CONFIG */

/* These features are always enabled. */
enum PSA_WANT_KEY_TYPE_DERIVE = 1;
enum PSA_WANT_KEY_TYPE_RAW_DATA = 1;

/* MBEDTLS_CONFIG_PSA_H */
