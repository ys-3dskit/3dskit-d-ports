module ys3ds.mbedtls.psa.crypto_compat;

/**
 * \file psa/crypto_compat.h
 *
 * \brief PSA cryptography module: Backward compatibility aliases
 *
 * This header declares alternative names for macro and functions.
 * New application code should not use these names.
 * These names may be removed in a future version of Mbed TLS.
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

import core.stdc.config;
import core.stdc.stddef;

import ys3ds.mbedtls.psa.crypto;

extern (C):

/*
 * To support both openless APIs and psa_open_key() temporarily, define
 * psa_key_handle_t to be equal to mbedtls_svc_key_id_t. Do not mark the
 * type and its utility macros and functions deprecated yet. This will be done
 * in a subsequent phase.
 */
alias psa_key_handle_t = uint;

enum PSA_KEY_HANDLE_INIT = MBEDTLS_SVC_KEY_ID_INIT;

/** Check whether a handle is null.
 *
 * \param handle  Handle
 *
 * \return Non-zero if the handle is null, zero otherwise.
 */
int psa_key_handle_is_null (psa_key_handle_t handle);

/*
 * Mechanism for declaring deprecated values
 */

alias mbedtls_deprecated_size_t = c_ulong;
alias mbedtls_deprecated_psa_status_t = int;
alias mbedtls_deprecated_psa_key_usage_t = uint;
alias mbedtls_deprecated_psa_ecc_family_t = ubyte;
alias mbedtls_deprecated_psa_dh_family_t = ubyte;
alias psa_ecc_curve_t = ubyte;
alias psa_dh_group_t = ubyte;
alias mbedtls_deprecated_psa_algorithm_t = uint;

alias PSA_KEY_TYPE_GET_CURVE = PSA_KEY_TYPE_ECC_GET_FAMILY;
alias PSA_KEY_TYPE_GET_GROUP = PSA_KEY_TYPE_DH_GET_FAMILY;

extern (D) auto MBEDTLS_DEPRECATED_CONSTANT(type, T)(auto ref T value)
{
    import std.conv : to;

    // no idea if this works lol
    // #define MBEDTLS_DEPRECATED_CONSTANT(type, value) \
    //     ((mbedtls_deprecated_##type) (valueu))
    return mixin("cast(mbedtls_deprecated_" ~ to!string(type) ~ ") value");
}

/*
 * Deprecated PSA Crypto error code definitions (PSA Crypto API  <= 1.0 beta2)
 */
enum PSA_ERROR_UNKNOWN_ERROR = MBEDTLS_DEPRECATED_CONSTANT!psa_status_t(PSA_ERROR_GENERIC_ERROR);
enum PSA_ERROR_OCCUPIED_SLOT = MBEDTLS_DEPRECATED_CONSTANT!psa_status_t(PSA_ERROR_ALREADY_EXISTS);
enum PSA_ERROR_EMPTY_SLOT = MBEDTLS_DEPRECATED_CONSTANT!psa_status_t(PSA_ERROR_DOES_NOT_EXIST);
enum PSA_ERROR_INSUFFICIENT_CAPACITY = MBEDTLS_DEPRECATED_CONSTANT!psa_status_t(PSA_ERROR_INSUFFICIENT_DATA);
enum PSA_ERROR_TAMPERING_DETECTED = MBEDTLS_DEPRECATED_CONSTANT!psa_status_t(PSA_ERROR_CORRUPTION_DETECTED);

/*
 * Deprecated PSA Crypto numerical encodings (PSA Crypto API  <= 1.0 beta3)
 */
enum PSA_KEY_USAGE_SIGN = MBEDTLS_DEPRECATED_CONSTANT!psa_key_usage_t(PSA_KEY_USAGE_SIGN_HASH);
enum PSA_KEY_USAGE_VERIFY = MBEDTLS_DEPRECATED_CONSTANT!psa_key_usage_t(PSA_KEY_USAGE_VERIFY_HASH);

/*
 * Deprecated PSA Crypto size calculation macros (PSA Crypto API  <= 1.0 beta3)
 */
enum PSA_ASYMMETRIC_SIGNATURE_MAX_SIZE = MBEDTLS_DEPRECATED_CONSTANT!size_t(PSA_SIGNATURE_MAX_SIZE);

extern (D) auto PSA_ASYMMETRIC_SIGN_OUTPUT_SIZE(T0, T1, T2)(auto ref T0 key_type, auto ref T1 key_bits, auto ref T2 alg)
{
    return MBEDTLS_DEPRECATED_CONSTANT!size_t(PSA_SIGN_OUTPUT_SIZE(key_type, key_bits, alg));
}

extern (D) auto PSA_KEY_EXPORT_MAX_SIZE(T0, T1)(auto ref T0 key_type, auto ref T1 key_bits)
{
    return MBEDTLS_DEPRECATED_CONSTANT!size_t(PSA_EXPORT_KEY_OUTPUT_SIZE(key_type, key_bits));
}

extern (D) auto PSA_BLOCK_CIPHER_BLOCK_SIZE(T)(auto ref T type)
{
    return MBEDTLS_DEPRECATED_CONSTANT!size_t(PSA_BLOCK_CIPHER_BLOCK_LENGTH(type));
}

enum PSA_MAX_BLOCK_CIPHER_BLOCK_SIZE = MBEDTLS_DEPRECATED_CONSTANT!size_t(PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE);

extern (D) auto PSA_HASH_SIZE(T)(auto ref T alg)
{
    return MBEDTLS_DEPRECATED_CONSTANT!size_t(PSA_HASH_LENGTH(alg));
}

extern (D) auto PSA_MAC_FINAL_SIZE(T0, T1, T2)(auto ref T0 key_type, auto ref T1 key_bits, auto ref T2 alg)
{
    return MBEDTLS_DEPRECATED_CONSTANT!size_t(PSA_MAC_LENGTH(key_type, key_bits, alg));
}

enum PSA_ALG_TLS12_PSK_TO_MS_MAX_PSK_LEN = MBEDTLS_DEPRECATED_CONSTANT!size_t(PSA_TLS12_PSK_TO_MS_PSK_MAX_SIZE);

/*
 * Deprecated PSA Crypto function names (PSA Crypto API  <= 1.0 beta3)
 */
psa_status_t psa_asymmetric_sign (
    psa_key_handle_t key,
    psa_algorithm_t alg,
    const(ubyte)* hash,
    size_t hash_length,
    ubyte* signature,
    size_t signature_size,
    size_t* signature_length);

psa_status_t psa_asymmetric_verify (
    psa_key_handle_t key,
    psa_algorithm_t alg,
    const(ubyte)* hash,
    size_t hash_length,
    const(ubyte)* signature,
    size_t signature_length);

/*
 * Size-specific elliptic curve families.
 */
enum PSA_ECC_CURVE_SECP160K1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECP_K1);
enum PSA_ECC_CURVE_SECP192K1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECP_K1);
enum PSA_ECC_CURVE_SECP224K1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECP_K1);
enum PSA_ECC_CURVE_SECP256K1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECP_K1);
enum PSA_ECC_CURVE_SECP160R1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECP_R1);
enum PSA_ECC_CURVE_SECP192R1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECP_R1);
enum PSA_ECC_CURVE_SECP224R1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECP_R1);
enum PSA_ECC_CURVE_SECP256R1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECP_R1);
enum PSA_ECC_CURVE_SECP384R1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECP_R1);
enum PSA_ECC_CURVE_SECP521R1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECP_R1);
enum PSA_ECC_CURVE_SECP160R2 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECP_R2);
enum PSA_ECC_CURVE_SECT163K1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECT_K1);
enum PSA_ECC_CURVE_SECT233K1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECT_K1);
enum PSA_ECC_CURVE_SECT239K1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECT_K1);
enum PSA_ECC_CURVE_SECT283K1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECT_K1);
enum PSA_ECC_CURVE_SECT409K1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECT_K1);
enum PSA_ECC_CURVE_SECT571K1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECT_K1);
enum PSA_ECC_CURVE_SECT163R1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECT_R1);
enum PSA_ECC_CURVE_SECT193R1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECT_R1);
enum PSA_ECC_CURVE_SECT233R1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECT_R1);
enum PSA_ECC_CURVE_SECT283R1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECT_R1);
enum PSA_ECC_CURVE_SECT409R1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECT_R1);
enum PSA_ECC_CURVE_SECT571R1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECT_R1);
enum PSA_ECC_CURVE_SECT163R2 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECT_R2);
enum PSA_ECC_CURVE_SECT193R2 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECT_R2);
enum PSA_ECC_CURVE_BRAINPOOL_P256R1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_BRAINPOOL_P_R1);
enum PSA_ECC_CURVE_BRAINPOOL_P384R1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_BRAINPOOL_P_R1);
enum PSA_ECC_CURVE_BRAINPOOL_P512R1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_BRAINPOOL_P_R1);
enum PSA_ECC_CURVE_CURVE25519 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_MONTGOMERY);
enum PSA_ECC_CURVE_CURVE448 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_MONTGOMERY);

/*
 * Curves that changed name due to PSA specification.
 */
enum PSA_ECC_CURVE_SECP_K1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECP_K1);
enum PSA_ECC_CURVE_SECP_R1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECP_R1);
enum PSA_ECC_CURVE_SECP_R2 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECP_R2);
enum PSA_ECC_CURVE_SECT_K1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECT_K1);
enum PSA_ECC_CURVE_SECT_R1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECT_R1);
enum PSA_ECC_CURVE_SECT_R2 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_SECT_R2);
enum PSA_ECC_CURVE_BRAINPOOL_P_R1 = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_BRAINPOOL_P_R1);
enum PSA_ECC_CURVE_MONTGOMERY = MBEDTLS_DEPRECATED_CONSTANT!psa_ecc_family_t(PSA_ECC_FAMILY_MONTGOMERY);

/*
 * Finite-field Diffie-Hellman families.
 */
enum PSA_DH_GROUP_FFDHE2048 = MBEDTLS_DEPRECATED_CONSTANT!psa_dh_family_t(PSA_DH_FAMILY_RFC7919);
enum PSA_DH_GROUP_FFDHE3072 = MBEDTLS_DEPRECATED_CONSTANT!psa_dh_family_t(PSA_DH_FAMILY_RFC7919);
enum PSA_DH_GROUP_FFDHE4096 = MBEDTLS_DEPRECATED_CONSTANT!psa_dh_family_t(PSA_DH_FAMILY_RFC7919);
enum PSA_DH_GROUP_FFDHE6144 = MBEDTLS_DEPRECATED_CONSTANT!psa_dh_family_t(PSA_DH_FAMILY_RFC7919);
enum PSA_DH_GROUP_FFDHE8192 = MBEDTLS_DEPRECATED_CONSTANT!psa_dh_family_t(PSA_DH_FAMILY_RFC7919);

/*
 * Diffie-Hellman families that changed name due to PSA specification.
 */
enum PSA_DH_GROUP_RFC7919 = MBEDTLS_DEPRECATED_CONSTANT!psa_dh_family_t(PSA_DH_FAMILY_RFC7919);
enum PSA_DH_GROUP_CUSTOM = MBEDTLS_DEPRECATED_CONSTANT!psa_dh_family_t(PSA_DH_FAMILY_CUSTOM);

/*
 * Deprecated PSA Crypto stream cipher algorithms (PSA Crypto API  <= 1.0 beta3)
 */
enum PSA_ALG_ARC4 = MBEDTLS_DEPRECATED_CONSTANT!psa_algorithm_t(PSA_ALG_STREAM_CIPHER);
enum PSA_ALG_CHACHA20 = MBEDTLS_DEPRECATED_CONSTANT!psa_algorithm_t(PSA_ALG_STREAM_CIPHER);

/*
 * Renamed AEAD tag length macros (PSA Crypto API  <= 1.0 beta3)
 */
extern (D) auto PSA_ALG_AEAD_WITH_DEFAULT_TAG_LENGTH(T)(auto ref T aead_alg)
{
    return MBEDTLS_DEPRECATED_CONSTANT!psa_algorithm_t(PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(aead_alg));
}

extern (D) auto PSA_ALG_AEAD_WITH_TAG_LENGTH(T0, T1)(auto ref T0 aead_alg, auto ref T1 tag_length)
{
    return MBEDTLS_DEPRECATED_CONSTANT!psa_algorithm_t(PSA_ALG_AEAD_WITH_SHORTENED_TAG(aead_alg, tag_length));
}

/*
 * Deprecated PSA AEAD output size macros (PSA Crypto API  <= 1.0 beta3)
 */

/** The tag size for an AEAD algorithm, in bytes.
 *
 * \param alg                 An AEAD algorithm
 *                            (\c PSA_ALG_XXX value such that
 *                            #PSA_ALG_IS_AEAD(\p alg) is true).
 *
 * \return                    The tag size for the specified algorithm.
 *                            If the AEAD algorithm does not have an identified
 *                            tag that can be distinguished from the rest of
 *                            the ciphertext, return 0.
 *                            If the AEAD algorithm is not recognized, return 0.
 */

/** The maximum size of the output of psa_aead_encrypt(), in bytes.
 *
 * If the size of the ciphertext buffer is at least this large, it is
 * guaranteed that psa_aead_encrypt() will not fail due to an
 * insufficient buffer size. Depending on the algorithm, the actual size of
 * the ciphertext may be smaller.
 *
 * \warning This macro may evaluate its arguments multiple times or
 *          zero times, so you should not pass arguments that contain
 *          side effects.
 *
 * \param alg                 An AEAD algorithm
 *                            (\c PSA_ALG_XXX value such that
 *                            #PSA_ALG_IS_AEAD(\p alg) is true).
 * \param plaintext_length    Size of the plaintext in bytes.
 *
 * \return                    The AEAD ciphertext size for the specified
 *                            algorithm.
 *                            If the AEAD algorithm is not recognized, return 0.
 */

/** The maximum size of the output of psa_aead_decrypt(), in bytes.
 *
 * If the size of the plaintext buffer is at least this large, it is
 * guaranteed that psa_aead_decrypt() will not fail due to an
 * insufficient buffer size. Depending on the algorithm, the actual size of
 * the plaintext may be smaller.
 *
 * \warning This macro may evaluate its arguments multiple times or
 *          zero times, so you should not pass arguments that contain
 *          side effects.
 *
 * \param alg                 An AEAD algorithm
 *                            (\c PSA_ALG_XXX value such that
 *                            #PSA_ALG_IS_AEAD(\p alg) is true).
 * \param ciphertext_length   Size of the plaintext in bytes.
 *
 * \return                    The AEAD ciphertext size for the specified
 *                            algorithm.
 *                            If the AEAD algorithm is not recognized, return 0.
 */

/** A sufficient output buffer size for psa_aead_update().
 *
 * If the size of the output buffer is at least this large, it is
 * guaranteed that psa_aead_update() will not fail due to an
 * insufficient buffer size. The actual size of the output may be smaller
 * in any given call.
 *
 * \warning This macro may evaluate its arguments multiple times or
 *          zero times, so you should not pass arguments that contain
 *          side effects.
 *
 * \param alg                 An AEAD algorithm
 *                            (\c PSA_ALG_XXX value such that
 *                            #PSA_ALG_IS_AEAD(\p alg) is true).
 * \param input_length        Size of the input in bytes.
 *
 * \return                    A sufficient output buffer size for the specified
 *                            algorithm.
 *                            If the AEAD algorithm is not recognized, return 0.
 */
/* For all the AEAD modes defined in this specification, it is possible
 * to emit output without delay. However, hardware may not always be
 * capable of this. So for modes based on a block cipher, allow the
 * implementation to delay the output until it has a full block. */

/** A sufficient ciphertext buffer size for psa_aead_finish().
 *
 * If the size of the ciphertext buffer is at least this large, it is
 * guaranteed that psa_aead_finish() will not fail due to an
 * insufficient ciphertext buffer size. The actual size of the output may
 * be smaller in any given call.
 *
 * \param alg                 An AEAD algorithm
 *                            (\c PSA_ALG_XXX value such that
 *                            #PSA_ALG_IS_AEAD(\p alg) is true).
 *
 * \return                    A sufficient ciphertext buffer size for the
 *                            specified algorithm.
 *                            If the AEAD algorithm is not recognized, return 0.
 */

/** A sufficient plaintext buffer size for psa_aead_verify().
 *
 * If the size of the plaintext buffer is at least this large, it is
 * guaranteed that psa_aead_verify() will not fail due to an
 * insufficient plaintext buffer size. The actual size of the output may
 * be smaller in any given call.
 *
 * \param alg                 An AEAD algorithm
 *                            (\c PSA_ALG_XXX value such that
 *                            #PSA_ALG_IS_AEAD(\p alg) is true).
 *
 * \return                    A sufficient plaintext buffer size for the
 *                            specified algorithm.
 *                            If the AEAD algorithm is not recognized, return 0.
 */

/* MBEDTLS_DEPRECATED_REMOVED */

/** Open a handle to an existing persistent key.
 *
 * Open a handle to a persistent key. A key is persistent if it was created
 * with a lifetime other than #PSA_KEY_LIFETIME_VOLATILE. A persistent key
 * always has a nonzero key identifier, set with psa_set_key_id() when
 * creating the key. Implementations may provide additional pre-provisioned
 * keys that can be opened with psa_open_key(). Such keys have an application
 * key identifier in the vendor range, as documented in the description of
 * #psa_key_id_t.
 *
 * The application must eventually close the handle with psa_close_key() or
 * psa_destroy_key() to release associated resources. If the application dies
 * without calling one of these functions, the implementation should perform
 * the equivalent of a call to psa_close_key().
 *
 * Some implementations permit an application to open the same key multiple
 * times. If this is successful, each call to psa_open_key() will return a
 * different key handle.
 *
 * \note This API is not part of the PSA Cryptography API Release 1.0.0
 * specification. It was defined in the 1.0 Beta 3 version of the
 * specification but was removed in the 1.0.0 released version. This API is
 * kept for the time being to not break applications relying on it. It is not
 * deprecated yet but will be in the near future.
 *
 * \note Applications that rely on opening a key multiple times will not be
 * portable to implementations that only permit a single key handle to be
 * opened. See also :ref:\`key-handles\`.
 *
 *
 * \param key           The persistent identifier of the key.
 * \param[out] handle   On success, a handle to the key.
 *
 * \retval #PSA_SUCCESS
 *         Success. The application can now use the value of `*handle`
 *         to access the key.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 *         The implementation does not have sufficient resources to open the
 *         key. This can be due to reaching an implementation limit on the
 *         number of open keys, the number of open key handles, or available
 *         memory.
 * \retval #PSA_ERROR_DOES_NOT_EXIST
 *         There is no persistent key with key identifier \p key.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \p key is not a valid persistent key identifier.
 * \retval #PSA_ERROR_NOT_PERMITTED
 *         The specified key exists, but the application does not have the
 *         permission to access it. Note that this specification does not
 *         define any way to create such a key, but it may be possible
 *         through implementation-specific means.
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE \emptydescription
 * \retval #PSA_ERROR_CORRUPTION_DETECTED \emptydescription
 * \retval #PSA_ERROR_STORAGE_FAILURE \emptydescription
 * \retval #PSA_ERROR_DATA_INVALID \emptydescription
 * \retval #PSA_ERROR_DATA_CORRUPT \emptydescription
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_open_key (mbedtls_svc_key_id_t key, psa_key_handle_t* handle);

/** Close a key handle.
 *
 * If the handle designates a volatile key, this will destroy the key material
 * and free all associated resources, just like psa_destroy_key().
 *
 * If this is the last open handle to a persistent key, then closing the handle
 * will free all resources associated with the key in volatile memory. The key
 * data in persistent storage is not affected and can be opened again later
 * with a call to psa_open_key().
 *
 * Closing the key handle makes the handle invalid, and the key handle
 * must not be used again by the application.
 *
 * \note This API is not part of the PSA Cryptography API Release 1.0.0
 * specification. It was defined in the 1.0 Beta 3 version of the
 * specification but was removed in the 1.0.0 released version. This API is
 * kept for the time being to not break applications relying on it. It is not
 * deprecated yet but will be in the near future.
 *
 * \note If the key handle was used to set up an active
 * :ref:\`multipart operation <multipart-operations>\`, then closing the
 * key handle can cause the multipart operation to fail. Applications should
 * maintain the key handle until after the multipart operation has finished.
 *
 * \param handle        The key handle to close.
 *                      If this is \c 0, do nothing and return \c PSA_SUCCESS.
 *
 * \retval #PSA_SUCCESS
 *         \p handle was a valid handle or \c 0. It is now closed.
 * \retval #PSA_ERROR_INVALID_HANDLE
 *         \p handle is not a valid handle nor \c 0.
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE \emptydescription
 * \retval #PSA_ERROR_CORRUPTION_DETECTED \emptydescription
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_close_key (psa_key_handle_t handle);

/* PSA_CRYPTO_COMPAT_H */
