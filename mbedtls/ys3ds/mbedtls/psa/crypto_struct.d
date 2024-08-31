module ys3ds.mbedtls.psa.crypto_struct;

/**
 * \file psa/crypto_struct.h
 *
 * \brief PSA cryptography module: Mbed TLS structured type implementations
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 *
 * This file contains the definitions of some data structures with
 * implementation-specific definitions.
 *
 * In implementations with isolation between the application and the
 * cryptography module, it is expected that the front-end and the back-end
 * would have different versions of this file.
 *
 * <h3>Design notes about multipart operation structures</h3>
 *
 * For multipart operations without driver delegation support, each multipart
 * operation structure contains a `psa_algorithm_t alg` field which indicates
 * which specific algorithm the structure is for. When the structure is not in
 * use, `alg` is 0. Most of the structure consists of a union which is
 * discriminated by `alg`.
 *
 * For multipart operations with driver delegation support, each multipart
 * operation structure contains an `unsigned int id` field indicating which
 * driver got assigned to do the operation. When the structure is not in use,
 * 'id' is 0. The structure contains also a driver context which is the union
 * of the contexts of all drivers able to handle the type of multipart
 * operation.
 *
 * Note that when `alg` or `id` is 0, the content of other fields is undefined.
 * In particular, it is not guaranteed that a freshly-initialized structure
 * is all-zero: we initialize structures to something like `{0, 0}`, which
 * is only guaranteed to initializes the first member of the union;
 * GCC and Clang initialize the whole structure to 0 (at the time of writing),
 * but MSVC and CompCert don't.
 *
 * In Mbed TLS, multipart operation structures live independently from
 * the key. This allows Mbed TLS to free the key objects when destroying
 * a key slot. If a multipart operation needs to remember the key after
 * the setup function returns, the operation structure needs to contain a
 * copy of the key.
 */

import ys3ds.mbedtls.psa.crypto_driver_contexts_primitives;
import ys3ds.mbedtls.psa.crypto_driver_contexts_composites;
import ys3ds.mbedtls.psa.crypto;
import ys3ds.mbedtls.cipher;

extern (C):

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/* Include the Mbed TLS configuration file, the way Mbed TLS does it
 * in each of its header files. */

/* Include the context definition for the compiled-in drivers for the primitive
 * algorithms. */

struct psa_hash_operation_s
{
    /** Unique ID indicating which driver got assigned to do the
     * operation. Since driver contexts are driver-specific, swapping
     * drivers halfway through the operation is not supported.
     * ID values are auto-generated in psa_driver_wrappers.h.
     * ID value zero means the context is not valid or not assigned to
     * any driver (i.e. the driver context is not active, in use). */
    uint id;
    psa_driver_hash_context_t ctx;
}

psa_hash_operation_s psa_hash_operation_init ();

struct psa_cipher_operation_s
{
    import std.bitmanip : bitfields;

    /** Unique ID indicating which driver got assigned to do the
     * operation. Since driver contexts are driver-specific, swapping
     * drivers halfway through the operation is not supported.
     * ID values are auto-generated in psa_crypto_driver_wrappers.h
     * ID value zero means the context is not valid or not assigned to
     * any driver (i.e. none of the driver contexts are active). */
    uint id;

    mixin(bitfields!(
        uint, "iv_required", 1,
        uint, "iv_set", 1,
        uint, "", 6));

    ubyte default_iv_length;

    psa_driver_cipher_context_t ctx;
}

psa_cipher_operation_s psa_cipher_operation_init ();

/* Include the context definition for the compiled-in drivers for the composite
 * algorithms. */

struct psa_mac_operation_s
{
    import std.bitmanip : bitfields;

    /** Unique ID indicating which driver got assigned to do the
     * operation. Since driver contexts are driver-specific, swapping
     * drivers halfway through the operation is not supported.
     * ID values are auto-generated in psa_driver_wrappers.h
     * ID value zero means the context is not valid or not assigned to
     * any driver (i.e. none of the driver contexts are active). */
    uint id;
    ubyte mac_size;

    mixin(bitfields!(
        uint, "is_sign", 1,
        uint, "", 7));

    psa_driver_mac_context_t ctx;
}

psa_mac_operation_s psa_mac_operation_init ();

struct psa_aead_operation_s
{
    import std.bitmanip : bitfields;

    psa_algorithm_t alg;

    mixin(bitfields!(
        uint, "key_set", 1,
        uint, "iv_set", 1,
        uint, "", 6));

    ubyte iv_size;
    ubyte block_size;

    /* Enable easier initializing of the union. */
    union _Anonymous_0
    {
        uint dummy;
        mbedtls_cipher_context_t cipher;
    }

    _Anonymous_0 ctx;
}

psa_aead_operation_s psa_aead_operation_init ();

struct psa_hkdf_key_derivation_t
{
    import std.bitmanip : bitfields;

    ubyte* info;
    size_t info_length;

    ubyte offset_in_block;
    ubyte block_number;

    mixin(bitfields!(
        uint, "state", 2,
        uint, "info_set", 1,
        uint, "", 5));

    ubyte[PSA_HASH_MAX_SIZE] output_block;
    ubyte[PSA_HASH_MAX_SIZE] prk;
    psa_mac_operation_s hmac;
}

/* MBEDTLS_PSA_BUILTIN_ALG_HKDF */

enum psa_tls12_prf_key_derivation_state_t
{
    PSA_TLS12_PRF_STATE_INIT = 0, /* no input provided */
    PSA_TLS12_PRF_STATE_SEED_SET = 1, /* seed has been set */
    PSA_TLS12_PRF_STATE_KEY_SET = 2, /* key has been set */
    PSA_TLS12_PRF_STATE_LABEL_SET = 3, /* label has been set */
    PSA_TLS12_PRF_STATE_OUTPUT = 4 /* output has been started */
}

struct psa_tls12_prf_key_derivation_s
{
    /* Indicates how many bytes in the current HMAC block have
     * not yet been read by the user. */
    ubyte left_in_block;

    /* The 1-based number of the block. */
    ubyte block_number;

    psa_tls12_prf_key_derivation_state_t state;

    ubyte* secret;
    size_t secret_length;
    ubyte* seed;
    size_t seed_length;
    ubyte* label;
    size_t label_length;

    ubyte[PSA_HASH_MAX_SIZE] Ai;

    /* `HMAC_hash( prk, A(i) + seed )` in the notation of RFC 5246, Sect. 5. */
    ubyte[PSA_HASH_MAX_SIZE] output_block;
}

alias psa_tls12_prf_key_derivation_t = psa_tls12_prf_key_derivation_s;
/* MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF) ||
 * MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS */

struct psa_key_derivation_s
{
    import std.bitmanip : bitfields;

    psa_algorithm_t alg;

    mixin(bitfields!(
        uint, "can_output_key", 1,
        uint, "", 7));

    size_t capacity;

    /* Make the union non-empty even with no supported algorithms. */
    union _Anonymous_1
    {
        ubyte dummy;
        psa_hkdf_key_derivation_t hkdf;
        psa_tls12_prf_key_derivation_t tls12_prf;
    }

    _Anonymous_1 ctx;
}

/* This only zeroes out the first byte in the union, the rest is unspecified. */
psa_key_derivation_s psa_key_derivation_operation_init ();

struct psa_key_policy_s
{
    psa_key_usage_t usage;
    psa_algorithm_t alg;
    psa_algorithm_t alg2;
}

alias psa_key_policy_t = psa_key_policy_s;

psa_key_policy_s psa_key_policy_init ();

/* The type used internally for key sizes.
 * Public interfaces use size_t, but internally we use a smaller type. */
alias psa_key_bits_t = ushort;
/* The maximum value of the type used to represent bit-sizes.
 * This is used to mark an invalid key size. */
enum PSA_KEY_BITS_TOO_LARGE = cast(psa_key_bits_t) -1;
/* The maximum size of a key in bits.
 * Currently defined as the maximum that can be represented, rounded down
 * to a whole number of bytes.
 * This is an uncast value so that it can be used in preprocessor
 * conditionals. */
enum PSA_MAX_KEY_BITS = 0xfff8;

/** A mask of flags that can be stored in key attributes.
 *
 * This type is also used internally to store flags in slots. Internal
 * flags are defined in library/psa_crypto_core.h. Internal flags may have
 * the same value as external flags if they are properly handled during
 * key creation and in psa_get_key_attributes.
 */
alias psa_key_attributes_flag_t = ushort;

enum MBEDTLS_PSA_KA_FLAG_HAS_SLOT_NUMBER = cast(psa_key_attributes_flag_t) 0x0001;

/* A mask of key attribute flags used externally only.
 * Only meant for internal checks inside the library. */
enum MBEDTLS_PSA_KA_MASK_EXTERNAL_ONLY = MBEDTLS_PSA_KA_FLAG_HAS_SLOT_NUMBER | 0;

/* A mask of key attribute flags used both internally and externally.
 * Currently there aren't any. */
enum MBEDTLS_PSA_KA_MASK_DUAL_USE = 0;

struct psa_core_key_attributes_t
{
    psa_key_type_t type;
    psa_key_bits_t bits;
    psa_key_lifetime_t lifetime;
    mbedtls_svc_key_id_t id;
    psa_key_policy_t policy;
    psa_key_attributes_flag_t flags;
}

struct psa_key_attributes_s
{
    psa_core_key_attributes_t core;

    /* MBEDTLS_PSA_CRYPTO_SE_C */
    void* domain_parameters;
    size_t domain_parameters_size;
}

psa_key_attributes_s psa_key_attributes_init ();

void psa_set_key_id (
    psa_key_attributes_t* attributes,
    mbedtls_svc_key_id_t key);

mbedtls_svc_key_id_t psa_get_key_id (const(psa_key_attributes_t)* attributes);

void psa_set_key_lifetime (
    psa_key_attributes_t* attributes,
    psa_key_lifetime_t lifetime);

psa_key_lifetime_t psa_get_key_lifetime (
    const(psa_key_attributes_t)* attributes);

void psa_extend_key_usage_flags (psa_key_usage_t* usage_flags);

void psa_set_key_usage_flags (
    psa_key_attributes_t* attributes,
    psa_key_usage_t usage_flags);

psa_key_usage_t psa_get_key_usage_flags (
    const(psa_key_attributes_t)* attributes);

void psa_set_key_algorithm (
    psa_key_attributes_t* attributes,
    psa_algorithm_t alg);

psa_algorithm_t psa_get_key_algorithm (const(psa_key_attributes_t)* attributes);

/* This function is declared in crypto_extra.h, which comes after this
 * header file, but we need the function here, so repeat the declaration. */
psa_status_t psa_set_key_domain_parameters (
    psa_key_attributes_t* attributes,
    psa_key_type_t type,
    const(ubyte)* data,
    size_t data_length);

/* Common case: quick path */

/* Call the bigger function to free the old domain parameters.
 * Ignore any errors which may arise due to type requiring
 * non-default domain parameters, since this function can't
 * report errors. */
void psa_set_key_type (psa_key_attributes_t* attributes, psa_key_type_t type);

psa_key_type_t psa_get_key_type (const(psa_key_attributes_t)* attributes);

void psa_set_key_bits (psa_key_attributes_t* attributes, size_t bits);

size_t psa_get_key_bits (const(psa_key_attributes_t)* attributes);

/* PSA_CRYPTO_STRUCT_H */
