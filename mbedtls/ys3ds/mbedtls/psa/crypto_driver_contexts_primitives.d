module ys3ds.mbedtls.psa.crypto_driver_contexts_primitives;

/*
 *  Declaration of context structures for use with the PSA driver wrapper
 *  interface. This file contains the context structures for 'primitive'
 *  operations, i.e. those operations which do not rely on other contexts.
 *
 *  Warning: This file will be auto-generated in the future.
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 *
 * \note This header and its content is not part of the Mbed TLS API and
 * applications must not depend on it. Its main purpose is to define the
 * multi-part state objects of the PSA drivers included in the cryptographic
 * library. The definition of these objects are then used by crypto_struct.h
 * to define the implementation-defined types of PSA multi-part state objects.
 */

import ys3ds.mbedtls.psa.crypto_builtin_primitives;

extern (C):

/*  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/* Include the context structure definitions for the Mbed TLS software drivers */

/* Include the context structure definitions for those drivers that were
 * declared during the autogeneration process. */

/* MBEDTLS_TEST_LIBTESTDRIVER1 &&
   LIBTESTDRIVER1_MBEDTLS_PSA_BUILTIN_CIPHER */

/* MBEDTLS_TEST_LIBTESTDRIVER1 &&
   LIBTESTDRIVER1_MBEDTLS_PSA_BUILTIN_HASH */

/* PSA_CRYPTO_DRIVER_TEST */

/* Define the context to be used for an operation that is executed through the
 * PSA Driver wrapper layer as the union of all possible driver's contexts.
 *
 * The union members are the driver's context structures, and the member names
 * are formatted as `'drivername'_ctx`. This allows for procedural generation
 * of both this file and the content of psa_crypto_driver_wrappers.c */

union psa_driver_hash_context_t
{
    uint dummy; /* Make sure this union is always non-empty */
    mbedtls_psa_hash_operation_t mbedtls_ctx;
}

union psa_driver_cipher_context_t
{
    uint dummy; /* Make sure this union is always non-empty */
    mbedtls_psa_cipher_operation_t mbedtls_ctx;
}

/* PSA_CRYPTO_DRIVER_CONTEXTS_PRIMITIVES_H */
/* End of automatically generated file. */
