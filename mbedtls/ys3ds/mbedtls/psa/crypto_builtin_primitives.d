module ys3ds.mbedtls.psa.crypto_builtin_primitives;

/*
 *  Context structure declaration of the Mbed TLS software-based PSA drivers
 *  called through the PSA Crypto driver dispatch layer.
 *  This file contains the context structures of those algorithms which do not
 *  rely on other algorithms, i.e. are 'primitive' algorithms.
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 *
 * \note This header and its content is not part of the Mbed TLS API and
 * applications must not depend on it. Its main purpose is to define the
 * multi-part state objects of the Mbed TLS software-based PSA drivers. The
 * definition of these objects are then used by crypto_struct.h to define the
 * implementation-defined types of PSA multi-part state objects.
 */

import ys3ds.mbedtls.psa.crypto_types;

import ys3ds.mbedtls.md2;
import ys3ds.mbedtls.md4;
import ys3ds.mbedtls.md5;
import ys3ds.mbedtls.ripemd160;
import ys3ds.mbedtls.sha1;
import ys3ds.mbedtls.sha256;
import ys3ds.mbedtls.sha512;
import ys3ds.mbedtls.cipher;

extern (C):

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * Hash multi-part operation definitions.
 */

struct mbedtls_psa_hash_operation_t
{
    psa_algorithm_t alg;

    /* Make the union non-empty even with no supported algorithms. */
    union _Anonymous_0
    {
        uint dummy;
        mbedtls_md5_context md5;
        mbedtls_ripemd160_context ripemd160;
        mbedtls_sha1_context sha1;
        mbedtls_sha256_context sha256;
        mbedtls_sha512_context sha512;
    }

    _Anonymous_0 ctx;
}

/*
 * Cipher multi-part operation definitions.
 */

enum MBEDTLS_PSA_BUILTIN_CIPHER = 1;

struct mbedtls_psa_cipher_operation_t
{
    /* Context structure for the Mbed TLS cipher implementation. */
    psa_algorithm_t alg;
    ubyte iv_length;
    ubyte block_length;

    union _Anonymous_1
    {
        uint dummy;
        mbedtls_cipher_context_t cipher;
    }

    _Anonymous_1 ctx;
}

/* PSA_CRYPTO_BUILTIN_PRIMITIVES_H */
