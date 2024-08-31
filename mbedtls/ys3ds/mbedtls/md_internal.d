/**
 * \file md_internal.h
 *
 * \brief Message digest wrappers.
 *
 * \warning This in an internal header. Do not include directly.
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

import ys3ds.mbedtls.md;

extern (C):

/**
 * Message digest information.
 * Allows message digest functions to be called in a generic way.
 */
struct mbedtls_md_info_t
{
    /** Name of the message digest */
    const(char)* name;

    /** Digest identifier */
    mbedtls_md_type_t type;

    /** Output length of the digest function in bytes */
    ubyte size;

    /** Block length of the digest function in bytes */
    ubyte block_size;
}

extern __gshared const mbedtls_md_info_t mbedtls_md5_info;

extern __gshared const mbedtls_md_info_t mbedtls_ripemd160_info;

extern __gshared const mbedtls_md_info_t mbedtls_sha1_info;

extern __gshared const mbedtls_md_info_t mbedtls_sha224_info;
extern __gshared const mbedtls_md_info_t mbedtls_sha256_info;

extern __gshared const mbedtls_md_info_t mbedtls_sha384_info;

extern __gshared const mbedtls_md_info_t mbedtls_sha512_info;

/* MBEDTLS_MD_WRAP_H */
