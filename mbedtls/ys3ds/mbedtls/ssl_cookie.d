/**
 * \file ssl_cookie.h
 *
 * \brief DTLS cookie callbacks implementation
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

import core.stdc.config;

import ys3ds.mbedtls.md;

extern (C) @nogc nothrow:

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */

enum MBEDTLS_SSL_COOKIE_TIMEOUT = 60; /**< Default expiration delay of DTLS cookies, in seconds if HAVE_TIME, or in number of cookies issued */

/** \} name SECTION: Module settings */

/**
 * \brief          Context for the default cookie functions.
 */
struct mbedtls_ssl_cookie_ctx
{
    mbedtls_md_context_t hmac_ctx; /*!< context for the HMAC portion   */

    /*!< serial number for expiration   */

    c_ulong timeout; /*!< timeout delay, in seconds if HAVE_TIME,
         or in number of tickets issued */
}

/**
 * \brief          Initialize cookie context
 */
void mbedtls_ssl_cookie_init (mbedtls_ssl_cookie_ctx* ctx);

/**
 * \brief          Setup cookie context (generate keys)
 */
int mbedtls_ssl_cookie_setup (
    mbedtls_ssl_cookie_ctx* ctx,
    int function (void*, ubyte*, size_t) f_rng,
    void* p_rng);

/**
 * \brief          Set expiration delay for cookies
 *                 (Default MBEDTLS_SSL_COOKIE_TIMEOUT)
 *
 * \param ctx      Cookie context
 * \param delay    Delay, in seconds if HAVE_TIME, or in number of cookies
 *                 issued in the meantime.
 *                 0 to disable expiration (NOT recommended)
 */
void mbedtls_ssl_cookie_set_timeout (mbedtls_ssl_cookie_ctx* ctx, c_ulong delay);

/**
 * \brief          Free cookie context
 */
void mbedtls_ssl_cookie_free (mbedtls_ssl_cookie_ctx* ctx);

/**
 * \brief          Generate cookie, see \c mbedtls_ssl_cookie_write_t
 */
int mbedtls_ssl_cookie_write ();

/**
 * \brief          Verify cookie, see \c mbedtls_ssl_cookie_write_t
 */
int mbedtls_ssl_cookie_check ();

/* ssl_cookie.h */
