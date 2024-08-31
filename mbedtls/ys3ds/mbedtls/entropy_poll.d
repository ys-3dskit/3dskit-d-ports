/**
 * \file entropy_poll.h
 *
 * \brief Platform-specific and custom entropy polling functions
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

extern (C) @nogc nothrow:

/*
 * Default thresholds for built-in sources, in bytes
 */
enum MBEDTLS_ENTROPY_MIN_PLATFORM = 32; /**< Minimum for platform source    */
enum MBEDTLS_ENTROPY_MIN_HAVEGE = 32; /**< Minimum for HAVEGE             */
enum MBEDTLS_ENTROPY_MIN_HARDCLOCK = 4; /**< Minimum for mbedtls_timing_hardclock()        */

enum MBEDTLS_ENTROPY_MIN_HARDWARE = 32; /**< Minimum for the hardware source */

/**
 * \brief           Entropy poll callback that provides 0 entropy.
 */

/**
 * \brief           Platform-specific entropy poll callback
 */

/**
 * \brief           HAVEGE based entropy poll callback
 *
 * Requires an HAVEGE state as its data pointer.
 */

/**
 * \brief           mbedtls_timing_hardclock-based entropy poll callback
 */

/**
 * \brief           Entropy poll callback for a hardware source
 *
 * \warning         This is not provided by Mbed TLS!
 *                  See \c MBEDTLS_ENTROPY_HARDWARE_ALT in config.h.
 *
 * \note            This must accept NULL as its first argument.
 */
int mbedtls_hardware_poll (void* data, ubyte* output, size_t len, size_t* olen);

/**
 * \brief           Entropy poll callback for a non-volatile seed file
 *
 * \note            This must accept NULL as its first argument.
 */

/* entropy_poll.h */
