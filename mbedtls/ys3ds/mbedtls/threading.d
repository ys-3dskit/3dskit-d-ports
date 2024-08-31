/**
 * \file threading.h
 *
 * \brief Threading abstraction layer
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

extern (C):

/* MBEDTLS_ERR_THREADING_FEATURE_UNAVAILABLE is deprecated and should not be
 * used. */
/** The selected feature is not available. */
enum MBEDTLS_ERR_THREADING_FEATURE_UNAVAILABLE = -0x001A;

/** Bad input parameters to function. */
enum MBEDTLS_ERR_THREADING_BAD_INPUT_DATA = -0x001C;
/** Locking / unlocking / free failed with error code. */
enum MBEDTLS_ERR_THREADING_MUTEX_ERROR = -0x001E;

/* is_valid is 0 after a failed init or a free, and nonzero after a
 * successful init. This field is not considered part of the public
 * API of Mbed TLS and may change without notice. */

/* You should define the mbedtls_threading_mutex_t type in your header */

/**
 * \brief           Set your alternate threading implementation function
 *                  pointers and initialize global mutexes. If used, this
 *                  function must be called once in the main thread before any
 *                  other Mbed TLS function is called, and
 *                  mbedtls_threading_free_alt() must be called once in the main
 *                  thread after all other Mbed TLS functions.
 *
 * \note            mutex_init() and mutex_free() don't return a status code.
 *                  If mutex_init() fails, it should leave its argument (the
 *                  mutex) in a state such that mutex_lock() will fail when
 *                  called with this argument.
 *
 * \param mutex_init    the init function implementation
 * \param mutex_free    the free function implementation
 * \param mutex_lock    the lock function implementation
 * \param mutex_unlock  the unlock function implementation
 */

/**
 * \brief               Free global mutexes.
 */

/* MBEDTLS_THREADING_ALT */

/*
 * The function pointers for mutex_init, mutex_free, mutex_ and mutex_unlock
 *
 * All these functions are expected to work or the result will be undefined.
 */

/*
 * Global mutexes
 */

/* This mutex may or may not be used in the default definition of
 * mbedtls_platform_gmtime_r(), but in order to determine that,
 * we need to check POSIX features, hence modify _POSIX_C_SOURCE.
 * With the current approach, this declaration is orphaned, lacking
 * an accompanying definition, in case mbedtls_platform_gmtime_r()
 * doesn't need it, but that's not a problem. */

/* MBEDTLS_HAVE_TIME_DATE && !MBEDTLS_PLATFORM_GMTIME_R_ALT */

/* MBEDTLS_THREADING_C */

/* threading.h */
