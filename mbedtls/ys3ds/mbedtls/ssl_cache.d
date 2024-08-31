/**
 * \file ssl_cache.h
 *
 * \brief SSL session cache implementation
 */

extern (C):

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */

enum MBEDTLS_SSL_CACHE_DEFAULT_TIMEOUT = 86400; /*!< 1 day  */

enum MBEDTLS_SSL_CACHE_DEFAULT_MAX_ENTRIES = 50; /*!< Maximum entries in cache */

/** \} name SECTION: Module settings */

/**
 * \brief   This structure is used for storing cache entries
 */
struct mbedtls_ssl_cache_entry
{
    mbedtls_time_t timestamp; /*!< entry timestamp    */

    mbedtls_ssl_session session; /*!< entry session      */

    mbedtls_x509_buf peer_cert; /*!< entry peer_cert    */

    mbedtls_ssl_cache_entry* next; /*!< chain pointer      */
}

/**
 * \brief Cache context
 */
struct mbedtls_ssl_cache_context
{
    mbedtls_ssl_cache_entry* chain; /*!< start of the chain     */
    int timeout; /*!< cache entry timeout    */
    int max_entries; /*!< maximum entries        */

    /*!< mutex                  */
}

/**
 * \brief          Initialize an SSL cache context
 *
 * \param cache    SSL cache context
 */
void mbedtls_ssl_cache_init (mbedtls_ssl_cache_context* cache);

/**
 * \brief          Cache get callback implementation
 *                 (Thread-safe if MBEDTLS_THREADING_C is enabled)
 *
 * \param data     SSL cache context
 * \param session  session to retrieve entry for
 *
 * \return                \c 0 on success.
 * \return                #MBEDTLS_ERR_SSL_CACHE_ENTRY_NOT_FOUND if there is
 *                        no cache entry with specified session ID found, or
 *                        any other negative error code for other failures.
 */
int mbedtls_ssl_cache_get (void* data, mbedtls_ssl_session* session);

/**
 * \brief          Cache set callback implementation
 *                 (Thread-safe if MBEDTLS_THREADING_C is enabled)
 *
 * \param data     SSL cache context
 * \param session  session to store entry for
 *
 * \return                \c 0 on success.
 * \return                A negative error code on failure.
 */
int mbedtls_ssl_cache_set (void* data, const(mbedtls_ssl_session)* session);

/**
 * \brief          Set the cache timeout
 *                 (Default: MBEDTLS_SSL_CACHE_DEFAULT_TIMEOUT (1 day))
 *
 *                 A timeout of 0 indicates no timeout.
 *
 * \param cache    SSL cache context
 * \param timeout  cache entry timeout in seconds
 */
void mbedtls_ssl_cache_set_timeout (mbedtls_ssl_cache_context* cache, int timeout);
/* MBEDTLS_HAVE_TIME */

/**
 * \brief          Set the maximum number of cache entries
 *                 (Default: MBEDTLS_SSL_CACHE_DEFAULT_MAX_ENTRIES (50))
 *
 * \param cache    SSL cache context
 * \param max      cache entry maximum
 */
void mbedtls_ssl_cache_set_max_entries (mbedtls_ssl_cache_context* cache, int max);

/**
 * \brief          Free referenced items in a cache context and clear memory
 *
 * \param cache    SSL cache context
 */
void mbedtls_ssl_cache_free (mbedtls_ssl_cache_context* cache);

/* ssl_cache.h */
