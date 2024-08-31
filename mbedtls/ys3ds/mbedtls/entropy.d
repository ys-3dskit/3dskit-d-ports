/**
 * \file entropy.h
 *
 * \brief Entropy accumulator implementation
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

import ys3ds.mbedtls.sha512;

extern (C):

/** Critical entropy source failure. */
enum MBEDTLS_ERR_ENTROPY_SOURCE_FAILED = -0x003C;
/** No more sources can be added. */
enum MBEDTLS_ERR_ENTROPY_MAX_SOURCES = -0x003E;
/** No sources have been added to poll. */
enum MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED = -0x0040;
/** No strong sources have been added to poll. */
enum MBEDTLS_ERR_ENTROPY_NO_STRONG_SOURCE = -0x003D;
/** Read/write error in file. */
enum MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR = -0x003F;

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */

enum MBEDTLS_ENTROPY_MAX_SOURCES = 20; /**< Maximum number of sources supported */

enum MBEDTLS_ENTROPY_MAX_GATHER = 128; /**< Maximum amount requested from entropy sources */

/** \} name SECTION: Module settings */

enum MBEDTLS_ENTROPY_BLOCK_SIZE = 64; /**< Block size of entropy accumulator (SHA-512) */

/**< Block size of entropy accumulator (SHA-256) */

enum MBEDTLS_ENTROPY_MAX_SEED_SIZE = 1024; /**< Maximum size of seed we read from seed file */
enum MBEDTLS_ENTROPY_SOURCE_MANUAL = MBEDTLS_ENTROPY_MAX_SOURCES;

enum MBEDTLS_ENTROPY_SOURCE_STRONG = 1; /**< Entropy source is strong   */
enum MBEDTLS_ENTROPY_SOURCE_WEAK = 0; /**< Entropy source is weak     */

/**
 * \brief           Entropy poll callback pointer
 *
 * \param data      Callback-specific data pointer
 * \param output    Data to fill
 * \param len       Maximum size to provide
 * \param olen      The actual amount of bytes put into the buffer (Can be 0)
 *
 * \return          0 if no critical failures occurred,
 *                  MBEDTLS_ERR_ENTROPY_SOURCE_FAILED otherwise
 */
alias mbedtls_entropy_f_source_ptr = int function (
    void* data,
    ubyte* output,
    size_t len,
    size_t* olen);

/**
 * \brief           Entropy source state
 */
struct mbedtls_entropy_source_state
{
    mbedtls_entropy_f_source_ptr f_source; /**< The entropy source callback */
    void* p_source; /**< The callback data pointer */
    size_t size; /**< Amount received in bytes */
    size_t threshold; /**< Minimum bytes required before release */
    int strong; /**< Is the source strong? */
}

/**
 * \brief           Entropy context structure
 */
struct mbedtls_entropy_context
{
    int accumulator_started; /* 0 after init.
     * 1 after the first update.
     * -1 after free. */

    mbedtls_sha512_context accumulator;

    int source_count; /* Number of entries used in source. */
    mbedtls_entropy_source_state[MBEDTLS_ENTROPY_MAX_SOURCES] source;

    /*!< mutex                  */
}

/**
 * \brief           Initialize the context
 *
 * \param ctx       Entropy context to initialize
 */
void mbedtls_entropy_init (mbedtls_entropy_context* ctx);

/**
 * \brief           Free the data in the context
 *
 * \param ctx       Entropy context to free
 */
void mbedtls_entropy_free (mbedtls_entropy_context* ctx);

/**
 * \brief           Adds an entropy source to poll
 *                  (Thread-safe if MBEDTLS_THREADING_C is enabled)
 *
 * \param ctx       Entropy context
 * \param f_source  Entropy function
 * \param p_source  Function data
 * \param threshold Minimum required from source before entropy is released
 *                  ( with mbedtls_entropy_func() ) (in bytes)
 * \param strong    MBEDTLS_ENTROPY_SOURCE_STRONG or
 *                  MBEDTLS_ENTROPY_SOURCE_WEAK.
 *                  At least one strong source needs to be added.
 *                  Weaker sources (such as the cycle counter) can be used as
 *                  a complement.
 *
 * \return          0 if successful or MBEDTLS_ERR_ENTROPY_MAX_SOURCES
 */
int mbedtls_entropy_add_source (
    mbedtls_entropy_context* ctx,
    mbedtls_entropy_f_source_ptr f_source,
    void* p_source,
    size_t threshold,
    int strong);

/**
 * \brief           Trigger an extra gather poll for the accumulator
 *                  (Thread-safe if MBEDTLS_THREADING_C is enabled)
 *
 * \param ctx       Entropy context
 *
 * \return          0 if successful, or MBEDTLS_ERR_ENTROPY_SOURCE_FAILED
 */
int mbedtls_entropy_gather (mbedtls_entropy_context* ctx);

/**
 * \brief           Retrieve entropy from the accumulator
 *                  (Maximum length: MBEDTLS_ENTROPY_BLOCK_SIZE)
 *                  (Thread-safe if MBEDTLS_THREADING_C is enabled)
 *
 * \param data      Entropy context
 * \param output    Buffer to fill
 * \param len       Number of bytes desired, must be at most MBEDTLS_ENTROPY_BLOCK_SIZE
 *
 * \return          0 if successful, or MBEDTLS_ERR_ENTROPY_SOURCE_FAILED
 */
int mbedtls_entropy_func (void* data, ubyte* output, size_t len);

/**
 * \brief           Add data to the accumulator manually
 *                  (Thread-safe if MBEDTLS_THREADING_C is enabled)
 *
 * \param ctx       Entropy context
 * \param data      Data to add
 * \param len       Length of data
 *
 * \return          0 if successful
 */
int mbedtls_entropy_update_manual (
    mbedtls_entropy_context* ctx,
    const(ubyte)* data,
    size_t len);

/**
 * \brief           Trigger an update of the seed file in NV by using the
 *                  current entropy pool.
 *
 * \param ctx       Entropy context
 *
 * \return          0 if successful
 */

/* MBEDTLS_ENTROPY_NV_SEED */

/**
 * \brief               Write a seed file
 *
 * \param ctx           Entropy context
 * \param path          Name of the file
 *
 * \return              0 if successful,
 *                      MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR on file error, or
 *                      MBEDTLS_ERR_ENTROPY_SOURCE_FAILED
 */
int mbedtls_entropy_write_seed_file (mbedtls_entropy_context* ctx, const(char)* path);

/**
 * \brief               Read and update a seed file. Seed is added to this
 *                      instance. No more than MBEDTLS_ENTROPY_MAX_SEED_SIZE bytes are
 *                      read from the seed file. The rest is ignored.
 *
 * \param ctx           Entropy context
 * \param path          Name of the file
 *
 * \return              0 if successful,
 *                      MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR on file error,
 *                      MBEDTLS_ERR_ENTROPY_SOURCE_FAILED
 */
int mbedtls_entropy_update_seed_file (mbedtls_entropy_context* ctx, const(char)* path);
/* MBEDTLS_FS_IO */

/**
 * \brief          Checkup routine
 *
 *                 This module self-test also calls the entropy self-test,
 *                 mbedtls_entropy_source_self_test();
 *
 * \return         0 if successful, or 1 if a test failed
 */

/**
 * \brief          Checkup routine
 *
 *                 Verifies the integrity of the hardware entropy source
 *                 provided by the function 'mbedtls_hardware_poll()'.
 *
 *                 Note this is the only hardware entropy source that is known
 *                 at link time, and other entropy sources configured
 *                 dynamically at runtime by the function
 *                 mbedtls_entropy_add_source() will not be tested.
 *
 * \return         0 if successful, or 1 if a test failed
 */

/* MBEDTLS_ENTROPY_HARDWARE_ALT */
/* MBEDTLS_SELF_TEST */

/* entropy.h */
