/**
 * \file platform.h
 *
 * \brief This file contains the definitions and functions of the
 *        Mbed TLS platform abstraction layer.
 *
 *        The platform abstraction layer removes the need for the library
 *        to directly link to standard C library functions or operating
 *        system services, making the library easier to port and embed.
 *        Application developers and users of the library can provide their own
 *        implementations of these functions, or implementations specific to
 *        their platform, which can be statically linked to the library or
 *        dynamically configured at runtime.
 *
 *        When all compilation options related to platform abstraction are
 *        disabled, this header just defines `mbedtls_xxx` function names
 *        as aliases to the standard `xxx` function.
 *
 *        Most modules in the library and example programs are expected to
 *        include this header.
 */

import core.stdc.stdio;
import core.stdc.stdlib;
import core.stdc.time;

extern (C) @nogc nothrow:

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/** Hardware accelerator failed */
enum MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED = -0x0070;
/** The requested feature is not supported by the platform */
enum MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED = -0x0072;

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */

/* The older Microsoft Windows common runtime provides non-conforming
 * implementations of some standard library functions, including snprintf
 * and vsnprintf. This affects MSVC and MinGW builds.
 */

/**< The default \c snprintf function to use.  */

alias MBEDTLS_PLATFORM_STD_SNPRINTF = snprintf; /**< The default \c snprintf function to use.  */

/**< The default \c vsnprintf function to use.  */

alias MBEDTLS_PLATFORM_STD_VSNPRINTF = vsnprintf; /**< The default \c vsnprintf function to use.  */

alias MBEDTLS_PLATFORM_STD_PRINTF = printf; /**< The default \c printf function to use. */

alias MBEDTLS_PLATFORM_STD_FPRINTF = fprintf; /**< The default \c fprintf function to use. */

alias MBEDTLS_PLATFORM_STD_CALLOC = calloc; /**< The default \c calloc function to use. */

alias MBEDTLS_PLATFORM_STD_FREE = free; /**< The default \c free function to use. */

alias MBEDTLS_PLATFORM_STD_EXIT = exit; /**< The default \c exit function to use. */

alias MBEDTLS_PLATFORM_STD_TIME = time; /**< The default \c time function to use. */

alias MBEDTLS_PLATFORM_STD_EXIT_SUCCESS = EXIT_SUCCESS; /**< The default exit value to use. */

alias MBEDTLS_PLATFORM_STD_EXIT_FAILURE = EXIT_FAILURE; /**< The default exit value to use. */

//alias MBEDTLS_PLATFORM_STD_NV_SEED_READ = mbedtls_platform_std_nv_seed_read;

//alias MBEDTLS_PLATFORM_STD_NV_SEED_WRITE = mbedtls_platform_std_nv_seed_write;

enum MBEDTLS_PLATFORM_STD_NV_SEED_FILE = "seedfile";

/* MBEDTLS_FS_IO */
/* MBEDTLS_PLATFORM_NO_STD_FUNCTIONS */

/* MBEDTLS_PLATFORM_NO_STD_FUNCTIONS */

/* Enable certain documented defines only when generating doxygen to avoid
 * an "unrecognized define" error. */

/** \} name SECTION: Module settings */

/*
 * The function pointers for calloc and free.
 * Please see MBEDTLS_PLATFORM_STD_CALLOC and MBEDTLS_PLATFORM_STD_FREE
 * in mbedtls_config.h for more information about behaviour and requirements.
 */

/* For size_t */

/**
 * \brief               This function dynamically sets the memory-management
 *                      functions used by the library, during runtime.
 *
 * \param calloc_func   The \c calloc function implementation.
 * \param free_func     The \c free function implementation.
 *
 * \return              \c 0.
 */

/* MBEDTLS_PLATFORM_FREE_MACRO && MBEDTLS_PLATFORM_CALLOC_MACRO */
/* !MBEDTLS_PLATFORM_MEMORY */

alias mbedtls_free = free;
alias mbedtls_calloc = calloc;
/* MBEDTLS_PLATFORM_MEMORY && !MBEDTLS_PLATFORM_{FREE,CALLOC}_MACRO */

/*
 * The function pointers for fprintf
 */

/* We need FILE * */

/**
 * \brief                This function dynamically configures the fprintf
 *                       function that is called when the
 *                       mbedtls_fprintf() function is invoked by the library.
 *
 * \param fprintf_func   The \c fprintf function implementation.
 *
 * \return               \c 0.
 */

alias mbedtls_fprintf = fprintf;
/* MBEDTLS_PLATFORM_FPRINTF_MACRO */
/* MBEDTLS_PLATFORM_FPRINTF_ALT */

/*
 * The function pointers for printf
 */

/**
 * \brief               This function dynamically configures the snprintf
 *                      function that is called when the mbedtls_snprintf()
 *                      function is invoked by the library.
 *
 * \param printf_func   The \c printf function implementation.
 *
 * \return              \c 0 on success.
 */

/* !MBEDTLS_PLATFORM_PRINTF_ALT */

alias mbedtls_printf = printf;
/* MBEDTLS_PLATFORM_PRINTF_MACRO */
/* MBEDTLS_PLATFORM_PRINTF_ALT */

/*
 * The function pointers for snprintf
 *
 * The snprintf implementation should conform to C99:
 * - it *must* always correctly zero-terminate the buffer
 *   (except when n == 0, then it must leave the buffer untouched)
 * - however it is acceptable to return -1 instead of the required length when
 *   the destination buffer is too short.
 */

/* For Windows (inc. MSYS2), we provide our own fixed implementation */

/**
 * \brief                 This function allows configuring a custom
 *                        \c snprintf function pointer.
 *
 * \param snprintf_func   The \c snprintf function implementation.
 *
 * \return                \c 0 on success.
 */

/* MBEDTLS_PLATFORM_SNPRINTF_ALT */

alias mbedtls_snprintf = MBEDTLS_PLATFORM_STD_SNPRINTF;
/* MBEDTLS_PLATFORM_SNPRINTF_MACRO */
/* MBEDTLS_PLATFORM_SNPRINTF_ALT */

/*
 * The function pointers for vsnprintf
 *
 * The vsnprintf implementation should conform to C99:
 * - it *must* always correctly zero-terminate the buffer
 *   (except when n == 0, then it must leave the buffer untouched)
 * - however it is acceptable to return -1 instead of the required length when
 *   the destination buffer is too short.
 */

/* For Older Windows (inc. MSYS2), we provide our own fixed implementation */

/**
 * \brief   Set your own snprintf function pointer
 *
 * \param   vsnprintf_func   The \c vsnprintf function implementation
 *
 * \return  \c 0
 */

/* MBEDTLS_PLATFORM_VSNPRINTF_ALT */

alias mbedtls_vsnprintf = vsnprintf;
/* MBEDTLS_PLATFORM_VSNPRINTF_MACRO */
/* MBEDTLS_PLATFORM_VSNPRINTF_ALT */

/*
 * The function pointers for exit
 */

/**
 * \brief             This function dynamically configures the exit
 *                    function that is called when the mbedtls_exit()
 *                    function is invoked by the library.
 *
 * \param exit_func   The \c exit function implementation.
 *
 * \return            \c 0 on success.
 */

alias mbedtls_exit = exit;
/* MBEDTLS_PLATFORM_EXIT_MACRO */
/* MBEDTLS_PLATFORM_EXIT_ALT */

/*
 * The default exit values
 */
enum MBEDTLS_EXIT_SUCCESS = MBEDTLS_PLATFORM_STD_EXIT_SUCCESS;

enum MBEDTLS_EXIT_FAILURE = MBEDTLS_PLATFORM_STD_EXIT_FAILURE;

/*
 * The function pointers for reading from and writing a seed file to
 * Non-Volatile storage (NV) in a platform-independent way
 *
 * Only enabled when the NV seed entropy source is enabled
 */

/* Internal standard platform definitions */

/**
 * \brief   This function allows configuring custom seed file writing and
 *          reading functions.
 *
 * \param   nv_seed_read_func   The seed reading function implementation.
 * \param   nv_seed_write_func  The seed writing function implementation.
 *
 * \return  \c 0 on success.
 */

/* MBEDTLS_PLATFORM_NV_SEED_ALT */
/* MBEDTLS_ENTROPY_NV_SEED */

/**
 * \brief   The platform context structure.
 *
 * \note    This structure may be used to assist platform-specific
 *          setup or teardown operations.
 */
struct mbedtls_platform_context
{
    char dummy; /**< A placeholder member, as empty structs are not portable. */
}

/* !MBEDTLS_PLATFORM_SETUP_TEARDOWN_ALT */

/**
 * \brief   This function performs any platform-specific initialization
 *          operations.
 *
 * \note    This function should be called before any other library functions.
 *
 *          Its implementation is platform-specific, and unless
 *          platform-specific code is provided, it does nothing.
 *
 * \note    The usage and necessity of this function is dependent on the platform.
 *
 * \param   ctx     The platform context.
 *
 * \return  \c 0 on success.
 */
int mbedtls_platform_setup (mbedtls_platform_context* ctx);
/**
 * \brief   This function performs any platform teardown operations.
 *
 * \note    This function should be called after every other Mbed TLS module
 *          has been correctly freed using the appropriate free function.
 *
 *          Its implementation is platform-specific, and unless
 *          platform-specific code is provided, it does nothing.
 *
 * \note    The usage and necessity of this function is dependent on the platform.
 *
 * \param   ctx     The platform context.
 *
 */
void mbedtls_platform_teardown (mbedtls_platform_context* ctx);

/* platform.h */
