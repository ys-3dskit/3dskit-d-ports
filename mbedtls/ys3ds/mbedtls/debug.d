/**
 * \file debug.h
 *
 * \brief Functions for controlling and providing debug output from the library.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

import ys3ds.mbedtls.ssl;
import ys3ds.mbedtls.bignum;
import ys3ds.mbedtls.ecp;
import ys3ds.mbedtls.x509;
import ys3ds.mbedtls.x509_crt;
import ys3ds.mbedtls.ecdh;

extern (C):

extern (D) auto MBEDTLS_SSL_DEBUG_RET(T0, T1, T2)(auto ref T0 level, auto ref T1 text, auto ref T2 ret)
{
    return mbedtls_debug_print_ret(ssl, level, __FILE__, __LINE__, text, ret);
}

extern (D) auto MBEDTLS_SSL_DEBUG_BUF(T0, T1, T2, T3)(auto ref T0 level, auto ref T1 text, auto ref T2 buf, auto ref T3 len)
{
    return mbedtls_debug_print_buf(ssl, level, __FILE__, __LINE__, text, buf, len);
}

extern (D) auto MBEDTLS_SSL_DEBUG_MPI(T0, T1, T2)(auto ref T0 level, auto ref T1 text, auto ref T2 X)
{
    return mbedtls_debug_print_mpi(ssl, level, __FILE__, __LINE__, text, X);
}

extern (D) auto MBEDTLS_SSL_DEBUG_ECP(T0, T1, T2)(auto ref T0 level, auto ref T1 text, auto ref T2 X)
{
    return mbedtls_debug_print_ecp(ssl, level, __FILE__, __LINE__, text, X);
}

extern (D) auto MBEDTLS_SSL_DEBUG_CRT(T0, T1, T2)(auto ref T0 level, auto ref T1 text, auto ref T2 crt)
{
    return mbedtls_debug_print_crt(ssl, level, __FILE__, __LINE__, text, crt);
}

extern (D) auto MBEDTLS_SSL_DEBUG_ECDH(T0, T1, T2)(auto ref T0 level, auto ref T1 ecdh, auto ref T2 attr)
{
    return mbedtls_debug_printf_ecdh(ssl, level, __FILE__, __LINE__, ecdh, attr);
}

/* MBEDTLS_DEBUG_C */

/* MBEDTLS_DEBUG_C */

/**
 * \def MBEDTLS_PRINTF_ATTRIBUTE
 *
 * Mark a function as having printf attributes, and thus enable checking
 * via -wFormat and other flags. This does nothing on builds with compilers
 * that do not support the format attribute
 *
 * Module:  library/debug.c
 * Caller:
 *
 * This module provides debugging functions.
 */

/* defined(__MINGW32__) && __USE_MINGW_ANSI_STDIO == 1 */

/* __has_attribute(format) */

/* __has_attribute(format) */
/* defined(__has_attribute) */

/**
 * \def MBEDTLS_PRINTF_SIZET
 *
 * MBEDTLS_PRINTF_xxx: Due to issues with older window compilers
 * and MinGW we need to define the printf specifier for size_t
 * and long long per platform.
 *
 * Module:  library/debug.c
 * Caller:
 *
 * This module provides debugging functions.
 */

/* (defined(__MINGW32__)  && __USE_MINGW_ANSI_STDIO == 0) || (defined(_MSC_VER) && _MSC_VER < 1800) */
enum MBEDTLS_PRINTF_SIZET = "zu";
enum MBEDTLS_PRINTF_LONGLONG = "lld";

/* (defined(__MINGW32__)  && __USE_MINGW_ANSI_STDIO == 0) || (defined(_MSC_VER) && _MSC_VER < 1800) */

/**
 * \brief   Set the threshold error level to handle globally all debug output.
 *          Debug messages that have a level over the threshold value are
 *          discarded.
 *          (Default value: 0 = No debug )
 *
 * \param threshold     threshold level of messages to filter on. Messages at a
 *                      higher level will be discarded.
 *                          - Debug levels
 *                              - 0 No debug
 *                              - 1 Error
 *                              - 2 State change
 *                              - 3 Informational
 *                              - 4 Verbose
 */
void mbedtls_debug_set_threshold (int threshold);

/**
 * \brief    Print a message to the debug output. This function is always used
 *          through the MBEDTLS_SSL_DEBUG_MSG() macro, which supplies the ssl
 *          context, file and line number parameters.
 *
 * \param ssl       SSL context
 * \param level     error level of the debug message
 * \param file      file the message has occurred in
 * \param line      line number the message has occurred at
 * \param format    format specifier, in printf format
 * \param ...       variables used by the format specifier
 *
 * \attention       This function is intended for INTERNAL usage within the
 *                  library only.
 */
void mbedtls_debug_print_msg (
    const(mbedtls_ssl_context)* ssl,
    int level,
    const(char)* file,
    int line,
    const(char)* format,
    ...);

/**
 * \brief   Print the return value of a function to the debug output. This
 *          function is always used through the MBEDTLS_SSL_DEBUG_RET() macro,
 *          which supplies the ssl context, file and line number parameters.
 *
 * \param ssl       SSL context
 * \param level     error level of the debug message
 * \param file      file the error has occurred in
 * \param line      line number the error has occurred in
 * \param text      the name of the function that returned the error
 * \param ret       the return code value
 *
 * \attention       This function is intended for INTERNAL usage within the
 *                  library only.
 */
void mbedtls_debug_print_ret (
    const(mbedtls_ssl_context)* ssl,
    int level,
    const(char)* file,
    int line,
    const(char)* text,
    int ret);

/**
 * \brief   Output a buffer of size len bytes to the debug output. This function
 *          is always used through the MBEDTLS_SSL_DEBUG_BUF() macro,
 *          which supplies the ssl context, file and line number parameters.
 *
 * \param ssl       SSL context
 * \param level     error level of the debug message
 * \param file      file the error has occurred in
 * \param line      line number the error has occurred in
 * \param text      a name or label for the buffer being dumped. Normally the
 *                  variable or buffer name
 * \param buf       the buffer to be outputted
 * \param len       length of the buffer
 *
 * \attention       This function is intended for INTERNAL usage within the
 *                  library only.
 */
void mbedtls_debug_print_buf (
    const(mbedtls_ssl_context)* ssl,
    int level,
    const(char)* file,
    int line,
    const(char)* text,
    const(ubyte)* buf,
    size_t len);

/**
 * \brief   Print a MPI variable to the debug output. This function is always
 *          used through the MBEDTLS_SSL_DEBUG_MPI() macro, which supplies the
 *          ssl context, file and line number parameters.
 *
 * \param ssl       SSL context
 * \param level     error level of the debug message
 * \param file      file the error has occurred in
 * \param line      line number the error has occurred in
 * \param text      a name or label for the MPI being output. Normally the
 *                  variable name
 * \param X         the MPI variable
 *
 * \attention       This function is intended for INTERNAL usage within the
 *                  library only.
 */
void mbedtls_debug_print_mpi (
    const(mbedtls_ssl_context)* ssl,
    int level,
    const(char)* file,
    int line,
    const(char)* text,
    const(mbedtls_mpi)* X);

/**
 * \brief   Print an ECP point to the debug output. This function is always
 *          used through the MBEDTLS_SSL_DEBUG_ECP() macro, which supplies the
 *          ssl context, file and line number parameters.
 *
 * \param ssl       SSL context
 * \param level     error level of the debug message
 * \param file      file the error has occurred in
 * \param line      line number the error has occurred in
 * \param text      a name or label for the ECP point being output. Normally the
 *                  variable name
 * \param X         the ECP point
 *
 * \attention       This function is intended for INTERNAL usage within the
 *                  library only.
 */
void mbedtls_debug_print_ecp (
    const(mbedtls_ssl_context)* ssl,
    int level,
    const(char)* file,
    int line,
    const(char)* text,
    const(mbedtls_ecp_point)* X);

/**
 * \brief   Print a X.509 certificate structure to the debug output. This
 *          function is always used through the MBEDTLS_SSL_DEBUG_CRT() macro,
 *          which supplies the ssl context, file and line number parameters.
 *
 * \param ssl       SSL context
 * \param level     error level of the debug message
 * \param file      file the error has occurred in
 * \param line      line number the error has occurred in
 * \param text      a name or label for the certificate being output
 * \param crt       X.509 certificate structure
 *
 * \attention       This function is intended for INTERNAL usage within the
 *                  library only.
 */
void mbedtls_debug_print_crt (
    const(mbedtls_ssl_context)* ssl,
    int level,
    const(char)* file,
    int line,
    const(char)* text,
    const(mbedtls_x509_crt)* crt);

enum mbedtls_debug_ecdh_attr
{
    MBEDTLS_DEBUG_ECDH_Q = 0,
    MBEDTLS_DEBUG_ECDH_QP = 1,
    MBEDTLS_DEBUG_ECDH_Z = 2
}

/**
 * \brief   Print a field of the ECDH structure in the SSL context to the debug
 *          output. This function is always used through the
 *          MBEDTLS_SSL_DEBUG_ECDH() macro, which supplies the ssl context, file
 *          and line number parameters.
 *
 * \param ssl       SSL context
 * \param level     error level of the debug message
 * \param file      file the error has occurred in
 * \param line      line number the error has occurred in
 * \param ecdh      the ECDH context
 * \param attr      the identifier of the attribute being output
 *
 * \attention       This function is intended for INTERNAL usage within the
 *                  library only.
 */
void mbedtls_debug_printf_ecdh (
    const(mbedtls_ssl_context)* ssl,
    int level,
    const(char)* file,
    int line,
    const(mbedtls_ecdh_context)* ecdh,
    mbedtls_debug_ecdh_attr attr);

/* debug.h */
