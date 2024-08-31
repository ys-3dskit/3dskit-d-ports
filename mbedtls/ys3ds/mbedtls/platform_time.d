/**
 * \file platform_time.h
 *
 * \brief Mbed TLS Platform time abstraction
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

import core.stdc.config;
import core.stdc.time;

extern (C):

/*
 * The time_t datatype
 */

/* For time_t */

alias mbedtls_time_t = c_long;
/* MBEDTLS_PLATFORM_TIME_TYPE_MACRO */

/*
 * The function pointers for time
 */

/**
 * \brief   Set your own time function pointer
 *
 * \param   time_func   the time function implementation
 *
 * \return              0
 */

alias mbedtls_time = time;
/* MBEDTLS_PLATFORM_TIME_MACRO */
/* MBEDTLS_PLATFORM_TIME_ALT */

/* platform_time.h */
