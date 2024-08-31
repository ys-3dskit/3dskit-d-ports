/**
 * \file check_config.h
 *
 * \brief Consistency checks for configuration options
 */

extern (C):

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * It is recommended to include this file from your config.h
 * in order to catch dependency issues early.
 */

/* *INDENT-OFF* */
/*
 * We assume CHAR_BIT is 8 in many places. In practice, this is true on our
 * target platforms, so not an issue, but let's just be extra sure.
 */

/* Fix the config here. Not convenient to put an #ifdef _WIN32 in config.h as
 * it would confuse config.py. */

/* _WIN32 */

/* MBEDTLS_PKCS11_C */

/* MBEDTLS_HAVE_INT32 && MBEDTLS_HAVE_INT64 */

/* (MBEDTLS_HAVE_INT32 || MBEDTLS_HAVE_INT64) && MBEDTLS_HAVE_ASM */

/* MBEDTLS_SSL_PROTO_SSL3 */

/* MBEDTLS_SSL_SRV_SUPPORT_SSLV2_CLIENT_HELLO */

/* MBEDTLS_DEPRECATED_REMOVED */
/* MBEDTLS_SSL_HW_RECORD_ACCEL */

/*
 * Avoid warning from -pedantic. This is a convenient place for this
 * workaround since this is included by every single file before the
 * #if defined(MBEDTLS_xxx_C) that results in empty translation units.
 */
alias mbedtls_iso_c_forbids_empty_translation_units = int;

/* *INDENT-ON* */
/* MBEDTLS_CHECK_CONFIG_H */
