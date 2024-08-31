module ys3ds.mbedtls.psa.crypto_driver_common;

/**
 * \file psa/crypto_driver_common.h
 * \brief Definitions for all PSA crypto drivers
 *
 * This file contains common definitions shared by all PSA crypto drivers.
 * Do not include it directly: instead, include the header file(s) for
 * the type(s) of driver that you are implementing. For example, if
 * you are writing a dynamically registered driver for a secure element,
 * include `psa/crypto_se_driver.h`.
 *
 * This file is part of the PSA Crypto Driver Model, containing functions for
 * driver developers to implement to enable hardware to be called in a
 * standardized way by a PSA Cryptographic API implementation. The functions
 * comprising the driver model, which driver authors implement, are not
 * intended to be called by application developers.
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

public import ys3ds.mbedtls.psa.crypto_types;
public import ys3ds.mbedtls.psa.crypto_values;
public import ys3ds.mbedtls.psa.crypto_sizes;

extern (C) @nogc nothrow:

/* Include type definitions (psa_status_t, psa_algorithm_t,
 * psa_key_type_t, etc.) and macros to build and analyze values
 * of these types. */

/* Include size definitions which are used to size some arrays in operation
 * structures. */

/** For encrypt-decrypt functions, whether the operation is an encryption
 * or a decryption. */
enum psa_encrypt_or_decrypt_t
{
    PSA_CRYPTO_DRIVER_DECRYPT = 0,
    PSA_CRYPTO_DRIVER_ENCRYPT = 1
}

/* PSA_CRYPTO_DRIVER_COMMON_H */
