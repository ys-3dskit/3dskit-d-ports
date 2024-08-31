/**
 * \file havege.h
 *
 * \brief HAVEGE: HArdware Volatile Entropy Gathering and Expansion
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

extern (C):

enum MBEDTLS_HAVEGE_COLLECT_SIZE = 1024;

/**
 * \brief          HAVEGE state structure
 */
struct mbedtls_havege_state
{
    uint PT1;
    uint PT2;
    uint[2] offset;
    uint[MBEDTLS_HAVEGE_COLLECT_SIZE] pool;
    uint[8192] WALK;
}

/**
 * \brief          HAVEGE initialization
 *
 * \param hs       HAVEGE state to be initialized
 */
void mbedtls_havege_init (mbedtls_havege_state* hs);

/**
 * \brief          Clear HAVEGE state
 *
 * \param hs       HAVEGE state to be cleared
 */
void mbedtls_havege_free (mbedtls_havege_state* hs);

/**
 * \brief          HAVEGE rand function
 *
 * \param p_rng    A HAVEGE state
 * \param output   Buffer to fill
 * \param len      Length of buffer
 *
 * \return         0
 */
int mbedtls_havege_random (void* p_rng, ubyte* output, size_t len);

/* havege.h */
