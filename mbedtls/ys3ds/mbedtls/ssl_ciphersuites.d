/**
 * \file ssl_ciphersuites.h
 *
 * \brief SSL Ciphersuites for Mbed TLS
 */

import ys3ds.mbedtls.cipher;
import ys3ds.mbedtls.pk;
import ys3ds.mbedtls.md;

extern (C):

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * Supported ciphersuites (Official IANA names)
 */
enum MBEDTLS_TLS_RSA_WITH_NULL_MD5 = 0x01; /**< Weak! */
enum MBEDTLS_TLS_RSA_WITH_NULL_SHA = 0x02; /**< Weak! */

enum MBEDTLS_TLS_RSA_WITH_RC4_128_MD5 = 0x04;
enum MBEDTLS_TLS_RSA_WITH_RC4_128_SHA = 0x05;
enum MBEDTLS_TLS_RSA_WITH_DES_CBC_SHA = 0x09; /**< Weak! Not in TLS 1.2 */

enum MBEDTLS_TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x0A;

enum MBEDTLS_TLS_DHE_RSA_WITH_DES_CBC_SHA = 0x15; /**< Weak! Not in TLS 1.2 */
enum MBEDTLS_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x16;

enum MBEDTLS_TLS_PSK_WITH_NULL_SHA = 0x2C; /**< Weak! */
enum MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA = 0x2D; /**< Weak! */
enum MBEDTLS_TLS_RSA_PSK_WITH_NULL_SHA = 0x2E; /**< Weak! */
enum MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA = 0x2F;

enum MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x33;
enum MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA = 0x35;
enum MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x39;

enum MBEDTLS_TLS_RSA_WITH_NULL_SHA256 = 0x3B; /**< Weak! */
enum MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x3C; /**< TLS 1.2 */
enum MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x3D; /**< TLS 1.2 */

enum MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x41;
enum MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x45;

enum MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x67; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x6B; /**< TLS 1.2 */

enum MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x84;
enum MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x88;

enum MBEDTLS_TLS_PSK_WITH_RC4_128_SHA = 0x8A;
enum MBEDTLS_TLS_PSK_WITH_3DES_EDE_CBC_SHA = 0x8B;
enum MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA = 0x8C;
enum MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA = 0x8D;

enum MBEDTLS_TLS_DHE_PSK_WITH_RC4_128_SHA = 0x8E;
enum MBEDTLS_TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA = 0x8F;
enum MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA = 0x90;
enum MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA = 0x91;

enum MBEDTLS_TLS_RSA_PSK_WITH_RC4_128_SHA = 0x92;
enum MBEDTLS_TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA = 0x93;
enum MBEDTLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA = 0x94;
enum MBEDTLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA = 0x95;

enum MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x9C; /**< TLS 1.2 */
enum MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x9D; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x9E; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x9F; /**< TLS 1.2 */

enum MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256 = 0xA8; /**< TLS 1.2 */
enum MBEDTLS_TLS_PSK_WITH_AES_256_GCM_SHA384 = 0xA9; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 = 0xAA; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 = 0xAB; /**< TLS 1.2 */
enum MBEDTLS_TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 = 0xAC; /**< TLS 1.2 */
enum MBEDTLS_TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 = 0xAD; /**< TLS 1.2 */

enum MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256 = 0xAE;
enum MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA384 = 0xAF;
enum MBEDTLS_TLS_PSK_WITH_NULL_SHA256 = 0xB0; /**< Weak! */
enum MBEDTLS_TLS_PSK_WITH_NULL_SHA384 = 0xB1; /**< Weak! */

enum MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 = 0xB2;
enum MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 = 0xB3;
enum MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA256 = 0xB4; /**< Weak! */
enum MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA384 = 0xB5; /**< Weak! */

enum MBEDTLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 = 0xB6;
enum MBEDTLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 = 0xB7;
enum MBEDTLS_TLS_RSA_PSK_WITH_NULL_SHA256 = 0xB8; /**< Weak! */
enum MBEDTLS_TLS_RSA_PSK_WITH_NULL_SHA384 = 0xB9; /**< Weak! */

enum MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xBA; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xBE; /**< TLS 1.2 */

enum MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0xC0; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0xC4; /**< TLS 1.2 */

enum MBEDTLS_TLS_ECDH_ECDSA_WITH_NULL_SHA = 0xC001; /**< Weak! */
enum MBEDTLS_TLS_ECDH_ECDSA_WITH_RC4_128_SHA = 0xC002; /**< Not in SSL3! */
enum MBEDTLS_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xC003; /**< Not in SSL3! */
enum MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = 0xC004; /**< Not in SSL3! */
enum MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = 0xC005; /**< Not in SSL3! */

enum MBEDTLS_TLS_ECDHE_ECDSA_WITH_NULL_SHA = 0xC006; /**< Weak! */
enum MBEDTLS_TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = 0xC007; /**< Not in SSL3! */
enum MBEDTLS_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xC008; /**< Not in SSL3! */
enum MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xC009; /**< Not in SSL3! */
enum MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xC00A; /**< Not in SSL3! */

enum MBEDTLS_TLS_ECDH_RSA_WITH_NULL_SHA = 0xC00B; /**< Weak! */
enum MBEDTLS_TLS_ECDH_RSA_WITH_RC4_128_SHA = 0xC00C; /**< Not in SSL3! */
enum MBEDTLS_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = 0xC00D; /**< Not in SSL3! */
enum MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = 0xC00E; /**< Not in SSL3! */
enum MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = 0xC00F; /**< Not in SSL3! */

enum MBEDTLS_TLS_ECDHE_RSA_WITH_NULL_SHA = 0xC010; /**< Weak! */
enum MBEDTLS_TLS_ECDHE_RSA_WITH_RC4_128_SHA = 0xC011; /**< Not in SSL3! */
enum MBEDTLS_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = 0xC012; /**< Not in SSL3! */
enum MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xC013; /**< Not in SSL3! */
enum MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xC014; /**< Not in SSL3! */

enum MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC023; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC024; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC025; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC026; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xC027; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xC028; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = 0xC029; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = 0xC02A; /**< TLS 1.2 */

enum MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02D; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02E; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = 0xC031; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = 0xC032; /**< TLS 1.2 */

enum MBEDTLS_TLS_ECDHE_PSK_WITH_RC4_128_SHA = 0xC033; /**< Not in SSL3! */
enum MBEDTLS_TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA = 0xC034; /**< Not in SSL3! */
enum MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA = 0xC035; /**< Not in SSL3! */
enum MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA = 0xC036; /**< Not in SSL3! */
enum MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 = 0xC037; /**< Not in SSL3! */
enum MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 = 0xC038; /**< Not in SSL3! */
enum MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA = 0xC039; /**< Weak! No SSL3! */
enum MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA256 = 0xC03A; /**< Weak! No SSL3! */
enum MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA384 = 0xC03B; /**< Weak! No SSL3! */

enum MBEDTLS_TLS_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC03C; /**< TLS 1.2 */
enum MBEDTLS_TLS_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC03D; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC044; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC045; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 = 0xC048; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 = 0xC049; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 = 0xC04A; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 = 0xC04B; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC04C; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC04D; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC04E; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC04F; /**< TLS 1.2 */
enum MBEDTLS_TLS_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC050; /**< TLS 1.2 */
enum MBEDTLS_TLS_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC051; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC052; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC053; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 = 0xC05C; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 = 0xC05D; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 = 0xC05E; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 = 0xC05F; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC060; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC061; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC062; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC063; /**< TLS 1.2 */
enum MBEDTLS_TLS_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC064; /**< TLS 1.2 */
enum MBEDTLS_TLS_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC065; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC066; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC067; /**< TLS 1.2 */
enum MBEDTLS_TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC068; /**< TLS 1.2 */
enum MBEDTLS_TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC069; /**< TLS 1.2 */
enum MBEDTLS_TLS_PSK_WITH_ARIA_128_GCM_SHA256 = 0xC06A; /**< TLS 1.2 */
enum MBEDTLS_TLS_PSK_WITH_ARIA_256_GCM_SHA384 = 0xC06B; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 = 0xC06C; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 = 0xC06D; /**< TLS 1.2 */
enum MBEDTLS_TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 = 0xC06E; /**< TLS 1.2 */
enum MBEDTLS_TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 = 0xC06F; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC070; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC071; /**< TLS 1.2 */

enum MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC072; /**< Not in SSL3! */
enum MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC073; /**< Not in SSL3! */
enum MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC074; /**< Not in SSL3! */
enum MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC075; /**< Not in SSL3! */
enum MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC076; /**< Not in SSL3! */
enum MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC077; /**< Not in SSL3! */
enum MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC078; /**< Not in SSL3! */
enum MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC079; /**< Not in SSL3! */

enum MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC07A; /**< TLS 1.2 */
enum MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC07B; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC07C; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC07D; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC086; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC087; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC088; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC089; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC08A; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC08B; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC08C; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC08D; /**< TLS 1.2 */

enum MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 0xC08E; /**< TLS 1.2 */
enum MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 0xC08F; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 0xC090; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 0xC091; /**< TLS 1.2 */
enum MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 0xC092; /**< TLS 1.2 */
enum MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 0xC093; /**< TLS 1.2 */

enum MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC094;
enum MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC095;
enum MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC096;
enum MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC097;
enum MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC098;
enum MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC099;
enum MBEDTLS_TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC09A; /**< Not in SSL3! */
enum MBEDTLS_TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC09B; /**< Not in SSL3! */

enum MBEDTLS_TLS_RSA_WITH_AES_128_CCM = 0xC09C; /**< TLS 1.2 */
enum MBEDTLS_TLS_RSA_WITH_AES_256_CCM = 0xC09D; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM = 0xC09E; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM = 0xC09F; /**< TLS 1.2 */
enum MBEDTLS_TLS_RSA_WITH_AES_128_CCM_8 = 0xC0A0; /**< TLS 1.2 */
enum MBEDTLS_TLS_RSA_WITH_AES_256_CCM_8 = 0xC0A1; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM_8 = 0xC0A2; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM_8 = 0xC0A3; /**< TLS 1.2 */
enum MBEDTLS_TLS_PSK_WITH_AES_128_CCM = 0xC0A4; /**< TLS 1.2 */
enum MBEDTLS_TLS_PSK_WITH_AES_256_CCM = 0xC0A5; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CCM = 0xC0A6; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CCM = 0xC0A7; /**< TLS 1.2 */
enum MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8 = 0xC0A8; /**< TLS 1.2 */
enum MBEDTLS_TLS_PSK_WITH_AES_256_CCM_8 = 0xC0A9; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CCM_8 = 0xC0AA; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CCM_8 = 0xC0AB; /**< TLS 1.2 */
/* The last two are named with PSK_DHE in the RFC, which looks like a typo */

enum MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM = 0xC0AC; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM = 0xC0AD; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = 0xC0AE; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = 0xC0AF; /**< TLS 1.2 */

enum MBEDTLS_TLS_ECJPAKE_WITH_AES_128_CCM_8 = 0xC0FF; /**< experimental */

/* RFC 7905 */
enum MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAA; /**< TLS 1.2 */
enum MBEDTLS_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAB; /**< TLS 1.2 */
enum MBEDTLS_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAC; /**< TLS 1.2 */
enum MBEDTLS_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAD; /**< TLS 1.2 */
enum MBEDTLS_TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAE; /**< TLS 1.2 */

/* Reminder: update mbedtls_ssl_premaster_secret when adding a new key exchange.
 * Reminder: update MBEDTLS_KEY_EXCHANGE__xxx below
 */
enum mbedtls_key_exchange_type_t
{
    MBEDTLS_KEY_EXCHANGE_NONE = 0,
    MBEDTLS_KEY_EXCHANGE_RSA = 1,
    MBEDTLS_KEY_EXCHANGE_DHE_RSA = 2,
    MBEDTLS_KEY_EXCHANGE_ECDHE_RSA = 3,
    MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA = 4,
    MBEDTLS_KEY_EXCHANGE_PSK = 5,
    MBEDTLS_KEY_EXCHANGE_DHE_PSK = 6,
    MBEDTLS_KEY_EXCHANGE_RSA_PSK = 7,
    MBEDTLS_KEY_EXCHANGE_ECDHE_PSK = 8,
    MBEDTLS_KEY_EXCHANGE_ECDH_RSA = 9,
    MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA = 10,
    MBEDTLS_KEY_EXCHANGE_ECJPAKE = 11
}

/* Key exchanges using a certificate */

/* Key exchanges allowing client certificate requests */

/* Key exchanges involving server signature in ServerKeyExchange */

/* Key exchanges using ECDH */

/* Key exchanges that don't involve ephemeral keys */

/* Key exchanges that involve ephemeral keys */

/* Key exchanges using a PSK */

/* Key exchanges using DHE */

/* Key exchanges using ECDHE */

enum MBEDTLS_CIPHERSUITE_WEAK = 0x01; /**< Weak ciphersuite flag  */
enum MBEDTLS_CIPHERSUITE_SHORT_TAG = 0x02; /**< Short authentication tag,
      eg for CCM_8 */
enum MBEDTLS_CIPHERSUITE_NODTLS = 0x04; /**< Can't be used with DTLS */

/**
 * \brief   This structure is used for storing ciphersuite information
 */
struct mbedtls_ssl_ciphersuite_t
{
    int id;
    const(char)* name;

    mbedtls_cipher_type_t cipher;
    mbedtls_md_type_t mac;
    mbedtls_key_exchange_type_t key_exchange;

    int min_major_ver;
    int min_minor_ver;
    int max_major_ver;
    int max_minor_ver;

    ubyte flags;
}

const(int)* mbedtls_ssl_list_ciphersuites ();

const(mbedtls_ssl_ciphersuite_t)* mbedtls_ssl_ciphersuite_from_string (const(char)* ciphersuite_name);
const(mbedtls_ssl_ciphersuite_t)* mbedtls_ssl_ciphersuite_from_id (int ciphersuite_id);

mbedtls_pk_type_t mbedtls_ssl_get_ciphersuite_sig_pk_alg (const(mbedtls_ssl_ciphersuite_t)* info);
mbedtls_pk_type_t mbedtls_ssl_get_ciphersuite_sig_alg (const(mbedtls_ssl_ciphersuite_t)* info);

int mbedtls_ssl_ciphersuite_uses_ec (const(mbedtls_ssl_ciphersuite_t)* info);
int mbedtls_ssl_ciphersuite_uses_psk (const(mbedtls_ssl_ciphersuite_t)* info);

pragma(inline, true) extern(D)
{
  int mbedtls_ssl_ciphersuite_has_pfs (const(mbedtls_ssl_ciphersuite_t)* info)
  {
    switch (info.key_exchange) with (mbedtls_key_exchange_type_t) {
        case MBEDTLS_KEY_EXCHANGE_DHE_RSA:
        case MBEDTLS_KEY_EXCHANGE_DHE_PSK:
        case MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
        case MBEDTLS_KEY_EXCHANGE_ECDHE_PSK:
        case MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
        case MBEDTLS_KEY_EXCHANGE_ECJPAKE:
            return 1;

        default:
            return 0;
    }
  }
  /* MBEDTLS_KEY_EXCHANGE_SOME_PFS_ENABLED */

  int mbedtls_ssl_ciphersuite_no_pfs (const(mbedtls_ssl_ciphersuite_t)* info)
  {
      switch (info.key_exchange) with (mbedtls_key_exchange_type_t) {
          case MBEDTLS_KEY_EXCHANGE_ECDH_RSA:
          case MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA:
          case MBEDTLS_KEY_EXCHANGE_RSA:
          case MBEDTLS_KEY_EXCHANGE_PSK:
          case MBEDTLS_KEY_EXCHANGE_RSA_PSK:
              return 1;

          default:
              return 0;
      }
  }
  /* MBEDTLS_KEY_EXCHANGE_SOME_NON_PFS_ENABLED */

  int mbedtls_ssl_ciphersuite_uses_ecdh (const(mbedtls_ssl_ciphersuite_t)* info)
  {
      switch (info.key_exchange) with (mbedtls_key_exchange_type_t) {
          case MBEDTLS_KEY_EXCHANGE_ECDH_RSA:
          case MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA:
              return 1;

          default:
              return 0;
      }
  }
  /* MBEDTLS_KEY_EXCHANGE_SOME_ECDH_ENABLED */

  int mbedtls_ssl_ciphersuite_cert_req_allowed (
      const(mbedtls_ssl_ciphersuite_t)* info)
  {
      switch (info.key_exchange) with (mbedtls_key_exchange_type_t) {
          case MBEDTLS_KEY_EXCHANGE_RSA:
          case MBEDTLS_KEY_EXCHANGE_DHE_RSA:
          case MBEDTLS_KEY_EXCHANGE_ECDH_RSA:
          case MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
          case MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA:
          case MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
              return 1;

          default:
              return 0;
      }
  }

  int mbedtls_ssl_ciphersuite_uses_srv_cert (
      const(mbedtls_ssl_ciphersuite_t)* info)
  {
      switch (info.key_exchange) with (mbedtls_key_exchange_type_t) {
          case MBEDTLS_KEY_EXCHANGE_RSA:
          case MBEDTLS_KEY_EXCHANGE_RSA_PSK:
          case MBEDTLS_KEY_EXCHANGE_DHE_RSA:
          case MBEDTLS_KEY_EXCHANGE_ECDH_RSA:
          case MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
          case MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA:
          case MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
              return 1;

          default:
              return 0;
      }
  }

  int mbedtls_ssl_ciphersuite_uses_dhe (const(mbedtls_ssl_ciphersuite_t)* info)
  {
      switch (info.key_exchange) with (mbedtls_key_exchange_type_t) {
          case MBEDTLS_KEY_EXCHANGE_DHE_RSA:
          case MBEDTLS_KEY_EXCHANGE_DHE_PSK:
              return 1;

          default:
              return 0;
      }
  }
  /* MBEDTLS_KEY_EXCHANGE_SOME_DHE_ENABLED) */

  int mbedtls_ssl_ciphersuite_uses_ecdhe (const(mbedtls_ssl_ciphersuite_t)* info)
  {
      switch (info.key_exchange) with (mbedtls_key_exchange_type_t) {
          case MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
          case MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
          case MBEDTLS_KEY_EXCHANGE_ECDHE_PSK:
              return 1;

          default:
              return 0;
      }
  }
  /* MBEDTLS_KEY_EXCHANGE_SOME_ECDHE_ENABLED) */

  int mbedtls_ssl_ciphersuite_uses_server_signature (
      const(mbedtls_ssl_ciphersuite_t)* info)
  {
      switch (info.key_exchange) with (mbedtls_key_exchange_type_t) {
          case MBEDTLS_KEY_EXCHANGE_DHE_RSA:
          case MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
          case MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
              return 1;

          default:
              return 0;
      }
  }
}
/* MBEDTLS_KEY_EXCHANGE_WITH_SERVER_SIGNATURE_ENABLED */

/* ssl_ciphersuites.h */
