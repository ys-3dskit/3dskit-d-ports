/**
 * \file certs.h
 *
 * \brief Sample certificates and DHM parameters for testing
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

extern (C) @nogc nothrow:

/* List of all PEM-encoded CA certificates, terminated by NULL;
 * PEM encoded if MBEDTLS_PEM_PARSE_C is enabled, DER encoded
 * otherwise. */
extern __gshared const(char)*[] mbedtls_test_cas;
extern __gshared const(size_t)[] mbedtls_test_cas_len;

/* List of all DER-encoded CA certificates, terminated by NULL */
extern __gshared const(ubyte)*[] mbedtls_test_cas_der;
extern __gshared const(size_t)[] mbedtls_test_cas_der_len;

/* Concatenation of all CA certificates in PEM format if available */
extern __gshared const(char)[] mbedtls_test_cas_pem;
extern __gshared const size_t mbedtls_test_cas_pem_len;
/* MBEDTLS_PEM_PARSE_C */

/*
 * CA test certificates
 */

extern __gshared const(char)[] mbedtls_test_ca_crt_ec_pem;
extern __gshared const(char)[] mbedtls_test_ca_key_ec_pem;
extern __gshared const(char)[] mbedtls_test_ca_pwd_ec_pem;
extern __gshared const(char)[] mbedtls_test_ca_key_rsa_pem;
extern __gshared const(char)[] mbedtls_test_ca_pwd_rsa_pem;
extern __gshared const(char)[] mbedtls_test_ca_crt_rsa_sha1_pem;
extern __gshared const(char)[] mbedtls_test_ca_crt_rsa_sha256_pem;

extern __gshared const(ubyte)[] mbedtls_test_ca_crt_ec_der;
extern __gshared const(ubyte)[] mbedtls_test_ca_key_ec_der;
extern __gshared const(ubyte)[] mbedtls_test_ca_key_rsa_der;
extern __gshared const(ubyte)[] mbedtls_test_ca_crt_rsa_sha1_der;
extern __gshared const(ubyte)[] mbedtls_test_ca_crt_rsa_sha256_der;

extern __gshared const size_t mbedtls_test_ca_crt_ec_pem_len;
extern __gshared const size_t mbedtls_test_ca_key_ec_pem_len;
extern __gshared const size_t mbedtls_test_ca_pwd_ec_pem_len;
extern __gshared const size_t mbedtls_test_ca_key_rsa_pem_len;
extern __gshared const size_t mbedtls_test_ca_pwd_rsa_pem_len;
extern __gshared const size_t mbedtls_test_ca_crt_rsa_sha1_pem_len;
extern __gshared const size_t mbedtls_test_ca_crt_rsa_sha256_pem_len;

extern __gshared const size_t mbedtls_test_ca_crt_ec_der_len;
extern __gshared const size_t mbedtls_test_ca_key_ec_der_len;
extern __gshared const size_t mbedtls_test_ca_pwd_ec_der_len;
extern __gshared const size_t mbedtls_test_ca_key_rsa_der_len;
extern __gshared const size_t mbedtls_test_ca_pwd_rsa_der_len;
extern __gshared const size_t mbedtls_test_ca_crt_rsa_sha1_der_len;
extern __gshared const size_t mbedtls_test_ca_crt_rsa_sha256_der_len;

/* Config-dependent dispatch between PEM and DER encoding
 * (PEM if enabled, otherwise DER) */

extern __gshared const(char)[] mbedtls_test_ca_crt_ec;
extern __gshared const(char)[] mbedtls_test_ca_key_ec;
extern __gshared const(char)[] mbedtls_test_ca_pwd_ec;
extern __gshared const(char)[] mbedtls_test_ca_key_rsa;
extern __gshared const(char)[] mbedtls_test_ca_pwd_rsa;
extern __gshared const(char)[] mbedtls_test_ca_crt_rsa_sha1;
extern __gshared const(char)[] mbedtls_test_ca_crt_rsa_sha256;

extern __gshared const size_t mbedtls_test_ca_crt_ec_len;
extern __gshared const size_t mbedtls_test_ca_key_ec_len;
extern __gshared const size_t mbedtls_test_ca_pwd_ec_len;
extern __gshared const size_t mbedtls_test_ca_key_rsa_len;
extern __gshared const size_t mbedtls_test_ca_pwd_rsa_len;
extern __gshared const size_t mbedtls_test_ca_crt_rsa_sha1_len;
extern __gshared const size_t mbedtls_test_ca_crt_rsa_sha256_len;

/* Config-dependent dispatch between SHA-1 and SHA-256
 * (SHA-256 if enabled, otherwise SHA-1) */

extern __gshared const(char)[] mbedtls_test_ca_crt_rsa;
extern __gshared const size_t mbedtls_test_ca_crt_rsa_len;

/* Config-dependent dispatch between EC and RSA
 * (RSA if enabled, otherwise EC) */

extern __gshared const(char)* mbedtls_test_ca_crt;
extern __gshared const(char)* mbedtls_test_ca_key;
extern __gshared const(char)* mbedtls_test_ca_pwd;
extern __gshared const size_t mbedtls_test_ca_crt_len;
extern __gshared const size_t mbedtls_test_ca_key_len;
extern __gshared const size_t mbedtls_test_ca_pwd_len;

/*
 * Server test certificates
 */

extern __gshared const(char)[] mbedtls_test_srv_crt_ec_pem;
extern __gshared const(char)[] mbedtls_test_srv_key_ec_pem;
extern __gshared const(char)[] mbedtls_test_srv_pwd_ec_pem;
extern __gshared const(char)[] mbedtls_test_srv_key_rsa_pem;
extern __gshared const(char)[] mbedtls_test_srv_pwd_rsa_pem;
extern __gshared const(char)[] mbedtls_test_srv_crt_rsa_sha1_pem;
extern __gshared const(char)[] mbedtls_test_srv_crt_rsa_sha256_pem;

extern __gshared const(ubyte)[] mbedtls_test_srv_crt_ec_der;
extern __gshared const(ubyte)[] mbedtls_test_srv_key_ec_der;
extern __gshared const(ubyte)[] mbedtls_test_srv_key_rsa_der;
extern __gshared const(ubyte)[] mbedtls_test_srv_crt_rsa_sha1_der;
extern __gshared const(ubyte)[] mbedtls_test_srv_crt_rsa_sha256_der;

extern __gshared const size_t mbedtls_test_srv_crt_ec_pem_len;
extern __gshared const size_t mbedtls_test_srv_key_ec_pem_len;
extern __gshared const size_t mbedtls_test_srv_pwd_ec_pem_len;
extern __gshared const size_t mbedtls_test_srv_key_rsa_pem_len;
extern __gshared const size_t mbedtls_test_srv_pwd_rsa_pem_len;
extern __gshared const size_t mbedtls_test_srv_crt_rsa_sha1_pem_len;
extern __gshared const size_t mbedtls_test_srv_crt_rsa_sha256_pem_len;

extern __gshared const size_t mbedtls_test_srv_crt_ec_der_len;
extern __gshared const size_t mbedtls_test_srv_key_ec_der_len;
extern __gshared const size_t mbedtls_test_srv_pwd_ec_der_len;
extern __gshared const size_t mbedtls_test_srv_key_rsa_der_len;
extern __gshared const size_t mbedtls_test_srv_pwd_rsa_der_len;
extern __gshared const size_t mbedtls_test_srv_crt_rsa_sha1_der_len;
extern __gshared const size_t mbedtls_test_srv_crt_rsa_sha256_der_len;

/* Config-dependent dispatch between PEM and DER encoding
 * (PEM if enabled, otherwise DER) */

extern __gshared const(char)[] mbedtls_test_srv_crt_ec;
extern __gshared const(char)[] mbedtls_test_srv_key_ec;
extern __gshared const(char)[] mbedtls_test_srv_pwd_ec;
extern __gshared const(char)[] mbedtls_test_srv_key_rsa;
extern __gshared const(char)[] mbedtls_test_srv_pwd_rsa;
extern __gshared const(char)[] mbedtls_test_srv_crt_rsa_sha1;
extern __gshared const(char)[] mbedtls_test_srv_crt_rsa_sha256;

extern __gshared const size_t mbedtls_test_srv_crt_ec_len;
extern __gshared const size_t mbedtls_test_srv_key_ec_len;
extern __gshared const size_t mbedtls_test_srv_pwd_ec_len;
extern __gshared const size_t mbedtls_test_srv_key_rsa_len;
extern __gshared const size_t mbedtls_test_srv_pwd_rsa_len;
extern __gshared const size_t mbedtls_test_srv_crt_rsa_sha1_len;
extern __gshared const size_t mbedtls_test_srv_crt_rsa_sha256_len;

/* Config-dependent dispatch between SHA-1 and SHA-256
 * (SHA-256 if enabled, otherwise SHA-1) */

extern __gshared const(char)[] mbedtls_test_srv_crt_rsa;
extern __gshared const size_t mbedtls_test_srv_crt_rsa_len;

/* Config-dependent dispatch between EC and RSA
 * (RSA if enabled, otherwise EC) */

extern __gshared const(char)* mbedtls_test_srv_crt;
extern __gshared const(char)* mbedtls_test_srv_key;
extern __gshared const(char)* mbedtls_test_srv_pwd;
extern __gshared const size_t mbedtls_test_srv_crt_len;
extern __gshared const size_t mbedtls_test_srv_key_len;
extern __gshared const size_t mbedtls_test_srv_pwd_len;

/*
 * Client test certificates
 */

extern __gshared const(char)[] mbedtls_test_cli_crt_ec_pem;
extern __gshared const(char)[] mbedtls_test_cli_key_ec_pem;
extern __gshared const(char)[] mbedtls_test_cli_pwd_ec_pem;
extern __gshared const(char)[] mbedtls_test_cli_key_rsa_pem;
extern __gshared const(char)[] mbedtls_test_cli_pwd_rsa_pem;
extern __gshared const(char)[] mbedtls_test_cli_crt_rsa_pem;

extern __gshared const(ubyte)[] mbedtls_test_cli_crt_ec_der;
extern __gshared const(ubyte)[] mbedtls_test_cli_key_ec_der;
extern __gshared const(ubyte)[] mbedtls_test_cli_key_rsa_der;
extern __gshared const(ubyte)[] mbedtls_test_cli_crt_rsa_der;

extern __gshared const size_t mbedtls_test_cli_crt_ec_pem_len;
extern __gshared const size_t mbedtls_test_cli_key_ec_pem_len;
extern __gshared const size_t mbedtls_test_cli_pwd_ec_pem_len;
extern __gshared const size_t mbedtls_test_cli_key_rsa_pem_len;
extern __gshared const size_t mbedtls_test_cli_pwd_rsa_pem_len;
extern __gshared const size_t mbedtls_test_cli_crt_rsa_pem_len;

extern __gshared const size_t mbedtls_test_cli_crt_ec_der_len;
extern __gshared const size_t mbedtls_test_cli_key_ec_der_len;
extern __gshared const size_t mbedtls_test_cli_key_rsa_der_len;
extern __gshared const size_t mbedtls_test_cli_crt_rsa_der_len;

/* Config-dependent dispatch between PEM and DER encoding
 * (PEM if enabled, otherwise DER) */

extern __gshared const(char)[] mbedtls_test_cli_crt_ec;
extern __gshared const(char)[] mbedtls_test_cli_key_ec;
extern __gshared const(char)[] mbedtls_test_cli_pwd_ec;
extern __gshared const(char)[] mbedtls_test_cli_key_rsa;
extern __gshared const(char)[] mbedtls_test_cli_pwd_rsa;
extern __gshared const(char)[] mbedtls_test_cli_crt_rsa;

extern __gshared const size_t mbedtls_test_cli_crt_ec_len;
extern __gshared const size_t mbedtls_test_cli_key_ec_len;
extern __gshared const size_t mbedtls_test_cli_pwd_ec_len;
extern __gshared const size_t mbedtls_test_cli_key_rsa_len;
extern __gshared const size_t mbedtls_test_cli_pwd_rsa_len;
extern __gshared const size_t mbedtls_test_cli_crt_rsa_len;

/* Config-dependent dispatch between EC and RSA
 * (RSA if enabled, otherwise EC) */

extern __gshared const(char)* mbedtls_test_cli_crt;
extern __gshared const(char)* mbedtls_test_cli_key;
extern __gshared const(char)* mbedtls_test_cli_pwd;
extern __gshared const size_t mbedtls_test_cli_crt_len;
extern __gshared const size_t mbedtls_test_cli_key_len;
extern __gshared const size_t mbedtls_test_cli_pwd_len;

/* certs.h */
