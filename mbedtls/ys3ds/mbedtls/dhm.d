/**
 * \file dhm.h
 *
 * \brief   This file contains Diffie-Hellman-Merkle (DHM) key exchange
 *          definitions and functions.
 *
 * Diffie-Hellman-Merkle (DHM) key exchange is defined in
 * <em>RFC-2631: Diffie-Hellman Key Agreement Method</em> and
 * <em>Public-Key Cryptography Standards (PKCS) #3: Diffie
 * Hellman Key Agreement Standard</em>.
 *
 * <em>RFC-3526: More Modular Exponential (MODP) Diffie-Hellman groups for
 * Internet Key Exchange (IKE)</em> defines a number of standardized
 * Diffie-Hellman groups for IKE.
 *
 * <em>RFC-5114: Additional Diffie-Hellman Groups for Use with IETF
 * Standards</em> defines a number of standardized Diffie-Hellman
 * groups that can be used.
 *
 * \warning  The security of the DHM key exchange relies on the proper choice
 *           of prime modulus - optimally, it should be a safe prime. The usage
 *           of non-safe primes both decreases the difficulty of the underlying
 *           discrete logarithm problem and can lead to small subgroup attacks
 *           leaking private exponent bits when invalid public keys are used
 *           and not detected. This is especially relevant if the same DHM
 *           parameters are reused for multiple key exchanges as in static DHM,
 *           while the criticality of small-subgroup attacks is lower for
 *           ephemeral DHM.
 *
 * \warning  For performance reasons, the code does neither perform primality
 *           nor safe primality tests, nor the expensive checks for invalid
 *           subgroups. Moreover, even if these were performed, non-standardized
 *           primes cannot be trusted because of the possibility of backdoors
 *           that can't be effectively checked for.
 *
 * \warning  Diffie-Hellman-Merkle is therefore a security risk when not using
 *           standardized primes generated using a trustworthy ("nothing up
 *           my sleeve") method, such as the RFC 3526 / 7919 primes. In the TLS
 *           protocol, DH parameters need to be negotiated, so using the default
 *           primes systematically is not always an option. If possible, use
 *           Elliptic Curve Diffie-Hellman (ECDH), which has better performance,
 *           and for which the TLS protocol mandates the use of standard
 *           parameters.
 *
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

import ys3ds.mbedtls.bignum;
import ys3ds.mbedtls.platform_util;

extern (C):

/*
 * DHM Error codes
 */
/** Bad input parameters. */
enum MBEDTLS_ERR_DHM_BAD_INPUT_DATA = -0x3080;
/** Reading of the DHM parameters failed. */
enum MBEDTLS_ERR_DHM_READ_PARAMS_FAILED = -0x3100;
/** Making of the DHM parameters failed. */
enum MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED = -0x3180;
/** Reading of the public values failed. */
enum MBEDTLS_ERR_DHM_READ_PUBLIC_FAILED = -0x3200;
/** Making of the public value failed. */
enum MBEDTLS_ERR_DHM_MAKE_PUBLIC_FAILED = -0x3280;
/** Calculation of the DHM secret failed. */
enum MBEDTLS_ERR_DHM_CALC_SECRET_FAILED = -0x3300;
/** The ASN.1 data is not formatted correctly. */
enum MBEDTLS_ERR_DHM_INVALID_FORMAT = -0x3380;
/** Allocation of memory failed. */
enum MBEDTLS_ERR_DHM_ALLOC_FAILED = -0x3400;
/** Read or write of file failed. */
enum MBEDTLS_ERR_DHM_FILE_IO_ERROR = -0x3480;

/* MBEDTLS_ERR_DHM_HW_ACCEL_FAILED is deprecated and should not be used. */
/** DHM hardware accelerator failed. */
enum MBEDTLS_ERR_DHM_HW_ACCEL_FAILED = -0x3500;

/** Setting the modulus and generator failed. */
enum MBEDTLS_ERR_DHM_SET_GROUP_FAILED = -0x3580;

/**
 * \brief          The DHM context structure.
 */
struct mbedtls_dhm_context
{
    size_t len; /*!<  The size of \p P in Bytes. */
    mbedtls_mpi P; /*!<  The prime modulus. */
    mbedtls_mpi G; /*!<  The generator. */
    mbedtls_mpi X; /*!<  Our secret value. */
    mbedtls_mpi GX; /*!<  Our public key = \c G^X mod \c P. */
    mbedtls_mpi GY; /*!<  The public key of the peer = \c G^Y mod \c P. */
    mbedtls_mpi K; /*!<  The shared secret = \c G^(XY) mod \c P. */
    mbedtls_mpi RP; /*!<  The cached value = \c R^2 mod \c P. */
    mbedtls_mpi Vi; /*!<  The blinding value. */
    mbedtls_mpi Vf; /*!<  The unblinding value. */
    mbedtls_mpi pX; /*!<  The previous \c X. */
}

/* MBEDTLS_DHM_ALT */

/* MBEDTLS_DHM_ALT */

/**
 * \brief          This function initializes the DHM context.
 *
 * \param ctx      The DHM context to initialize.
 */
void mbedtls_dhm_init (mbedtls_dhm_context* ctx);

/**
 * \brief          This function parses the DHM parameters in a
 *                 TLS ServerKeyExchange handshake message
 *                 (DHM modulus, generator, and public key).
 *
 * \note           In a TLS handshake, this is the how the client
 *                 sets up its DHM context from the server's public
 *                 DHM key material.
 *
 * \param ctx      The DHM context to use. This must be initialized.
 * \param p        On input, *p must be the start of the input buffer.
 *                 On output, *p is updated to point to the end of the data
 *                 that has been read. On success, this is the first byte
 *                 past the end of the ServerKeyExchange parameters.
 *                 On error, this is the point at which an error has been
 *                 detected, which is usually not useful except to debug
 *                 failures.
 * \param end      The end of the input buffer.
 *
 * \return         \c 0 on success.
 * \return         An \c MBEDTLS_ERR_DHM_XXX error code on failure.
 */
int mbedtls_dhm_read_params (
    mbedtls_dhm_context* ctx,
    ubyte** p,
    const(ubyte)* end);

/**
 * \brief          This function generates a DHM key pair and exports its
 *                 public part together with the DHM parameters in the format
 *                 used in a TLS ServerKeyExchange handshake message.
 *
 * \note           This function assumes that the DHM parameters \c ctx->P
 *                 and \c ctx->G have already been properly set. For that, use
 *                 mbedtls_dhm_set_group() below in conjunction with
 *                 mbedtls_mpi_read_binary() and mbedtls_mpi_read_string().
 *
 * \note           In a TLS handshake, this is the how the server generates
 *                 and exports its DHM key material.
 *
 * \param ctx      The DHM context to use. This must be initialized
 *                 and have the DHM parameters set. It may or may not
 *                 already have imported the peer's public key.
 * \param x_size   The private key size in Bytes.
 * \param olen     The address at which to store the number of Bytes
 *                 written on success. This must not be \c NULL.
 * \param output   The destination buffer. This must be a writable buffer of
 *                 sufficient size to hold the reduced binary presentation of
 *                 the modulus, the generator and the public key, each wrapped
 *                 with a 2-byte length field. It is the responsibility of the
 *                 caller to ensure that enough space is available. Refer to
 *                 mbedtls_mpi_size() to computing the byte-size of an MPI.
 * \param f_rng    The RNG function. Must not be \c NULL.
 * \param p_rng    The RNG context to be passed to \p f_rng. This may be
 *                 \c NULL if \p f_rng doesn't need a context parameter.
 *
 * \return         \c 0 on success.
 * \return         An \c MBEDTLS_ERR_DHM_XXX error code on failure.
 */
int mbedtls_dhm_make_params (
    mbedtls_dhm_context* ctx,
    int x_size,
    ubyte* output,
    size_t* olen,
    int function (void*, ubyte*, size_t) f_rng,
    void* p_rng);

/**
 * \brief          This function sets the prime modulus and generator.
 *
 * \note           This function can be used to set \c ctx->P, \c ctx->G
 *                 in preparation for mbedtls_dhm_make_params().
 *
 * \param ctx      The DHM context to configure. This must be initialized.
 * \param P        The MPI holding the DHM prime modulus. This must be
 *                 an initialized MPI.
 * \param G        The MPI holding the DHM generator. This must be an
 *                 initialized MPI.
 *
 * \return         \c 0 if successful.
 * \return         An \c MBEDTLS_ERR_DHM_XXX error code on failure.
 */
int mbedtls_dhm_set_group (
    mbedtls_dhm_context* ctx,
    const(mbedtls_mpi)* P,
    const(mbedtls_mpi)* G);

/**
 * \brief          This function imports the raw public value of the peer.
 *
 * \note           In a TLS handshake, this is the how the server imports
 *                 the Client's public DHM key.
 *
 * \param ctx      The DHM context to use. This must be initialized and have
 *                 its DHM parameters set, e.g. via mbedtls_dhm_set_group().
 *                 It may or may not already have generated its own private key.
 * \param input    The input buffer containing the \c G^Y value of the peer.
 *                 This must be a readable buffer of size \p ilen Bytes.
 * \param ilen     The size of the input buffer \p input in Bytes.
 *
 * \return         \c 0 on success.
 * \return         An \c MBEDTLS_ERR_DHM_XXX error code on failure.
 */
int mbedtls_dhm_read_public (
    mbedtls_dhm_context* ctx,
    const(ubyte)* input,
    size_t ilen);

/**
 * \brief          This function creates a DHM key pair and exports
 *                 the raw public key in big-endian format.
 *
 * \note           The destination buffer is always fully written
 *                 so as to contain a big-endian representation of G^X mod P.
 *                 If it is larger than \c ctx->len, it is padded accordingly
 *                 with zero-bytes at the beginning.
 *
 * \param ctx      The DHM context to use. This must be initialized and
 *                 have the DHM parameters set. It may or may not already
 *                 have imported the peer's public key.
 * \param x_size   The private key size in Bytes.
 * \param output   The destination buffer. This must be a writable buffer of
 *                 size \p olen Bytes.
 * \param olen     The length of the destination buffer. This must be at least
 *                 equal to `ctx->len` (the size of \c P).
 * \param f_rng    The RNG function. This must not be \c NULL.
 * \param p_rng    The RNG context to be passed to \p f_rng. This may be \c NULL
 *                 if \p f_rng doesn't need a context argument.
 *
 * \return         \c 0 on success.
 * \return         An \c MBEDTLS_ERR_DHM_XXX error code on failure.
 */
int mbedtls_dhm_make_public (
    mbedtls_dhm_context* ctx,
    int x_size,
    ubyte* output,
    size_t olen,
    int function (void*, ubyte*, size_t) f_rng,
    void* p_rng);

/**
 * \brief          This function derives and exports the shared secret
 *                 \c (G^Y)^X mod \c P.
 *
 * \note           If \p f_rng is not \c NULL, it is used to blind the input as
 *                 a countermeasure against timing attacks. Blinding is used
 *                 only if our private key \c X is re-used, and not used
 *                 otherwise. We recommend always passing a non-NULL
 *                 \p f_rng argument.
 *
 * \param ctx           The DHM context to use. This must be initialized
 *                      and have its own private key generated and the peer's
 *                      public key imported.
 * \param output        The buffer to write the generated shared key to. This
 *                      must be a writable buffer of size \p output_size Bytes.
 * \param output_size   The size of the destination buffer. This must be at
 *                      least the size of \c ctx->len (the size of \c P).
 * \param olen          On exit, holds the actual number of Bytes written.
 * \param f_rng         The RNG function, for blinding purposes. This may
 *                      b \c NULL if blinding isn't needed.
 * \param p_rng         The RNG context. This may be \c NULL if \p f_rng
 *                      doesn't need a context argument.
 *
 * \return              \c 0 on success.
 * \return              An \c MBEDTLS_ERR_DHM_XXX error code on failure.
 */
int mbedtls_dhm_calc_secret (
    mbedtls_dhm_context* ctx,
    ubyte* output,
    size_t output_size,
    size_t* olen,
    int function (void*, ubyte*, size_t) f_rng,
    void* p_rng);

/**
 * \brief          This function frees and clears the components
 *                 of a DHM context.
 *
 * \param ctx      The DHM context to free and clear. This may be \c NULL,
 *                 in which case this function is a no-op. If it is not \c NULL,
 *                 it must point to an initialized DHM context.
 */
void mbedtls_dhm_free (mbedtls_dhm_context* ctx);

/**
 * \brief             This function parses DHM parameters in PEM or DER format.
 *
 * \param dhm         The DHM context to import the DHM parameters into.
 *                    This must be initialized.
 * \param dhmin       The input buffer. This must be a readable buffer of
 *                    length \p dhminlen Bytes.
 * \param dhminlen    The size of the input buffer \p dhmin, including the
 *                    terminating \c NULL Byte for PEM data.
 *
 * \return            \c 0 on success.
 * \return            An \c MBEDTLS_ERR_DHM_XXX or \c MBEDTLS_ERR_PEM_XXX error
 *                    code on failure.
 */
int mbedtls_dhm_parse_dhm (
    mbedtls_dhm_context* dhm,
    const(ubyte)* dhmin,
    size_t dhminlen);

/**
 * \brief          This function loads and parses DHM parameters from a file.
 *
 * \param dhm      The DHM context to load the parameters to.
 *                 This must be initialized.
 * \param path     The filename to read the DHM parameters from.
 *                 This must not be \c NULL.
 *
 * \return         \c 0 on success.
 * \return         An \c MBEDTLS_ERR_DHM_XXX or \c MBEDTLS_ERR_PEM_XXX
 *                 error code on failure.
 */
int mbedtls_dhm_parse_dhmfile (mbedtls_dhm_context* dhm, const(char)* path);
/* MBEDTLS_FS_IO */
/* MBEDTLS_ASN1_PARSE_C */

/**
 * \brief          The DMH checkup routine.
 *
 * \return         \c 0 on success.
 * \return         \c 1 on failure.
 */

/* MBEDTLS_SELF_TEST */

/**
 * RFC 3526, RFC 5114 and RFC 7919 standardize a number of
 * Diffie-Hellman groups, some of which are included here
 * for use within the SSL/TLS module and the user's convenience
 * when configuring the Diffie-Hellman parameters by hand
 * through \c mbedtls_ssl_conf_dh_param.
 *
 * The following lists the source of the above groups in the standards:
 * - RFC 5114 section 2.2:  2048-bit MODP Group with 224-bit Prime Order Subgroup
 * - RFC 3526 section 3:    2048-bit MODP Group
 * - RFC 3526 section 4:    3072-bit MODP Group
 * - RFC 3526 section 5:    4096-bit MODP Group
 * - RFC 7919 section A.1:  ffdhe2048
 * - RFC 7919 section A.2:  ffdhe3072
 * - RFC 7919 section A.3:  ffdhe4096
 * - RFC 7919 section A.4:  ffdhe6144
 * - RFC 7919 section A.5:  ffdhe8192
 *
 * The constants with suffix "_p" denote the chosen prime moduli, while
 * the constants with suffix "_g" denote the chosen generator
 * of the associated prime field.
 *
 * The constants further suffixed with "_bin" are provided in binary format,
 * while all other constants represent null-terminated strings holding the
 * hexadecimal presentation of the respective numbers.
 *
 * The primes from RFC 3526 and RFC 7919 have been generating by the following
 * trust-worthy procedure:
 * - Fix N in { 2048, 3072, 4096, 6144, 8192 } and consider the N-bit number
 *   the first and last 64 bits are all 1, and the remaining N - 128 bits of
 *   which are 0x7ff...ff.
 * - Add the smallest multiple of the first N - 129 bits of the binary expansion
 *   of pi (for RFC 5236) or e (for RFC 7919) to this intermediate bit-string
 *   such that the resulting integer is a safe-prime.
 * - The result is the respective RFC 3526 / 7919 prime, and the corresponding
 *   generator is always chosen to be 2 (which is a square for these prime,
 *   hence the corresponding subgroup has order (p-1)/2 and avoids leaking a
 *   bit in the private exponent).
 *
 */

/**
 * \warning The origin of the primes in RFC 5114 is not documented and
 *          their use therefore constitutes a security risk!
 *
 * \deprecated The hex-encoded primes from RFC 5114 are deprecated and are
 *             likely to be removed in a future version of the library without
 *             replacement.
 */

/**
 * The hexadecimal presentation of the prime underlying the
 * 2048-bit MODP Group with 224-bit Prime Order Subgroup, as defined
 * in <em>RFC-5114: Additional Diffie-Hellman Groups for Use with
 * IETF Standards</em>.
 */
enum MBEDTLS_DHM_RFC5114_MODP_2048_P = MBEDTLS_DEPRECATED_STRING_CONSTANT("AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1" ~ "B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15" ~ "EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC212" ~ "9037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207" ~ "C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708" ~ "B3BF8A317091883681286130BC8985DB1602E714415D9330" ~ "278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486D" ~ "CDF93ACC44328387315D75E198C641A480CD86A1B9E587E8" ~ "BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763" ~ "C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71" ~ "CF9DE5384E71B81C0AC4DFFE0C10E64F");

/**
 * The hexadecimal presentation of the chosen generator of the 2048-bit MODP
 * Group with 224-bit Prime Order Subgroup, as defined in <em>RFC-5114:
 * Additional Diffie-Hellman Groups for Use with IETF Standards</em>.
 */
enum MBEDTLS_DHM_RFC5114_MODP_2048_G = MBEDTLS_DEPRECATED_STRING_CONSTANT("AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF" ~ "74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFA" ~ "AB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7" ~ "C17669101999024AF4D027275AC1348BB8A762D0521BC98A" ~ "E247150422EA1ED409939D54DA7460CDB5F6C6B250717CBE" ~ "F180EB34118E98D119529A45D6F834566E3025E316A330EF" ~ "BB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB" ~ "10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381" ~ "B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269" ~ "EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC0179" ~ "81BC087F2A7065B384B890D3191F2BFA");

/**
 * The hexadecimal presentation of the prime underlying the 2048-bit MODP
 * Group, as defined in <em>RFC-3526: More Modular Exponential (MODP)
 * Diffie-Hellman groups for Internet Key Exchange (IKE)</em>.
 *
 * \deprecated The hex-encoded primes from RFC 3625 are deprecated and
 *             superseded by the corresponding macros providing them as
 *             binary constants. Their hex-encoded constants are likely
 *             to be removed in a future version of the library.
 *
 */
enum MBEDTLS_DHM_RFC3526_MODP_2048_P = MBEDTLS_DEPRECATED_STRING_CONSTANT("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" ~ "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" ~ "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" ~ "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" ~ "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" ~ "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" ~ "83655D23DCA3AD961C62F356208552BB9ED529077096966D" ~ "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" ~ "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" ~ "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" ~ "15728E5A8AACAA68FFFFFFFFFFFFFFFF");

/**
 * The hexadecimal presentation of the chosen generator of the 2048-bit MODP
 * Group, as defined in <em>RFC-3526: More Modular Exponential (MODP)
 * Diffie-Hellman groups for Internet Key Exchange (IKE)</em>.
 */
enum MBEDTLS_DHM_RFC3526_MODP_2048_G = MBEDTLS_DEPRECATED_STRING_CONSTANT("02");

/**
 * The hexadecimal presentation of the prime underlying the 3072-bit MODP
 * Group, as defined in <em>RFC-3072: More Modular Exponential (MODP)
 * Diffie-Hellman groups for Internet Key Exchange (IKE)</em>.
 */
enum MBEDTLS_DHM_RFC3526_MODP_3072_P = MBEDTLS_DEPRECATED_STRING_CONSTANT("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" ~ "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" ~ "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" ~ "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" ~ "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" ~ "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" ~ "83655D23DCA3AD961C62F356208552BB9ED529077096966D" ~ "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" ~ "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" ~ "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" ~ "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" ~ "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" ~ "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" ~ "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" ~ "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" ~ "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF");

/**
 * The hexadecimal presentation of the chosen generator of the 3072-bit MODP
 * Group, as defined in <em>RFC-3526: More Modular Exponential (MODP)
 * Diffie-Hellman groups for Internet Key Exchange (IKE)</em>.
 */
enum MBEDTLS_DHM_RFC3526_MODP_3072_G = MBEDTLS_DEPRECATED_STRING_CONSTANT("02");

/**
 * The hexadecimal presentation of the prime underlying the 4096-bit MODP
 * Group, as defined in <em>RFC-3526: More Modular Exponential (MODP)
 * Diffie-Hellman groups for Internet Key Exchange (IKE)</em>.
 */
enum MBEDTLS_DHM_RFC3526_MODP_4096_P = MBEDTLS_DEPRECATED_STRING_CONSTANT("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" ~ "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" ~ "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" ~ "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" ~ "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" ~ "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" ~ "83655D23DCA3AD961C62F356208552BB9ED529077096966D" ~ "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" ~ "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" ~ "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" ~ "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" ~ "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" ~ "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" ~ "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" ~ "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" ~ "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7" ~ "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA" ~ "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6" ~ "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED" ~ "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9" ~ "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199" ~ "FFFFFFFFFFFFFFFF");

/**
 * The hexadecimal presentation of the chosen generator of the 4096-bit MODP
 * Group, as defined in <em>RFC-3526: More Modular Exponential (MODP)
 * Diffie-Hellman groups for Internet Key Exchange (IKE)</em>.
 */
enum MBEDTLS_DHM_RFC3526_MODP_4096_G = MBEDTLS_DEPRECATED_STRING_CONSTANT("02");

/* MBEDTLS_DEPRECATED_REMOVED */

/*
 * Trustworthy DHM parameters in binary form
 */

/* dhm.h */
