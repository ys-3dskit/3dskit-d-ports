/**
 * \file cipher.h
 *
 * \brief This file contains an abstraction interface for use with the cipher
 * primitives provided by the library. It provides a common interface to all of
 * the available cipher operations.
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 */

extern (C):

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/** The selected feature is not available. */
enum MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE = -0x6080;
/** Bad input parameters. */
enum MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA = -0x6100;
/** Failed to allocate memory. */
enum MBEDTLS_ERR_CIPHER_ALLOC_FAILED = -0x6180;
/** Input data contains invalid padding and is rejected. */
enum MBEDTLS_ERR_CIPHER_INVALID_PADDING = -0x6200;
/** Decryption of block requires a full block. */
enum MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED = -0x6280;
/** Authentication failed (for AEAD modes). */
enum MBEDTLS_ERR_CIPHER_AUTH_FAILED = -0x6300;
/** The context is invalid. For example, because it was freed. */
enum MBEDTLS_ERR_CIPHER_INVALID_CONTEXT = -0x6380;

/* MBEDTLS_ERR_CIPHER_HW_ACCEL_FAILED is deprecated and should not be used. */
/** Cipher hardware accelerator failed. */
enum MBEDTLS_ERR_CIPHER_HW_ACCEL_FAILED = -0x6400;

enum MBEDTLS_CIPHER_VARIABLE_IV_LEN = 0x01; /**< Cipher accepts IVs of variable length. */
enum MBEDTLS_CIPHER_VARIABLE_KEY_LEN = 0x02; /**< Cipher accepts keys of variable length. */

/**
 * \brief     Supported cipher types.
 *
 * \warning   RC4 and DES/3DES are considered weak ciphers and their use
 *            constitutes a security risk. We recommend considering stronger
 *            ciphers instead.
 */
enum mbedtls_cipher_id_t
{
    MBEDTLS_CIPHER_ID_NONE = 0, /**< Placeholder to mark the end of cipher ID lists. */
    MBEDTLS_CIPHER_ID_NULL = 1, /**< The identity cipher, treated as a stream cipher. */
    MBEDTLS_CIPHER_ID_AES = 2, /**< The AES cipher. */
    MBEDTLS_CIPHER_ID_DES = 3, /**< The DES cipher. \warning DES is considered weak. */
    MBEDTLS_CIPHER_ID_3DES = 4, /**< The Triple DES cipher. \warning 3DES is considered weak. */
    MBEDTLS_CIPHER_ID_CAMELLIA = 5, /**< The Camellia cipher. */
    MBEDTLS_CIPHER_ID_BLOWFISH = 6, /**< The Blowfish cipher. */
    MBEDTLS_CIPHER_ID_ARC4 = 7, /**< The RC4 cipher. */
    MBEDTLS_CIPHER_ID_ARIA = 8, /**< The Aria cipher. */
    MBEDTLS_CIPHER_ID_CHACHA20 = 9 /**< The ChaCha20 cipher. */
}

/**
 * \brief     Supported {cipher type, cipher mode} pairs.
 *
 * \warning   RC4 and DES/3DES are considered weak ciphers and their use
 *            constitutes a security risk. We recommend considering stronger
 *            ciphers instead.
 */
enum mbedtls_cipher_type_t
{
    MBEDTLS_CIPHER_NONE = 0, /**< Placeholder to mark the end of cipher-pair lists. */
    MBEDTLS_CIPHER_NULL = 1, /**< The identity stream cipher. */
    MBEDTLS_CIPHER_AES_128_ECB = 2, /**< AES cipher with 128-bit ECB mode. */
    MBEDTLS_CIPHER_AES_192_ECB = 3, /**< AES cipher with 192-bit ECB mode. */
    MBEDTLS_CIPHER_AES_256_ECB = 4, /**< AES cipher with 256-bit ECB mode. */
    MBEDTLS_CIPHER_AES_128_CBC = 5, /**< AES cipher with 128-bit CBC mode. */
    MBEDTLS_CIPHER_AES_192_CBC = 6, /**< AES cipher with 192-bit CBC mode. */
    MBEDTLS_CIPHER_AES_256_CBC = 7, /**< AES cipher with 256-bit CBC mode. */
    MBEDTLS_CIPHER_AES_128_CFB128 = 8, /**< AES cipher with 128-bit CFB128 mode. */
    MBEDTLS_CIPHER_AES_192_CFB128 = 9, /**< AES cipher with 192-bit CFB128 mode. */
    MBEDTLS_CIPHER_AES_256_CFB128 = 10, /**< AES cipher with 256-bit CFB128 mode. */
    MBEDTLS_CIPHER_AES_128_CTR = 11, /**< AES cipher with 128-bit CTR mode. */
    MBEDTLS_CIPHER_AES_192_CTR = 12, /**< AES cipher with 192-bit CTR mode. */
    MBEDTLS_CIPHER_AES_256_CTR = 13, /**< AES cipher with 256-bit CTR mode. */
    MBEDTLS_CIPHER_AES_128_GCM = 14, /**< AES cipher with 128-bit GCM mode. */
    MBEDTLS_CIPHER_AES_192_GCM = 15, /**< AES cipher with 192-bit GCM mode. */
    MBEDTLS_CIPHER_AES_256_GCM = 16, /**< AES cipher with 256-bit GCM mode. */
    MBEDTLS_CIPHER_CAMELLIA_128_ECB = 17, /**< Camellia cipher with 128-bit ECB mode. */
    MBEDTLS_CIPHER_CAMELLIA_192_ECB = 18, /**< Camellia cipher with 192-bit ECB mode. */
    MBEDTLS_CIPHER_CAMELLIA_256_ECB = 19, /**< Camellia cipher with 256-bit ECB mode. */
    MBEDTLS_CIPHER_CAMELLIA_128_CBC = 20, /**< Camellia cipher with 128-bit CBC mode. */
    MBEDTLS_CIPHER_CAMELLIA_192_CBC = 21, /**< Camellia cipher with 192-bit CBC mode. */
    MBEDTLS_CIPHER_CAMELLIA_256_CBC = 22, /**< Camellia cipher with 256-bit CBC mode. */
    MBEDTLS_CIPHER_CAMELLIA_128_CFB128 = 23, /**< Camellia cipher with 128-bit CFB128 mode. */
    MBEDTLS_CIPHER_CAMELLIA_192_CFB128 = 24, /**< Camellia cipher with 192-bit CFB128 mode. */
    MBEDTLS_CIPHER_CAMELLIA_256_CFB128 = 25, /**< Camellia cipher with 256-bit CFB128 mode. */
    MBEDTLS_CIPHER_CAMELLIA_128_CTR = 26, /**< Camellia cipher with 128-bit CTR mode. */
    MBEDTLS_CIPHER_CAMELLIA_192_CTR = 27, /**< Camellia cipher with 192-bit CTR mode. */
    MBEDTLS_CIPHER_CAMELLIA_256_CTR = 28, /**< Camellia cipher with 256-bit CTR mode. */
    MBEDTLS_CIPHER_CAMELLIA_128_GCM = 29, /**< Camellia cipher with 128-bit GCM mode. */
    MBEDTLS_CIPHER_CAMELLIA_192_GCM = 30, /**< Camellia cipher with 192-bit GCM mode. */
    MBEDTLS_CIPHER_CAMELLIA_256_GCM = 31, /**< Camellia cipher with 256-bit GCM mode. */
    MBEDTLS_CIPHER_DES_ECB = 32, /**< DES cipher with ECB mode. \warning DES is considered weak. */
    MBEDTLS_CIPHER_DES_CBC = 33, /**< DES cipher with CBC mode. \warning DES is considered weak. */
    MBEDTLS_CIPHER_DES_EDE_ECB = 34, /**< DES cipher with EDE ECB mode. \warning 3DES is considered weak. */
    MBEDTLS_CIPHER_DES_EDE_CBC = 35, /**< DES cipher with EDE CBC mode. \warning 3DES is considered weak. */
    MBEDTLS_CIPHER_DES_EDE3_ECB = 36, /**< DES cipher with EDE3 ECB mode. \warning 3DES is considered weak. */
    MBEDTLS_CIPHER_DES_EDE3_CBC = 37, /**< DES cipher with EDE3 CBC mode. \warning 3DES is considered weak. */
    MBEDTLS_CIPHER_BLOWFISH_ECB = 38, /**< Blowfish cipher with ECB mode. */
    MBEDTLS_CIPHER_BLOWFISH_CBC = 39, /**< Blowfish cipher with CBC mode. */
    MBEDTLS_CIPHER_BLOWFISH_CFB64 = 40, /**< Blowfish cipher with CFB64 mode. */
    MBEDTLS_CIPHER_BLOWFISH_CTR = 41, /**< Blowfish cipher with CTR mode. */
    MBEDTLS_CIPHER_ARC4_128 = 42, /**< RC4 cipher with 128-bit mode. */
    MBEDTLS_CIPHER_AES_128_CCM = 43, /**< AES cipher with 128-bit CCM mode. */
    MBEDTLS_CIPHER_AES_192_CCM = 44, /**< AES cipher with 192-bit CCM mode. */
    MBEDTLS_CIPHER_AES_256_CCM = 45, /**< AES cipher with 256-bit CCM mode. */
    MBEDTLS_CIPHER_CAMELLIA_128_CCM = 46, /**< Camellia cipher with 128-bit CCM mode. */
    MBEDTLS_CIPHER_CAMELLIA_192_CCM = 47, /**< Camellia cipher with 192-bit CCM mode. */
    MBEDTLS_CIPHER_CAMELLIA_256_CCM = 48, /**< Camellia cipher with 256-bit CCM mode. */
    MBEDTLS_CIPHER_ARIA_128_ECB = 49, /**< Aria cipher with 128-bit key and ECB mode. */
    MBEDTLS_CIPHER_ARIA_192_ECB = 50, /**< Aria cipher with 192-bit key and ECB mode. */
    MBEDTLS_CIPHER_ARIA_256_ECB = 51, /**< Aria cipher with 256-bit key and ECB mode. */
    MBEDTLS_CIPHER_ARIA_128_CBC = 52, /**< Aria cipher with 128-bit key and CBC mode. */
    MBEDTLS_CIPHER_ARIA_192_CBC = 53, /**< Aria cipher with 192-bit key and CBC mode. */
    MBEDTLS_CIPHER_ARIA_256_CBC = 54, /**< Aria cipher with 256-bit key and CBC mode. */
    MBEDTLS_CIPHER_ARIA_128_CFB128 = 55, /**< Aria cipher with 128-bit key and CFB-128 mode. */
    MBEDTLS_CIPHER_ARIA_192_CFB128 = 56, /**< Aria cipher with 192-bit key and CFB-128 mode. */
    MBEDTLS_CIPHER_ARIA_256_CFB128 = 57, /**< Aria cipher with 256-bit key and CFB-128 mode. */
    MBEDTLS_CIPHER_ARIA_128_CTR = 58, /**< Aria cipher with 128-bit key and CTR mode. */
    MBEDTLS_CIPHER_ARIA_192_CTR = 59, /**< Aria cipher with 192-bit key and CTR mode. */
    MBEDTLS_CIPHER_ARIA_256_CTR = 60, /**< Aria cipher with 256-bit key and CTR mode. */
    MBEDTLS_CIPHER_ARIA_128_GCM = 61, /**< Aria cipher with 128-bit key and GCM mode. */
    MBEDTLS_CIPHER_ARIA_192_GCM = 62, /**< Aria cipher with 192-bit key and GCM mode. */
    MBEDTLS_CIPHER_ARIA_256_GCM = 63, /**< Aria cipher with 256-bit key and GCM mode. */
    MBEDTLS_CIPHER_ARIA_128_CCM = 64, /**< Aria cipher with 128-bit key and CCM mode. */
    MBEDTLS_CIPHER_ARIA_192_CCM = 65, /**< Aria cipher with 192-bit key and CCM mode. */
    MBEDTLS_CIPHER_ARIA_256_CCM = 66, /**< Aria cipher with 256-bit key and CCM mode. */
    MBEDTLS_CIPHER_AES_128_OFB = 67, /**< AES 128-bit cipher in OFB mode. */
    MBEDTLS_CIPHER_AES_192_OFB = 68, /**< AES 192-bit cipher in OFB mode. */
    MBEDTLS_CIPHER_AES_256_OFB = 69, /**< AES 256-bit cipher in OFB mode. */
    MBEDTLS_CIPHER_AES_128_XTS = 70, /**< AES 128-bit cipher in XTS block mode. */
    MBEDTLS_CIPHER_AES_256_XTS = 71, /**< AES 256-bit cipher in XTS block mode. */
    MBEDTLS_CIPHER_CHACHA20 = 72, /**< ChaCha20 stream cipher. */
    MBEDTLS_CIPHER_CHACHA20_POLY1305 = 73, /**< ChaCha20-Poly1305 AEAD cipher. */
    MBEDTLS_CIPHER_AES_128_KW = 74, /**< AES cipher with 128-bit NIST KW mode. */
    MBEDTLS_CIPHER_AES_192_KW = 75, /**< AES cipher with 192-bit NIST KW mode. */
    MBEDTLS_CIPHER_AES_256_KW = 76, /**< AES cipher with 256-bit NIST KW mode. */
    MBEDTLS_CIPHER_AES_128_KWP = 77, /**< AES cipher with 128-bit NIST KWP mode. */
    MBEDTLS_CIPHER_AES_192_KWP = 78, /**< AES cipher with 192-bit NIST KWP mode. */
    MBEDTLS_CIPHER_AES_256_KWP = 79 /**< AES cipher with 256-bit NIST KWP mode. */
}

/** Supported cipher modes. */
enum mbedtls_cipher_mode_t
{
    MBEDTLS_MODE_NONE = 0, /**< None.                        */
    MBEDTLS_MODE_ECB = 1, /**< The ECB cipher mode.         */
    MBEDTLS_MODE_CBC = 2, /**< The CBC cipher mode.         */
    MBEDTLS_MODE_CFB = 3, /**< The CFB cipher mode.         */
    MBEDTLS_MODE_OFB = 4, /**< The OFB cipher mode.         */
    MBEDTLS_MODE_CTR = 5, /**< The CTR cipher mode.         */
    MBEDTLS_MODE_GCM = 6, /**< The GCM cipher mode.         */
    MBEDTLS_MODE_STREAM = 7, /**< The stream cipher mode.      */
    MBEDTLS_MODE_CCM = 8, /**< The CCM cipher mode.         */
    MBEDTLS_MODE_XTS = 9, /**< The XTS cipher mode.         */
    MBEDTLS_MODE_CHACHAPOLY = 10, /**< The ChaCha-Poly cipher mode. */
    MBEDTLS_MODE_KW = 11, /**< The SP800-38F KW mode */
    MBEDTLS_MODE_KWP = 12 /**< The SP800-38F KWP mode */
}

/** Supported cipher padding types. */
enum mbedtls_cipher_padding_t
{
    MBEDTLS_PADDING_PKCS7 = 0, /**< PKCS7 padding (default).        */
    MBEDTLS_PADDING_ONE_AND_ZEROS = 1, /**< ISO/IEC 7816-4 padding.         */
    MBEDTLS_PADDING_ZEROS_AND_LEN = 2, /**< ANSI X.923 padding.             */
    MBEDTLS_PADDING_ZEROS = 3, /**< Zero padding (not reversible). */
    MBEDTLS_PADDING_NONE = 4 /**< Never pad (full blocks only).   */
}

/** Type of operation. */
enum mbedtls_operation_t
{
    MBEDTLS_OPERATION_NONE = -1,
    MBEDTLS_DECRYPT = 0,
    MBEDTLS_ENCRYPT = 1
}

enum
{
    /** Undefined key length. */
    MBEDTLS_KEY_LENGTH_NONE = 0,
    /** Key length, in bits (including parity), for DES keys. \warning DES is considered weak. */
    MBEDTLS_KEY_LENGTH_DES = 64,
    /** Key length in bits, including parity, for DES in two-key EDE. \warning 3DES is considered weak. */
    MBEDTLS_KEY_LENGTH_DES_EDE = 128,
    /** Key length in bits, including parity, for DES in three-key EDE. \warning 3DES is considered weak. */
    MBEDTLS_KEY_LENGTH_DES_EDE3 = 192
}

/** Maximum length of any IV, in Bytes. */
/* This should ideally be derived automatically from list of ciphers.
 * This should be kept in sync with MBEDTLS_SSL_MAX_IV_LENGTH defined
 * in ssl_internal.h. */
enum MBEDTLS_MAX_IV_LENGTH = 16;

/** Maximum block size of any cipher, in Bytes. */
/* This should ideally be derived automatically from list of ciphers.
 * This should be kept in sync with MBEDTLS_SSL_MAX_BLOCK_LENGTH defined
 * in ssl_internal.h. */
enum MBEDTLS_MAX_BLOCK_LENGTH = 16;

/** Maximum key length, in Bytes. */
/* This should ideally be derived automatically from list of ciphers.
 * For now, only check whether XTS is enabled which uses 64 Byte keys,
 * and use 32 Bytes as an upper bound for the maximum key length otherwise.
 * This should be kept in sync with MBEDTLS_SSL_MAX_BLOCK_LENGTH defined
 * in ssl_internal.h, which however deliberately ignores the case of XTS
 * since the latter isn't used in SSL/TLS. */
enum MBEDTLS_MAX_KEY_LENGTH = 64;

/* MBEDTLS_CIPHER_MODE_XTS */

/**
 * Base cipher information (opaque struct).
 */
struct mbedtls_cipher_base_t;

/**
 * CMAC context (opaque struct).
 */
struct mbedtls_cmac_context_t;

/**
 * Cipher information. Allows calling cipher functions
 * in a generic way.
 */
struct mbedtls_cipher_info_t
{
    /** Full cipher identifier. For example,
     * MBEDTLS_CIPHER_AES_256_CBC.
     */
    mbedtls_cipher_type_t type;

    /** The cipher mode. For example, MBEDTLS_MODE_CBC. */
    mbedtls_cipher_mode_t mode;

    /** The cipher key length, in bits. This is the
     * default length for variable sized ciphers.
     * Includes parity bits for ciphers like DES.
     */
    uint key_bitlen;

    /** Name of the cipher. */
    const(char)* name;

    /** IV or nonce size, in Bytes.
     * For ciphers that accept variable IV sizes,
     * this is the recommended size.
     */
    uint iv_size;

    /** Bitflag comprised of MBEDTLS_CIPHER_VARIABLE_IV_LEN and
     *  MBEDTLS_CIPHER_VARIABLE_KEY_LEN indicating whether the
     *  cipher supports variable IV or variable key sizes, respectively.
     */
    int flags;

    /** The block size, in Bytes. */
    uint block_size;

    /** Struct for base cipher information and functions. */
    const(mbedtls_cipher_base_t)* base;
}

/**
 * Generic cipher context.
 */
struct mbedtls_cipher_context_t
{
    /** Information about the associated cipher. */
    const(mbedtls_cipher_info_t)* cipher_info;

    /** Key length to use. */
    int key_bitlen;

    /** Operation that the key of the context has been
     * initialized for.
     */
    mbedtls_operation_t operation;

    /** Padding functions to use, if relevant for
     * the specific cipher mode.
     */
    void function (ubyte* output, size_t olen, size_t data_len) add_padding;
    int function (ubyte* input, size_t ilen, size_t* data_len) get_padding;

    /** Buffer for input that has not been processed yet. */
    ubyte[MBEDTLS_MAX_BLOCK_LENGTH] unprocessed_data;

    /** Number of Bytes that have not been processed yet. */
    size_t unprocessed_len;

    /** Current IV or NONCE_COUNTER for CTR-mode, data unit (or sector) number
     * for XTS-mode. */
    ubyte[MBEDTLS_MAX_IV_LENGTH] iv;

    /** IV size in Bytes, for ciphers with variable-length IVs. */
    size_t iv_size;

    /** The cipher-specific context. */
    void* cipher_ctx;

    /** CMAC-specific context. */
    mbedtls_cmac_context_t* cmac_ctx;

    /** Indicates whether the cipher operations should be performed
     *  by Mbed TLS' own crypto library or an external implementation
     *  of the PSA Crypto API.
     *  This is unset if the cipher context was established through
     *  mbedtls_cipher_setup(), and set if it was established through
     *  mbedtls_cipher_setup_psa().
     */

    /* MBEDTLS_USE_PSA_CRYPTO */
}

/**
 * \brief This function retrieves the list of ciphers supported
 *        by the generic cipher module.
 *
 *        For any cipher identifier in the returned list, you can
 *        obtain the corresponding generic cipher information structure
 *        via mbedtls_cipher_info_from_type(), which can then be used
 *        to prepare a cipher context via mbedtls_cipher_setup().
 *
 *
 * \return      A statically-allocated array of cipher identifiers
 *              of type cipher_type_t. The last entry is zero.
 */
const(int)* mbedtls_cipher_list ();

/**
 * \brief               This function retrieves the cipher-information
 *                      structure associated with the given cipher name.
 *
 * \param cipher_name   Name of the cipher to search for. This must not be
 *                      \c NULL.
 *
 * \return              The cipher information structure associated with the
 *                      given \p cipher_name.
 * \return              \c NULL if the associated cipher information is not found.
 */
const(mbedtls_cipher_info_t)* mbedtls_cipher_info_from_string (const(char)* cipher_name);

/**
 * \brief               This function retrieves the cipher-information
 *                      structure associated with the given cipher type.
 *
 * \param cipher_type   Type of the cipher to search for.
 *
 * \return              The cipher information structure associated with the
 *                      given \p cipher_type.
 * \return              \c NULL if the associated cipher information is not found.
 */
const(mbedtls_cipher_info_t)* mbedtls_cipher_info_from_type (const mbedtls_cipher_type_t cipher_type);

/**
 * \brief               This function retrieves the cipher-information
 *                      structure associated with the given cipher ID,
 *                      key size and mode.
 *
 * \param cipher_id     The ID of the cipher to search for. For example,
 *                      #MBEDTLS_CIPHER_ID_AES.
 * \param key_bitlen    The length of the key in bits.
 * \param mode          The cipher mode. For example, #MBEDTLS_MODE_CBC.
 *
 * \return              The cipher information structure associated with the
 *                      given \p cipher_id.
 * \return              \c NULL if the associated cipher information is not found.
 */
const(mbedtls_cipher_info_t)* mbedtls_cipher_info_from_values (
    const mbedtls_cipher_id_t cipher_id,
    int key_bitlen,
    const mbedtls_cipher_mode_t mode);

/**
 * \brief               This function initializes a \p ctx as NONE.
 *
 * \param ctx           The context to be initialized. This must not be \c NULL.
 */
void mbedtls_cipher_init (mbedtls_cipher_context_t* ctx);

/**
 * \brief               This function frees and clears the cipher-specific
 *                      context of \p ctx. Freeing \p ctx itself remains the
 *                      responsibility of the caller.
 *
 * \param ctx           The context to be freed. If this is \c NULL, the
 *                      function has no effect, otherwise this must point to an
 *                      initialized context.
 */
void mbedtls_cipher_free (mbedtls_cipher_context_t* ctx);

/**
 * \brief               This function prepares a cipher context for
 *                      use with the given cipher primitive.
 *
 * \warning             In CBC mode, if mbedtls_cipher_set_padding_mode() is not called:
 *                      - If MBEDTLS_CIPHER_PADDING_PKCS7 is enabled, the
 *                      context will use PKCS7 padding.
 *                      - Otherwise the context uses no padding and the input
 *                      must be a whole number of blocks.
 *
 * \note                After calling this function, you should call
 *                      mbedtls_cipher_setkey() and, if the mode uses padding,
 *                      mbedtls_cipher_set_padding_mode(), then for each
 *                      message to encrypt or decrypt with this key, either:
 *                      - mbedtls_cipher_crypt() for one-shot processing with
 *                      non-AEAD modes;
 *                      - mbedtls_cipher_auth_encrypt_ext() or
 *                      mbedtls_cipher_auth_decrypt_ext() for one-shot
 *                      processing with AEAD modes or NIST_KW;
 *                      - for multi-part processing, see the documentation of
 *                      mbedtls_cipher_reset().
 *
 * \param ctx           The context to prepare. This must be initialized by
 *                      a call to mbedtls_cipher_init() first.
 * \param cipher_info   The cipher to use.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA on
 *                      parameter-verification failure.
 * \return              #MBEDTLS_ERR_CIPHER_ALLOC_FAILED if allocation of the
 *                      cipher-specific context fails.
 *
 * \internal Currently, the function also clears the structure.
 * In future versions, the caller will be required to call
 * mbedtls_cipher_init() on the structure first.
 */
int mbedtls_cipher_setup (
    mbedtls_cipher_context_t* ctx,
    const(mbedtls_cipher_info_t)* cipher_info);

/**
 * \brief               This function initializes a cipher context for
 *                      PSA-based use with the given cipher primitive.
 *
 * \note                See #MBEDTLS_USE_PSA_CRYPTO for information on PSA.
 *
 * \param ctx           The context to initialize. May not be \c NULL.
 * \param cipher_info   The cipher to use.
 * \param taglen        For AEAD ciphers, the length in bytes of the
 *                      authentication tag to use. Subsequent uses of
 *                      mbedtls_cipher_auth_encrypt() or
 *                      mbedtls_cipher_auth_decrypt() must provide
 *                      the same tag length.
 *                      For non-AEAD ciphers, the value must be \c 0.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA on
 *                      parameter-verification failure.
 * \return              #MBEDTLS_ERR_CIPHER_ALLOC_FAILED if allocation of the
 *                      cipher-specific context fails.
 */

/* MBEDTLS_USE_PSA_CRYPTO */

/**
 * \brief        This function returns the block size of the given cipher.
 *
 * \param ctx    The context of the cipher. This must be initialized.
 *
 * \return       The block size of the underlying cipher.
 * \return       \c 0 if \p ctx has not been initialized.
 */
pragma(inline, true) extern(D)
uint mbedtls_cipher_get_block_size (const(mbedtls_cipher_context_t)* ctx)
{
  MBEDTLS_INTERNAL_VALIDATE_RET(ctx != null, 0);
  if (ctx.cipher_info == null)
    return 0;

  return ctx.cipher_info.block_size;
}

/**
 * \brief        This function returns the mode of operation for
 *               the cipher. For example, MBEDTLS_MODE_CBC.
 *
 * \param ctx    The context of the cipher. This must be initialized.
 *
 * \return       The mode of operation.
 * \return       #MBEDTLS_MODE_NONE if \p ctx has not been initialized.
 */
pragma(inline, true) extern(D)
mbedtls_cipher_mode_t mbedtls_cipher_get_cipher_mode (
    const(mbedtls_cipher_context_t)* ctx);
{
  MBEDTLS_INTERNAL_VALIDATE_RET(ctx != null, MBEDTLS_MODE_NONE);
  if (ctx.cipher_info == null)
    return MBEDTLS_MODE_NONE;

  return ctx.cipher_info.mode;
}

/**
 * \brief       This function returns the size of the IV or nonce
 *              of the cipher, in Bytes.
 *
 * \param ctx   The context of the cipher. This must be initialized.
 *
 * \return      The recommended IV size if no IV has been set.
 * \return      \c 0 for ciphers not using an IV or a nonce.
 * \return      The actual size if an IV has been set.
 */
pragma(inline, true) extern(D)
int mbedtls_cipher_get_iv_size (const(mbedtls_cipher_context_t)* ctx)
{
  MBEDTLS_INTERNAL_VALIDATE_RET(ctx != null, 0);
  if (ctx.cipher_info == null)
    return 0;

  return ctx.cipher_info.iv_size;
}

/**
 * \brief               This function returns the type of the given cipher.
 *
 * \param ctx           The context of the cipher. This must be initialized.
 *
 * \return              The type of the cipher.
 * \return              #MBEDTLS_CIPHER_NONE if \p ctx has not been initialized.
 */
pragma(inline, true) extern(D)
mbedtls_cipher_type_t mbedtls_cipher_get_type (
    const(mbedtls_cipher_context_t)* ctx)
{
  MBEDTLS_INTERNAL_VALIDATE_RET(ctx != null, MBEDTLS_CIPHER_NONE);
  if (ctx.cipher_info == null)
    return MBEDTLS_CIPHER_NONE;

  return ctx.cipher_info.type;
}

/**
 * \brief               This function returns the name of the given cipher
 *                      as a string.
 *
 * \param ctx           The context of the cipher. This must be initialized.
 *
 * \return              The name of the cipher.
 * \return              NULL if \p ctx has not been not initialized.
 */
pragma(inline, true) extern(D)
const(char)* mbedtls_cipher_get_name (const(mbedtls_cipher_context_t)* ctx)
{
  MBEDTLS_INTERNAL_VALIDATE_RET(ctx != null, 0);
  if (ctx.cipher_info == null)
    return 0;

  return ctx.cipher_info.name;
}

/**
 * \brief               This function returns the key length of the cipher.
 *
 * \param ctx           The context of the cipher. This must be initialized.
 *
 * \return              The key length of the cipher in bits.
 * \return              #MBEDTLS_KEY_LENGTH_NONE if \p ctx has not been
 *                      initialized.
 */
pragma(inline, true) extern(D)
int mbedtls_cipher_get_key_bitlen (const(mbedtls_cipher_context_t)* ctx)
{
  MBEDTLS_INTERNAL_VALIDATE_RET(ctx != null, MBEDTLS_KEY_LENGTH_NONE);
  if (ctx.cipher_info == null)
    return MBEDTLS_KEY_LENGTH_NONE;

  return cast(int) ctx.cipher_info.key_bitlen;
}

/**
 * \brief          This function returns the operation of the given cipher.
 *
 * \param ctx      The context of the cipher. This must be initialized.
 *
 * \return         The type of operation: #MBEDTLS_ENCRYPT or #MBEDTLS_DECRYPT.
 * \return         #MBEDTLS_OPERATION_NONE if \p ctx has not been initialized.
 */
pragma(inline, true) extern(D)
mbedtls_operation_t mbedtls_cipher_get_operation (
    const(mbedtls_cipher_context_t)* ctx)
{
  MBEDTLS_INTERNAL_VALIDATE_RET(ctx != null, MBEDTLS_OPERATION_NONE);
  if (ctx.cipher_info == null)
    return MBEDTLS_OPERATION_NONE;

  return ctx.operation;
}

/**
 * \brief               This function sets the key to use with the given context.
 *
 * \param ctx           The generic cipher context. This must be initialized and
 *                      bound to a cipher information structure.
 * \param key           The key to use. This must be a readable buffer of at
 *                      least \p key_bitlen Bits.
 * \param key_bitlen    The key length to use, in Bits.
 * \param operation     The operation that the key will be used for:
 *                      #MBEDTLS_ENCRYPT or #MBEDTLS_DECRYPT.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA on
 *                      parameter-verification failure.
 * \return              A cipher-specific error code on failure.
 */
int mbedtls_cipher_setkey (
    mbedtls_cipher_context_t* ctx,
    const(ubyte)* key,
    int key_bitlen,
    const mbedtls_operation_t operation);

/**
 * \brief               This function sets the padding mode, for cipher modes
 *                      that use padding.
 *
 * \param ctx           The generic cipher context. This must be initialized and
 *                      bound to a cipher information structure.
 * \param mode          The padding mode.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE
 *                      if the selected padding mode is not supported.
 * \return              #MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA if the cipher mode
 *                      does not support padding.
 */
int mbedtls_cipher_set_padding_mode (
    mbedtls_cipher_context_t* ctx,
    mbedtls_cipher_padding_t mode);
/* MBEDTLS_CIPHER_MODE_WITH_PADDING */

/**
 * \brief           This function sets the initialization vector (IV)
 *                  or nonce.
 *
 * \note            Some ciphers do not use IVs nor nonce. For these
 *                  ciphers, this function has no effect.
 *
 * \param ctx       The generic cipher context. This must be initialized and
 *                  bound to a cipher information structure.
 * \param iv        The IV to use, or NONCE_COUNTER for CTR-mode ciphers. This
 *                  must be a readable buffer of at least \p iv_len Bytes.
 * \param iv_len    The IV length for ciphers with variable-size IV.
 *                  This parameter is discarded by ciphers with fixed-size IV.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA on
 *                  parameter-verification failure.
 */
int mbedtls_cipher_set_iv (
    mbedtls_cipher_context_t* ctx,
    const(ubyte)* iv,
    size_t iv_len);

/**
 * \brief         This function resets the cipher state.
 *
 * \note          With non-AEAD ciphers, the order of calls for each message
 *                is as follows:
 *                1. mbedtls_cipher_set_iv() if the mode uses an IV/nonce.
 *                2. mbedtls_cipher_reset()
 *                3. mbedtls_cipher_update() one or more times
 *                4. mbedtls_cipher_finish()
 *                .
 *                This sequence can be repeated to encrypt or decrypt multiple
 *                messages with the same key.
 *
 * \note          With AEAD ciphers, the order of calls for each message
 *                is as follows:
 *                1. mbedtls_cipher_set_iv() if the mode uses an IV/nonce.
 *                2. mbedtls_cipher_reset()
 *                3. mbedtls_cipher_update_ad()
 *                4. mbedtls_cipher_update() one or more times
 *                5. mbedtls_cipher_check_tag() (for decryption) or
 *                mbedtls_cipher_write_tag() (for encryption).
 *                .
 *                This sequence can be repeated to encrypt or decrypt multiple
 *                messages with the same key.
 *
 * \param ctx     The generic cipher context. This must be bound to a key.
 *
 * \return        \c 0 on success.
 * \return        #MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA on
 *                parameter-verification failure.
 */
int mbedtls_cipher_reset (mbedtls_cipher_context_t* ctx);

/**
 * \brief               This function adds additional data for AEAD ciphers.
 *                      Currently supported with GCM and ChaCha20+Poly1305.
 *                      This must be called exactly once, after
 *                      mbedtls_cipher_reset().
 *
 * \param ctx           The generic cipher context. This must be initialized.
 * \param ad            The additional data to use. This must be a readable
 *                      buffer of at least \p ad_len Bytes.
 * \param ad_len        The length of \p ad in Bytes.
 *
 * \return              \c 0 on success.
 * \return              A specific error code on failure.
 */
int mbedtls_cipher_update_ad (
    mbedtls_cipher_context_t* ctx,
    const(ubyte)* ad,
    size_t ad_len);
/* MBEDTLS_GCM_C || MBEDTLS_CHACHAPOLY_C */

/**
 * \brief               The generic cipher update function. It encrypts or
 *                      decrypts using the given cipher context. Writes as
 *                      many block-sized blocks of data as possible to output.
 *                      Any data that cannot be written immediately is either
 *                      added to the next block, or flushed when
 *                      mbedtls_cipher_finish() is called.
 *                      Exception: For MBEDTLS_MODE_ECB, expects a single block
 *                      in size. For example, 16 Bytes for AES.
 *
 * \note                If the underlying cipher is used in GCM mode, all calls
 *                      to this function, except for the last one before
 *                      mbedtls_cipher_finish(), must have \p ilen as a
 *                      multiple of the block size of the cipher.
 *
 * \param ctx           The generic cipher context. This must be initialized and
 *                      bound to a key.
 * \param input         The buffer holding the input data. This must be a
 *                      readable buffer of at least \p ilen Bytes.
 * \param ilen          The length of the input data.
 * \param output        The buffer for the output data. This must be able to
 *                      hold at least `ilen + block_size`. This must not be the
 *                      same buffer as \p input.
 * \param olen          The length of the output data, to be updated with the
 *                      actual number of Bytes written. This must not be
 *                      \c NULL.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA on
 *                      parameter-verification failure.
 * \return              #MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE on an
 *                      unsupported mode for a cipher.
 * \return              A cipher-specific error code on failure.
 */
int mbedtls_cipher_update (
    mbedtls_cipher_context_t* ctx,
    const(ubyte)* input,
    size_t ilen,
    ubyte* output,
    size_t* olen);

/**
 * \brief               The generic cipher finalization function. If data still
 *                      needs to be flushed from an incomplete block, the data
 *                      contained in it is padded to the size of
 *                      the last block, and written to the \p output buffer.
 *
 * \param ctx           The generic cipher context. This must be initialized and
 *                      bound to a key.
 * \param output        The buffer to write data to. This needs to be a writable
 *                      buffer of at least block_size Bytes.
 * \param olen          The length of the data written to the \p output buffer.
 *                      This may not be \c NULL.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA on
 *                      parameter-verification failure.
 * \return              #MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED on decryption
 *                      expecting a full block but not receiving one.
 * \return              #MBEDTLS_ERR_CIPHER_INVALID_PADDING on invalid padding
 *                      while decrypting.
 * \return              A cipher-specific error code on failure.
 */
int mbedtls_cipher_finish (
    mbedtls_cipher_context_t* ctx,
    ubyte* output,
    size_t* olen);

/**
 * \brief               This function writes a tag for AEAD ciphers.
 *                      Currently supported with GCM and ChaCha20+Poly1305.
 *                      This must be called after mbedtls_cipher_finish().
 *
 * \param ctx           The generic cipher context. This must be initialized,
 *                      bound to a key, and have just completed a cipher
 *                      operation through mbedtls_cipher_finish() the tag for
 *                      which should be written.
 * \param tag           The buffer to write the tag to. This must be a writable
 *                      buffer of at least \p tag_len Bytes.
 * \param tag_len       The length of the tag to write.
 *
 * \return              \c 0 on success.
 * \return              A specific error code on failure.
 */
int mbedtls_cipher_write_tag (
    mbedtls_cipher_context_t* ctx,
    ubyte* tag,
    size_t tag_len);

/**
 * \brief               This function checks the tag for AEAD ciphers.
 *                      Currently supported with GCM and ChaCha20+Poly1305.
 *                      This must be called after mbedtls_cipher_finish().
 *
 * \param ctx           The generic cipher context. This must be initialized.
 * \param tag           The buffer holding the tag. This must be a readable
 *                      buffer of at least \p tag_len Bytes.
 * \param tag_len       The length of the tag to check.
 *
 * \return              \c 0 on success.
 * \return              A specific error code on failure.
 */
int mbedtls_cipher_check_tag (
    mbedtls_cipher_context_t* ctx,
    const(ubyte)* tag,
    size_t tag_len);
/* MBEDTLS_GCM_C || MBEDTLS_CHACHAPOLY_C */

/**
 * \brief               The generic all-in-one encryption/decryption function,
 *                      for all ciphers except AEAD constructs.
 *
 * \param ctx           The generic cipher context. This must be initialized.
 * \param iv            The IV to use, or NONCE_COUNTER for CTR-mode ciphers.
 *                      This must be a readable buffer of at least \p iv_len
 *                      Bytes.
 * \param iv_len        The IV length for ciphers with variable-size IV.
 *                      This parameter is discarded by ciphers with fixed-size
 *                      IV.
 * \param input         The buffer holding the input data. This must be a
 *                      readable buffer of at least \p ilen Bytes.
 * \param ilen          The length of the input data in Bytes.
 * \param output        The buffer for the output data. This must be able to
 *                      hold at least `ilen + block_size`. This must not be the
 *                      same buffer as \p input.
 * \param olen          The length of the output data, to be updated with the
 *                      actual number of Bytes written. This must not be
 *                      \c NULL.
 *
 * \note                Some ciphers do not use IVs nor nonce. For these
 *                      ciphers, use \p iv = NULL and \p iv_len = 0.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA on
 *                      parameter-verification failure.
 * \return              #MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED on decryption
 *                      expecting a full block but not receiving one.
 * \return              #MBEDTLS_ERR_CIPHER_INVALID_PADDING on invalid padding
 *                      while decrypting.
 * \return              A cipher-specific error code on failure.
 */
int mbedtls_cipher_crypt (
    mbedtls_cipher_context_t* ctx,
    const(ubyte)* iv,
    size_t iv_len,
    const(ubyte)* input,
    size_t ilen,
    ubyte* output,
    size_t* olen);

/* MBEDTLS_DEPRECATED_WARNING */
/**
 * \brief               The generic authenticated encryption (AEAD) function.
 *
 * \deprecated          Superseded by mbedtls_cipher_auth_encrypt_ext().
 *
 * \note                This function only supports AEAD algorithms, not key
 *                      wrapping algorithms such as NIST_KW; for this, see
 *                      mbedtls_cipher_auth_encrypt_ext().
 *
 * \param ctx           The generic cipher context. This must be initialized and
 *                      bound to a key associated with an AEAD algorithm.
 * \param iv            The nonce to use. This must be a readable buffer of
 *                      at least \p iv_len Bytes and must not be \c NULL.
 * \param iv_len        The length of the nonce. This must satisfy the
 *                      constraints imposed by the AEAD cipher used.
 * \param ad            The additional data to authenticate. This must be a
 *                      readable buffer of at least \p ad_len Bytes, and may
 *                      be \c NULL is \p ad_len is \c 0.
 * \param ad_len        The length of \p ad.
 * \param input         The buffer holding the input data. This must be a
 *                      readable buffer of at least \p ilen Bytes, and may be
 *                      \c NULL if \p ilen is \c 0.
 * \param ilen          The length of the input data.
 * \param output        The buffer for the output data. This must be a
 *                      writable buffer of at least \p ilen Bytes, and must
 *                      not be \c NULL.
 * \param olen          This will be filled with the actual number of Bytes
 *                      written to the \p output buffer. This must point to a
 *                      writable object of type \c size_t.
 * \param tag           The buffer for the authentication tag. This must be a
 *                      writable buffer of at least \p tag_len Bytes. See note
 *                      below regarding restrictions with PSA-based contexts.
 * \param tag_len       The desired length of the authentication tag. This
 *                      must match the constraints imposed by the AEAD cipher
 *                      used, and in particular must not be \c 0.
 *
 * \note                If the context is based on PSA (that is, it was set up
 *                      with mbedtls_cipher_setup_psa()), then it is required
 *                      that \c tag == output + ilen. That is, the tag must be
 *                      appended to the ciphertext as recommended by RFC 5116.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA on
 *                      parameter-verification failure.
 * \return              A cipher-specific error code on failure.
 */
int mbedtls_cipher_auth_encrypt (
    mbedtls_cipher_context_t* ctx,
    const(ubyte)* iv,
    size_t iv_len,
    const(ubyte)* ad,
    size_t ad_len,
    const(ubyte)* input,
    size_t ilen,
    ubyte* output,
    size_t* olen,
    ubyte* tag,
    size_t tag_len);

/**
 * \brief               The generic authenticated decryption (AEAD) function.
 *
 * \deprecated          Superseded by mbedtls_cipher_auth_decrypt_ext().
 *
 * \note                This function only supports AEAD algorithms, not key
 *                      wrapping algorithms such as NIST_KW; for this, see
 *                      mbedtls_cipher_auth_decrypt_ext().
 *
 * \note                If the data is not authentic, then the output buffer
 *                      is zeroed out to prevent the unauthentic plaintext being
 *                      used, making this interface safer.
 *
 * \param ctx           The generic cipher context. This must be initialized and
 *                      bound to a key associated with an AEAD algorithm.
 * \param iv            The nonce to use. This must be a readable buffer of
 *                      at least \p iv_len Bytes and must not be \c NULL.
 * \param iv_len        The length of the nonce. This must satisfy the
 *                      constraints imposed by the AEAD cipher used.
 * \param ad            The additional data to authenticate. This must be a
 *                      readable buffer of at least \p ad_len Bytes, and may
 *                      be \c NULL is \p ad_len is \c 0.
 * \param ad_len        The length of \p ad.
 * \param input         The buffer holding the input data. This must be a
 *                      readable buffer of at least \p ilen Bytes, and may be
 *                      \c NULL if \p ilen is \c 0.
 * \param ilen          The length of the input data.
 * \param output        The buffer for the output data. This must be a
 *                      writable buffer of at least \p ilen Bytes, and must
 *                      not be \c NULL.
 * \param olen          This will be filled with the actual number of Bytes
 *                      written to the \p output buffer. This must point to a
 *                      writable object of type \c size_t.
 * \param tag           The buffer for the authentication tag. This must be a
 *                      readable buffer of at least \p tag_len Bytes. See note
 *                      below regarding restrictions with PSA-based contexts.
 * \param tag_len       The length of the authentication tag. This must match
 *                      the constraints imposed by the AEAD cipher used, and in
 *                      particular must not be \c 0.
 *
 * \note                If the context is based on PSA (that is, it was set up
 *                      with mbedtls_cipher_setup_psa()), then it is required
 *                      that \c tag == input + len. That is, the tag must be
 *                      appended to the ciphertext as recommended by RFC 5116.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA on
 *                      parameter-verification failure.
 * \return              #MBEDTLS_ERR_CIPHER_AUTH_FAILED if data is not authentic.
 * \return              A cipher-specific error code on failure.
 */
int mbedtls_cipher_auth_decrypt (
    mbedtls_cipher_context_t* ctx,
    const(ubyte)* iv,
    size_t iv_len,
    const(ubyte)* ad,
    size_t ad_len,
    const(ubyte)* input,
    size_t ilen,
    ubyte* output,
    size_t* olen,
    const(ubyte)* tag,
    size_t tag_len);

/* MBEDTLS_DEPRECATED_REMOVED */
/* MBEDTLS_CIPHER_MODE_AEAD */

/**
 * \brief               The authenticated encryption (AEAD/NIST_KW) function.
 *
 * \note                For AEAD modes, the tag will be appended to the
 *                      ciphertext, as recommended by RFC 5116.
 *                      (NIST_KW doesn't have a separate tag.)
 *
 * \param ctx           The generic cipher context. This must be initialized and
 *                      bound to a key, with an AEAD algorithm or NIST_KW.
 * \param iv            The nonce to use. This must be a readable buffer of
 *                      at least \p iv_len Bytes and may be \c NULL if \p
 *                      iv_len is \c 0.
 * \param iv_len        The length of the nonce. For AEAD ciphers, this must
 *                      satisfy the constraints imposed by the cipher used.
 *                      For NIST_KW, this must be \c 0.
 * \param ad            The additional data to authenticate. This must be a
 *                      readable buffer of at least \p ad_len Bytes, and may
 *                      be \c NULL is \p ad_len is \c 0.
 * \param ad_len        The length of \p ad. For NIST_KW, this must be \c 0.
 * \param input         The buffer holding the input data. This must be a
 *                      readable buffer of at least \p ilen Bytes, and may be
 *                      \c NULL if \p ilen is \c 0.
 * \param ilen          The length of the input data.
 * \param output        The buffer for the output data. This must be a
 *                      writable buffer of at least \p output_len Bytes, and
 *                      must not be \c NULL.
 * \param output_len    The length of the \p output buffer in Bytes. For AEAD
 *                      ciphers, this must be at least \p ilen + \p tag_len.
 *                      For NIST_KW, this must be at least \p ilen + 8
 *                      (rounded up to a multiple of 8 if KWP is used);
 *                      \p ilen + 15 is always a safe value.
 * \param olen          This will be filled with the actual number of Bytes
 *                      written to the \p output buffer. This must point to a
 *                      writable object of type \c size_t.
 * \param tag_len       The desired length of the authentication tag. For AEAD
 *                      ciphers, this must match the constraints imposed by
 *                      the cipher used, and in particular must not be \c 0.
 *                      For NIST_KW, this must be \c 0.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA on
 *                      parameter-verification failure.
 * \return              A cipher-specific error code on failure.
 */
int mbedtls_cipher_auth_encrypt_ext (
    mbedtls_cipher_context_t* ctx,
    const(ubyte)* iv,
    size_t iv_len,
    const(ubyte)* ad,
    size_t ad_len,
    const(ubyte)* input,
    size_t ilen,
    ubyte* output,
    size_t output_len,
    size_t* olen,
    size_t tag_len);

/**
 * \brief               The authenticated encryption (AEAD/NIST_KW) function.
 *
 * \note                If the data is not authentic, then the output buffer
 *                      is zeroed out to prevent the unauthentic plaintext being
 *                      used, making this interface safer.
 *
 * \note                For AEAD modes, the tag must be appended to the
 *                      ciphertext, as recommended by RFC 5116.
 *                      (NIST_KW doesn't have a separate tag.)
 *
 * \param ctx           The generic cipher context. This must be initialized and
 *                      bound to a key, with an AEAD algorithm or NIST_KW.
 * \param iv            The nonce to use. This must be a readable buffer of
 *                      at least \p iv_len Bytes and may be \c NULL if \p
 *                      iv_len is \c 0.
 * \param iv_len        The length of the nonce. For AEAD ciphers, this must
 *                      satisfy the constraints imposed by the cipher used.
 *                      For NIST_KW, this must be \c 0.
 * \param ad            The additional data to authenticate. This must be a
 *                      readable buffer of at least \p ad_len Bytes, and may
 *                      be \c NULL is \p ad_len is \c 0.
 * \param ad_len        The length of \p ad. For NIST_KW, this must be \c 0.
 * \param input         The buffer holding the input data. This must be a
 *                      readable buffer of at least \p ilen Bytes, and may be
 *                      \c NULL if \p ilen is \c 0.
 * \param ilen          The length of the input data. For AEAD ciphers this
 *                      must be at least \p tag_len. For NIST_KW this must be
 *                      at least \c 8.
 * \param output        The buffer for the output data. This must be a
 *                      writable buffer of at least \p output_len Bytes, and
 *                      may be \c NULL if \p output_len is \c 0.
 * \param output_len    The length of the \p output buffer in Bytes. For AEAD
 *                      ciphers, this must be at least \p ilen - \p tag_len.
 *                      For NIST_KW, this must be at least \p ilen - 8.
 * \param olen          This will be filled with the actual number of Bytes
 *                      written to the \p output buffer. This must point to a
 *                      writable object of type \c size_t.
 * \param tag_len       The actual length of the authentication tag. For AEAD
 *                      ciphers, this must match the constraints imposed by
 *                      the cipher used, and in particular must not be \c 0.
 *                      For NIST_KW, this must be \c 0.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA on
 *                      parameter-verification failure.
 * \return              #MBEDTLS_ERR_CIPHER_AUTH_FAILED if data is not authentic.
 * \return              A cipher-specific error code on failure.
 */
int mbedtls_cipher_auth_decrypt_ext (
    mbedtls_cipher_context_t* ctx,
    const(ubyte)* iv,
    size_t iv_len,
    const(ubyte)* ad,
    size_t ad_len,
    const(ubyte)* input,
    size_t ilen,
    ubyte* output,
    size_t output_len,
    size_t* olen,
    size_t tag_len);
/* MBEDTLS_CIPHER_MODE_AEAD || MBEDTLS_NIST_KW_C */

/* MBEDTLS_CIPHER_H */
