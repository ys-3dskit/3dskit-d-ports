/**
 * \file pk.h
 *
 * \brief Public Key abstraction layer
 */

import core.stdc.config;
import ys3ds.mbedtls.md;
import ys3ds.mbedtls.rsa;
import ys3ds.mbedtls.ecp;
import ys3ds.mbedtls.bignum;

extern (C):

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/** Memory allocation failed. */
enum MBEDTLS_ERR_PK_ALLOC_FAILED = -0x3F80;
/** Type mismatch, eg attempt to encrypt with an ECDSA key */
enum MBEDTLS_ERR_PK_TYPE_MISMATCH = -0x3F00;
/** Bad input parameters to function. */
enum MBEDTLS_ERR_PK_BAD_INPUT_DATA = -0x3E80;
/** Read/write of file failed. */
enum MBEDTLS_ERR_PK_FILE_IO_ERROR = -0x3E00;
/** Unsupported key version */
enum MBEDTLS_ERR_PK_KEY_INVALID_VERSION = -0x3D80;
/** Invalid key tag or value. */
enum MBEDTLS_ERR_PK_KEY_INVALID_FORMAT = -0x3D00;
/** Key algorithm is unsupported (only RSA and EC are supported). */
enum MBEDTLS_ERR_PK_UNKNOWN_PK_ALG = -0x3C80;
/** Private key password can't be empty. */
enum MBEDTLS_ERR_PK_PASSWORD_REQUIRED = -0x3C00;
/** Given private key password does not allow for correct decryption. */
enum MBEDTLS_ERR_PK_PASSWORD_MISMATCH = -0x3B80;
/** The pubkey tag or value is invalid (only RSA and EC are supported). */
enum MBEDTLS_ERR_PK_INVALID_PUBKEY = -0x3B00;
/** The algorithm tag or value is invalid. */
enum MBEDTLS_ERR_PK_INVALID_ALG = -0x3A80;
/** Elliptic curve is unsupported (only NIST curves are supported). */
enum MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE = -0x3A00;
/** Unavailable feature, e.g. RSA disabled for RSA key. */
enum MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE = -0x3980;
/** The buffer contains a valid signature followed by more data. */
enum MBEDTLS_ERR_PK_SIG_LEN_MISMATCH = -0x3900;

/* MBEDTLS_ERR_PK_HW_ACCEL_FAILED is deprecated and should not be used. */
/** PK hardware accelerator failed. */
enum MBEDTLS_ERR_PK_HW_ACCEL_FAILED = -0x3880;

/**
 * \brief          Public key types
 */
enum mbedtls_pk_type_t
{
    MBEDTLS_PK_NONE = 0,
    MBEDTLS_PK_RSA = 1,
    MBEDTLS_PK_ECKEY = 2,
    MBEDTLS_PK_ECKEY_DH = 3,
    MBEDTLS_PK_ECDSA = 4,
    MBEDTLS_PK_RSA_ALT = 5,
    MBEDTLS_PK_RSASSA_PSS = 6,
    MBEDTLS_PK_OPAQUE = 7
}

/**
 * \brief           Options for RSASSA-PSS signature verification.
 *                  See \c mbedtls_rsa_rsassa_pss_verify_ext()
 */
struct mbedtls_pk_rsassa_pss_options
{
    mbedtls_md_type_t mgf1_hash_id;
    int expected_salt_len;
}

/**
 * \brief           Maximum size of a signature made by mbedtls_pk_sign().
 */
/* We need to set MBEDTLS_PK_SIGNATURE_MAX_SIZE to the maximum signature
 * size among the supported signature types. Do it by starting at 0,
 * then incrementally increasing to be large enough for each supported
 * signature mechanism.
 *
 * The resulting value can be 0, for example if MBEDTLS_ECDH_C is enabled
 * (which allows the pk module to be included) but neither MBEDTLS_ECDSA_C
 * nor MBEDTLS_RSA_C nor any opaque signature mechanism (PSA or RSA_ALT).
 */
enum MBEDTLS_PK_SIGNATURE_MAX_SIZE = MBEDTLS_MPI_MAX_SIZE;

/* For RSA, the signature can be as large as the bignum module allows.
 * For RSA_ALT, the signature size is not necessarily tied to what the
 * bignum module can do, but in the absence of any specific setting,
 * we use that (rsa_alt_sign_wrap in pk_wrap will check). */

//enum MBEDTLS_PK_SIGNATURE_MAX_SIZE = MBEDTLS_MPI_MAX_SIZE;

/* For ECDSA, the ecdsa module exports a constant for the maximum
 * signature size. */

/* PSA_SIGNATURE_MAX_SIZE is the maximum size of a signature made
 * through the PSA API in the PSA representation. */

/* The Mbed TLS representation is different for ECDSA signatures:
 * PSA uses the raw concatenation of r and s,
 * whereas Mbed TLS uses the ASN.1 representation (SEQUENCE of two INTEGERs).
 * Add the overhead of ASN.1: up to (1+2) + 2 * (1+2+1) for the
 * types, lengths (represented by up to 2 bytes), and potential leading
 * zeros of the INTEGERs and the SEQUENCE. */

/* defined(MBEDTLS_USE_PSA_CRYPTO) */

/**
 * \brief           Types for interfacing with the debug module
 */
enum mbedtls_pk_debug_type
{
    MBEDTLS_PK_DEBUG_NONE = 0,
    MBEDTLS_PK_DEBUG_MPI = 1,
    MBEDTLS_PK_DEBUG_ECP = 2
}

/**
 * \brief           Item to send to the debug module
 */
struct mbedtls_pk_debug_item
{
    mbedtls_pk_debug_type type;
    const(char)* name;
    void* value;
}

/** Maximum number of item send for debugging, plus 1 */
enum MBEDTLS_PK_DEBUG_MAX_ITEMS = 3;

/**
 * \brief           Public key information and operations
 */
struct mbedtls_pk_info_t;

/**
 * \brief           Public key container
 */
struct mbedtls_pk_context
{
    const(mbedtls_pk_info_t)* pk_info; /**< Public key information         */
    void* pk_ctx; /**< Underlying public key context  */
}

/**
 * \brief           Context for resuming operations
 */

/**< Public key information         */
/**< Underlying restart context     */

/* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
/* Now we can declare functions that take a pointer to that */
alias mbedtls_pk_restart_ctx = void;
/* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

/**
 * \brief           Types for RSA-alt abstraction
 */
alias mbedtls_pk_rsa_alt_decrypt_func = int function (
    void* ctx,
    int mode,
    size_t* olen,
    const(ubyte)* input,
    ubyte* output,
    size_t output_max_len);
alias mbedtls_pk_rsa_alt_sign_func = int function (
    void* ctx,
    int function (void*, ubyte*, size_t) f_rng,
    void* p_rng,
    int mode,
    mbedtls_md_type_t md_alg,
    uint hashlen,
    const(ubyte)* hash,
    ubyte* sig);
alias mbedtls_pk_rsa_alt_key_len_func = c_ulong function (void* ctx);
/* MBEDTLS_PK_RSA_ALT_SUPPORT */

/**
 * \brief           Return information associated with the given PK type
 *
 * \param pk_type   PK type to search for.
 *
 * \return          The PK info associated with the type or NULL if not found.
 */
const(mbedtls_pk_info_t)* mbedtls_pk_info_from_type (mbedtls_pk_type_t pk_type);

/**
 * \brief           Initialize a #mbedtls_pk_context (as NONE).
 *
 * \param ctx       The context to initialize.
 *                  This must not be \c NULL.
 */
void mbedtls_pk_init (mbedtls_pk_context* ctx);

/**
 * \brief           Free the components of a #mbedtls_pk_context.
 *
 * \param ctx       The context to clear. It must have been initialized.
 *                  If this is \c NULL, this function does nothing.
 *
 * \note            For contexts that have been set up with
 *                  mbedtls_pk_setup_opaque(), this does not free the underlying
 *                  PSA key and you still need to call psa_destroy_key()
 *                  independently if you want to destroy that key.
 */
void mbedtls_pk_free (mbedtls_pk_context* ctx);

/**
 * \brief           Initialize a restart context
 *
 * \param ctx       The context to initialize.
 *                  This must not be \c NULL.
 */

/**
 * \brief           Free the components of a restart context
 *
 * \param ctx       The context to clear. It must have been initialized.
 *                  If this is \c NULL, this function does nothing.
 */

/* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

/**
 * \brief           Initialize a PK context with the information given
 *                  and allocates the type-specific PK subcontext.
 *
 * \param ctx       Context to initialize. It must not have been set
 *                  up yet (type #MBEDTLS_PK_NONE).
 * \param info      Information to use
 *
 * \return          0 on success,
 *                  MBEDTLS_ERR_PK_BAD_INPUT_DATA on invalid input,
 *                  MBEDTLS_ERR_PK_ALLOC_FAILED on allocation failure.
 *
 * \note            For contexts holding an RSA-alt key, use
 *                  \c mbedtls_pk_setup_rsa_alt() instead.
 */
int mbedtls_pk_setup (mbedtls_pk_context* ctx, const(mbedtls_pk_info_t)* info);

/**
 * \brief           Initialize a PK context to wrap a PSA key.
 *
 * \note            This function replaces mbedtls_pk_setup() for contexts
 *                  that wrap a (possibly opaque) PSA key instead of
 *                  storing and manipulating the key material directly.
 *
 * \param ctx       The context to initialize. It must be empty (type NONE).
 * \param key       The PSA key to wrap, which must hold an ECC key pair
 *                  (see notes below).
 *
 * \note            The wrapped key must remain valid as long as the
 *                  wrapping PK context is in use, that is at least between
 *                  the point this function is called and the point
 *                  mbedtls_pk_free() is called on this context. The wrapped
 *                  key might then be independently used or destroyed.
 *
 * \note            This function is currently only available for ECC key
 *                  pairs (that is, ECC keys containing private key material).
 *                  Support for other key types may be added later.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_PK_BAD_INPUT_DATA on invalid input
 *                  (context already used, invalid key identifier).
 * \return          #MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE if the key is not an
 *                  ECC key pair.
 * \return          #MBEDTLS_ERR_PK_ALLOC_FAILED on allocation failure.
 */

/* MBEDTLS_USE_PSA_CRYPTO */

/**
 * \brief           Initialize an RSA-alt context
 *
 * \param ctx       Context to initialize. It must not have been set
 *                  up yet (type #MBEDTLS_PK_NONE).
 * \param key       RSA key pointer
 * \param decrypt_func  Decryption function
 * \param sign_func     Signing function
 * \param key_len_func  Function returning key length in bytes
 *
 * \return          0 on success, or MBEDTLS_ERR_PK_BAD_INPUT_DATA if the
 *                  context wasn't already initialized as RSA_ALT.
 *
 * \note            This function replaces \c mbedtls_pk_setup() for RSA-alt.
 */
int mbedtls_pk_setup_rsa_alt (
    mbedtls_pk_context* ctx,
    void* key,
    mbedtls_pk_rsa_alt_decrypt_func decrypt_func,
    mbedtls_pk_rsa_alt_sign_func sign_func,
    mbedtls_pk_rsa_alt_key_len_func key_len_func);
/* MBEDTLS_PK_RSA_ALT_SUPPORT */

/**
 * \brief           Get the size in bits of the underlying key
 *
 * \param ctx       The context to query. It must have been initialized.
 *
 * \return          Key size in bits, or 0 on error
 */
size_t mbedtls_pk_get_bitlen (const(mbedtls_pk_context)* ctx);

/**
 * \brief           Get the length in bytes of the underlying key
 *
 * \param ctx       The context to query. It must have been initialized.
 *
 * \return          Key length in bytes, or 0 on error
 */
size_t mbedtls_pk_get_len (const(mbedtls_pk_context)* ctx);

/**
 * \brief           Tell if a context can do the operation given by type
 *
 * \param ctx       The context to query. It must have been initialized.
 * \param type      The desired type.
 *
 * \return          1 if the context can do operations on the given type.
 * \return          0 if the context cannot do the operations on the given
 *                  type. This is always the case for a context that has
 *                  been initialized but not set up, or that has been
 *                  cleared with mbedtls_pk_free().
 */
int mbedtls_pk_can_do (const(mbedtls_pk_context)* ctx, mbedtls_pk_type_t type);

/**
 * \brief           Verify signature (including padding if relevant).
 *
 * \param ctx       The PK context to use. It must have been set up.
 * \param md_alg    Hash algorithm used (see notes)
 * \param hash      Hash of the message to sign
 * \param hash_len  Hash length or 0 (see notes)
 * \param sig       Signature to verify
 * \param sig_len   Signature length
 *
 * \return          0 on success (signature is valid),
 *                  #MBEDTLS_ERR_PK_SIG_LEN_MISMATCH if there is a valid
 *                  signature in \p sig but its length is less than \p sig_len,
 *                  or a specific error code.
 *
 * \note            For RSA keys, the default padding type is PKCS#1 v1.5.
 *                  Use \c mbedtls_pk_verify_ext( MBEDTLS_PK_RSASSA_PSS, ... )
 *                  to verify RSASSA_PSS signatures.
 *
 * \note            If #MBEDTLS_USE_PSA_CRYPTO is enabled, the PSA crypto
 *                  subsystem must have been initialized by calling
 *                  psa_crypto_init() before calling this function,
 *                  if the key might be an ECC (ECDSA) key.
 *
 * \note            If hash_len is 0, then the length associated with md_alg
 *                  is used instead, or an error returned if it is invalid.
 *
 * \note            md_alg may be MBEDTLS_MD_NONE, only if hash_len != 0
 */
int mbedtls_pk_verify (
    mbedtls_pk_context* ctx,
    mbedtls_md_type_t md_alg,
    const(ubyte)* hash,
    size_t hash_len,
    const(ubyte)* sig,
    size_t sig_len);

/**
 * \brief           Restartable version of \c mbedtls_pk_verify()
 *
 * \note            Performs the same job as \c mbedtls_pk_verify(), but can
 *                  return early and restart according to the limit set with
 *                  \c mbedtls_ecp_set_max_ops() to reduce blocking for ECC
 *                  operations. For RSA, same as \c mbedtls_pk_verify().
 *
 * \param ctx       The PK context to use. It must have been set up.
 * \param md_alg    Hash algorithm used (see notes)
 * \param hash      Hash of the message to sign
 * \param hash_len  Hash length or 0 (see notes)
 * \param sig       Signature to verify
 * \param sig_len   Signature length
 * \param rs_ctx    Restart context (NULL to disable restart)
 *
 * \return          See \c mbedtls_pk_verify(), or
 * \return          #MBEDTLS_ERR_ECP_IN_PROGRESS if maximum number of
 *                  operations was reached: see \c mbedtls_ecp_set_max_ops().
 */
int mbedtls_pk_verify_restartable (
    mbedtls_pk_context* ctx,
    mbedtls_md_type_t md_alg,
    const(ubyte)* hash,
    size_t hash_len,
    const(ubyte)* sig,
    size_t sig_len,
    mbedtls_pk_restart_ctx* rs_ctx);

/**
 * \brief           Verify signature, with options.
 *                  (Includes verification of the padding depending on type.)
 *
 * \param type      Signature type (inc. possible padding type) to verify
 * \param options   Pointer to type-specific options, or NULL
 * \param ctx       The PK context to use. It must have been set up.
 * \param md_alg    Hash algorithm used (see notes)
 * \param hash      Hash of the message to sign
 * \param hash_len  Hash length or 0 (see notes)
 * \param sig       Signature to verify
 * \param sig_len   Signature length
 *
 * \return          0 on success (signature is valid),
 *                  #MBEDTLS_ERR_PK_TYPE_MISMATCH if the PK context can't be
 *                  used for this type of signatures,
 *                  #MBEDTLS_ERR_PK_SIG_LEN_MISMATCH if there is a valid
 *                  signature in \p sig but its length is less than \p sig_len,
 *                  or a specific error code.
 *
 * \note            If hash_len is 0, then the length associated with md_alg
 *                  is used instead, or an error returned if it is invalid.
 *
 * \note            md_alg may be MBEDTLS_MD_NONE, only if hash_len != 0
 *
 * \note            If type is MBEDTLS_PK_RSASSA_PSS, then options must point
 *                  to a mbedtls_pk_rsassa_pss_options structure,
 *                  otherwise it must be NULL.
 */
int mbedtls_pk_verify_ext (
    mbedtls_pk_type_t type,
    const(void)* options,
    mbedtls_pk_context* ctx,
    mbedtls_md_type_t md_alg,
    const(ubyte)* hash,
    size_t hash_len,
    const(ubyte)* sig,
    size_t sig_len);

/**
 * \brief           Make signature, including padding if relevant.
 *
 * \param ctx       The PK context to use. It must have been set up
 *                  with a private key.
 * \param md_alg    Hash algorithm used (see notes)
 * \param hash      Hash of the message to sign
 * \param hash_len  Hash length or 0 (see notes)
 * \param sig       Place to write the signature.
 *                  It must have enough room for the signature.
 *                  #MBEDTLS_PK_SIGNATURE_MAX_SIZE is always enough.
 *                  You may use a smaller buffer if it is large enough
 *                  given the key type.
 * \param sig_len   On successful return,
 *                  the number of bytes written to \p sig.
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \return          0 on success, or a specific error code.
 *
 * \note            For RSA keys, the default padding type is PKCS#1 v1.5.
 *                  There is no interface in the PK module to make RSASSA-PSS
 *                  signatures yet.
 *
 * \note            If hash_len is 0, then the length associated with md_alg
 *                  is used instead, or an error returned if it is invalid.
 *
 * \note            For RSA, md_alg may be MBEDTLS_MD_NONE if hash_len != 0.
 *                  For ECDSA, md_alg may never be MBEDTLS_MD_NONE.
 */
int mbedtls_pk_sign (
    mbedtls_pk_context* ctx,
    mbedtls_md_type_t md_alg,
    const(ubyte)* hash,
    size_t hash_len,
    ubyte* sig,
    size_t* sig_len,
    int function (void*, ubyte*, size_t) f_rng,
    void* p_rng);

/**
 * \brief           Restartable version of \c mbedtls_pk_sign()
 *
 * \note            Performs the same job as \c mbedtls_pk_sign(), but can
 *                  return early and restart according to the limit set with
 *                  \c mbedtls_ecp_set_max_ops() to reduce blocking for ECC
 *                  operations. For RSA, same as \c mbedtls_pk_sign().
 *
 * \param ctx       The PK context to use. It must have been set up
 *                  with a private key.
 * \param md_alg    Hash algorithm used (see notes for mbedtls_pk_sign())
 * \param hash      Hash of the message to sign
 * \param hash_len  Hash length or 0 (see notes for mbedtls_pk_sign())
 * \param sig       Place to write the signature.
 *                  It must have enough room for the signature.
 *                  #MBEDTLS_PK_SIGNATURE_MAX_SIZE is always enough.
 *                  You may use a smaller buffer if it is large enough
 *                  given the key type.
 * \param sig_len   On successful return,
 *                  the number of bytes written to \p sig.
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 * \param rs_ctx    Restart context (NULL to disable restart)
 *
 * \return          See \c mbedtls_pk_sign().
 * \return          #MBEDTLS_ERR_ECP_IN_PROGRESS if maximum number of
 *                  operations was reached: see \c mbedtls_ecp_set_max_ops().
 */
int mbedtls_pk_sign_restartable (
    mbedtls_pk_context* ctx,
    mbedtls_md_type_t md_alg,
    const(ubyte)* hash,
    size_t hash_len,
    ubyte* sig,
    size_t* sig_len,
    int function (void*, ubyte*, size_t) f_rng,
    void* p_rng,
    mbedtls_pk_restart_ctx* rs_ctx);

/**
 * \brief           Decrypt message (including padding if relevant).
 *
 * \param ctx       The PK context to use. It must have been set up
 *                  with a private key.
 * \param input     Input to decrypt
 * \param ilen      Input size
 * \param output    Decrypted output
 * \param olen      Decrypted message length
 * \param osize     Size of the output buffer
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \note            For RSA keys, the default padding type is PKCS#1 v1.5.
 *
 * \return          0 on success, or a specific error code.
 */
int mbedtls_pk_decrypt (
    mbedtls_pk_context* ctx,
    const(ubyte)* input,
    size_t ilen,
    ubyte* output,
    size_t* olen,
    size_t osize,
    int function (void*, ubyte*, size_t) f_rng,
    void* p_rng);

/**
 * \brief           Encrypt message (including padding if relevant).
 *
 * \param ctx       The PK context to use. It must have been set up.
 * \param input     Message to encrypt
 * \param ilen      Message size
 * \param output    Encrypted output
 * \param olen      Encrypted output length
 * \param osize     Size of the output buffer
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \note            For RSA keys, the default padding type is PKCS#1 v1.5.
 *
 * \return          0 on success, or a specific error code.
 */
int mbedtls_pk_encrypt (
    mbedtls_pk_context* ctx,
    const(ubyte)* input,
    size_t ilen,
    ubyte* output,
    size_t* olen,
    size_t osize,
    int function (void*, ubyte*, size_t) f_rng,
    void* p_rng);

/**
 * \brief           Check if a public-private pair of keys matches.
 *
 * \param pub       Context holding a public key.
 * \param prv       Context holding a private (and public) key.
 *
 * \return          \c 0 on success (keys were checked and match each other).
 * \return          #MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE if the keys could not
 *                  be checked - in that case they may or may not match.
 * \return          #MBEDTLS_ERR_PK_BAD_INPUT_DATA if a context is invalid.
 * \return          Another non-zero value if the keys do not match.
 */
int mbedtls_pk_check_pair (const(mbedtls_pk_context)* pub, const(mbedtls_pk_context)* prv);

/**
 * \brief           Export debug information
 *
 * \param ctx       The PK context to use. It must have been initialized.
 * \param items     Place to write debug items
 *
 * \return          0 on success or MBEDTLS_ERR_PK_BAD_INPUT_DATA
 */
int mbedtls_pk_debug (const(mbedtls_pk_context)* ctx, mbedtls_pk_debug_item* items);

/**
 * \brief           Access the type name
 *
 * \param ctx       The PK context to use. It must have been initialized.
 *
 * \return          Type name on success, or "invalid PK"
 */
const(char)* mbedtls_pk_get_name (const(mbedtls_pk_context)* ctx);

/**
 * \brief           Get the key type
 *
 * \param ctx       The PK context to use. It must have been initialized.
 *
 * \return          Type on success.
 * \return          #MBEDTLS_PK_NONE for a context that has not been set up.
 */
mbedtls_pk_type_t mbedtls_pk_get_type (const(mbedtls_pk_context)* ctx);

/**
 * Quick access to an RSA context inside a PK context.
 *
 * \warning This function can only be used when the type of the context, as
 * returned by mbedtls_pk_get_type(), is #MBEDTLS_PK_RSA.
 * Ensuring that is the caller's responsibility.
 * Alternatively, you can check whether this function returns NULL.
 *
 * \return The internal RSA context held by the PK context, or NULL.
 */
pragma(inline, true) extern(D)
mbedtls_rsa_context* mbedtls_pk_rsa (const mbedtls_pk_context pk)
{
  switch (mbedtls_pk_get_type(&pk)) with (mbedtls_pk_type_t)
  {
    case MBEDTLS_PK_RSA:
      return cast(mbedtls_rsa_context*) pk.pk_ctx;

    default:
      return null;
  }
}
/* MBEDTLS_RSA_C */

/**
 * Quick access to an EC context inside a PK context.
 *
 * \warning This function can only be used when the type of the context, as
 * returned by mbedtls_pk_get_type(), is #MBEDTLS_PK_ECKEY,
 * #MBEDTLS_PK_ECKEY_DH, or #MBEDTLS_PK_ECDSA.
 * Ensuring that is the caller's responsibility.
 * Alternatively, you can check whether this function returns NULL.
 *
 * \return The internal EC context held by the PK context, or NULL.
 */
pragma(inline, true) extern(D)
mbedtls_ecp_keypair* mbedtls_pk_ec (const mbedtls_pk_context pk)
{
  switch (mbedtls_pk_get_type(&pk)) with (mbedtls_pk_type_t)
  {
    case MBEDTLS_PK_ECKEY:
    case MBEDTLS_PK_ECKEY_DH:
    case MBEDTLS_PK_ECDSA:
      return cast(mbedtls_ecp_keypair*) pk.pk_ctx;

    default:
      return null;
  }
}
/* MBEDTLS_ECP_C */

/** \ingroup pk_module */
/**
 * \brief           Parse a private key in PEM or DER format
 *
 * \param ctx       The PK context to fill. It must have been initialized
 *                  but not set up.
 * \param key       Input buffer to parse.
 *                  The buffer must contain the input exactly, with no
 *                  extra trailing material. For PEM, the buffer must
 *                  contain a null-terminated string.
 * \param keylen    Size of \b key in bytes.
 *                  For PEM data, this includes the terminating null byte,
 *                  so \p keylen must be equal to `strlen(key) + 1`.
 * \param pwd       Optional password for decryption.
 *                  Pass \c NULL if expecting a non-encrypted key.
 *                  Pass a string of \p pwdlen bytes if expecting an encrypted
 *                  key; a non-encrypted key will also be accepted.
 *                  The empty password is not supported.
 * \param pwdlen    Size of the password in bytes.
 *                  Ignored if \p pwd is \c NULL.
 *
 * \note            On entry, ctx must be empty, either freshly initialised
 *                  with mbedtls_pk_init() or reset with mbedtls_pk_free(). If you need a
 *                  specific key type, check the result with mbedtls_pk_can_do().
 *
 * \note            The key is also checked for correctness.
 *
 * \return          0 if successful, or a specific PK or PEM error code
 */
int mbedtls_pk_parse_key (
    mbedtls_pk_context* ctx,
    const(ubyte)* key,
    size_t keylen,
    const(ubyte)* pwd,
    size_t pwdlen);

/** \ingroup pk_module */
/**
 * \brief           Parse a public key in PEM or DER format
 *
 * \param ctx       The PK context to fill. It must have been initialized
 *                  but not set up.
 * \param key       Input buffer to parse.
 *                  The buffer must contain the input exactly, with no
 *                  extra trailing material. For PEM, the buffer must
 *                  contain a null-terminated string.
 * \param keylen    Size of \b key in bytes.
 *                  For PEM data, this includes the terminating null byte,
 *                  so \p keylen must be equal to `strlen(key) + 1`.
 *
 * \note            On entry, ctx must be empty, either freshly initialised
 *                  with mbedtls_pk_init() or reset with mbedtls_pk_free(). If you need a
 *                  specific key type, check the result with mbedtls_pk_can_do().
 *
 * \note            The key is also checked for correctness.
 *
 * \return          0 if successful, or a specific PK or PEM error code
 */
int mbedtls_pk_parse_public_key (
    mbedtls_pk_context* ctx,
    const(ubyte)* key,
    size_t keylen);

/** \ingroup pk_module */
/**
 * \brief           Load and parse a private key
 *
 * \param ctx       The PK context to fill. It must have been initialized
 *                  but not set up.
 * \param path      filename to read the private key from
 * \param password  Optional password to decrypt the file.
 *                  Pass \c NULL if expecting a non-encrypted key.
 *                  Pass a null-terminated string if expecting an encrypted
 *                  key; a non-encrypted key will also be accepted.
 *                  The empty password is not supported.
 *
 * \note            On entry, ctx must be empty, either freshly initialised
 *                  with mbedtls_pk_init() or reset with mbedtls_pk_free(). If you need a
 *                  specific key type, check the result with mbedtls_pk_can_do().
 *
 * \note            The key is also checked for correctness.
 *
 * \return          0 if successful, or a specific PK or PEM error code
 */
int mbedtls_pk_parse_keyfile (
    mbedtls_pk_context* ctx,
    const(char)* path,
    const(char)* password);

/** \ingroup pk_module */
/**
 * \brief           Load and parse a public key
 *
 * \param ctx       The PK context to fill. It must have been initialized
 *                  but not set up.
 * \param path      filename to read the public key from
 *
 * \note            On entry, ctx must be empty, either freshly initialised
 *                  with mbedtls_pk_init() or reset with mbedtls_pk_free(). If
 *                  you need a specific key type, check the result with
 *                  mbedtls_pk_can_do().
 *
 * \note            The key is also checked for correctness.
 *
 * \return          0 if successful, or a specific PK or PEM error code
 */
int mbedtls_pk_parse_public_keyfile (mbedtls_pk_context* ctx, const(char)* path);
/* MBEDTLS_FS_IO */
/* MBEDTLS_PK_PARSE_C */

/**
 * \brief           Write a private key to a PKCS#1 or SEC1 DER structure
 *                  Note: data is written at the end of the buffer! Use the
 *                        return value to determine where you should start
 *                        using the buffer
 *
 * \param ctx       PK context which must contain a valid private key.
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          length of data written if successful, or a specific
 *                  error code
 */
int mbedtls_pk_write_key_der (mbedtls_pk_context* ctx, ubyte* buf, size_t size);

/**
 * \brief           Write a public key to a SubjectPublicKeyInfo DER structure
 *                  Note: data is written at the end of the buffer! Use the
 *                        return value to determine where you should start
 *                        using the buffer
 *
 * \param ctx       PK context which must contain a valid public or private key.
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          length of data written if successful, or a specific
 *                  error code
 */
int mbedtls_pk_write_pubkey_der (mbedtls_pk_context* ctx, ubyte* buf, size_t size);

/**
 * \brief           Write a public key to a PEM string
 *
 * \param ctx       PK context which must contain a valid public or private key.
 * \param buf       Buffer to write to. The output includes a
 *                  terminating null byte.
 * \param size      Size of the buffer in bytes.
 *
 * \return          0 if successful, or a specific error code
 */
int mbedtls_pk_write_pubkey_pem (mbedtls_pk_context* ctx, ubyte* buf, size_t size);

/**
 * \brief           Write a private key to a PKCS#1 or SEC1 PEM string
 *
 * \param ctx       PK context which must contain a valid private key.
 * \param buf       Buffer to write to. The output includes a
 *                  terminating null byte.
 * \param size      Size of the buffer in bytes.
 *
 * \return          0 if successful, or a specific error code
 */
int mbedtls_pk_write_key_pem (mbedtls_pk_context* ctx, ubyte* buf, size_t size);
/* MBEDTLS_PEM_WRITE_C */
/* MBEDTLS_PK_WRITE_C */

/*
 * WARNING: Low-level functions. You probably do not want to use these unless
 *          you are certain you do ;)
 */

/**
 * \brief           Parse a SubjectPublicKeyInfo DER structure
 *
 * \param p         the position in the ASN.1 data
 * \param end       end of the buffer
 * \param pk        The PK context to fill. It must have been initialized
 *                  but not set up.
 *
 * \return          0 if successful, or a specific PK error code
 */
int mbedtls_pk_parse_subpubkey (
    ubyte** p,
    const(ubyte)* end,
    mbedtls_pk_context* pk);
/* MBEDTLS_PK_PARSE_C */

/**
 * \brief           Write a subjectPublicKey to ASN.1 data
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param key       PK context which must contain a valid public or private key.
 *
 * \return          the length written or a negative error code
 */
int mbedtls_pk_write_pubkey (
    ubyte** p,
    ubyte* start,
    const(mbedtls_pk_context)* key);
/* MBEDTLS_PK_WRITE_C */

/*
 * Internal module functions. You probably do not want to use these unless you
 * know you do.
 */
int mbedtls_pk_load_file (const(char)* path, ubyte** buf, size_t* n);

/**
 * \brief           Turn an EC key into an opaque one.
 *
 * \warning         This is a temporary utility function for tests. It might
 *                  change or be removed at any time without notice.
 *
 * \note            Only ECDSA keys are supported so far. Signing with the
 *                  specified hash is the only allowed use of that key.
 *
 * \param pk        Input: the EC key to import to a PSA key.
 *                  Output: a PK context wrapping that PSA key.
 * \param key       Output: a PSA key identifier.
 *                  It's the caller's responsibility to call
 *                  psa_destroy_key() on that key identifier after calling
 *                  mbedtls_pk_free() on the PK context.
 * \param hash_alg  The hash algorithm to allow for use with that key.
 *
 * \return          \c 0 if successful.
 * \return          An Mbed TLS error code otherwise.
 */

/* MBEDTLS_USE_PSA_CRYPTO */

/* MBEDTLS_PK_H */
