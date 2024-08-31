module ys3ds.mbedtls.ssl_internal;

/**
 * \file ssl_internal.h
 *
 * \brief Internal functions shared by the SSL modules
 */

import ys3ds.mbedtls.ssl;
import ys3ds.mbedtls.ssl_ciphersuites;
import ys3ds.mbedtls.dhm;
import ys3ds.mbedtls.ecdh;
import ys3ds.mbedtls.ecp;
import ys3ds.mbedtls.x509;
import ys3ds.mbedtls.x509_crt;
import ys3ds.mbedtls.x509_crl;
import ys3ds.mbedtls.md5;
import ys3ds.mbedtls.sha1;
import ys3ds.mbedtls.sha256;
import ys3ds.mbedtls.sha512;
import ys3ds.mbedtls.md;
import ys3ds.mbedtls.pk;
import ys3ds.mbedtls.cipher;

extern (C) @nogc nothrow:

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/* MBEDTLS_USE_PSA_CRYPTO */

/* Determine minimum supported version */
enum MBEDTLS_SSL_MIN_MAJOR_VERSION = MBEDTLS_SSL_MAJOR_VERSION_3;

enum MBEDTLS_SSL_MIN_MINOR_VERSION = MBEDTLS_SSL_MINOR_VERSION_1;

/* MBEDTLS_SSL_PROTO_TLS1_2 */
/* MBEDTLS_SSL_PROTO_TLS1_1 */
/* MBEDTLS_SSL_PROTO_TLS1   */
/* MBEDTLS_SSL_PROTO_SSL3   */

enum MBEDTLS_SSL_MIN_VALID_MINOR_VERSION = MBEDTLS_SSL_MINOR_VERSION_1;
enum MBEDTLS_SSL_MIN_VALID_MAJOR_VERSION = MBEDTLS_SSL_MAJOR_VERSION_3;

/* Determine maximum supported version */
enum MBEDTLS_SSL_MAX_MAJOR_VERSION = MBEDTLS_SSL_MAJOR_VERSION_3;

enum MBEDTLS_SSL_MAX_MINOR_VERSION = MBEDTLS_SSL_MINOR_VERSION_3;

/* MBEDTLS_SSL_PROTO_SSL3   */
/* MBEDTLS_SSL_PROTO_TLS1   */
/* MBEDTLS_SSL_PROTO_TLS1_1 */
/* MBEDTLS_SSL_PROTO_TLS1_2 */

/* Shorthand for restartable ECC */

enum MBEDTLS_SSL_INITIAL_HANDSHAKE = 0;
enum MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS = 1; /* In progress */
enum MBEDTLS_SSL_RENEGOTIATION_DONE = 2; /* Done or aborted */
enum MBEDTLS_SSL_RENEGOTIATION_PENDING = 3; /* Requested (server only) */

/*
 * DTLS retransmission states, see RFC 6347 4.2.4
 *
 * The SENDING state is merged in PREPARING for initial sends,
 * but is distinct for resends.
 *
 * Note: initial state is wrong for server, but is not used anyway.
 */
enum MBEDTLS_SSL_RETRANS_PREPARING = 0;
enum MBEDTLS_SSL_RETRANS_SENDING = 1;
enum MBEDTLS_SSL_RETRANS_WAITING = 2;
enum MBEDTLS_SSL_RETRANS_FINISHED = 3;

/*
 * Allow extra bytes for record, authentication and encryption overhead:
 * counter (8) + header (5) + IV(16) + MAC (16-48) + padding (0-256)
 * and allow for a maximum of 1024 of compression expansion if
 * enabled.
 */

enum MBEDTLS_SSL_COMPRESSION_ADD = 0;

/* This macro determines whether CBC is supported. */

/* This macro determines whether the CBC construct used in TLS 1.0-1.2 (as
 * opposed to the very different CBC construct used in SSLv3) is supported. */

/* Ciphersuites using HMAC */
enum MBEDTLS_SSL_MAC_ADD = 48; /* SHA-384 used for HMAC */

/* SHA-256 used for HMAC */

/* SHA-1   used for HMAC */

/* MBEDTLS_SSL_SOME_MODES_USE_MAC */
/* AEAD ciphersuites: GCM and CCM use a 128 bits tag */

enum MBEDTLS_SSL_PADDING_ADD = 256;

enum MBEDTLS_SSL_MAX_CID_EXPANSION = 0;

enum MBEDTLS_SSL_PAYLOAD_OVERHEAD = MBEDTLS_SSL_COMPRESSION_ADD + MBEDTLS_MAX_IV_LENGTH + MBEDTLS_SSL_MAC_ADD + MBEDTLS_SSL_PADDING_ADD + MBEDTLS_SSL_MAX_CID_EXPANSION;

enum MBEDTLS_SSL_IN_PAYLOAD_LEN = MBEDTLS_SSL_PAYLOAD_OVERHEAD + MBEDTLS_SSL_IN_CONTENT_LEN;

enum MBEDTLS_SSL_OUT_PAYLOAD_LEN = MBEDTLS_SSL_PAYLOAD_OVERHEAD + MBEDTLS_SSL_OUT_CONTENT_LEN;

/* The maximum number of buffered handshake messages. */
enum MBEDTLS_SSL_MAX_BUFFERED_HS = 4;

/* Maximum length we can advertise as our max content length for
   RFC 6066 max_fragment_length extension negotiation purposes
   (the lesser of both sizes, if they are unequal.)
 */
enum MBEDTLS_TLS_EXT_ADV_CONTENT_LEN = (MBEDTLS_SSL_IN_CONTENT_LEN > MBEDTLS_SSL_OUT_CONTENT_LEN) ? MBEDTLS_SSL_OUT_CONTENT_LEN : MBEDTLS_SSL_IN_CONTENT_LEN;

/* Maximum size in bytes of list in sig-hash algorithm ext., RFC 5246 */
enum MBEDTLS_SSL_MAX_SIG_HASH_ALG_LIST_LEN = 65534;

/* Maximum size in bytes of list in supported elliptic curve ext., RFC 4492 */
enum MBEDTLS_SSL_MAX_CURVE_LIST_LEN = 65535;

/*
 * Check that we obey the standard's message size bounds
 */

/* Calculate buffer sizes */

/* Note: Even though the TLS record header is only 5 bytes
   long, we're internally using 8 bytes to store the
   implicit sequence number. */
enum MBEDTLS_SSL_HEADER_LEN = 13;

enum MBEDTLS_SSL_IN_BUFFER_LEN = MBEDTLS_SSL_HEADER_LEN + MBEDTLS_SSL_IN_PAYLOAD_LEN;

enum MBEDTLS_SSL_OUT_BUFFER_LEN = MBEDTLS_SSL_HEADER_LEN + MBEDTLS_SSL_OUT_PAYLOAD_LEN;

/* Compression buffer holds both IN and OUT buffers, so should be size of the larger */

/*
 * TLS extension flags (for extensions with outgoing ServerHello content
 * that need it (e.g. for RENEGOTIATION_INFO the server already knows because
 * of state of the renegotiation flag, so no indicator is required)
 */
enum MBEDTLS_TLS_EXT_SUPPORTED_POINT_FORMATS_PRESENT = 1 << 0;
enum MBEDTLS_TLS_EXT_ECJPAKE_KKPP_OK = 1 << 1;

/**
 * \brief        This function checks if the remaining size in a buffer is
 *               greater or equal than a needed space.
 *
 * \param cur    Pointer to the current position in the buffer.
 * \param end    Pointer to one past the end of the buffer.
 * \param need   Needed space in bytes.
 *
 * \return       Zero if the needed space is available in the buffer, non-zero
 *               otherwise.
 */
int mbedtls_ssl_chk_buf_ptr (const(ubyte)* cur, const(ubyte)* end, size_t need);

/**
 * \brief        This macro checks if the remaining size in a buffer is
 *               greater or equal than a needed space. If it is not the case,
 *               it returns an SSL_BUFFER_TOO_SMALL error.
 *
 * \param cur    Pointer to the current position in the buffer.
 * \param end    Pointer to one past the end of the buffer.
 * \param need   Needed space in bytes.
 *
 */

/*
 * Abstraction for a grid of allowed signature-hash-algorithm pairs.
 */
struct mbedtls_ssl_sig_hash_set_t
{
    /* At the moment, we only need to remember a single suitable
     * hash algorithm per signature algorithm. As long as that's
     * the case - and we don't need a general lookup function -
     * we can implement the sig-hash-set as a map from signatures
     * to hash algorithms. */
    mbedtls_md_type_t rsa;
    mbedtls_md_type_t ecdsa;
}

/* MBEDTLS_SSL_PROTO_TLS1_2 &&
   MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

alias mbedtls_ssl_tls_prf_cb = int function (
    const(ubyte)* secret,
    size_t slen,
    const(char)* label,
    const(ubyte)* random,
    size_t rlen,
    ubyte* dstbuf,
    size_t dlen);

/* cipher.h exports the maximum IV, key and block length from
 * all ciphers enabled in the config, regardless of whether those
 * ciphers are actually usable in SSL/TLS. Notably, XTS is enabled
 * in the default configuration and uses 64 Byte keys, but it is
 * not used for record protection in SSL/TLS.
 *
 * In order to prevent unnecessary inflation of key structures,
 * we introduce SSL-specific variants of the max-{key,block,IV}
 * macros here which are meant to only take those ciphers into
 * account which can be negotiated in SSL/TLS.
 *
 * Since the current definitions of MBEDTLS_MAX_{KEY|BLOCK|IV}_LENGTH
 * in cipher.h are rough overapproximations of the real maxima, here
 * we content ourselves with replicating those overapproximations
 * for the maximum block and IV length, and excluding XTS from the
 * computation of the maximum key length. */
enum MBEDTLS_SSL_MAX_BLOCK_LENGTH = 16;
enum MBEDTLS_SSL_MAX_IV_LENGTH = 16;
enum MBEDTLS_SSL_MAX_KEY_LENGTH = 32;

/**
 * \brief   The data structure holding the cryptographic material (key and IV)
 *          used for record protection in TLS 1.3.
 */
struct mbedtls_ssl_key_set
{
    /*! The key for client->server records. */
    ubyte[MBEDTLS_SSL_MAX_KEY_LENGTH] client_write_key;
    /*! The key for server->client records. */
    ubyte[MBEDTLS_SSL_MAX_KEY_LENGTH] server_write_key;
    /*! The IV  for client->server records. */
    ubyte[MBEDTLS_SSL_MAX_IV_LENGTH] client_write_iv;
    /*! The IV  for server->client records. */
    ubyte[MBEDTLS_SSL_MAX_IV_LENGTH] server_write_iv;

    size_t key_len; /*!< The length of client_write_key and
     *   server_write_key, in Bytes. */
    size_t iv_len; /*!< The length of client_write_iv and
     *   server_write_iv, in Bytes. */
}

/*
 * This structure contains the parameters only needed during handshake.
 */
struct mbedtls_ssl_handshake_params
{
    /*
     * Handshake specific crypto variables
     */

    ubyte max_major_ver; /*!< max. major version client*/
    ubyte max_minor_ver; /*!< max. minor version client*/
    ubyte resume; /*!<  session resume indicator*/
    ubyte cli_exts; /*!< client extension presence*/

    ubyte sni_authmode; /*!< authmode from SNI callback     */

    ubyte new_session_ticket; /*!< use NewSessionTicket?    */
    /* MBEDTLS_SSL_SESSION_TICKETS */

    ubyte extended_ms; /*!< use Extended Master Secret? */

    /*!< an asynchronous operation is in progress */
    /* MBEDTLS_SSL_ASYNC_PRIVATE */

    ubyte retransmit_state; /*!<  Retransmission state           */

    /*!< Handshake supports EC restart? */
    /* this complements ssl->state with info on intra-state operations */
    /*!< nothing going on (yet)         */
    /*!< Certificate: crt_verify()      */
    /*!< ServerKeyExchange: pk_verify() */
    /*!< ClientKeyExchange: ECDH step 2 */
    /*!< CertificateVerify: pk_sign()   */
    /*!< current (or last) operation    */
    /*!< The peer's CRT chain.          */
    /*!< place for saving a length      */

    mbedtls_ssl_sig_hash_set_t hash_algs; /*!<  Set of suitable sig-hash pairs */

    size_t pmslen; /*!<  premaster length        */

    const(mbedtls_ssl_ciphersuite_t)* ciphersuite_info;

    void function (mbedtls_ssl_context*, const(ubyte)*, size_t) update_checksum;
    void function (const(mbedtls_ssl_context)*, ubyte*, size_t*) calc_verify;
    void function (mbedtls_ssl_context*, ubyte*, int) calc_finished;
    int function () tls_prf;

    mbedtls_dhm_context dhm_ctx; /*!<  DHM key exchange        */

    /* Adding guard for MBEDTLS_ECDSA_C to ensure no compile errors due
     * to guards also being in ssl_srv.c and ssl_cli.c. There is a gap
     * in functionality that access to ecdh_ctx structure is needed for
     * MBEDTLS_ECDSA_C which does not seem correct.
     */

    mbedtls_ecdh_context ecdh_ctx; /*!<  ECDH key exchange       */

    /* MBEDTLS_USE_PSA_CRYPTO */
    /* MBEDTLS_ECDH_C || MBEDTLS_ECDSA_C */

    /*!< EC J-PAKE key exchange */

    /*!< Cache for ClientHello ext */
    /*!< Length of cached data */

    /* MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

    const(mbedtls_ecp_curve_info*)* curves; /*!<  Supported elliptic curves */

    /*!< Opaque PSK from the callback   */
    /* MBEDTLS_USE_PSA_CRYPTO */
    ubyte* psk; /*!<  PSK from the callback         */
    size_t psk_len; /*!<  Length of PSK from callback   */
    /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

    mbedtls_ssl_key_cert* key_cert; /*!< chosen key/cert pair (server)  */

    mbedtls_ssl_key_cert* sni_key_cert; /*!< key/cert list from SNI         */
    mbedtls_x509_crt* sni_ca_chain; /*!< trusted CAs from SNI callback  */
    mbedtls_x509_crl* sni_ca_crl; /*!< trusted CAs CRLs from SNI      */
    /* MBEDTLS_SSL_SERVER_NAME_INDICATION */
    /* MBEDTLS_X509_CRT_PARSE_C */

    /*!< restart context            */

    /*!< The public key from the peer.  */
    /* MBEDTLS_X509_CRT_PARSE_C && !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */

    /*!< Cumulative size of heap allocated
     *   buffers used for message buffering. */

    /*!< Indicates if a CCS message has
     *   been seen in the current flight. */
    struct _Anonymous_0
    {
        size_t total_bytes_buffered;
        ubyte seen_ccs;

        struct mbedtls_ssl_hs_buffer
        {
            import std.bitmanip : bitfields;

            mixin(bitfields!(
                uint, "is_valid", 1,
                uint, "is_fragmented", 1,
                uint, "is_complete", 1,
                uint, "", 5));

            ubyte* data;
            size_t data_len;
        }

        mbedtls_ssl_hs_buffer[MBEDTLS_SSL_MAX_BUFFERED_HS] hs;

        struct _Anonymous_1
        {
            ubyte* data;
            size_t len;
            uint epoch;
        }

        _Anonymous_1 future_record;
    }

    _Anonymous_0 buffering;

    uint out_msg_seq; /*!<  Outgoing handshake sequence number */
    uint in_msg_seq; /*!<  Incoming handshake sequence number */

    ubyte* verify_cookie; /*!<  Cli: HelloVerifyRequest cookie
          Srv: unused                    */
    ubyte verify_cookie_len; /*!<  Cli: cookie length
          Srv: flag for sending a cookie */

    uint retransmit_timeout; /*!<  Current value of timeout       */
    mbedtls_ssl_flight_item* flight; /*!<  Current outgoing flight        */
    mbedtls_ssl_flight_item* cur_msg; /*!<  Current message in flight      */
    ubyte* cur_msg_p; /*!<  Position in current message    */
    uint in_flight_start_seq; /*!<  Minimum message sequence in the
          flight being received          */
    mbedtls_ssl_transform* alt_transform_out; /*!<  Alternative transform for
       resending messages             */
    ubyte[8] alt_out_ctr; /*!<  Alternative record epoch/counter
          for resending messages         */

    /* The state of CID configuration in this handshake. */

    /*!< This indicates whether the use of the CID extension
     *   has been negotiated. Possible values are
     *   #MBEDTLS_SSL_CID_ENABLED and
     *   #MBEDTLS_SSL_CID_DISABLED. */
    /*! The peer's CID */
    /*!< The length of
     *   \c peer_cid.  */
    /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

    ushort mtu; /*!<  Handshake mtu, used to fragment outgoing messages */
    /* MBEDTLS_SSL_PROTO_DTLS */

    /*
     * Checksum contexts
     */

    mbedtls_md5_context fin_md5;
    mbedtls_sha1_context fin_sha1;

    mbedtls_sha256_context fin_sha256;

    mbedtls_sha512_context fin_sha512;

    /* MBEDTLS_SSL_PROTO_TLS1_2 */

    ubyte[64] randbytes; /*!<  random bytes            */
    ubyte[1060] premaster;
    /*!<  premaster secret        */

    /** Asynchronous operation context. This field is meant for use by the
     * asynchronous operation callbacks (mbedtls_ssl_config::f_async_sign_start,
     * mbedtls_ssl_config::f_async_decrypt_start,
     * mbedtls_ssl_config::f_async_resume, mbedtls_ssl_config::f_async_cancel).
     * The library does not use it internally. */

    /* MBEDTLS_SSL_ASYNC_PRIVATE */
}

/*
 * Representation of decryption/encryption transformations on records
 *
 * There are the following general types of record transformations:
 * - Stream transformations (TLS versions <= 1.2 only)
 *   Transformation adding a MAC and applying a stream-cipher
 *   to the authenticated message.
 * - CBC block cipher transformations ([D]TLS versions <= 1.2 only)
 *   In addition to the distinction of the order of encryption and
 *   authentication, there's a fundamental difference between the
 *   handling in SSL3 & TLS 1.0 and TLS 1.1 and TLS 1.2: For SSL3
 *   and TLS 1.0, the final IV after processing a record is used
 *   as the IV for the next record. No explicit IV is contained
 *   in an encrypted record. The IV for the first record is extracted
 *   at key extraction time. In contrast, for TLS 1.1 and 1.2, no
 *   IV is generated at key extraction time, but every encrypted
 *   record is explicitly prefixed by the IV with which it was encrypted.
 * - AEAD transformations ([D]TLS versions >= 1.2 only)
 *   These come in two fundamentally different versions, the first one
 *   used in TLS 1.2, excluding ChaChaPoly ciphersuites, and the second
 *   one used for ChaChaPoly ciphersuites in TLS 1.2 as well as for TLS 1.3.
 *   In the first transformation, the IV to be used for a record is obtained
 *   as the concatenation of an explicit, static 4-byte IV and the 8-byte
 *   record sequence number, and explicitly prepending this sequence number
 *   to the encrypted record. In contrast, in the second transformation
 *   the IV is obtained by XOR'ing a static IV obtained at key extraction
 *   time with the 8-byte record sequence number, without prepending the
 *   latter to the encrypted record.
 *
 * Additionally, DTLS 1.2 + CID as well as TLS 1.3 use an inner plaintext
 * which allows to add flexible length padding and to hide a record's true
 * content type.
 *
 * In addition to type and version, the following parameters are relevant:
 * - The symmetric cipher algorithm to be used.
 * - The (static) encryption/decryption keys for the cipher.
 * - For stream/CBC, the type of message digest to be used.
 * - For stream/CBC, (static) encryption/decryption keys for the digest.
 * - For AEAD transformations, the size (potentially 0) of an explicit,
 *   random initialization vector placed in encrypted records.
 * - For some transformations (currently AEAD and CBC in SSL3 and TLS 1.0)
 *   an implicit IV. It may be static (e.g. AEAD) or dynamic (e.g. CBC)
 *   and (if present) is combined with the explicit IV in a transformation-
 *   dependent way (e.g. appending in TLS 1.2 and XOR'ing in TLS 1.3).
 * - For stream/CBC, a flag determining the order of encryption and MAC.
 * - The details of the transformation depend on the SSL/TLS version.
 * - The length of the authentication tag.
 *
 * Note: Except for CBC in SSL3 and TLS 1.0, these parameters are
 *       constant across multiple encryption/decryption operations.
 *       For CBC, the implicit IV needs to be updated after each
 *       operation.
 *
 * The struct below refines this abstract view as follows:
 * - The cipher underlying the transformation is managed in
 *   cipher contexts cipher_ctx_{enc/dec}, which must have the
 *   same cipher type. The mode of these cipher contexts determines
 *   the type of the transformation in the sense above: e.g., if
 *   the type is MBEDTLS_CIPHER_AES_256_CBC resp. MBEDTLS_CIPHER_AES_192_GCM
 *   then the transformation has type CBC resp. AEAD.
 * - The cipher keys are never stored explicitly but
 *   are maintained within cipher_ctx_{enc/dec}.
 * - For stream/CBC transformations, the message digest contexts
 *   used for the MAC's are stored in md_ctx_{enc/dec}. These contexts
 *   are unused for AEAD transformations.
 * - For stream/CBC transformations and versions > SSL3, the
 *   MAC keys are not stored explicitly but maintained within
 *   md_ctx_{enc/dec}.
 * - For stream/CBC transformations and version SSL3, the MAC
 *   keys are stored explicitly in mac_enc, mac_dec and have
 *   a fixed size of 20 bytes. These fields are unused for
 *   AEAD transformations or transformations >= TLS 1.0.
 * - For transformations using an implicit IV maintained within
 *   the transformation context, its contents are stored within
 *   iv_{enc/dec}.
 * - The value of ivlen indicates the length of the IV.
 *   This is redundant in case of stream/CBC transformations
 *   which always use 0 resp. the cipher's block length as the
 *   IV length, but is needed for AEAD ciphers and may be
 *   different from the underlying cipher's block length
 *   in this case.
 * - The field fixed_ivlen is nonzero for AEAD transformations only
 *   and indicates the length of the static part of the IV which is
 *   constant throughout the communication, and which is stored in
 *   the first fixed_ivlen bytes of the iv_{enc/dec} arrays.
 *   Note: For CBC in SSL3 and TLS 1.0, the fields iv_{enc/dec}
 *   still store IV's for continued use across multiple transformations,
 *   so it is not true that fixed_ivlen == 0 means that iv_{enc/dec} are
 *   not being used!
 * - minor_ver denotes the SSL/TLS version
 * - For stream/CBC transformations, maclen denotes the length of the
 *   authentication tag, while taglen is unused and 0.
 * - For AEAD transformations, taglen denotes the length of the
 *   authentication tag, while maclen is unused and 0.
 * - For CBC transformations, encrypt_then_mac determines the
 *   order of encryption and authentication. This field is unused
 *   in other transformations.
 *
 */
struct mbedtls_ssl_transform
{
    /*
     * Session specific crypto layer
     */
    size_t minlen; /*!<  min. ciphertext length  */
    size_t ivlen; /*!<  IV length               */
    size_t fixed_ivlen; /*!<  Fixed part of IV (AEAD) */
    size_t maclen; /*!<  MAC(CBC) len            */
    size_t taglen; /*!<  TAG(AEAD) len           */

    ubyte[16] iv_enc; /*!<  IV (encryption)         */
    ubyte[16] iv_dec; /*!<  IV (decryption)         */

    /* Needed only for SSL v3.0 secret */
    /*!<  SSL v3.0 secret (enc)   */
    /*!<  SSL v3.0 secret (dec)   */
    /* MBEDTLS_SSL_PROTO_SSL3 */

    mbedtls_md_context_t md_ctx_enc; /*!<  MAC (encryption)        */
    mbedtls_md_context_t md_ctx_dec; /*!<  MAC (decryption)        */

    int encrypt_then_mac; /*!< flag for EtM activation                */

    /* MBEDTLS_SSL_SOME_MODES_USE_MAC */

    mbedtls_cipher_context_t cipher_ctx_enc; /*!<  encryption context      */
    mbedtls_cipher_context_t cipher_ctx_dec; /*!<  decryption context      */
    int minor_ver;

    /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

    /*
     * Session specific compression layer
     */

    /*!<  compression context     */
    /*!<  decompression context   */

    /* We need the Hello random bytes in order to re-derive keys from the
     * Master Secret and other session info, see ssl_populate_transform() */
    ubyte[64] randbytes; /*!< ServerHello.random+ClientHello.random */
    /* MBEDTLS_SSL_CONTEXT_SERIALIZATION */
}

/*
 * Return 1 if the transform uses an AEAD cipher, 0 otherwise.
 * Equivalently, return 0 if a separate MAC is used, 1 otherwise.
 */
int mbedtls_ssl_transform_uses_aead (const(mbedtls_ssl_transform)* transform);

/*
 * Internal representation of record frames
 *
 * Instances come in two flavors:
 * (1) Encrypted
 *     These always have data_offset = 0
 * (2) Unencrypted
 *     These have data_offset set to the amount of
 *     pre-expansion during record protection. Concretely,
 *     this is the length of the fixed part of the explicit IV
 *     used for encryption, or 0 if no explicit IV is used
 *     (e.g. for CBC in TLS 1.0, or stream ciphers).
 *
 * The reason for the data_offset in the unencrypted case
 * is to allow for in-place conversion of an unencrypted to
 * an encrypted record. If the offset wasn't included, the
 * encrypted content would need to be shifted afterwards to
 * make space for the fixed IV.
 *
 */

enum MBEDTLS_SSL_CID_LEN_MAX = MBEDTLS_SSL_CID_IN_LEN_MAX;

struct mbedtls_record
{
    ubyte[8] ctr; /* In TLS:  The implicit record sequence number.
     * In DTLS: The 2-byte epoch followed by
     *          the 6-byte sequence number.
     * This is stored as a raw big endian byte array
     * as opposed to a uint64_t because we rarely
     * need to perform arithmetic on this, but do
     * need it as a Byte array for the purpose of
     * MAC computations.                             */
    ubyte type; /* The record content type.                      */
    ubyte[2] ver; /* SSL/TLS version as present on the wire.
     * Convert to internal presentation of versions
     * using mbedtls_ssl_read_version() and
     * mbedtls_ssl_write_version().
     * Keep wire-format for MAC computations.        */

    ubyte* buf; /* Memory buffer enclosing the record content    */
    size_t buf_len; /* Buffer length                                 */
    size_t data_offset; /* Offset of record content                      */
    size_t data_len; /* Length of record content                      */

    /* Length of the CID (0 if not present)          */
    /* The CID                 */
    /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
}

/*
 * List of certificate + private key pairs
 */
struct mbedtls_ssl_key_cert
{
    mbedtls_x509_crt* cert; /*!< cert                       */
    mbedtls_pk_context* key; /*!< private key                */
    mbedtls_ssl_key_cert* next; /*!< next key/cert pair         */
}

/* MBEDTLS_X509_CRT_PARSE_C */

/*
 * List of handshake messages kept around for resending
 */
struct mbedtls_ssl_flight_item
{
    ubyte* p; /*!< message, including handshake headers   */
    size_t len; /*!< length of p                            */
    ubyte type; /*!< type of the message: handshake or CCS  */
    mbedtls_ssl_flight_item* next; /*!< next handshake message(s)              */
}

/* MBEDTLS_SSL_PROTO_DTLS */

/* Find an entry in a signature-hash set matching a given hash algorithm. */
mbedtls_md_type_t mbedtls_ssl_sig_hash_set_find (
    mbedtls_ssl_sig_hash_set_t* set,
    mbedtls_pk_type_t sig_alg);
/* Add a signature-hash-pair to a signature-hash set */
void mbedtls_ssl_sig_hash_set_add (
    mbedtls_ssl_sig_hash_set_t* set,
    mbedtls_pk_type_t sig_alg,
    mbedtls_md_type_t md_alg);
/* Allow exactly one hash algorithm for each signature. */
void mbedtls_ssl_sig_hash_set_const_hash (
    mbedtls_ssl_sig_hash_set_t* set,
    mbedtls_md_type_t md_alg);

/* Setup an empty signature-hash set */
pragma(inline, true) extern(D)
void mbedtls_ssl_sig_hash_set_init (mbedtls_ssl_sig_hash_set_t* set)
{
  mbedtls_ssl_sig_hash_set_const_hash(set, mbedtls_md_type_t.MBEDTLS_MD_NONE);
}

/* MBEDTLS_SSL_PROTO_TLS1_2) &&
   MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

/**
 * \brief           Free referenced items in an SSL transform context and clear
 *                  memory
 *
 * \param transform SSL transform context
 */
void mbedtls_ssl_transform_free (mbedtls_ssl_transform* transform);

/**
 * \brief           Free referenced items in an SSL handshake context and clear
 *                  memory
 *
 * \param ssl       SSL context
 */
void mbedtls_ssl_handshake_free (mbedtls_ssl_context* ssl);

int mbedtls_ssl_handshake_client_step (mbedtls_ssl_context* ssl);
int mbedtls_ssl_handshake_server_step (mbedtls_ssl_context* ssl);
void mbedtls_ssl_handshake_wrapup (mbedtls_ssl_context* ssl);

int mbedtls_ssl_send_fatal_handshake_failure (mbedtls_ssl_context* ssl);

void mbedtls_ssl_reset_checksum (mbedtls_ssl_context* ssl);
int mbedtls_ssl_derive_keys (mbedtls_ssl_context* ssl);

int mbedtls_ssl_handle_message_type (mbedtls_ssl_context* ssl);
int mbedtls_ssl_prepare_handshake_record (mbedtls_ssl_context* ssl);
void mbedtls_ssl_update_handshake_status (mbedtls_ssl_context* ssl);

/**
 * \brief       Update record layer
 *
 *              This function roughly separates the implementation
 *              of the logic of (D)TLS from the implementation
 *              of the secure transport.
 *
 * \param  ssl              The SSL context to use.
 * \param  update_hs_digest This indicates if the handshake digest
 *                          should be automatically updated in case
 *                          a handshake message is found.
 *
 * \return      0 or non-zero error code.
 *
 * \note        A clarification on what is called 'record layer' here
 *              is in order, as many sensible definitions are possible:
 *
 *              The record layer takes as input an untrusted underlying
 *              transport (stream or datagram) and transforms it into
 *              a serially multiplexed, secure transport, which
 *              conceptually provides the following:
 *
 *              (1) Three datagram based, content-agnostic transports
 *                  for handshake, alert and CCS messages.
 *              (2) One stream- or datagram-based transport
 *                  for application data.
 *              (3) Functionality for changing the underlying transform
 *                  securing the contents.
 *
 *              The interface to this functionality is given as follows:
 *
 *              a Updating
 *                [Currently implemented by mbedtls_ssl_read_record]
 *
 *                Check if and on which of the four 'ports' data is pending:
 *                Nothing, a controlling datagram of type (1), or application
 *                data (2). In any case data is present, internal buffers
 *                provide access to the data for the user to process it.
 *                Consumption of type (1) datagrams is done automatically
 *                on the next update, invalidating that the internal buffers
 *                for previous datagrams, while consumption of application
 *                data (2) is user-controlled.
 *
 *              b Reading of application data
 *                [Currently manual adaption of ssl->in_offt pointer]
 *
 *                As mentioned in the last paragraph, consumption of data
 *                is different from the automatic consumption of control
 *                datagrams (1) because application data is treated as a stream.
 *
 *              c Tracking availability of application data
 *                [Currently manually through decreasing ssl->in_msglen]
 *
 *                For efficiency and to retain datagram semantics for
 *                application data in case of DTLS, the record layer
 *                provides functionality for checking how much application
 *                data is still available in the internal buffer.
 *
 *              d Changing the transformation securing the communication.
 *
 *              Given an opaque implementation of the record layer in the
 *              above sense, it should be possible to implement the logic
 *              of (D)TLS on top of it without the need to know anything
 *              about the record layer's internals. This is done e.g.
 *              in all the handshake handling functions, and in the
 *              application data reading function mbedtls_ssl_read.
 *
 * \note        The above tries to give a conceptual picture of the
 *              record layer, but the current implementation deviates
 *              from it in some places. For example, our implementation of
 *              the update functionality through mbedtls_ssl_read_record
 *              discards datagrams depending on the current state, which
 *              wouldn't fall under the record layer's responsibility
 *              following the above definition.
 *
 */
int mbedtls_ssl_read_record (mbedtls_ssl_context* ssl, uint update_hs_digest);
int mbedtls_ssl_fetch_input (mbedtls_ssl_context* ssl, size_t nb_want);

int mbedtls_ssl_write_handshake_msg (mbedtls_ssl_context* ssl);
int mbedtls_ssl_write_record (mbedtls_ssl_context* ssl, ubyte force_flush);
int mbedtls_ssl_flush_output (mbedtls_ssl_context* ssl);

int mbedtls_ssl_parse_certificate (mbedtls_ssl_context* ssl);
int mbedtls_ssl_write_certificate (mbedtls_ssl_context* ssl);

int mbedtls_ssl_parse_change_cipher_spec (mbedtls_ssl_context* ssl);
int mbedtls_ssl_write_change_cipher_spec (mbedtls_ssl_context* ssl);

int mbedtls_ssl_parse_finished (mbedtls_ssl_context* ssl);
int mbedtls_ssl_write_finished (mbedtls_ssl_context* ssl);

void mbedtls_ssl_optimize_checksum (
    mbedtls_ssl_context* ssl,
    const(mbedtls_ssl_ciphersuite_t)* ciphersuite_info);

int mbedtls_ssl_psk_derive_premaster (
    mbedtls_ssl_context* ssl,
    mbedtls_key_exchange_type_t key_ex);

/**
 * Get the first defined PSK by order of precedence:
 * 1. handshake PSK set by \c mbedtls_ssl_set_hs_psk() in the PSK callback
 * 2. static PSK configured by \c mbedtls_ssl_conf_psk()
 * Return a code and update the pair (PSK, PSK length) passed to this function
 */
pragma(inline, true) extern(D)
int mbedtls_ssl_get_psk (
    const(mbedtls_ssl_context)* ssl,
    const(ubyte)** psk,
    size_t* psk_len)
{
  if (ssl.handshake.psk != null && ssl.handshake.psk_len > 0)
  {
    *psk = ssl.handshake.psk;
    *psk_len = ssl.handshake.psk_len;
  }
  else if (ssl.conf.psk != null && ssl.conf.psk_len > 0)
  {
    *psk = ssl.conf.psk;
    *psk_len = ssl.conf.psk_len;
  }
  else
  {
    *psk = null;
    *psk_len = 0;
    return MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED;
  }

  return 0;
}

/**
 * Get the first defined opaque PSK by order of precedence:
 * 1. handshake PSK set by \c mbedtls_ssl_set_hs_psk_opaque() in the PSK
 *    callback
 * 2. static PSK configured by \c mbedtls_ssl_conf_psk_opaque()
 * Return an opaque PSK
 */

/* MBEDTLS_USE_PSA_CRYPTO */

/* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

ubyte mbedtls_ssl_sig_from_pk (mbedtls_pk_context* pk);
ubyte mbedtls_ssl_sig_from_pk_alg (mbedtls_pk_type_t type);
mbedtls_pk_type_t mbedtls_ssl_pk_alg_from_sig (ubyte sig);

mbedtls_md_type_t mbedtls_ssl_md_alg_from_hash (ubyte hash);
ubyte mbedtls_ssl_hash_from_md_alg (int md);
int mbedtls_ssl_set_calc_verify_md (mbedtls_ssl_context* ssl, int md);

int mbedtls_ssl_check_curve (
    const(mbedtls_ssl_context)* ssl,
    mbedtls_ecp_group_id grp_id);
int mbedtls_ssl_check_curve_tls_id (
    const(mbedtls_ssl_context)* ssl,
    ushort tls_id);

int mbedtls_ssl_check_sig_hash (
    const(mbedtls_ssl_context)* ssl,
    mbedtls_md_type_t md);

pragma(inline, true) extern(D)
{
  mbedtls_pk_context* mbedtls_ssl_own_key (mbedtls_ssl_context* ssl)
  {
    mbedtls_ssl_key_cert* key_cert;

    if (ssl.handshake != null && ssl.handshake.key_cert != null)
      key_cert = ssl.handshake.key_cert;
    else
      key_cert = cast(mbedtls_ssl_key_cert*) ssl.conf.key_cert;

    return key_cert == null ? null : key_cert.key;
  }

  mbedtls_x509_crt* mbedtls_ssl_own_cert (mbedtls_ssl_context* ssl)
  {
    mbedtls_ssl_key_cert* key_cert;

    if (ssl.handshake != null && ssl.handshake.key_cert != null)
      key_cert = ssl.handshake.key_cert;
    else
      key_cert = cast(mbedtls_ssl_key_cert*) ssl.conf.key_cert;

    return key_cert == null ? null : key_cert.cert;
  }
}
/*
 * Check usage of a certificate wrt extensions:
 * keyUsage, extendedKeyUsage (later), and nSCertType (later).
 *
 * Warning: cert_endpoint is the endpoint of the cert (ie, of our peer when we
 * check a cert we received from them)!
 *
 * Return 0 if everything is OK, -1 if not.
 */
int mbedtls_ssl_check_cert_usage (
    const(mbedtls_x509_crt)* cert,
    const(mbedtls_ssl_ciphersuite_t)* ciphersuite,
    int cert_endpoint,
    uint* flags);
/* MBEDTLS_X509_CRT_PARSE_C */

void mbedtls_ssl_write_version (
    int major,
    int minor,
    int transport,
    ref ubyte[2] ver);
void mbedtls_ssl_read_version (
    int* major,
    int* minor,
    int transport,
    ref const(ubyte)[2] ver);

/* MBEDTLS_SSL_PROTO_DTLS */
pragma(inline, true) extern(D)
{
  size_t mbedtls_ssl_in_hdr_len (const(mbedtls_ssl_context)* ssl)
  {
    if (ssl.conf.transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM)
      return 13;
    else
      return 5;
  }

  size_t mbedtls_ssl_out_hdr_len (const(mbedtls_ssl_context)* ssl)
  {
    return cast(size_t) (ssl.out_iv - ssl.out_hdr);
  }

  size_t mbedtls_ssl_hs_hdr_len (const(mbedtls_ssl_context)* ssl)
  {
    if (ssl.conf.transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM)
      return 12;

    return 4;
  }
}

void mbedtls_ssl_send_flight_completed (mbedtls_ssl_context* ssl);
void mbedtls_ssl_recv_flight_completed (mbedtls_ssl_context* ssl);
int mbedtls_ssl_resend (mbedtls_ssl_context* ssl);
int mbedtls_ssl_flight_transmit (mbedtls_ssl_context* ssl);

/* Visible for testing purposes only */
int mbedtls_ssl_dtls_replay_check (const(mbedtls_ssl_context)* ssl);
void mbedtls_ssl_dtls_replay_update (mbedtls_ssl_context* ssl);

int mbedtls_ssl_session_copy (
    mbedtls_ssl_session* dst,
    const(mbedtls_ssl_session)* src);

int mbedtls_ssl_get_key_exchange_md_ssl_tls (
    mbedtls_ssl_context* ssl,
    ubyte* output,
    ubyte* data,
    size_t data_len);
/* MBEDTLS_SSL_PROTO_SSL3 || MBEDTLS_SSL_PROTO_TLS1 || \
   MBEDTLS_SSL_PROTO_TLS1_1 */

/* The hash buffer must have at least MBEDTLS_MD_MAX_SIZE bytes of length. */
int mbedtls_ssl_get_key_exchange_md_tls1_2 (
    mbedtls_ssl_context* ssl,
    ubyte* hash,
    size_t* hashlen,
    ubyte* data,
    size_t data_len,
    mbedtls_md_type_t md_alg);
/* MBEDTLS_SSL_PROTO_TLS1 || MBEDTLS_SSL_PROTO_TLS1_1 || \
   MBEDTLS_SSL_PROTO_TLS1_2 */

void mbedtls_ssl_transform_init (mbedtls_ssl_transform* transform);
int mbedtls_ssl_encrypt_buf (
    mbedtls_ssl_context* ssl,
    mbedtls_ssl_transform* transform,
    mbedtls_record* rec,
    int function (void*, ubyte*, size_t) f_rng,
    void* p_rng);
int mbedtls_ssl_decrypt_buf (
    const(mbedtls_ssl_context)* ssl,
    mbedtls_ssl_transform* transform,
    mbedtls_record* rec);

/* Length of the "epoch" field in the record header */
pragma(inline, true) extern(D)
size_t mbedtls_ssl_ep_len (const(mbedtls_ssl_context)* ssl)
{
  if (ssl.conf.transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM)
    return 2;

  return 0;
}

int mbedtls_ssl_resend_hello_request (mbedtls_ssl_context* ssl);
/* MBEDTLS_SSL_PROTO_DTLS */

void mbedtls_ssl_set_timer (mbedtls_ssl_context* ssl, uint millisecs);
int mbedtls_ssl_check_timer (mbedtls_ssl_context* ssl);

void mbedtls_ssl_reset_in_out_pointers (mbedtls_ssl_context* ssl);
void mbedtls_ssl_update_out_pointers (
    mbedtls_ssl_context* ssl,
    mbedtls_ssl_transform* transform);
void mbedtls_ssl_update_in_pointers (mbedtls_ssl_context* ssl);

int mbedtls_ssl_session_reset_int (mbedtls_ssl_context* ssl, int partial);

void mbedtls_ssl_dtls_replay_reset (mbedtls_ssl_context* ssl);

void mbedtls_ssl_handshake_wrapup_free_hs_transform (mbedtls_ssl_context* ssl);

int mbedtls_ssl_start_renegotiation (mbedtls_ssl_context* ssl);
/* MBEDTLS_SSL_RENEGOTIATION */

size_t mbedtls_ssl_get_current_mtu (const(mbedtls_ssl_context)* ssl);
void mbedtls_ssl_buffering_free (mbedtls_ssl_context* ssl);
void mbedtls_ssl_flight_free (mbedtls_ssl_flight_item* flight);
/* MBEDTLS_SSL_PROTO_DTLS */

/* ssl_internal.h */
