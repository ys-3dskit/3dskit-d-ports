/**
 * \file x509.h
 *
 * \brief X.509 generic defines and structures
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

extern (C):

/**
 * \addtogroup x509_module
 * \{
 */

/**
 * Maximum number of intermediate CAs in a verification chain.
 * That is, maximum length of the chain, excluding the end-entity certificate
 * and the trusted root certificate.
 *
 * Set this to a low value to prevent an adversary from making you waste
 * resources verifying an overlong certificate chain.
 */
enum MBEDTLS_X509_MAX_INTERMEDIATE_CA = 8;

/**
 * \name X509 Error codes
 * \{
 */
/** Unavailable feature, e.g. RSA hashing/encryption combination. */
enum MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE = -0x2080;
/** Requested OID is unknown. */
enum MBEDTLS_ERR_X509_UNKNOWN_OID = -0x2100;
/** The CRT/CRL/CSR format is invalid, e.g. different type expected. */
enum MBEDTLS_ERR_X509_INVALID_FORMAT = -0x2180;
/** The CRT/CRL/CSR version element is invalid. */
enum MBEDTLS_ERR_X509_INVALID_VERSION = -0x2200;
/** The serial tag or value is invalid. */
enum MBEDTLS_ERR_X509_INVALID_SERIAL = -0x2280;
/** The algorithm tag or value is invalid. */
enum MBEDTLS_ERR_X509_INVALID_ALG = -0x2300;
/** The name tag or value is invalid. */
enum MBEDTLS_ERR_X509_INVALID_NAME = -0x2380;
/** The date tag or value is invalid. */
enum MBEDTLS_ERR_X509_INVALID_DATE = -0x2400;
/** The signature tag or value invalid. */
enum MBEDTLS_ERR_X509_INVALID_SIGNATURE = -0x2480;
/** The extension tag or value is invalid. */
enum MBEDTLS_ERR_X509_INVALID_EXTENSIONS = -0x2500;
/** CRT/CRL/CSR has an unsupported version number. */
enum MBEDTLS_ERR_X509_UNKNOWN_VERSION = -0x2580;
/** Signature algorithm (oid) is unsupported. */
enum MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG = -0x2600;
/** Signature algorithms do not match. (see \c ::mbedtls_x509_crt sig_oid) */
enum MBEDTLS_ERR_X509_SIG_MISMATCH = -0x2680;
/** Certificate verification failed, e.g. CRL, CA or signature check failed. */
enum MBEDTLS_ERR_X509_CERT_VERIFY_FAILED = -0x2700;
/** Format not recognized as DER or PEM. */
enum MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT = -0x2780;
/** Input invalid. */
enum MBEDTLS_ERR_X509_BAD_INPUT_DATA = -0x2800;
/** Allocation of memory failed. */
enum MBEDTLS_ERR_X509_ALLOC_FAILED = -0x2880;
/** Read/write of file failed. */
enum MBEDTLS_ERR_X509_FILE_IO_ERROR = -0x2900;
/** Destination buffer is too small. */
enum MBEDTLS_ERR_X509_BUFFER_TOO_SMALL = -0x2980;
/** A fatal error occurred, eg the chain is too long or the vrfy callback failed. */
enum MBEDTLS_ERR_X509_FATAL_ERROR = -0x3000;
/** \} name X509 Error codes */

/**
 * \name X509 Verify codes
 * \{
 */
/* Reminder: update x509_crt_verify_strings[] in library/x509_crt.c */
enum MBEDTLS_X509_BADCERT_EXPIRED = 0x01; /**< The certificate validity has expired. */
enum MBEDTLS_X509_BADCERT_REVOKED = 0x02; /**< The certificate has been revoked (is on a CRL). */
enum MBEDTLS_X509_BADCERT_CN_MISMATCH = 0x04; /**< The certificate Common Name (CN) does not match with the expected CN. */
enum MBEDTLS_X509_BADCERT_NOT_TRUSTED = 0x08; /**< The certificate is not correctly signed by the trusted CA. */
enum MBEDTLS_X509_BADCRL_NOT_TRUSTED = 0x10; /**< The CRL is not correctly signed by the trusted CA. */
enum MBEDTLS_X509_BADCRL_EXPIRED = 0x20; /**< The CRL is expired. */
enum MBEDTLS_X509_BADCERT_MISSING = 0x40; /**< Certificate was missing. */
enum MBEDTLS_X509_BADCERT_SKIP_VERIFY = 0x80; /**< Certificate verification was skipped. */
enum MBEDTLS_X509_BADCERT_OTHER = 0x0100; /**< Other reason (can be used by verify callback) */
enum MBEDTLS_X509_BADCERT_FUTURE = 0x0200; /**< The certificate validity starts in the future. */
enum MBEDTLS_X509_BADCRL_FUTURE = 0x0400; /**< The CRL is from the future */
enum MBEDTLS_X509_BADCERT_KEY_USAGE = 0x0800; /**< Usage does not match the keyUsage extension. */
enum MBEDTLS_X509_BADCERT_EXT_KEY_USAGE = 0x1000; /**< Usage does not match the extendedKeyUsage extension. */
enum MBEDTLS_X509_BADCERT_NS_CERT_TYPE = 0x2000; /**< Usage does not match the nsCertType extension. */
enum MBEDTLS_X509_BADCERT_BAD_MD = 0x4000; /**< The certificate is signed with an unacceptable hash. */
enum MBEDTLS_X509_BADCERT_BAD_PK = 0x8000; /**< The certificate is signed with an unacceptable PK alg (eg RSA vs ECDSA). */
enum MBEDTLS_X509_BADCERT_BAD_KEY = 0x010000; /**< The certificate is signed with an unacceptable key (eg bad curve, RSA too short). */
enum MBEDTLS_X509_BADCRL_BAD_MD = 0x020000; /**< The CRL is signed with an unacceptable hash. */
enum MBEDTLS_X509_BADCRL_BAD_PK = 0x040000; /**< The CRL is signed with an unacceptable PK alg (eg RSA vs ECDSA). */
enum MBEDTLS_X509_BADCRL_BAD_KEY = 0x080000; /**< The CRL is signed with an unacceptable key (eg bad curve, RSA too short). */

/** \} name X509 Verify codes */
/** \} addtogroup x509_module */

/*
 * X.509 v3 Subject Alternative Name types.
 *      otherName                       [0]     OtherName,
 *      rfc822Name                      [1]     IA5String,
 *      dNSName                         [2]     IA5String,
 *      x400Address                     [3]     ORAddress,
 *      directoryName                   [4]     Name,
 *      ediPartyName                    [5]     EDIPartyName,
 *      uniformResourceIdentifier       [6]     IA5String,
 *      iPAddress                       [7]     OCTET STRING,
 *      registeredID                    [8]     OBJECT IDENTIFIER
 */
enum MBEDTLS_X509_SAN_OTHER_NAME = 0;
enum MBEDTLS_X509_SAN_RFC822_NAME = 1;
enum MBEDTLS_X509_SAN_DNS_NAME = 2;
enum MBEDTLS_X509_SAN_X400_ADDRESS_NAME = 3;
enum MBEDTLS_X509_SAN_DIRECTORY_NAME = 4;
enum MBEDTLS_X509_SAN_EDI_PARTY_NAME = 5;
enum MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER = 6;
enum MBEDTLS_X509_SAN_IP_ADDRESS = 7;
enum MBEDTLS_X509_SAN_REGISTERED_ID = 8;

/*
 * X.509 v3 Key Usage Extension flags
 * Reminder: update x509_info_key_usage() when adding new flags.
 */
enum MBEDTLS_X509_KU_DIGITAL_SIGNATURE = 0x80; /* bit 0 */
enum MBEDTLS_X509_KU_NON_REPUDIATION = 0x40; /* bit 1 */
enum MBEDTLS_X509_KU_KEY_ENCIPHERMENT = 0x20; /* bit 2 */
enum MBEDTLS_X509_KU_DATA_ENCIPHERMENT = 0x10; /* bit 3 */
enum MBEDTLS_X509_KU_KEY_AGREEMENT = 0x08; /* bit 4 */
enum MBEDTLS_X509_KU_KEY_CERT_SIGN = 0x04; /* bit 5 */
enum MBEDTLS_X509_KU_CRL_SIGN = 0x02; /* bit 6 */
enum MBEDTLS_X509_KU_ENCIPHER_ONLY = 0x01; /* bit 7 */
enum MBEDTLS_X509_KU_DECIPHER_ONLY = 0x8000; /* bit 8 */

/*
 * Netscape certificate types
 * (http://www.mozilla.org/projects/security/pki/nss/tech-notes/tn3.html)
 */

enum MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT = 0x80; /* bit 0 */
enum MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER = 0x40; /* bit 1 */
enum MBEDTLS_X509_NS_CERT_TYPE_EMAIL = 0x20; /* bit 2 */
enum MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING = 0x10; /* bit 3 */
enum MBEDTLS_X509_NS_CERT_TYPE_RESERVED = 0x08; /* bit 4 */
enum MBEDTLS_X509_NS_CERT_TYPE_SSL_CA = 0x04; /* bit 5 */
enum MBEDTLS_X509_NS_CERT_TYPE_EMAIL_CA = 0x02; /* bit 6 */
enum MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING_CA = 0x01; /* bit 7 */

/*
 * X.509 extension types
 *
 * Comments refer to the status for using certificates. Status can be
 * different for writing certificates or reading CRLs or CSRs.
 *
 * Those are defined in oid.h as oid.c needs them in a data structure. Since
 * these were previously defined here, let's have aliases for compatibility.
 */
enum MBEDTLS_X509_EXT_AUTHORITY_KEY_IDENTIFIER = MBEDTLS_OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER;
enum MBEDTLS_X509_EXT_SUBJECT_KEY_IDENTIFIER = MBEDTLS_OID_X509_EXT_SUBJECT_KEY_IDENTIFIER;
enum MBEDTLS_X509_EXT_KEY_USAGE = MBEDTLS_OID_X509_EXT_KEY_USAGE;
enum MBEDTLS_X509_EXT_CERTIFICATE_POLICIES = MBEDTLS_OID_X509_EXT_CERTIFICATE_POLICIES;
enum MBEDTLS_X509_EXT_POLICY_MAPPINGS = MBEDTLS_OID_X509_EXT_POLICY_MAPPINGS;
enum MBEDTLS_X509_EXT_SUBJECT_ALT_NAME = MBEDTLS_OID_X509_EXT_SUBJECT_ALT_NAME; /* Supported (DNS) */
enum MBEDTLS_X509_EXT_ISSUER_ALT_NAME = MBEDTLS_OID_X509_EXT_ISSUER_ALT_NAME;
enum MBEDTLS_X509_EXT_SUBJECT_DIRECTORY_ATTRS = MBEDTLS_OID_X509_EXT_SUBJECT_DIRECTORY_ATTRS;
enum MBEDTLS_X509_EXT_BASIC_CONSTRAINTS = MBEDTLS_OID_X509_EXT_BASIC_CONSTRAINTS; /* Supported */
enum MBEDTLS_X509_EXT_NAME_CONSTRAINTS = MBEDTLS_OID_X509_EXT_NAME_CONSTRAINTS;
enum MBEDTLS_X509_EXT_POLICY_CONSTRAINTS = MBEDTLS_OID_X509_EXT_POLICY_CONSTRAINTS;
enum MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE = MBEDTLS_OID_X509_EXT_EXTENDED_KEY_USAGE;
enum MBEDTLS_X509_EXT_CRL_DISTRIBUTION_POINTS = MBEDTLS_OID_X509_EXT_CRL_DISTRIBUTION_POINTS;
enum MBEDTLS_X509_EXT_INIHIBIT_ANYPOLICY = MBEDTLS_OID_X509_EXT_INIHIBIT_ANYPOLICY;
enum MBEDTLS_X509_EXT_FRESHEST_CRL = MBEDTLS_OID_X509_EXT_FRESHEST_CRL;
enum MBEDTLS_X509_EXT_NS_CERT_TYPE = MBEDTLS_OID_X509_EXT_NS_CERT_TYPE;

/*
 * Storage format identifiers
 * Recognized formats: PEM and DER
 */
enum MBEDTLS_X509_FORMAT_DER = 1;
enum MBEDTLS_X509_FORMAT_PEM = 2;

enum MBEDTLS_X509_MAX_DN_NAME_SIZE = 256; /**< Maximum value size of a DN entry */

/**
 * \addtogroup x509_module
 * \{ */

/**
 * \name Structures for parsing X.509 certificates, CRLs and CSRs
 * \{
 */

/**
 * Type-length-value structure that allows for ASN1 using DER.
 */
alias mbedtls_x509_buf = mbedtls_asn1_buf_;

/**
 * Container for ASN1 bit strings.
 */
alias mbedtls_x509_bitstring = mbedtls_asn1_bitstring_;

/**
 * Container for ASN1 named information objects.
 * It allows for Relative Distinguished Names (e.g. cn=localhost,ou=code,etc.).
 */
alias mbedtls_x509_name = mbedtls_asn1_named_data_;

/**
 * Container for a sequence of ASN.1 items
 */
alias mbedtls_x509_sequence = mbedtls_asn1_sequence_;

/** Container for date and time (precision in seconds). */
struct mbedtls_x509_time
{
    int year;
    int mon;
    int day; /**< Date. */
    int hour;
    int min;
    int sec; /**< Time. */
}

/** \} name Structures for parsing X.509 certificates, CRLs and CSRs */

/**
 * \brief          Store the certificate DN in printable form into buf;
 *                 no more than size characters will be written.
 *
 * \param buf      Buffer to write to
 * \param size     Maximum size of buffer
 * \param dn       The X509 name to represent
 *
 * \return         The length of the string written (not including the
 *                 terminated nul byte), or a negative error code.
 */
int mbedtls_x509_dn_gets (char* buf, size_t size, const(mbedtls_x509_name)* dn);

/**
 * \brief          Store the certificate serial in printable form into buf;
 *                 no more than size characters will be written.
 *
 * \param buf      Buffer to write to
 * \param size     Maximum size of buffer
 * \param serial   The X509 serial to represent
 *
 * \return         The length of the string written (not including the
 *                 terminated nul byte), or a negative error code.
 */
int mbedtls_x509_serial_gets (char* buf, size_t size, const(mbedtls_x509_buf)* serial);

/**
 * \brief          Check a given mbedtls_x509_time against the system time
 *                 and tell if it's in the past.
 *
 * \note           Intended usage is "if( is_past( valid_to ) ) ERROR".
 *                 Hence the return value of 1 if on internal errors.
 *
 * \param to       mbedtls_x509_time to check
 *
 * \return         1 if the given time is in the past or an error occurred,
 *                 0 otherwise.
 */
int mbedtls_x509_time_is_past (const(mbedtls_x509_time)* to);

/**
 * \brief          Check a given mbedtls_x509_time against the system time
 *                 and tell if it's in the future.
 *
 * \note           Intended usage is "if( is_future( valid_from ) ) ERROR".
 *                 Hence the return value of 1 if on internal errors.
 *
 * \param from     mbedtls_x509_time to check
 *
 * \return         1 if the given time is in the future or an error occurred,
 *                 0 otherwise.
 */
int mbedtls_x509_time_is_future (const(mbedtls_x509_time)* from);

/** \} addtogroup x509_module */

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */

/* MBEDTLS_SELF_TEST */

/*
 * Internal module functions. You probably do not want to use these unless you
 * know you do.
 */
int mbedtls_x509_get_name (
    ubyte** p,
    const(ubyte)* end,
    mbedtls_x509_name* cur);
int mbedtls_x509_get_alg_null (
    ubyte** p,
    const(ubyte)* end,
    mbedtls_x509_buf* alg);
int mbedtls_x509_get_alg (
    ubyte** p,
    const(ubyte)* end,
    mbedtls_x509_buf* alg,
    mbedtls_x509_buf* params);
int mbedtls_x509_get_rsassa_pss_params (
    const(mbedtls_x509_buf)* params,
    mbedtls_md_type_t* md_alg,
    mbedtls_md_type_t* mgf_md,
    int* salt_len);

int mbedtls_x509_get_sig (ubyte** p, const(ubyte)* end, mbedtls_x509_buf* sig);
int mbedtls_x509_get_sig_alg (
    const(mbedtls_x509_buf)* sig_oid,
    const(mbedtls_x509_buf)* sig_params,
    mbedtls_md_type_t* md_alg,
    mbedtls_pk_type_t* pk_alg,
    void** sig_opts);
int mbedtls_x509_get_time (ubyte** p, const(ubyte)* end, mbedtls_x509_time* t);
int mbedtls_x509_get_serial (
    ubyte** p,
    const(ubyte)* end,
    mbedtls_x509_buf* serial);
int mbedtls_x509_get_ext (
    ubyte** p,
    const(ubyte)* end,
    mbedtls_x509_buf* ext,
    int tag);
int mbedtls_x509_sig_alg_gets (
    char* buf,
    size_t size,
    const(mbedtls_x509_buf)* sig_oid,
    mbedtls_pk_type_t pk_alg,
    mbedtls_md_type_t md_alg,
    const(void)* sig_opts);
int mbedtls_x509_key_size_helper (char* buf, size_t buf_size, const(char)* name);
int mbedtls_x509_string_to_names (mbedtls_asn1_named_data** head, const(char)* name);
int mbedtls_x509_set_extension (
    mbedtls_asn1_named_data** head,
    const(char)* oid,
    size_t oid_len,
    int critical,
    const(ubyte)* val,
    size_t val_len);
int mbedtls_x509_write_extensions (
    ubyte** p,
    ubyte* start,
    mbedtls_asn1_named_data* first);
int mbedtls_x509_write_names (
    ubyte** p,
    ubyte* start,
    mbedtls_asn1_named_data* first);
int mbedtls_x509_write_sig (
    ubyte** p,
    ubyte* start,
    const(char)* oid,
    size_t oid_len,
    ubyte* sig,
    size_t size,
    mbedtls_pk_type_t pk_alg);

/* x509.h */
