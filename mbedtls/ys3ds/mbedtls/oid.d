/**
 * \file oid.h
 *
 * \brief Object Identifier (OID) database
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

extern (C):

/** OID is not found. */
enum MBEDTLS_ERR_OID_NOT_FOUND = -0x002E;
/** output buffer is too small */
enum MBEDTLS_ERR_OID_BUF_TOO_SMALL = -0x000B;

/* This is for the benefit of X.509, but defined here in order to avoid
 * having a "backwards" include of x.509.h here */
/*
 * X.509 extension types (internal, arbitrary values for bitsets)
 */
enum MBEDTLS_OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER = 1 << 0;
enum MBEDTLS_OID_X509_EXT_SUBJECT_KEY_IDENTIFIER = 1 << 1;
enum MBEDTLS_OID_X509_EXT_KEY_USAGE = 1 << 2;
enum MBEDTLS_OID_X509_EXT_CERTIFICATE_POLICIES = 1 << 3;
enum MBEDTLS_OID_X509_EXT_POLICY_MAPPINGS = 1 << 4;
enum MBEDTLS_OID_X509_EXT_SUBJECT_ALT_NAME = 1 << 5;
enum MBEDTLS_OID_X509_EXT_ISSUER_ALT_NAME = 1 << 6;
enum MBEDTLS_OID_X509_EXT_SUBJECT_DIRECTORY_ATTRS = 1 << 7;
enum MBEDTLS_OID_X509_EXT_BASIC_CONSTRAINTS = 1 << 8;
enum MBEDTLS_OID_X509_EXT_NAME_CONSTRAINTS = 1 << 9;
enum MBEDTLS_OID_X509_EXT_POLICY_CONSTRAINTS = 1 << 10;
enum MBEDTLS_OID_X509_EXT_EXTENDED_KEY_USAGE = 1 << 11;
enum MBEDTLS_OID_X509_EXT_CRL_DISTRIBUTION_POINTS = 1 << 12;
enum MBEDTLS_OID_X509_EXT_INIHIBIT_ANYPOLICY = 1 << 13;
enum MBEDTLS_OID_X509_EXT_FRESHEST_CRL = 1 << 14;
enum MBEDTLS_OID_X509_EXT_NS_CERT_TYPE = 1 << 16;

/*
 * Top level OID tuples
 */
enum MBEDTLS_OID_ISO_MEMBER_BODIES = "\x2a"; /* {iso(1) member-body(2)} */
enum MBEDTLS_OID_ISO_IDENTIFIED_ORG = "\x2b"; /* {iso(1) identified-organization(3)} */
enum MBEDTLS_OID_ISO_CCITT_DS = "\x55"; /* {joint-iso-ccitt(2) ds(5)} */
enum MBEDTLS_OID_ISO_ITU_COUNTRY = "\x60"; /* {joint-iso-itu-t(2) country(16)} */

/*
 * ISO Member bodies OID parts
 */
enum MBEDTLS_OID_COUNTRY_US = "\x86\x48"; /* {us(840)} */
enum MBEDTLS_OID_ORG_RSA_DATA_SECURITY = "\x86\xf7\x0d"; /* {rsadsi(113549)} */ /* {iso(1) member-body(2) us(840) rsadsi(113549)} */
enum MBEDTLS_OID_ORG_ANSI_X9_62 = "\xce\x3d"; /* ansi-X9-62(10045) */

/*
 * ISO Identified organization OID parts
 */
enum MBEDTLS_OID_ORG_DOD = "\x06"; /* {dod(6)} */
enum MBEDTLS_OID_ORG_OIW = "\x0e";
enum MBEDTLS_OID_ORG_CERTICOM = "\x81\x04"; /* certicom(132) */
enum MBEDTLS_OID_ORG_TELETRUST = "\x24"; /* teletrust(36) */

/*
 * ISO ITU OID parts
 */
enum MBEDTLS_OID_ORGANIZATION = "\x01"; /* {organization(1)} */ /* {joint-iso-itu-t(2) country(16) us(840) organization(1)} */

enum MBEDTLS_OID_ORG_GOV = "\x65"; /* {gov(101)} */ /* {joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101)} */

enum MBEDTLS_OID_ORG_NETSCAPE = "\x86\xF8\x42"; /* {netscape(113730)} */ /* Netscape OID {joint-iso-itu-t(2) country(16) us(840) organization(1) netscape(113730)} */

/* ISO arc for standard certificate and CRL extensions */ /**< id-ce OBJECT IDENTIFIER  ::=  {joint-iso-ccitt(2) ds(5) 29} */ /** { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) */

/**
 * Private Internet Extensions
 * { iso(1) identified-organization(3) dod(6) internet(1)
 *                      security(5) mechanisms(5) pkix(7) }
 */

/*
 * Arc for standard naming attributes
 */ /**< id-at OBJECT IDENTIFIER ::= {joint-iso-ccitt(2) ds(5) 4} */ /**< id-at-commonName AttributeType:= {id-at 3} */ /**< id-at-surName AttributeType:= {id-at 4} */ /**< id-at-serialNumber AttributeType:= {id-at 5} */ /**< id-at-countryName AttributeType:= {id-at 6} */ /**< id-at-locality AttributeType:= {id-at 7} */ /**< id-at-state AttributeType:= {id-at 8} */ /**< id-at-organizationName AttributeType:= {id-at 10} */ /**< id-at-organizationalUnitName AttributeType:= {id-at 11} */ /**< id-at-title AttributeType:= {id-at 12} */ /**< id-at-postalAddress AttributeType:= {id-at 16} */ /**< id-at-postalCode AttributeType:= {id-at 17} */ /**< id-at-givenName AttributeType:= {id-at 42} */ /**< id-at-initials AttributeType:= {id-at 43} */ /**< id-at-generationQualifier AttributeType:= {id-at 44} */ /**< id-at-uniqueIdentifier AttributeType:= {id-at 45} */ /**< id-at-dnQualifier AttributeType:= {id-at 46} */ /**< id-at-pseudonym AttributeType:= {id-at 65} */

enum MBEDTLS_OID_DOMAIN_COMPONENT = "\x09\x92\x26\x89\x93\xF2\x2C\x64\x01\x19"; /** id-domainComponent AttributeType:= {itu-t(0) data(9) pss(2342) ucl(19200300) pilot(100) pilotAttributeType(1) domainComponent(25)} */

/*
 * OIDs for standard certificate extensions
 */ /**< id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 } */ /**< id-ce-subjectKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 14 } */ /**< id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 } */ /**< id-ce-certificatePolicies OBJECT IDENTIFIER ::=  { id-ce 32 } */ /**< id-ce-policyMappings OBJECT IDENTIFIER ::=  { id-ce 33 } */ /**< id-ce-subjectAltName OBJECT IDENTIFIER ::=  { id-ce 17 } */ /**< id-ce-issuerAltName OBJECT IDENTIFIER ::=  { id-ce 18 } */ /**< id-ce-subjectDirectoryAttributes OBJECT IDENTIFIER ::=  { id-ce 9 } */ /**< id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 } */ /**< id-ce-nameConstraints OBJECT IDENTIFIER ::=  { id-ce 30 } */ /**< id-ce-policyConstraints OBJECT IDENTIFIER ::=  { id-ce 36 } */ /**< id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 } */ /**< id-ce-cRLDistributionPoints OBJECT IDENTIFIER ::=  { id-ce 31 } */ /**< id-ce-inhibitAnyPolicy OBJECT IDENTIFIER ::=  { id-ce 54 } */ /**< id-ce-freshestCRL OBJECT IDENTIFIER ::=  { id-ce 46 } */

/*
 * Certificate policies
 */ /**< anyPolicy OBJECT IDENTIFIER ::= { id-ce-certificatePolicies 0 } */

/*
 * Netscape certificate extensions
 */

/*
 * OIDs for CRL extensions
 */ /**< id-ce-cRLNumber OBJECT IDENTIFIER ::= { id-ce 20 } */

/*
 * X.509 v3 Extended key usage OIDs
 */ /**< anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 } */ /**< id-kp OBJECT IDENTIFIER ::= { id-pkix 3 } */ /**< id-kp-serverAuth OBJECT IDENTIFIER ::= { id-kp 1 } */ /**< id-kp-clientAuth OBJECT IDENTIFIER ::= { id-kp 2 } */ /**< id-kp-codeSigning OBJECT IDENTIFIER ::= { id-kp 3 } */ /**< id-kp-emailProtection OBJECT IDENTIFIER ::= { id-kp 4 } */ /**< id-kp-timeStamping OBJECT IDENTIFIER ::= { id-kp 8 } */ /**< id-kp-OCSPSigning OBJECT IDENTIFIER ::= { id-kp 9 } */

/**
 * Wi-SUN Alliance Field Area Network
 * { iso(1) identified-organization(3) dod(6) internet(1)
 *                      private(4) enterprise(1) WiSUN(45605) FieldAreaNetwork(1) }
 */ /**< id-on OBJECT IDENTIFIER ::= { id-pkix 8 } */ /**< id-on-hardwareModuleName OBJECT IDENTIFIER ::= { id-on 4 } */

/*
 * PKCS definition OIDs
 */ /**< pkcs OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) 1 } */ /**< pkcs-1 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 } */ /**< pkcs-5 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 5 } */ /**< pkcs-9 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 9 } */ /**< pkcs-12 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 12 } */

/*
 * PKCS#1 OIDs
 */ /**< rsaEncryption OBJECT IDENTIFIER ::= { pkcs-1 1 } */ /**< md2WithRSAEncryption ::= { pkcs-1 2 } */ /**< md4WithRSAEncryption ::= { pkcs-1 3 } */ /**< md5WithRSAEncryption ::= { pkcs-1 4 } */ /**< sha1WithRSAEncryption ::= { pkcs-1 5 } */ /**< sha224WithRSAEncryption ::= { pkcs-1 14 } */ /**< sha256WithRSAEncryption ::= { pkcs-1 11 } */ /**< sha384WithRSAEncryption ::= { pkcs-1 12 } */ /**< sha512WithRSAEncryption ::= { pkcs-1 13 } */

enum MBEDTLS_OID_RSA_SHA_OBS = "\x2B\x0E\x03\x02\x1D"; /**< emailAddress AttributeType ::= { pkcs-9 1 } */

/* RFC 4055 */ /**< id-RSASSA-PSS ::= { pkcs-1 10 } */ /**< id-mgf1 ::= { pkcs-1 8 } */

/*
 * Digest algorithms
 */ /**< id-mbedtls_md2 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 2 } */ /**< id-mbedtls_md4 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 4 } */ /**< id-mbedtls_md5 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 5 } */ /**< id-mbedtls_sha1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) 26 } */ /**< id-sha224 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 4 } */ /**< id-mbedtls_sha256 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 1 } */ /**< id-sha384 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 2 } */ /**< id-mbedtls_sha512 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 3 } */ /**< id-ripemd160 OBJECT IDENTIFIER :: { iso(1) identified-organization(3) teletrust(36) algorithm(3) hashAlgorithm(2) ripemd160(1) } */ /**< id-hmacWithSHA1 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 7 } */ /**< id-hmacWithSHA224 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 8 } */ /**< id-hmacWithSHA256 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 9 } */ /**< id-hmacWithSHA384 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 10 } */ /**< id-hmacWithSHA512 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 11 } */

/*
 * Encryption algorithms
 */ /**< desCBC OBJECT IDENTIFIER ::= { iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) 7 } */ /**< des-ede3-cbc OBJECT IDENTIFIER ::= { iso(1) member-body(2) -- us(840) rsadsi(113549) encryptionAlgorithm(3) 7 } */ /** aes OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) 1 } */

/*
 * Key Wrapping algorithms
 */
/*
 * RFC 5649
 */ /** id-aes128-wrap     OBJECT IDENTIFIER ::= { aes 5 } */ /** id-aes128-wrap-pad OBJECT IDENTIFIER ::= { aes 8 } */ /** id-aes192-wrap     OBJECT IDENTIFIER ::= { aes 25 } */ /** id-aes192-wrap-pad OBJECT IDENTIFIER ::= { aes 28 } */ /** id-aes256-wrap     OBJECT IDENTIFIER ::= { aes 45 } */ /** id-aes256-wrap-pad OBJECT IDENTIFIER ::= { aes 48 } */
/*
 * PKCS#5 OIDs
 */ /**< id-PBKDF2 OBJECT IDENTIFIER ::= {pkcs-5 12} */ /**< id-PBES2 OBJECT IDENTIFIER ::= {pkcs-5 13} */ /**< id-PBMAC1 OBJECT IDENTIFIER ::= {pkcs-5 14} */

/*
 * PKCS#5 PBES1 algorithms
 */ /**< pbeWithMD2AndDES-CBC OBJECT IDENTIFIER ::= {pkcs-5 1} */ /**< pbeWithMD2AndRC2-CBC OBJECT IDENTIFIER ::= {pkcs-5 4} */ /**< pbeWithMD5AndDES-CBC OBJECT IDENTIFIER ::= {pkcs-5 3} */ /**< pbeWithMD5AndRC2-CBC OBJECT IDENTIFIER ::= {pkcs-5 6} */ /**< pbeWithSHA1AndDES-CBC OBJECT IDENTIFIER ::= {pkcs-5 10} */ /**< pbeWithSHA1AndRC2-CBC OBJECT IDENTIFIER ::= {pkcs-5 11} */

/*
 * PKCS#8 OIDs
 */ /**< extensionRequest OBJECT IDENTIFIER ::= {pkcs-9 14} */

/*
 * PKCS#12 PBE OIDs
 */ /**< pkcs-12PbeIds OBJECT IDENTIFIER ::= {pkcs-12 1} */ /**< pbeWithSHAAnd128BitRC4 OBJECT IDENTIFIER ::= {pkcs-12PbeIds 1} */ /**< pbeWithSHAAnd40BitRC4 OBJECT IDENTIFIER ::= {pkcs-12PbeIds 2} */ /**< pbeWithSHAAnd3-KeyTripleDES-CBC OBJECT IDENTIFIER ::= {pkcs-12PbeIds 3} */ /**< pbeWithSHAAnd2-KeyTripleDES-CBC OBJECT IDENTIFIER ::= {pkcs-12PbeIds 4} */ /**< pbeWithSHAAnd128BitRC2-CBC OBJECT IDENTIFIER ::= {pkcs-12PbeIds 5} */ /**< pbeWithSHAAnd40BitRC2-CBC OBJECT IDENTIFIER ::= {pkcs-12PbeIds 6} */

/*
 * EC key algorithms from RFC 5480
 */

/* id-ecPublicKey OBJECT IDENTIFIER ::= {
 *       iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1 } */

/*   id-ecDH OBJECT IDENTIFIER ::= {
 *     iso(1) identified-organization(3) certicom(132)
 *     schemes(1) ecdh(12) } */

/*
 * ECParameters namedCurve identifiers, from RFC 5480, RFC 5639, and SEC2
 */

/* secp192r1 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3) prime(1) 1 } */

/* secp224r1 OBJECT IDENTIFIER ::= {
 *   iso(1) identified-organization(3) certicom(132) curve(0) 33 } */

/* secp256r1 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3) prime(1) 7 } */

/* secp384r1 OBJECT IDENTIFIER ::= {
 *   iso(1) identified-organization(3) certicom(132) curve(0) 34 } */

/* secp521r1 OBJECT IDENTIFIER ::= {
 *   iso(1) identified-organization(3) certicom(132) curve(0) 35 } */

/* secp192k1 OBJECT IDENTIFIER ::= {
 *   iso(1) identified-organization(3) certicom(132) curve(0) 31 } */

/* secp224k1 OBJECT IDENTIFIER ::= {
 *   iso(1) identified-organization(3) certicom(132) curve(0) 32 } */

/* secp256k1 OBJECT IDENTIFIER ::= {
 *   iso(1) identified-organization(3) certicom(132) curve(0) 10 } */

/* RFC 5639 4.1
 * ecStdCurvesAndGeneration OBJECT IDENTIFIER::= {iso(1)
 * identified-organization(3) teletrust(36) algorithm(3) signature-
 * algorithm(3) ecSign(2) 8}
 * ellipticCurve OBJECT IDENTIFIER ::= {ecStdCurvesAndGeneration 1}
 * versionOne OBJECT IDENTIFIER ::= {ellipticCurve 1} */

/* brainpoolP256r1 OBJECT IDENTIFIER ::= {versionOne 7} */

/* brainpoolP384r1 OBJECT IDENTIFIER ::= {versionOne 11} */

/* brainpoolP512r1 OBJECT IDENTIFIER ::= {versionOne 13} */

/*
 * SEC1 C.1
 *
 * prime-field OBJECT IDENTIFIER ::= { id-fieldType 1 }
 * id-fieldType OBJECT IDENTIFIER ::= { ansi-X9-62 fieldType(1)}
 */

/*
 * ECDSA signature identifiers, from RFC 5480
 */ /* signatures(4) */ /* ecdsa-with-SHA2(3) */

/* ecdsa-with-SHA1 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4) 1 } */

/* ecdsa-with-SHA224 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
 *   ecdsa-with-SHA2(3) 1 } */

/* ecdsa-with-SHA256 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
 *   ecdsa-with-SHA2(3) 2 } */

/* ecdsa-with-SHA384 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
 *   ecdsa-with-SHA2(3) 3 } */

/* ecdsa-with-SHA512 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
 *   ecdsa-with-SHA2(3) 4 } */

/**
 * \brief Base OID descriptor structure
 */
struct mbedtls_oid_descriptor_t
{
    const(char)* asn1; /*!< OID ASN.1 representation       */
    size_t asn1_len; /*!< length of asn1                 */
    const(char)* name; /*!< official name (e.g. from RFC)  */
    const(char)* description; /*!< human friendly description     */
}

/**
 * \brief           Translate an ASN.1 OID into its numeric representation
 *                  (e.g. "\x2A\x86\x48\x86\xF7\x0D" into "1.2.840.113549")
 *
 * \param buf       buffer to put representation in
 * \param size      size of the buffer
 * \param oid       OID to translate
 *
 * \return          Length of the string written (excluding final NULL) or
 *                  MBEDTLS_ERR_OID_BUF_TOO_SMALL in case of error
 */
int mbedtls_oid_get_numeric_string (char* buf, size_t size, const(mbedtls_asn1_buf)* oid);

/**
 * \brief          Translate an X.509 extension OID into local values
 *
 * \param oid      OID to use
 * \param ext_type place to store the extension type
 *
 * \return         0 if successful, or MBEDTLS_ERR_OID_NOT_FOUND
 */
int mbedtls_oid_get_x509_ext_type (const(mbedtls_asn1_buf)* oid, int* ext_type);

/**
 * \brief          Translate an X.509 attribute type OID into the short name
 *                 (e.g. the OID for an X520 Common Name into "CN")
 *
 * \param oid      OID to use
 * \param short_name    place to store the string pointer
 *
 * \return         0 if successful, or MBEDTLS_ERR_OID_NOT_FOUND
 */
int mbedtls_oid_get_attr_short_name (const(mbedtls_asn1_buf)* oid, const(char*)* short_name);

/**
 * \brief          Translate PublicKeyAlgorithm OID into pk_type
 *
 * \param oid      OID to use
 * \param pk_alg   place to store public key algorithm
 *
 * \return         0 if successful, or MBEDTLS_ERR_OID_NOT_FOUND
 */
int mbedtls_oid_get_pk_alg (const(mbedtls_asn1_buf)* oid, mbedtls_pk_type_t* pk_alg);

/**
 * \brief          Translate pk_type into PublicKeyAlgorithm OID
 *
 * \param pk_alg   Public key type to look for
 * \param oid      place to store ASN.1 OID string pointer
 * \param olen     length of the OID
 *
 * \return         0 if successful, or MBEDTLS_ERR_OID_NOT_FOUND
 */
int mbedtls_oid_get_oid_by_pk_alg (
    mbedtls_pk_type_t pk_alg,
    const(char*)* oid,
    size_t* olen);

/**
 * \brief          Translate NamedCurve OID into an EC group identifier
 *
 * \param oid      OID to use
 * \param grp_id   place to store group id
 *
 * \return         0 if successful, or MBEDTLS_ERR_OID_NOT_FOUND
 */
int mbedtls_oid_get_ec_grp (const(mbedtls_asn1_buf)* oid, mbedtls_ecp_group_id* grp_id);

/**
 * \brief          Translate EC group identifier into NamedCurve OID
 *
 * \param grp_id   EC group identifier
 * \param oid      place to store ASN.1 OID string pointer
 * \param olen     length of the OID
 *
 * \return         0 if successful, or MBEDTLS_ERR_OID_NOT_FOUND
 */
int mbedtls_oid_get_oid_by_ec_grp (
    mbedtls_ecp_group_id grp_id,
    const(char*)* oid,
    size_t* olen);
/* MBEDTLS_ECP_C */

/**
 * \brief          Translate SignatureAlgorithm OID into md_type and pk_type
 *
 * \param oid      OID to use
 * \param md_alg   place to store message digest algorithm
 * \param pk_alg   place to store public key algorithm
 *
 * \return         0 if successful, or MBEDTLS_ERR_OID_NOT_FOUND
 */
int mbedtls_oid_get_sig_alg (
    const(mbedtls_asn1_buf)* oid,
    mbedtls_md_type_t* md_alg,
    mbedtls_pk_type_t* pk_alg);

/**
 * \brief          Translate SignatureAlgorithm OID into description
 *
 * \param oid      OID to use
 * \param desc     place to store string pointer
 *
 * \return         0 if successful, or MBEDTLS_ERR_OID_NOT_FOUND
 */
int mbedtls_oid_get_sig_alg_desc (const(mbedtls_asn1_buf)* oid, const(char*)* desc);

/**
 * \brief          Translate md_type and pk_type into SignatureAlgorithm OID
 *
 * \param md_alg   message digest algorithm
 * \param pk_alg   public key algorithm
 * \param oid      place to store ASN.1 OID string pointer
 * \param olen     length of the OID
 *
 * \return         0 if successful, or MBEDTLS_ERR_OID_NOT_FOUND
 */
int mbedtls_oid_get_oid_by_sig_alg (
    mbedtls_pk_type_t pk_alg,
    mbedtls_md_type_t md_alg,
    const(char*)* oid,
    size_t* olen);

/**
 * \brief          Translate hash algorithm OID into md_type
 *
 * \param oid      OID to use
 * \param md_alg   place to store message digest algorithm
 *
 * \return         0 if successful, or MBEDTLS_ERR_OID_NOT_FOUND
 */
int mbedtls_oid_get_md_alg (const(mbedtls_asn1_buf)* oid, mbedtls_md_type_t* md_alg);

/**
 * \brief          Translate hmac algorithm OID into md_type
 *
 * \param oid      OID to use
 * \param md_hmac  place to store message hmac algorithm
 *
 * \return         0 if successful, or MBEDTLS_ERR_OID_NOT_FOUND
 */
int mbedtls_oid_get_md_hmac (const(mbedtls_asn1_buf)* oid, mbedtls_md_type_t* md_hmac);
/* MBEDTLS_MD_C */

/**
 * \brief          Translate Extended Key Usage OID into description
 *
 * \param oid      OID to use
 * \param desc     place to store string pointer
 *
 * \return         0 if successful, or MBEDTLS_ERR_OID_NOT_FOUND
 */
int mbedtls_oid_get_extended_key_usage (const(mbedtls_asn1_buf)* oid, const(char*)* desc);

/**
 * \brief          Translate certificate policies OID into description
 *
 * \param oid      OID to use
 * \param desc     place to store string pointer
 *
 * \return         0 if successful, or MBEDTLS_ERR_OID_NOT_FOUND
 */
int mbedtls_oid_get_certificate_policies (const(mbedtls_asn1_buf)* oid, const(char*)* desc);

/**
 * \brief          Translate md_type into hash algorithm OID
 *
 * \param md_alg   message digest algorithm
 * \param oid      place to store ASN.1 OID string pointer
 * \param olen     length of the OID
 *
 * \return         0 if successful, or MBEDTLS_ERR_OID_NOT_FOUND
 */
int mbedtls_oid_get_oid_by_md (mbedtls_md_type_t md_alg, const(char*)* oid, size_t* olen);

/**
 * \brief          Translate encryption algorithm OID into cipher_type
 *
 * \param oid           OID to use
 * \param cipher_alg    place to store cipher algorithm
 *
 * \return         0 if successful, or MBEDTLS_ERR_OID_NOT_FOUND
 */
int mbedtls_oid_get_cipher_alg (const(mbedtls_asn1_buf)* oid, mbedtls_cipher_type_t* cipher_alg);
/* MBEDTLS_CIPHER_C */

/**
 * \brief          Translate PKCS#12 PBE algorithm OID into md_type and
 *                 cipher_type
 *
 * \param oid           OID to use
 * \param md_alg        place to store message digest algorithm
 * \param cipher_alg    place to store cipher algorithm
 *
 * \return         0 if successful, or MBEDTLS_ERR_OID_NOT_FOUND
 */
int mbedtls_oid_get_pkcs12_pbe_alg (
    const(mbedtls_asn1_buf)* oid,
    mbedtls_md_type_t* md_alg,
    mbedtls_cipher_type_t* cipher_alg);
/* MBEDTLS_PKCS12_C */

/* oid.h */
