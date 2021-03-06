module c.openssl.objects;

import core.stdc.config;

public import c.openssl.bio;
//public import c.openssl.asn1;

version = USE_OBJ_MAC;

version(USE_OBJ_MAC)
{
	public import c.openssl.obj_mac;
}
else
{
enum SN_undef = "UNDEF";
enum LN_undef = "undefined";
enum NID_undef = 0;
// #define OBJ_undef			0L

enum SN_Algorithm = "Algorithm";
enum LN_algorithm = "algorithm";
enum NID_algorithm = 38;
// #define OBJ_algorithm			1L,3L,14L,3L,2L

enum LN_rsadsi = "rsadsi";
enum NID_rsadsi = 1;
// #define OBJ_rsadsi			1L,2L,840L,113549L

enum LN_pkcs = "pkcs";
enum NID_pkcs = 2;
// #define OBJ_pkcs			OBJ_rsadsi,1L

enum SN_md2 = "MD2";
enum LN_md2 = "md2";
enum NID_md2 = 3;
// #define OBJ_md2				OBJ_rsadsi,2L,2L

enum SN_md5 = "MD5";
enum LN_md5 = "md5";
enum NID_md5 = 4;
// #define OBJ_md5				OBJ_rsadsi,2L,5L

enum SN_rc4 = "RC4";
enum LN_rc4 = "rc4";
enum NID_rc4 = 5;
// #define OBJ_rc4				OBJ_rsadsi,3L,4L

enum LN_rsaEncryption = "rsaEncryption";
enum NID_rsaEncryption = 6;
// #define OBJ_rsaEncryption		OBJ_pkcs,1L,1L

enum SN_md2WithRSAEncryption = "RSA-MD2";
enum LN_md2WithRSAEncryption = "md2WithRSAEncryption";
enum NID_md2WithRSAEncryption = 7;
// #define OBJ_md2WithRSAEncryption	OBJ_pkcs,1L,2L

enum SN_md5WithRSAEncryption = "RSA-MD5";
enum LN_md5WithRSAEncryption = "md5WithRSAEncryption";
enum NID_md5WithRSAEncryption = 8;
// #define OBJ_md5WithRSAEncryption	OBJ_pkcs,1L,4L

enum SN_pbeWithMD2AndDES_CBC = "PBE-MD2-DES";
enum LN_pbeWithMD2AndDES_CBC = "pbeWithMD2AndDES-CBC";
enum NID_pbeWithMD2AndDES_CBC = 9;
// #define OBJ_pbeWithMD2AndDES_CBC	OBJ_pkcs,5L,1L

enum SN_pbeWithMD5AndDES_CBC = "PBE-MD5-DES";
enum LN_pbeWithMD5AndDES_CBC = "pbeWithMD5AndDES-CBC";
enum NID_pbeWithMD5AndDES_CBC = 10;
// #define OBJ_pbeWithMD5AndDES_CBC	OBJ_pkcs,5L,3L

enum LN_X500 = "X500";
enum NID_X500 = 11;
// #define OBJ_X500			2L,5L

enum LN_X509 = "X509";
enum NID_X509 = 12;
// #define OBJ_X509			OBJ_X500,4L

enum SN_commonName = "CN";
enum LN_commonName = "commonName";
enum NID_commonName = 13;
// #define OBJ_commonName			OBJ_X509,3L

enum SN_countryName = "C";
enum LN_countryName = "countryName";
enum NID_countryName = 14;
// #define OBJ_countryName			OBJ_X509,6L

enum SN_localityName = "L";
enum LN_localityName = "localityName";
enum NID_localityName = 15;
// #define OBJ_localityName		OBJ_X509,7L

/* Postal Address? PA */

/* should be "ST" (rfc1327) but MS uses 'S' */
enum SN_stateOrProvinceName = "ST";
enum LN_stateOrProvinceName = "stateOrProvinceName";
enum NID_stateOrProvinceName = 16;
// #define OBJ_stateOrProvinceName		OBJ_X509,8L

enum SN_organizationName = "O";
enum LN_organizationName = "organizationName";
enum NID_organizationName = 17;
// #define OBJ_organizationName		OBJ_X509,10L

enum SN_organizationalUnitName = "OU";
enum LN_organizationalUnitName = "organizationalUnitName";
enum NID_organizationalUnitName = 18;
// #define OBJ_organizationalUnitName	OBJ_X509,11L

enum SN_rsa = "RSA";
enum LN_rsa = "rsa";
enum NID_rsa = 19;
// #define OBJ_rsa				OBJ_X500,8L,1L,1L

enum LN_pkcs7 = "pkcs7";
enum NID_pkcs7 = 20;
// #define OBJ_pkcs7			OBJ_pkcs,7L

enum LN_pkcs7_data = "pkcs7-data";
enum NID_pkcs7_data = 21;
// #define OBJ_pkcs7_data			OBJ_pkcs7,1L

enum LN_pkcs7_signed = "pkcs7-signedData";
enum NID_pkcs7_signed = 22;
// #define OBJ_pkcs7_signed		OBJ_pkcs7,2L

enum LN_pkcs7_enveloped = "pkcs7-envelopedData";
enum NID_pkcs7_enveloped = 23;
// #define OBJ_pkcs7_enveloped		OBJ_pkcs7,3L

enum LN_pkcs7_signedAndEnveloped = "pkcs7-signedAndEnvelopedData";
enum NID_pkcs7_signedAndEnveloped = 24;
// #define OBJ_pkcs7_signedAndEnveloped	OBJ_pkcs7,4L

enum LN_pkcs7_digest = "pkcs7-digestData";
enum NID_pkcs7_digest = 25;
// #define OBJ_pkcs7_digest		OBJ_pkcs7,5L

enum LN_pkcs7_encrypted = "pkcs7-encryptedData";
enum NID_pkcs7_encrypted = 26;
// #define OBJ_pkcs7_encrypted		OBJ_pkcs7,6L

enum LN_pkcs3 = "pkcs3";
enum NID_pkcs3 = 27;
// #define OBJ_pkcs3			OBJ_pkcs,3L

enum LN_dhKeyAgreement = "dhKeyAgreement";
enum NID_dhKeyAgreement = 28;
// #define OBJ_dhKeyAgreement		OBJ_pkcs3,1L

enum SN_des_ecb = "DES-ECB";
enum LN_des_ecb = "des-ecb";
enum NID_des_ecb = 29;
// #define OBJ_des_ecb			OBJ_algorithm,6L

enum SN_des_cfb64 = "DES-CFB";
enum LN_des_cfb64 = "des-cfb";
enum NID_des_cfb64 = 30;
/* IV + num */
// #define OBJ_des_cfb64			OBJ_algorithm,9L

enum SN_des_cbc = "DES-CBC";
enum LN_des_cbc = "des-cbc";
enum NID_des_cbc = 31;
/* IV */
// #define OBJ_des_cbc			OBJ_algorithm,7L

enum SN_des_ede = "DES-EDE";
enum LN_des_ede = "des-ede";
enum NID_des_ede = 32;
/* ?? */
// #define OBJ_des_ede			OBJ_algorithm,17L

enum SN_des_ede3 = "DES-EDE3";
enum LN_des_ede3 = "des-ede3";
enum NID_des_ede3 = 33;

enum SN_idea_cbc = "IDEA-CBC";
enum LN_idea_cbc = "idea-cbc";
enum NID_idea_cbc = 34;
// #define OBJ_idea_cbc			1L,3L,6L,1L,4L,1L,188L,7L,1L,1L,2L

enum SN_idea_cfb64 = "IDEA-CFB";
enum LN_idea_cfb64 = "idea-cfb";
enum NID_idea_cfb64 = 35;

enum SN_idea_ecb = "IDEA-ECB";
enum LN_idea_ecb = "idea-ecb";
enum NID_idea_ecb = 36;

enum SN_rc2_cbc = "RC2-CBC";
enum LN_rc2_cbc = "rc2-cbc";
enum NID_rc2_cbc = 37;
// #define OBJ_rc2_cbc			OBJ_rsadsi,3L,2L

enum SN_rc2_ecb = "RC2-ECB";
enum LN_rc2_ecb = "rc2-ecb";
enum NID_rc2_ecb = 38;

enum SN_rc2_cfb64 = "RC2-CFB";
enum LN_rc2_cfb64 = "rc2-cfb";
enum NID_rc2_cfb64 = 39;

enum SN_rc2_ofb64 = "RC2-OFB";
enum LN_rc2_ofb64 = "rc2-ofb";
enum NID_rc2_ofb64 = 40;

enum SN_sha = "SHA";
enum LN_sha = "sha";
enum NID_sha = 41;
// #define OBJ_sha				OBJ_algorithm,18L

enum SN_shaWithRSAEncryption = "RSA-SHA";
enum LN_shaWithRSAEncryption = "shaWithRSAEncryption";
enum NID_shaWithRSAEncryption = 42;
// #define OBJ_shaWithRSAEncryption	OBJ_algorithm,15L

enum SN_des_ede_cbc = "DES-EDE-CBC";
enum LN_des_ede_cbc = "des-ede-cbc";
enum NID_des_ede_cbc = 43;

enum SN_des_ede3_cbc = "DES-EDE3-CBC";
enum LN_des_ede3_cbc = "des-ede3-cbc";
enum NID_des_ede3_cbc = 44;
// #define OBJ_des_ede3_cbc		OBJ_rsadsi,3L,7L

enum SN_des_ofb64 = "DES-OFB";
enum LN_des_ofb64 = "des-ofb";
enum NID_des_ofb64 = 45;
// #define OBJ_des_ofb64			OBJ_algorithm,8L

enum SN_idea_ofb64 = "IDEA-OFB";
enum LN_idea_ofb64 = "idea-ofb";
enum NID_idea_ofb64 = 46;

enum LN_pkcs9 = "pkcs9";
enum NID_pkcs9 = 47;
// #define OBJ_pkcs9			OBJ_pkcs,9L

enum SN_pkcs9_emailAddress = "Email";
enum LN_pkcs9_emailAddress = "emailAddress";
enum NID_pkcs9_emailAddress = 48;
// #define OBJ_pkcs9_emailAddress		OBJ_pkcs9,1L

enum LN_pkcs9_unstructuredName = "unstructuredName";
enum NID_pkcs9_unstructuredName = 49;
// #define OBJ_pkcs9_unstructuredName	OBJ_pkcs9,2L

enum LN_pkcs9_contentType = "contentType";
enum NID_pkcs9_contentType = 50;
// #define OBJ_pkcs9_contentType		OBJ_pkcs9,3L

enum LN_pkcs9_messageDigest = "messageDigest";
enum NID_pkcs9_messageDigest = 51;
// #define OBJ_pkcs9_messageDigest		OBJ_pkcs9,4L

enum LN_pkcs9_signingTime = "signingTime";
enum NID_pkcs9_signingTime = 52;
// #define OBJ_pkcs9_signingTime		OBJ_pkcs9,5L

enum LN_pkcs9_countersignature = "countersignature";
enum NID_pkcs9_countersignature = 53;
// #define OBJ_pkcs9_countersignature	OBJ_pkcs9,6L

enum LN_pkcs9_challengePassword = "challengePassword";
enum NID_pkcs9_challengePassword = 54;
// #define OBJ_pkcs9_challengePassword	OBJ_pkcs9,7L

enum LN_pkcs9_unstructuredAddress = "unstructuredAddress";
enum NID_pkcs9_unstructuredAddress = 55;
// #define OBJ_pkcs9_unstructuredAddress	OBJ_pkcs9,8L

enum LN_pkcs9_extCertAttributes = "extendedCertificateAttributes";
enum NID_pkcs9_extCertAttributes = 56;
// #define OBJ_pkcs9_extCertAttributes	OBJ_pkcs9,9L

enum SN_netscape = "Netscape";
enum LN_netscape = "Netscape Communications Corp.";
enum NID_netscape = 57;
// #define OBJ_netscape			2L,16L,840L,1L,113730L

enum SN_netscape_cert_extension = "nsCertExt";
enum LN_netscape_cert_extension = "Netscape Certificate Extension";
enum NID_netscape_cert_extension = 58;
// #define OBJ_netscape_cert_extension	OBJ_netscape,1L

enum SN_netscape_data_type = "nsDataType";
enum LN_netscape_data_type = "Netscape Data Type";
enum NID_netscape_data_type = 59;
// #define OBJ_netscape_data_type		OBJ_netscape,2L

enum SN_des_ede_cfb64 = "DES-EDE-CFB";
enum LN_des_ede_cfb64 = "des-ede-cfb";
enum NID_des_ede_cfb64 = 60;

enum SN_des_ede3_cfb64 = "DES-EDE3-CFB";
enum LN_des_ede3_cfb64 = "des-ede3-cfb";
enum NID_des_ede3_cfb64 = 61;

enum SN_des_ede_ofb64 = "DES-EDE-OFB";
enum LN_des_ede_ofb64 = "des-ede-ofb";
enum NID_des_ede_ofb64 = 62;

enum SN_des_ede3_ofb64 = "DES-EDE3-OFB";
enum LN_des_ede3_ofb64 = "des-ede3-ofb";
enum NID_des_ede3_ofb64 = 63;

/* I'm not sure about the object ID */
enum SN_sha1 = "SHA1";
enum LN_sha1 = "sha1";
enum NID_sha1 = 64;
// #define OBJ_sha1			OBJ_algorithm,26L
/* 28 Jun 1996 - eay */
/* #define OBJ_sha1			1L,3L,14L,2L,26L,05L <- wrong */

enum SN_sha1WithRSAEncryption = "RSA-SHA1";
enum LN_sha1WithRSAEncryption = "sha1WithRSAEncryption";
enum NID_sha1WithRSAEncryption = 65;
// #define OBJ_sha1WithRSAEncryption	OBJ_pkcs,1L,5L

enum SN_dsaWithSHA = "DSA-SHA";
enum LN_dsaWithSHA = "dsaWithSHA";
enum NID_dsaWithSHA = 66;
// #define OBJ_dsaWithSHA			OBJ_algorithm,13L

enum SN_dsa_2 = "DSA-old";
enum LN_dsa_2 = "dsaEncryption-old";
enum NID_dsa_2 = 67;
// #define OBJ_dsa_2			OBJ_algorithm,12L

/* proposed by microsoft to RSA */
enum SN_pbeWithSHA1AndRC2_CBC = "PBE-SHA1-RC2-64";
enum LN_pbeWithSHA1AndRC2_CBC = "pbeWithSHA1AndRC2-CBC";
enum NID_pbeWithSHA1AndRC2_CBC = 68;
// #define OBJ_pbeWithSHA1AndRC2_CBC	OBJ_pkcs,5L,11L

/* proposed by microsoft to RSA as pbeWithSHA1AndRC4: it is now
 * defined explicitly in PKCS#5 v2.0 as id-PBKDF2 which is something
 * completely different.
 */
enum LN_id_pbkdf2 = "PBKDF2";
enum NID_id_pbkdf2 = 69;
// #define OBJ_id_pbkdf2			OBJ_pkcs,5L,12L

enum SN_dsaWithSHA1_2 = "DSA-SHA1-old";
enum LN_dsaWithSHA1_2 = "dsaWithSHA1-old";
enum NID_dsaWithSHA1_2 = 70;
/* Got this one from 'sdn706r20.pdf' which is actually an NSA document :-) */
// #define OBJ_dsaWithSHA1_2		OBJ_algorithm,27L

enum SN_netscape_cert_type = "nsCertType";
enum LN_netscape_cert_type = "Netscape Cert Type";
enum NID_netscape_cert_type = 71;
// #define OBJ_netscape_cert_type		OBJ_netscape_cert_extension,1L

enum SN_netscape_base_url = "nsBaseUrl";
enum LN_netscape_base_url = "Netscape Base Url";
enum NID_netscape_base_url = 72;
// #define OBJ_netscape_base_url		OBJ_netscape_cert_extension,2L

enum SN_netscape_revocation_url = "nsRevocationUrl";
enum LN_netscape_revocation_url = "Netscape Revocation Url";
enum NID_netscape_revocation_url = 73;
// #define OBJ_netscape_revocation_url	OBJ_netscape_cert_extension,3L

enum SN_netscape_ca_revocation_url = "nsCaRevocationUrl";
enum LN_netscape_ca_revocation_url = "Netscape CA Revocation Url";
enum NID_netscape_ca_revocation_url = 74;
// #define OBJ_netscape_ca_revocation_url	OBJ_netscape_cert_extension,4L

enum SN_netscape_renewal_url = "nsRenewalUrl";
enum LN_netscape_renewal_url = "Netscape Renewal Url";
enum NID_netscape_renewal_url = 75;
// #define OBJ_netscape_renewal_url	OBJ_netscape_cert_extension,7L

enum SN_netscape_ca_policy_url = "nsCaPolicyUrl";
enum LN_netscape_ca_policy_url = "Netscape CA Policy Url";
enum NID_netscape_ca_policy_url = 76;
// #define OBJ_netscape_ca_policy_url	OBJ_netscape_cert_extension,8L

enum SN_netscape_ssl_server_name = "nsSslServerName";
enum LN_netscape_ssl_server_name = "Netscape SSL Server Name";
enum NID_netscape_ssl_server_name = 77;
// #define OBJ_netscape_ssl_server_name	OBJ_netscape_cert_extension,12L

enum SN_netscape_comment = "nsComment";
enum LN_netscape_comment = "Netscape Comment";
enum NID_netscape_comment = 78;
// #define OBJ_netscape_comment		OBJ_netscape_cert_extension,13L

enum SN_netscape_cert_sequence = "nsCertSequence";
enum LN_netscape_cert_sequence = "Netscape Certificate Sequence";
enum NID_netscape_cert_sequence = 79;
// #define OBJ_netscape_cert_sequence	OBJ_netscape_data_type,5L

enum SN_desx_cbc = "DESX-CBC";
enum LN_desx_cbc = "desx-cbc";
enum NID_desx_cbc = 80;

enum SN_id_ce = "id-ce";
enum NID_id_ce = 81;
// #define OBJ_id_ce			2L,5L,29L

enum SN_subject_key_identifier = "subjectKeyIdentifier";
enum LN_subject_key_identifier = "X509v3 Subject Key Identifier";
enum NID_subject_key_identifier = 82;
// #define OBJ_subject_key_identifier	OBJ_id_ce,14L

enum SN_key_usage = "keyUsage";
enum LN_key_usage = "X509v3 Key Usage";
enum NID_key_usage = 83;
// #define OBJ_key_usage			OBJ_id_ce,15L

enum SN_private_key_usage_period = "privateKeyUsagePeriod";
enum LN_private_key_usage_period = "X509v3 Private Key Usage Period";
enum NID_private_key_usage_period = 84;
// #define OBJ_private_key_usage_period	OBJ_id_ce,16L

enum SN_subject_alt_name = "subjectAltName";
enum LN_subject_alt_name = "X509v3 Subject Alternative Name";
enum NID_subject_alt_name = 85;
// #define OBJ_subject_alt_name		OBJ_id_ce,17L

enum SN_issuer_alt_name = "issuerAltName";
enum LN_issuer_alt_name = "X509v3 Issuer Alternative Name";
enum NID_issuer_alt_name = 86;
// #define OBJ_issuer_alt_name		OBJ_id_ce,18L

enum SN_basic_constraints = "basicConstraints";
enum LN_basic_constraints = "X509v3 Basic Constraints";
enum NID_basic_constraints = 87;
// #define OBJ_basic_constraints		OBJ_id_ce,19L

enum SN_crl_number = "crlNumber";
enum LN_crl_number = "X509v3 CRL Number";
enum NID_crl_number = 88;
// #define OBJ_crl_number			OBJ_id_ce,20L

enum SN_certificate_policies = "certificatePolicies";
enum LN_certificate_policies = "X509v3 Certificate Policies";
enum NID_certificate_policies = 89;
// #define OBJ_certificate_policies	OBJ_id_ce,32L

enum SN_authority_key_identifier = "authorityKeyIdentifier";
enum LN_authority_key_identifier = "X509v3 Authority Key Identifier";
enum NID_authority_key_identifier = 90;
// #define OBJ_authority_key_identifier	OBJ_id_ce,35L

enum SN_bf_cbc = "BF-CBC";
enum LN_bf_cbc = "bf-cbc";
enum NID_bf_cbc = 91;
// #define OBJ_bf_cbc			1L,3L,6L,1L,4L,1L,3029L,1L,2L

enum SN_bf_ecb = "BF-ECB";
enum LN_bf_ecb = "bf-ecb";
enum NID_bf_ecb = 92;

enum SN_bf_cfb64 = "BF-CFB";
enum LN_bf_cfb64 = "bf-cfb";
enum NID_bf_cfb64 = 93;

enum SN_bf_ofb64 = "BF-OFB";
enum LN_bf_ofb64 = "bf-ofb";
enum NID_bf_ofb64 = 94;

enum SN_mdc2 = "MDC2";
enum LN_mdc2 = "mdc2";
enum NID_mdc2 = 95;
// #define OBJ_mdc2			2L,5L,8L,3L,101L
/* An alternative?			1L,3L,14L,3L,2L,19L */

enum SN_mdc2WithRSA = "RSA-MDC2";
enum LN_mdc2WithRSA = "mdc2withRSA";
enum NID_mdc2WithRSA = 96;
// #define OBJ_mdc2WithRSA			2L,5L,8L,3L,100L

enum SN_rc4_40 = "RC4-40";
enum LN_rc4_40 = "rc4-40";
enum NID_rc4_40 = 97;

enum SN_rc2_40_cbc = "RC2-40-CBC";
enum LN_rc2_40_cbc = "rc2-40-cbc";
enum NID_rc2_40_cbc = 98;

enum SN_givenName = "G";
enum LN_givenName = "givenName";
enum NID_givenName = 99;
// #define OBJ_givenName			OBJ_X509,42L

enum SN_surname = "S";
enum LN_surname = "surname";
enum NID_surname = 100;
// #define OBJ_surname			OBJ_X509,4L

enum SN_initials = "I";
enum LN_initials = "initials";
enum NID_initials = 101;
// #define OBJ_initials			OBJ_X509,43L

enum SN_uniqueIdentifier = "UID";
enum LN_uniqueIdentifier = "uniqueIdentifier";
enum NID_uniqueIdentifier = 102;
// #define OBJ_uniqueIdentifier		OBJ_X509,45L

enum SN_crl_distribution_points = "crlDistributionPoints";
enum LN_crl_distribution_points = "X509v3 CRL Distribution Points";
enum NID_crl_distribution_points = 103;
// #define OBJ_crl_distribution_points	OBJ_id_ce,31L

enum SN_md5WithRSA = "RSA-NP-MD5";
enum LN_md5WithRSA = "md5WithRSA";
enum NID_md5WithRSA = 104;
// #define OBJ_md5WithRSA			OBJ_algorithm,3L

enum SN_serialNumber = "SN";
enum LN_serialNumber = "serialNumber";
enum NID_serialNumber = 105;
// #define OBJ_serialNumber		OBJ_X509,5L

enum SN_title = "T";
enum LN_title = "title";
enum NID_title = 106;
// #define OBJ_title			OBJ_X509,12L

enum SN_description = "D";
enum LN_description = "description";
enum NID_description = 107;
// #define OBJ_description			OBJ_X509,13L

/* CAST5 is CAST-128, I'm just sticking with the documentation */
enum SN_cast5_cbc = "CAST5-CBC";
enum LN_cast5_cbc = "cast5-cbc";
enum NID_cast5_cbc = 108;
// #define OBJ_cast5_cbc			1L,2L,840L,113533L,7L,66L,10L

enum SN_cast5_ecb = "CAST5-ECB";
enum LN_cast5_ecb = "cast5-ecb";
enum NID_cast5_ecb = 109;

enum SN_cast5_cfb64 = "CAST5-CFB";
enum LN_cast5_cfb64 = "cast5-cfb";
enum NID_cast5_cfb64 = 110;

enum SN_cast5_ofb64 = "CAST5-OFB";
enum LN_cast5_ofb64 = "cast5-ofb";
enum NID_cast5_ofb64 = 111;

enum LN_pbeWithMD5AndCast5_CBC = "pbeWithMD5AndCast5CBC";
enum NID_pbeWithMD5AndCast5_CBC = 112;
// #define OBJ_pbeWithMD5AndCast5_CBC	1L,2L,840L,113533L,7L,66L,12L

/* This is one sun will soon be using :-(
 * id-dsa-with-sha1 ID  ::= {
 *   iso(1) member-body(2) us(840) x9-57 (10040) x9cm(4) 3 }
 */
enum SN_dsaWithSHA1 = "DSA-SHA1";
enum LN_dsaWithSHA1 = "dsaWithSHA1";
enum NID_dsaWithSHA1 = 113;
// #define OBJ_dsaWithSHA1			1L,2L,840L,10040L,4L,3L

enum NID_md5_sha1 = 114;
enum SN_md5_sha1 = "MD5-SHA1";
enum LN_md5_sha1 = "md5-sha1";

enum SN_sha1WithRSA = "RSA-SHA1-2";
enum LN_sha1WithRSA = "sha1WithRSA";
enum NID_sha1WithRSA = 115;
// #define OBJ_sha1WithRSA			OBJ_algorithm,29L

enum SN_dsa = "DSA";
enum LN_dsa = "dsaEncryption";
enum NID_dsa = 116;
// #define OBJ_dsa				1L,2L,840L,10040L,4L,1L

enum SN_ripemd160 = "RIPEMD160";
enum LN_ripemd160 = "ripemd160";
enum NID_ripemd160 = 117;
// #define OBJ_ripemd160			1L,3L,36L,3L,2L,1L

/* The name should actually be rsaSignatureWithripemd160, but I'm going
 * to continue using the convention I'm using with the other ciphers */
enum SN_ripemd160WithRSA = "RSA-RIPEMD160";
enum LN_ripemd160WithRSA = "ripemd160WithRSA";
enum NID_ripemd160WithRSA = 119;
// #define OBJ_ripemd160WithRSA		1L,3L,36L,3L,3L,1L,2L

/* Taken from rfc2040
 *  RC5_CBC_Parameters ::= SEQUENCE {
 *	version           INTEGER (v1_0(16)),
 *	rounds            INTEGER (8..127),
 *	blockSizeInBits   INTEGER (64, 128),
 *	iv                OCTET STRING OPTIONAL
 *	}
 */
enum SN_rc5_cbc = "RC5-CBC";
enum LN_rc5_cbc = "rc5-cbc";
enum NID_rc5_cbc = 120;
// #define OBJ_rc5_cbc			OBJ_rsadsi,3L,8L

enum SN_rc5_ecb = "RC5-ECB";
enum LN_rc5_ecb = "rc5-ecb";
enum NID_rc5_ecb = 121;

enum SN_rc5_cfb64 = "RC5-CFB";
enum LN_rc5_cfb64 = "rc5-cfb";
enum NID_rc5_cfb64 = 122;

enum SN_rc5_ofb64 = "RC5-OFB";
enum LN_rc5_ofb64 = "rc5-ofb";
enum NID_rc5_ofb64 = 123;

enum SN_rle_compression = "RLE";
enum LN_rle_compression = "run length compression";
enum NID_rle_compression = 124;
// #define OBJ_rle_compression		1L,1L,1L,1L,666L,1L

enum SN_zlib_compression = "ZLIB";
enum LN_zlib_compression = "zlib compression";
enum NID_zlib_compression = 125;
// #define OBJ_zlib_compression		1L,1L,1L,1L,666L,2L

enum SN_ext_key_usage = "extendedKeyUsage";
enum LN_ext_key_usage = "X509v3 Extended Key Usage";
enum NID_ext_key_usage = 126;
// #define OBJ_ext_key_usage		OBJ_id_ce,37

enum SN_id_pkix = "PKIX";
enum NID_id_pkix = 127;
// #define OBJ_id_pkix			1L,3L,6L,1L,5L,5L,7L

enum SN_id_kp = "id-kp";
enum NID_id_kp = 128;
// #define OBJ_id_kp			OBJ_id_pkix,3L

/* PKIX extended key usage OIDs */

enum SN_server_auth = "serverAuth";
enum LN_server_auth = "TLS Web Server Authentication";
enum NID_server_auth = 129;
// #define OBJ_server_auth			OBJ_id_kp,1L

enum SN_client_auth = "clientAuth";
enum LN_client_auth = "TLS Web Client Authentication";
enum NID_client_auth = 130;
// #define OBJ_client_auth			OBJ_id_kp,2L

enum SN_code_sign = "codeSigning";
enum LN_code_sign = "Code Signing";
enum NID_code_sign = 131;
// #define OBJ_code_sign			OBJ_id_kp,3L

enum SN_email_protect = "emailProtection";
enum LN_email_protect = "E-mail Protection";
enum NID_email_protect = 132;
// #define OBJ_email_protect		OBJ_id_kp,4L

enum SN_time_stamp = "timeStamping";
enum LN_time_stamp = "Time Stamping";
enum NID_time_stamp = 133;
// #define OBJ_time_stamp			OBJ_id_kp,8L

/* Additional extended key usage OIDs: Microsoft */

enum SN_ms_code_ind = "msCodeInd";
enum LN_ms_code_ind = "Microsoft Individual Code Signing";
enum NID_ms_code_ind = 134;
// #define OBJ_ms_code_ind			1L,3L,6L,1L,4L,1L,311L,2L,1L,21L

enum SN_ms_code_com = "msCodeCom";
enum LN_ms_code_com = "Microsoft Commercial Code Signing";
enum NID_ms_code_com = 135;
// #define OBJ_ms_code_com			1L,3L,6L,1L,4L,1L,311L,2L,1L,22L

enum SN_ms_ctl_sign = "msCTLSign";
enum LN_ms_ctl_sign = "Microsoft Trust List Signing";
enum NID_ms_ctl_sign = 136;
// #define OBJ_ms_ctl_sign			1L,3L,6L,1L,4L,1L,311L,10L,3L,1L

enum SN_ms_sgc = "msSGC";
enum LN_ms_sgc = "Microsoft Server Gated Crypto";
enum NID_ms_sgc = 137;
// #define OBJ_ms_sgc			1L,3L,6L,1L,4L,1L,311L,10L,3L,3L

enum SN_ms_efs = "msEFS";
enum LN_ms_efs = "Microsoft Encrypted File System";
enum NID_ms_efs = 138;
// #define OBJ_ms_efs			1L,3L,6L,1L,4L,1L,311L,10L,3L,4L

/* Additional usage: Netscape */

enum SN_ns_sgc = "nsSGC";
enum LN_ns_sgc = "Netscape Server Gated Crypto";
enum NID_ns_sgc = 139;
// #define OBJ_ns_sgc			OBJ_netscape,4L,1L

enum SN_delta_crl = "deltaCRL";
enum LN_delta_crl = "X509v3 Delta CRL Indicator";
enum NID_delta_crl = 140;
// #define OBJ_delta_crl			OBJ_id_ce,27L

enum SN_crl_reason = "CRLReason";
enum LN_crl_reason = "CRL Reason Code";
enum NID_crl_reason = 141;
// #define OBJ_crl_reason			OBJ_id_ce,21L

enum SN_invalidity_date = "invalidityDate";
enum LN_invalidity_date = "Invalidity Date";
enum NID_invalidity_date = 142;
// #define OBJ_invalidity_date		OBJ_id_ce,24L

enum SN_sxnet = "SXNetID";
enum LN_sxnet = "Strong Extranet ID";
enum NID_sxnet = 143;
// #define OBJ_sxnet			1L,3L,101L,1L,4L,1L

/* PKCS12 and related OBJECT IDENTIFIERS */

// #define OBJ_pkcs12			OBJ_pkcs,12L
// #define OBJ_pkcs12_pbeids		OBJ_pkcs12, 1

enum SN_pbe_WithSHA1And128BitRC4 = "PBE-SHA1-RC4-128";
enum LN_pbe_WithSHA1And128BitRC4 = "pbeWithSHA1And128BitRC4";
enum NID_pbe_WithSHA1And128BitRC4 = 144;
// #define OBJ_pbe_WithSHA1And128BitRC4	OBJ_pkcs12_pbeids, 1L

enum SN_pbe_WithSHA1And40BitRC4 = "PBE-SHA1-RC4-40";
enum LN_pbe_WithSHA1And40BitRC4 = "pbeWithSHA1And40BitRC4";
enum NID_pbe_WithSHA1And40BitRC4 = 145;
// #define OBJ_pbe_WithSHA1And40BitRC4	OBJ_pkcs12_pbeids, 2L

enum SN_pbe_WithSHA1And3_Key_TripleDES_CBC = "PBE-SHA1-3DES";
enum LN_pbe_WithSHA1And3_Key_TripleDES_CBC = "pbeWithSHA1And3-KeyTripleDES-CBC";
enum NID_pbe_WithSHA1And3_Key_TripleDES_CBC = 146;
// #define OBJ_pbe_WithSHA1And3_Key_TripleDES_CBC	OBJ_pkcs12_pbeids, 3L

enum SN_pbe_WithSHA1And2_Key_TripleDES_CBC = "PBE-SHA1-2DES";
enum LN_pbe_WithSHA1And2_Key_TripleDES_CBC = "pbeWithSHA1And2-KeyTripleDES-CBC";
enum NID_pbe_WithSHA1And2_Key_TripleDES_CBC = 147;
// #define OBJ_pbe_WithSHA1And2_Key_TripleDES_CBC	OBJ_pkcs12_pbeids, 4L

enum SN_pbe_WithSHA1And128BitRC2_CBC = "PBE-SHA1-RC2-128";
enum LN_pbe_WithSHA1And128BitRC2_CBC = "pbeWithSHA1And128BitRC2-CBC";
enum NID_pbe_WithSHA1And128BitRC2_CBC = 148;
// #define OBJ_pbe_WithSHA1And128BitRC2_CBC	OBJ_pkcs12_pbeids, 5L

enum SN_pbe_WithSHA1And40BitRC2_CBC = "PBE-SHA1-RC2-40";
enum LN_pbe_WithSHA1And40BitRC2_CBC = "pbeWithSHA1And40BitRC2-CBC";
enum NID_pbe_WithSHA1And40BitRC2_CBC = 149;
// #define OBJ_pbe_WithSHA1And40BitRC2_CBC	OBJ_pkcs12_pbeids, 6L

// #define OBJ_pkcs12_Version1	OBJ_pkcs12, 10L

// #define OBJ_pkcs12_BagIds	OBJ_pkcs12_Version1, 1L

enum LN_keyBag = "keyBag";
enum NID_keyBag = 150;
// #define OBJ_keyBag		OBJ_pkcs12_BagIds, 1L

enum LN_pkcs8ShroudedKeyBag = "pkcs8ShroudedKeyBag";
enum NID_pkcs8ShroudedKeyBag = 151;
// #define OBJ_pkcs8ShroudedKeyBag	OBJ_pkcs12_BagIds, 2L

enum LN_certBag = "certBag";
enum NID_certBag = 152;
// #define OBJ_certBag		OBJ_pkcs12_BagIds, 3L

enum LN_crlBag = "crlBag";
enum NID_crlBag = 153;
// #define OBJ_crlBag		OBJ_pkcs12_BagIds, 4L

enum LN_secretBag = "secretBag";
enum NID_secretBag = 154;
// #define OBJ_secretBag		OBJ_pkcs12_BagIds, 5L

enum LN_safeContentsBag = "safeContentsBag";
enum NID_safeContentsBag = 155;
// #define OBJ_safeContentsBag	OBJ_pkcs12_BagIds, 6L

enum LN_friendlyName = "friendlyName";
enum NID_friendlyName = 156;
// #define OBJ_friendlyName	OBJ_pkcs9, 20L

enum LN_localKeyID = "localKeyID";
enum NID_localKeyID = 157;
// #define OBJ_localKeyID		OBJ_pkcs9, 21L

// #define OBJ_certTypes		OBJ_pkcs9, 22L

enum LN_x509Certificate = "x509Certificate";
enum NID_x509Certificate = 158;
// #define OBJ_x509Certificate	OBJ_certTypes, 1L

enum LN_sdsiCertificate = "sdsiCertificate";
enum NID_sdsiCertificate = 159;
// #define OBJ_sdsiCertificate	OBJ_certTypes, 2L

// #define OBJ_crlTypes		OBJ_pkcs9, 23L

enum LN_x509Crl = "x509Crl";
enum NID_x509Crl = 160;
// #define OBJ_x509Crl		OBJ_crlTypes, 1L

/* PKCS#5 v2 OIDs */

enum LN_pbes2 = "PBES2";
enum NID_pbes2 = 161;
// #define OBJ_pbes2		OBJ_pkcs,5L,13L

enum LN_pbmac1 = "PBMAC1";
enum NID_pbmac1 = 162;
// #define OBJ_pbmac1		OBJ_pkcs,5L,14L

enum LN_hmacWithSHA1 = "hmacWithSHA1";
enum NID_hmacWithSHA1 = 163;
// #define OBJ_hmacWithSHA1	OBJ_rsadsi,2L,7L

/* Policy Qualifier Ids */

enum LN_id_qt_cps = "Policy Qualifier CPS";
enum SN_id_qt_cps = "id-qt-cps";
enum NID_id_qt_cps = 164;
// #define OBJ_id_qt_cps		OBJ_id_pkix,2L,1L

enum LN_id_qt_unotice = "Policy Qualifier User Notice";
enum SN_id_qt_unotice = "id-qt-unotice";
enum NID_id_qt_unotice = 165;
// #define OBJ_id_qt_unotice	OBJ_id_pkix,2L,2L

enum SN_rc2_64_cbc = "RC2-64-CBC";
enum LN_rc2_64_cbc = "rc2-64-cbc";
enum NID_rc2_64_cbc = 166;

enum SN_SMIMECapabilities = "SMIME-CAPS";
enum LN_SMIMECapabilities = "S/MIME Capabilities";
enum NID_SMIMECapabilities = 167;
// #define OBJ_SMIMECapabilities		OBJ_pkcs9,15L

enum SN_pbeWithMD2AndRC2_CBC = "PBE-MD2-RC2-64";
enum LN_pbeWithMD2AndRC2_CBC = "pbeWithMD2AndRC2-CBC";
enum NID_pbeWithMD2AndRC2_CBC = 168;
// #define OBJ_pbeWithMD2AndRC2_CBC	OBJ_pkcs,5L,4L

enum SN_pbeWithMD5AndRC2_CBC = "PBE-MD5-RC2-64";
enum LN_pbeWithMD5AndRC2_CBC = "pbeWithMD5AndRC2-CBC";
enum NID_pbeWithMD5AndRC2_CBC = 169;
// #define OBJ_pbeWithMD5AndRC2_CBC	OBJ_pkcs,5L,6L

enum SN_pbeWithSHA1AndDES_CBC = "PBE-SHA1-DES";
enum LN_pbeWithSHA1AndDES_CBC = "pbeWithSHA1AndDES-CBC";
enum NID_pbeWithSHA1AndDES_CBC = 170;
// #define OBJ_pbeWithSHA1AndDES_CBC	OBJ_pkcs,5L,10L

/* Extension request OIDs */

enum LN_ms_ext_req = "Microsoft Extension Request";
enum SN_ms_ext_req = "msExtReq";
enum NID_ms_ext_req = 171;
// #define OBJ_ms_ext_req			1L,3L,6L,1L,4L,1L,311L,2L,1L,14L

enum LN_ext_req = "Extension Request";
enum SN_ext_req = "extReq";
enum NID_ext_req = 172;
// #define OBJ_ext_req			OBJ_pkcs9,14L

enum SN_name = "name";
enum LN_name = "name";
enum NID_name = 173;
// #define OBJ_name			OBJ_X509,41L

enum SN_dnQualifier = "dnQualifier";
enum LN_dnQualifier = "dnQualifier";
enum NID_dnQualifier = 174;
// #define OBJ_dnQualifier			OBJ_X509,46L

enum SN_id_pe = "id-pe";
enum NID_id_pe = 175;
// #define OBJ_id_pe			OBJ_id_pkix,1L

enum SN_id_ad = "id-ad";
enum NID_id_ad = 176;
// #define OBJ_id_ad			OBJ_id_pkix,48L

enum SN_info_access = "authorityInfoAccess";
enum LN_info_access = "Authority Information Access";
enum NID_info_access = 177;
// #define OBJ_info_access			OBJ_id_pe,1L

enum SN_ad_OCSP = "OCSP";
enum LN_ad_OCSP = "OCSP";
enum NID_ad_OCSP = 178;
// #define OBJ_ad_OCSP			OBJ_id_ad,1L

enum SN_ad_ca_issuers = "caIssuers";
enum LN_ad_ca_issuers = "CA Issuers";
enum NID_ad_ca_issuers = 179;
// #define OBJ_ad_ca_issuers		OBJ_id_ad,2L

enum SN_OCSP_sign = "OCSPSigning";
enum LN_OCSP_sign = "OCSP Signing";
enum NID_OCSP_sign = 180;
// #define OBJ_OCSP_sign			OBJ_id_kp,9L
}

public import c.openssl.bio;
public import c.openssl.asn1;

enum OBJ_NAME_TYPE_UNDEF = 0x00;
enum OBJ_NAME_TYPE_MD_METH = 0x01;
enum OBJ_NAME_TYPE_CIPHER_METH = 0x02;
enum OBJ_NAME_TYPE_PKEY_METH = 0x03;
enum OBJ_NAME_TYPE_COMP_METH = 0x04;
enum OBJ_NAME_TYPE_NUM = 0x05;

enum OBJ_NAME_ALIAS = 0x8000;

enum OBJ_BSEARCH_VALUE_ON_NOMATCH = 0x01;
enum OBJ_BSEARCH_FIRST_VALUE_ON_MATCH = 0x02;

int OBJ_create_and_add_object(const(char)* oid, const(char)* sn, const(char)* ln)
{ return OBJ_create(oid,sn,ln); }

extern (C):

alias obj_name_st OBJ_NAME;

extern __gshared int obj_cleanup_defer;

struct obj_name_st
{
    int type;
    int alias_;
    const(char)* name;
    const(char)* data;
}

int OBJ_NAME_init ();
int OBJ_NAME_new_index (c_ulong function (const(char)*) hash_func, int function (const(char)*, const(char)*) cmp_func, void function (const(char)*, int, const(char)*) free_func);
const(char)* OBJ_NAME_get (const(char)* name, int type);
int OBJ_NAME_add (const(char)* name, int type, const(char)* data);
int OBJ_NAME_remove (const(char)* name, int type);
void OBJ_NAME_cleanup (int type);
void OBJ_NAME_do_all (int type, void function (const(OBJ_NAME)*, void*) fn, void* arg);
void OBJ_NAME_do_all_sorted (int type, void function (const(OBJ_NAME)*, void*) fn, void* arg);
ASN1_OBJECT* OBJ_dup (const(ASN1_OBJECT)* o);
ASN1_OBJECT* OBJ_nid2obj (int n);
const(char)* OBJ_nid2ln (int n);
const(char)* OBJ_nid2sn (int n);
int OBJ_obj2nid (const(ASN1_OBJECT)* o);
ASN1_OBJECT* OBJ_txt2obj (const(char)* s, int no_name);
int OBJ_obj2txt (char* buf, int buf_len, const(ASN1_OBJECT)* a, int no_name);
int OBJ_txt2nid (const(char)* s);
int OBJ_ln2nid (const(char)* s);
int OBJ_sn2nid (const(char)* s);
int OBJ_cmp (const(ASN1_OBJECT)* a, const(ASN1_OBJECT)* b);
const(void)* OBJ_bsearch_ (const(void)* key, const(void)* base, int num, int size, int function (const(void)*, const(void)*) cmp);
const(void)* OBJ_bsearch_ex_ (const(void)* key, const(void)* base, int num, int size, int function (const(void)*, const(void)*) cmp, int flags);
int OBJ_new_nid (int num);
int OBJ_add_object (const(ASN1_OBJECT)* obj);
int OBJ_create (const(char)* oid, const(char)* sn, const(char)* ln);
void OBJ_cleanup ();
int OBJ_create_objects (BIO* in_);
int OBJ_find_sigid_algs (int signid, int* pdig_nid, int* ppkey_nid);
int OBJ_find_sigid_by_algs (int* psignid, int dig_nid, int pkey_nid);
int OBJ_add_sigid (int signid, int dig_id, int pkey_id);
void OBJ_sigid_free ();
void check_defer (int nid);
void ERR_load_OBJ_strings ();


/* Error codes for the OBJ functions. */

/* Function codes. */
enum OBJ_F_OBJ_ADD_OBJECT = 105;
enum OBJ_F_OBJ_CREATE = 100;
enum OBJ_F_OBJ_DUP = 101;
enum OBJ_F_OBJ_NAME_NEW_INDEX = 106;
enum OBJ_F_OBJ_NID2LN = 102;
enum OBJ_F_OBJ_NID2OBJ = 103;
enum OBJ_F_OBJ_NID2SN = 104;

/* Reason codes. */
enum OBJ_R_MALLOC_FAILURE = 100;
enum OBJ_R_UNKNOWN_NID = 101;
