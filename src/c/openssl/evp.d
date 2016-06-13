module c.openssl.evp;

import core.stdc.config;

//public import c.openssl.opensslconf;
public import c.openssl.ossl_typ;
public import c.openssl.bio;
public import c.openssl.objects;

// These imports are not in the original header, but D needs them.
// Otherwise, D won't know what the aliases in this module are referring to.
import c.openssl.ec;

extern (C):

/*
enum EVP_RC2_KEY_SIZE = 16;
enum EVP_RC4_KEY_SIZE = 16;
enum EVP_BLOWFISH_KEY_SIZE = 16;
enum EVP_CAST5_KEY_SIZE = 16;
enum EVP_RC5_32_12_16_KEY_SIZE = 16;
*/
enum EVP_MAX_MD_SIZE = 64;	/* longest known is SHA512 */
enum EVP_MAX_KEY_LENGTH = 64;
enum EVP_MAX_IV_LENGTH = 16;
enum EVP_MAX_BLOCK_LENGTH = 32;

enum PKCS5_SALT_LEN = 8;
/* Default PKCS#5 iteration count */
enum PKCS5_DEFAULT_ITER = 2048;

enum EVP_PK_RSA = 0x0001;
enum EVP_PK_DSA = 0x0002;
enum EVP_PK_DH = 0x0004;
enum EVP_PK_EC = 0x0008;
enum EVP_PKT_SIGN = 0x0010;
enum EVP_PKT_ENC = 0x0020;
enum EVP_PKT_EXCH = 0x0040;
enum EVP_PKS_RSA = 0x0100;
enum EVP_PKS_DSA = 0x0200;
enum EVP_PKS_EC = 0x0400;
enum EVP_PKT_EXP = 0x1000; /* <= 512 bit key */

enum EVP_PKEY_NONE = NID_undef;
enum EVP_PKEY_RSA = NID_rsaEncryption;
enum EVP_PKEY_RSA2 = NID_rsa;
enum EVP_PKEY_DSA = NID_dsa;
enum EVP_PKEY_DSA1 = NID_dsa_2;
enum EVP_PKEY_DSA2 = NID_dsaWithSHA;
enum EVP_PKEY_DSA3 = NID_dsaWithSHA1;
enum EVP_PKEY_DSA4 = NID_dsaWithSHA1_2;
enum EVP_PKEY_DH = NID_dhKeyAgreement;
enum EVP_PKEY_EC = NID_X9_62_id_ecPublicKey;
enum EVP_PKEY_GOSTR01 = NID_id_GostR3410_2001;
enum EVP_PKEY_GOSTIMIT = NID_id_Gost28147_89_MAC;
enum EVP_PKEY_HMAC = NID_hmac;
enum EVP_PKEY_CMAC = NID_cmac;
enum EVP_PKEY_GOSTR12_256 = NID_id_tc26_gost3410_2012_256;
enum EVP_PKEY_GOSTR12_512 = NID_id_tc26_gost3410_2012_512;

enum EVP_PKEY_MO_SIGN = 0x0001;
enum EVP_PKEY_MO_VERIFY = 0x0002;
enum EVP_PKEY_MO_ENCRYPT = 0x0004;
enum EVP_PKEY_MO_DECRYPT = 0x0008;

enum EVP_MD_FLAG_ONESHOT = 0x0001; /* digest can only handle a single
					* block */

enum EVP_MD_FLAG_PKEY_DIGEST = 0x0002; /* digest is a "clone" digest used
					* which is a copy of an existing
					* one for a specific public key type.
					* EVP_dss1() etc */

/* Digest uses EVP_PKEY_METHOD for signing instead of MD specific signing */

enum EVP_MD_FLAG_PKEY_METHOD_SIGNATURE = 0x0004;

/* DigestAlgorithmIdentifier flags... */

enum EVP_MD_FLAG_DIGALGID_MASK = 0x0018;

/* NULL or absent parameter accepted. Use NULL */

enum EVP_MD_FLAG_DIGALGID_NULL = 0x0000;

/* NULL or absent parameter accepted. Use NULL for PKCS#1 otherwise absent */

enum EVP_MD_FLAG_DIGALGID_ABSENT = 0x0008;

/* Custom handling via ctrl */

enum EVP_MD_FLAG_DIGALGID_CUSTOM = 0x0018;

enum EVP_MD_FLAG_FIPS = 0x0400; /* Note if suitable for use in FIPS mode */

/* Digest ctrls */

enum EVP_MD_CTRL_DIGALGID = 0x1;
enum EVP_MD_CTRL_MICALG = 0x2;
enum EVP_MD_CTRL_SET_KEY = 0x3;
enum EVP_MD_CTRL_GOST_SET_SBOX = 0x4;

/* Minimum Algorithm specific ctrl value */

enum EVP_MD_CTRL_ALG_CTRL = 0x1000;

/+
// I don't know how to convert these to D.  They seem to rely heavily on textual inclusion and context.
enum EVP_PKEY_NULL_method = NULL,NULL,{0,0,0,0};

#define EVP_PKEY_DSA_method	(evp_sign_method *)DSA_sign, \
				(evp_verify_method *)DSA_verify, \
				{EVP_PKEY_DSA,EVP_PKEY_DSA2,EVP_PKEY_DSA3, \
					EVP_PKEY_DSA4,0}

#define EVP_PKEY_ECDSA_method   (evp_sign_method *)ECDSA_sign, \
				(evp_verify_method *)ECDSA_verify, \
                                 {EVP_PKEY_EC,0,0,0}

#define EVP_PKEY_RSA_method	(evp_sign_method *)RSA_sign, \
				(evp_verify_method *)RSA_verify, \
				{EVP_PKEY_RSA,EVP_PKEY_RSA2,0,0}
#define EVP_PKEY_RSA_ASN1_OCTET_STRING_method \
				(evp_sign_method *)RSA_sign_ASN1_OCTET_STRING, \
				(evp_verify_method *)RSA_verify_ASN1_OCTET_STRING, \
				{EVP_PKEY_RSA,EVP_PKEY_RSA2,0,0}
+/

enum EVP_MD_CTX_FLAG_ONESHOT = 0x0001; /* digest update will be called
						* once only */
enum EVP_MD_CTX_FLAG_CLEANED = 0x0002; /* context has already been
						* cleaned */
enum EVP_MD_CTX_FLAG_REUSE = 0x0004; /* Don't free up ctx->md_data
						* in EVP_MD_CTX_cleanup */
/* FIPS and pad options are ignored in 1.0.0, definitions are here
 * so we don't accidentally reuse the values for other purposes.
 */

enum EVP_MD_CTX_FLAG_NON_FIPS_ALLOW = 0x0008;	/* Allow use of non FIPS digest
						 * in FIPS mode */

/* The following PAD options are also currently ignored in 1.0.0, digest
 * parameters are handled through EVP_DigestSign*() and EVP_DigestVerify*()
 * instead.
 */
enum EVP_MD_CTX_FLAG_PAD_MASK = 0xF0;	/* RSA mode to use */
enum EVP_MD_CTX_FLAG_PAD_PKCS1 = 0x00;	/* PKCS#1 v1.5 mode */
enum EVP_MD_CTX_FLAG_PAD_X931 = 0x10;	/* X9.31 mode */
enum EVP_MD_CTX_FLAG_PAD_PSS = 0x20;	/* PSS mode */

enum EVP_MD_CTX_FLAG_NO_INIT = 0x0100; /* Don't initialize md_data */

/* Values for cipher flags */

/* Modes for ciphers */

enum EVP_CIPH_STREAM_CIPHER = 0x0;
enum EVP_CIPH_ECB_MODE = 0x1;
enum EVP_CIPH_CBC_MODE = 0x2;
enum EVP_CIPH_CFB_MODE = 0x3;
enum EVP_CIPH_OFB_MODE = 0x4;
enum EVP_CIPH_CTR_MODE = 0x5;
enum EVP_CIPH_GCM_MODE = 0x6;
enum EVP_CIPH_CCM_MODE = 0x7;
enum EVP_CIPH_XTS_MODE = 0x10001;
enum EVP_CIPH_MODE = 0xF0007;
/* Set if variable length cipher */
enum EVP_CIPH_VARIABLE_LENGTH = 0x8;
/* Set if the iv handling should be done by the cipher itself */
enum EVP_CIPH_CUSTOM_IV = 0x10;
/* Set if the cipher's init() function should be called if key is NULL */
enum EVP_CIPH_ALWAYS_CALL_INIT = 0x20;
/* Call ctrl() to init cipher parameters */
enum EVP_CIPH_CTRL_INIT = 0x40;
/* Don't use standard key length function */
enum EVP_CIPH_CUSTOM_KEY_LENGTH = 0x80;
/* Don't use standard block padding */
enum EVP_CIPH_NO_PADDING = 0x100;
/* cipher handles random key generation */
enum EVP_CIPH_RAND_KEY = 0x200;
/* cipher has its own additional copying logic */
enum EVP_CIPH_CUSTOM_COPY = 0x400;
/* Allow use default ASN1 get/set iv */
enum EVP_CIPH_FLAG_DEFAULT_ASN1 = 0x1000;
/* Buffer length in bits not bytes: CFB1 mode only */
enum EVP_CIPH_FLAG_LENGTH_BITS = 0x2000;
/* Note if suitable for use in FIPS mode */
enum EVP_CIPH_FLAG_FIPS = 0x4000;
/* Allow non FIPS cipher in FIPS mode */
enum EVP_CIPH_FLAG_NON_FIPS_ALLOW = 0x8000;
/* Cipher handles any and all padding logic as well
 * as finalisation.
 */
enum EVP_CIPH_FLAG_CUSTOM_CIPHER = 0x100000;
enum EVP_CIPH_FLAG_AEAD_CIPHER = 0x200000;

/* ctrl() values */

enum EVP_CTRL_INIT = 0x0;
enum EVP_CTRL_SET_KEY_LENGTH = 0x1;
enum EVP_CTRL_GET_RC2_KEY_BITS = 0x2;
enum EVP_CTRL_SET_RC2_KEY_BITS = 0x3;
enum EVP_CTRL_GET_RC5_ROUNDS = 0x4;
enum EVP_CTRL_SET_RC5_ROUNDS = 0x5;
enum EVP_CTRL_RAND_KEY = 0x6;
enum EVP_CTRL_PBE_PRF_NID = 0x7;
enum EVP_CTRL_COPY = 0x8;
enum EVP_CTRL_GCM_SET_IVLEN = 0x9;
enum EVP_CTRL_GCM_GET_TAG = 0x10;
enum EVP_CTRL_GCM_SET_TAG = 0x11;
enum EVP_CTRL_GCM_SET_IV_FIXED = 0x12;
enum EVP_CTRL_GCM_IV_GEN = 0x13;
enum EVP_CTRL_CCM_SET_IVLEN = EVP_CTRL_GCM_SET_IVLEN;
enum EVP_CTRL_CCM_GET_TAG = EVP_CTRL_GCM_GET_TAG;
enum EVP_CTRL_CCM_SET_TAG = EVP_CTRL_GCM_SET_TAG;
enum EVP_CTRL_CCM_SET_L = 0x14;
enum EVP_CTRL_CCM_SET_MSGLEN = 0x15;
/* AEAD cipher deduces payload length and returns number of bytes
 * required to store MAC and eventual padding. Subsequent call to
 * EVP_Cipher even appends/verifies MAC.
 */
enum EVP_CTRL_AEAD_TLS1_AAD = 0x16;
/* Used by composite AEAD ciphers, no-op in GCM, CCM... */
enum EVP_CTRL_AEAD_SET_MAC_KEY = 0x17;
/* Set the GCM invocation field, decrypt only */
enum EVP_CTRL_GCM_SET_IV_INV = 0x18;
/* Set the S-BOX NID for GOST ciphers */
enum EVP_CTRL_GOST_SET_SBOX = 0x19;

/* GCM TLS constants */
/* Length of fixed part of IV derived from PRF */
enum EVP_GCM_TLS_FIXED_IV_LEN = 4;
/* Length of explicit part of IV part of TLS records */
enum EVP_GCM_TLS_EXPLICIT_IV_LEN = 8;
/* Length of tag for TLS */
enum EVP_GCM_TLS_TAG_LEN = 16;

int EVP_PKEY_assign (EVP_PKEY* pkey, int type, void* key);
extern(D)
{
auto EVP_PKEY_assign_RSA(T)(EVP_PKEY* pkey,T rsa)      { return EVP_PKEY_assign((pkey),EVP_PKEY_RSA,cast(void *)(rsa))        ; }
auto EVP_PKEY_assign_DSA(T)(EVP_PKEY* pkey,T dsa)      { return EVP_PKEY_assign((pkey),EVP_PKEY_DSA,cast(void *)(dsa))        ; }
auto EVP_PKEY_assign_DH(T)(EVP_PKEY* pkey,T dh)        { return EVP_PKEY_assign((pkey),EVP_PKEY_DH,cast(void *)(dh))          ; }
auto EVP_PKEY_assign_EC_KEY(T)(EVP_PKEY* pkey,T eckey) { return EVP_PKEY_assign((pkey),EVP_PKEY_EC,cast(void *)(eckey))       ; }
auto EVP_PKEY_assign_GOST(T)(EVP_PKEY* pkey,T gostkey) { return EVP_PKEY_assign((pkey),EVP_PKEY_GOSTR01,cast(void *)(gostkey)); }

/* Add some extra combinations */
auto EVP_get_digestbynid(int a)          { return EVP_get_digestbyname(OBJ_nid2sn(a)); }
auto EVP_get_digestbyobj(ASN1_OBJECT* a) { return EVP_get_digestbynid(OBJ_obj2nid(a)); }
auto EVP_get_cipherbynid(int a)          { return EVP_get_cipherbyname(OBJ_nid2sn(a)); }
auto EVP_get_cipherbyobj(ASN1_OBJECT* a) { return EVP_get_cipherbynid(OBJ_obj2nid(a)); }
}

const(EVP_MD)* EVP_MD_CTX_md (const(EVP_MD_CTX)* ctx);
int EVP_MD_type (const(EVP_MD)* md);
int EVP_MD_size (const(EVP_MD)* md);
int EVP_MD_pkey_type (const(EVP_MD)* md);
int EVP_MD_block_size (const(EVP_MD)* md);
extern(D)
{
	int EVP_MD_nid(const(EVP_MD)* e)                { return EVP_MD_type(e)                     ;}
	const(char)*  EVP_MD_name(const(EVP_MD)* e)     { return OBJ_nid2sn(EVP_MD_nid(e))          ;}
	int EVP_MD_CTX_size(const(EVP_MD_CTX)* e)       { return EVP_MD_size(EVP_MD_CTX_md(e))      ;}
	int EVP_MD_CTX_block_size(const(EVP_MD_CTX)* e) { return EVP_MD_block_size(EVP_MD_CTX_md(e));}
	int EVP_MD_CTX_type(const(EVP_MD_CTX)* e)       { return EVP_MD_type(EVP_MD_CTX_md(e))      ;}

	const(char)*  EVP_CIPHER_name(const(EVP_CIPHER)* e) { return OBJ_nid2sn(EVP_CIPHER_nid(e)); }
	int  EVP_CIPHER_mode(const(EVP_CIPHER)* e)          { return (EVP_CIPHER_flags(e) & EVP_CIPH_MODE); }

	int EVP_CIPHER_CTX_type(const(EVP_CIPHER_CTX)* c) { return EVP_CIPHER_type(EVP_CIPHER_CTX_cipher(c)); }

	c_ulong EVP_CIPHER_CTX_mode(const(EVP_CIPHER_CTX)* e) { return (EVP_CIPHER_CTX_flags(e) & EVP_CIPH_MODE); }

	auto EVP_ENCODE_LENGTH(T)(T l) { return (((l+2)/3*4)+(l/48+1)*2+80); }
	auto EVP_DECODE_LENGTH(T)(T l) { return ((l+3)/4*3+80); }

	/+
	// not worth it right now... O.o
	#define EVP_SignInit_ex(a,b,c)		EVP_DigestInit_ex(a,b,c)
	#define EVP_SignInit(a,b)		EVP_DigestInit(a,b)
	#define EVP_SignUpdate(a,b,c)		EVP_DigestUpdate(a,b,c)
	#define	EVP_VerifyInit_ex(a,b,c)	EVP_DigestInit_ex(a,b,c)
	#define	EVP_VerifyInit(a,b)		EVP_DigestInit(a,b)
	#define	EVP_VerifyUpdate(a,b,c)		EVP_DigestUpdate(a,b,c)
	#define EVP_OpenUpdate(a,b,c,d,e)	EVP_DecryptUpdate(a,b,c,d,e)
	#define EVP_SealUpdate(a,b,c,d,e)	EVP_EncryptUpdate(a,b,c,d,e)
	#define EVP_DigestSignUpdate(a,b,c)	EVP_DigestUpdate(a,b,c)
	#define EVP_DigestVerifyUpdate(a,b,c)	EVP_DigestUpdate(a,b,c)
	+/

	c_long BIO_set_md(T)(BIO* b,T md)           { return BIO_ctrl(b,BIO_C_SET_MD,0,cast(void *)md)          ;}
	c_long BIO_get_md(T)(BIO* b,T mdp)          { return BIO_ctrl(b,BIO_C_GET_MD,0,cast(void *)mdp)         ;}
	c_long BIO_get_md_ctx(T)(BIO* b,T mdcp)     { return BIO_ctrl(b,BIO_C_GET_MD_CTX,0,cast(void *)mdcp)    ;}
	c_long BIO_set_md_ctx(T)(BIO* b,T mdcp)     { return BIO_ctrl(b,BIO_C_SET_MD_CTX,0,cast(void *)mdcp)    ;}
	c_long BIO_get_cipher_status(T)(BIO* b)     { return BIO_ctrl(b,BIO_C_GET_CIPHER_STATUS,0,NULL)     ;}
	c_long BIO_get_cipher_ctx(T)(BIO* b,T c_pp) { return BIO_ctrl(b,BIO_C_GET_CIPHER_CTX,0,cast(void *)c_pp);}

	int EVP_add_cipher_alias(const(char)* n, const(char)* _alias)  { return OBJ_NAME_add(_alias,OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS,(n)); }
	int EVP_add_digest_alias(const(char)* n, const(char)* _alias)  { return OBJ_NAME_add(_alias,OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS,(n));     }
	int EVP_delete_cipher_alias(const(char)* _alias)               { return OBJ_NAME_remove(_alias,OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS);  }
	int EVP_delete_digest_alias(const(char)* _alias)               { return OBJ_NAME_remove(_alias,OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS);      }
}

alias EVP_idea_cfb = EVP_idea_cfb64;
alias EVP_rc2_cfb = EVP_rc2_cfb64;
alias EVP_bf_cfb = EVP_bf_cfb64;
alias EVP_cast5_cfb = EVP_cast5_cfb64;
alias EVP_aes_128_cfb = EVP_aes_128_cfb128;
alias EVP_aes_192_cfb = EVP_aes_192_cfb128;
alias EVP_aes_256_cfb = EVP_aes_256_cfb128;
alias EVP_camellia_128_cfb = EVP_camellia_128_cfb128;
alias EVP_camellia_192_cfb = EVP_camellia_192_cfb128;
alias EVP_camellia_256_cfb = EVP_camellia_256_cfb128;

// #ifdef OPENSSL_LOAD_CONF
alias OpenSSL_add_all_algorithms = OPENSSL_add_all_algorithms_conf;
// #else
// #define OpenSSL_add_all_algorithms() OPENSSL_add_all_algorithms_noconf()
// #endif


alias SSLeay_add_all_algorithms = OpenSSL_add_all_algorithms;
alias SSLeay_add_all_ciphers    = OpenSSL_add_all_ciphers;
alias SSLeay_add_all_digests    = OpenSSL_add_all_digests;

/* PBE type */

/* Can appear as the outermost AlgorithmIdentifier */
enum EVP_PBE_TYPE_OUTER = 0x0;
/* Is an PRF type OID */
enum EVP_PBE_TYPE_PRF = 0x1;

enum ASN1_PKEY_ALIAS = 0x1;
enum ASN1_PKEY_DYNAMIC = 0x2;
enum ASN1_PKEY_SIGPARAM_NULL = 0x4;

enum ASN1_PKEY_CTRL_PKCS7_SIGN = 0x1;
enum ASN1_PKEY_CTRL_PKCS7_ENCRYPT = 0x2;
enum ASN1_PKEY_CTRL_DEFAULT_MD_NID = 0x3;
enum ASN1_PKEY_CTRL_CMS_SIGN = 0x5;
enum ASN1_PKEY_CTRL_CMS_ENVELOPE = 0x7;

enum EVP_PKEY_OP_UNDEFINED = 0;
enum EVP_PKEY_OP_PARAMGEN = (1<<1);
enum EVP_PKEY_OP_KEYGEN = (1<<2);
enum EVP_PKEY_OP_SIGN = (1<<3);
enum EVP_PKEY_OP_VERIFY = (1<<4);
enum EVP_PKEY_OP_VERIFYRECOVER = (1<<5);
enum EVP_PKEY_OP_SIGNCTX = (1<<6);
enum EVP_PKEY_OP_VERIFYCTX = (1<<7);
enum EVP_PKEY_OP_ENCRYPT = (1<<8);
enum EVP_PKEY_OP_DECRYPT = (1<<9);
enum EVP_PKEY_OP_DERIVE = (1<<10);

enum EVP_PKEY_OP_TYPE_SIG =
	(EVP_PKEY_OP_SIGN | EVP_PKEY_OP_VERIFY | EVP_PKEY_OP_VERIFYRECOVER
		| EVP_PKEY_OP_SIGNCTX | EVP_PKEY_OP_VERIFYCTX);

enum EVP_PKEY_OP_TYPE_CRYPT =
	(EVP_PKEY_OP_ENCRYPT | EVP_PKEY_OP_DECRYPT);

// I can't find where EVP_PKEY_OP_SIG is defined in the original headers.
// It might actually be a typo where they meant EVP_PKEY_OP_SIGN (note the N at the end).
// It is quite possible that this macro would never have expanded successfully in C code.
//enum EVP_PKEY_OP_TYPE_NOGEN =
//	(EVP_PKEY_OP_SIG | EVP_PKEY_OP_CRYPT | EVP_PKEY_OP_DERIVE);

enum EVP_PKEY_OP_TYPE_GEN =
		(EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN);

extern(D) int EVP_PKEY_CTX_set_signature_md(T)(EVP_PKEY_CTX* ctx, T md)
{
	return EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_CTRL_MD, 0, cast(void *)md);
}

enum EVP_PKEY_CTRL_MD = 1;
enum EVP_PKEY_CTRL_PEER_KEY = 2;

enum EVP_PKEY_CTRL_PKCS7_ENCRYPT = 3;
enum EVP_PKEY_CTRL_PKCS7_DECRYPT = 4;

enum EVP_PKEY_CTRL_PKCS7_SIGN = 5;

enum EVP_PKEY_CTRL_SET_MAC_KEY = 6;

enum EVP_PKEY_CTRL_DIGESTINIT = 7;

/* Used by GOST key encryption in TLS */
enum EVP_PKEY_CTRL_SET_IV = 8;

enum EVP_PKEY_CTRL_CMS_ENCRYPT = 9;
enum EVP_PKEY_CTRL_CMS_DECRYPT = 10;
enum EVP_PKEY_CTRL_CMS_SIGN = 11;

enum EVP_PKEY_CTRL_CIPHER = 12;

enum EVP_PKEY_ALG_CTRL = 0x1000;


enum EVP_PKEY_FLAG_AUTOARGLEN = 2;
/* Method handles all operations: don't assume any digest related
 * defaults.
 */
enum EVP_PKEY_FLAG_SIGCTX_CUSTOM = 4;

/* EVP_AEAD_MAX_TAG_LENGTH is the maximum tag length used by any AEAD
 * defined in this header. */
enum EVP_AEAD_MAX_TAG_LENGTH = 16;

/* EVP_AEAD_DEFAULT_TAG_LENGTH is a magic value that can be passed to
 * EVP_AEAD_CTX_init to indicate that the default tag length for an AEAD
 * should be used. */
enum EVP_AEAD_DEFAULT_TAG_LENGTH = 0;

/* Error codes for the EVP functions. */

/* Function codes. */
enum EVP_F_AEAD_AES_GCM_INIT = 187;
enum EVP_F_AEAD_AES_GCM_OPEN = 188;
enum EVP_F_AEAD_AES_GCM_SEAL = 189;
enum EVP_F_AEAD_CHACHA20_POLY1305_INIT = 192;
enum EVP_F_AEAD_CHACHA20_POLY1305_OPEN = 193;
enum EVP_F_AEAD_CHACHA20_POLY1305_SEAL = 194;
enum EVP_F_AEAD_CTX_OPEN = 185;
enum EVP_F_AEAD_CTX_SEAL = 186;
enum EVP_F_AESNI_INIT_KEY = 165;
enum EVP_F_AESNI_XTS_CIPHER = 176;
enum EVP_F_AES_INIT_KEY = 133;
enum EVP_F_AES_XTS = 172;
enum EVP_F_AES_XTS_CIPHER = 175;
enum EVP_F_ALG_MODULE_INIT = 177;
enum EVP_F_CAMELLIA_INIT_KEY = 159;
enum EVP_F_CMAC_INIT = 173;
enum EVP_F_D2I_PKEY = 100;
enum EVP_F_DO_SIGVER_INIT = 161;
enum EVP_F_DSAPKEY2PKCS8 = 134;
enum EVP_F_DSA_PKEY2PKCS8 = 135;
enum EVP_F_ECDSA_PKEY2PKCS8 = 129;
enum EVP_F_ECKEY_PKEY2PKCS8 = 132;
enum EVP_F_EVP_AEAD_CTX_INIT = 180;
enum EVP_F_EVP_AEAD_CTX_OPEN = 190;
enum EVP_F_EVP_AEAD_CTX_SEAL = 191;
enum EVP_F_EVP_BYTESTOKEY = 200;
enum EVP_F_EVP_CIPHERINIT_EX = 123;
enum EVP_F_EVP_CIPHER_CTX_COPY = 163;
enum EVP_F_EVP_CIPHER_CTX_CTRL = 124;
enum EVP_F_EVP_CIPHER_CTX_SET_KEY_LENGTH = 122;
enum EVP_F_EVP_CIPHER_GET_ASN1_IV = 201;
enum EVP_F_EVP_CIPHER_SET_ASN1_IV = 202;
enum EVP_F_EVP_DECRYPTFINAL_EX = 101;
enum EVP_F_EVP_DECRYPTUPDATE = 199;
enum EVP_F_EVP_DIGESTFINAL_EX = 196;
enum EVP_F_EVP_DIGESTINIT_EX = 128;
enum EVP_F_EVP_ENCRYPTFINAL_EX = 127;
enum EVP_F_EVP_ENCRYPTUPDATE = 198;
enum EVP_F_EVP_MD_CTX_COPY_EX = 110;
enum EVP_F_EVP_MD_CTX_CTRL = 195;
enum EVP_F_EVP_MD_SIZE = 162;
enum EVP_F_EVP_OPENINIT = 102;
enum EVP_F_EVP_PBE_ALG_ADD = 115;
enum EVP_F_EVP_PBE_ALG_ADD_TYPE = 160;
enum EVP_F_EVP_PBE_CIPHERINIT = 116;
enum EVP_F_EVP_PKCS82PKEY = 111;
enum EVP_F_EVP_PKCS82PKEY_BROKEN = 136;
enum EVP_F_EVP_PKEY2PKCS8_BROKEN = 113;
enum EVP_F_EVP_PKEY_COPY_PARAMETERS = 103;
enum EVP_F_EVP_PKEY_CTX_CTRL = 137;
enum EVP_F_EVP_PKEY_CTX_CTRL_STR = 150;
enum EVP_F_EVP_PKEY_CTX_DUP = 156;
enum EVP_F_EVP_PKEY_DECRYPT = 104;
enum EVP_F_EVP_PKEY_DECRYPT_INIT = 138;
enum EVP_F_EVP_PKEY_DECRYPT_OLD = 151;
enum EVP_F_EVP_PKEY_DERIVE = 153;
enum EVP_F_EVP_PKEY_DERIVE_INIT = 154;
enum EVP_F_EVP_PKEY_DERIVE_SET_PEER = 155;
enum EVP_F_EVP_PKEY_ENCRYPT = 105;
enum EVP_F_EVP_PKEY_ENCRYPT_INIT = 139;
enum EVP_F_EVP_PKEY_ENCRYPT_OLD = 152;
enum EVP_F_EVP_PKEY_GET1_DH = 119;
enum EVP_F_EVP_PKEY_GET1_DSA = 120;
enum EVP_F_EVP_PKEY_GET1_ECDSA = 130;
enum EVP_F_EVP_PKEY_GET1_EC_KEY = 131;
enum EVP_F_EVP_PKEY_GET1_RSA = 121;
enum EVP_F_EVP_PKEY_KEYGEN = 146;
enum EVP_F_EVP_PKEY_KEYGEN_INIT = 147;
enum EVP_F_EVP_PKEY_NEW = 106;
enum EVP_F_EVP_PKEY_PARAMGEN = 148;
enum EVP_F_EVP_PKEY_PARAMGEN_INIT = 149;
enum EVP_F_EVP_PKEY_SIGN = 140;
enum EVP_F_EVP_PKEY_SIGN_INIT = 141;
enum EVP_F_EVP_PKEY_VERIFY = 142;
enum EVP_F_EVP_PKEY_VERIFY_INIT = 143;
enum EVP_F_EVP_PKEY_VERIFY_RECOVER = 144;
enum EVP_F_EVP_PKEY_VERIFY_RECOVER_INIT = 145;
enum EVP_F_EVP_RIJNDAEL = 126;
enum EVP_F_EVP_SIGNFINAL = 107;
enum EVP_F_EVP_VERIFYFINAL = 108;
enum EVP_F_FIPS_CIPHERINIT = 166;
enum EVP_F_FIPS_CIPHER_CTX_COPY = 170;
enum EVP_F_FIPS_CIPHER_CTX_CTRL = 167;
enum EVP_F_FIPS_CIPHER_CTX_SET_KEY_LENGTH = 171;
enum EVP_F_FIPS_DIGESTINIT = 168;
enum EVP_F_FIPS_MD_CTX_COPY = 169;
enum EVP_F_HMAC_INIT_EX = 174;
enum EVP_F_INT_CTX_NEW = 157;
enum EVP_F_PKCS5_PBE_KEYIVGEN = 117;
enum EVP_F_PKCS5_V2_PBE_KEYIVGEN = 118;
enum EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN = 164;
enum EVP_F_PKCS8_SET_BROKEN = 112;
enum EVP_F_PKEY_SET_TYPE = 158;
enum EVP_F_RC2_GET_ASN1_TYPE_AND_IV = 197;
enum EVP_F_RC2_MAGIC_TO_METH = 109;
enum EVP_F_RC5_CTRL = 125;

/* Reason codes. */
enum EVP_R_AES_IV_SETUP_FAILED = 162;
enum EVP_R_AES_KEY_SETUP_FAILED = 143;
enum EVP_R_ASN1_LIB = 140;
enum EVP_R_BAD_BLOCK_LENGTH = 136;
enum EVP_R_BAD_DECRYPT = 100;
enum EVP_R_BAD_KEY_LENGTH = 137;
enum EVP_R_BN_DECODE_ERROR = 112;
enum EVP_R_BN_PUBKEY_ERROR = 113;
enum EVP_R_BUFFER_TOO_SMALL = 155;
enum EVP_R_CAMELLIA_KEY_SETUP_FAILED = 157;
enum EVP_R_CIPHER_PARAMETER_ERROR = 122;
enum EVP_R_COMMAND_NOT_SUPPORTED = 147;
enum EVP_R_CTRL_NOT_IMPLEMENTED = 132;
enum EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED = 133;
enum EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH = 138;
enum EVP_R_DECODE_ERROR = 114;
enum EVP_R_DIFFERENT_KEY_TYPES = 101;
enum EVP_R_DIFFERENT_PARAMETERS = 153;
enum EVP_R_DISABLED_FOR_FIPS = 163;
enum EVP_R_ENCODE_ERROR = 115;
enum EVP_R_ERROR_LOADING_SECTION = 165;
enum EVP_R_ERROR_SETTING_FIPS_MODE = 166;
enum EVP_R_EVP_PBE_CIPHERINIT_ERROR = 119;
enum EVP_R_EXPECTING_AN_RSA_KEY = 127;
enum EVP_R_EXPECTING_A_DH_KEY = 128;
enum EVP_R_EXPECTING_A_DSA_KEY = 129;
enum EVP_R_EXPECTING_A_ECDSA_KEY = 141;
enum EVP_R_EXPECTING_A_EC_KEY = 142;
enum EVP_R_FIPS_MODE_NOT_SUPPORTED = 167;
enum EVP_R_INITIALIZATION_ERROR = 134;
enum EVP_R_INPUT_NOT_INITIALIZED = 111;
enum EVP_R_INVALID_DIGEST = 152;
enum EVP_R_INVALID_FIPS_MODE = 168;
enum EVP_R_INVALID_KEY_LENGTH = 130;
enum EVP_R_INVALID_OPERATION = 148;
enum EVP_R_IV_TOO_LARGE = 102;
enum EVP_R_KEYGEN_FAILURE = 120;
enum EVP_R_MESSAGE_DIGEST_IS_NULL = 159;
enum EVP_R_METHOD_NOT_SUPPORTED = 144;
enum EVP_R_MISSING_PARAMETERS = 103;
enum EVP_R_NO_CIPHER_SET = 131;
enum EVP_R_NO_DEFAULT_DIGEST = 158;
enum EVP_R_NO_DIGEST_SET = 139;
enum EVP_R_NO_DSA_PARAMETERS = 116;
enum EVP_R_NO_KEY_SET = 154;
enum EVP_R_NO_OPERATION_SET = 149;
enum EVP_R_NO_SIGN_FUNCTION_CONFIGURED = 104;
enum EVP_R_NO_VERIFY_FUNCTION_CONFIGURED = 105;
enum EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE = 150;
enum EVP_R_OPERATON_NOT_INITIALIZED = 151;
enum EVP_R_OUTPUT_ALIASES_INPUT = 172;
enum EVP_R_PKCS8_UNKNOWN_BROKEN_TYPE = 117;
enum EVP_R_PRIVATE_KEY_DECODE_ERROR = 145;
enum EVP_R_PRIVATE_KEY_ENCODE_ERROR = 146;
enum EVP_R_PUBLIC_KEY_NOT_RSA = 106;
enum EVP_R_TAG_TOO_LARGE = 171;
enum EVP_R_TOO_LARGE = 164;
enum EVP_R_UNKNOWN_CIPHER = 160;
enum EVP_R_UNKNOWN_DIGEST = 161;
enum EVP_R_UNKNOWN_OPTION = 169;
enum EVP_R_UNKNOWN_PBE_ALGORITHM = 121;
enum EVP_R_UNSUPORTED_NUMBER_OF_ROUNDS = 135;
enum EVP_R_UNSUPPORTED_ALGORITHM = 156;
enum EVP_R_UNSUPPORTED_CIPHER = 107;
enum EVP_R_UNSUPPORTED_KEYLENGTH = 123;
enum EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION = 124;
enum EVP_R_UNSUPPORTED_KEY_SIZE = 108;
enum EVP_R_UNSUPPORTED_PRF = 125;
enum EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM = 118;
enum EVP_R_UNSUPPORTED_SALT_TYPE = 126;
enum EVP_R_WRONG_FINAL_BLOCK_LENGTH = 109;
enum EVP_R_WRONG_PUBLIC_KEY_TYPE = 110;

/+
// Hard to convert.  Not worth it unless needed.
typedef int evp_sign_method(int type, const unsigned char *m,
    unsigned int m_length, unsigned char *sigret, unsigned int *siglen,
    void *key);
typedef int evp_verify_method(int type, const unsigned char *m,
    unsigned int m_length, const unsigned char *sigbuf, unsigned int siglen,
    void *key);

typedef int (EVP_PBE_KEYGEN)(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
    ASN1_TYPE *param, const EVP_CIPHER *cipher, const EVP_MD *md, int en_de);

typedef int EVP_PKEY_gen_cb(EVP_PKEY_CTX *ctx);
+/

alias evp_cipher_info_st EVP_CIPHER_INFO;
alias evp_Encode_Ctx_st EVP_ENCODE_CTX;
alias evp_aead_st EVP_AEAD;
alias evp_aead_ctx_st EVP_AEAD_CTX;

struct evp_pkey_st
{
    int type;
    int save_type;
    int references;
    const(EVP_PKEY_ASN1_METHOD)* ameth;
    ENGINE* engine;
    union
    {
        char* ptr;
        rsa_st* rsa;
        dsa_st* dsa;
        dh_st* dh;
        ec_key_st* ec;
        gost_key_st* gost;
    }
    int save_parameters;
    // HACK: turn this back once X509 is converted.
    //stack_st_X509_ATTRIBUTE* attributes;
    void* attributes;
}

struct env_md_st
{
    int type;
    int pkey_type;
    int md_size;
    c_ulong flags;
    int function (EVP_MD_CTX*) init;
    int function (EVP_MD_CTX*, const(void)*, size_t) update;
    int function (EVP_MD_CTX*, ubyte*) final_;
    int function (EVP_MD_CTX*, const(EVP_MD_CTX)*) copy;
    int function (EVP_MD_CTX*) cleanup;
    int function (int, const(ubyte)*, uint, ubyte*, uint*, void*) sign;
    int function (int, const(ubyte)*, uint, const(ubyte)*, uint, void*) verify;
    int[5] required_pkey_type;
    int block_size;
    int ctx_size;
    int function (EVP_MD_CTX*, int, int, void*) md_ctrl;
}

struct env_md_ctx_st
{
    const(EVP_MD)* digest;
    ENGINE* engine;
    c_ulong flags;
    void* md_data;
    EVP_PKEY_CTX* pctx;
    int function (EVP_MD_CTX*, const(void)*, size_t) update;
}

struct evp_cipher_st
{
    int nid;
    int block_size;
    int key_len;
    int iv_len;
    c_ulong flags;
    int function (EVP_CIPHER_CTX*, const(ubyte)*, const(ubyte)*, int) init;
    int function (EVP_CIPHER_CTX*, ubyte*, const(ubyte)*, size_t) do_cipher;
    int function (EVP_CIPHER_CTX*) cleanup;
    int ctx_size;
    int function (EVP_CIPHER_CTX*, ASN1_TYPE*) set_asn1_parameters;
    int function (EVP_CIPHER_CTX*, ASN1_TYPE*) get_asn1_parameters;
    int function (EVP_CIPHER_CTX*, int, int, void*) ctrl;
    void* app_data;
}

struct evp_cipher_info_st
{
    const(EVP_CIPHER)* cipher;
    ubyte[16] iv;
}

struct evp_cipher_ctx_st
{
    const(EVP_CIPHER)* cipher;
    ENGINE* engine;
    int encrypt;
    int buf_len;
    ubyte[16] oiv;
    ubyte[16] iv;
    ubyte[32] buf;
    int num;
    void* app_data;
    int key_len;
    c_ulong flags;
    void* cipher_data;
    int final_used;
    int block_mask;
    ubyte[32] final_;
}

struct evp_Encode_Ctx_st
{
    int num;
    int length;
    ubyte[80] enc_data;
    int line_num;
    int expect_nl;
}

struct evp_aead_ctx_st
{
    const(EVP_AEAD)* aead;
    void* aead_state;
}

// Already defined in openssl.ec;
//struct ec_key_st;


struct dsa_st;


struct evp_aead_st;


struct gost_key_st;


struct dh_st;


struct rsa_st;


c_ulong EVP_MD_flags (const(EVP_MD)* md);
int EVP_CIPHER_nid (const(EVP_CIPHER)* cipher);
int EVP_CIPHER_block_size (const(EVP_CIPHER)* cipher);
int EVP_CIPHER_key_length (const(EVP_CIPHER)* cipher);
int EVP_CIPHER_iv_length (const(EVP_CIPHER)* cipher);
c_ulong EVP_CIPHER_flags (const(EVP_CIPHER)* cipher);
const(EVP_CIPHER)* EVP_CIPHER_CTX_cipher (const(EVP_CIPHER_CTX)* ctx);
int EVP_CIPHER_CTX_nid (const(EVP_CIPHER_CTX)* ctx);
int EVP_CIPHER_CTX_block_size (const(EVP_CIPHER_CTX)* ctx);
int EVP_CIPHER_CTX_key_length (const(EVP_CIPHER_CTX)* ctx);
int EVP_CIPHER_CTX_iv_length (const(EVP_CIPHER_CTX)* ctx);
int EVP_CIPHER_CTX_copy (EVP_CIPHER_CTX* out_, const(EVP_CIPHER_CTX)* in_);
void* EVP_CIPHER_CTX_get_app_data (const(EVP_CIPHER_CTX)* ctx);
void EVP_CIPHER_CTX_set_app_data (EVP_CIPHER_CTX* ctx, void* data);
c_ulong EVP_CIPHER_CTX_flags (const(EVP_CIPHER_CTX)* ctx);
int EVP_Cipher (EVP_CIPHER_CTX* c, ubyte* out_, const(ubyte)* in_, uint inl);
void EVP_MD_CTX_init (EVP_MD_CTX* ctx);
int EVP_MD_CTX_cleanup (EVP_MD_CTX* ctx);
EVP_MD_CTX* EVP_MD_CTX_create ();
void EVP_MD_CTX_destroy (EVP_MD_CTX* ctx);
int EVP_MD_CTX_copy_ex (EVP_MD_CTX* out_, const(EVP_MD_CTX)* in_);
void EVP_MD_CTX_set_flags (EVP_MD_CTX* ctx, int flags);
void EVP_MD_CTX_clear_flags (EVP_MD_CTX* ctx, int flags);
int EVP_MD_CTX_ctrl (EVP_MD_CTX* ctx, int type, int arg, void* ptr);
int EVP_MD_CTX_test_flags (const(EVP_MD_CTX)* ctx, int flags);
int EVP_DigestInit_ex (EVP_MD_CTX* ctx, const(EVP_MD)* type, ENGINE* impl);
int EVP_DigestUpdate (EVP_MD_CTX* ctx, const(void)* d, size_t cnt);
int EVP_DigestFinal_ex (EVP_MD_CTX* ctx, ubyte* md, uint* s);
int EVP_Digest (const(void)* data, size_t count, ubyte* md, uint* size, const(EVP_MD)* type, ENGINE* impl);
int EVP_MD_CTX_copy (EVP_MD_CTX* out_, const(EVP_MD_CTX)* in_);
int EVP_DigestInit (EVP_MD_CTX* ctx, const(EVP_MD)* type);
int EVP_DigestFinal (EVP_MD_CTX* ctx, ubyte* md, uint* s);
int EVP_read_pw_string (char* buf, int length, const(char)* prompt, int verify);
int EVP_read_pw_string_min (char* buf, int minlen, int maxlen, const(char)* prompt, int verify);
void EVP_set_pw_prompt (const(char)* prompt);
char* EVP_get_pw_prompt ();
int EVP_BytesToKey (const(EVP_CIPHER)* type, const(EVP_MD)* md, const(ubyte)* salt, const(ubyte)* data, int datal, int count, ubyte* key, ubyte* iv);
void EVP_CIPHER_CTX_set_flags (EVP_CIPHER_CTX* ctx, int flags);
void EVP_CIPHER_CTX_clear_flags (EVP_CIPHER_CTX* ctx, int flags);
int EVP_CIPHER_CTX_test_flags (const(EVP_CIPHER_CTX)* ctx, int flags);
int EVP_EncryptInit (EVP_CIPHER_CTX* ctx, const(EVP_CIPHER)* cipher, const(ubyte)* key, const(ubyte)* iv);
int EVP_EncryptInit_ex (EVP_CIPHER_CTX* ctx, const(EVP_CIPHER)* cipher, ENGINE* impl, const(ubyte)* key, const(ubyte)* iv);
int EVP_EncryptUpdate (EVP_CIPHER_CTX* ctx, ubyte* out_, int* outl, const(ubyte)* in_, int inl);
int EVP_EncryptFinal_ex (EVP_CIPHER_CTX* ctx, ubyte* out_, int* outl);
int EVP_EncryptFinal (EVP_CIPHER_CTX* ctx, ubyte* out_, int* outl);
int EVP_DecryptInit (EVP_CIPHER_CTX* ctx, const(EVP_CIPHER)* cipher, const(ubyte)* key, const(ubyte)* iv);
int EVP_DecryptInit_ex (EVP_CIPHER_CTX* ctx, const(EVP_CIPHER)* cipher, ENGINE* impl, const(ubyte)* key, const(ubyte)* iv);
int EVP_DecryptUpdate (EVP_CIPHER_CTX* ctx, ubyte* out_, int* outl, const(ubyte)* in_, int inl);
int EVP_DecryptFinal_ex (EVP_CIPHER_CTX* ctx, ubyte* outm, int* outl);
int EVP_DecryptFinal (EVP_CIPHER_CTX* ctx, ubyte* outm, int* outl);
int EVP_CipherInit (EVP_CIPHER_CTX* ctx, const(EVP_CIPHER)* cipher, const(ubyte)* key, const(ubyte)* iv, int enc);
int EVP_CipherInit_ex (EVP_CIPHER_CTX* ctx, const(EVP_CIPHER)* cipher, ENGINE* impl, const(ubyte)* key, const(ubyte)* iv, int enc);
int EVP_CipherUpdate (EVP_CIPHER_CTX* ctx, ubyte* out_, int* outl, const(ubyte)* in_, int inl);
int EVP_CipherFinal_ex (EVP_CIPHER_CTX* ctx, ubyte* outm, int* outl);
int EVP_CipherFinal (EVP_CIPHER_CTX* ctx, ubyte* outm, int* outl);
int EVP_SignFinal (EVP_MD_CTX* ctx, ubyte* md, uint* s, EVP_PKEY* pkey);
int EVP_VerifyFinal (EVP_MD_CTX* ctx, const(ubyte)* sigbuf, uint siglen, EVP_PKEY* pkey);
int EVP_DigestSignInit (EVP_MD_CTX* ctx, EVP_PKEY_CTX** pctx, const(EVP_MD)* type, ENGINE* e, EVP_PKEY* pkey);
int EVP_DigestSignFinal (EVP_MD_CTX* ctx, ubyte* sigret, size_t* siglen);
int EVP_DigestVerifyInit (EVP_MD_CTX* ctx, EVP_PKEY_CTX** pctx, const(EVP_MD)* type, ENGINE* e, EVP_PKEY* pkey);
int EVP_DigestVerifyFinal (EVP_MD_CTX* ctx, ubyte* sig, size_t siglen);
int EVP_OpenInit (EVP_CIPHER_CTX* ctx, const(EVP_CIPHER)* type, const(ubyte)* ek, int ekl, const(ubyte)* iv, EVP_PKEY* priv);
int EVP_OpenFinal (EVP_CIPHER_CTX* ctx, ubyte* out_, int* outl);
int EVP_SealInit (EVP_CIPHER_CTX* ctx, const(EVP_CIPHER)* type, ubyte** ek, int* ekl, ubyte* iv, EVP_PKEY** pubk, int npubk);
int EVP_SealFinal (EVP_CIPHER_CTX* ctx, ubyte* out_, int* outl);
void EVP_EncodeInit (EVP_ENCODE_CTX* ctx);
void EVP_EncodeUpdate (EVP_ENCODE_CTX* ctx, ubyte* out_, int* outl, const(ubyte)* in_, int inl);
void EVP_EncodeFinal (EVP_ENCODE_CTX* ctx, ubyte* out_, int* outl);
int EVP_EncodeBlock (ubyte* t, const(ubyte)* f, int n);
void EVP_DecodeInit (EVP_ENCODE_CTX* ctx);
int EVP_DecodeUpdate (EVP_ENCODE_CTX* ctx, ubyte* out_, int* outl, const(ubyte)* in_, int inl);
int EVP_DecodeFinal (EVP_ENCODE_CTX* ctx, ubyte* out_, int* outl);
int EVP_DecodeBlock (ubyte* t, const(ubyte)* f, int n);
void EVP_CIPHER_CTX_init (EVP_CIPHER_CTX* a);
int EVP_CIPHER_CTX_cleanup (EVP_CIPHER_CTX* a);
EVP_CIPHER_CTX* EVP_CIPHER_CTX_new ();
void EVP_CIPHER_CTX_free (EVP_CIPHER_CTX* a);
int EVP_CIPHER_CTX_set_key_length (EVP_CIPHER_CTX* x, int keylen);
int EVP_CIPHER_CTX_set_padding (EVP_CIPHER_CTX* c, int pad);
int EVP_CIPHER_CTX_ctrl (EVP_CIPHER_CTX* ctx, int type, int arg, void* ptr);
int EVP_CIPHER_CTX_rand_key (EVP_CIPHER_CTX* ctx, ubyte* key);
BIO_METHOD* BIO_f_md ();
BIO_METHOD* BIO_f_base64 ();
BIO_METHOD* BIO_f_cipher ();
void BIO_set_cipher (BIO* b, const(EVP_CIPHER)* c, const(ubyte)* k, const(ubyte)* i, int enc);
const(EVP_MD)* EVP_md_null ();
const(EVP_MD)* EVP_md4 ();
const(EVP_MD)* EVP_md5 ();
const(EVP_MD)* EVP_sha1 ();
const(EVP_MD)* EVP_dss ();
const(EVP_MD)* EVP_dss1 ();
const(EVP_MD)* EVP_ecdsa ();
const(EVP_MD)* EVP_sha224 ();
const(EVP_MD)* EVP_sha256 ();
const(EVP_MD)* EVP_sha384 ();
const(EVP_MD)* EVP_sha512 ();
const(EVP_MD)* EVP_ripemd160 ();
const(EVP_MD)* EVP_whirlpool ();
const(EVP_MD)* EVP_gostr341194 ();
const(EVP_MD)* EVP_gost2814789imit ();
const(EVP_MD)* EVP_streebog256 ();
const(EVP_MD)* EVP_streebog512 ();
const(EVP_CIPHER)* EVP_enc_null ();
const(EVP_CIPHER)* EVP_des_ecb ();
const(EVP_CIPHER)* EVP_des_ede ();
const(EVP_CIPHER)* EVP_des_ede3 ();
const(EVP_CIPHER)* EVP_des_ede_ecb ();
const(EVP_CIPHER)* EVP_des_ede3_ecb ();
const(EVP_CIPHER)* EVP_des_cfb64 ();
const(EVP_CIPHER)* EVP_des_cfb1 ();
const(EVP_CIPHER)* EVP_des_cfb8 ();
const(EVP_CIPHER)* EVP_des_ede_cfb64 ();
const(EVP_CIPHER)* EVP_des_ede3_cfb64 ();
const(EVP_CIPHER)* EVP_des_ede3_cfb1 ();
const(EVP_CIPHER)* EVP_des_ede3_cfb8 ();
const(EVP_CIPHER)* EVP_des_ofb ();
const(EVP_CIPHER)* EVP_des_ede_ofb ();
const(EVP_CIPHER)* EVP_des_ede3_ofb ();
const(EVP_CIPHER)* EVP_des_cbc ();
const(EVP_CIPHER)* EVP_des_ede_cbc ();
const(EVP_CIPHER)* EVP_des_ede3_cbc ();
const(EVP_CIPHER)* EVP_desx_cbc ();
const(EVP_CIPHER)* EVP_rc4 ();
const(EVP_CIPHER)* EVP_rc4_40 ();
const(EVP_CIPHER)* EVP_rc4_hmac_md5 ();
const(EVP_CIPHER)* EVP_idea_ecb ();
const(EVP_CIPHER)* EVP_idea_cfb64 ();
const(EVP_CIPHER)* EVP_idea_ofb ();
const(EVP_CIPHER)* EVP_idea_cbc ();
const(EVP_CIPHER)* EVP_rc2_ecb ();
const(EVP_CIPHER)* EVP_rc2_cbc ();
const(EVP_CIPHER)* EVP_rc2_40_cbc ();
const(EVP_CIPHER)* EVP_rc2_64_cbc ();
const(EVP_CIPHER)* EVP_rc2_cfb64 ();
const(EVP_CIPHER)* EVP_rc2_ofb ();
const(EVP_CIPHER)* EVP_bf_ecb ();
const(EVP_CIPHER)* EVP_bf_cbc ();
const(EVP_CIPHER)* EVP_bf_cfb64 ();
const(EVP_CIPHER)* EVP_bf_ofb ();
const(EVP_CIPHER)* EVP_cast5_ecb ();
const(EVP_CIPHER)* EVP_cast5_cbc ();
const(EVP_CIPHER)* EVP_cast5_cfb64 ();
const(EVP_CIPHER)* EVP_cast5_ofb ();
const(EVP_CIPHER)* EVP_aes_128_ecb ();
const(EVP_CIPHER)* EVP_aes_128_cbc ();
const(EVP_CIPHER)* EVP_aes_128_cfb1 ();
const(EVP_CIPHER)* EVP_aes_128_cfb8 ();
const(EVP_CIPHER)* EVP_aes_128_cfb128 ();
const(EVP_CIPHER)* EVP_aes_128_ofb ();
const(EVP_CIPHER)* EVP_aes_128_ctr ();
const(EVP_CIPHER)* EVP_aes_128_ccm ();
const(EVP_CIPHER)* EVP_aes_128_gcm ();
const(EVP_CIPHER)* EVP_aes_128_xts ();
const(EVP_CIPHER)* EVP_aes_192_ecb ();
const(EVP_CIPHER)* EVP_aes_192_cbc ();
const(EVP_CIPHER)* EVP_aes_192_cfb1 ();
const(EVP_CIPHER)* EVP_aes_192_cfb8 ();
const(EVP_CIPHER)* EVP_aes_192_cfb128 ();
const(EVP_CIPHER)* EVP_aes_192_ofb ();
const(EVP_CIPHER)* EVP_aes_192_ctr ();
const(EVP_CIPHER)* EVP_aes_192_ccm ();
const(EVP_CIPHER)* EVP_aes_192_gcm ();
const(EVP_CIPHER)* EVP_aes_256_ecb ();
const(EVP_CIPHER)* EVP_aes_256_cbc ();
const(EVP_CIPHER)* EVP_aes_256_cfb1 ();
const(EVP_CIPHER)* EVP_aes_256_cfb8 ();
const(EVP_CIPHER)* EVP_aes_256_cfb128 ();
const(EVP_CIPHER)* EVP_aes_256_ofb ();
const(EVP_CIPHER)* EVP_aes_256_ctr ();
const(EVP_CIPHER)* EVP_aes_256_ccm ();
const(EVP_CIPHER)* EVP_aes_256_gcm ();
const(EVP_CIPHER)* EVP_aes_256_xts ();
const(EVP_CIPHER)* EVP_aes_128_cbc_hmac_sha1 ();
const(EVP_CIPHER)* EVP_aes_256_cbc_hmac_sha1 ();
const(EVP_CIPHER)* EVP_camellia_128_ecb ();
const(EVP_CIPHER)* EVP_camellia_128_cbc ();
const(EVP_CIPHER)* EVP_camellia_128_cfb1 ();
const(EVP_CIPHER)* EVP_camellia_128_cfb8 ();
const(EVP_CIPHER)* EVP_camellia_128_cfb128 ();
const(EVP_CIPHER)* EVP_camellia_128_ofb ();
const(EVP_CIPHER)* EVP_camellia_192_ecb ();
const(EVP_CIPHER)* EVP_camellia_192_cbc ();
const(EVP_CIPHER)* EVP_camellia_192_cfb1 ();
const(EVP_CIPHER)* EVP_camellia_192_cfb8 ();
const(EVP_CIPHER)* EVP_camellia_192_cfb128 ();
const(EVP_CIPHER)* EVP_camellia_192_ofb ();
const(EVP_CIPHER)* EVP_camellia_256_ecb ();
const(EVP_CIPHER)* EVP_camellia_256_cbc ();
const(EVP_CIPHER)* EVP_camellia_256_cfb1 ();
const(EVP_CIPHER)* EVP_camellia_256_cfb8 ();
const(EVP_CIPHER)* EVP_camellia_256_cfb128 ();
const(EVP_CIPHER)* EVP_camellia_256_ofb ();
const(EVP_CIPHER)* EVP_chacha20 ();
const(EVP_CIPHER)* EVP_gost2814789_ecb ();
const(EVP_CIPHER)* EVP_gost2814789_cfb64 ();
const(EVP_CIPHER)* EVP_gost2814789_cnt ();
void OPENSSL_add_all_algorithms_noconf ();
void OPENSSL_add_all_algorithms_conf ();
void OpenSSL_add_all_ciphers ();
void OpenSSL_add_all_digests ();
int EVP_add_cipher (const(EVP_CIPHER)* cipher);
int EVP_add_digest (const(EVP_MD)* digest);
const(EVP_CIPHER)* EVP_get_cipherbyname (const(char)* name);
const(EVP_MD)* EVP_get_digestbyname (const(char)* name);
void EVP_cleanup ();
void EVP_CIPHER_do_all (void function (const(EVP_CIPHER)*, const(char)*, const(char)*, void*) fn, void* arg);
void EVP_CIPHER_do_all_sorted (void function (const(EVP_CIPHER)*, const(char)*, const(char)*, void*) fn, void* arg);
void EVP_MD_do_all (void function (const(EVP_MD)*, const(char)*, const(char)*, void*) fn, void* arg);
void EVP_MD_do_all_sorted (void function (const(EVP_MD)*, const(char)*, const(char)*, void*) fn, void* arg);
int EVP_PKEY_decrypt_old (ubyte* dec_key, const(ubyte)* enc_key, int enc_key_len, EVP_PKEY* private_key);
int EVP_PKEY_encrypt_old (ubyte* enc_key, const(ubyte)* key, int key_len, EVP_PKEY* pub_key);
int EVP_PKEY_type (int type);
int EVP_PKEY_id (const(EVP_PKEY)* pkey);
int EVP_PKEY_base_id (const(EVP_PKEY)* pkey);
int EVP_PKEY_bits (EVP_PKEY* pkey);
int EVP_PKEY_size (EVP_PKEY* pkey);
int EVP_PKEY_set_type (EVP_PKEY* pkey, int type);
int EVP_PKEY_set_type_str (EVP_PKEY* pkey, const(char)* str, int len);
void* EVP_PKEY_get0 (EVP_PKEY* pkey);
int EVP_PKEY_set1_RSA (EVP_PKEY* pkey, rsa_st* key);
rsa_st* EVP_PKEY_get1_RSA (EVP_PKEY* pkey);
int EVP_PKEY_set1_DSA (EVP_PKEY* pkey, dsa_st* key);
dsa_st* EVP_PKEY_get1_DSA (EVP_PKEY* pkey);
int EVP_PKEY_set1_DH (EVP_PKEY* pkey, dh_st* key);
dh_st* EVP_PKEY_get1_DH (EVP_PKEY* pkey);
int EVP_PKEY_set1_EC_KEY (EVP_PKEY* pkey, ec_key_st* key);
ec_key_st* EVP_PKEY_get1_EC_KEY (EVP_PKEY* pkey);
EVP_PKEY* EVP_PKEY_new ();
void EVP_PKEY_free (EVP_PKEY* pkey);
EVP_PKEY* d2i_PublicKey (int type, EVP_PKEY** a, const(ubyte*)* pp, c_long length);
int i2d_PublicKey (EVP_PKEY* a, ubyte** pp);
EVP_PKEY* d2i_PrivateKey (int type, EVP_PKEY** a, const(ubyte*)* pp, c_long length);
EVP_PKEY* d2i_AutoPrivateKey (EVP_PKEY** a, const(ubyte*)* pp, c_long length);
int i2d_PrivateKey (EVP_PKEY* a, ubyte** pp);
int EVP_PKEY_copy_parameters (EVP_PKEY* to, const(EVP_PKEY)* from);
int EVP_PKEY_missing_parameters (const(EVP_PKEY)* pkey);
int EVP_PKEY_save_parameters (EVP_PKEY* pkey, int mode);
int EVP_PKEY_cmp_parameters (const(EVP_PKEY)* a, const(EVP_PKEY)* b);
int EVP_PKEY_cmp (const(EVP_PKEY)* a, const(EVP_PKEY)* b);
int EVP_PKEY_print_public (BIO* out_, const(EVP_PKEY)* pkey, int indent, ASN1_PCTX* pctx);
int EVP_PKEY_print_private (BIO* out_, const(EVP_PKEY)* pkey, int indent, ASN1_PCTX* pctx);
int EVP_PKEY_print_params (BIO* out_, const(EVP_PKEY)* pkey, int indent, ASN1_PCTX* pctx);
int EVP_PKEY_get_default_digest_nid (EVP_PKEY* pkey, int* pnid);
int EVP_CIPHER_type (const(EVP_CIPHER)* ctx);
int EVP_CIPHER_param_to_asn1 (EVP_CIPHER_CTX* c, ASN1_TYPE* type);
int EVP_CIPHER_asn1_to_param (EVP_CIPHER_CTX* c, ASN1_TYPE* type);
int EVP_CIPHER_set_asn1_iv (EVP_CIPHER_CTX* c, ASN1_TYPE* type);
int EVP_CIPHER_get_asn1_iv (EVP_CIPHER_CTX* c, ASN1_TYPE* type);
int PKCS5_PBE_keyivgen (EVP_CIPHER_CTX* ctx, const(char)* pass, int passlen, ASN1_TYPE* param, const(EVP_CIPHER)* cipher, const(EVP_MD)* md, int en_de);
int PKCS5_PBKDF2_HMAC_SHA1 (const(char)* pass, int passlen, const(ubyte)* salt, int saltlen, int iter, int keylen, ubyte* out_);
int PKCS5_PBKDF2_HMAC (const(char)* pass, int passlen, const(ubyte)* salt, int saltlen, int iter, const(EVP_MD)* digest, int keylen, ubyte* out_);
int PKCS5_v2_PBE_keyivgen (EVP_CIPHER_CTX* ctx, const(char)* pass, int passlen, ASN1_TYPE* param, const(EVP_CIPHER)* cipher, const(EVP_MD)* md, int en_de);
void PKCS5_PBE_add ();
int EVP_PBE_CipherInit (ASN1_OBJECT* pbe_obj, const(char)* pass, int passlen, ASN1_TYPE* param, EVP_CIPHER_CTX* ctx, int en_de);
int EVP_PBE_alg_add_type (int pbe_type, int pbe_nid, int cipher_nid, int md_nid, int function (EVP_CIPHER_CTX*, const(char)*, int, ASN1_TYPE*, const(EVP_CIPHER)*, const(EVP_MD)*, int) keygen);
int EVP_PBE_alg_add (int nid, const(EVP_CIPHER)* cipher, const(EVP_MD)* md, int function (EVP_CIPHER_CTX*, const(char)*, int, ASN1_TYPE*, const(EVP_CIPHER)*, const(EVP_MD)*, int) keygen);
int EVP_PBE_find (int type, int pbe_nid, int* pcnid, int* pmnid, int function (EVP_CIPHER_CTX*, const(char)*, int, ASN1_TYPE*, const(EVP_CIPHER)*, const(EVP_MD)*, int)* pkeygen);
void EVP_PBE_cleanup ();
int EVP_PKEY_asn1_get_count ();
const(EVP_PKEY_ASN1_METHOD)* EVP_PKEY_asn1_get0 (int idx);
const(EVP_PKEY_ASN1_METHOD)* EVP_PKEY_asn1_find (ENGINE** pe, int type);
const(EVP_PKEY_ASN1_METHOD)* EVP_PKEY_asn1_find_str (ENGINE** pe, const(char)* str, int len);
int EVP_PKEY_asn1_add0 (const(EVP_PKEY_ASN1_METHOD)* ameth);
int EVP_PKEY_asn1_add_alias (int to, int from);
int EVP_PKEY_asn1_get0_info (int* ppkey_id, int* pkey_base_id, int* ppkey_flags, const(char*)* pinfo, const(char*)* ppem_str, const(EVP_PKEY_ASN1_METHOD)* ameth);
const(EVP_PKEY_ASN1_METHOD)* EVP_PKEY_get0_asn1 (EVP_PKEY* pkey);
EVP_PKEY_ASN1_METHOD* EVP_PKEY_asn1_new (int id, int flags, const(char)* pem_str, const(char)* info);
void EVP_PKEY_asn1_copy (EVP_PKEY_ASN1_METHOD* dst, const(EVP_PKEY_ASN1_METHOD)* src);
void EVP_PKEY_asn1_free (EVP_PKEY_ASN1_METHOD* ameth);
void EVP_PKEY_asn1_set_public (EVP_PKEY_ASN1_METHOD* ameth, int function (EVP_PKEY*, X509_PUBKEY*) pub_decode, int function (X509_PUBKEY*, const(EVP_PKEY)*) pub_encode, int function (const(EVP_PKEY)*, const(EVP_PKEY)*) pub_cmp, int function (BIO*, const(EVP_PKEY)*, int, ASN1_PCTX*) pub_print, int function (const(EVP_PKEY)*) pkey_size, int function (const(EVP_PKEY)*) pkey_bits);
void EVP_PKEY_asn1_set_private (EVP_PKEY_ASN1_METHOD* ameth, int function (EVP_PKEY*, PKCS8_PRIV_KEY_INFO*) priv_decode, int function (PKCS8_PRIV_KEY_INFO*, const(EVP_PKEY)*) priv_encode, int function (BIO*, const(EVP_PKEY)*, int, ASN1_PCTX*) priv_print);
void EVP_PKEY_asn1_set_param (EVP_PKEY_ASN1_METHOD* ameth, int function (EVP_PKEY*, const(ubyte*)*, int) param_decode, int function (const(EVP_PKEY)*, ubyte**) param_encode, int function (const(EVP_PKEY)*) param_missing, int function (EVP_PKEY*, const(EVP_PKEY)*) param_copy, int function (const(EVP_PKEY)*, const(EVP_PKEY)*) param_cmp, int function (BIO*, const(EVP_PKEY)*, int, ASN1_PCTX*) param_print);
void EVP_PKEY_asn1_set_free (EVP_PKEY_ASN1_METHOD* ameth, void function (EVP_PKEY*) pkey_free);
void EVP_PKEY_asn1_set_ctrl (EVP_PKEY_ASN1_METHOD* ameth, int function (EVP_PKEY*, int, c_long, void*) pkey_ctrl);
const(EVP_PKEY_METHOD)* EVP_PKEY_meth_find (int type);
EVP_PKEY_METHOD* EVP_PKEY_meth_new (int id, int flags);
void EVP_PKEY_meth_get0_info (int* ppkey_id, int* pflags, const(EVP_PKEY_METHOD)* meth);
void EVP_PKEY_meth_copy (EVP_PKEY_METHOD* dst, const(EVP_PKEY_METHOD)* src);
void EVP_PKEY_meth_free (EVP_PKEY_METHOD* pmeth);
int EVP_PKEY_meth_add0 (const(EVP_PKEY_METHOD)* pmeth);
EVP_PKEY_CTX* EVP_PKEY_CTX_new (EVP_PKEY* pkey, ENGINE* e);
EVP_PKEY_CTX* EVP_PKEY_CTX_new_id (int id, ENGINE* e);
EVP_PKEY_CTX* EVP_PKEY_CTX_dup (EVP_PKEY_CTX* ctx);
void EVP_PKEY_CTX_free (EVP_PKEY_CTX* ctx);
int EVP_PKEY_CTX_ctrl (EVP_PKEY_CTX* ctx, int keytype, int optype, int cmd, int p1, void* p2);
int EVP_PKEY_CTX_ctrl_str (EVP_PKEY_CTX* ctx, const(char)* type, const(char)* value);
int EVP_PKEY_CTX_get_operation (EVP_PKEY_CTX* ctx);
void EVP_PKEY_CTX_set0_keygen_info (EVP_PKEY_CTX* ctx, int* dat, int datlen);
EVP_PKEY* EVP_PKEY_new_mac_key (int type, ENGINE* e, const(ubyte)* key, int keylen);
void EVP_PKEY_CTX_set_data (EVP_PKEY_CTX* ctx, void* data);
void* EVP_PKEY_CTX_get_data (EVP_PKEY_CTX* ctx);
EVP_PKEY* EVP_PKEY_CTX_get0_pkey (EVP_PKEY_CTX* ctx);
EVP_PKEY* EVP_PKEY_CTX_get0_peerkey (EVP_PKEY_CTX* ctx);
void EVP_PKEY_CTX_set_app_data (EVP_PKEY_CTX* ctx, void* data);
void* EVP_PKEY_CTX_get_app_data (EVP_PKEY_CTX* ctx);
int EVP_PKEY_sign_init (EVP_PKEY_CTX* ctx);
int EVP_PKEY_sign (EVP_PKEY_CTX* ctx, ubyte* sig, size_t* siglen, const(ubyte)* tbs, size_t tbslen);
int EVP_PKEY_verify_init (EVP_PKEY_CTX* ctx);
int EVP_PKEY_verify (EVP_PKEY_CTX* ctx, const(ubyte)* sig, size_t siglen, const(ubyte)* tbs, size_t tbslen);
int EVP_PKEY_verify_recover_init (EVP_PKEY_CTX* ctx);
int EVP_PKEY_verify_recover (EVP_PKEY_CTX* ctx, ubyte* rout, size_t* routlen, const(ubyte)* sig, size_t siglen);
int EVP_PKEY_encrypt_init (EVP_PKEY_CTX* ctx);
int EVP_PKEY_encrypt (EVP_PKEY_CTX* ctx, ubyte* out_, size_t* outlen, const(ubyte)* in_, size_t inlen);
int EVP_PKEY_decrypt_init (EVP_PKEY_CTX* ctx);
int EVP_PKEY_decrypt (EVP_PKEY_CTX* ctx, ubyte* out_, size_t* outlen, const(ubyte)* in_, size_t inlen);
int EVP_PKEY_derive_init (EVP_PKEY_CTX* ctx);
int EVP_PKEY_derive_set_peer (EVP_PKEY_CTX* ctx, EVP_PKEY* peer);
int EVP_PKEY_derive (EVP_PKEY_CTX* ctx, ubyte* key, size_t* keylen);
int EVP_PKEY_paramgen_init (EVP_PKEY_CTX* ctx);
int EVP_PKEY_paramgen (EVP_PKEY_CTX* ctx, EVP_PKEY** ppkey);
int EVP_PKEY_keygen_init (EVP_PKEY_CTX* ctx);
int EVP_PKEY_keygen (EVP_PKEY_CTX* ctx, EVP_PKEY** ppkey);
void EVP_PKEY_CTX_set_cb (EVP_PKEY_CTX* ctx, int function (EVP_PKEY_CTX*) cb);
int function (EVP_PKEY_CTX*) EVP_PKEY_CTX_get_cb (EVP_PKEY_CTX* ctx);
int EVP_PKEY_CTX_get_keygen_info (EVP_PKEY_CTX* ctx, int idx);
void EVP_PKEY_meth_set_init (EVP_PKEY_METHOD* pmeth, int function (EVP_PKEY_CTX*) init);
void EVP_PKEY_meth_set_copy (EVP_PKEY_METHOD* pmeth, int function (EVP_PKEY_CTX*, EVP_PKEY_CTX*) copy);
void EVP_PKEY_meth_set_cleanup (EVP_PKEY_METHOD* pmeth, void function (EVP_PKEY_CTX*) cleanup);
void EVP_PKEY_meth_set_paramgen (EVP_PKEY_METHOD* pmeth, int function (EVP_PKEY_CTX*) paramgen_init, int function (EVP_PKEY_CTX*, EVP_PKEY*) paramgen);
void EVP_PKEY_meth_set_keygen (EVP_PKEY_METHOD* pmeth, int function (EVP_PKEY_CTX*) keygen_init, int function (EVP_PKEY_CTX*, EVP_PKEY*) keygen);
void EVP_PKEY_meth_set_sign (EVP_PKEY_METHOD* pmeth, int function (EVP_PKEY_CTX*) sign_init, int function (EVP_PKEY_CTX*, ubyte*, size_t*, const(ubyte)*, size_t) sign);
void EVP_PKEY_meth_set_verify (EVP_PKEY_METHOD* pmeth, int function (EVP_PKEY_CTX*) verify_init, int function (EVP_PKEY_CTX*, const(ubyte)*, size_t, const(ubyte)*, size_t) verify);
void EVP_PKEY_meth_set_verify_recover (EVP_PKEY_METHOD* pmeth, int function (EVP_PKEY_CTX*) verify_recover_init, int function (EVP_PKEY_CTX*, ubyte*, size_t*, const(ubyte)*, size_t) verify_recover);
void EVP_PKEY_meth_set_signctx (EVP_PKEY_METHOD* pmeth, int function (EVP_PKEY_CTX*, EVP_MD_CTX*) signctx_init, int function (EVP_PKEY_CTX*, ubyte*, size_t*, EVP_MD_CTX*) signctx);
void EVP_PKEY_meth_set_verifyctx (EVP_PKEY_METHOD* pmeth, int function (EVP_PKEY_CTX*, EVP_MD_CTX*) verifyctx_init, int function (EVP_PKEY_CTX*, const(ubyte)*, int, EVP_MD_CTX*) verifyctx);
void EVP_PKEY_meth_set_encrypt (EVP_PKEY_METHOD* pmeth, int function (EVP_PKEY_CTX*) encrypt_init, int function (EVP_PKEY_CTX*, ubyte*, size_t*, const(ubyte)*, size_t) encryptfn);
void EVP_PKEY_meth_set_decrypt (EVP_PKEY_METHOD* pmeth, int function (EVP_PKEY_CTX*) decrypt_init, int function (EVP_PKEY_CTX*, ubyte*, size_t*, const(ubyte)*, size_t) decrypt);
void EVP_PKEY_meth_set_derive (EVP_PKEY_METHOD* pmeth, int function (EVP_PKEY_CTX*) derive_init, int function (EVP_PKEY_CTX*, ubyte*, size_t*) derive);
void EVP_PKEY_meth_set_ctrl (EVP_PKEY_METHOD* pmeth, int function (EVP_PKEY_CTX*, int, int, void*) ctrl, int function (EVP_PKEY_CTX*, const(char)*, const(char)*) ctrl_str);
const(EVP_AEAD)* EVP_aead_aes_128_gcm ();
const(EVP_AEAD)* EVP_aead_aes_256_gcm ();
const(EVP_AEAD)* EVP_aead_chacha20_poly1305 ();
const(EVP_AEAD)* EVP_aead_chacha20_poly1305_old ();
size_t EVP_AEAD_key_length (const(EVP_AEAD)* aead);
size_t EVP_AEAD_nonce_length (const(EVP_AEAD)* aead);
size_t EVP_AEAD_max_overhead (const(EVP_AEAD)* aead);
size_t EVP_AEAD_max_tag_len (const(EVP_AEAD)* aead);
int EVP_AEAD_CTX_init (EVP_AEAD_CTX* ctx, const(EVP_AEAD)* aead, const(ubyte)* key, size_t key_len, size_t tag_len, ENGINE* impl);
void EVP_AEAD_CTX_cleanup (EVP_AEAD_CTX* ctx);
int EVP_AEAD_CTX_seal (const(EVP_AEAD_CTX)* ctx, ubyte* out_, size_t* out_len, size_t max_out_len, const(ubyte)* nonce, size_t nonce_len, const(ubyte)* in_, size_t in_len, const(ubyte)* ad, size_t ad_len);
int EVP_AEAD_CTX_open (const(EVP_AEAD_CTX)* ctx, ubyte* out_, size_t* out_len, size_t max_out_len, const(ubyte)* nonce, size_t nonce_len, const(ubyte)* in_, size_t in_len, const(ubyte)* ad, size_t ad_len);
void EVP_add_alg_module ();
void ERR_load_EVP_strings ();