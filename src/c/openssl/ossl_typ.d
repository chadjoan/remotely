module c.openssl.ossl_typ;

// public import c.openssl.opensslconf;


// These imports are not in the original header, but D needs them.
// Otherwise, D won't know what the aliases in this module are referring to.
import c.openssl.crypto;
import c.openssl.evp;
import c.openssl.ecdsa;

extern (C):

alias asn1_string_st ASN1_INTEGER;
alias asn1_string_st ASN1_ENUMERATED;
alias asn1_string_st ASN1_BIT_STRING;
alias asn1_string_st ASN1_OCTET_STRING;
alias asn1_string_st ASN1_PRINTABLESTRING;
alias asn1_string_st ASN1_T61STRING;
alias asn1_string_st ASN1_IA5STRING;
alias asn1_string_st ASN1_GENERALSTRING;
alias asn1_string_st ASN1_UNIVERSALSTRING;
alias asn1_string_st ASN1_BMPSTRING;
alias asn1_string_st ASN1_UTCTIME;
alias asn1_string_st ASN1_TIME;
alias asn1_string_st ASN1_GENERALIZEDTIME;
alias asn1_string_st ASN1_VISIBLESTRING;
alias asn1_string_st ASN1_UTF8STRING;
alias asn1_string_st ASN1_STRING;
alias int ASN1_BOOLEAN;
alias int ASN1_NULL;
alias ASN1_ITEM = ASN1_ITEM_st;
alias asn1_pctx_st ASN1_PCTX;
alias bignum_st BIGNUM;
alias bignum_ctx BN_CTX;
alias bn_blinding_st BN_BLINDING;
alias bn_mont_ctx_st BN_MONT_CTX;
alias bn_recp_ctx_st BN_RECP_CTX;
alias bn_gencb_st BN_GENCB;
alias buf_mem_st BUF_MEM;
alias evp_cipher_st EVP_CIPHER;
alias evp_cipher_ctx_st EVP_CIPHER_CTX;
alias env_md_st EVP_MD;
alias env_md_ctx_st EVP_MD_CTX;
alias evp_pkey_st EVP_PKEY;
alias evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;
alias evp_pkey_method_st EVP_PKEY_METHOD;
alias evp_pkey_ctx_st EVP_PKEY_CTX;
alias dh_st DH;
alias dh_method DH_METHOD;
alias dsa_st DSA;
alias dsa_method DSA_METHOD;
alias rsa_st RSA;
alias rsa_meth_st RSA_METHOD;
alias rand_meth_st RAND_METHOD;
alias ecdh_method ECDH_METHOD;
alias ecdsa_method ECDSA_METHOD;
alias x509_st X509;
alias X509_algor_st X509_ALGOR;
alias X509_crl_st X509_CRL;
alias x509_crl_method_st X509_CRL_METHOD;
alias x509_revoked_st X509_REVOKED;
alias X509_name_st X509_NAME;
alias X509_pubkey_st X509_PUBKEY;
alias x509_store_st X509_STORE;
alias x509_store_ctx_st X509_STORE_CTX;
alias pkcs8_priv_key_info_st PKCS8_PRIV_KEY_INFO;
alias v3_ext_ctx X509V3_CTX;
alias conf_st CONF;
alias store_st STORE;
alias store_method_st STORE_METHOD;
alias ui_st UI;
alias ui_method_st UI_METHOD;
alias st_ERR_FNS ERR_FNS;
alias engine_st ENGINE;
alias ssl_st SSL;
alias ssl_ctx_st SSL_CTX;
alias X509_POLICY_NODE_st X509_POLICY_NODE;
alias X509_POLICY_LEVEL_st X509_POLICY_LEVEL;
alias X509_POLICY_TREE_st X509_POLICY_TREE;
alias X509_POLICY_CACHE_st X509_POLICY_CACHE;
alias AUTHORITY_KEYID_st AUTHORITY_KEYID;
alias DIST_POINT_st DIST_POINT;
alias ISSUING_DIST_POINT_st ISSUING_DIST_POINT;
alias NAME_CONSTRAINTS_st NAME_CONSTRAINTS;
alias crypto_ex_data_st CRYPTO_EX_DATA;

alias CRYPTO_EX_new = int function(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
    int idx, long argl, void *argp);
alias CRYPTO_EX_free = void function(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
    int idx, long argl, void *argp);
alias CRYPTO_EX_dup = int function(CRYPTO_EX_DATA *to, CRYPTO_EX_DATA *from,
    void *from_d, int idx, long argl, void *argp);

alias ocsp_req_ctx_st OCSP_REQ_CTX;
alias ocsp_response_st OCSP_RESPONSE;
alias ocsp_responder_id_st OCSP_RESPID;

struct st_ERR_FNS;


struct NAME_CONSTRAINTS_st;

// Defined in openssl.asn1
//struct asn1_string_st;

struct asn1_pctx_st;
struct ASN1_ITEM_st;

struct X509_pubkey_st;
struct X509_crl_st;
struct x509_st;
struct x509_store_st;
struct x509_revoked_st;
struct X509_name_st;
struct X509_POLICY_CACHE_st;
struct X509_POLICY_TREE_st;
struct x509_store_ctx_st;
struct X509_algor_st;
struct X509_POLICY_NODE_st;
struct x509_crl_method_st;
struct X509_POLICY_LEVEL_st;



// Defined in openssl.crypto;
//struct crypto_ex_data_st;


struct ssl_ctx_st;


struct ui_method_st;


struct dsa_method;


struct rsa_st;




struct bn_gencb_st;




struct AUTHORITY_KEYID_st;


struct ocsp_response_st;


struct ocsp_req_ctx_st;




struct bn_mont_ctx_st;


struct bignum_st;


struct dsa_st;


struct conf_st;


struct v3_ext_ctx;




struct store_method_st;


struct ssl_st;






struct rsa_meth_st;




struct bn_recp_ctx_st;

// Defined in openssl.ecdsa
//struct ecdsa_method;

struct ecdh_method;

struct rand_meth_st;


struct pkcs8_priv_key_info_st;



// Defined in openssl.evp
// struct env_md_ctx_st;
// struct env_md_st;
// struct evp_pkey_st;
// struct evp_cipher_st;
// struct evp_cipher_ctx_st;

struct evp_pkey_ctx_st;
struct evp_pkey_method_st;
struct evp_pkey_asn1_method_st;



struct buf_mem_st;


struct ocsp_responder_id_st;


struct dh_method;






struct ISSUING_DIST_POINT_st;


struct bignum_ctx;


struct DIST_POINT_st;


struct bn_blinding_st;








struct store_st;

struct ui_st;

struct dh_st;

struct engine_st;