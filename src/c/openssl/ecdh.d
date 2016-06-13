module c.openssl.ecdh;

import core.stdc.config;

//public import c.openssl.opensslconf;

public import c.openssl.ec;
public import c.openssl.ossl_typ;
// public import c.openssl.bn;

extern (C):

const(ECDH_METHOD)* ECDH_OpenSSL ();
void ECDH_set_default_method (const(ECDH_METHOD)*);
const(ECDH_METHOD)* ECDH_get_default_method ();
int ECDH_set_method (EC_KEY*, const(ECDH_METHOD)*);
int ECDH_size (const(EC_KEY)* ecdh);
int ECDH_compute_key (void* out_, size_t outlen, const(EC_POINT)* pub_key, EC_KEY* ecdh, void* function (const(void)*, size_t, void*, size_t*) KDF);
int ECDH_get_ex_new_index (c_long argl, void* argp, int function (void*, void*, CRYPTO_EX_DATA*, int, c_long, void*) new_func, int function (CRYPTO_EX_DATA*, CRYPTO_EX_DATA*, void*, int, c_long, void*) dup_func, void function (void*, void*, CRYPTO_EX_DATA*, int, c_long, void*) free_func);
int ECDH_set_ex_data (EC_KEY* d, int idx, void* arg);
void* ECDH_get_ex_data (EC_KEY* d, int idx);
void ERR_load_ECDH_strings ();

/* Error codes for the ECDH functions. */

/* Function codes. */
enum ECDH_F_ECDH_CHECK = 102;
enum ECDH_F_ECDH_COMPUTE_KEY = 100;
enum ECDH_F_ECDH_DATA_NEW_METHOD = 101;

/* Reason codes. */
enum ECDH_R_KDF_FAILED = 102;
enum ECDH_R_KEY_TRUNCATION = 104;
enum ECDH_R_NON_FIPS_METHOD = 103;
enum ECDH_R_NO_PRIVATE_VALUE = 100;
enum ECDH_R_POINT_ARITHMETIC_FAILURE = 101;
