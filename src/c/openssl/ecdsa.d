module c.openssl.ecdsa;

import core.stdc.config;

public import c.openssl.ec;
public import c.openssl.ossl_typ;
// public import c.openssl.bn;

extern (C):

/* If this flag is set the ECDSA method is FIPS compliant and can be used
 * in FIPS mode. This is set in the validated module method. If an
 * application sets this flag in its own methods it is its responsibility
 * to ensure the result is compliant.
 */
enum ECDSA_FLAG_FIPS_METHOD = 0x1;

alias ECDSA_SIG_st ECDSA_SIG;

struct ecdsa_method
{
    const(char)* name;
    ECDSA_SIG* function (const(ubyte)*, int, const(BIGNUM)*, const(BIGNUM)*, EC_KEY*) ecdsa_do_sign;
    int function (EC_KEY*, BN_CTX*, BIGNUM**, BIGNUM**) ecdsa_sign_setup;
    int function (const(ubyte)*, int, const(ECDSA_SIG)*, EC_KEY*) ecdsa_do_verify;
    int flags;
    char* app_data;
}

struct ECDSA_SIG_st
{
    BIGNUM* r;
    BIGNUM* s;
}

ECDSA_SIG* ECDSA_SIG_new ();
void ECDSA_SIG_free (ECDSA_SIG* sig);
int i2d_ECDSA_SIG (const(ECDSA_SIG)* sig, ubyte** pp);
ECDSA_SIG* d2i_ECDSA_SIG (ECDSA_SIG** sig, const(ubyte*)* pp, c_long len);
ECDSA_SIG* ECDSA_do_sign (const(ubyte)* dgst, int dgst_len, EC_KEY* eckey);
ECDSA_SIG* ECDSA_do_sign_ex (const(ubyte)* dgst, int dgstlen, const(BIGNUM)* kinv, const(BIGNUM)* rp, EC_KEY* eckey);
int ECDSA_do_verify (const(ubyte)* dgst, int dgst_len, const(ECDSA_SIG)* sig, EC_KEY* eckey);
const(ECDSA_METHOD)* ECDSA_OpenSSL ();
void ECDSA_set_default_method (const(ECDSA_METHOD)* meth);
const(ECDSA_METHOD)* ECDSA_get_default_method ();
int ECDSA_set_method (EC_KEY* eckey, const(ECDSA_METHOD)* meth);
int ECDSA_size (const(EC_KEY)* eckey);
int ECDSA_sign_setup (EC_KEY* eckey, BN_CTX* ctx, BIGNUM** kinv, BIGNUM** rp);
int ECDSA_sign (int type, const(ubyte)* dgst, int dgstlen, ubyte* sig, uint* siglen, EC_KEY* eckey);
int ECDSA_sign_ex (int type, const(ubyte)* dgst, int dgstlen, ubyte* sig, uint* siglen, const(BIGNUM)* kinv, const(BIGNUM)* rp, EC_KEY* eckey);
int ECDSA_verify (int type, const(ubyte)* dgst, int dgstlen, const(ubyte)* sig, int siglen, EC_KEY* eckey);
int ECDSA_get_ex_new_index (c_long argl, void* argp, int function (void*, void*, CRYPTO_EX_DATA*, int, c_long, void*) new_func, int function (CRYPTO_EX_DATA*, CRYPTO_EX_DATA*, void*, int, c_long, void*) dup_func, void function (void*, void*, CRYPTO_EX_DATA*, int, c_long, void*) free_func);
int ECDSA_set_ex_data (EC_KEY* d, int idx, void* arg);
void* ECDSA_get_ex_data (EC_KEY* d, int idx);
void ERR_load_ECDSA_strings ();

/* Error codes for the ECDSA functions. */

/* Function codes. */
enum ECDSA_F_ECDSA_CHECK = 104;
enum ECDSA_F_ECDSA_DATA_NEW_METHOD = 100;
enum ECDSA_F_ECDSA_DO_SIGN = 101;
enum ECDSA_F_ECDSA_DO_VERIFY = 102;
enum ECDSA_F_ECDSA_SIGN_SETUP = 103;

/* Reason codes. */
enum ECDSA_R_BAD_SIGNATURE = 100;
enum ECDSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE = 101;
enum ECDSA_R_ERR_EC_LIB = 102;
enum ECDSA_R_MISSING_PARAMETERS = 103;
enum ECDSA_R_NEED_NEW_SETUP_VALUES = 106;
enum ECDSA_R_NON_FIPS_METHOD = 107;
enum ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED = 104;
enum ECDSA_R_SIGNATURE_MALLOC_FAILED = 105;
