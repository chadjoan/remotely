module c.openssl.err;

import core.stdc.stdio;
import core.stdc.config;
import core.stdc.stdarg;

//public import c.openssl.opensslconf;
public import c.openssl.ossl_typ;
public import c.openssl.bio;
//public import c.openssl.lhash;

//#ifndef OPENSSL_NO_ERR
auto ERR_PUT_error(A,B,C,D,E)(A a, B b, C c, D d, E e) { return ERR_put_error(a,b,c,d,e); }
//#else
//#define ERR_PUT_error(a,b,c,d,e)	ERR_put_error(a,b,c,NULL,0)
//#endif

extern (C):


enum ERR_TXT_MALLOCED = 0x01;
enum ERR_TXT_STRING = 0x02;

enum ERR_FLAG_MARK = 0x01;

enum ERR_NUM_ERRORS = 16;


/* library */
enum ERR_LIB_NONE = 1;
enum ERR_LIB_SYS = 2;
enum ERR_LIB_BN = 3;
enum ERR_LIB_RSA = 4;
enum ERR_LIB_DH = 5;
enum ERR_LIB_EVP = 6;
enum ERR_LIB_BUF = 7;
enum ERR_LIB_OBJ = 8;
enum ERR_LIB_PEM = 9;
enum ERR_LIB_DSA = 10;
enum ERR_LIB_X509 = 11;
/* #define ERR_LIB_METH         12 */
enum ERR_LIB_ASN1 = 13;
enum ERR_LIB_CONF = 14;
enum ERR_LIB_CRYPTO = 15;
enum ERR_LIB_EC = 16;
enum ERR_LIB_SSL = 20;
/* #define ERR_LIB_SSL23        21 */
/* #define ERR_LIB_SSL2         22 */
/* #define ERR_LIB_SSL3         23 */
/* #define ERR_LIB_RSAREF       30 */
/* #define ERR_LIB_PROXY        31 */
enum ERR_LIB_BIO = 32;
enum ERR_LIB_PKCS7 = 33;
enum ERR_LIB_X509V3 = 34;
enum ERR_LIB_PKCS12 = 35;
enum ERR_LIB_RAND = 36;
enum ERR_LIB_DSO = 37;
enum ERR_LIB_ENGINE = 38;
enum ERR_LIB_OCSP = 39;
enum ERR_LIB_UI = 40;
enum ERR_LIB_COMP = 41;
enum ERR_LIB_ECDSA = 42;
enum ERR_LIB_ECDH = 43;
enum ERR_LIB_STORE = 44;
enum ERR_LIB_FIPS = 45;
enum ERR_LIB_CMS = 46;
enum ERR_LIB_TS = 47;
enum ERR_LIB_HMAC = 48;
enum ERR_LIB_JPAKE = 49;
enum ERR_LIB_GOST = 50;

enum ERR_LIB_USER = 128;


/* OS functions */
enum SYS_F_FOPEN = 1;
enum SYS_F_CONNECT = 2;
enum SYS_F_GETSERVBYNAME = 3;
enum SYS_F_SOCKET = 4;
enum SYS_F_IOCTLSOCKET = 5;
enum SYS_F_BIND = 6;
enum SYS_F_LISTEN = 7;
enum SYS_F_ACCEPT = 8;
enum SYS_F_WSASTARTUP = 9; /* Winsock stuff */
enum SYS_F_OPENDIR = 10;
enum SYS_F_FREAD = 11;


/* reasons */
enum ERR_R_SYS_LIB = ERR_LIB_SYS;       /* 2 */
enum ERR_R_BN_LIB = ERR_LIB_BN;        /* 3 */
enum ERR_R_RSA_LIB = ERR_LIB_RSA;       /* 4 */
enum ERR_R_DH_LIB = ERR_LIB_DH;        /* 5 */
enum ERR_R_EVP_LIB = ERR_LIB_EVP;       /* 6 */
enum ERR_R_BUF_LIB = ERR_LIB_BUF;       /* 7 */
enum ERR_R_OBJ_LIB = ERR_LIB_OBJ;       /* 8 */
enum ERR_R_PEM_LIB = ERR_LIB_PEM;       /* 9 */
enum ERR_R_DSA_LIB = ERR_LIB_DSA;      /* 10 */
enum ERR_R_X509_LIB = ERR_LIB_X509;     /* 11 */
enum ERR_R_ASN1_LIB = ERR_LIB_ASN1;     /* 13 */
enum ERR_R_CONF_LIB = ERR_LIB_CONF;     /* 14 */
enum ERR_R_CRYPTO_LIB = ERR_LIB_CRYPTO;  /* 15 */
enum ERR_R_EC_LIB = ERR_LIB_EC;       /* 16 */
enum ERR_R_SSL_LIB = ERR_LIB_SSL;      /* 20 */
enum ERR_R_BIO_LIB = ERR_LIB_BIO;      /* 32 */
enum ERR_R_PKCS7_LIB = ERR_LIB_PKCS7;    /* 33 */
enum ERR_R_X509V3_LIB = ERR_LIB_X509V3;  /* 34 */
enum ERR_R_PKCS12_LIB = ERR_LIB_PKCS12;  /* 35 */
enum ERR_R_RAND_LIB = ERR_LIB_RAND;     /* 36 */
enum ERR_R_DSO_LIB = ERR_LIB_DSO;      /* 37 */
enum ERR_R_ENGINE_LIB = ERR_LIB_ENGINE;  /* 38 */
enum ERR_R_OCSP_LIB = ERR_LIB_OCSP;     /* 39 */
enum ERR_R_UI_LIB = ERR_LIB_UI;       /* 40 */
enum ERR_R_COMP_LIB = ERR_LIB_COMP;     /* 41 */
enum ERR_R_ECDSA_LIB = ERR_LIB_ECDSA;	 /* 42 */
enum ERR_R_ECDH_LIB = ERR_LIB_ECDH;	 /* 43 */
enum ERR_R_STORE_LIB = ERR_LIB_STORE;    /* 44 */
enum ERR_R_TS_LIB = ERR_LIB_TS;       /* 45 */

enum ERR_R_NESTED_ASN1_ERROR = 58;
enum ERR_R_BAD_ASN1_OBJECT_HEADER = 59;
enum ERR_R_BAD_GET_ASN1_OBJECT_CALL = 60;
enum ERR_R_EXPECTING_AN_ASN1_SEQUENCE = 61;
enum ERR_R_ASN1_LENGTH_MISMATCH = 62;
enum ERR_R_MISSING_ASN1_EOS = 63;

/* fatal error */
enum ERR_R_FATAL = 64;
enum ERR_R_MALLOC_FAILURE = (1|ERR_R_FATAL);
enum ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED = (2|ERR_R_FATAL);
enum ERR_R_PASSED_NULL_PARAMETER = (3|ERR_R_FATAL);
enum ERR_R_INTERNAL_ERROR = (4|ERR_R_FATAL);
enum ERR_R_DISABLED = (5|ERR_R_FATAL);

/* 99 is the maximum possible ERR_R_... code, higher values
 * are reserved for the individual libraries */


alias err_state_st ERR_STATE;
alias ERR_string_data_st ERR_STRING_DATA;

struct err_state_st
{
    CRYPTO_THREADID tid;
    int[ERR_NUM_ERRORS] err_flags;
    c_ulong[ERR_NUM_ERRORS] err_buffer;
    char*[ERR_NUM_ERRORS] err_data;
    int[ERR_NUM_ERRORS] err_data_flags;
    const(char)*[ERR_NUM_ERRORS] err_file;
    int[ERR_NUM_ERRORS] err_line;
    int top;
    int bottom;
}

struct ERR_string_data_st
{
    c_ulong error;
    const(char)* string;
}

struct lhash_st_ERR_STRING_DATA;


struct lhash_st_ERR_STATE;


void ERR_put_error (int lib, int func, int reason, const(char)* file, int line);
void ERR_set_error_data (char* data, int flags);
c_ulong ERR_get_error ();
c_ulong ERR_get_error_line (const(char*)* file, int* line);
c_ulong ERR_get_error_line_data (const(char*)* file, int* line, const(char*)* data, int* flags);
c_ulong ERR_peek_error ();
c_ulong ERR_peek_error_line (const(char*)* file, int* line);
c_ulong ERR_peek_error_line_data (const(char*)* file, int* line, const(char*)* data, int* flags);
c_ulong ERR_peek_last_error ();
c_ulong ERR_peek_last_error_line (const(char*)* file, int* line);
c_ulong ERR_peek_last_error_line_data (const(char*)* file, int* line, const(char*)* data, int* flags);
void ERR_clear_error ();
char* ERR_error_string (c_ulong e, char* buf);
void ERR_error_string_n (c_ulong e, char* buf, size_t len);
const(char)* ERR_lib_error_string (c_ulong e);
const(char)* ERR_func_error_string (c_ulong e);
const(char)* ERR_reason_error_string (c_ulong e);
void ERR_print_errors_cb (int function (const(char)*, size_t, void*) cb, void* u);
void ERR_print_errors_fp (FILE* fp);
void ERR_print_errors (BIO* bp);
void ERR_asprintf_error_data (char* format, ...);
void ERR_add_error_data (int num, ...);
void ERR_add_error_vdata (int num, va_list args);

// TODO: SMELL: IS D's "T* x" binary compatible with C's "T x[]"?
// void ERR_load_strings(int lib, ERR_STRING_DATA str[]);
// void ERR_unload_strings(int lib, ERR_STRING_DATA str[]);
void ERR_load_strings (int lib, ERR_STRING_DATA* str);
void ERR_unload_strings (int lib, ERR_STRING_DATA* str);

void ERR_load_ERR_strings ();
void ERR_load_crypto_strings ();
void ERR_free_strings ();
void ERR_remove_thread_state (const(CRYPTO_THREADID)* tid);
void ERR_remove_state (c_ulong pid);
ERR_STATE* ERR_get_state ();
lhash_st_ERR_STRING_DATA* ERR_get_string_table ();
lhash_st_ERR_STATE* ERR_get_err_state_table ();
void ERR_release_err_state_table (lhash_st_ERR_STATE** hash);
int ERR_get_next_error_library ();
int ERR_set_mark ();
int ERR_pop_to_mark ();
const(ERR_FNS)* ERR_get_implementation ();
int ERR_set_implementation (const(ERR_FNS)* fns);
