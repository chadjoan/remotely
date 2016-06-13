module c.openssl.crypto;

import std.string;

import core.stdc.stdio;
import core.stdc.config;


//public import c.openssl.opensslconf;

//public import c.openssl.stack;
//public import c.openssl.safestack;
//public import c.openssl.opensslv;
public import c.openssl.ossl_typ;

extern (C):

// Can't actually find where this is declared in the C headers.
// They seem to pass it as "struct CRYPTO_dynlock_value*" all the time, so maybe
// it doesn't /need/ to be declared in C.  But it does in D.
struct CRYPTO_dynlock_value;

/* Backward compatibility to SSLeay */
/* This is more to be used to check the correct DLL is being used
 * in the MS world. */
//enum SSLEAY_VERSION_NUMBER = OPENSSL_VERSION_NUMBER;
enum SSLEAY_VERSION = 0;
/* #define SSLEAY_OPTIONS	1 no longer supported */
enum SSLEAY_CFLAGS = 2;
enum SSLEAY_BUILT_ON = 3;
enum SSLEAY_PLATFORM = 4;
enum SSLEAY_DIR = 5;


/* When changing the CRYPTO_LOCK_* list, be sure to maintain the text lock
 * names in cryptlib.c
 */

enum CRYPTO_LOCK_ERR = 1;
enum CRYPTO_LOCK_EX_DATA = 2;
enum CRYPTO_LOCK_X509 = 3;
enum CRYPTO_LOCK_X509_INFO = 4;
enum CRYPTO_LOCK_X509_PKEY = 5;
enum CRYPTO_LOCK_X509_CRL = 6;
enum CRYPTO_LOCK_X509_REQ = 7;
enum CRYPTO_LOCK_DSA = 8;
enum CRYPTO_LOCK_RSA = 9;
enum CRYPTO_LOCK_EVP_PKEY = 10;
enum CRYPTO_LOCK_X509_STORE = 11;
enum CRYPTO_LOCK_SSL_CTX = 12;
enum CRYPTO_LOCK_SSL_CERT = 13;
enum CRYPTO_LOCK_SSL_SESSION = 14;
enum CRYPTO_LOCK_SSL_SESS_CERT = 15;
enum CRYPTO_LOCK_SSL = 16;
enum CRYPTO_LOCK_SSL_METHOD = 17;
enum CRYPTO_LOCK_RAND = 18;
enum CRYPTO_LOCK_RAND2 = 19;
enum CRYPTO_LOCK_MALLOC = 20;
enum CRYPTO_LOCK_BIO = 21;
enum CRYPTO_LOCK_GETHOSTBYNAME = 22;
enum CRYPTO_LOCK_GETSERVBYNAME = 23;
enum CRYPTO_LOCK_READDIR = 24;
enum CRYPTO_LOCK_RSA_BLINDING = 25;
enum CRYPTO_LOCK_DH = 26;
enum CRYPTO_LOCK_MALLOC2 = 27;
enum CRYPTO_LOCK_DSO = 28;
enum CRYPTO_LOCK_DYNLOCK = 29;
enum CRYPTO_LOCK_ENGINE = 30;
enum CRYPTO_LOCK_UI = 31;
enum CRYPTO_LOCK_ECDSA = 32;
enum CRYPTO_LOCK_EC = 33;
enum CRYPTO_LOCK_ECDH = 34;
enum CRYPTO_LOCK_BN = 35;
enum CRYPTO_LOCK_EC_PRE_COMP = 36;
enum CRYPTO_LOCK_STORE = 37;
enum CRYPTO_LOCK_COMP = 38;
enum CRYPTO_LOCK_FIPS = 39;
enum CRYPTO_LOCK_FIPS2 = 40;
enum CRYPTO_NUM_LOCKS = 41;

enum CRYPTO_LOCK = 1;
enum CRYPTO_UNLOCK = 2;
enum CRYPTO_READ = 4;
enum CRYPTO_WRITE = 8;

void CRYPTO_lock (int mode, int type, immutable(char)* file, int line);
int CRYPTO_add_lock (int* pointer, int amount, int type, immutable(char)* file, int line);
//#ifndef OPENSSL_NO_LOCKING
//#ifndef CRYPTO_w_lock
extern(D) {
	// From C macros.
	void CRYPTO_w_lock(int type, string file = __FILE__, int line = __LINE__) {
		CRYPTO_lock(CRYPTO_LOCK|CRYPTO_WRITE,type,file.toStringz(),line);
	}
	void CRYPTO_w_unlock(int type, string file = __FILE__, int line = __LINE__) {
		CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_WRITE,type,file.toStringz(),line);
	}
	void CRYPTO_r_lock(int type, string file = __FILE__, int line = __LINE__) {
		CRYPTO_lock(CRYPTO_LOCK|CRYPTO_READ,type,file.toStringz(),line);
	}
	void CRYPTO_r_unlock(int type, string file = __FILE__, int line = __LINE__) {
		CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_READ,type,file.toStringz(),line);
	}
	int CRYPTO_add(int* addr, int amount, int type, string file = __FILE__, int line = __LINE__)	{
		return CRYPTO_add_lock(addr,amount,type,file.toStringz(),line);
	}
}
/+
#endif
#else
#define CRYPTO_w_lock(a)
#define CRYPTO_w_unlock(a)
#define CRYPTO_r_lock(a)
#define CRYPTO_r_unlock(a)
#define CRYPTO_add(a,b,c)	((*(a))+=(b))
#endif
+/

/* The following can be used to detect memory leaks in the SSLeay library.
 * It used, it turns on malloc checking */

enum CRYPTO_MEM_CHECK_OFF = 0x0;	/* an enume */
enum CRYPTO_MEM_CHECK_ON = 0x1;	/* a bit */
enum CRYPTO_MEM_CHECK_ENABLE = 0x2;	/* a bit */
enum CRYPTO_MEM_CHECK_DISABLE = 0x3;	/* an enume */

/* The following are bit values to turn on or off options connected to the
 * malloc checking functionality */

/* Adds time to the memory checking information */
enum V_CRYPTO_MDEBUG_TIME = 0x1; /* a bit */
/* Adds thread number to the memory checking information */
enum V_CRYPTO_MDEBUG_THREAD = 0x2; /* a bit */

enum V_CRYPTO_MDEBUG_ALL = (V_CRYPTO_MDEBUG_TIME | V_CRYPTO_MDEBUG_THREAD);


/* Per class, we have a STACK of CRYPTO_EX_DATA_FUNCS for each CRYPTO_EX_DATA
 * entry.
 */

enum CRYPTO_EX_INDEX_BIO = 0;
enum CRYPTO_EX_INDEX_SSL = 1;
enum CRYPTO_EX_INDEX_SSL_CTX = 2;
enum CRYPTO_EX_INDEX_SSL_SESSION = 3;
enum CRYPTO_EX_INDEX_X509_STORE = 4;
enum CRYPTO_EX_INDEX_X509_STORE_CTX = 5;
enum CRYPTO_EX_INDEX_RSA = 6;
enum CRYPTO_EX_INDEX_DSA = 7;
enum CRYPTO_EX_INDEX_DH = 8;
enum CRYPTO_EX_INDEX_ENGINE = 9;
enum CRYPTO_EX_INDEX_X509 = 10;
enum CRYPTO_EX_INDEX_UI = 11;
enum CRYPTO_EX_INDEX_ECDSA = 12;
enum CRYPTO_EX_INDEX_ECDH = 13;
enum CRYPTO_EX_INDEX_COMP = 14;
enum CRYPTO_EX_INDEX_STORE = 15;

/* Dynamically assigned indexes start from this value (don't use directly, use
 * via CRYPTO_ex_data_new_class). */
enum CRYPTO_EX_INDEX_USER = 100;

int CRYPTO_malloc_init() { return 0; }
int CRYPTO_malloc_debug_init() { return 0; }

//#if defined CRYPTO_MDEBUG_ALL || defined CRYPTO_MDEBUG_TIME || defined CRYPTO_MDEBUG_THREAD
//# ifndef CRYPTO_MDEBUG /* avoid duplicate #define */
//#  define CRYPTO_MDEBUG
//# endif
//#endif


/* for applications */
int CRYPTO_mem_ctrl (int mode);
void* CRYPTO_malloc (int num, immutable(char)* file, int line);
char* CRYPTO_strdup (const(char)* str, immutable(char)* file, int line);
void CRYPTO_free (void* ptr);
void* CRYPTO_realloc (void* addr, int num, immutable(char)* file, int line);
void* CRYPTO_realloc_clean (void* addr, int old_num, int num, immutable(char)* file, int line);
void* CRYPTO_remalloc (void* addr, int num, immutable(char)* file, int line);
void* CRYPTO_malloc_locked (int num, immutable(char)* file, int line);
void CRYPTO_free_locked (void* ptr);
int CRYPTO_push_info_ (const(char)* info, immutable(char)* file, int line);

extern(D) {
	// From C macros.
	int MemCheck_start() { return CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON) ;}
	int MemCheck_stop()  { return CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_OFF);}

	void* OPENSSL_malloc(int num, string file = __FILE__, int line = __LINE__) {
		return CRYPTO_malloc(num,file.toStringz(),line);
	}
	char* OPENSSL_strdup(const(char)* str, string file = __FILE__, int line = __LINE__) {
		return CRYPTO_strdup(str,file.toStringz(),line);
	}
	void* OPENSSL_realloc(void* addr,int num, string file = __FILE__, int line = __LINE__) {
		return CRYPTO_realloc(addr,num,file.toStringz(),line);
	}
	void* OPENSSL_realloc_clean(void* addr,int old_num,int num, string file = __FILE__, int line = __LINE__) {
		return CRYPTO_realloc_clean(addr,old_num,num,file.toStringz(),line);
	}
	void* OPENSSL_remalloc(void* addr,int num, string file = __FILE__, int line = __LINE__) {
		return CRYPTO_remalloc(addr,num,file.toStringz(),line);
	}
	void OPENSSL_freeFunc(void *ptr) { CRYPTO_free(ptr); } // TODO: This is probably not an accurate conversion.
	void OPENSSL_free(void* addr) { CRYPTO_free(addr); }

	void* OPENSSL_malloc_locked(int num, string file = __FILE__, int line = __LINE__) {
		return CRYPTO_malloc_locked(num,file.toStringz(),line);
	}
	void OPENSSL_free_locked(void* addr) { CRYPTO_free_locked(addr); }

	int CRYPTO_push_info(const(char)* info, string file = __FILE__, int line = __LINE__) {
		return CRYPTO_push_info_(info, file.toStringz(), line);
	}
}

alias openssl_item_st OPENSSL_ITEM;
alias bio_st BIO_dummy;
alias crypto_ex_data_func_st CRYPTO_EX_DATA_FUNCS;
alias st_CRYPTO_EX_DATA_IMPL CRYPTO_EX_DATA_IMPL;
alias crypto_threadid_st CRYPTO_THREADID;
alias CRYPTO_MEM_LEAK_CB = void *function(c_ulong, const char *, int, int, void *);

struct openssl_item_st
{
    int code;
    void* value;
    size_t value_size;
    size_t* value_length;
}

struct CRYPTO_dynlock
{
    int references;
    CRYPTO_dynlock_value* data;
}

struct crypto_ex_data_st
{
    stack_st_void* sk;
}

struct stack_st_void;
//struct stack_st_void
//{
//    _STACK stack;
//}

struct crypto_ex_data_func_st
{
    c_long argl;
    void* argp;
    int function (void*, void*, CRYPTO_EX_DATA*, int, c_long, void*) new_func;
    void function (void*, void*, CRYPTO_EX_DATA*, int, c_long, void*) free_func;
    int function (CRYPTO_EX_DATA*, CRYPTO_EX_DATA*, void*, int, c_long, void*) dup_func;
}

struct stack_st_CRYPTO_EX_DATA_FUNCS;
/+struct stack_st_CRYPTO_EX_DATA_FUNCS
{
    _STACK stack;
}+/

struct crypto_threadid_st
{
    void* ptr;
    c_ulong val;
}

struct bio_st;


struct st_CRYPTO_EX_DATA_IMPL;


int CRYPTO_is_mem_check_on ();
const(char)* SSLeay_version (int type);
c_ulong SSLeay ();
const(CRYPTO_EX_DATA_IMPL)* CRYPTO_get_ex_data_implementation ();
int CRYPTO_set_ex_data_implementation (const(CRYPTO_EX_DATA_IMPL)* i);
int CRYPTO_ex_data_new_class ();
int CRYPTO_get_ex_new_index (int class_index, c_long argl, void* argp, int function (void*, void*, CRYPTO_EX_DATA*, int, c_long, void*) new_func, int function (CRYPTO_EX_DATA*, CRYPTO_EX_DATA*, void*, int, c_long, void*) dup_func, void function (void*, void*, CRYPTO_EX_DATA*, int, c_long, void*) free_func);
int CRYPTO_new_ex_data (int class_index, void* obj, CRYPTO_EX_DATA* ad);
int CRYPTO_dup_ex_data (int class_index, CRYPTO_EX_DATA* to, CRYPTO_EX_DATA* from);
void CRYPTO_free_ex_data (int class_index, void* obj, CRYPTO_EX_DATA* ad);
int CRYPTO_set_ex_data (CRYPTO_EX_DATA* ad, int idx, void* val);
void* CRYPTO_get_ex_data (const(CRYPTO_EX_DATA)* ad, int idx);
void CRYPTO_cleanup_all_ex_data ();
int CRYPTO_get_new_lockid (char* name);
int CRYPTO_num_locks ();
void CRYPTO_set_locking_callback (void function (int, int, const(char)*, int) func);
void function (int, int, const(char)*, int) CRYPTO_get_locking_callback (int mode, int type, const(char)* file, int line);
void CRYPTO_set_add_lock_callback (int function (int*, int, int, const(char)*, int) func);
int function (int*, int, int, const(char)*, int) CRYPTO_get_add_lock_callback (int* num, int mount, int type, const(char)* file, int line);
void CRYPTO_THREADID_set_numeric (CRYPTO_THREADID* id, c_ulong val);
void CRYPTO_THREADID_set_pointer (CRYPTO_THREADID* id, void* ptr);
int CRYPTO_THREADID_set_callback (void function (CRYPTO_THREADID*) threadid_func);
void function (CRYPTO_THREADID*) CRYPTO_THREADID_get_callback (CRYPTO_THREADID*);
void CRYPTO_THREADID_current (CRYPTO_THREADID* id);
int CRYPTO_THREADID_cmp (const(CRYPTO_THREADID)* a, const(CRYPTO_THREADID)* b);
void CRYPTO_THREADID_cpy (CRYPTO_THREADID* dest, const(CRYPTO_THREADID)* src);
c_ulong CRYPTO_THREADID_hash (const(CRYPTO_THREADID)* id);
void CRYPTO_set_id_callback (c_ulong function () func);
c_ulong function () CRYPTO_get_id_callback ();
c_ulong CRYPTO_thread_id ();
const(char)* CRYPTO_get_lock_name (int type);
int CRYPTO_get_new_dynlockid ();
void CRYPTO_destroy_dynlockid (int i);
CRYPTO_dynlock_value* CRYPTO_get_dynlock_value (int i);
void CRYPTO_set_dynlock_create_callback (CRYPTO_dynlock_value* function (const(char)*, int) dyn_create_function);
void CRYPTO_set_dynlock_lock_callback (void function (int, CRYPTO_dynlock_value*, const(char)*, int) dyn_lock_function);
void CRYPTO_set_dynlock_destroy_callback (void function (CRYPTO_dynlock_value*, const(char)*, int) dyn_destroy_function);
CRYPTO_dynlock_value* function (const(char)*, int) CRYPTO_get_dynlock_create_callback (const(char)* file, int line);
void function (int, CRYPTO_dynlock_value*, const(char)*, int) CRYPTO_get_dynlock_lock_callback (int mode, CRYPTO_dynlock_value* l, const(char)* file, int line);
void function (CRYPTO_dynlock_value*, const(char)*, int) CRYPTO_get_dynlock_destroy_callback (CRYPTO_dynlock_value* l, const(char)* file, int line);
int CRYPTO_set_mem_functions (void* function (size_t) m, void* function (void*, size_t) r, void function (void*) f);
int CRYPTO_set_locked_mem_functions (void* function (size_t) m, void function (void*) free_func);
int CRYPTO_set_mem_ex_functions (void* function (size_t, const(char)*, int) m, void* function (void*, size_t, const(char)*, int) r, void function (void*) f);
int CRYPTO_set_locked_mem_ex_functions (void* function (size_t, const(char)*, int) m, void function (void*) free_func);
int CRYPTO_set_mem_debug_functions (void function (void*, int, const(char)*, int, int) m, void function (void*, void*, int, const(char)*, int, int) r, void function (void*, int) f, void function (c_long) so, c_long function () go);
void CRYPTO_get_mem_functions (void* function (size_t)* m, void* function (void*, size_t)* r, void function (void*)* f);
void CRYPTO_get_locked_mem_functions (void* function (size_t)* m, void function (void*)* f);
void CRYPTO_get_mem_ex_functions (void* function (size_t, const(char)*, int)* m, void* function (void*, size_t, const(char)*, int)* r, void function (void*)* f);
void CRYPTO_get_locked_mem_ex_functions (void* function (size_t, const(char)*, int)* m, void function (void*)* f);
void CRYPTO_get_mem_debug_functions (void function (void*, int, const(char)*, int, int)* m, void function (void*, void*, int, const(char)*, int, int)* r, void function (void*, int)* f, void function (c_long)* so, c_long function ()* go);
void OPENSSL_cleanse (void* ptr, size_t len);
void CRYPTO_set_mem_debug_options (c_long bits);
c_long CRYPTO_get_mem_debug_options ();
int CRYPTO_pop_info ();
int CRYPTO_remove_all_info ();
void CRYPTO_dbg_malloc (void* addr, int num, const(char)* file, int line, int before_p);
void CRYPTO_dbg_realloc (void* addr1, void* addr2, int num, const(char)* file, int line, int before_p);
void CRYPTO_dbg_free (void* addr, int before_p);
void CRYPTO_dbg_set_options (c_long bits);
c_long CRYPTO_dbg_get_options ();
void CRYPTO_mem_leaks_fp (FILE*);
void CRYPTO_mem_leaks (bio_st* bio);
void CRYPTO_mem_leaks_cb (void* function (c_ulong, const(char)*, int, int, void*) cb);
void OpenSSLDie (const(char)* file, int line, const(char)* assertion);
ulong OPENSSL_cpu_caps ();
int OPENSSL_isservice ();
void OPENSSL_init ();
int CRYPTO_memcmp (const(void)* a, const(void)* b, size_t len);
void ERR_load_CRYPTO_strings ();


/* Error codes for the CRYPTO functions. */

/* Function codes. */
enum CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX = 100;
enum CRYPTO_F_CRYPTO_GET_NEW_DYNLOCKID = 103;
enum CRYPTO_F_CRYPTO_GET_NEW_LOCKID = 101;
enum CRYPTO_F_CRYPTO_SET_EX_DATA = 102;
enum CRYPTO_F_DEF_ADD_INDEX = 104;
enum CRYPTO_F_DEF_GET_CLASS = 105;
enum CRYPTO_F_FIPS_MODE_SET = 109;
enum CRYPTO_F_INT_DUP_EX_DATA = 106;
enum CRYPTO_F_INT_FREE_EX_DATA = 107;
enum CRYPTO_F_INT_NEW_EX_DATA = 108;

/* Reason codes. */
enum CRYPTO_R_FIPS_MODE_NOT_SUPPORTED = 101;
enum CRYPTO_R_NO_DYNLOCK_CREATE_CALLBACK = 100;
