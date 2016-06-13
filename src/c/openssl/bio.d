module c.openssl.bio;

import core.stdc.stdio;
import core.stdc.config;
import core.stdc.stdarg;

public import c.openssl.crypto;

extern (C):

/* These are the 'types' of BIOs */
enum BIO_TYPE_NONE = 0;
enum BIO_TYPE_MEM = (1|0x0400);
enum BIO_TYPE_FILE = (2|0x0400);

enum BIO_TYPE_FD = (4|0x0400|0x0100);
enum BIO_TYPE_SOCKET = (5|0x0400|0x0100);
enum BIO_TYPE_NULL = (6|0x0400);
enum BIO_TYPE_SSL = (7|0x0200);
enum BIO_TYPE_MD = (8|0x0200);		/* passive filter */
enum BIO_TYPE_BUFFER = (9|0x0200);		/* filter */
enum BIO_TYPE_CIPHER = (10|0x0200);		/* filter */
enum BIO_TYPE_BASE64 = (11|0x0200);		/* filter */
enum BIO_TYPE_CONNECT = (12|0x0400|0x0100);	/* socket - connect */
enum BIO_TYPE_ACCEPT = (13|0x0400|0x0100);	/* socket for accept */
enum BIO_TYPE_PROXY_CLIENT = (14|0x0200);		/* client proxy BIO */
enum BIO_TYPE_PROXY_SERVER = (15|0x0200);		/* server proxy BIO */
enum BIO_TYPE_NBIO_TEST = (16|0x0200);		/* server proxy BIO */
enum BIO_TYPE_NULL_FILTER = (17|0x0200);
enum BIO_TYPE_BER = (18|0x0200);		/* BER -> bin filter */
enum BIO_TYPE_BIO = (19|0x0400);		/* (half a) BIO pair */
enum BIO_TYPE_LINEBUFFER = (20|0x0200);		/* filter */
enum BIO_TYPE_DGRAM = (21|0x0400|0x0100);
enum BIO_TYPE_ASN1 = (22|0x0200);		/* filter */
enum BIO_TYPE_COMP = (23|0x0200);		/* filter */

enum BIO_TYPE_DESCRIPTOR = 0x0100;	/* socket, fd, connect or accept */
enum BIO_TYPE_FILTER = 0x0200;
enum BIO_TYPE_SOURCE_SINK = 0x0400;

/* BIO_FILENAME_READ|BIO_CLOSE to open or close on free.
 * BIO_set_fp(in,stdin,BIO_NOCLOSE); */
enum BIO_NOCLOSE = 0x00;
enum BIO_CLOSE = 0x01;

/* These are used in the following macros and are passed to
 * BIO_ctrl() */
enum BIO_CTRL_RESET = 1;  /* opt - rewind/zero etc */
enum BIO_CTRL_EOF = 2;  /* opt - are we at the eof */
enum BIO_CTRL_INFO = 3;  /* opt - extra tit-bits */
enum BIO_CTRL_SET = 4;  /* man - set the 'IO' type */
enum BIO_CTRL_GET = 5;  /* man - get the 'IO' type */
enum BIO_CTRL_PUSH = 6;  /* opt - internal, used to signify change */
enum BIO_CTRL_POP = 7;  /* opt - internal, used to signify change */
enum BIO_CTRL_GET_CLOSE = 8;  /* man - set the 'close' on free */
enum BIO_CTRL_SET_CLOSE = 9;  /* man - set the 'close' on free */
enum BIO_CTRL_PENDING = 10;  /* opt - is their more data buffered */
enum BIO_CTRL_FLUSH = 11;  /* opt - 'flush' buffered output */
enum BIO_CTRL_DUP = 12;  /* man - extra stuff for 'duped' BIO */
enum BIO_CTRL_WPENDING = 13;  /* opt - number of bytes still to write */
/* callback is int cb(BIO *bio,state,ret); */
enum BIO_CTRL_SET_CALLBACK = 14;  /* opt - set callback function */
enum BIO_CTRL_GET_CALLBACK = 15;  /* opt - set callback function */

enum BIO_CTRL_SET_FILENAME = 30;	/* BIO_s_file special */

/* dgram BIO stuff */
enum BIO_CTRL_DGRAM_CONNECT = 31;  /* BIO dgram special */
enum BIO_CTRL_DGRAM_SET_CONNECTED = 32;  /* allow for an externally
					  * connected socket to be
					  * passed in */
enum BIO_CTRL_DGRAM_SET_RECV_TIMEOUT = 33; /* setsockopt, essentially */
enum BIO_CTRL_DGRAM_GET_RECV_TIMEOUT = 34; /* getsockopt, essentially */
enum BIO_CTRL_DGRAM_SET_SEND_TIMEOUT = 35; /* setsockopt, essentially */
enum BIO_CTRL_DGRAM_GET_SEND_TIMEOUT = 36; /* getsockopt, essentially */

enum BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP = 37; /* flag whether the last */
enum BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP = 38; /* I/O operation tiemd out */

/* #ifdef IP_MTU_DISCOVER */
enum BIO_CTRL_DGRAM_MTU_DISCOVER = 39; /* set DF bit on egress packets */
/* #endif */

enum BIO_CTRL_DGRAM_QUERY_MTU = 40; /* as kernel for current MTU */
enum BIO_CTRL_DGRAM_GET_FALLBACK_MTU = 47;
enum BIO_CTRL_DGRAM_GET_MTU = 41; /* get cached value for MTU */
enum BIO_CTRL_DGRAM_SET_MTU = 42; /* set cached value for
					      * MTU. want to use this
					      * if asking the kernel
					      * fails */

enum BIO_CTRL_DGRAM_MTU_EXCEEDED = 43; /* check whether the MTU
					      * was exceed in the
					      * previous write
					      * operation */

enum BIO_CTRL_DGRAM_GET_PEER = 46;
enum BIO_CTRL_DGRAM_SET_PEER = 44; /* Destination for the data */

enum BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT = 45; /* Next DTLS handshake timeout to
                                              * adjust socket timeouts */


/* modifiers */
enum BIO_FP_READ = 0x02;
enum BIO_FP_WRITE = 0x04;
enum BIO_FP_APPEND = 0x08;
enum BIO_FP_TEXT = 0x10;

enum BIO_FLAGS_READ = 0x01;
enum BIO_FLAGS_WRITE = 0x02;
enum BIO_FLAGS_IO_SPECIAL = 0x04;
enum BIO_FLAGS_RWS = (BIO_FLAGS_READ|BIO_FLAGS_WRITE|BIO_FLAGS_IO_SPECIAL);
enum BIO_FLAGS_SHOULD_RETRY = 0x08;

/* Used in BIO_gethostbyname() */
enum BIO_GHBN_CTRL_HITS = 1;
enum BIO_GHBN_CTRL_MISSES = 2;
enum BIO_GHBN_CTRL_CACHE_SIZE = 3;
enum BIO_GHBN_CTRL_GET_ENTRY = 4;
enum BIO_GHBN_CTRL_FLUSH = 5;

/* Mostly used in the SSL BIO */
/* Not used anymore
 * enum BIO_FLAGS_PROTOCOL_DELAYED_READ = 0x10;
 * enum BIO_FLAGS_PROTOCOL_DELAYED_WRITE = 0x20;
 * enum BIO_FLAGS_PROTOCOL_STARTUP = 0x40;
 */

enum BIO_FLAGS_BASE64_NO_NL = 0x100;

/* This is used with memory BIOs: it means we shouldn't free up or change the
 * data in any way.
 */
enum BIO_FLAGS_MEM_RDONLY = 0x200;

extern(D)
{
	auto BIO_get_flags(BIO* b) { return BIO_test_flags(b, ~(0x0)); }
	auto BIO_set_retry_special(BIO* b)
	{ return BIO_set_flags(b, (BIO_FLAGS_IO_SPECIAL|BIO_FLAGS_SHOULD_RETRY)); }
	auto BIO_set_retry_read(BIO* b)
	{ return BIO_set_flags(b, (BIO_FLAGS_READ|BIO_FLAGS_SHOULD_RETRY)); }
	auto BIO_set_retry_write(BIO* b)
	{ return BIO_set_flags(b, (BIO_FLAGS_WRITE|BIO_FLAGS_SHOULD_RETRY)); }

	/* These are normally used internally in BIOs */
	auto BIO_clear_retry_flags(BIO* b)
	{ return BIO_clear_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY)); }
	auto BIO_get_retry_flags(BIO* b)
	{ return BIO_test_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY)); }

	/* These should be used by the application to tell why we should retry */
	auto BIO_should_read(BIO* a)       { return BIO_test_flags(a, BIO_FLAGS_READ)        ;}
	auto BIO_should_write(BIO* a)      { return BIO_test_flags(a, BIO_FLAGS_WRITE)       ;}
	auto BIO_should_io_special(BIO* a) { return BIO_test_flags(a, BIO_FLAGS_IO_SPECIAL)  ;}
	auto BIO_retry_type(BIO* a)        { return BIO_test_flags(a, BIO_FLAGS_RWS)         ;}
	auto BIO_should_retry(BIO* a)      { return BIO_test_flags(a, BIO_FLAGS_SHOULD_RETRY);}
}

/* The next three are used in conjunction with the
 * BIO_should_io_special() condition.  After this returns true,
 * BIO *BIO_get_retry_BIO(BIO *bio, int *reason); will walk the BIO
 * stack and return the 'reason' for the special and the offending BIO.
 * Given a BIO, BIO_get_retry_reason(bio) will return the code. */
/* Returned from the SSL bio when the certificate retrieval code had an error */
enum BIO_RR_SSL_X509_LOOKUP = 0x01;
/* Returned from the connect BIO when a connect would have blocked */
enum BIO_RR_CONNECT = 0x02;
/* Returned from the accept BIO when an accept would have blocked */
enum BIO_RR_ACCEPT = 0x03;

/* These are passed by the BIO callback */
enum BIO_CB_FREE = 0x01;
enum BIO_CB_READ = 0x02;
enum BIO_CB_WRITE = 0x03;
enum BIO_CB_PUTS = 0x04;
enum BIO_CB_GETS = 0x05;
enum BIO_CB_CTRL = 0x06;

/* The callback is called before and after the underling operation,
 * The BIO_CB_RETURN flag indicates if it is after the call */
enum BIO_CB_RETURN = 0x80;

extern(D)
{
	auto BIO_CB_return(T)(T a) { return (a)|BIO_CB_RETURN   ; }
	auto BIO_cb_pre(T)(T a)    { return !((a)&BIO_CB_RETURN); }
	auto BIO_cb_post(T)(T a)   { return (a)&BIO_CB_RETURN   ; }
}

alias bio_st BIO;
alias bio_info_cb = void function(bio_st *, int, const(char)*, int, long, long);

alias bio_method_st BIO_METHOD;
alias bio_f_buffer_ctx_struct BIO_F_BUFFER_CTX;

/* Prefix and suffix callback in ASN1 BIO */
alias ans1_ps_func = int function(BIO *b, ubyte **pbuf, int *plen, void *parg);

/* connect BIO stuff */
enum BIO_CONN_S_BEFORE = 1;
enum BIO_CONN_S_GET_IP = 2;
enum BIO_CONN_S_GET_PORT = 3;
enum BIO_CONN_S_CREATE_SOCKET = 4;
enum BIO_CONN_S_CONNECT = 5;
enum BIO_CONN_S_OK = 6;
enum BIO_CONN_S_BLOCKED_CONNECT = 7;
enum BIO_CONN_S_NBIO = 8;
/*#define BIO_CONN_get_param_hostname	BIO_ctrl */

enum BIO_C_SET_CONNECT = 100;
enum BIO_C_DO_STATE_MACHINE = 101;
enum BIO_C_SET_NBIO = 102;
enum BIO_C_SET_PROXY_PARAM = 103;
enum BIO_C_SET_FD = 104;
enum BIO_C_GET_FD = 105;
enum BIO_C_SET_FILE_PTR = 106;
enum BIO_C_GET_FILE_PTR = 107;
enum BIO_C_SET_FILENAME = 108;
enum BIO_C_SET_SSL = 109;
enum BIO_C_GET_SSL = 110;
enum BIO_C_SET_MD = 111;
enum BIO_C_GET_MD = 112;
enum BIO_C_GET_CIPHER_STATUS = 113;
enum BIO_C_SET_BUF_MEM = 114;
enum BIO_C_GET_BUF_MEM_PTR = 115;
enum BIO_C_GET_BUFF_NUM_LINES = 116;
enum BIO_C_SET_BUFF_SIZE = 117;
enum BIO_C_SET_ACCEPT = 118;
enum BIO_C_SSL_MODE = 119;
enum BIO_C_GET_MD_CTX = 120;
enum BIO_C_GET_PROXY_PARAM = 121;
enum BIO_C_SET_BUFF_READ_DATA = 122; /* data to read first */
enum BIO_C_GET_CONNECT = 123;
enum BIO_C_GET_ACCEPT = 124;
enum BIO_C_SET_SSL_RENEGOTIATE_BYTES = 125;
enum BIO_C_GET_SSL_NUM_RENEGOTIATES = 126;
enum BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT = 127;
enum BIO_C_FILE_SEEK = 128;
enum BIO_C_GET_CIPHER_CTX = 129;
enum BIO_C_SET_BUF_MEM_EOF_RETURN = 130;/*return end of input value*/
enum BIO_C_SET_BIND_MODE = 131;
enum BIO_C_GET_BIND_MODE = 132;
enum BIO_C_FILE_TELL = 133;
enum BIO_C_GET_SOCKS = 134;
enum BIO_C_SET_SOCKS = 135;

enum BIO_C_SET_WRITE_BUF_SIZE = 136;/* for BIO_s_bio */
enum BIO_C_GET_WRITE_BUF_SIZE = 137;
enum BIO_C_MAKE_BIO_PAIR = 138;
enum BIO_C_DESTROY_BIO_PAIR = 139;
enum BIO_C_GET_WRITE_GUARANTEE = 140;
enum BIO_C_GET_READ_REQUEST = 141;
enum BIO_C_SHUTDOWN_WR = 142;
enum BIO_C_NREAD0 = 143;
enum BIO_C_NREAD = 144;
enum BIO_C_NWRITE0 = 145;
enum BIO_C_NWRITE = 146;
enum BIO_C_RESET_READ_REQUEST = 147;
enum BIO_C_SET_MD_CTX = 148;

enum BIO_C_SET_PREFIX = 149;
enum BIO_C_GET_PREFIX = 150;
enum BIO_C_SET_SUFFIX = 151;
enum BIO_C_GET_SUFFIX = 152;

enum BIO_C_SET_EX_ARG = 153;
enum BIO_C_GET_EX_ARG = 154;

struct bio_method_st
{
    int type;
    const(char)* name;
    int function (BIO*, const(char)*, int) bwrite;
    int function (BIO*, char*, int) bread;
    int function (BIO*, const(char)*) bputs;
    int function (BIO*, char*, int) bgets;
    c_long function (BIO*, int, c_long, void*) ctrl;
    int function (BIO*) create;
    int function (BIO*) destroy;
    c_long function (BIO*, int, void function (bio_st*, int, const(char)*, int, c_long, c_long)) callback_ctrl;
}

struct bio_st
{
    BIO_METHOD* method;
    c_long function (bio_st*, int, const(char)*, int, c_long, c_long) callback;
    char* cb_arg;
    int init;
    int shutdown;
    int flags;
    int retry_reason;
    int num;
    void* ptr;
    bio_st* next_bio;
    bio_st* prev_bio;
    int references;
    c_ulong num_read;
    c_ulong num_write;
    CRYPTO_EX_DATA ex_data;
}

/+
struct stack_st_BIO
{
    _STACK stack;
}
+/
struct stack_st_BIO;

struct bio_f_buffer_ctx_struct
{
    int ibuf_size;
    int obuf_size;
    char* ibuf;
    int ibuf_len;
    int ibuf_off;
    char* obuf;
    int obuf_len;
    int obuf_off;
}

struct hostent;


void BIO_set_flags (BIO* b, int flags);
int BIO_test_flags (const(BIO)* b, int flags);
void BIO_clear_flags (BIO* b, int flags);
c_long function (bio_st*, int, const(char)*, int, c_long, c_long) BIO_get_callback (bio_st*, int, const(char)*, int, c_long, c_long, const(BIO)* b);
void BIO_set_callback (BIO* b, c_long function (bio_st*, int, const(char)*, int, c_long, c_long) callback);
char* BIO_get_callback_arg (const(BIO)* b);
void BIO_set_callback_arg (BIO* b, char* arg);
const(char)* BIO_method_name (const(BIO)* b);
int BIO_method_type (const(BIO)* b);
size_t BIO_ctrl_pending (BIO* b);
size_t BIO_ctrl_wpending (BIO* b);
size_t BIO_ctrl_get_write_guarantee (BIO* b);
size_t BIO_ctrl_get_read_request (BIO* b);
int BIO_ctrl_reset_read_request (BIO* b);
int BIO_set_ex_data (BIO* bio, int idx, void* data);
void* BIO_get_ex_data (BIO* bio, int idx);
int BIO_get_ex_new_index (c_long argl, void* argp, int function (void*, void*, CRYPTO_EX_DATA*, int, c_long, void*) new_func, int function (CRYPTO_EX_DATA*, CRYPTO_EX_DATA*, void*, int, c_long, void*) dup_func, void function (void*, void*, CRYPTO_EX_DATA*, int, c_long, void*) free_func);
c_ulong BIO_number_read (BIO* bio);
c_ulong BIO_number_written (BIO* bio);
int BIO_asn1_set_prefix (BIO* b, int function (BIO*, ubyte**, int*, void*) prefix, int function (BIO*, ubyte**, int*, void*) prefix_free);
int BIO_asn1_get_prefix (BIO* b, int function (BIO*, ubyte**, int*, void*)* pprefix, int function (BIO*, ubyte**, int*, void*)* pprefix_free);
int BIO_asn1_set_suffix (BIO* b, int function (BIO*, ubyte**, int*, void*) suffix, int function (BIO*, ubyte**, int*, void*) suffix_free);
int BIO_asn1_get_suffix (BIO* b, int function (BIO*, ubyte**, int*, void*)* psuffix, int function (BIO*, ubyte**, int*, void*)* psuffix_free);
BIO_METHOD* BIO_s_file ();
BIO* BIO_new_file (const(char)* filename, const(char)* mode);
BIO* BIO_new_fp (FILE* stream, int close_flag);
BIO* BIO_new (BIO_METHOD* type);
int BIO_set (BIO* a, BIO_METHOD* type);
int BIO_free (BIO* a);
void BIO_vfree (BIO* a);
int BIO_read (BIO* b, void* data, int len);
int BIO_gets (BIO* bp, char* buf, int size);
int BIO_write (BIO* b, const(void)* data, int len);
int BIO_puts (BIO* bp, const(char)* buf);
int BIO_indent (BIO* b, int indent, int max);
c_long BIO_ctrl (BIO* bp, int cmd, c_long larg, void* parg);
c_long BIO_callback_ctrl (BIO* b, int cmd, void function (bio_st*, int, const(char)*, int, c_long, c_long) fp);
char* BIO_ptr_ctrl (BIO* bp, int cmd, c_long larg);
c_long BIO_int_ctrl (BIO* bp, int cmd, c_long larg, int iarg);
BIO* BIO_push (BIO* b, BIO* append);
BIO* BIO_pop (BIO* b);
void BIO_free_all (BIO* a);
BIO* BIO_find_type (BIO* b, int bio_type);
BIO* BIO_next (BIO* b);
BIO* BIO_get_retry_BIO (BIO* bio, int* reason);
int BIO_get_retry_reason (BIO* bio);
BIO* BIO_dup_chain (BIO* in_);
int BIO_nread0 (BIO* bio, char** buf);
int BIO_nread (BIO* bio, char** buf, int num);
int BIO_nwrite0 (BIO* bio, char** buf);
int BIO_nwrite (BIO* bio, char** buf, int num);
c_long BIO_debug_callback (BIO* bio, int cmd, const(char)* argp, int argi, c_long argl, c_long ret);
BIO_METHOD* BIO_s_mem ();
BIO* BIO_new_mem_buf (void* buf, int len);
BIO_METHOD* BIO_s_socket ();
BIO_METHOD* BIO_s_connect ();
BIO_METHOD* BIO_s_accept ();
BIO_METHOD* BIO_s_fd ();
BIO_METHOD* BIO_s_log ();
BIO_METHOD* BIO_s_bio ();
BIO_METHOD* BIO_s_null ();
BIO_METHOD* BIO_f_null ();
BIO_METHOD* BIO_f_buffer ();
BIO_METHOD* BIO_f_nbio_test ();
BIO_METHOD* BIO_s_datagram ();
int BIO_sock_should_retry (int i);
int BIO_sock_non_fatal_error (int _error);
int BIO_dgram_non_fatal_error (int _error);
int BIO_fd_should_retry (int i);
int BIO_fd_non_fatal_error (int _error);
int BIO_dump_cb (int function (const(void)*, size_t, void*) cb, void* u, const(char)* s, int len);
int BIO_dump_indent_cb (int function (const(void)*, size_t, void*) cb, void* u, const(char)* s, int len, int indent);
int BIO_dump (BIO* b, const(char)* bytes, int len);
int BIO_dump_indent (BIO* b, const(char)* bytes, int len, int indent);
int BIO_dump_fp (FILE* fp, const(char)* s, int len);
int BIO_dump_indent_fp (FILE* fp, const(char)* s, int len, int indent);
hostent* BIO_gethostbyname (const(char)* name);
int BIO_sock_error (int sock);
int BIO_socket_ioctl (int fd, c_long type, void* arg);
int BIO_socket_nbio (int fd, int mode);
int BIO_get_port (const(char)* str, ushort* port_ptr);
int BIO_get_host_ip (const(char)* str, ubyte* ip);
int BIO_get_accept_socket (char* host_port, int mode);
int BIO_accept (int sock, char** ip_port);
int BIO_sock_init ();
void BIO_sock_cleanup ();
int BIO_set_tcp_ndelay (int sock, int turn_on);
BIO* BIO_new_socket (int sock, int close_flag);
BIO* BIO_new_dgram (int fd, int close_flag);
BIO* BIO_new_fd (int fd, int close_flag);
BIO* BIO_new_connect (char* host_port);
BIO* BIO_new_accept (char* host_port);
int BIO_new_bio_pair (BIO** bio1, size_t writebuf1, BIO** bio2, size_t writebuf2);
void BIO_copy_next_retry (BIO* b);
int BIO_printf (BIO* bio, const(char)* format, ...);
int BIO_vprintf (BIO* bio, const(char)* format, va_list args);
int BIO_snprintf (char* buf, size_t n, const(char)* format, ...);
int BIO_vsnprintf (char* buf, size_t n, const(char)* format, va_list args);
void ERR_load_BIO_strings ();

/* Error codes for the BIO functions. */

/* Function codes. */
enum BIO_F_ACPT_STATE = 100;
enum BIO_F_BIO_ACCEPT = 101;
enum BIO_F_BIO_BER_GET_HEADER = 102;
enum BIO_F_BIO_CALLBACK_CTRL = 131;
enum BIO_F_BIO_CTRL = 103;
enum BIO_F_BIO_GETHOSTBYNAME = 120;
enum BIO_F_BIO_GETS = 104;
enum BIO_F_BIO_GET_ACCEPT_SOCKET = 105;
enum BIO_F_BIO_GET_HOST_IP = 106;
enum BIO_F_BIO_GET_PORT = 107;
enum BIO_F_BIO_MAKE_PAIR = 121;
enum BIO_F_BIO_NEW = 108;
enum BIO_F_BIO_NEW_FILE = 109;
enum BIO_F_BIO_NEW_MEM_BUF = 126;
enum BIO_F_BIO_NREAD = 123;
enum BIO_F_BIO_NREAD0 = 124;
enum BIO_F_BIO_NWRITE = 125;
enum BIO_F_BIO_NWRITE0 = 122;
enum BIO_F_BIO_PUTS = 110;
enum BIO_F_BIO_READ = 111;
enum BIO_F_BIO_SOCK_INIT = 112;
enum BIO_F_BIO_WRITE = 113;
enum BIO_F_BUFFER_CTRL = 114;
enum BIO_F_CONN_CTRL = 127;
enum BIO_F_CONN_STATE = 115;
enum BIO_F_DGRAM_SCTP_READ = 132;
enum BIO_F_FILE_CTRL = 116;
enum BIO_F_FILE_READ = 130;
enum BIO_F_LINEBUFFER_CTRL = 129;
enum BIO_F_MEM_READ = 128;
enum BIO_F_MEM_WRITE = 117;
enum BIO_F_SSL_NEW = 118;
enum BIO_F_WSASTARTUP = 119;

/* Reason codes. */
enum BIO_R_ACCEPT_ERROR = 100;
enum BIO_R_BAD_FOPEN_MODE = 101;
enum BIO_R_BAD_HOSTNAME_LOOKUP = 102;
enum BIO_R_BROKEN_PIPE = 124;
enum BIO_R_CONNECT_ERROR = 103;
enum BIO_R_EOF_ON_MEMORY_BIO = 127;
enum BIO_R_ERROR_SETTING_NBIO = 104;
enum BIO_R_ERROR_SETTING_NBIO_ON_ACCEPTED_SOCKET = 105;
enum BIO_R_ERROR_SETTING_NBIO_ON_ACCEPT_SOCKET = 106;
enum BIO_R_GETHOSTBYNAME_ADDR_IS_NOT_AF_INET = 107;
enum BIO_R_INVALID_ARGUMENT = 125;
enum BIO_R_INVALID_IP_ADDRESS = 108;
enum BIO_R_INVALID_PORT_NUMBER = 129;
enum BIO_R_IN_USE = 123;
enum BIO_R_KEEPALIVE = 109;
enum BIO_R_NBIO_CONNECT_ERROR = 110;
enum BIO_R_NO_ACCEPT_PORT_SPECIFIED = 111;
enum BIO_R_NO_HOSTNAME_SPECIFIED = 112;
enum BIO_R_NO_PORT_DEFINED = 113;
enum BIO_R_NO_PORT_SPECIFIED = 114;
enum BIO_R_NO_SUCH_FILE = 128;
enum BIO_R_NULL_PARAMETER = 115;
enum BIO_R_TAG_MISMATCH = 116;
enum BIO_R_UNABLE_TO_BIND_SOCKET = 117;
enum BIO_R_UNABLE_TO_CREATE_SOCKET = 118;
enum BIO_R_UNABLE_TO_LISTEN_SOCKET = 119;
enum BIO_R_UNINITIALIZED = 120;
enum BIO_R_UNSUPPORTED_METHOD = 121;
enum BIO_R_WRITE_TO_READ_ONLY_BIO = 126;
enum BIO_R_WSASTARTUP = 122;
