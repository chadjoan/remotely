module c.openssl.asn1;

import core.stdc.time;
import core.stdc.stdio;
import core.stdc.config;

//public import c.openssl.opensslconf;

public import c.openssl.bio;
//public import c.openssl.stack;
//public import c.openssl.safestack;

public import c.openssl.ossl_typ;
//public import c.openssl.bn;

extern(D)
{
/* Macro to obtain ASN1_ITEM pointer from exported type */
auto ASN1_ITEM_ptr(T)(T iptr) { return iptr; }

/* Macro to include ASN1_ITEM pointer from base type */
/+
#define ASN1_ITEM_ref(iptr) (&(iptr##_it))

#define ASN1_ITEM_rptr(ref) (&(ref##_it))
+/
}

extern (C):

enum V_ASN1_UNIVERSAL = 0x00;
enum V_ASN1_APPLICATION = 0x40;
enum V_ASN1_CONTEXT_SPECIFIC = 0x80;
enum V_ASN1_PRIVATE = 0xc0;

enum V_ASN1_CONSTRUCTED = 0x20;
enum V_ASN1_PRIMITIVE_TAG = 0x1f;
enum V_ASN1_PRIMATIVE_TAG = 0x1f;

enum V_ASN1_APP_CHOOSE = -2;	/* let the recipient choose */
enum V_ASN1_OTHER = -3;	/* used in ASN1_TYPE */
enum V_ASN1_ANY = -4;	/* used in ASN1 template code */

enum V_ASN1_NEG = 0x100;	/* negative flag */

enum V_ASN1_UNDEF = -1;
enum V_ASN1_EOC = 0;
enum V_ASN1_BOOLEAN = 1;	/**/
enum V_ASN1_INTEGER = 2;
enum V_ASN1_NEG_INTEGER = (2 | V_ASN1_NEG);
enum V_ASN1_BIT_STRING = 3;
enum V_ASN1_OCTET_STRING = 4;
enum V_ASN1_NULL = 5;
enum V_ASN1_OBJECT = 6;
enum V_ASN1_OBJECT_DESCRIPTOR = 7;
enum V_ASN1_EXTERNAL = 8;
enum V_ASN1_REAL = 9;
enum V_ASN1_ENUMERATED = 10;
enum V_ASN1_NEG_ENUMERATED = (10 | V_ASN1_NEG);
enum V_ASN1_UTF8STRING = 12;
enum V_ASN1_SEQUENCE = 16;
enum V_ASN1_SET = 17;
enum V_ASN1_NUMERICSTRING = 18;	/**/
enum V_ASN1_PRINTABLESTRING = 19;
enum V_ASN1_T61STRING = 20;
enum V_ASN1_TELETEXSTRING = 20;	/* alias */
enum V_ASN1_VIDEOTEXSTRING = 21;	/**/
enum V_ASN1_IA5STRING = 22;
enum V_ASN1_UTCTIME = 23;
enum V_ASN1_GENERALIZEDTIME = 24;	/**/
enum V_ASN1_GRAPHICSTRING = 25;	/**/
enum V_ASN1_ISO64STRING = 26;	/**/
enum V_ASN1_VISIBLESTRING = 26;	/* alias */
enum V_ASN1_GENERALSTRING = 27;	/**/
enum V_ASN1_UNIVERSALSTRING = 28;	/**/
enum V_ASN1_BMPSTRING = 30;

/* For use with d2i_ASN1_type_bytes() */
enum B_ASN1_NUMERICSTRING = 0x0001;
enum B_ASN1_PRINTABLESTRING = 0x0002;
enum B_ASN1_T61STRING = 0x0004;
enum B_ASN1_TELETEXSTRING = 0x0004;
enum B_ASN1_VIDEOTEXSTRING = 0x0008;
enum B_ASN1_IA5STRING = 0x0010;
enum B_ASN1_GRAPHICSTRING = 0x0020;
enum B_ASN1_ISO64STRING = 0x0040;
enum B_ASN1_VISIBLESTRING = 0x0040;
enum B_ASN1_GENERALSTRING = 0x0080;
enum B_ASN1_UNIVERSALSTRING = 0x0100;
enum B_ASN1_OCTET_STRING = 0x0200;
enum B_ASN1_BIT_STRING = 0x0400;
enum B_ASN1_BMPSTRING = 0x0800;
enum B_ASN1_UNKNOWN = 0x1000;
enum B_ASN1_UTF8STRING = 0x2000;
enum B_ASN1_UTCTIME = 0x4000;
enum B_ASN1_GENERALIZEDTIME = 0x8000;
enum B_ASN1_SEQUENCE = 0x10000;

/* For use with ASN1_mbstring_copy() */
enum MBSTRING_FLAG = 0x1000;
enum MBSTRING_UTF8 = (MBSTRING_FLAG);
enum MBSTRING_ASC = (MBSTRING_FLAG|1);
enum MBSTRING_BMP = (MBSTRING_FLAG|2);
enum MBSTRING_UNIV = (MBSTRING_FLAG|4);

enum SMIME_OLDMIME = 0x400;
enum SMIME_CRLFEOL = 0x800;
enum SMIME_STREAM = 0x1000;

/* These are used internally in the ASN1_OBJECT to keep track of
 * whether the names and data need to be free()ed */
enum ASN1_OBJECT_FLAG_DYNAMIC = 0x01;	/* internal use */
enum ASN1_OBJECT_FLAG_CRITICAL = 0x02;	/* critical x509v3 object id */
enum ASN1_OBJECT_FLAG_DYNAMIC_STRINGS = 0x04;	/* internal use */
enum ASN1_OBJECT_FLAG_DYNAMIC_DATA = 0x08;	/* internal use */

enum ASN1_STRING_FLAG_BITS_LEFT = 0x08; /* Set if 0x07 has bits left value */
/* This indicates that the ASN1_STRING is not a real value but just a place
 * holder for the location where indefinite length constructed data should
 * be inserted in the memory buffer
 */
enum ASN1_STRING_FLAG_NDEF = 0x010;

/* This flag is used by the CMS code to indicate that a string is not
 * complete and is a place holder for content when it had all been
 * accessed. The flag will be reset when content has been written to it.
 */

enum ASN1_STRING_FLAG_CONT = 0x020;
/* This flag is used by ASN1 code to indicate an ASN1_STRING is an MSTRING
 * type.
 */
enum ASN1_STRING_FLAG_MSTRING = 0x040;

/* Used with ASN1 LONG type: if a long is set to this it is omitted */
enum ASN1_LONG_UNDEF = 0x7fffffffL;

enum STABLE_FLAGS_MALLOC = 0x01;
enum STABLE_NO_MASK = 0x02;
enum DIRSTRING_TYPE = (B_ASN1_PRINTABLESTRING|B_ASN1_T61STRING|B_ASN1_BMPSTRING|B_ASN1_UTF8STRING);
enum PKCS9STRING_TYPE = (DIRSTRING_TYPE|B_ASN1_IA5STRING);

/* size limits: this stuff is taken straight from RFC2459 */

enum ub_name = 32768;
enum ub_common_name = 64;
enum ub_locality_name = 128;
enum ub_state_name = 128;
enum ub_organization_name = 64;
enum ub_organization_unit_name = 64;
enum ub_title = 64;
enum ub_email_address = 128;

/* Parameters used by ASN1_STRING_print_ex() */

/* These determine which characters to escape:
 * RFC2253 special characters, control characters and
 * MSB set characters
 */

enum ASN1_STRFLGS_ESC_2253 = 1;
enum ASN1_STRFLGS_ESC_CTRL = 2;
enum ASN1_STRFLGS_ESC_MSB = 4;


/* This flag determines how we do escaping: normally
 * RC2253 backslash only, set this to use backslash and
 * quote.
 */

enum ASN1_STRFLGS_ESC_QUOTE = 8;


/* These three flags are internal use only. */

/* Character is a valid PrintableString character */
enum CHARTYPE_PRINTABLESTRING = 0x10;
/* Character needs escaping if it is the first character */
enum CHARTYPE_FIRST_ESC_2253 = 0x20;
/* Character needs escaping if it is the last character */
enum CHARTYPE_LAST_ESC_2253 = 0x40;

/* NB the internal flags are safely reused below by flags
 * handled at the top level.
 */

/* If this is set we convert all character strings
 * to UTF8 first
 */

enum ASN1_STRFLGS_UTF8_CONVERT = 0x10;

/* If this is set we don't attempt to interpret content:
 * just assume all strings are 1 byte per character. This
 * will produce some pretty odd looking output!
 */

enum ASN1_STRFLGS_IGNORE_TYPE = 0x20;

/* If this is set we include the string type in the output */
enum ASN1_STRFLGS_SHOW_TYPE = 0x40;

/* This determines which strings to display and which to
 * 'dump' (hex dump of content octets or DER encoding). We can
 * only dump non character strings or everything. If we
 * don't dump 'unknown' they are interpreted as character
 * strings with 1 octet per character and are subject to
 * the usual escaping options.
 */

enum ASN1_STRFLGS_DUMP_ALL = 0x80;
enum ASN1_STRFLGS_DUMP_UNKNOWN = 0x100;

/* These determine what 'dumping' does, we can dump the
 * content octets or the DER encoding: both use the
 * RFC2253 #NNNNN notation.
 */

enum ASN1_STRFLGS_DUMP_DER = 0x200;

/* All the string flags consistent with RFC2253,
 * escaping control characters isn't essential in
 * RFC2253 but it is advisable anyway.
 */

enum ASN1_STRFLGS_RFC2253 = (ASN1_STRFLGS_ESC_2253 |
				ASN1_STRFLGS_ESC_CTRL |
				ASN1_STRFLGS_ESC_MSB |
				ASN1_STRFLGS_UTF8_CONVERT |
				ASN1_STRFLGS_DUMP_UNKNOWN |
				ASN1_STRFLGS_DUMP_DER);


/* ASN1 Print flags */

/* Indicate missing OPTIONAL fields */
enum ASN1_PCTX_FLAGS_SHOW_ABSENT = 0x001;
/* Mark start and end of SEQUENCE */
enum ASN1_PCTX_FLAGS_SHOW_SEQUENCE = 0x002;
/* Mark start and end of SEQUENCE/SET OF */
enum ASN1_PCTX_FLAGS_SHOW_SSOF = 0x004;
/* Show the ASN1 type of primitives */
enum ASN1_PCTX_FLAGS_SHOW_TYPE = 0x008;
/* Don't show ASN1 type of ANY */
enum ASN1_PCTX_FLAGS_NO_ANY_TYPE = 0x010;
/* Don't show ASN1 type of MSTRINGs */
enum ASN1_PCTX_FLAGS_NO_MSTRING_TYPE = 0x020;
/* Don't show field names in SEQUENCE */
enum ASN1_PCTX_FLAGS_NO_FIELD_NAME = 0x040;
/* Show structure names of each SEQUENCE field */
enum ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME = 0x080;
/* Don't show structure name even at top level */
enum ASN1_PCTX_FLAGS_NO_STRUCT_NAME = 0x100;

alias asn1_ctx_st ASN1_CTX;
alias asn1_const_ctx_st ASN1_const_CTX;
alias asn1_object_st ASN1_OBJECT;
alias ASN1_ENCODING_st ASN1_ENCODING;
alias asn1_string_table_st ASN1_STRING_TABLE;
alias ASN1_TEMPLATE_st ASN1_TEMPLATE;
alias ASN1_TLC_st ASN1_TLC;
alias ASN1_VALUE_st ASN1_VALUE;
alias const ASN1_ITEM_st ASN1_ITEM_EXP;
alias asn1_type_st ASN1_TYPE;
alias stack_st_ASN1_TYPE ASN1_SEQUENCE_ANY;
alias NETSCAPE_X509_st NETSCAPE_X509;
alias BIT_STRING_BITNAME_st BIT_STRING_BITNAME;

/+
// Need to port asn1t.h to make these work.  Not worth it right now.
extern __gshared const ASN1_ITEM ASN1_SEQUENCE_ANY_it;
extern __gshared const ASN1_ITEM ASN1_SET_ANY_it;
extern __gshared const ASN1_ITEM ASN1_ANY_it;
extern __gshared const ASN1_ITEM ASN1_OBJECT_it;
extern __gshared const ASN1_ITEM ASN1_BIT_STRING_it;
extern __gshared const ASN1_ITEM ASN1_INTEGER_it;
extern __gshared const ASN1_ITEM ASN1_ENUMERATED_it;
extern __gshared const ASN1_ITEM ASN1_OCTET_STRING_it;
extern __gshared const ASN1_ITEM ASN1_VISIBLESTRING_it;
extern __gshared const ASN1_ITEM ASN1_UNIVERSALSTRING_it;
extern __gshared const ASN1_ITEM ASN1_UTF8STRING_it;
extern __gshared const ASN1_ITEM ASN1_NULL_it;
extern __gshared const ASN1_ITEM ASN1_BMPSTRING_it;
extern __gshared const ASN1_ITEM ASN1_PRINTABLE_it;
extern __gshared const ASN1_ITEM DIRECTORYSTRING_it;
extern __gshared const ASN1_ITEM DISPLAYTEXT_it;
extern __gshared const ASN1_ITEM ASN1_PRINTABLESTRING_it;
extern __gshared const ASN1_ITEM ASN1_T61STRING_it;
extern __gshared const ASN1_ITEM ASN1_IA5STRING_it;
extern __gshared const ASN1_ITEM ASN1_GENERALSTRING_it;
extern __gshared const ASN1_ITEM ASN1_UTCTIME_it;
extern __gshared const ASN1_ITEM ASN1_GENERALIZEDTIME_it;
extern __gshared const ASN1_ITEM ASN1_TIME_it;
extern __gshared const ASN1_ITEM ASN1_OCTET_STRING_NDEF_it;
extern __gshared const ASN1_ITEM NETSCAPE_X509_it;
+/

/+
struct stack_st_X509_ALGOR
{
    _STACK stack;
}
+/
struct stack_st_X509_ALGOR;

struct asn1_ctx_st
{
    ubyte* p;
    int eos;
    int error;
    int inf;
    int tag;
    int xclass;
    c_long slen;
    ubyte* max;
    ubyte* q;
    ubyte** pp;
    int line;
}

struct asn1_const_ctx_st
{
    const(ubyte)* p;
    int eos;
    int error;
    int inf;
    int tag;
    int xclass;
    c_long slen;
    const(ubyte)* max;
    const(ubyte)* q;
    const(ubyte*)* pp;
    int line;
}

struct asn1_object_st
{
    const(char)* sn;
    const(char)* ln;
    int nid;
    int length;
    const(ubyte)* data;
    int flags;
}

struct asn1_string_st
{
    int length;
    int type;
    ubyte* data;
    c_long flags;
}

struct ASN1_ENCODING_st
{
    ubyte* enc;
    c_long len;
    int modified;
}

struct asn1_string_table_st
{
    int nid;
    c_long minsize;
    c_long maxsize;
    c_ulong mask;
    c_ulong flags;
}

struct stack_st_ASN1_STRING_TABLE;
struct stack_st_ASN1_INTEGER;
struct stack_st_ASN1_GENERALSTRING;
/+
struct stack_st_ASN1_STRING_TABLE
{
    _STACK stack;
}

struct stack_st_ASN1_INTEGER
{
    _STACK stack;
}

struct stack_st_ASN1_GENERALSTRING
{
    _STACK stack;
}
+/

struct asn1_type_st
{
    int type;
    union
    {
        char* ptr;
        ASN1_BOOLEAN boolean;
        ASN1_STRING* asn1_string;
        ASN1_OBJECT* object;
        ASN1_INTEGER* integer;
        ASN1_ENUMERATED* enumerated;
        ASN1_BIT_STRING* bit_string;
        ASN1_OCTET_STRING* octet_string;
        ASN1_PRINTABLESTRING* printablestring;
        ASN1_T61STRING* t61string;
        ASN1_IA5STRING* ia5string;
        ASN1_GENERALSTRING* generalstring;
        ASN1_BMPSTRING* bmpstring;
        ASN1_UNIVERSALSTRING* universalstring;
        ASN1_UTCTIME* utctime;
        ASN1_GENERALIZEDTIME* generalizedtime;
        ASN1_VISIBLESTRING* visiblestring;
        ASN1_UTF8STRING* utf8string;
        ASN1_STRING* set;
        ASN1_STRING* sequence;
        ASN1_VALUE* asn1_value;
    }
}

struct stack_st_ASN1_TYPE;
/+
struct stack_st_ASN1_TYPE
{
    _STACK stack;
}
+/

struct NETSCAPE_X509_st
{
    ASN1_OCTET_STRING* header;
    X509* cert;
}

struct BIT_STRING_BITNAME_st
{
    int bitnum;
    const(char)* lname;
    const(char)* sname;
}

struct stack_st_ASN1_OBJECT;
/+
struct stack_st_ASN1_OBJECT
{
    _STACK stack;
}
+/

struct ASN1_TLC_st;


struct ASN1_VALUE_st;


struct ASN1_TEMPLATE_st;


struct X509_algor_st;


ASN1_SEQUENCE_ANY* d2i_ASN1_SEQUENCE_ANY (ASN1_SEQUENCE_ANY** a, const(ubyte*)* in_, c_long len);
int i2d_ASN1_SEQUENCE_ANY (const(ASN1_SEQUENCE_ANY)* a, ubyte** out_);
ASN1_SEQUENCE_ANY* d2i_ASN1_SET_ANY (ASN1_SEQUENCE_ANY** a, const(ubyte*)* in_, c_long len);
int i2d_ASN1_SET_ANY (const(ASN1_SEQUENCE_ANY)* a, ubyte** out_);
ASN1_TYPE* ASN1_TYPE_new ();
void ASN1_TYPE_free (ASN1_TYPE* a);
ASN1_TYPE* d2i_ASN1_TYPE (ASN1_TYPE** a, const(ubyte*)* in_, c_long len);
int i2d_ASN1_TYPE (ASN1_TYPE* a, ubyte** out_);
int ASN1_TYPE_get (ASN1_TYPE* a);
void ASN1_TYPE_set (ASN1_TYPE* a, int type, void* value);
int ASN1_TYPE_set1 (ASN1_TYPE* a, int type, const(void)* value);
int ASN1_TYPE_cmp (ASN1_TYPE* a, ASN1_TYPE* b);
ASN1_OBJECT* ASN1_OBJECT_new ();
void ASN1_OBJECT_free (ASN1_OBJECT* a);
int i2d_ASN1_OBJECT (ASN1_OBJECT* a, ubyte** pp);
ASN1_OBJECT* c2i_ASN1_OBJECT (ASN1_OBJECT** a, const(ubyte*)* pp, c_long length);
ASN1_OBJECT* d2i_ASN1_OBJECT (ASN1_OBJECT** a, const(ubyte*)* pp, c_long length);
ASN1_STRING* ASN1_STRING_new ();
void ASN1_STRING_free (ASN1_STRING* a);
int ASN1_STRING_copy (ASN1_STRING* dst, const(ASN1_STRING)* str);
ASN1_STRING* ASN1_STRING_dup (const(ASN1_STRING)* a);
ASN1_STRING* ASN1_STRING_type_new (int type);
int ASN1_STRING_cmp (const(ASN1_STRING)* a, const(ASN1_STRING)* b);
int ASN1_STRING_set (ASN1_STRING* str, const(void)* data, int len);
void ASN1_STRING_set0 (ASN1_STRING* str, void* data, int len);
int ASN1_STRING_length (const(ASN1_STRING)* x);
void ASN1_STRING_length_set (ASN1_STRING* x, int n);
int ASN1_STRING_type (ASN1_STRING* x);
ubyte* ASN1_STRING_data (ASN1_STRING* x);
ASN1_BIT_STRING* ASN1_BIT_STRING_new ();
void ASN1_BIT_STRING_free (ASN1_BIT_STRING* a);
ASN1_BIT_STRING* d2i_ASN1_BIT_STRING (ASN1_BIT_STRING** a, const(ubyte*)* in_, c_long len);
int i2d_ASN1_BIT_STRING (ASN1_BIT_STRING* a, ubyte** out_);
int i2c_ASN1_BIT_STRING (ASN1_BIT_STRING* a, ubyte** pp);
ASN1_BIT_STRING* c2i_ASN1_BIT_STRING (ASN1_BIT_STRING** a, const(ubyte*)* pp, c_long length);
int ASN1_BIT_STRING_set (ASN1_BIT_STRING* a, ubyte* d, int length);
int ASN1_BIT_STRING_set_bit (ASN1_BIT_STRING* a, int n, int value);
int ASN1_BIT_STRING_get_bit (ASN1_BIT_STRING* a, int n);
int ASN1_BIT_STRING_check (ASN1_BIT_STRING* a, ubyte* flags, int flags_len);
int ASN1_BIT_STRING_name_print (BIO* out_, ASN1_BIT_STRING* bs, BIT_STRING_BITNAME* tbl, int indent);
int ASN1_BIT_STRING_num_asc (char* name, BIT_STRING_BITNAME* tbl);
int ASN1_BIT_STRING_set_asc (ASN1_BIT_STRING* bs, char* name, int value, BIT_STRING_BITNAME* tbl);
int i2d_ASN1_BOOLEAN (int a, ubyte** pp);
int d2i_ASN1_BOOLEAN (int* a, const(ubyte*)* pp, c_long length);
ASN1_INTEGER* ASN1_INTEGER_new ();
void ASN1_INTEGER_free (ASN1_INTEGER* a);
ASN1_INTEGER* d2i_ASN1_INTEGER (ASN1_INTEGER** a, const(ubyte*)* in_, c_long len);
int i2d_ASN1_INTEGER (ASN1_INTEGER* a, ubyte** out_);
int i2c_ASN1_INTEGER (ASN1_INTEGER* a, ubyte** pp);
ASN1_INTEGER* c2i_ASN1_INTEGER (ASN1_INTEGER** a, const(ubyte*)* pp, c_long length);
ASN1_INTEGER* d2i_ASN1_UINTEGER (ASN1_INTEGER** a, const(ubyte*)* pp, c_long length);
ASN1_INTEGER* ASN1_INTEGER_dup (const(ASN1_INTEGER)* x);
int ASN1_INTEGER_cmp (const(ASN1_INTEGER)* x, const(ASN1_INTEGER)* y);
ASN1_ENUMERATED* ASN1_ENUMERATED_new ();
void ASN1_ENUMERATED_free (ASN1_ENUMERATED* a);
ASN1_ENUMERATED* d2i_ASN1_ENUMERATED (ASN1_ENUMERATED** a, const(ubyte*)* in_, c_long len);
int i2d_ASN1_ENUMERATED (ASN1_ENUMERATED* a, ubyte** out_);
int ASN1_UTCTIME_check (ASN1_UTCTIME* a);
ASN1_UTCTIME* ASN1_UTCTIME_set (ASN1_UTCTIME* s, time_t t);
ASN1_UTCTIME* ASN1_UTCTIME_adj (ASN1_UTCTIME* s, time_t t, int offset_day, c_long offset_sec);
int ASN1_UTCTIME_set_string (ASN1_UTCTIME* s, const(char)* str);
int ASN1_UTCTIME_cmp_time_t (const(ASN1_UTCTIME)* s, time_t t);
int ASN1_GENERALIZEDTIME_check (ASN1_GENERALIZEDTIME* a);
ASN1_GENERALIZEDTIME* ASN1_GENERALIZEDTIME_set (ASN1_GENERALIZEDTIME* s, time_t t);
ASN1_GENERALIZEDTIME* ASN1_GENERALIZEDTIME_adj (ASN1_GENERALIZEDTIME* s, time_t t, int offset_day, c_long offset_sec);
int ASN1_GENERALIZEDTIME_set_string (ASN1_GENERALIZEDTIME* s, const(char)* str);
ASN1_OCTET_STRING* ASN1_OCTET_STRING_new ();
void ASN1_OCTET_STRING_free (ASN1_OCTET_STRING* a);
ASN1_OCTET_STRING* d2i_ASN1_OCTET_STRING (ASN1_OCTET_STRING** a, const(ubyte*)* in_, c_long len);
int i2d_ASN1_OCTET_STRING (ASN1_OCTET_STRING* a, ubyte** out_);
ASN1_OCTET_STRING* ASN1_OCTET_STRING_dup (const(ASN1_OCTET_STRING)* a);
int ASN1_OCTET_STRING_cmp (const(ASN1_OCTET_STRING)* a, const(ASN1_OCTET_STRING)* b);
int ASN1_OCTET_STRING_set (ASN1_OCTET_STRING* str, const(ubyte)* data, int len);
ASN1_VISIBLESTRING* ASN1_VISIBLESTRING_new ();
void ASN1_VISIBLESTRING_free (ASN1_VISIBLESTRING* a);
ASN1_VISIBLESTRING* d2i_ASN1_VISIBLESTRING (ASN1_VISIBLESTRING** a, const(ubyte*)* in_, c_long len);
int i2d_ASN1_VISIBLESTRING (ASN1_VISIBLESTRING* a, ubyte** out_);
ASN1_UNIVERSALSTRING* ASN1_UNIVERSALSTRING_new ();
void ASN1_UNIVERSALSTRING_free (ASN1_UNIVERSALSTRING* a);
ASN1_UNIVERSALSTRING* d2i_ASN1_UNIVERSALSTRING (ASN1_UNIVERSALSTRING** a, const(ubyte*)* in_, c_long len);
int i2d_ASN1_UNIVERSALSTRING (ASN1_UNIVERSALSTRING* a, ubyte** out_);
ASN1_UTF8STRING* ASN1_UTF8STRING_new ();
void ASN1_UTF8STRING_free (ASN1_UTF8STRING* a);
ASN1_UTF8STRING* d2i_ASN1_UTF8STRING (ASN1_UTF8STRING** a, const(ubyte*)* in_, c_long len);
int i2d_ASN1_UTF8STRING (ASN1_UTF8STRING* a, ubyte** out_);
ASN1_NULL* ASN1_NULL_new ();
void ASN1_NULL_free (ASN1_NULL* a);
ASN1_NULL* d2i_ASN1_NULL (ASN1_NULL** a, const(ubyte*)* in_, c_long len);
int i2d_ASN1_NULL (ASN1_NULL* a, ubyte** out_);
ASN1_BMPSTRING* ASN1_BMPSTRING_new ();
void ASN1_BMPSTRING_free (ASN1_BMPSTRING* a);
ASN1_BMPSTRING* d2i_ASN1_BMPSTRING (ASN1_BMPSTRING** a, const(ubyte*)* in_, c_long len);
int i2d_ASN1_BMPSTRING (ASN1_BMPSTRING* a, ubyte** out_);
ASN1_STRING* ASN1_PRINTABLE_new ();
void ASN1_PRINTABLE_free (ASN1_STRING* a);
ASN1_STRING* d2i_ASN1_PRINTABLE (ASN1_STRING** a, const(ubyte*)* in_, c_long len);
int i2d_ASN1_PRINTABLE (ASN1_STRING* a, ubyte** out_);
ASN1_STRING* DIRECTORYSTRING_new ();
void DIRECTORYSTRING_free (ASN1_STRING* a);
ASN1_STRING* d2i_DIRECTORYSTRING (ASN1_STRING** a, const(ubyte*)* in_, c_long len);
int i2d_DIRECTORYSTRING (ASN1_STRING* a, ubyte** out_);
ASN1_STRING* DISPLAYTEXT_new ();
void DISPLAYTEXT_free (ASN1_STRING* a);
ASN1_STRING* d2i_DISPLAYTEXT (ASN1_STRING** a, const(ubyte*)* in_, c_long len);
int i2d_DISPLAYTEXT (ASN1_STRING* a, ubyte** out_);
ASN1_PRINTABLESTRING* ASN1_PRINTABLESTRING_new ();
void ASN1_PRINTABLESTRING_free (ASN1_PRINTABLESTRING* a);
ASN1_PRINTABLESTRING* d2i_ASN1_PRINTABLESTRING (ASN1_PRINTABLESTRING** a, const(ubyte*)* in_, c_long len);
int i2d_ASN1_PRINTABLESTRING (ASN1_PRINTABLESTRING* a, ubyte** out_);
ASN1_T61STRING* ASN1_T61STRING_new ();
void ASN1_T61STRING_free (ASN1_T61STRING* a);
ASN1_T61STRING* d2i_ASN1_T61STRING (ASN1_T61STRING** a, const(ubyte*)* in_, c_long len);
int i2d_ASN1_T61STRING (ASN1_T61STRING* a, ubyte** out_);
ASN1_IA5STRING* ASN1_IA5STRING_new ();
void ASN1_IA5STRING_free (ASN1_IA5STRING* a);
ASN1_IA5STRING* d2i_ASN1_IA5STRING (ASN1_IA5STRING** a, const(ubyte*)* in_, c_long len);
int i2d_ASN1_IA5STRING (ASN1_IA5STRING* a, ubyte** out_);
ASN1_GENERALSTRING* ASN1_GENERALSTRING_new ();
void ASN1_GENERALSTRING_free (ASN1_GENERALSTRING* a);
ASN1_GENERALSTRING* d2i_ASN1_GENERALSTRING (ASN1_GENERALSTRING** a, const(ubyte*)* in_, c_long len);
int i2d_ASN1_GENERALSTRING (ASN1_GENERALSTRING* a, ubyte** out_);
ASN1_UTCTIME* ASN1_UTCTIME_new ();
void ASN1_UTCTIME_free (ASN1_UTCTIME* a);
ASN1_UTCTIME* d2i_ASN1_UTCTIME (ASN1_UTCTIME** a, const(ubyte*)* in_, c_long len);
int i2d_ASN1_UTCTIME (ASN1_UTCTIME* a, ubyte** out_);
ASN1_GENERALIZEDTIME* ASN1_GENERALIZEDTIME_new ();
void ASN1_GENERALIZEDTIME_free (ASN1_GENERALIZEDTIME* a);
ASN1_GENERALIZEDTIME* d2i_ASN1_GENERALIZEDTIME (ASN1_GENERALIZEDTIME** a, const(ubyte*)* in_, c_long len);
int i2d_ASN1_GENERALIZEDTIME (ASN1_GENERALIZEDTIME* a, ubyte** out_);
ASN1_TIME* ASN1_TIME_new ();
void ASN1_TIME_free (ASN1_TIME* a);
ASN1_TIME* d2i_ASN1_TIME (ASN1_TIME** a, const(ubyte*)* in_, c_long len);
int i2d_ASN1_TIME (ASN1_TIME* a, ubyte** out_);
ASN1_TIME* ASN1_TIME_set (ASN1_TIME* s, time_t t);
ASN1_TIME* ASN1_TIME_adj (ASN1_TIME* s, time_t t, int offset_day, c_long offset_sec);
int ASN1_TIME_check (ASN1_TIME* t);
ASN1_GENERALIZEDTIME* ASN1_TIME_to_generalizedtime (ASN1_TIME* t, ASN1_GENERALIZEDTIME** out_);
int ASN1_TIME_set_string (ASN1_TIME* s, const(char)* str);
//int i2d_ASN1_SET (stack_st_OPENSSL_BLOCK* a, ubyte** pp, int function (void*, ubyte**) i2d, int ex_tag, int ex_class, int is_set);
//stack_st_OPENSSL_BLOCK* d2i_ASN1_SET (stack_st_OPENSSL_BLOCK** a, const(ubyte*)* pp, c_long length, void* function (void**, const(ubyte*)*, c_long) d2i, void function (OPENSSL_BLOCK) free_func, int ex_tag, int ex_class);
int i2a_ASN1_INTEGER (BIO* bp, ASN1_INTEGER* a);
int a2i_ASN1_INTEGER (BIO* bp, ASN1_INTEGER* bs, char* buf, int size);
int i2a_ASN1_ENUMERATED (BIO* bp, ASN1_ENUMERATED* a);
int a2i_ASN1_ENUMERATED (BIO* bp, ASN1_ENUMERATED* bs, char* buf, int size);
int i2a_ASN1_OBJECT (BIO* bp, ASN1_OBJECT* a);
int a2i_ASN1_STRING (BIO* bp, ASN1_STRING* bs, char* buf, int size);
int i2a_ASN1_STRING (BIO* bp, ASN1_STRING* a, int type);
int i2t_ASN1_OBJECT (char* buf, int buf_len, ASN1_OBJECT* a);
int a2d_ASN1_OBJECT (ubyte* out_, int olen, const(char)* buf, int num);
ASN1_OBJECT* ASN1_OBJECT_create (int nid, ubyte* data, int len, const(char)* sn, const(char)* ln);
int ASN1_INTEGER_set (ASN1_INTEGER* a, c_long v);
c_long ASN1_INTEGER_get (const(ASN1_INTEGER)* a);
ASN1_INTEGER* BN_to_ASN1_INTEGER (const(BIGNUM)* bn, ASN1_INTEGER* ai);
BIGNUM* ASN1_INTEGER_to_BN (const(ASN1_INTEGER)* ai, BIGNUM* bn);
int ASN1_ENUMERATED_set (ASN1_ENUMERATED* a, c_long v);
c_long ASN1_ENUMERATED_get (ASN1_ENUMERATED* a);
ASN1_ENUMERATED* BN_to_ASN1_ENUMERATED (BIGNUM* bn, ASN1_ENUMERATED* ai);
BIGNUM* ASN1_ENUMERATED_to_BN (ASN1_ENUMERATED* ai, BIGNUM* bn);
int ASN1_PRINTABLE_type (const(ubyte)* s, int max);
int i2d_ASN1_bytes (ASN1_STRING* a, ubyte** pp, int tag, int xclass);
ASN1_STRING* d2i_ASN1_bytes (ASN1_STRING** a, const(ubyte*)* pp, c_long length, int Ptag, int Pclass);
c_ulong ASN1_tag2bit (int tag);
ASN1_STRING* d2i_ASN1_type_bytes (ASN1_STRING** a, const(ubyte*)* pp, c_long length, int type);
int asn1_Finish (ASN1_CTX* c);
int asn1_const_Finish (ASN1_const_CTX* c);
int ASN1_get_object (const(ubyte*)* pp, c_long* plength, int* ptag, int* pclass, c_long omax);
int ASN1_check_infinite_end (ubyte** p, c_long len);
int ASN1_const_check_infinite_end (const(ubyte*)* p, c_long len);
void ASN1_put_object (ubyte** pp, int constructed, int length, int tag, int xclass);
int ASN1_put_eoc (ubyte** pp);
int ASN1_object_size (int constructed, int length, int tag);
void* ASN1_item_dup (const(ASN1_ITEM)* it, void* x);
void* ASN1_dup (int function (void*, ubyte**) i2d, void* function (void**, const(ubyte*)*, c_long) d2i, void* x);
void* ASN1_d2i_fp (void* function () xnew, void* function (void**, const(ubyte*)*, c_long) d2i, FILE* in_, void** x);
void* ASN1_item_d2i_fp (const(ASN1_ITEM)* it, FILE* in_, void* x);
int ASN1_i2d_fp (int function (void*, ubyte**) i2d, FILE* out_, void* x);
int ASN1_item_i2d_fp (const(ASN1_ITEM)* it, FILE* out_, void* x);
int ASN1_STRING_print_ex_fp (FILE* fp, ASN1_STRING* str, c_ulong flags);
int ASN1_STRING_to_UTF8 (ubyte** out_, ASN1_STRING* in_);
void* ASN1_d2i_bio (void* function () xnew, void* function (void**, const(ubyte*)*, c_long) d2i, BIO* in_, void** x);
void* ASN1_item_d2i_bio (const(ASN1_ITEM)* it, BIO* in_, void* x);
int ASN1_i2d_bio (int function (void*, ubyte**) i2d, BIO* out_, ubyte* x);
int ASN1_item_i2d_bio (const(ASN1_ITEM)* it, BIO* out_, void* x);
int ASN1_UTCTIME_print (BIO* fp, const(ASN1_UTCTIME)* a);
int ASN1_GENERALIZEDTIME_print (BIO* fp, const(ASN1_GENERALIZEDTIME)* a);
int ASN1_TIME_print (BIO* fp, const(ASN1_TIME)* a);
int ASN1_STRING_print (BIO* bp, const(ASN1_STRING)* v);
int ASN1_STRING_print_ex (BIO* out_, ASN1_STRING* str, c_ulong flags);
int ASN1_bn_print (BIO* bp, const(char)* number, const(BIGNUM)* num, ubyte* buf, int off);
int ASN1_parse (BIO* bp, const(ubyte)* pp, c_long len, int indent);
int ASN1_parse_dump (BIO* bp, const(ubyte)* pp, c_long len, int indent, int dump);
const(char)* ASN1_tag2str (int tag);
NETSCAPE_X509* NETSCAPE_X509_new ();
void NETSCAPE_X509_free (NETSCAPE_X509* a);
NETSCAPE_X509* d2i_NETSCAPE_X509 (NETSCAPE_X509** a, const(ubyte*)* in_, c_long len);
int i2d_NETSCAPE_X509 (NETSCAPE_X509* a, ubyte** out_);
int ASN1_UNIVERSALSTRING_to_string (ASN1_UNIVERSALSTRING* s);
int ASN1_TYPE_set_octetstring (ASN1_TYPE* a, ubyte* data, int len);
int ASN1_TYPE_get_octetstring (ASN1_TYPE* a, ubyte* data, int max_len);
int ASN1_TYPE_set_int_octetstring (ASN1_TYPE* a, c_long num, ubyte* data, int len);
int ASN1_TYPE_get_int_octetstring (ASN1_TYPE* a, c_long* num, ubyte* data, int max_len);
//stack_st_OPENSSL_BLOCK* ASN1_seq_unpack (const(ubyte)* buf, int len, void* function (void**, const(ubyte*)*, c_long) d2i, void function (OPENSSL_BLOCK) free_func);
//ubyte* ASN1_seq_pack (stack_st_OPENSSL_BLOCK* safes, int function (void*, ubyte**) i2d, ubyte** buf, int* len);
void* ASN1_unpack_string (ASN1_STRING* oct, void* function (void**, const(ubyte*)*, c_long) d2i);
void* ASN1_item_unpack (ASN1_STRING* oct, const(ASN1_ITEM)* it);
ASN1_STRING* ASN1_pack_string (void* obj, int function (void*, ubyte**) i2d, ASN1_OCTET_STRING** oct);
ASN1_STRING* ASN1_item_pack (void* obj, const(ASN1_ITEM)* it, ASN1_OCTET_STRING** oct);
void ASN1_STRING_set_default_mask (c_ulong mask);
int ASN1_STRING_set_default_mask_asc (const(char)* p);
c_ulong ASN1_STRING_get_default_mask ();
int ASN1_mbstring_copy (ASN1_STRING** out_, const(ubyte)* in_, int len, int inform, c_ulong mask);
int ASN1_mbstring_ncopy (ASN1_STRING** out_, const(ubyte)* in_, int len, int inform, c_ulong mask, c_long minsize, c_long maxsize);
ASN1_STRING* ASN1_STRING_set_by_NID (ASN1_STRING** out_, const(ubyte)* in_, int inlen, int inform, int nid);
ASN1_STRING_TABLE* ASN1_STRING_TABLE_get (int nid);
int ASN1_STRING_TABLE_add (int, c_long, c_long, c_ulong, c_ulong);
void ASN1_STRING_TABLE_cleanup ();
ASN1_VALUE* ASN1_item_new (const(ASN1_ITEM)* it);
void ASN1_item_free (ASN1_VALUE* val, const(ASN1_ITEM)* it);
ASN1_VALUE* ASN1_item_d2i (ASN1_VALUE** val, const(ubyte*)* in_, c_long len, const(ASN1_ITEM)* it);
int ASN1_item_i2d (ASN1_VALUE* val, ubyte** out_, const(ASN1_ITEM)* it);
int ASN1_item_ndef_i2d (ASN1_VALUE* val, ubyte** out_, const(ASN1_ITEM)* it);
void ASN1_add_oid_module ();
ASN1_TYPE* ASN1_generate_nconf (char* str, CONF* nconf);
ASN1_TYPE* ASN1_generate_v3 (char* str, X509V3_CTX* cnf);
int ASN1_item_print (BIO* out_, ASN1_VALUE* ifld, int indent, const(ASN1_ITEM)* it, const(ASN1_PCTX)* pctx);
ASN1_PCTX* ASN1_PCTX_new ();
void ASN1_PCTX_free (ASN1_PCTX* p);
c_ulong ASN1_PCTX_get_flags (ASN1_PCTX* p);
void ASN1_PCTX_set_flags (ASN1_PCTX* p, c_ulong flags);
c_ulong ASN1_PCTX_get_nm_flags (ASN1_PCTX* p);
void ASN1_PCTX_set_nm_flags (ASN1_PCTX* p, c_ulong flags);
c_ulong ASN1_PCTX_get_cert_flags (ASN1_PCTX* p);
void ASN1_PCTX_set_cert_flags (ASN1_PCTX* p, c_ulong flags);
c_ulong ASN1_PCTX_get_oid_flags (ASN1_PCTX* p);
void ASN1_PCTX_set_oid_flags (ASN1_PCTX* p, c_ulong flags);
c_ulong ASN1_PCTX_get_str_flags (ASN1_PCTX* p);
void ASN1_PCTX_set_str_flags (ASN1_PCTX* p, c_ulong flags);
BIO_METHOD* BIO_f_asn1 ();
BIO* BIO_new_NDEF (BIO* out_, ASN1_VALUE* val, const(ASN1_ITEM)* it);
int i2d_ASN1_bio_stream (BIO* out_, ASN1_VALUE* val, BIO* in_, int flags, const(ASN1_ITEM)* it);
int PEM_write_bio_ASN1_stream (BIO* out_, ASN1_VALUE* val, BIO* in_, int flags, const(char)* hdr, const(ASN1_ITEM)* it);
int SMIME_write_ASN1 (BIO* bio, ASN1_VALUE* val, BIO* data, int flags, int ctype_nid, int econt_nid, stack_st_X509_ALGOR* mdalgs, const(ASN1_ITEM)* it);
ASN1_VALUE* SMIME_read_ASN1 (BIO* bio, BIO** bcont, const(ASN1_ITEM)* it);
int SMIME_crlf_copy (BIO* in_, BIO* out_, int flags);
int SMIME_text (BIO* in_, BIO* out_);
void ERR_load_ASN1_strings ();


/* Error codes for the ASN1 functions. */

/* Function codes. */
enum ASN1_F_A2D_ASN1_OBJECT = 100;
enum ASN1_F_A2I_ASN1_ENUMERATED = 101;
enum ASN1_F_A2I_ASN1_INTEGER = 102;
enum ASN1_F_A2I_ASN1_STRING = 103;
enum ASN1_F_APPEND_EXP = 176;
enum ASN1_F_ASN1_BIT_STRING_SET_BIT = 183;
enum ASN1_F_ASN1_CB = 177;
enum ASN1_F_ASN1_CHECK_TLEN = 104;
enum ASN1_F_ASN1_COLLATE_PRIMITIVE = 105;
enum ASN1_F_ASN1_COLLECT = 106;
enum ASN1_F_ASN1_D2I_EX_PRIMITIVE = 108;
enum ASN1_F_ASN1_D2I_FP = 109;
enum ASN1_F_ASN1_D2I_READ_BIO = 107;
enum ASN1_F_ASN1_DIGEST = 184;
enum ASN1_F_ASN1_DO_ADB = 110;
enum ASN1_F_ASN1_DUP = 111;
enum ASN1_F_ASN1_ENUMERATED_SET = 112;
enum ASN1_F_ASN1_ENUMERATED_TO_BN = 113;
enum ASN1_F_ASN1_EX_C2I = 204;
enum ASN1_F_ASN1_FIND_END = 190;
enum ASN1_F_ASN1_GENERALIZEDTIME_ADJ = 216;
enum ASN1_F_ASN1_GENERALIZEDTIME_SET = 185;
enum ASN1_F_ASN1_GENERATE_V3 = 178;
enum ASN1_F_ASN1_GET_OBJECT = 114;
enum ASN1_F_ASN1_HEADER_NEW = 115;
enum ASN1_F_ASN1_I2D_BIO = 116;
enum ASN1_F_ASN1_I2D_FP = 117;
enum ASN1_F_ASN1_INTEGER_SET = 118;
enum ASN1_F_ASN1_INTEGER_TO_BN = 119;
enum ASN1_F_ASN1_ITEM_D2I_FP = 206;
enum ASN1_F_ASN1_ITEM_DUP = 191;
enum ASN1_F_ASN1_ITEM_EX_COMBINE_NEW = 121;
enum ASN1_F_ASN1_ITEM_EX_D2I = 120;
enum ASN1_F_ASN1_ITEM_I2D_BIO = 192;
enum ASN1_F_ASN1_ITEM_I2D_FP = 193;
enum ASN1_F_ASN1_ITEM_PACK = 198;
enum ASN1_F_ASN1_ITEM_SIGN = 195;
enum ASN1_F_ASN1_ITEM_SIGN_CTX = 220;
enum ASN1_F_ASN1_ITEM_UNPACK = 199;
enum ASN1_F_ASN1_ITEM_VERIFY = 197;
enum ASN1_F_ASN1_MBSTRING_NCOPY = 122;
enum ASN1_F_ASN1_OBJECT_NEW = 123;
enum ASN1_F_ASN1_OUTPUT_DATA = 214;
enum ASN1_F_ASN1_PACK_STRING = 124;
enum ASN1_F_ASN1_PCTX_NEW = 205;
enum ASN1_F_ASN1_PKCS5_PBE_SET = 125;
enum ASN1_F_ASN1_SEQ_PACK = 126;
enum ASN1_F_ASN1_SEQ_UNPACK = 127;
enum ASN1_F_ASN1_SIGN = 128;
enum ASN1_F_ASN1_STR2TYPE = 179;
enum ASN1_F_ASN1_STRING_SET = 186;
enum ASN1_F_ASN1_STRING_TABLE_ADD = 129;
enum ASN1_F_ASN1_STRING_TYPE_NEW = 130;
enum ASN1_F_ASN1_TEMPLATE_EX_D2I = 132;
enum ASN1_F_ASN1_TEMPLATE_NEW = 133;
enum ASN1_F_ASN1_TEMPLATE_NOEXP_D2I = 131;
enum ASN1_F_ASN1_TIME_ADJ = 217;
enum ASN1_F_ASN1_TIME_SET = 175;
enum ASN1_F_ASN1_TYPE_GET_INT_OCTETSTRING = 134;
enum ASN1_F_ASN1_TYPE_GET_OCTETSTRING = 135;
enum ASN1_F_ASN1_UNPACK_STRING = 136;
enum ASN1_F_ASN1_UTCTIME_ADJ = 218;
enum ASN1_F_ASN1_UTCTIME_SET = 187;
enum ASN1_F_ASN1_VERIFY = 137;
enum ASN1_F_B64_READ_ASN1 = 209;
enum ASN1_F_B64_WRITE_ASN1 = 210;
enum ASN1_F_BIO_NEW_NDEF = 208;
enum ASN1_F_BITSTR_CB = 180;
enum ASN1_F_BN_TO_ASN1_ENUMERATED = 138;
enum ASN1_F_BN_TO_ASN1_INTEGER = 139;
enum ASN1_F_C2I_ASN1_BIT_STRING = 189;
enum ASN1_F_C2I_ASN1_INTEGER = 194;
enum ASN1_F_C2I_ASN1_OBJECT = 196;
enum ASN1_F_COLLECT_DATA = 140;
enum ASN1_F_D2I_ASN1_BIT_STRING = 141;
enum ASN1_F_D2I_ASN1_BOOLEAN = 142;
enum ASN1_F_D2I_ASN1_BYTES = 143;
enum ASN1_F_D2I_ASN1_GENERALIZEDTIME = 144;
enum ASN1_F_D2I_ASN1_HEADER = 145;
enum ASN1_F_D2I_ASN1_INTEGER = 146;
enum ASN1_F_D2I_ASN1_OBJECT = 147;
enum ASN1_F_D2I_ASN1_SET = 148;
enum ASN1_F_D2I_ASN1_TYPE_BYTES = 149;
enum ASN1_F_D2I_ASN1_UINTEGER = 150;
enum ASN1_F_D2I_ASN1_UTCTIME = 151;
enum ASN1_F_D2I_AUTOPRIVATEKEY = 207;
enum ASN1_F_D2I_NETSCAPE_RSA = 152;
enum ASN1_F_D2I_NETSCAPE_RSA_2 = 153;
enum ASN1_F_D2I_PRIVATEKEY = 154;
enum ASN1_F_D2I_PUBLICKEY = 155;
enum ASN1_F_D2I_RSA_NET = 200;
enum ASN1_F_D2I_RSA_NET_2 = 201;
enum ASN1_F_D2I_X509 = 156;
enum ASN1_F_D2I_X509_CINF = 157;
enum ASN1_F_D2I_X509_PKEY = 159;
enum ASN1_F_I2D_ASN1_BIO_STREAM = 211;
enum ASN1_F_I2D_ASN1_SET = 188;
enum ASN1_F_I2D_ASN1_TIME = 160;
enum ASN1_F_I2D_DSA_PUBKEY = 161;
enum ASN1_F_I2D_EC_PUBKEY = 181;
enum ASN1_F_I2D_PRIVATEKEY = 163;
enum ASN1_F_I2D_PUBLICKEY = 164;
enum ASN1_F_I2D_RSA_NET = 162;
enum ASN1_F_I2D_RSA_PUBKEY = 165;
enum ASN1_F_LONG_C2I = 166;
enum ASN1_F_OID_MODULE_INIT = 174;
enum ASN1_F_PARSE_TAGGING = 182;
enum ASN1_F_PKCS5_PBE2_SET_IV = 167;
enum ASN1_F_PKCS5_PBE_SET = 202;
enum ASN1_F_PKCS5_PBE_SET0_ALGOR = 215;
enum ASN1_F_PKCS5_PBKDF2_SET = 219;
enum ASN1_F_SMIME_READ_ASN1 = 212;
enum ASN1_F_SMIME_TEXT = 213;
enum ASN1_F_X509_CINF_NEW = 168;
enum ASN1_F_X509_CRL_ADD0_REVOKED = 169;
enum ASN1_F_X509_INFO_NEW = 170;
enum ASN1_F_X509_NAME_ENCODE = 203;
enum ASN1_F_X509_NAME_EX_D2I = 158;
enum ASN1_F_X509_NAME_EX_NEW = 171;
enum ASN1_F_X509_NEW = 172;
enum ASN1_F_X509_PKEY_NEW = 173;

/* Reason codes. */
enum ASN1_R_ADDING_OBJECT = 171;
enum ASN1_R_ASN1_PARSE_ERROR = 203;
enum ASN1_R_ASN1_SIG_PARSE_ERROR = 204;
enum ASN1_R_AUX_ERROR = 100;
enum ASN1_R_BAD_CLASS = 101;
enum ASN1_R_BAD_OBJECT_HEADER = 102;
enum ASN1_R_BAD_PASSWORD_READ = 103;
enum ASN1_R_BAD_TAG = 104;
enum ASN1_R_BMPSTRING_IS_WRONG_LENGTH = 214;
enum ASN1_R_BN_LIB = 105;
enum ASN1_R_BOOLEAN_IS_WRONG_LENGTH = 106;
enum ASN1_R_BUFFER_TOO_SMALL = 107;
enum ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER = 108;
enum ASN1_R_CONTEXT_NOT_INITIALISED = 217;
enum ASN1_R_DATA_IS_WRONG = 109;
enum ASN1_R_DECODE_ERROR = 110;
enum ASN1_R_DECODING_ERROR = 111;
enum ASN1_R_DEPTH_EXCEEDED = 174;
enum ASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED = 198;
enum ASN1_R_ENCODE_ERROR = 112;
enum ASN1_R_ERROR_GETTING_TIME = 173;
enum ASN1_R_ERROR_LOADING_SECTION = 172;
enum ASN1_R_ERROR_PARSING_SET_ELEMENT = 113;
enum ASN1_R_ERROR_SETTING_CIPHER_PARAMS = 114;
enum ASN1_R_EXPECTING_AN_INTEGER = 115;
enum ASN1_R_EXPECTING_AN_OBJECT = 116;
enum ASN1_R_EXPECTING_A_BOOLEAN = 117;
enum ASN1_R_EXPECTING_A_TIME = 118;
enum ASN1_R_EXPLICIT_LENGTH_MISMATCH = 119;
enum ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED = 120;
enum ASN1_R_FIELD_MISSING = 121;
enum ASN1_R_FIRST_NUM_TOO_LARGE = 122;
enum ASN1_R_HEADER_TOO_LONG = 123;
enum ASN1_R_ILLEGAL_BITSTRING_FORMAT = 175;
enum ASN1_R_ILLEGAL_BOOLEAN = 176;
enum ASN1_R_ILLEGAL_CHARACTERS = 124;
enum ASN1_R_ILLEGAL_FORMAT = 177;
enum ASN1_R_ILLEGAL_HEX = 178;
enum ASN1_R_ILLEGAL_IMPLICIT_TAG = 179;
enum ASN1_R_ILLEGAL_INTEGER = 180;
enum ASN1_R_ILLEGAL_NESTED_TAGGING = 181;
enum ASN1_R_ILLEGAL_NULL = 125;
enum ASN1_R_ILLEGAL_NULL_VALUE = 182;
enum ASN1_R_ILLEGAL_OBJECT = 183;
enum ASN1_R_ILLEGAL_OPTIONAL_ANY = 126;
enum ASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE = 170;
enum ASN1_R_ILLEGAL_TAGGED_ANY = 127;
enum ASN1_R_ILLEGAL_TIME_VALUE = 184;
enum ASN1_R_INTEGER_NOT_ASCII_FORMAT = 185;
enum ASN1_R_INTEGER_TOO_LARGE_FOR_LONG = 128;
enum ASN1_R_INVALID_BIT_STRING_BITS_LEFT = 220;
enum ASN1_R_INVALID_BMPSTRING_LENGTH = 129;
enum ASN1_R_INVALID_DIGIT = 130;
enum ASN1_R_INVALID_MIME_TYPE = 205;
enum ASN1_R_INVALID_MODIFIER = 186;
enum ASN1_R_INVALID_NUMBER = 187;
enum ASN1_R_INVALID_OBJECT_ENCODING = 216;
enum ASN1_R_INVALID_SEPARATOR = 131;
enum ASN1_R_INVALID_TIME_FORMAT = 132;
enum ASN1_R_INVALID_UNIVERSALSTRING_LENGTH = 133;
enum ASN1_R_INVALID_UTF8STRING = 134;
enum ASN1_R_IV_TOO_LARGE = 135;
enum ASN1_R_LENGTH_ERROR = 136;
enum ASN1_R_LIST_ERROR = 188;
enum ASN1_R_MIME_NO_CONTENT_TYPE = 206;
enum ASN1_R_MIME_PARSE_ERROR = 207;
enum ASN1_R_MIME_SIG_PARSE_ERROR = 208;
enum ASN1_R_MISSING_EOC = 137;
enum ASN1_R_MISSING_SECOND_NUMBER = 138;
enum ASN1_R_MISSING_VALUE = 189;
enum ASN1_R_MSTRING_NOT_UNIVERSAL = 139;
enum ASN1_R_MSTRING_WRONG_TAG = 140;
enum ASN1_R_NESTED_ASN1_STRING = 197;
enum ASN1_R_NON_HEX_CHARACTERS = 141;
enum ASN1_R_NOT_ASCII_FORMAT = 190;
enum ASN1_R_NOT_ENOUGH_DATA = 142;
enum ASN1_R_NO_CONTENT_TYPE = 209;
enum ASN1_R_NO_DEFAULT_DIGEST = 201;
enum ASN1_R_NO_MATCHING_CHOICE_TYPE = 143;
enum ASN1_R_NO_MULTIPART_BODY_FAILURE = 210;
enum ASN1_R_NO_MULTIPART_BOUNDARY = 211;
enum ASN1_R_NO_SIG_CONTENT_TYPE = 212;
enum ASN1_R_NULL_IS_WRONG_LENGTH = 144;
enum ASN1_R_OBJECT_NOT_ASCII_FORMAT = 191;
enum ASN1_R_ODD_NUMBER_OF_CHARS = 145;
enum ASN1_R_PRIVATE_KEY_HEADER_MISSING = 146;
enum ASN1_R_SECOND_NUMBER_TOO_LARGE = 147;
enum ASN1_R_SEQUENCE_LENGTH_MISMATCH = 148;
enum ASN1_R_SEQUENCE_NOT_CONSTRUCTED = 149;
enum ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG = 192;
enum ASN1_R_SHORT_LINE = 150;
enum ASN1_R_SIG_INVALID_MIME_TYPE = 213;
enum ASN1_R_STREAMING_NOT_SUPPORTED = 202;
enum ASN1_R_STRING_TOO_LONG = 151;
enum ASN1_R_STRING_TOO_SHORT = 152;
enum ASN1_R_TAG_VALUE_TOO_HIGH = 153;
enum ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD = 154;
enum ASN1_R_TIME_NOT_ASCII_FORMAT = 193;
enum ASN1_R_TOO_LONG = 155;
enum ASN1_R_TYPE_NOT_CONSTRUCTED = 156;
enum ASN1_R_UNABLE_TO_DECODE_RSA_KEY = 157;
enum ASN1_R_UNABLE_TO_DECODE_RSA_PRIVATE_KEY = 158;
enum ASN1_R_UNEXPECTED_EOC = 159;
enum ASN1_R_UNIVERSALSTRING_IS_WRONG_LENGTH = 215;
enum ASN1_R_UNKNOWN_FORMAT = 160;
enum ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM = 161;
enum ASN1_R_UNKNOWN_OBJECT_TYPE = 162;
enum ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE = 163;
enum ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM = 199;
enum ASN1_R_UNKNOWN_TAG = 194;
enum ASN1_R_UNKOWN_FORMAT = 195;
enum ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE = 164;
enum ASN1_R_UNSUPPORTED_CIPHER = 165;
enum ASN1_R_UNSUPPORTED_ENCRYPTION_ALGORITHM = 166;
enum ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE = 167;
enum ASN1_R_UNSUPPORTED_TYPE = 196;
enum ASN1_R_WRONG_PUBLIC_KEY_TYPE = 200;
enum ASN1_R_WRONG_TAG = 168;
enum ASN1_R_WRONG_TYPE = 169;

