typedef unsigned char   undefined;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long double    longdouble;
typedef long long    longlong;
typedef unsigned long long    qword;
typedef int    sdword;
typedef long long    sqword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined3;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined5;
typedef unsigned long long    undefined6;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    word;
#define unkbyte9   unsigned long long
#define unkbyte10   unsigned long long
#define unkbyte11   unsigned long long
#define unkbyte12   unsigned long long
#define unkbyte13   unsigned long long
#define unkbyte14   unsigned long long
#define unkbyte15   unsigned long long
#define unkbyte16   unsigned long long

#define unkuint9   unsigned long long
#define unkuint10   unsigned long long
#define unkuint11   unsigned long long
#define unkuint12   unsigned long long
#define unkuint13   unsigned long long
#define unkuint14   unsigned long long
#define unkuint15   unsigned long long
#define unkuint16   unsigned long long

#define unkint9   long long
#define unkint10   long long
#define unkint11   long long
#define unkint12   long long
#define unkint13   long long
#define unkint14   long long
#define unkint15   long long
#define unkint16   long long

#define unkfloat1   float
#define unkfloat2   float
#define unkfloat3   float
#define unkfloat5   double
#define unkfloat6   double
#define unkfloat7   double
#define unkfloat9   long double
#define unkfloat11   long double
#define unkfloat12   long double
#define unkfloat13   long double
#define unkfloat14   long double
#define unkfloat15   long double
#define unkfloat16   long double

#define BADSPACEBASE   void
#define code   void

typedef ushort sa_family_t;

typedef void _IO_lock_t;

typedef struct _IO_marker _IO_marker, *P_IO_marker;

typedef struct _IO_FILE _IO_FILE, *P_IO_FILE;

typedef long __off_t;

typedef longlong __quad_t;

typedef __quad_t __off64_t;

typedef ulong size_t;

struct _IO_FILE {
    int _flags;
    char *_IO_read_ptr;
    char *_IO_read_end;
    char *_IO_read_base;
    char *_IO_write_base;
    char *_IO_write_ptr;
    char *_IO_write_end;
    char *_IO_buf_base;
    char *_IO_buf_end;
    char *_IO_save_base;
    char *_IO_backup_base;
    char *_IO_save_end;
    struct _IO_marker *_markers;
    struct _IO_FILE *_chain;
    int _fileno;
    int _flags2;
    __off_t _old_offset;
    ushort _cur_column;
    char _vtable_offset;
    char _shortbuf[1];
    _IO_lock_t *_lock;
    __off64_t _offset;
    void *__pad1;
    void *__pad2;
    void *__pad3;
    void *__pad4;
    size_t __pad5;
    int _mode;
    char _unused2[40];
};

struct _IO_marker {
    struct _IO_marker *_next;
    struct _IO_FILE *_sbuf;
    int _pos;
};

typedef struct stat stat, *Pstat;

typedef ulonglong __u_quad_t;

typedef __u_quad_t __dev_t;

typedef ulong __ino_t;

typedef uint __mode_t;

typedef uint __nlink_t;

typedef uint __uid_t;

typedef uint __gid_t;

typedef long __blksize_t;

typedef long __blkcnt_t;

typedef struct timespec timespec, *Ptimespec;

typedef long __time_t;

struct timespec {
    __time_t tv_sec;
    long tv_nsec;
};

struct stat {
    __dev_t st_dev;
    ushort __pad1;
    __ino_t st_ino;
    __mode_t st_mode;
    __nlink_t st_nlink;
    __uid_t st_uid;
    __gid_t st_gid;
    __dev_t st_rdev;
    ushort __pad2;
    __off_t st_size;
    __blksize_t st_blksize;
    __blkcnt_t st_blocks;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    ulong __unused4;
    ulong __unused5;
};

typedef struct addrinfo addrinfo, *Paddrinfo;

typedef uint __socklen_t;

typedef __socklen_t socklen_t;

typedef struct sockaddr sockaddr, *Psockaddr;

struct addrinfo {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    socklen_t ai_addrlen;
    struct sockaddr *ai_addr;
    char *ai_canonname;
    struct addrinfo *ai_next;
};

struct sockaddr {
    sa_family_t sa_family;
    char sa_data[14];
};

typedef struct aes_key_st aes_key_st, *Paes_key_st;

struct aes_key_st {
    uint rd_key[60];
    int rounds;
};

typedef struct aes_key_st AES_KEY;

typedef struct _IO_FILE FILE;

typedef int __jmp_buf[6];

typedef int __ssize_t;

typedef __ssize_t ssize_t;

typedef int __pid_t;

typedef int __clockid_t;

typedef int __int32_t;

typedef uint __useconds_t;

typedef long __suseconds_t;

typedef long __clock_t;

typedef struct pollfd pollfd, *Ppollfd;

struct pollfd {
    int fd;
    short events;
    short revents;
};

typedef ulong nfds_t;

typedef struct asn1_string_st asn1_string_st, *Pasn1_string_st;

typedef struct asn1_string_st ASN1_BMPSTRING;

struct asn1_string_st {
    int length;
    int type;
    uchar *data;
    long flags;
};

typedef struct asn1_string_st ASN1_T61STRING;

typedef struct asn1_string_st ASN1_OCTET_STRING;

typedef struct asn1_string_st ASN1_GENERALSTRING;

typedef struct asn1_string_st ASN1_UTF8STRING;

typedef struct asn1_string_st ASN1_ENUMERATED;

typedef struct asn1_string_st ASN1_UTCTIME;

typedef struct asn1_string_st ASN1_STRING;

typedef struct asn1_string_st ASN1_PRINTABLESTRING;

typedef struct asn1_string_st ASN1_BIT_STRING;

typedef struct asn1_string_st ASN1_INTEGER;

typedef struct evp_cipher_ctx_st evp_cipher_ctx_st, *Pevp_cipher_ctx_st;

typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

typedef struct evp_cipher_st evp_cipher_st, *Pevp_cipher_st;

typedef struct asn1_type_st asn1_type_st, *Pasn1_type_st;

typedef struct asn1_type_st ASN1_TYPE;

typedef struct evp_cipher_st EVP_CIPHER;

typedef struct engine_st engine_st, *Pengine_st;

typedef struct engine_st ENGINE;

typedef union _union_263 _union_263, *P_union_263;

typedef int ASN1_BOOLEAN;

typedef struct asn1_object_st asn1_object_st, *Pasn1_object_st;

typedef struct asn1_object_st ASN1_OBJECT;

typedef struct asn1_string_st ASN1_IA5STRING;

typedef struct asn1_string_st ASN1_UNIVERSALSTRING;

typedef struct asn1_string_st ASN1_GENERALIZEDTIME;

typedef struct asn1_string_st ASN1_VISIBLESTRING;

typedef struct ASN1_VALUE_st ASN1_VALUE_st, *PASN1_VALUE_st;

typedef struct ASN1_VALUE_st ASN1_VALUE;

struct ASN1_VALUE_st {
};

struct engine_st {
};

struct evp_cipher_ctx_st {
    EVP_CIPHER *cipher;
    ENGINE *engine;
    int encrypt;
    int buf_len;
    uchar oiv[16];
    uchar iv[16];
    uchar buf[32];
    int num;
    void *app_data;
    int key_len;
    ulong flags;
    void *cipher_data;
    int final_used;
    int block_mask;
    uchar final[32];
};

union _union_263 {
    char *ptr;
    ASN1_BOOLEAN boolean;
    ASN1_STRING *asn1_string;
    ASN1_OBJECT *object;
    ASN1_INTEGER *integer;
    ASN1_ENUMERATED *enumerated;
    ASN1_BIT_STRING *bit_string;
    ASN1_OCTET_STRING *octet_string;
    ASN1_PRINTABLESTRING *printablestring;
    ASN1_T61STRING *t61string;
    ASN1_IA5STRING *ia5string;
    ASN1_GENERALSTRING *generalstring;
    ASN1_BMPSTRING *bmpstring;
    ASN1_UNIVERSALSTRING *universalstring;
    ASN1_UTCTIME *utctime;
    ASN1_GENERALIZEDTIME *generalizedtime;
    ASN1_VISIBLESTRING *visiblestring;
    ASN1_UTF8STRING *utf8string;
    ASN1_STRING *set;
    ASN1_STRING *sequence;
    ASN1_VALUE *asn1_value;
};

struct asn1_type_st {
    int type;
    union _union_263 value;
};

struct evp_cipher_st {
    int nid;
    int block_size;
    int key_len;
    int iv_len;
    ulong flags;
    int (*init)(EVP_CIPHER_CTX *, uchar *, uchar *, int);
    int (*do_cipher)(EVP_CIPHER_CTX *, uchar *, uchar *, size_t);
    int (*cleanup)(EVP_CIPHER_CTX *);
    int ctx_size;
    int (*set_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *);
    int (*get_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *);
    int (*ctrl)(EVP_CIPHER_CTX *, int, int, void *);
    void *app_data;
};

struct asn1_object_st {
    char *sn;
    char **ln;
    int nid;
    int length;
    uchar *data;
    int flags;
};

typedef struct __pthread_internal_slist __pthread_internal_slist, *P__pthread_internal_slist;

struct __pthread_internal_slist {
    struct __pthread_internal_slist *__next;
};

typedef union pthread_mutex_t pthread_mutex_t, *Ppthread_mutex_t;

typedef struct __pthread_mutex_s __pthread_mutex_s, *P__pthread_mutex_s;

typedef union _union_13 _union_13, *P_union_13;

typedef struct __pthread_internal_slist __pthread_slist_t;

union _union_13 {
    int __spins;
    __pthread_slist_t __list;
};

struct __pthread_mutex_s {
    int __lock;
    uint __count;
    int __owner;
    int __kind;
    uint __nusers;
    union _union_13 field5_0x14;
};

union pthread_mutex_t {
    struct __pthread_mutex_s __data;
    char __size[24];
    long __align;
};

typedef union pthread_mutexattr_t pthread_mutexattr_t, *Ppthread_mutexattr_t;

union pthread_mutexattr_t {
    char __size[4];
    int __align;
};

typedef ulong pthread_t;

typedef union pthread_attr_t pthread_attr_t, *Ppthread_attr_t;

union pthread_attr_t {
    char __size[36];
    long __align;
};

typedef union _union_1031 _union_1031, *P_union_1031;

typedef struct _struct_1032 _struct_1032, *P_struct_1032;

typedef struct _struct_1033 _struct_1033, *P_struct_1033;

typedef struct _struct_1034 _struct_1034, *P_struct_1034;

typedef struct _struct_1035 _struct_1035, *P_struct_1035;

typedef struct _struct_1036 _struct_1036, *P_struct_1036;

typedef struct _struct_1037 _struct_1037, *P_struct_1037;

typedef union sigval sigval, *Psigval;

typedef union sigval sigval_t;

struct _struct_1032 {
    __pid_t si_pid;
    __uid_t si_uid;
};

union sigval {
    int sival_int;
    void *sival_ptr;
};

struct _struct_1033 {
    int si_tid;
    int si_overrun;
    sigval_t si_sigval;
};

struct _struct_1035 {
    __pid_t si_pid;
    __uid_t si_uid;
    int si_status;
    __clock_t si_utime;
    __clock_t si_stime;
};

struct _struct_1037 {
    long si_band;
    int si_fd;
};

struct _struct_1036 {
    void *si_addr;
};

struct _struct_1034 {
    __pid_t si_pid;
    __uid_t si_uid;
    sigval_t si_sigval;
};

union _union_1031 {
    int _pad[29];
    struct _struct_1032 _kill;
    struct _struct_1033 _timer;
    struct _struct_1034 _rt;
    struct _struct_1035 _sigchld;
    struct _struct_1036 _sigfault;
    struct _struct_1037 _sigpoll;
};

typedef struct siginfo siginfo, *Psiginfo;

struct siginfo {
    int si_signo;
    int si_errno;
    int si_code;
    union _union_1031 _sifields;
};

typedef struct siginfo siginfo_t;

typedef dword u32;

typedef uchar UQItype;

typedef qword uint64_t;

typedef ushort WORD_T;

typedef int __syscall_slong_t;


// WARNING! conflicting data type names: /DWARF/__blkcnt_t - /types.h/__blkcnt_t

typedef uchar BYTE;

typedef ushort prime_t;


// WARNING! conflicting data type names: /DWARF/__off_t - /types.h/__off_t

typedef uchar uint8_t;

typedef dword uint32_t;

typedef ushort BOOL_T;

typedef ulonglong UDItype;

typedef ushort WORD;


// WARNING! conflicting data type names: /DWARF/pthread_t - /pthreadtypes.h/pthread_t

typedef int __fd_mask;


// WARNING! conflicting data type names: /DWARF/__clock_t - /types.h/__clock_t

typedef uint sizetype;

typedef bool UA_Boolean;

typedef uint hashval_t;

typedef sqword int64_t;


// WARNING! conflicting data type names: /DWARF/size_t - /stddef.h/size_t

typedef qword u64;

typedef int __sig_atomic_t;

typedef uchar u8;

typedef uint USItype;

typedef longlong DItype;

typedef uchar xmlChar;


// WARNING! conflicting data type names: /DWARF/__time_t - /types.h/__time_t

typedef uint seed_word;

typedef sdword int32_t;

typedef double DFtype;

typedef uint DWORD;

typedef uint arm_fpu_feature_set;

typedef uint uintptr_t;

typedef qword complex float;


// WARNING! conflicting data type names: /DWARF/__suseconds_t - /types.h/__suseconds_t

typedef word uint16_t;

typedef bool _Bool;

typedef int ASN1_NULL;

typedef double UA_Double;


// WARNING! conflicting data type names: /DWARF/__blksize_t - /types.h/__blksize_t

typedef uint DWORD_T;

typedef undefined complex double[16];


// WARNING! conflicting data type names: /DWARF/__ino_t - /types.h/__ino_t

typedef union anon_union_4_2_485e7bf3 anon_union_4_2_485e7bf3, *Panon_union_4_2_485e7bf3;

union anon_union_4_2_485e7bf3 {
    long one;
    char little;
};

typedef struct ccm128_context ccm128_context, *Pccm128_context;

typedef struct ccm128_context CCM128_CONTEXT;

typedef union anon_union_16_2_94730053_for_nonce_cmac anon_union_16_2_94730053_for_nonce_cmac, *Panon_union_16_2_94730053_for_nonce_cmac;

typedef void (*block128_f)(uchar *, uchar *, void *);

union anon_union_16_2_94730053_for_nonce_cmac {
    u64 u[2];
    u8 c[16];
};

struct ccm128_context {
    union anon_union_16_2_94730053_for_nonce_cmac nonce;
    union anon_union_16_2_94730053_for_nonce_cmac cmac;
    u64 blocks;
    block128_f block;
    void *key;
};

typedef struct gcm128_context gcm128_context, *Pgcm128_context;

typedef struct u128 u128, *Pu128;

typedef struct gcm128_context GCM128_CONTEXT;

typedef union anon_union_16_4_d826f663_for_Yi_EKi_EK0_len_Xi_H anon_union_16_4_d826f663_for_Yi_EKi_EK0_len_Xi_H, *Panon_union_16_4_d826f663_for_Yi_EKi_EK0_len_Xi_H;

struct u128 {
    u64 hi;
    u64 lo;
};

union anon_union_16_4_d826f663_for_Yi_EKi_EK0_len_Xi_H {
    u64 u[2];
    u32 d[4];
    u8 c[16];
    size_t t[4];
};

struct gcm128_context {
    union anon_union_16_4_d826f663_for_Yi_EKi_EK0_len_Xi_H Yi;
    union anon_union_16_4_d826f663_for_Yi_EKi_EK0_len_Xi_H EKi;
    union anon_union_16_4_d826f663_for_Yi_EKi_EK0_len_Xi_H EK0;
    union anon_union_16_4_d826f663_for_Yi_EKi_EK0_len_Xi_H len;
    union anon_union_16_4_d826f663_for_Yi_EKi_EK0_len_Xi_H Xi;
    union anon_union_16_4_d826f663_for_Yi_EKi_EK0_len_Xi_H H;
    struct u128 Htable[16];
    void (*gmult)(u64 *, struct u128 *);
    void (*ghash)(u64 *, struct u128 *, u8 *, size_t);
    uint mres;
    uint ares;
    block128_f block;
    void *key;
};

typedef void (*ctr128_f)(uchar *, uchar *, size_t, void *, uchar *);

typedef void (*ccm128_f)(uchar *, uchar *, size_t, void *, uchar *, uchar *);

typedef struct xts128_context xts128_context, *Pxts128_context;

typedef struct xts128_context XTS128_CONTEXT;

struct xts128_context {
    void *key1;
    void *key2;
    block128_f block1;
    block128_f block2;
};

typedef void (*cbc128_f)(uchar *, uchar *, size_t, void *, uchar *, int);

typedef struct stack_st_PKCS7_RECIP_INFO stack_st_PKCS7_RECIP_INFO, *Pstack_st_PKCS7_RECIP_INFO;

typedef struct stack_st stack_st, *Pstack_st;

typedef struct stack_st _STACK;

struct stack_st {
    int num;
    char **data;
    int sorted;
    int num_alloc;
    int (*comp)(void *, void *);
};

struct stack_st_PKCS7_RECIP_INFO {
    _STACK stack;
};

typedef struct pkcs7_encrypted_st pkcs7_encrypted_st, *Ppkcs7_encrypted_st;

typedef struct pkcs7_encrypted_st PKCS7_ENCRYPT;

typedef struct pkcs7_enc_content_st pkcs7_enc_content_st, *Ppkcs7_enc_content_st;

typedef struct pkcs7_enc_content_st PKCS7_ENC_CONTENT;


// WARNING! conflicting data type names: /DWARF/ossl_typ.h/ASN1_OBJECT - /asn1.h/ASN1_OBJECT

typedef struct X509_algor_st X509_algor_st, *PX509_algor_st;

typedef struct X509_algor_st X509_ALGOR;


// WARNING! conflicting data type names: /DWARF/ossl_typ.h/EVP_CIPHER - /ossl_typ.h/EVP_CIPHER


// WARNING! conflicting data type names: /DWARF/asn1.h/ASN1_TYPE - /asn1.h/ASN1_TYPE

struct X509_algor_st {
    ASN1_OBJECT *algorithm;
    ASN1_TYPE *parameter;
};

struct pkcs7_encrypted_st {
    ASN1_INTEGER *version;
    PKCS7_ENC_CONTENT *enc_data;
};

struct pkcs7_enc_content_st {
    ASN1_OBJECT *content_type;
    X509_ALGOR *algorithm;
    ASN1_OCTET_STRING *enc_data;
    EVP_CIPHER *cipher;
};

typedef struct pkcs7_digest_st pkcs7_digest_st, *Ppkcs7_digest_st;

typedef struct pkcs7_st pkcs7_st, *Ppkcs7_st;

typedef union anon_union_4_8_e47e5135_for_d anon_union_4_8_e47e5135_for_d, *Panon_union_4_8_e47e5135_for_d;

typedef struct pkcs7_signed_st pkcs7_signed_st, *Ppkcs7_signed_st;

typedef struct pkcs7_signed_st PKCS7_SIGNED;

typedef struct pkcs7_enveloped_st pkcs7_enveloped_st, *Ppkcs7_enveloped_st;

typedef struct pkcs7_enveloped_st PKCS7_ENVELOPE;

typedef struct pkcs7_signedandenveloped_st pkcs7_signedandenveloped_st, *Ppkcs7_signedandenveloped_st;

typedef struct pkcs7_signedandenveloped_st PKCS7_SIGN_ENVELOPE;

typedef struct pkcs7_digest_st PKCS7_DIGEST;

typedef struct stack_st_X509_ALGOR stack_st_X509_ALGOR, *Pstack_st_X509_ALGOR;

typedef struct stack_st_X509 stack_st_X509, *Pstack_st_X509;

typedef struct stack_st_X509_CRL stack_st_X509_CRL, *Pstack_st_X509_CRL;

typedef struct stack_st_PKCS7_SIGNER_INFO stack_st_PKCS7_SIGNER_INFO, *Pstack_st_PKCS7_SIGNER_INFO;

struct pkcs7_digest_st {
    ASN1_INTEGER *version;
    X509_ALGOR *md;
    struct pkcs7_st *contents;
    ASN1_OCTET_STRING *digest;
};

struct stack_st_PKCS7_SIGNER_INFO {
    _STACK stack;
};

struct pkcs7_signedandenveloped_st {
    ASN1_INTEGER *version;
    struct stack_st_X509_ALGOR *md_algs;
    struct stack_st_X509 *cert;
    struct stack_st_X509_CRL *crl;
    struct stack_st_PKCS7_SIGNER_INFO *signer_info;
    PKCS7_ENC_CONTENT *enc_data;
    struct stack_st_PKCS7_RECIP_INFO *recipientinfo;
};

struct stack_st_X509 {
    _STACK stack;
};

union anon_union_4_8_e47e5135_for_d {
    char *ptr;
    ASN1_OCTET_STRING *data;
    PKCS7_SIGNED *sign;
    PKCS7_ENVELOPE *enveloped;
    PKCS7_SIGN_ENVELOPE *signed_and_enveloped;
    PKCS7_DIGEST *digest;
    PKCS7_ENCRYPT *encrypted;
    ASN1_TYPE *other;
};

struct pkcs7_st {
    uchar *asn1;
    long length;
    int state;
    int detached;
    ASN1_OBJECT *type;
    union anon_union_4_8_e47e5135_for_d d;
};

struct pkcs7_enveloped_st {
    ASN1_INTEGER *version;
    struct stack_st_PKCS7_RECIP_INFO *recipientinfo;
    PKCS7_ENC_CONTENT *enc_data;
};

struct stack_st_X509_CRL {
    _STACK stack;
};

struct pkcs7_signed_st {
    ASN1_INTEGER *version;
    struct stack_st_X509_ALGOR *md_algs;
    struct stack_st_X509 *cert;
    struct stack_st_X509_CRL *crl;
    struct stack_st_PKCS7_SIGNER_INFO *signer_info;
    struct pkcs7_st *contents;
};

struct stack_st_X509_ALGOR {
    _STACK stack;
};

typedef struct pkcs7_signer_info_st pkcs7_signer_info_st, *Ppkcs7_signer_info_st;

typedef struct pkcs7_signer_info_st PKCS7_SIGNER_INFO;

typedef struct pkcs7_issuer_and_serial_st pkcs7_issuer_and_serial_st, *Ppkcs7_issuer_and_serial_st;

typedef struct pkcs7_issuer_and_serial_st PKCS7_ISSUER_AND_SERIAL;

typedef struct stack_st_X509_ATTRIBUTE stack_st_X509_ATTRIBUTE, *Pstack_st_X509_ATTRIBUTE;

typedef struct evp_pkey_st evp_pkey_st, *Pevp_pkey_st;

typedef struct evp_pkey_st EVP_PKEY;

typedef struct X509_name_st X509_name_st, *PX509_name_st;

typedef struct X509_name_st X509_NAME;

typedef struct evp_pkey_asn1_method_st evp_pkey_asn1_method_st, *Pevp_pkey_asn1_method_st;

typedef struct X509_pubkey_st X509_pubkey_st, *PX509_pubkey_st;

typedef struct X509_pubkey_st X509_PUBKEY;

typedef struct bio_st bio_st, *Pbio_st;

typedef struct bio_st BIO;

typedef struct asn1_pctx_st asn1_pctx_st, *Pasn1_pctx_st;

typedef struct asn1_pctx_st ASN1_PCTX;

typedef struct pkcs8_priv_key_info_st pkcs8_priv_key_info_st, *Ppkcs8_priv_key_info_st;

typedef struct pkcs8_priv_key_info_st PKCS8_PRIV_KEY_INFO;

typedef struct env_md_ctx_st env_md_ctx_st, *Penv_md_ctx_st;

typedef struct env_md_ctx_st EVP_MD_CTX;

typedef struct ASN1_ITEM_st ASN1_ITEM_st, *PASN1_ITEM_st;

typedef struct ASN1_ITEM_st ASN1_ITEM;

typedef struct evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;


// WARNING! conflicting data type names: /DWARF/ossl_typ.h/ENGINE - /ossl_typ.h/ENGINE

typedef union anon_union_4_5_72b9019e_for_pkey anon_union_4_5_72b9019e_for_pkey, *Panon_union_4_5_72b9019e_for_pkey;

typedef struct stack_st_X509_NAME_ENTRY stack_st_X509_NAME_ENTRY, *Pstack_st_X509_NAME_ENTRY;

typedef struct buf_mem_st buf_mem_st, *Pbuf_mem_st;

typedef struct buf_mem_st BUF_MEM;

typedef struct bio_method_st bio_method_st, *Pbio_method_st;

typedef struct bio_method_st BIO_METHOD;

typedef struct crypto_ex_data_st crypto_ex_data_st, *Pcrypto_ex_data_st;

typedef struct crypto_ex_data_st CRYPTO_EX_DATA;

typedef struct env_md_st env_md_st, *Penv_md_st;

typedef struct env_md_st EVP_MD;

typedef struct evp_pkey_ctx_st evp_pkey_ctx_st, *Pevp_pkey_ctx_st;

typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

typedef struct ASN1_TEMPLATE_st ASN1_TEMPLATE_st, *PASN1_TEMPLATE_st;

typedef struct ASN1_TEMPLATE_st ASN1_TEMPLATE;

typedef struct rsa_st rsa_st, *Prsa_st;

typedef struct dsa_st dsa_st, *Pdsa_st;

typedef struct dh_st dh_st, *Pdh_st;

typedef struct ec_key_st ec_key_st, *Pec_key_st;

typedef struct stack_st_void stack_st_void, *Pstack_st_void;

typedef struct evp_pkey_method_st evp_pkey_method_st, *Pevp_pkey_method_st;

typedef struct evp_pkey_method_st EVP_PKEY_METHOD;

typedef ASN1_ITEM ASN1_ITEM_EXP;

typedef struct rsa_meth_st rsa_meth_st, *Prsa_meth_st;

typedef struct rsa_st RSA;

typedef struct bignum_st bignum_st, *Pbignum_st;

typedef struct bignum_st BIGNUM;

typedef struct bignum_ctx bignum_ctx, *Pbignum_ctx;

typedef struct bignum_ctx BN_CTX;

typedef struct bn_mont_ctx_st bn_mont_ctx_st, *Pbn_mont_ctx_st;

typedef struct bn_mont_ctx_st BN_MONT_CTX;

typedef struct bn_gencb_st bn_gencb_st, *Pbn_gencb_st;

typedef struct bn_gencb_st BN_GENCB;

typedef struct rsa_meth_st RSA_METHOD;

typedef struct bn_blinding_st bn_blinding_st, *Pbn_blinding_st;

typedef struct bn_blinding_st BN_BLINDING;

typedef struct dsa_method dsa_method, *Pdsa_method;

typedef struct DSA_SIG_st DSA_SIG_st, *PDSA_SIG_st;

typedef struct DSA_SIG_st DSA_SIG;

typedef struct dsa_st DSA;

typedef struct dsa_method DSA_METHOD;

typedef struct dh_method dh_method, *Pdh_method;

typedef struct dh_st DH;

typedef struct dh_method DH_METHOD;

typedef struct ec_group_st ec_group_st, *Pec_group_st;

typedef struct ec_group_st EC_GROUP;

typedef struct ec_point_st ec_point_st, *Pec_point_st;

typedef struct ec_point_st EC_POINT;

typedef enum point_conversion_form_t {
    POINT_CONVERSION_COMPRESSED=2,
    POINT_CONVERSION_UNCOMPRESSED=4,
    POINT_CONVERSION_HYBRID=6
} point_conversion_form_t;

typedef struct ec_extra_data_st ec_extra_data_st, *Pec_extra_data_st;

typedef struct ec_extra_data_st EC_EXTRA_DATA;

typedef struct bignum_pool bignum_pool, *Pbignum_pool;

typedef struct bignum_pool BN_POOL;

typedef struct bignum_ctx_stack bignum_ctx_stack, *Pbignum_ctx_stack;

typedef struct bignum_ctx_stack BN_STACK;

typedef union anon_union_4_2_314529c2_for_cb anon_union_4_2_314529c2_for_cb, *Panon_union_4_2_314529c2_for_cb;

typedef struct crypto_threadid_st crypto_threadid_st, *Pcrypto_threadid_st;

typedef struct crypto_threadid_st CRYPTO_THREADID;

typedef struct ec_method_st ec_method_st, *Pec_method_st;

typedef struct ec_method_st EC_METHOD;

typedef struct bignum_pool_item bignum_pool_item, *Pbignum_pool_item;

typedef struct bignum_pool_item BN_POOL_ITEM;

union anon_union_4_2_314529c2_for_cb {
    void (*cb_1)(int, int, void *);
    int (*cb_2)(int, int, BN_GENCB *);
};

struct bn_gencb_st {
    uint ver;
    void *arg;
    union anon_union_4_2_314529c2_for_cb cb;
};

struct crypto_ex_data_st {
    struct stack_st_void *sk;
    int dummy;
};

struct ec_extra_data_st {
    struct ec_extra_data_st *next;
    void *data;
    void * (*dup_func)(void *);
    void (*free_func)(void *);
    void (*clear_free_func)(void *);
};

struct ec_method_st {
    int flags;
    int field_type;
    int (*group_init)(EC_GROUP *);
    void (*group_finish)(EC_GROUP *);
    void (*group_clear_finish)(EC_GROUP *);
    int (*group_copy)(EC_GROUP *, EC_GROUP *);
    int (*group_set_curve)(EC_GROUP *, BIGNUM *, BIGNUM *, BIGNUM *, BN_CTX *);
    int (*group_get_curve)(EC_GROUP *, BIGNUM *, BIGNUM *, BIGNUM *, BN_CTX *);
    int (*group_get_degree)(EC_GROUP *);
    int (*group_check_discriminant)(EC_GROUP *, BN_CTX *);
    int (*point_init)(EC_POINT *);
    void (*point_finish)(EC_POINT *);
    void (*point_clear_finish)(EC_POINT *);
    int (*point_copy)(EC_POINT *, EC_POINT *);
    int (*point_set_to_infinity)(EC_GROUP *, EC_POINT *);
    int (*point_set_Jprojective_coordinates_GFp)(EC_GROUP *, EC_POINT *, BIGNUM *, BIGNUM *, BIGNUM *, BN_CTX *);
    int (*point_get_Jprojective_coordinates_GFp)(EC_GROUP *, EC_POINT *, BIGNUM *, BIGNUM *, BIGNUM *, BN_CTX *);
    int (*point_set_affine_coordinates)(EC_GROUP *, EC_POINT *, BIGNUM *, BIGNUM *, BN_CTX *);
    int (*point_get_affine_coordinates)(EC_GROUP *, EC_POINT *, BIGNUM *, BIGNUM *, BN_CTX *);
    int (*point_set_compressed_coordinates)(EC_GROUP *, EC_POINT *, BIGNUM *, int, BN_CTX *);
    size_t (*point2oct)(EC_GROUP *, EC_POINT *, enum point_conversion_form_t, uchar *, size_t, BN_CTX *);
    int (*oct2point)(EC_GROUP *, EC_POINT *, uchar *, size_t, BN_CTX *);
    int (*add)(EC_GROUP *, EC_POINT *, EC_POINT *, EC_POINT *, BN_CTX *);
    int (*dbl)(EC_GROUP *, EC_POINT *, EC_POINT *, BN_CTX *);
    int (*invert)(EC_GROUP *, EC_POINT *, BN_CTX *);
    int (*is_at_infinity)(EC_GROUP *, EC_POINT *);
    int (*is_on_curve)(EC_GROUP *, EC_POINT *, BN_CTX *);
    int (*point_cmp)(EC_GROUP *, EC_POINT *, EC_POINT *, BN_CTX *);
    int (*make_affine)(EC_GROUP *, EC_POINT *, BN_CTX *);
    int (*points_make_affine)(EC_GROUP *, size_t, EC_POINT **, BN_CTX *);
    int (*mul)(EC_GROUP *, EC_POINT *, BIGNUM *, size_t, EC_POINT **, BIGNUM **, BN_CTX *);
    int (*precompute_mult)(EC_GROUP *, BN_CTX *);
    int (*have_precompute_mult)(EC_GROUP *);
    int (*field_mul)(EC_GROUP *, BIGNUM *, BIGNUM *, BIGNUM *, BN_CTX *);
    int (*field_sqr)(EC_GROUP *, BIGNUM *, BIGNUM *, BN_CTX *);
    int (*field_div)(EC_GROUP *, BIGNUM *, BIGNUM *, BIGNUM *, BN_CTX *);
    int (*field_encode)(EC_GROUP *, BIGNUM *, BIGNUM *, BN_CTX *);
    int (*field_decode)(EC_GROUP *, BIGNUM *, BIGNUM *, BN_CTX *);
    int (*field_set_to_one)(EC_GROUP *, BIGNUM *, BN_CTX *);
};

struct env_md_ctx_st {
    EVP_MD *digest;
    ENGINE *engine;
    ulong flags;
    void *md_data;
    EVP_PKEY_CTX *pctx;
    int (*update)(EVP_MD_CTX *, void *, size_t);
};

struct rsa_st {
    int pad;
    long version;
    RSA_METHOD *meth;
    ENGINE *engine;
    BIGNUM *n;
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *dmp1;
    BIGNUM *dmq1;
    BIGNUM *iqmp;
    CRYPTO_EX_DATA ex_data;
    int references;
    int flags;
    BN_MONT_CTX *_method_mod_n;
    BN_MONT_CTX *_method_mod_p;
    BN_MONT_CTX *_method_mod_q;
    char *bignum_data;
    BN_BLINDING *blinding;
    BN_BLINDING *mt_blinding;
};

struct pkcs8_priv_key_info_st {
    int broken;
    ASN1_INTEGER *version;
    X509_ALGOR *pkeyalg;
    ASN1_TYPE *pkey;
    struct stack_st_X509_ATTRIBUTE *attributes;
};

struct evp_pkey_asn1_method_st {
    int pkey_id;
    int pkey_base_id;
    ulong pkey_flags;
    char *pem_str;
    char *info;
    int (*pub_decode)(EVP_PKEY *, X509_PUBKEY *);
    int (*pub_encode)(X509_PUBKEY *, EVP_PKEY *);
    int (*pub_cmp)(EVP_PKEY *, EVP_PKEY *);
    int (*pub_print)(BIO *, EVP_PKEY *, int, ASN1_PCTX *);
    int (*priv_decode)(EVP_PKEY *, PKCS8_PRIV_KEY_INFO *);
    int (*priv_encode)(PKCS8_PRIV_KEY_INFO *, EVP_PKEY *);
    int (*priv_print)(BIO *, EVP_PKEY *, int, ASN1_PCTX *);
    int (*pkey_size)(EVP_PKEY *);
    int (*pkey_bits)(EVP_PKEY *);
    int (*param_decode)(EVP_PKEY *, uchar **, int);
    int (*param_encode)(EVP_PKEY *, uchar **);
    int (*param_missing)(EVP_PKEY *);
    int (*param_copy)(EVP_PKEY *, EVP_PKEY *);
    int (*param_cmp)(EVP_PKEY *, EVP_PKEY *);
    int (*param_print)(BIO *, EVP_PKEY *, int, ASN1_PCTX *);
    int (*sig_print)(BIO *, X509_ALGOR *, ASN1_STRING *, int, ASN1_PCTX *);
    void (*pkey_free)(EVP_PKEY *);
    int (*pkey_ctrl)(EVP_PKEY *, int, long, void *);
    int (*old_priv_decode)(EVP_PKEY *, uchar **, int);
    int (*old_priv_encode)(EVP_PKEY *, uchar **);
    int (*item_verify)(EVP_MD_CTX *, ASN1_ITEM *, void *, X509_ALGOR *, ASN1_BIT_STRING *, EVP_PKEY *);
    int (*item_sign)(EVP_MD_CTX *, ASN1_ITEM *, void *, X509_ALGOR *, X509_ALGOR *, ASN1_BIT_STRING *);
};

struct dh_st {
    int pad;
    int version;
    BIGNUM *p;
    BIGNUM *g;
    long length;
    BIGNUM *pub_key;
    BIGNUM *priv_key;
    int flags;
    BN_MONT_CTX *method_mont_p;
    BIGNUM *q;
    BIGNUM *j;
    uchar *seed;
    int seedlen;
    BIGNUM *counter;
    int references;
    CRYPTO_EX_DATA ex_data;
    DH_METHOD *meth;
    ENGINE *engine;
};

struct bio_st {
    BIO_METHOD *method;
    long (*callback)(struct bio_st *, int, char *, int, long, long);
    char *cb_arg;
    int init;
    int shutdown;
    int flags;
    int retry_reason;
    int num;
    void *ptr;
    struct bio_st *next_bio;
    struct bio_st *prev_bio;
    int references;
    ulong num_read;
    ulong num_write;
    CRYPTO_EX_DATA ex_data;
};

struct X509_pubkey_st {
    X509_ALGOR *algor;
    ASN1_BIT_STRING *public_key;
    EVP_PKEY *pkey;
};

struct ASN1_TEMPLATE_st {
    ulong flags;
    long tag;
    ulong offset;
    char *field_name;
    ASN1_ITEM_EXP *item;
};

struct bignum_st {
    uint *d;
    int top;
    int dmax;
    int neg;
    int flags;
};

struct bignum_pool_item {
    BIGNUM vals[16];
    struct bignum_pool_item *prev;
    struct bignum_pool_item *next;
};

struct crypto_threadid_st {
    void *ptr;
    ulong val;
};

struct bn_blinding_st {
    BIGNUM *A;
    BIGNUM *Ai;
    BIGNUM *e;
    BIGNUM *mod;
    ulong thread_id;
    CRYPTO_THREADID tid;
    int counter;
    ulong flags;
    BN_MONT_CTX *m_ctx;
    int (*bn_mod_exp)(BIGNUM *, BIGNUM *, BIGNUM *, BIGNUM *, BN_CTX *, BN_MONT_CTX *);
};

struct ec_group_st {
    EC_METHOD *meth;
    EC_POINT *generator;
    BIGNUM order;
    BIGNUM cofactor;
    int curve_name;
    int asn1_flag;
    enum point_conversion_form_t asn1_form;
    uchar *seed;
    size_t seed_len;
    EC_EXTRA_DATA *extra_data;
    BIGNUM field;
    int poly[6];
    BIGNUM a;
    BIGNUM b;
    int a_is_minus3;
    void *field_data1;
    void *field_data2;
    int (*field_mod_func)(BIGNUM *, BIGNUM *, BIGNUM *, BN_CTX *);
    BN_MONT_CTX *mont_data;
};

struct dh_method {
    char *name;
    int (*generate_key)(DH *);
    int (*compute_key)(uchar *, BIGNUM *, DH *);
    int (*bn_mod_exp)(DH *, BIGNUM *, BIGNUM *, BIGNUM *, BIGNUM *, BN_CTX *, BN_MONT_CTX *);
    int (*init)(DH *);
    int (*finish)(DH *);
    int flags;
    char *app_data;
    int (*generate_params)(DH *, int, int, BN_GENCB *);
};

struct asn1_pctx_st {
    ulong flags;
    ulong nm_flags;
    ulong cert_flags;
    ulong oid_flags;
    ulong str_flags;
};

struct buf_mem_st {
    size_t length;
    char *data;
    size_t max;
};

struct ASN1_ITEM_st {
    char itype;
    long utype;
    ASN1_TEMPLATE *templates;
    long tcount;
    void *funcs;
    long size;
    char *sname;
};

struct evp_pkey_ctx_st {
    EVP_PKEY_METHOD *pmeth;
    ENGINE *engine;
    EVP_PKEY *pkey;
    EVP_PKEY *peerkey;
    int operation;
    void *data;
    void *app_data;
    int (*pkey_gencb)(EVP_PKEY_CTX *);
    int *keygen_info;
    int keygen_info_count;
};

struct stack_st_X509_ATTRIBUTE {
    _STACK stack;
};

struct env_md_st {
    int type;
    int pkey_type;
    int md_size;
    ulong flags;
    int (*init)(EVP_MD_CTX *);
    int (*update)(EVP_MD_CTX *, void *, size_t);
    int (*final)(EVP_MD_CTX *, uchar *);
    int (*copy)(EVP_MD_CTX *, EVP_MD_CTX *);
    int (*cleanup)(EVP_MD_CTX *);
    int (*sign)(int, uchar *, uint, uchar *, uint *, void *);
    int (*verify)(int, uchar *, uint, uchar *, uint, void *);
    int required_pkey_type[5];
    int block_size;
    int ctx_size;
    int (*md_ctrl)(EVP_MD_CTX *, int, int, void *);
};

union anon_union_4_5_72b9019e_for_pkey {
    char *ptr;
    struct rsa_st *rsa;
    struct dsa_st *dsa;
    struct dh_st *dh;
    struct ec_key_st *ec;
};

struct stack_st_void {
    _STACK stack;
};

struct ec_key_st {
    int version;
    EC_GROUP *group;
    EC_POINT *pub_key;
    BIGNUM *priv_key;
    uint enc_flag;
    enum point_conversion_form_t conv_form;
    int references;
    int flags;
    EC_EXTRA_DATA *method_data;
};

struct X509_name_st {
    struct stack_st_X509_NAME_ENTRY *entries;
    int modified;
    BUF_MEM *bytes;
    uchar *canon_enc;
    int canon_enclen;
};

struct pkcs7_signer_info_st {
    ASN1_INTEGER *version;
    PKCS7_ISSUER_AND_SERIAL *issuer_and_serial;
    X509_ALGOR *digest_alg;
    struct stack_st_X509_ATTRIBUTE *auth_attr;
    X509_ALGOR *digest_enc_alg;
    ASN1_OCTET_STRING *enc_digest;
    struct stack_st_X509_ATTRIBUTE *unauth_attr;
    EVP_PKEY *pkey;
};

struct bignum_ctx_stack {
    uint *indexes;
    uint depth;
    uint size;
};

struct bignum_pool {
    BN_POOL_ITEM *head;
    BN_POOL_ITEM *current;
    BN_POOL_ITEM *tail;
    uint used;
    uint size;
};

struct bignum_ctx {
    BN_POOL pool;
    BN_STACK stack;
    uint used;
    int err_stack;
    int too_many;
};

struct dsa_st {
    int pad;
    long version;
    int write_params;
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *g;
    BIGNUM *pub_key;
    BIGNUM *priv_key;
    BIGNUM *kinv;
    BIGNUM *r;
    int flags;
    BN_MONT_CTX *method_mont_p;
    int references;
    CRYPTO_EX_DATA ex_data;
    DSA_METHOD *meth;
    ENGINE *engine;
};

struct DSA_SIG_st {
    BIGNUM *r;
    BIGNUM *s;
};

struct evp_pkey_method_st {
    int pkey_id;
    int flags;
    int (*init)(EVP_PKEY_CTX *);
    int (*copy)(EVP_PKEY_CTX *, EVP_PKEY_CTX *);
    void (*cleanup)(EVP_PKEY_CTX *);
    int (*paramgen_init)(EVP_PKEY_CTX *);
    int (*paramgen)(EVP_PKEY_CTX *, EVP_PKEY *);
    int (*keygen_init)(EVP_PKEY_CTX *);
    int (*keygen)(EVP_PKEY_CTX *, EVP_PKEY *);
    int (*sign_init)(EVP_PKEY_CTX *);
    int (*sign)(EVP_PKEY_CTX *, uchar *, size_t *, uchar *, size_t);
    int (*verify_init)(EVP_PKEY_CTX *);
    int (*verify)(EVP_PKEY_CTX *, uchar *, size_t, uchar *, size_t);
    int (*verify_recover_init)(EVP_PKEY_CTX *);
    int (*verify_recover)(EVP_PKEY_CTX *, uchar *, size_t *, uchar *, size_t);
    int (*signctx_init)(EVP_PKEY_CTX *, EVP_MD_CTX *);
    int (*signctx)(EVP_PKEY_CTX *, uchar *, size_t *, EVP_MD_CTX *);
    int (*verifyctx_init)(EVP_PKEY_CTX *, EVP_MD_CTX *);
    int (*verifyctx)(EVP_PKEY_CTX *, uchar *, int, EVP_MD_CTX *);
    int (*encrypt_init)(EVP_PKEY_CTX *);
    int (*encrypt)(EVP_PKEY_CTX *, uchar *, size_t *, uchar *, size_t);
    int (*decrypt_init)(EVP_PKEY_CTX *);
    int (*decrypt)(EVP_PKEY_CTX *, uchar *, size_t *, uchar *, size_t);
    int (*derive_init)(EVP_PKEY_CTX *);
    int (*derive)(EVP_PKEY_CTX *, uchar *, size_t *);
    int (*ctrl)(EVP_PKEY_CTX *, int, int, void *);
    int (*ctrl_str)(EVP_PKEY_CTX *, char *, char *);
};

struct rsa_meth_st {
    char *name;
    int (*rsa_pub_enc)(int, uchar *, uchar *, RSA *, int);
    int (*rsa_pub_dec)(int, uchar *, uchar *, RSA *, int);
    int (*rsa_priv_enc)(int, uchar *, uchar *, RSA *, int);
    int (*rsa_priv_dec)(int, uchar *, uchar *, RSA *, int);
    int (*rsa_mod_exp)(BIGNUM *, BIGNUM *, RSA *, BN_CTX *);
    int (*bn_mod_exp)(BIGNUM *, BIGNUM *, BIGNUM *, BIGNUM *, BN_CTX *, BN_MONT_CTX *);
    int (*init)(RSA *);
    int (*finish)(RSA *);
    int flags;
    char *app_data;
    int (*rsa_sign)(int, uchar *, uint, uchar *, uint *, RSA *);
    int (*rsa_verify)(int, uchar *, uint, uchar *, uint, RSA *);
    int (*rsa_keygen)(RSA *, int, BIGNUM *, BN_GENCB *);
};

struct bio_method_st {
    int type;
    char *name;
    int (*bwrite)(BIO *, char *, int);
    int (*bread)(BIO *, char *, int);
    int (*bputs)(BIO *, char *);
    int (*bgets)(BIO *, char *, int);
    long (*ctrl)(BIO *, int, long, void *);
    int (*create)(BIO *);
    int (*destroy)(BIO *);
    long (*callback_ctrl)(BIO *, int, void (*)(struct bio_st *, int, char *, int, long, long));
};

struct stack_st_X509_NAME_ENTRY {
    _STACK stack;
};

struct dsa_method {
    char *name;
    DSA_SIG * (*dsa_do_sign)(uchar *, int, DSA *);
    int (*dsa_sign_setup)(DSA *, BN_CTX *, BIGNUM **, BIGNUM **);
    int (*dsa_do_verify)(uchar *, int, DSA_SIG *, DSA *);
    int (*dsa_mod_exp)(DSA *, BIGNUM *, BIGNUM *, BIGNUM *, BIGNUM *, BIGNUM *, BIGNUM *, BN_CTX *, BN_MONT_CTX *);
    int (*bn_mod_exp)(DSA *, BIGNUM *, BIGNUM *, BIGNUM *, BIGNUM *, BN_CTX *, BN_MONT_CTX *);
    int (*init)(DSA *);
    int (*finish)(DSA *);
    int flags;
    char *app_data;
    int (*dsa_paramgen)(DSA *, int, uchar *, int, int *, ulong *, BN_GENCB *);
    int (*dsa_keygen)(DSA *);
};

struct evp_pkey_st {
    int type;
    int save_type;
    int references;
    EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *engine;
    union anon_union_4_5_72b9019e_for_pkey pkey;
    int save_parameters;
    struct stack_st_X509_ATTRIBUTE *attributes;
};

struct pkcs7_issuer_and_serial_st {
    X509_NAME *issuer;
    ASN1_INTEGER *serial;
};

struct bn_mont_ctx_st {
    int ri;
    BIGNUM RR;
    BIGNUM N;
    BIGNUM Ni;
    uint n0[2];
    int flags;
};

struct ec_point_st {
    EC_METHOD *meth;
    BIGNUM X;
    BIGNUM Y;
    BIGNUM Z;
    int Z_is_one;
};

typedef struct pkcs7_recip_info_st pkcs7_recip_info_st, *Ppkcs7_recip_info_st;

typedef struct pkcs7_recip_info_st PKCS7_RECIP_INFO;

typedef struct x509_st x509_st, *Px509_st;

typedef struct x509_st X509;

typedef struct x509_cinf_st x509_cinf_st, *Px509_cinf_st;

typedef struct x509_cinf_st X509_CINF;

typedef struct AUTHORITY_KEYID_st AUTHORITY_KEYID_st, *PAUTHORITY_KEYID_st;

typedef struct AUTHORITY_KEYID_st AUTHORITY_KEYID;

typedef struct X509_POLICY_CACHE_st X509_POLICY_CACHE_st, *PX509_POLICY_CACHE_st;

typedef struct X509_POLICY_CACHE_st X509_POLICY_CACHE;

typedef struct stack_st_DIST_POINT stack_st_DIST_POINT, *Pstack_st_DIST_POINT;

typedef struct stack_st_GENERAL_NAME stack_st_GENERAL_NAME, *Pstack_st_GENERAL_NAME;

typedef struct NAME_CONSTRAINTS_st NAME_CONSTRAINTS_st, *PNAME_CONSTRAINTS_st;

typedef struct NAME_CONSTRAINTS_st NAME_CONSTRAINTS;

typedef struct x509_cert_aux_st x509_cert_aux_st, *Px509_cert_aux_st;

typedef struct x509_cert_aux_st X509_CERT_AUX;

typedef struct X509_val_st X509_val_st, *PX509_val_st;

typedef struct X509_val_st X509_VAL;

typedef struct stack_st_X509_EXTENSION stack_st_X509_EXTENSION, *Pstack_st_X509_EXTENSION;

typedef struct ASN1_ENCODING_st ASN1_ENCODING_st, *PASN1_ENCODING_st;

typedef struct ASN1_ENCODING_st ASN1_ENCODING;

typedef struct stack_st_GENERAL_NAME GENERAL_NAMES;

typedef struct X509_POLICY_DATA_st X509_POLICY_DATA_st, *PX509_POLICY_DATA_st;

typedef struct X509_POLICY_DATA_st X509_POLICY_DATA;

typedef struct stack_st_X509_POLICY_DATA stack_st_X509_POLICY_DATA, *Pstack_st_X509_POLICY_DATA;

typedef struct stack_st_GENERAL_SUBTREE stack_st_GENERAL_SUBTREE, *Pstack_st_GENERAL_SUBTREE;

typedef struct stack_st_ASN1_OBJECT stack_st_ASN1_OBJECT, *Pstack_st_ASN1_OBJECT;

typedef struct asn1_string_st ASN1_TIME;

typedef struct stack_st_POLICYQUALINFO stack_st_POLICYQUALINFO, *Pstack_st_POLICYQUALINFO;

struct ASN1_ENCODING_st {
    uchar *enc;
    long len;
    int modified;
};

struct x509_cinf_st {
    ASN1_INTEGER *version;
    ASN1_INTEGER *serialNumber;
    X509_ALGOR *signature;
    X509_NAME *issuer;
    X509_VAL *validity;
    X509_NAME *subject;
    X509_PUBKEY *key;
    ASN1_BIT_STRING *issuerUID;
    ASN1_BIT_STRING *subjectUID;
    struct stack_st_X509_EXTENSION *extensions;
    ASN1_ENCODING enc;
};

struct AUTHORITY_KEYID_st {
    ASN1_OCTET_STRING *keyid;
    GENERAL_NAMES *issuer;
    ASN1_INTEGER *serial;
};

struct pkcs7_recip_info_st {
    ASN1_INTEGER *version;
    PKCS7_ISSUER_AND_SERIAL *issuer_and_serial;
    X509_ALGOR *key_enc_algor;
    ASN1_OCTET_STRING *enc_key;
    X509 *cert;
};

struct stack_st_DIST_POINT {
    _STACK stack;
};

struct NAME_CONSTRAINTS_st {
    struct stack_st_GENERAL_SUBTREE *permittedSubtrees;
    struct stack_st_GENERAL_SUBTREE *excludedSubtrees;
};

struct stack_st_X509_POLICY_DATA {
    _STACK stack;
};

struct X509_POLICY_DATA_st {
    uint flags;
    ASN1_OBJECT *valid_policy;
    struct stack_st_POLICYQUALINFO *qualifier_set;
    struct stack_st_ASN1_OBJECT *expected_policy_set;
};

struct x509_st {
    X509_CINF *cert_info;
    X509_ALGOR *sig_alg;
    ASN1_BIT_STRING *signature;
    int valid;
    int references;
    char *name;
    CRYPTO_EX_DATA ex_data;
    long ex_pathlen;
    long ex_pcpathlen;
    ulong ex_flags;
    ulong ex_kusage;
    ulong ex_xkusage;
    ulong ex_nscert;
    ASN1_OCTET_STRING *skid;
    AUTHORITY_KEYID *akid;
    X509_POLICY_CACHE *policy_cache;
    struct stack_st_DIST_POINT *crldp;
    struct stack_st_GENERAL_NAME *altname;
    NAME_CONSTRAINTS *nc;
    uchar sha1_hash[20];
    X509_CERT_AUX *aux;
};

struct X509_val_st {
    ASN1_TIME *notBefore;
    ASN1_TIME *notAfter;
};

struct stack_st_X509_EXTENSION {
    _STACK stack;
};

struct stack_st_ASN1_OBJECT {
    _STACK stack;
};

struct X509_POLICY_CACHE_st {
    X509_POLICY_DATA *anyPolicy;
    struct stack_st_X509_POLICY_DATA *data;
    long any_skip;
    long explicit_skip;
    long map_skip;
};

struct stack_st_POLICYQUALINFO {
    _STACK stack;
};

struct stack_st_GENERAL_SUBTREE {
    _STACK stack;
};

struct x509_cert_aux_st {
    struct stack_st_ASN1_OBJECT *trust;
    struct stack_st_ASN1_OBJECT *reject;
    ASN1_UTF8STRING *alias;
    ASN1_OCTET_STRING *keyid;
    struct stack_st_X509_ALGOR *other;
};

struct stack_st_GENERAL_NAME {
    _STACK stack;
};

typedef struct pkcs7_st PKCS7;

typedef struct stack_st_PKCS7 stack_st_PKCS7, *Pstack_st_PKCS7;

struct stack_st_PKCS7 {
    _STACK stack;
};

typedef struct tech_dbdata tech_dbdata, *Ptech_dbdata;

typedef struct tech_dbdata TECH_DBDATA;

typedef union db_Value_union db_Value_union, *Pdb_Value_union;

typedef union db_Value_union DBVALUE;

union db_Value_union {
    uchar cdata;
    ushort sdata;
    ulong ldata;
    uint dwdata;
    char string[40];
};

struct tech_dbdata {
    char str[16384];
    ushort u16SrtLen;
    uchar u8DBVal[8192];
    ushort u16DataLen;
    DBVALUE Value;
    ulong Value_ID;
    char *Name;
    char *DescriptionC;
    char *DescriptionE;
    char Precision;
    char Datatype;
    uint Groups;
};

typedef struct dbdata_desc_54_52 dbdata_desc_54_52, *Pdbdata_desc_54_52;

typedef struct dbdata_desc_54_52 DBDATA_DESC_54_52;

struct dbdata_desc_54_52 {
    char Name[32];
    int Address54;
    char Precision54;
    int Address52;
    char Precision52;
    char DescriptionC[32];
};

typedef struct objfolder_HMIVerision objfolder_HMIVerision, *Pobjfolder_HMIVerision;

struct objfolder_HMIVerision {
    char *Name;
    char precision_FT;
    char precision_LJ;
};

typedef struct objfolder_ERROR objfolder_ERROR, *Pobjfolder_ERROR;

typedef struct objfolder_ERROR OBJFOLDER_ERROR;

struct objfolder_ERROR {
    int num;
    char *Name;
};

typedef struct dbdata_desc dbdata_desc, *Pdbdata_desc;

struct dbdata_desc {
    DBVALUE Value;
    int Value_ID;
    char *Name;
    char *DescriptionC;
    char *DescriptionE;
    char Precision;
    char Datatype;
    uint Groups;
};

typedef struct dbdata_desc DBDATA_DESC;

typedef struct objfolder_precision objfolder_precision, *Pobjfolder_precision;

typedef struct objfolder_precision OBJFOLDER_PRECISION;

struct objfolder_precision {
    char *Name;
    char precision_54;
    char precision_52;
    char leng_52;
};

typedef struct objfolder_HMIVerision OBJFOLDER_HMIVERSION;

typedef struct objfolder_desc objfolder_desc, *Pobjfolder_desc;

struct objfolder_desc {
    char *Description;
    char *DisplayName;
    int Num;
};

typedef enum Mode {
    Standard=0,
    General=1,
    Lite=2
} Mode;

typedef struct objfolder_desc OBJFOLDER_DESC;

typedef struct PKCS12 PKCS12, *PPKCS12;

typedef struct PKCS12_MAC_DATA PKCS12_MAC_DATA, *PPKCS12_MAC_DATA;

typedef struct X509_sig_st X509_sig_st, *PX509_sig_st;

typedef struct X509_sig_st X509_SIG;

struct PKCS12 {
    ASN1_INTEGER *version;
    struct PKCS12_MAC_DATA *mac;
    PKCS7 *authsafes;
};

struct PKCS12_MAC_DATA {
    X509_SIG *dinfo;
    ASN1_OCTET_STRING *salt;
    ASN1_INTEGER *iter;
};

struct X509_sig_st {
    X509_ALGOR *algor;
    ASN1_OCTET_STRING *digest;
};

typedef struct pkcs12_bag_st pkcs12_bag_st, *Ppkcs12_bag_st;

typedef union anon_union_4_5_40886c17_for_value anon_union_4_5_40886c17_for_value, *Panon_union_4_5_40886c17_for_value;

union anon_union_4_5_40886c17_for_value {
    ASN1_OCTET_STRING *x509cert;
    ASN1_OCTET_STRING *x509crl;
    ASN1_OCTET_STRING *octet;
    ASN1_IA5STRING *sdsicert;
    ASN1_TYPE *other;
};

struct pkcs12_bag_st {
    ASN1_OBJECT *type;
    union anon_union_4_5_40886c17_for_value value;
};

typedef struct pkcs12_bag_st PKCS12_BAGS;

typedef struct stack_st_PKCS12_SAFEBAG stack_st_PKCS12_SAFEBAG, *Pstack_st_PKCS12_SAFEBAG;

struct stack_st_PKCS12_SAFEBAG {
    _STACK stack;
};

typedef struct PKCS12_SAFEBAG PKCS12_SAFEBAG, *PPKCS12_SAFEBAG;

typedef union anon_union_4_5_9dea7667_for_value anon_union_4_5_9dea7667_for_value, *Panon_union_4_5_9dea7667_for_value;

union anon_union_4_5_9dea7667_for_value {
    struct pkcs12_bag_st *bag;
    struct pkcs8_priv_key_info_st *keybag;
    X509_SIG *shkeybag;
    struct stack_st_PKCS12_SAFEBAG *safes;
    ASN1_TYPE *other;
};

struct PKCS12_SAFEBAG {
    ASN1_OBJECT *type;
    union anon_union_4_5_9dea7667_for_value value;
    struct stack_st_X509_ATTRIBUTE *attrib;
};

typedef struct __va_list __va_list, *P__va_list;

typedef struct __va_list __gnuc_va_list;

struct __va_list {
    void *__ap;
};

typedef struct _xmlExpNode _xmlExpNode, *P_xmlExpNode;

typedef struct _xmlExpNode xmlExpNode;

struct _xmlExpNode {
};

typedef xmlExpNode *xmlExpNodePtr;

typedef struct ECDSA_SIG_st ECDSA_SIG_st, *PECDSA_SIG_st;

typedef struct ECDSA_SIG_st ECDSA_SIG;

struct ECDSA_SIG_st {
    BIGNUM *r;
    BIGNUM *s;
};

typedef void (*__sighandler_t)(int);

typedef __sig_atomic_t sig_atomic_t;

typedef struct ec_privatekey_st ec_privatekey_st, *Pec_privatekey_st;

typedef struct ec_privatekey_st EC_PRIVATEKEY;

typedef struct ecpk_parameters_st ecpk_parameters_st, *Pecpk_parameters_st;

typedef struct ecpk_parameters_st ECPKPARAMETERS;

typedef union anon_union_4_3_63d456ad_for_value anon_union_4_3_63d456ad_for_value, *Panon_union_4_3_63d456ad_for_value;

typedef struct ec_parameters_st ec_parameters_st, *Pec_parameters_st;

typedef struct ec_parameters_st ECPARAMETERS;

typedef struct x9_62_fieldid_st x9_62_fieldid_st, *Px9_62_fieldid_st;

typedef struct x9_62_fieldid_st X9_62_FIELDID;

typedef struct x9_62_curve_st x9_62_curve_st, *Px9_62_curve_st;

typedef struct x9_62_curve_st X9_62_CURVE;

typedef union anon_union_4_4_221cd37f_for_p anon_union_4_4_221cd37f_for_p, *Panon_union_4_4_221cd37f_for_p;

typedef struct x9_62_characteristic_two_st x9_62_characteristic_two_st, *Px9_62_characteristic_two_st;

typedef struct x9_62_characteristic_two_st X9_62_CHARACTERISTIC_TWO;

typedef union anon_union_4_5_cc9f2c01_for_p anon_union_4_5_cc9f2c01_for_p, *Panon_union_4_5_cc9f2c01_for_p;

typedef struct x9_62_pentanomial_st x9_62_pentanomial_st, *Px9_62_pentanomial_st;

typedef struct x9_62_pentanomial_st X9_62_PENTANOMIAL;

union anon_union_4_5_cc9f2c01_for_p {
    char *ptr;
    ASN1_NULL *onBasis;
    ASN1_INTEGER *tpBasis;
    X9_62_PENTANOMIAL *ppBasis;
    ASN1_TYPE *other;
};

struct x9_62_characteristic_two_st {
    long m;
    ASN1_OBJECT *type;
    union anon_union_4_5_cc9f2c01_for_p p;
};

struct ec_parameters_st {
    long version;
    X9_62_FIELDID *fieldID;
    X9_62_CURVE *curve;
    ASN1_OCTET_STRING *base;
    ASN1_INTEGER *order;
    ASN1_INTEGER *cofactor;
};

union anon_union_4_4_221cd37f_for_p {
    char *ptr;
    ASN1_INTEGER *prime;
    X9_62_CHARACTERISTIC_TWO *char_two;
    ASN1_TYPE *other;
};

struct x9_62_fieldid_st {
    ASN1_OBJECT *fieldType;
    union anon_union_4_4_221cd37f_for_p p;
};

struct ec_privatekey_st {
    long version;
    ASN1_OCTET_STRING *privateKey;
    ECPKPARAMETERS *parameters;
    ASN1_BIT_STRING *publicKey;
};

struct x9_62_curve_st {
    ASN1_OCTET_STRING *a;
    ASN1_OCTET_STRING *b;
    ASN1_BIT_STRING *seed;
};

struct x9_62_pentanomial_st {
    long k1;
    long k2;
    long k3;
};

union anon_union_4_3_63d456ad_for_value {
    ASN1_OBJECT *named_curve;
    ECPARAMETERS *parameters;
    ASN1_NULL *implicitlyCA;
};

struct ecpk_parameters_st {
    int type;
    union anon_union_4_3_63d456ad_for_value value;
};

typedef struct DES_ks DES_ks, *PDES_ks;

typedef struct DES_ks DES_key_schedule;

typedef union anon_union_8_2_85ee1207 anon_union_8_2_85ee1207, *Panon_union_8_2_85ee1207;

typedef uchar DES_cblock[8];

union anon_union_8_2_85ee1207 {
    DES_cblock cblock;
    uint deslong[2];
};

struct DES_ks {
    union anon_union_8_2_85ee1207 ks[16];
};

typedef uchar const_DES_cblock[8];

typedef struct HMAC_PKEY_CTX HMAC_PKEY_CTX, *PHMAC_PKEY_CTX;

typedef struct hmac_ctx_st hmac_ctx_st, *Phmac_ctx_st;

typedef struct hmac_ctx_st HMAC_CTX;

struct hmac_ctx_st {
    EVP_MD *md;
    EVP_MD_CTX md_ctx;
    EVP_MD_CTX i_ctx;
    EVP_MD_CTX o_ctx;
    uint key_length;
    uchar key[128];
};

struct HMAC_PKEY_CTX {
    EVP_MD *md;
    ASN1_OCTET_STRING ktmp;
    HMAC_CTX ctx;
};


// WARNING! conflicting data type names: /DWARF/libio.h/_IO_marker - /libio.h/_IO_marker


// WARNING! conflicting data type names: /DWARF/libio.h/_IO_FILE - /stdio.h/_IO_FILE

typedef struct tagsignmes tagsignmes, *Ptagsignmes;

struct tagsignmes {
    char signature[344];
    int size;
};

typedef struct tagsignmes Signmes;

typedef struct IPV6_STAT IPV6_STAT, *PIPV6_STAT;

struct IPV6_STAT {
    uchar tmp[16];
    int total;
    int zero_pos;
    int zero_cnt;
};

typedef int (*equal_fn)(uchar *, size_t, uchar *, size_t, uint);

typedef enum __socket_type {
    SOCK_STREAM=1,
    SOCK_DGRAM=2,
    SOCK_RAW=3,
    SOCK_RDM=4,
    SOCK_SEQPACKET=5,
    SOCK_DCCP=6,
    SOCK_PACKET=10,
    SOCK_NONBLOCK=2048,
    SOCK_CLOEXEC=524288
} __socket_type;

typedef struct _xmlError _xmlError, *P_xmlError;

typedef struct _xmlError xmlError;

typedef enum xmlErrorLevel {
    XML_ERR_NONE=0,
    XML_ERR_WARNING=1,
    XML_ERR_ERROR=2,
    XML_ERR_FATAL=3
} xmlErrorLevel;

struct _xmlError {
    int domain;
    int code;
    char *message;
    enum xmlErrorLevel level;
    char *file;
    int line;
    char *str1;
    char *str2;
    char *str3;
    int int1;
    int int2;
    void *ctxt;
    void *node;
};

typedef xmlError *xmlErrorPtr;

typedef void (*xmlStructuredErrorFunc)(void *, xmlErrorPtr);

typedef struct DESX_CBC_KEY DESX_CBC_KEY, *PDESX_CBC_KEY;

struct DESX_CBC_KEY {
    DES_key_schedule ks;
    DES_cblock inw;
    DES_cblock outw;
};

typedef union anon_union_16464_2_9473004f anon_union_16464_2_9473004f, *Panon_union_16464_2_9473004f;

union anon_union_16464_2_9473004f {
    u8 c[16464];
    u64 q[2058];
};

typedef union anon_union_64_2_9473004f anon_union_64_2_9473004f, *Panon_union_64_2_9473004f;

union anon_union_64_2_9473004f {
    u64 q[8];
    u8 c[64];
};

typedef struct ecdh_data_st ecdh_data_st, *Pecdh_data_st;

typedef struct ec_key_st EC_KEY;

typedef struct ecdh_method ecdh_method, *Pecdh_method;

typedef struct ecdh_method ECDH_METHOD;

struct ecdh_method {
    char *name;
    int (*compute_key)(void *, size_t, EC_POINT *, EC_KEY *, void * (*)(void *, size_t, void *, size_t *));
    int flags;
    char *app_data;
};

struct ecdh_data_st {
    int (*init)(EC_KEY *);
    ENGINE *engine;
    int flags;
    ECDH_METHOD *meth;
    CRYPTO_EX_DATA ex_data;
};

typedef struct ecdh_data_st ECDH_DATA;

typedef struct _xmlHashTable _xmlHashTable, *P_xmlHashTable;

typedef struct _xmlHashTable xmlHashTable;

struct _xmlHashTable {
};

typedef xmlHashTable *xmlHashTablePtr;

typedef struct CMS_SharedInfo CMS_SharedInfo, *PCMS_SharedInfo;

struct CMS_SharedInfo {
    X509_ALGOR *keyInfo;
    ASN1_OCTET_STRING *entityUInfo;
    ASN1_OCTET_STRING *suppPubInfo;
};

typedef union anon_union_4_2_e8430b04 anon_union_4_2_e8430b04, *Panon_union_4_2_e8430b04;


// WARNING! conflicting data type names: /DWARF/asn1.h/ASN1_VALUE - /asn1.h/ASN1_VALUE

union anon_union_4_2_e8430b04 {
    struct CMS_SharedInfo *pecsi;
    ASN1_VALUE *a;
};

typedef enum _LIB_VERSION_TYPE {
    _IEEE_=-1,
    _SVID_=0,
    _XOPEN_=1,
    _POSIX_=2,
    _ISOC_=3
} _LIB_VERSION_TYPE;

typedef struct bio_f_buffer_ctx_struct bio_f_buffer_ctx_struct, *Pbio_f_buffer_ctx_struct;

typedef struct bio_f_buffer_ctx_struct BIO_F_BUFFER_CTX;

struct bio_f_buffer_ctx_struct {
    int ibuf_size;
    int obuf_size;
    char *ibuf;
    int ibuf_len;
    int ibuf_off;
    char *obuf;
    int obuf_len;
    int obuf_off;
};

typedef struct stack_st_BIO stack_st_BIO, *Pstack_st_BIO;

struct stack_st_BIO {
    _STACK stack;
};

typedef struct DES_EDE_KEY DES_EDE_KEY, *PDES_EDE_KEY;

typedef union anon_union_384_2_8c9ca482_for_ks anon_union_384_2_8c9ca482_for_ks, *Panon_union_384_2_8c9ca482_for_ks;

typedef union anon_union_4_1_ba1d3b44_for_stream anon_union_4_1_ba1d3b44_for_stream, *Panon_union_4_1_ba1d3b44_for_stream;

union anon_union_384_2_8c9ca482_for_ks {
    double align;
    DES_key_schedule ks[3];
};

union anon_union_4_1_ba1d3b44_for_stream {
    void (*cbc)(void *, void *, size_t, DES_key_schedule *, uchar *);
};

struct DES_EDE_KEY {
    union anon_union_384_2_8c9ca482_for_ks ks;
    union anon_union_4_1_ba1d3b44_for_stream stream;
};

typedef struct CMS_RevocationInfoChoice_st CMS_RevocationInfoChoice_st, *PCMS_RevocationInfoChoice_st;

typedef struct CMS_RevocationInfoChoice_st CMS_RevocationInfoChoice;

typedef union anon_union_4_2_31f6d874_for_d anon_union_4_2_31f6d874_for_d, *Panon_union_4_2_31f6d874_for_d;

typedef struct X509_crl_st X509_crl_st, *PX509_crl_st;

typedef struct X509_crl_st X509_CRL;

typedef struct CMS_OtherRevocationInfoFormat_st CMS_OtherRevocationInfoFormat_st, *PCMS_OtherRevocationInfoFormat_st;

typedef struct CMS_OtherRevocationInfoFormat_st CMS_OtherRevocationInfoFormat;

typedef struct X509_crl_info_st X509_crl_info_st, *PX509_crl_info_st;

typedef struct X509_crl_info_st X509_CRL_INFO;

typedef struct ISSUING_DIST_POINT_st ISSUING_DIST_POINT_st, *PISSUING_DIST_POINT_st;

typedef struct ISSUING_DIST_POINT_st ISSUING_DIST_POINT;

typedef struct stack_st_GENERAL_NAMES stack_st_GENERAL_NAMES, *Pstack_st_GENERAL_NAMES;

typedef struct x509_crl_method_st x509_crl_method_st, *Px509_crl_method_st;

typedef struct x509_revoked_st x509_revoked_st, *Px509_revoked_st;

typedef struct x509_revoked_st X509_REVOKED;

typedef struct x509_crl_method_st X509_CRL_METHOD;

typedef struct stack_st_X509_REVOKED stack_st_X509_REVOKED, *Pstack_st_X509_REVOKED;

typedef struct DIST_POINT_NAME_st DIST_POINT_NAME_st, *PDIST_POINT_NAME_st;

typedef struct DIST_POINT_NAME_st DIST_POINT_NAME;

typedef union anon_union_4_2_ced00d1e_for_name anon_union_4_2_ced00d1e_for_name, *Panon_union_4_2_ced00d1e_for_name;

union anon_union_4_2_31f6d874_for_d {
    X509_CRL *crl;
    CMS_OtherRevocationInfoFormat *other;
};

struct CMS_RevocationInfoChoice_st {
    int type;
    union anon_union_4_2_31f6d874_for_d d;
};

struct x509_crl_method_st {
    int flags;
    int (*crl_init)(X509_CRL *);
    int (*crl_free)(X509_CRL *);
    int (*crl_lookup)(X509_CRL *, X509_REVOKED **, ASN1_INTEGER *, X509_NAME *);
    int (*crl_verify)(X509_CRL *, EVP_PKEY *);
};

struct x509_revoked_st {
    ASN1_INTEGER *serialNumber;
    ASN1_TIME *revocationDate;
    struct stack_st_X509_EXTENSION *extensions;
    struct stack_st_GENERAL_NAME *issuer;
    int reason;
    int sequence;
};

struct ISSUING_DIST_POINT_st {
    DIST_POINT_NAME *distpoint;
    int onlyuser;
    int onlyCA;
    ASN1_BIT_STRING *onlysomereasons;
    int indirectCRL;
    int onlyattr;
};

struct X509_crl_st {
    X509_CRL_INFO *crl;
    X509_ALGOR *sig_alg;
    ASN1_BIT_STRING *signature;
    int references;
    int flags;
    AUTHORITY_KEYID *akid;
    ISSUING_DIST_POINT *idp;
    int idp_flags;
    int idp_reasons;
    ASN1_INTEGER *crl_number;
    ASN1_INTEGER *base_crl_number;
    uchar sha1_hash[20];
    struct stack_st_GENERAL_NAMES *issuers;
    X509_CRL_METHOD *meth;
    void *meth_data;
};

struct X509_crl_info_st {
    ASN1_INTEGER *version;
    X509_ALGOR *sig_alg;
    X509_NAME *issuer;
    ASN1_TIME *lastUpdate;
    ASN1_TIME *nextUpdate;
    struct stack_st_X509_REVOKED *revoked;
    struct stack_st_X509_EXTENSION *extensions;
    ASN1_ENCODING enc;
};

struct stack_st_X509_REVOKED {
    _STACK stack;
};

struct stack_st_GENERAL_NAMES {
    _STACK stack;
};

union anon_union_4_2_ced00d1e_for_name {
    GENERAL_NAMES *fullname;
    struct stack_st_X509_NAME_ENTRY *relativename;
};

struct DIST_POINT_NAME_st {
    int type;
    union anon_union_4_2_ced00d1e_for_name name;
    X509_NAME *dpname;
};

struct CMS_OtherRevocationInfoFormat_st {
    ASN1_OBJECT *otherRevInfoFormat;
    ASN1_TYPE *otherRevInfo;
};

typedef struct CMS_OtherKeyAttribute_st CMS_OtherKeyAttribute_st, *PCMS_OtherKeyAttribute_st;

typedef struct CMS_OtherKeyAttribute_st CMS_OtherKeyAttribute;

struct CMS_OtherKeyAttribute_st {
    ASN1_OBJECT *keyAttrId;
    ASN1_TYPE *keyAttr;
};

typedef struct CMS_SignerInfo_st CMS_SignerInfo_st, *PCMS_SignerInfo_st;

typedef struct CMS_SignerInfo_st CMS_SignerInfo;

typedef struct CMS_SignerIdentifier_st CMS_SignerIdentifier_st, *PCMS_SignerIdentifier_st;

typedef struct CMS_SignerIdentifier_st CMS_SignerIdentifier;

typedef union anon_union_4_2_ee7ba1e0_for_d anon_union_4_2_ee7ba1e0_for_d, *Panon_union_4_2_ee7ba1e0_for_d;

typedef struct CMS_IssuerAndSerialNumber_st CMS_IssuerAndSerialNumber_st, *PCMS_IssuerAndSerialNumber_st;

typedef struct CMS_IssuerAndSerialNumber_st CMS_IssuerAndSerialNumber;

struct CMS_IssuerAndSerialNumber_st {
    X509_NAME *issuer;
    ASN1_INTEGER *serialNumber;
};

union anon_union_4_2_ee7ba1e0_for_d {
    CMS_IssuerAndSerialNumber *issuerAndSerialNumber;
    ASN1_OCTET_STRING *subjectKeyIdentifier;
};

struct CMS_SignerIdentifier_st {
    int type;
    union anon_union_4_2_ee7ba1e0_for_d d;
};

struct CMS_SignerInfo_st {
    long version;
    CMS_SignerIdentifier *sid;
    X509_ALGOR *digestAlgorithm;
    struct stack_st_X509_ATTRIBUTE *signedAttrs;
    X509_ALGOR *signatureAlgorithm;
    ASN1_OCTET_STRING *signature;
    struct stack_st_X509_ATTRIBUTE *unsignedAttrs;
    X509 *signer;
    EVP_PKEY *pkey;
    EVP_MD_CTX mctx;
    EVP_PKEY_CTX *pctx;
};

typedef struct stack_st_CMS_RecipientEncryptedKey stack_st_CMS_RecipientEncryptedKey, *Pstack_st_CMS_RecipientEncryptedKey;

struct stack_st_CMS_RecipientEncryptedKey {
    _STACK stack;
};

typedef struct CMS_ContentInfo_st CMS_ContentInfo_st, *PCMS_ContentInfo_st;

typedef struct CMS_ContentInfo_st CMS_ContentInfo;

typedef union anon_union_4_9_b1472a57_for_d anon_union_4_9_b1472a57_for_d, *Panon_union_4_9_b1472a57_for_d;

typedef struct CMS_SignedData_st CMS_SignedData_st, *PCMS_SignedData_st;

typedef struct CMS_SignedData_st CMS_SignedData;

typedef struct CMS_EnvelopedData_st CMS_EnvelopedData_st, *PCMS_EnvelopedData_st;

typedef struct CMS_EnvelopedData_st CMS_EnvelopedData;

typedef struct CMS_DigestedData_st CMS_DigestedData_st, *PCMS_DigestedData_st;

typedef struct CMS_DigestedData_st CMS_DigestedData;

typedef struct CMS_EncryptedData_st CMS_EncryptedData_st, *PCMS_EncryptedData_st;

typedef struct CMS_EncryptedData_st CMS_EncryptedData;

typedef struct CMS_AuthenticatedData_st CMS_AuthenticatedData_st, *PCMS_AuthenticatedData_st;

typedef struct CMS_AuthenticatedData_st CMS_AuthenticatedData;

typedef struct CMS_CompressedData_st CMS_CompressedData_st, *PCMS_CompressedData_st;

typedef struct CMS_CompressedData_st CMS_CompressedData;

typedef struct CMS_EncapsulatedContentInfo_st CMS_EncapsulatedContentInfo_st, *PCMS_EncapsulatedContentInfo_st;

typedef struct CMS_EncapsulatedContentInfo_st CMS_EncapsulatedContentInfo;

typedef struct stack_st_CMS_CertificateChoices stack_st_CMS_CertificateChoices, *Pstack_st_CMS_CertificateChoices;

typedef struct stack_st_CMS_RevocationInfoChoice stack_st_CMS_RevocationInfoChoice, *Pstack_st_CMS_RevocationInfoChoice;

typedef struct stack_st_CMS_SignerInfo stack_st_CMS_SignerInfo, *Pstack_st_CMS_SignerInfo;

typedef struct CMS_OriginatorInfo_st CMS_OriginatorInfo_st, *PCMS_OriginatorInfo_st;

typedef struct CMS_OriginatorInfo_st CMS_OriginatorInfo;

typedef struct stack_st_CMS_RecipientInfo stack_st_CMS_RecipientInfo, *Pstack_st_CMS_RecipientInfo;

typedef struct CMS_EncryptedContentInfo_st CMS_EncryptedContentInfo_st, *PCMS_EncryptedContentInfo_st;

typedef struct CMS_EncryptedContentInfo_st CMS_EncryptedContentInfo;

struct stack_st_CMS_CertificateChoices {
    _STACK stack;
};

struct CMS_CompressedData_st {
    long version;
    X509_ALGOR *compressionAlgorithm;
    struct stack_st_CMS_RecipientInfo *recipientInfos;
    CMS_EncapsulatedContentInfo *encapContentInfo;
};

struct CMS_SignedData_st {
    long version;
    struct stack_st_X509_ALGOR *digestAlgorithms;
    CMS_EncapsulatedContentInfo *encapContentInfo;
    struct stack_st_CMS_CertificateChoices *certificates;
    struct stack_st_CMS_RevocationInfoChoice *crls;
    struct stack_st_CMS_SignerInfo *signerInfos;
};

struct CMS_DigestedData_st {
    long version;
    X509_ALGOR *digestAlgorithm;
    CMS_EncapsulatedContentInfo *encapContentInfo;
    ASN1_OCTET_STRING *digest;
};

struct CMS_EncryptedData_st {
    long version;
    CMS_EncryptedContentInfo *encryptedContentInfo;
    struct stack_st_X509_ATTRIBUTE *unprotectedAttrs;
};

struct CMS_OriginatorInfo_st {
    struct stack_st_CMS_CertificateChoices *certificates;
    struct stack_st_CMS_RevocationInfoChoice *crls;
};

union anon_union_4_9_b1472a57_for_d {
    ASN1_OCTET_STRING *data;
    CMS_SignedData *signedData;
    CMS_EnvelopedData *envelopedData;
    CMS_DigestedData *digestedData;
    CMS_EncryptedData *encryptedData;
    CMS_AuthenticatedData *authenticatedData;
    CMS_CompressedData *compressedData;
    ASN1_TYPE *other;
    void *otherData;
};

struct stack_st_CMS_RecipientInfo {
    _STACK stack;
};

struct CMS_EncryptedContentInfo_st {
    ASN1_OBJECT *contentType;
    X509_ALGOR *contentEncryptionAlgorithm;
    ASN1_OCTET_STRING *encryptedContent;
    EVP_CIPHER *cipher;
    uchar *key;
    size_t keylen;
    int debug;
};

struct stack_st_CMS_RevocationInfoChoice {
    _STACK stack;
};

struct CMS_EncapsulatedContentInfo_st {
    ASN1_OBJECT *eContentType;
    ASN1_OCTET_STRING *eContent;
    int partial;
};

struct CMS_ContentInfo_st {
    ASN1_OBJECT *contentType;
    union anon_union_4_9_b1472a57_for_d d;
};

struct CMS_AuthenticatedData_st {
    long version;
    CMS_OriginatorInfo *originatorInfo;
    struct stack_st_CMS_RecipientInfo *recipientInfos;
    X509_ALGOR *macAlgorithm;
    X509_ALGOR *digestAlgorithm;
    CMS_EncapsulatedContentInfo *encapContentInfo;
    struct stack_st_X509_ATTRIBUTE *authAttrs;
    ASN1_OCTET_STRING *mac;
    struct stack_st_X509_ATTRIBUTE *unauthAttrs;
};

struct stack_st_CMS_SignerInfo {
    _STACK stack;
};

struct CMS_EnvelopedData_st {
    long version;
    CMS_OriginatorInfo *originatorInfo;
    struct stack_st_CMS_RecipientInfo *recipientInfos;
    CMS_EncryptedContentInfo *encryptedContentInfo;
    struct stack_st_X509_ATTRIBUTE *unprotectedAttrs;
};

typedef struct CMS_RecipientInfo_st CMS_RecipientInfo_st, *PCMS_RecipientInfo_st;

typedef struct CMS_RecipientInfo_st CMS_RecipientInfo;

typedef union anon_union_4_5_88aa0e37_for_d anon_union_4_5_88aa0e37_for_d, *Panon_union_4_5_88aa0e37_for_d;

typedef struct CMS_KeyTransRecipientInfo_st CMS_KeyTransRecipientInfo_st, *PCMS_KeyTransRecipientInfo_st;

typedef struct CMS_KeyTransRecipientInfo_st CMS_KeyTransRecipientInfo;

typedef struct CMS_KeyAgreeRecipientInfo_st CMS_KeyAgreeRecipientInfo_st, *PCMS_KeyAgreeRecipientInfo_st;

typedef struct CMS_KeyAgreeRecipientInfo_st CMS_KeyAgreeRecipientInfo;

typedef struct CMS_KEKRecipientInfo_st CMS_KEKRecipientInfo_st, *PCMS_KEKRecipientInfo_st;

typedef struct CMS_KEKRecipientInfo_st CMS_KEKRecipientInfo;

typedef struct CMS_PasswordRecipientInfo_st CMS_PasswordRecipientInfo_st, *PCMS_PasswordRecipientInfo_st;

typedef struct CMS_PasswordRecipientInfo_st CMS_PasswordRecipientInfo;

typedef struct CMS_OtherRecipientInfo_st CMS_OtherRecipientInfo_st, *PCMS_OtherRecipientInfo_st;

typedef struct CMS_OtherRecipientInfo_st CMS_OtherRecipientInfo;

typedef CMS_SignerIdentifier CMS_RecipientIdentifier;

typedef struct CMS_OriginatorIdentifierOrKey_st CMS_OriginatorIdentifierOrKey_st, *PCMS_OriginatorIdentifierOrKey_st;

typedef struct CMS_OriginatorIdentifierOrKey_st CMS_OriginatorIdentifierOrKey;


// WARNING! conflicting data type names: /DWARF/ossl_typ.h/EVP_CIPHER_CTX - /ossl_typ.h/EVP_CIPHER_CTX

typedef struct CMS_KEKIdentifier_st CMS_KEKIdentifier_st, *PCMS_KEKIdentifier_st;

typedef struct CMS_KEKIdentifier_st CMS_KEKIdentifier;

typedef union anon_union_4_3_0790b0f2_for_d anon_union_4_3_0790b0f2_for_d, *Panon_union_4_3_0790b0f2_for_d;

typedef struct CMS_OriginatorPublicKey_st CMS_OriginatorPublicKey_st, *PCMS_OriginatorPublicKey_st;

typedef struct CMS_OriginatorPublicKey_st CMS_OriginatorPublicKey;

union anon_union_4_3_0790b0f2_for_d {
    CMS_IssuerAndSerialNumber *issuerAndSerialNumber;
    ASN1_OCTET_STRING *subjectKeyIdentifier;
    CMS_OriginatorPublicKey *originatorKey;
};

struct CMS_KEKIdentifier_st {
    ASN1_OCTET_STRING *keyIdentifier;
    ASN1_GENERALIZEDTIME *date;
    CMS_OtherKeyAttribute *other;
};

struct CMS_OriginatorPublicKey_st {
    X509_ALGOR *algorithm;
    ASN1_BIT_STRING *publicKey;
};

union anon_union_4_5_88aa0e37_for_d {
    CMS_KeyTransRecipientInfo *ktri;
    CMS_KeyAgreeRecipientInfo *kari;
    CMS_KEKRecipientInfo *kekri;
    CMS_PasswordRecipientInfo *pwri;
    CMS_OtherRecipientInfo *ori;
};

struct CMS_KeyAgreeRecipientInfo_st {
    long version;
    CMS_OriginatorIdentifierOrKey *originator;
    ASN1_OCTET_STRING *ukm;
    X509_ALGOR *keyEncryptionAlgorithm;
    struct stack_st_CMS_RecipientEncryptedKey *recipientEncryptedKeys;
    EVP_PKEY_CTX *pctx;
    EVP_CIPHER_CTX ctx;
};

struct CMS_OtherRecipientInfo_st {
    ASN1_OBJECT *oriType;
    ASN1_TYPE *oriValue;
};

struct CMS_OriginatorIdentifierOrKey_st {
    int type;
    union anon_union_4_3_0790b0f2_for_d d;
};

struct CMS_KEKRecipientInfo_st {
    long version;
    CMS_KEKIdentifier *kekid;
    X509_ALGOR *keyEncryptionAlgorithm;
    ASN1_OCTET_STRING *encryptedKey;
    uchar *key;
    size_t keylen;
};

struct CMS_KeyTransRecipientInfo_st {
    long version;
    CMS_RecipientIdentifier *rid;
    X509_ALGOR *keyEncryptionAlgorithm;
    ASN1_OCTET_STRING *encryptedKey;
    X509 *recip;
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *pctx;
};

struct CMS_PasswordRecipientInfo_st {
    long version;
    X509_ALGOR *keyDerivationAlgorithm;
    X509_ALGOR *keyEncryptionAlgorithm;
    ASN1_OCTET_STRING *encryptedKey;
    uchar *pass;
    size_t passlen;
};

struct CMS_RecipientInfo_st {
    int type;
    union anon_union_4_5_88aa0e37_for_d d;
};

typedef struct CMS_RecipientEncryptedKey_st CMS_RecipientEncryptedKey_st, *PCMS_RecipientEncryptedKey_st;

typedef struct CMS_RecipientEncryptedKey_st CMS_RecipientEncryptedKey;

typedef struct CMS_KeyAgreeRecipientIdentifier_st CMS_KeyAgreeRecipientIdentifier_st, *PCMS_KeyAgreeRecipientIdentifier_st;

typedef struct CMS_KeyAgreeRecipientIdentifier_st CMS_KeyAgreeRecipientIdentifier;

typedef union anon_union_4_2_5469f80c_for_d anon_union_4_2_5469f80c_for_d, *Panon_union_4_2_5469f80c_for_d;

typedef struct CMS_RecipientKeyIdentifier_st CMS_RecipientKeyIdentifier_st, *PCMS_RecipientKeyIdentifier_st;

typedef struct CMS_RecipientKeyIdentifier_st CMS_RecipientKeyIdentifier;

struct CMS_RecipientEncryptedKey_st {
    CMS_KeyAgreeRecipientIdentifier *rid;
    ASN1_OCTET_STRING *encryptedKey;
    EVP_PKEY *pkey;
};

union anon_union_4_2_5469f80c_for_d {
    CMS_IssuerAndSerialNumber *issuerAndSerialNumber;
    CMS_RecipientKeyIdentifier *rKeyId;
};

struct CMS_KeyAgreeRecipientIdentifier_st {
    int type;
    union anon_union_4_2_5469f80c_for_d d;
};

struct CMS_RecipientKeyIdentifier_st {
    ASN1_OCTET_STRING *subjectKeyIdentifier;
    ASN1_GENERALIZEDTIME *date;
    CMS_OtherKeyAttribute *other;
};

typedef struct _xmlDict _xmlDict, *P_xmlDict;

typedef struct _xmlDict xmlDict;

struct _xmlDict {
};

typedef xmlDict *xmlDictPtr;

typedef struct ec_pre_comp_st ec_pre_comp_st, *Pec_pre_comp_st;

struct ec_pre_comp_st {
    EC_GROUP *group;
    size_t blocksize;
    size_t numblocks;
    size_t w;
    EC_POINT **points;
    size_t num;
    int references;
};

typedef struct ec_pre_comp_st EC_PRE_COMP;

typedef struct rand_meth_st rand_meth_st, *Prand_meth_st;

struct rand_meth_st {
    void (*seed)(void *, int);
    int (*bytes)(uchar *, int);
    void (*cleanup)(void);
    void (*add)(void *, int, double);
    int (*pseudorand)(uchar *, int);
    int (*status)(void);
};

typedef struct EVP_AES_WRAP_CTX EVP_AES_WRAP_CTX, *PEVP_AES_WRAP_CTX;

typedef union anon_union_248_2_8c9ca482_for_ks anon_union_248_2_8c9ca482_for_ks, *Panon_union_248_2_8c9ca482_for_ks;

union anon_union_248_2_8c9ca482_for_ks {
    double align;
    AES_KEY ks;
    undefined1 field2[248]; // Automatically generated padding to match DWARF declared size
};

struct EVP_AES_WRAP_CTX {
    union anon_union_248_2_8c9ca482_for_ks ks;
    uchar *iv;
};

typedef struct EVP_AES_GCM_CTX EVP_AES_GCM_CTX, *PEVP_AES_GCM_CTX;

struct EVP_AES_GCM_CTX {
    union anon_union_248_2_8c9ca482_for_ks ks;
    int key_set;
    int iv_set;
    GCM128_CONTEXT gcm;
    uchar *iv;
    int ivlen;
    int taglen;
    int iv_gen;
    int tls_aad_len;
    ctr128_f ctr;
};

typedef struct EVP_AES_KEY EVP_AES_KEY, *PEVP_AES_KEY;

typedef union anon_union_4_2_43a76a9e_for_stream anon_union_4_2_43a76a9e_for_stream, *Panon_union_4_2_43a76a9e_for_stream;

union anon_union_4_2_43a76a9e_for_stream {
    cbc128_f cbc;
    ctr128_f ctr;
};

struct EVP_AES_KEY {
    union anon_union_248_2_8c9ca482_for_ks ks;
    block128_f block;
    union anon_union_4_2_43a76a9e_for_stream stream;
};

typedef struct EVP_AES_CCM_CTX EVP_AES_CCM_CTX, *PEVP_AES_CCM_CTX;

struct EVP_AES_CCM_CTX {
    union anon_union_248_2_8c9ca482_for_ks ks;
    int key_set;
    int iv_set;
    int tag_set;
    int len_set;
    int L;
    int M;
    CCM128_CONTEXT ccm;
    ccm128_f str;
};

typedef struct EVP_AES_XTS_CTX EVP_AES_XTS_CTX, *PEVP_AES_XTS_CTX;

typedef union anon_union_248_2_8c9ca482_for_ks1_ks2 anon_union_248_2_8c9ca482_for_ks1_ks2, *Panon_union_248_2_8c9ca482_for_ks1_ks2;

union anon_union_248_2_8c9ca482_for_ks1_ks2 {
    double align;
    AES_KEY ks;
    undefined1 field2[248]; // Automatically generated padding to match DWARF declared size
};

struct EVP_AES_XTS_CTX {
    union anon_union_248_2_8c9ca482_for_ks1_ks2 ks1;
    union anon_union_248_2_8c9ca482_for_ks1_ks2 ks2;
    XTS128_CONTEXT xts;
    void (*stream)(uchar *, uchar *, size_t, AES_KEY *, AES_KEY *, uchar *);
};

typedef struct store_method_st store_method_st, *Pstore_method_st;

typedef struct store_method_st STORE_METHOD;

struct store_method_st {
};

typedef struct ocsp_response_st ocsp_response_st, *Pocsp_response_st;

typedef struct ocsp_response_st OCSP_RESPONSE;

typedef struct ocsp_resp_bytes_st ocsp_resp_bytes_st, *Pocsp_resp_bytes_st;

typedef struct ocsp_resp_bytes_st OCSP_RESPBYTES;

struct ocsp_resp_bytes_st {
    ASN1_OBJECT *responseType;
    ASN1_OCTET_STRING *response;
};

struct ocsp_response_st {
    ASN1_ENUMERATED *responseStatus;
    OCSP_RESPBYTES *responseBytes;
};

typedef struct ocsp_responder_id_st ocsp_responder_id_st, *Pocsp_responder_id_st;

typedef struct ocsp_responder_id_st OCSP_RESPID;

typedef union anon_union_4_2_9e5887f9_for_value anon_union_4_2_9e5887f9_for_value, *Panon_union_4_2_9e5887f9_for_value;

union anon_union_4_2_9e5887f9_for_value {
    X509_NAME *byName;
    ASN1_OCTET_STRING *byKey;
};

struct ocsp_responder_id_st {
    int type;
    union anon_union_4_2_9e5887f9_for_value value;
};

typedef struct X509_POLICY_TREE_st X509_POLICY_TREE_st, *PX509_POLICY_TREE_st;

typedef struct X509_POLICY_TREE_st X509_POLICY_TREE;

typedef struct X509_POLICY_LEVEL_st X509_POLICY_LEVEL_st, *PX509_POLICY_LEVEL_st;

typedef struct X509_POLICY_LEVEL_st X509_POLICY_LEVEL;

typedef struct stack_st_X509_POLICY_NODE stack_st_X509_POLICY_NODE, *Pstack_st_X509_POLICY_NODE;

typedef struct X509_POLICY_NODE_st X509_POLICY_NODE_st, *PX509_POLICY_NODE_st;

typedef struct X509_POLICY_NODE_st X509_POLICY_NODE;

struct stack_st_X509_POLICY_NODE {
    _STACK stack;
};

struct X509_POLICY_LEVEL_st {
    X509 *cert;
    struct stack_st_X509_POLICY_NODE *nodes;
    X509_POLICY_NODE *anyPolicy;
    uint flags;
};

struct X509_POLICY_NODE_st {
    X509_POLICY_DATA *data;
    X509_POLICY_NODE *parent;
    int nchild;
};

struct X509_POLICY_TREE_st {
    X509_POLICY_LEVEL *levels;
    int nlevel;
    struct stack_st_X509_POLICY_DATA *extra_data;
    struct stack_st_X509_POLICY_NODE *auth_policies;
    struct stack_st_X509_POLICY_NODE *user_policies;
    uint flags;
};

typedef struct v3_ext_ctx v3_ext_ctx, *Pv3_ext_ctx;

typedef struct v3_ext_ctx X509V3_CTX;

typedef struct X509_req_st X509_req_st, *PX509_req_st;

typedef struct X509_req_st X509_REQ;

typedef struct X509V3_CONF_METHOD_st X509V3_CONF_METHOD_st, *PX509V3_CONF_METHOD_st;

typedef struct stack_st_CONF_VALUE stack_st_CONF_VALUE, *Pstack_st_CONF_VALUE;

typedef struct X509V3_CONF_METHOD_st X509V3_CONF_METHOD;

typedef struct X509_req_info_st X509_req_info_st, *PX509_req_info_st;

typedef struct X509_req_info_st X509_REQ_INFO;

struct X509_req_info_st {
    ASN1_ENCODING enc;
    ASN1_INTEGER *version;
    X509_NAME *subject;
    X509_PUBKEY *pubkey;
    struct stack_st_X509_ATTRIBUTE *attributes;
};

struct stack_st_CONF_VALUE {
    _STACK stack;
};

struct X509_req_st {
    X509_REQ_INFO *req_info;
    X509_ALGOR *sig_alg;
    ASN1_BIT_STRING *signature;
    int references;
};

struct v3_ext_ctx {
    int flags;
    X509 *issuer_cert;
    X509 *subject_cert;
    X509_REQ *subject_req;
    X509_CRL *crl;
    X509V3_CONF_METHOD *db_meth;
    void *db;
};

struct X509V3_CONF_METHOD_st {
    char * (*get_string)(void *, char *, char *);
    stack_st_CONF_VALUE * (*get_section)(void *, char *);
    void (*free_string)(void *, char *);
    void (*free_section)(void *, struct stack_st_CONF_VALUE *);
};

typedef struct ecdsa_method ecdsa_method, *Pecdsa_method;

typedef struct ecdsa_method ECDSA_METHOD;

struct ecdsa_method {
    char *name;
    ECDSA_SIG * (*ecdsa_do_sign)(uchar *, int, BIGNUM *, BIGNUM *, EC_KEY *);
    int (*ecdsa_sign_setup)(EC_KEY *, BN_CTX *, BIGNUM **, BIGNUM **);
    int (*ecdsa_do_verify)(uchar *, int, ECDSA_SIG *, EC_KEY *);
    int flags;
    void *app_data;
};

typedef struct ocsp_req_ctx_st ocsp_req_ctx_st, *Pocsp_req_ctx_st;

typedef struct ocsp_req_ctx_st OCSP_REQ_CTX;

struct ocsp_req_ctx_st {
    int state;
    uchar *iobuf;
    int iobuflen;
    BIO *io;
    BIO *mem;
    ulong asn1_len;
    ulong max_resp_len;
};

typedef struct st_ERR_FNS st_ERR_FNS, *Pst_ERR_FNS;

typedef struct lhash_st_ERR_STRING_DATA lhash_st_ERR_STRING_DATA, *Plhash_st_ERR_STRING_DATA;

typedef struct ERR_string_data_st ERR_string_data_st, *PERR_string_data_st;

typedef struct ERR_string_data_st ERR_STRING_DATA;

typedef struct lhash_st_ERR_STATE lhash_st_ERR_STATE, *Plhash_st_ERR_STATE;

typedef struct err_state_st err_state_st, *Perr_state_st;

typedef struct err_state_st ERR_STATE;

typedef struct st_ERR_FNS ERR_FNS;

struct st_ERR_FNS {
    lhash_st_ERR_STRING_DATA * (*cb_err_get)(int);
    void (*cb_err_del)(void);
    ERR_STRING_DATA * (*cb_err_get_item)(ERR_STRING_DATA *);
    ERR_STRING_DATA * (*cb_err_set_item)(ERR_STRING_DATA *);
    ERR_STRING_DATA * (*cb_err_del_item)(ERR_STRING_DATA *);
    lhash_st_ERR_STATE * (*cb_thread_get)(int);
    void (*cb_thread_release)(struct lhash_st_ERR_STATE **);
    ERR_STATE * (*cb_thread_get_item)(ERR_STATE *);
    ERR_STATE * (*cb_thread_set_item)(ERR_STATE *);
    void (*cb_thread_del_item)(ERR_STATE *);
    int (*cb_get_next_lib)(void);
};

struct lhash_st_ERR_STATE {
    int dummy;
};

struct lhash_st_ERR_STRING_DATA {
    int dummy;
};

struct ERR_string_data_st {
    ulong error;
    char *string;
};

struct err_state_st {
    CRYPTO_THREADID tid;
    int err_flags[16];
    ulong err_buffer[16];
    char *err_data[16];
    int err_data_flags[16];
    char *err_file[16];
    int err_line[16];
    int top;
    int bottom;
};

typedef struct ssl_st ssl_st, *Pssl_st;

typedef struct ssl_st SSL;

struct ssl_st {
};

typedef struct ui_method_st ui_method_st, *Pui_method_st;

typedef struct ui_st ui_st, *Pui_st;

typedef struct ui_st UI;

typedef struct ui_string_st ui_string_st, *Pui_string_st;

typedef struct ui_string_st UI_STRING;

typedef struct ui_method_st UI_METHOD;

typedef struct stack_st_UI_STRING stack_st_UI_STRING, *Pstack_st_UI_STRING;

typedef enum UI_string_types {
    UIT_NONE=0,
    UIT_PROMPT=1,
    UIT_VERIFY=2,
    UIT_BOOLEAN=3,
    UIT_INFO=4,
    UIT_ERROR=5
} UI_string_types;

typedef union anon_union_12_2_28e20dda_for__ anon_union_12_2_28e20dda_for__, *Panon_union_12_2_28e20dda_for__;

typedef struct anon_struct_12_3_c4dfa62e_for_string_data anon_struct_12_3_c4dfa62e_for_string_data, *Panon_struct_12_3_c4dfa62e_for_string_data;

typedef struct anon_struct_12_3_772ecc94_for_boolean_data anon_struct_12_3_772ecc94_for_boolean_data, *Panon_struct_12_3_772ecc94_for_boolean_data;

struct ui_st {
    UI_METHOD *meth;
    struct stack_st_UI_STRING *strings;
    void *user_data;
    CRYPTO_EX_DATA ex_data;
    int flags;
};

struct anon_struct_12_3_772ecc94_for_boolean_data {
    char *action_desc;
    char *ok_chars;
    char *cancel_chars;
};

struct anon_struct_12_3_c4dfa62e_for_string_data {
    int result_minsize;
    int result_maxsize;
    char *test_buf;
};

union anon_union_12_2_28e20dda_for__ {
    struct anon_struct_12_3_c4dfa62e_for_string_data string_data;
    struct anon_struct_12_3_772ecc94_for_boolean_data boolean_data;
};

struct ui_string_st {
    enum UI_string_types type;
    char *out_string;
    int input_flags;
    char *result_buf;
    union anon_union_12_2_28e20dda_for__ _;
    int flags;
};

struct ui_method_st {
    char *name;
    int (*ui_open_session)(UI *);
    int (*ui_write_string)(UI *, UI_STRING *);
    int (*ui_flush)(UI *);
    int (*ui_read_string)(UI *, UI_STRING *);
    int (*ui_close_session)(UI *);
    char * (*ui_construct_prompt)(UI *, char *, char *);
};

struct stack_st_UI_STRING {
    _STACK stack;
};

typedef struct bn_recp_ctx_st bn_recp_ctx_st, *Pbn_recp_ctx_st;

typedef struct bn_recp_ctx_st BN_RECP_CTX;

struct bn_recp_ctx_st {
    BIGNUM N;
    BIGNUM Nr;
    int num_bits;
    int shift;
    int flags;
};

typedef struct x509_store_st x509_store_st, *Px509_store_st;

typedef struct x509_store_ctx_st x509_store_ctx_st, *Px509_store_ctx_st;

typedef struct x509_store_ctx_st X509_STORE_CTX;

typedef struct x509_store_st X509_STORE;

typedef struct stack_st_X509_OBJECT stack_st_X509_OBJECT, *Pstack_st_X509_OBJECT;

typedef struct stack_st_X509_LOOKUP stack_st_X509_LOOKUP, *Pstack_st_X509_LOOKUP;

typedef struct X509_VERIFY_PARAM_st X509_VERIFY_PARAM_st, *PX509_VERIFY_PARAM_st;

typedef struct X509_VERIFY_PARAM_st X509_VERIFY_PARAM;

typedef __time_t time_t;

typedef struct X509_VERIFY_PARAM_ID_st X509_VERIFY_PARAM_ID_st, *PX509_VERIFY_PARAM_ID_st;

typedef struct X509_VERIFY_PARAM_ID_st X509_VERIFY_PARAM_ID;

typedef struct stack_st_OPENSSL_STRING stack_st_OPENSSL_STRING, *Pstack_st_OPENSSL_STRING;

struct stack_st_OPENSSL_STRING {
    _STACK stack;
};

struct stack_st_X509_OBJECT {
    _STACK stack;
};

struct X509_VERIFY_PARAM_st {
    char *name;
    time_t check_time;
    ulong inh_flags;
    ulong flags;
    int purpose;
    int trust;
    int depth;
    struct stack_st_ASN1_OBJECT *policies;
    X509_VERIFY_PARAM_ID *id;
};

struct x509_store_st {
    int cache;
    struct stack_st_X509_OBJECT *objs;
    struct stack_st_X509_LOOKUP *get_cert_methods;
    X509_VERIFY_PARAM *param;
    int (*verify)(X509_STORE_CTX *);
    int (*verify_cb)(int, X509_STORE_CTX *);
    int (*get_issuer)(X509 **, X509_STORE_CTX *, X509 *);
    int (*check_issued)(X509_STORE_CTX *, X509 *, X509 *);
    int (*check_revocation)(X509_STORE_CTX *);
    int (*get_crl)(X509_STORE_CTX *, X509_CRL **, X509 *);
    int (*check_crl)(X509_STORE_CTX *, X509_CRL *);
    int (*cert_crl)(X509_STORE_CTX *, X509_CRL *, X509 *);
    stack_st_X509 * (*lookup_certs)(X509_STORE_CTX *, X509_NAME *);
    stack_st_X509_CRL * (*lookup_crls)(X509_STORE_CTX *, X509_NAME *);
    int (*cleanup)(X509_STORE_CTX *);
    CRYPTO_EX_DATA ex_data;
    int references;
};

struct stack_st_X509_LOOKUP {
    _STACK stack;
};

struct x509_store_ctx_st {
    X509_STORE *ctx;
    int current_method;
    X509 *cert;
    struct stack_st_X509 *untrusted;
    struct stack_st_X509_CRL *crls;
    X509_VERIFY_PARAM *param;
    void *other_ctx;
    int (*verify)(X509_STORE_CTX *);
    int (*verify_cb)(int, X509_STORE_CTX *);
    int (*get_issuer)(X509 **, X509_STORE_CTX *, X509 *);
    int (*check_issued)(X509_STORE_CTX *, X509 *, X509 *);
    int (*check_revocation)(X509_STORE_CTX *);
    int (*get_crl)(X509_STORE_CTX *, X509_CRL **, X509 *);
    int (*check_crl)(X509_STORE_CTX *, X509_CRL *);
    int (*cert_crl)(X509_STORE_CTX *, X509_CRL *, X509 *);
    int (*check_policy)(X509_STORE_CTX *);
    stack_st_X509 * (*lookup_certs)(X509_STORE_CTX *, X509_NAME *);
    stack_st_X509_CRL * (*lookup_crls)(X509_STORE_CTX *, X509_NAME *);
    int (*cleanup)(X509_STORE_CTX *);
    int valid;
    int last_untrusted;
    struct stack_st_X509 *chain;
    X509_POLICY_TREE *tree;
    int explicit_policy;
    int error_depth;
    int error;
    X509 *current_cert;
    X509 *current_issuer;
    X509_CRL *current_crl;
    int current_crl_score;
    uint current_reasons;
    X509_STORE_CTX *parent;
    CRYPTO_EX_DATA ex_data;
};

struct X509_VERIFY_PARAM_ID_st {
    struct stack_st_OPENSSL_STRING *hosts;
    uint hostflags;
    char *peername;
    char *email;
    size_t emaillen;
    uchar *ip;
    size_t iplen;
};

typedef struct DIST_POINT_st DIST_POINT_st, *PDIST_POINT_st;

typedef struct DIST_POINT_st DIST_POINT;

struct DIST_POINT_st {
    DIST_POINT_NAME *distpoint;
    ASN1_BIT_STRING *reasons;
    GENERAL_NAMES *CRLissuer;
    int dp_reasons;
};

typedef struct conf_st conf_st, *Pconf_st;

typedef struct conf_st CONF;

typedef struct conf_method_st conf_method_st, *Pconf_method_st;

typedef struct conf_method_st CONF_METHOD;

typedef struct lhash_st_CONF_VALUE lhash_st_CONF_VALUE, *Plhash_st_CONF_VALUE;

struct lhash_st_CONF_VALUE {
    int dummy;
};

struct conf_st {
    CONF_METHOD *meth;
    void *meth_data;
    struct lhash_st_CONF_VALUE *data;
};

struct conf_method_st {
    char *name;
    CONF * (*create)(CONF_METHOD *);
    int (*init)(CONF *);
    int (*destroy)(CONF *);
    int (*destroy_data)(CONF *);
    int (*load_bio)(CONF *, BIO *, long *);
    int (*dump)(CONF *, BIO *);
    int (*is_number)(CONF *, char);
    int (*to_int)(CONF *, char);
    int (*load)(CONF *, char *, long *);
};

typedef struct rand_meth_st RAND_METHOD;

typedef enum arm_cond_code {
    ARM_EQ=0,
    ARM_NE=1,
    ARM_CS=2,
    ARM_CC=3,
    ARM_MI=4,
    ARM_PL=5,
    ARM_VS=6,
    ARM_VC=7,
    ARM_HI=8,
    ARM_LS=9,
    ARM_GE=10,
    ARM_LT=11,
    ARM_GT=12,
    ARM_LE=13,
    ARM_AL=14,
    ARM_NV=15
} arm_cond_code;

typedef enum vfp_reg_type {
    VFP_NONE=0,
    VFP_REG_D16=1,
    VFP_REG_D32=2,
    VFP_REG_SINGLE=3
} vfp_reg_type;

typedef enum arm_fp_model {
    ARM_FP_MODEL_UNKNOWN=0,
    ARM_FP_MODEL_VFP=1
} arm_fp_model;

typedef enum base_architecture {
    BASE_ARCH_0=0,
    BASE_ARCH_2=2,
    BASE_ARCH_3=3,
    BASE_ARCH_3M=3,
    BASE_ARCH_4=4,
    BASE_ARCH_4T=4,
    BASE_ARCH_5=5,
    BASE_ARCH_5E=5,
    BASE_ARCH_5T=5,
    BASE_ARCH_5TE=5,
    BASE_ARCH_5TEJ=5,
    BASE_ARCH_6=6,
    BASE_ARCH_6J=6,
    BASE_ARCH_6K=6,
    BASE_ARCH_6KZ=6,
    BASE_ARCH_6M=6,
    BASE_ARCH_6T2=6,
    BASE_ARCH_6Z=6,
    BASE_ARCH_7=7,
    BASE_ARCH_7A=7,
    BASE_ARCH_7EM=7,
    BASE_ARCH_7M=7,
    BASE_ARCH_7R=7,
    BASE_ARCH_8A=8
} base_architecture;

typedef struct arm_fpu_desc arm_fpu_desc, *Parm_fpu_desc;

struct arm_fpu_desc {
    char *name;
    enum arm_fp_model model;
    int rev;
    enum vfp_reg_type regs;
    arm_fpu_feature_set features;
};

typedef enum arm_cond_code arm_cc;

typedef enum arm_pcs {
    ARM_PCS_AAPCS=0,
    ARM_PCS_AAPCS_VFP=1,
    ARM_PCS_AAPCS_IWMMXT=2,
    ARM_PCS_AAPCS_LOCAL=3,
    ARM_PCS_ATPCS=4,
    ARM_PCS_APCS=5,
    ARM_PCS_UNKNOWN=6
} arm_pcs;

typedef struct tag_name_st tag_name_st, *Ptag_name_st;

struct tag_name_st {
    char *strnam;
    int len;
    int tag;
};

typedef struct tag_exp_type tag_exp_type, *Ptag_exp_type;

struct tag_exp_type {
    int exp_tag;
    int exp_class;
    int exp_constructed;
    int exp_pad;
    long exp_len;
};

typedef struct tag_exp_arg tag_exp_arg, *Ptag_exp_arg;

struct tag_exp_arg {
    int imp_tag;
    int imp_class;
    int utype;
    int format;
    char *str;
    struct tag_exp_type exp_list[20];
    int exp_count;
};

typedef struct EVP_CAMELLIA_KEY EVP_CAMELLIA_KEY, *PEVP_CAMELLIA_KEY;

typedef struct camellia_key_st camellia_key_st, *Pcamellia_key_st;

typedef struct camellia_key_st CAMELLIA_KEY;

typedef union anon_union_272_2_a929cc6d_for_u anon_union_272_2_a929cc6d_for_u, *Panon_union_272_2_a929cc6d_for_u;

typedef uint KEY_TABLE_TYPE[68];

union anon_union_272_2_a929cc6d_for_u {
    double d;
    KEY_TABLE_TYPE rd_key;
};

struct camellia_key_st {
    union anon_union_272_2_a929cc6d_for_u u;
    int grand_rounds;
};

struct EVP_CAMELLIA_KEY {
    CAMELLIA_KEY ks;
    block128_f block;
    union anon_union_4_2_43a76a9e_for_stream stream;
};

typedef struct __sigset_t __sigset_t, *P__sigset_t;

typedef struct __sigset_t sigset_t;

struct __sigset_t {
    ulong __val[32];
};

typedef struct fd_set fd_set, *Pfd_set;

struct fd_set {
    __fd_mask fds_bits[32];
};

typedef struct crypto_ex_data_func_st crypto_ex_data_func_st, *Pcrypto_ex_data_func_st;

struct crypto_ex_data_func_st {
    long argl;
    void *argp;
    int (*new_func)(void *, void *, CRYPTO_EX_DATA *, int, long, void *);
    void (*free_func)(void *, void *, CRYPTO_EX_DATA *, int, long, void *);
    int (*dup_func)(CRYPTO_EX_DATA *, CRYPTO_EX_DATA *, void *, int, long, void *);
};

typedef struct CRYPTO_dynlock CRYPTO_dynlock, *PCRYPTO_dynlock;

typedef struct CRYPTO_dynlock_value CRYPTO_dynlock_value, *PCRYPTO_dynlock_value;

struct CRYPTO_dynlock {
    int references;
    struct CRYPTO_dynlock_value *data;
};

struct CRYPTO_dynlock_value {
};

typedef struct crypto_ex_data_func_st CRYPTO_EX_DATA_FUNCS;

typedef struct st_CRYPTO_EX_DATA_IMPL st_CRYPTO_EX_DATA_IMPL, *Pst_CRYPTO_EX_DATA_IMPL;

typedef struct st_CRYPTO_EX_DATA_IMPL CRYPTO_EX_DATA_IMPL;

struct st_CRYPTO_EX_DATA_IMPL {
    int (*cb_new_class)(void);
    void (*cb_cleanup)(void);
    int (*cb_get_new_index)(int, long, void *, int (*)(void *, void *, CRYPTO_EX_DATA *, int, long, void *), int (*)(CRYPTO_EX_DATA *, CRYPTO_EX_DATA *, void *, int, long, void *), void (*)(void *, void *, CRYPTO_EX_DATA *, int, long, void *));
    int (*cb_new_ex_data)(int, void *, CRYPTO_EX_DATA *);
    int (*cb_dup_ex_data)(int, CRYPTO_EX_DATA *, CRYPTO_EX_DATA *);
    void (*cb_free_ex_data)(int, void *, CRYPTO_EX_DATA *);
};

typedef struct stack_st_CRYPTO_EX_DATA_FUNCS stack_st_CRYPTO_EX_DATA_FUNCS, *Pstack_st_CRYPTO_EX_DATA_FUNCS;

struct stack_st_CRYPTO_EX_DATA_FUNCS {
    _STACK stack;
};

typedef struct EVP_BF_KEY EVP_BF_KEY, *PEVP_BF_KEY;

typedef struct bf_key_st bf_key_st, *Pbf_key_st;

typedef struct bf_key_st BF_KEY;

struct bf_key_st {
    uint P[18];
    uint S[1024];
};

struct EVP_BF_KEY {
    BF_KEY ks;
};

typedef __mode_t mode_t;

typedef char *__caddr_t;

typedef struct CMS_CertificateChoices CMS_CertificateChoices, *PCMS_CertificateChoices;

typedef union anon_union_4_5_e195caea_for_d anon_union_4_5_e195caea_for_d, *Panon_union_4_5_e195caea_for_d;

typedef struct CMS_OtherCertificateFormat_st CMS_OtherCertificateFormat_st, *PCMS_OtherCertificateFormat_st;

typedef struct CMS_OtherCertificateFormat_st CMS_OtherCertificateFormat;

struct CMS_OtherCertificateFormat_st {
    ASN1_OBJECT *otherCertFormat;
    ASN1_TYPE *otherCert;
};

union anon_union_4_5_e195caea_for_d {
    X509 *certificate;
    ASN1_STRING *extendedCertificate;
    ASN1_STRING *v1AttrCert;
    ASN1_STRING *v2AttrCert;
    CMS_OtherCertificateFormat *other;
};

struct CMS_CertificateChoices {
    int type;
    union anon_union_4_5_e195caea_for_d d;
};

typedef struct SHAstate_st SHAstate_st, *PSHAstate_st;

typedef struct SHAstate_st SHA_CTX;

struct SHAstate_st {
    uint h0;
    uint h1;
    uint h2;
    uint h3;
    uint h4;
    uint Nl;
    uint Nh;
    uint data[16];
    uint num;
};

typedef struct SHA256state_st SHA256state_st, *PSHA256state_st;

typedef struct SHA256state_st SHA256_CTX;

struct SHA256state_st {
    uint h[8];
    uint Nl;
    uint Nh;
    uint data[16];
    uint num;
    uint md_len;
};

typedef struct SHA512state_st SHA512state_st, *PSHA512state_st;

typedef struct SHA512state_st SHA512_CTX;

typedef union anon_union_128_2_9473006d_for_u anon_union_128_2_9473006d_for_u, *Panon_union_128_2_9473006d_for_u;

union anon_union_128_2_9473006d_for_u {
    ulonglong d[16];
    uchar p[128];
};

struct SHA512state_st {
    ulonglong h[8];
    ulonglong Nl;
    ulonglong Nh;
    union anon_union_128_2_9473006d_for_u u;
    uint num;
    uint md_len;
};

typedef struct obj_name_st obj_name_st, *Pobj_name_st;

typedef struct obj_name_st OBJ_NAME;

struct obj_name_st {
    int type;
    int alias;
    char *name;
    char *data;
};

typedef struct DH_PKEY_CTX DH_PKEY_CTX, *PDH_PKEY_CTX;

struct DH_PKEY_CTX {
    int prime_len;
    int generator;
    int use_dsa;
    int subprime_len;
    EVP_MD *md;
    int rfc5114_param;
    int gentmp[2];
    char kdf_type;
    ASN1_OBJECT *kdf_oid;
    EVP_MD *kdf_md;
    uchar *kdf_ukm;
    size_t kdf_ukmlen;
    size_t kdf_outlen;
};

typedef struct EVP_CAST_KEY EVP_CAST_KEY, *PEVP_CAST_KEY;

typedef struct cast_key_st cast_key_st, *Pcast_key_st;

typedef struct cast_key_st CAST_KEY;

struct cast_key_st {
    uint data[32];
    int short_key;
};

struct EVP_CAST_KEY {
    CAST_KEY ks;
};

typedef struct BIO_ASN1_EX_FUNCS_st BIO_ASN1_EX_FUNCS_st, *PBIO_ASN1_EX_FUNCS_st;

typedef struct BIO_ASN1_EX_FUNCS_st BIO_ASN1_EX_FUNCS;

struct BIO_ASN1_EX_FUNCS_st {
    int (*ex_func)(BIO *, uchar **, int *, void *);
    int (*ex_free_func)(BIO *, uchar **, int *, void *);
};

typedef struct BIO_ASN1_BUF_CTX_t BIO_ASN1_BUF_CTX_t, *PBIO_ASN1_BUF_CTX_t;

typedef struct BIO_ASN1_BUF_CTX_t BIO_ASN1_BUF_CTX;

typedef enum asn1_bio_state_t {
    ASN1_STATE_START=0,
    ASN1_STATE_PRE_COPY=1,
    ASN1_STATE_HEADER=2,
    ASN1_STATE_HEADER_COPY=3,
    ASN1_STATE_DATA_COPY=4,
    ASN1_STATE_POST_COPY=5,
    ASN1_STATE_DONE=6
} asn1_bio_state_t;

struct BIO_ASN1_BUF_CTX_t {
    enum asn1_bio_state_t state;
    uchar *buf;
    int bufsize;
    int bufpos;
    int buflen;
    int copylen;
    int asn1_class;
    int asn1_tag;
    int (*prefix)(BIO *, uchar **, int *, void *);
    int (*prefix_free)(BIO *, uchar **, int *, void *);
    int (*suffix)(BIO *, uchar **, int *, void *);
    int (*suffix_free)(BIO *, uchar **, int *, void *);
    uchar *ex_buf;
    int ex_len;
    int ex_pos;
    void *ex_arg;
};

typedef __gnuc_va_list va_list;


// WARNING! conflicting data type names: /DWARF/stdio.h/FILE - /stdio.h/FILE

typedef struct x509_lookup_method_st x509_lookup_method_st, *Px509_lookup_method_st;

typedef struct x509_lookup_st x509_lookup_st, *Px509_lookup_st;

typedef struct x509_lookup_st X509_LOOKUP;

typedef struct x509_object_st x509_object_st, *Px509_object_st;

typedef struct x509_object_st X509_OBJECT;

typedef struct x509_lookup_method_st X509_LOOKUP_METHOD;

typedef union anon_union_4_4_ca12f507_for_data anon_union_4_4_ca12f507_for_data, *Panon_union_4_4_ca12f507_for_data;

struct x509_lookup_method_st {
    char *name;
    int (*new_item)(X509_LOOKUP *);
    void (*free)(X509_LOOKUP *);
    int (*init)(X509_LOOKUP *);
    int (*shutdown)(X509_LOOKUP *);
    int (*ctrl)(X509_LOOKUP *, int, char *, long, char **);
    int (*get_by_subject)(X509_LOOKUP *, int, X509_NAME *, X509_OBJECT *);
    int (*get_by_issuer_serial)(X509_LOOKUP *, int, X509_NAME *, ASN1_INTEGER *, X509_OBJECT *);
    int (*get_by_fingerprint)(X509_LOOKUP *, int, uchar *, int, X509_OBJECT *);
    int (*get_by_alias)(X509_LOOKUP *, int, char *, int, X509_OBJECT *);
};

union anon_union_4_4_ca12f507_for_data {
    char *ptr;
    X509 *x509;
    X509_CRL *crl;
    EVP_PKEY *pkey;
};

struct x509_object_st {
    int type;
    union anon_union_4_4_ca12f507_for_data data;
};

struct x509_lookup_st {
    int init;
    int skip;
    X509_LOOKUP_METHOD *method;
    char *method_data;
    X509_STORE *store_ctx;
};

typedef struct stack_st_X509_VERIFY_PARAM stack_st_X509_VERIFY_PARAM, *Pstack_st_X509_VERIFY_PARAM;

struct stack_st_X509_VERIFY_PARAM {
    _STACK stack;
};

typedef struct WHIRLPOOL_CTX WHIRLPOOL_CTX, *PWHIRLPOOL_CTX;

typedef union anon_union_64_2_9473004f_for_H anon_union_64_2_9473004f_for_H, *Panon_union_64_2_9473004f_for_H;

union anon_union_64_2_9473004f_for_H {
    uchar c[64];
    double q[8];
};

struct WHIRLPOOL_CTX {
    union anon_union_64_2_9473004f_for_H H;
    uchar data[64];
    uint bitoff;
    size_t bitlen[8];
};

typedef union anon_union_4_2_947300ab anon_union_4_2_947300ab, *Panon_union_4_2_947300ab;

union anon_union_4_2_947300ab {
    int (*f)(void *, char *, int);
    void *p;
};

typedef union anon_union_4_2_0c0d52ef anon_union_4_2_0c0d52ef, *Panon_union_4_2_0c0d52ef;

typedef void (*DSO_FUNC_TYPE)(void);

union anon_union_4_2_0c0d52ef {
    DSO_FUNC_TYPE sym;
    void *dlret;
};

typedef struct stack_st_nid_triple stack_st_nid_triple, *Pstack_st_nid_triple;

struct stack_st_nid_triple {
    _STACK stack;
};

typedef struct nid_triple nid_triple, *Pnid_triple;

struct nid_triple {
    int sign_id;
    int hash_id;
    int pkey_id;
};


// WARNING! conflicting data type names: /DWARF/stat.h/stat - /stat.h/stat

typedef struct ndef_aux_st ndef_aux_st, *Pndef_aux_st;

typedef struct ndef_aux_st NDEF_SUPPORT;

struct ndef_aux_st {
    ASN1_VALUE *val;
    ASN1_ITEM *it;
    BIO *ndef_bio;
    BIO *out;
    uchar **boundary;
    uchar *derbuf;
};

typedef struct Dl_info Dl_info, *PDl_info;

struct Dl_info {
    char *dli_fname;
    void *dli_fbase;
    char *dli_sname;
    void *dli_saddr;
};

typedef struct ASN1_AUX_st ASN1_AUX_st, *PASN1_AUX_st;

struct ASN1_AUX_st {
    void *app_data;
    int flags;
    int ref_offset;
    int ref_lock;
    int (*asn1_cb)(int, ASN1_VALUE **, ASN1_ITEM *, void *);
    int enc_offset;
};

typedef struct ASN1_COMPAT_FUNCS_st ASN1_COMPAT_FUNCS_st, *PASN1_COMPAT_FUNCS_st;

typedef struct ASN1_COMPAT_FUNCS_st ASN1_COMPAT_FUNCS;

struct ASN1_COMPAT_FUNCS_st {
    ASN1_VALUE * (*asn1_new)(void);
    void (*asn1_free)(ASN1_VALUE *);
    ASN1_VALUE * (*asn1_d2i)(ASN1_VALUE **, uchar **, long);
    int (*asn1_i2d)(ASN1_VALUE *, uchar **);
};

typedef struct ASN1_PRIMITIVE_FUNCS_st ASN1_PRIMITIVE_FUNCS_st, *PASN1_PRIMITIVE_FUNCS_st;

struct ASN1_PRIMITIVE_FUNCS_st {
    void *app_data;
    ulong flags;
    int (*prim_new)(ASN1_VALUE **, ASN1_ITEM *);
    void (*prim_free)(ASN1_VALUE **, ASN1_ITEM *);
    void (*prim_clear)(ASN1_VALUE **, ASN1_ITEM *);
    int (*prim_c2i)(ASN1_VALUE **, uchar *, int, int, char *, ASN1_ITEM *);
    int (*prim_i2c)(ASN1_VALUE **, uchar *, int *, ASN1_ITEM *);
    int (*prim_print)(BIO *, ASN1_VALUE **, ASN1_ITEM *, int, ASN1_PCTX *);
};

typedef struct ASN1_ADB_st ASN1_ADB_st, *PASN1_ADB_st;

typedef struct ASN1_ADB_st ASN1_ADB;

typedef struct stack_st_ASN1_ADB_TABLE stack_st_ASN1_ADB_TABLE, *Pstack_st_ASN1_ADB_TABLE;

typedef struct ASN1_ADB_TABLE_st ASN1_ADB_TABLE_st, *PASN1_ADB_TABLE_st;

typedef struct ASN1_ADB_TABLE_st ASN1_ADB_TABLE;

struct ASN1_ADB_st {
    ulong flags;
    ulong offset;
    struct stack_st_ASN1_ADB_TABLE **app_items;
    ASN1_ADB_TABLE *tbl;
    long tblcount;
    ASN1_TEMPLATE *default_tt;
    ASN1_TEMPLATE *null_tt;
};

struct stack_st_ASN1_ADB_TABLE {
};

struct ASN1_ADB_TABLE_st {
    long value;
    ASN1_TEMPLATE tt;
};

typedef struct ASN1_STREAM_ARG_st ASN1_STREAM_ARG_st, *PASN1_STREAM_ARG_st;

typedef struct ASN1_STREAM_ARG_st ASN1_STREAM_ARG;

struct ASN1_STREAM_ARG_st {
    BIO *out;
    BIO *ndef_bio;
    uchar **boundary;
};

typedef struct ASN1_EXTERN_FUNCS_st ASN1_EXTERN_FUNCS_st, *PASN1_EXTERN_FUNCS_st;

typedef struct ASN1_TLC_st ASN1_TLC_st, *PASN1_TLC_st;

typedef struct ASN1_TLC_st ASN1_TLC;

typedef struct ASN1_EXTERN_FUNCS_st ASN1_EXTERN_FUNCS;

struct ASN1_EXTERN_FUNCS_st {
    void *app_data;
    int (*asn1_ex_new)(ASN1_VALUE **, ASN1_ITEM *);
    void (*asn1_ex_free)(ASN1_VALUE **, ASN1_ITEM *);
    void (*asn1_ex_clear)(ASN1_VALUE **, ASN1_ITEM *);
    int (*asn1_ex_d2i)(ASN1_VALUE **, uchar **, long, ASN1_ITEM *, int, int, char, ASN1_TLC *);
    int (*asn1_ex_i2d)(ASN1_VALUE **, uchar **, ASN1_ITEM *, int, int);
    int (*asn1_ex_print)(BIO *, ASN1_VALUE **, int, char *, ASN1_PCTX *);
};

struct ASN1_TLC_st {
    char valid;
    int ret;
    long plen;
    int ptag;
    int pclass;
    int hdrlen;
};

typedef struct ASN1_PRINT_ARG_st ASN1_PRINT_ARG_st, *PASN1_PRINT_ARG_st;

typedef struct ASN1_PRINT_ARG_st ASN1_PRINT_ARG;

struct ASN1_PRINT_ARG_st {
    BIO *out;
    int indent;
    ASN1_PCTX *pctx;
};

typedef struct ASN1_AUX_st ASN1_AUX;

typedef struct stack_st_ASN1_VALUE stack_st_ASN1_VALUE, *Pstack_st_ASN1_VALUE;

struct stack_st_ASN1_VALUE {
    _STACK stack;
};

typedef struct ASN1_PRIMITIVE_FUNCS_st ASN1_PRIMITIVE_FUNCS;

typedef struct termio termio, *Ptermio;

struct termio {
    ushort c_iflag;
    ushort c_oflag;
    ushort c_cflag;
    ushort c_lflag;
    uchar c_line;
    uchar c_cc[8];
};

typedef struct ecdsa_data_st ecdsa_data_st, *Pecdsa_data_st;

typedef struct ecdsa_data_st ECDSA_DATA;

struct ecdsa_data_st {
    int (*init)(EC_KEY *);
    ENGINE *engine;
    int flags;
    ECDSA_METHOD *meth;
    CRYPTO_EX_DATA ex_data;
};

typedef struct stack_st_EVP_PKEY_METHOD stack_st_EVP_PKEY_METHOD, *Pstack_st_EVP_PKEY_METHOD;

struct stack_st_EVP_PKEY_METHOD {
    _STACK stack;
};

typedef struct doall_md doall_md, *Pdoall_md;

struct doall_md {
    void *arg;
    void (*fn)(EVP_MD *, char *, char *, void *);
};

typedef struct doall_cipher doall_cipher, *Pdoall_cipher;

struct doall_cipher {
    void *arg;
    void (*fn)(EVP_CIPHER *, char *, char *, void *);
};

typedef struct int_dhx942_dh int_dhx942_dh, *Pint_dhx942_dh;

typedef struct int_dhvparams int_dhvparams, *Pint_dhvparams;

struct int_dhvparams {
    ASN1_BIT_STRING *seed;
    BIGNUM *counter;
};

struct int_dhx942_dh {
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *g;
    BIGNUM *j;
    struct int_dhvparams *vparams;
};

typedef struct POLICYQUALINFO_st POLICYQUALINFO_st, *PPOLICYQUALINFO_st;

typedef struct POLICYQUALINFO_st POLICYQUALINFO;

typedef union anon_union_4_3_92eb2655_for_d anon_union_4_3_92eb2655_for_d, *Panon_union_4_3_92eb2655_for_d;

typedef struct USERNOTICE_st USERNOTICE_st, *PUSERNOTICE_st;

typedef struct USERNOTICE_st USERNOTICE;

typedef struct NOTICEREF_st NOTICEREF_st, *PNOTICEREF_st;

typedef struct NOTICEREF_st NOTICEREF;

typedef struct stack_st_ASN1_INTEGER stack_st_ASN1_INTEGER, *Pstack_st_ASN1_INTEGER;

union anon_union_4_3_92eb2655_for_d {
    ASN1_IA5STRING *cpsuri;
    USERNOTICE *usernotice;
    ASN1_TYPE *other;
};

struct NOTICEREF_st {
    ASN1_STRING *organization;
    struct stack_st_ASN1_INTEGER *noticenos;
};

struct POLICYQUALINFO_st {
    ASN1_OBJECT *pqualid;
    union anon_union_4_3_92eb2655_for_d d;
};

struct USERNOTICE_st {
    NOTICEREF *noticeref;
    ASN1_STRING *exptext;
};

struct stack_st_ASN1_INTEGER {
    _STACK stack;
};

typedef struct POLICY_CONSTRAINTS_st POLICY_CONSTRAINTS_st, *PPOLICY_CONSTRAINTS_st;

typedef struct POLICY_CONSTRAINTS_st POLICY_CONSTRAINTS;

struct POLICY_CONSTRAINTS_st {
    ASN1_INTEGER *requireExplicitPolicy;
    ASN1_INTEGER *inhibitPolicyMapping;
};

typedef struct GENERAL_SUBTREE_st GENERAL_SUBTREE_st, *PGENERAL_SUBTREE_st;

typedef struct GENERAL_SUBTREE_st GENERAL_SUBTREE;

typedef struct GENERAL_NAME_st GENERAL_NAME_st, *PGENERAL_NAME_st;

typedef struct GENERAL_NAME_st GENERAL_NAME;

typedef union anon_union_4_15_d29bcaab_for_d anon_union_4_15_d29bcaab_for_d, *Panon_union_4_15_d29bcaab_for_d;

typedef struct otherName_st otherName_st, *PotherName_st;

typedef struct otherName_st OTHERNAME;

typedef struct EDIPartyName_st EDIPartyName_st, *PEDIPartyName_st;

typedef struct EDIPartyName_st EDIPARTYNAME;

struct GENERAL_SUBTREE_st {
    GENERAL_NAME *base;
    ASN1_INTEGER *minimum;
    ASN1_INTEGER *maximum;
};

struct EDIPartyName_st {
    ASN1_STRING *nameAssigner;
    ASN1_STRING *partyName;
};

union anon_union_4_15_d29bcaab_for_d {
    char *ptr;
    OTHERNAME *otherName;
    ASN1_IA5STRING *rfc822Name;
    ASN1_IA5STRING *dNSName;
    ASN1_TYPE *x400Address;
    X509_NAME *directoryName;
    EDIPARTYNAME *ediPartyName;
    ASN1_IA5STRING *uniformResourceIdentifier;
    ASN1_OCTET_STRING *iPAddress;
    ASN1_OBJECT *registeredID;
    ASN1_OCTET_STRING *ip;
    X509_NAME *dirn;
    ASN1_IA5STRING *ia5;
    ASN1_OBJECT *rid;
    ASN1_TYPE *other;
};

struct GENERAL_NAME_st {
    int type;
    union anon_union_4_15_d29bcaab_for_d d;
};

struct otherName_st {
    ASN1_OBJECT *type_id;
    ASN1_TYPE *value;
};

typedef struct PROXY_CERT_INFO_EXTENSION_st PROXY_CERT_INFO_EXTENSION_st, *PPROXY_CERT_INFO_EXTENSION_st;

typedef struct PROXY_CERT_INFO_EXTENSION_st PROXY_CERT_INFO_EXTENSION;

typedef struct PROXY_POLICY_st PROXY_POLICY_st, *PPROXY_POLICY_st;

typedef struct PROXY_POLICY_st PROXY_POLICY;

struct PROXY_POLICY_st {
    ASN1_OBJECT *policyLanguage;
    ASN1_OCTET_STRING *policy;
};

struct PROXY_CERT_INFO_EXTENSION_st {
    ASN1_INTEGER *pcPathLengthConstraint;
    PROXY_POLICY *proxyPolicy;
};

typedef struct PKEY_USAGE_PERIOD_st PKEY_USAGE_PERIOD_st, *PPKEY_USAGE_PERIOD_st;

typedef struct PKEY_USAGE_PERIOD_st PKEY_USAGE_PERIOD;

struct PKEY_USAGE_PERIOD_st {
    ASN1_GENERALIZEDTIME *notBefore;
    ASN1_GENERALIZEDTIME *notAfter;
};

typedef struct v3_ext_method v3_ext_method, *Pv3_ext_method;

typedef void * (*X509V3_EXT_V2I)(struct v3_ext_method *, struct v3_ext_ctx *, struct stack_st_CONF_VALUE *);

typedef void * (*X509V3_EXT_NEW)(void);

typedef void (*X509V3_EXT_FREE)(void *);

typedef void * (*X509V3_EXT_D2I)(void *, uchar **, long);

typedef int (*X509V3_EXT_I2D)(void *, uchar **);

typedef char * (*X509V3_EXT_I2S)(struct v3_ext_method *, void *);

typedef void * (*X509V3_EXT_S2I)(struct v3_ext_method *, struct v3_ext_ctx *, char *);

typedef stack_st_CONF_VALUE * (*X509V3_EXT_I2V)(struct v3_ext_method *, void *, struct stack_st_CONF_VALUE *);

typedef int (*X509V3_EXT_I2R)(struct v3_ext_method *, void *, BIO *, int);

typedef void * (*X509V3_EXT_R2I)(struct v3_ext_method *, struct v3_ext_ctx *, char *);

struct v3_ext_method {
    int ext_nid;
    int ext_flags;
    ASN1_ITEM_EXP *it;
    X509V3_EXT_NEW ext_new;
    X509V3_EXT_FREE ext_free;
    X509V3_EXT_D2I d2i;
    X509V3_EXT_I2D i2d;
    X509V3_EXT_I2S i2s;
    X509V3_EXT_S2I s2i;
    X509V3_EXT_I2V i2v;
    X509V3_EXT_V2I v2i;
    X509V3_EXT_I2R i2r;
    X509V3_EXT_R2I r2i;
    void *usr_data;
};

typedef struct POLICYINFO_st POLICYINFO_st, *PPOLICYINFO_st;

typedef struct POLICYINFO_st POLICYINFO;

struct POLICYINFO_st {
    ASN1_OBJECT *policyid;
    struct stack_st_POLICYQUALINFO *qualifiers;
};

typedef struct v3_ext_method X509V3_EXT_METHOD;

typedef struct stack_st_X509V3_EXT_METHOD stack_st_X509V3_EXT_METHOD, *Pstack_st_X509V3_EXT_METHOD;

struct stack_st_X509V3_EXT_METHOD {
    _STACK stack;
};

typedef struct ACCESS_DESCRIPTION_st ACCESS_DESCRIPTION_st, *PACCESS_DESCRIPTION_st;

typedef struct ACCESS_DESCRIPTION_st ACCESS_DESCRIPTION;

struct ACCESS_DESCRIPTION_st {
    ASN1_OBJECT *method;
    GENERAL_NAME *location;
};

typedef struct SXNET_ID_st SXNET_ID_st, *PSXNET_ID_st;

typedef struct SXNET_ID_st SXNETID;

struct SXNET_ID_st {
    ASN1_INTEGER *zone;
    ASN1_OCTET_STRING *user;
};

typedef struct BASIC_CONSTRAINTS_st BASIC_CONSTRAINTS_st, *PBASIC_CONSTRAINTS_st;

typedef struct BASIC_CONSTRAINTS_st BASIC_CONSTRAINTS;

struct BASIC_CONSTRAINTS_st {
    int ca;
    ASN1_INTEGER *pathlen;
};

typedef struct BIT_STRING_BITNAME_st BIT_STRING_BITNAME_st, *PBIT_STRING_BITNAME_st;

typedef struct BIT_STRING_BITNAME_st BIT_STRING_BITNAME;

typedef BIT_STRING_BITNAME ENUMERATED_NAMES;

struct BIT_STRING_BITNAME_st {
    int bitnum;
    char *lname;
    char *sname;
};

typedef struct SXNET_st SXNET_st, *PSXNET_st;

typedef struct SXNET_st SXNET;

typedef struct stack_st_SXNETID stack_st_SXNETID, *Pstack_st_SXNETID;

struct stack_st_SXNETID {
    _STACK stack;
};

struct SXNET_st {
    ASN1_INTEGER *version;
    struct stack_st_SXNETID *ids;
};

typedef struct stack_st_ASN1_OBJECT EXTENDED_KEY_USAGE;

typedef struct stack_st_POLICY_MAPPING stack_st_POLICY_MAPPING, *Pstack_st_POLICY_MAPPING;

typedef struct stack_st_POLICY_MAPPING POLICY_MAPPINGS;

struct stack_st_POLICY_MAPPING {
    _STACK stack;
};

typedef struct POLICY_MAPPING_st POLICY_MAPPING_st, *PPOLICY_MAPPING_st;

typedef struct POLICY_MAPPING_st POLICY_MAPPING;

struct POLICY_MAPPING_st {
    ASN1_OBJECT *issuerDomainPolicy;
    ASN1_OBJECT *subjectDomainPolicy;
};

typedef struct stack_st_POLICYINFO stack_st_POLICYINFO, *Pstack_st_POLICYINFO;

typedef struct stack_st_POLICYINFO CERTIFICATEPOLICIES;

struct stack_st_POLICYINFO {
    _STACK stack;
};

typedef struct stack_st_DIST_POINT CRL_DIST_POINTS;

typedef struct x509_purpose_st x509_purpose_st, *Px509_purpose_st;

struct x509_purpose_st {
    int purpose;
    int trust;
    int flags;
    int (*check_purpose)(struct x509_purpose_st *, X509 *, int);
    char *name;
    char *sname;
    void *usr_data;
};

typedef struct stack_st_ACCESS_DESCRIPTION stack_st_ACCESS_DESCRIPTION, *Pstack_st_ACCESS_DESCRIPTION;

typedef struct stack_st_ACCESS_DESCRIPTION AUTHORITY_INFO_ACCESS;

struct stack_st_ACCESS_DESCRIPTION {
    _STACK stack;
};

typedef struct stack_st_X509_PURPOSE stack_st_X509_PURPOSE, *Pstack_st_X509_PURPOSE;

struct stack_st_X509_PURPOSE {
    _STACK stack;
};

typedef struct x509_purpose_st X509_PURPOSE;

typedef struct ENGINE_FIND_STR ENGINE_FIND_STR, *PENGINE_FIND_STR;

struct ENGINE_FIND_STR {
    ENGINE *e;
    EVP_PKEY_ASN1_METHOD *ameth;
    char *str;
    int len;
};

typedef struct stack_st_X509_EXTENSION X509_EXTENSIONS;

typedef struct PBKDF2PARAM_st PBKDF2PARAM_st, *PPBKDF2PARAM_st;

typedef struct PBKDF2PARAM_st PBKDF2PARAM;

struct PBKDF2PARAM_st {
    ASN1_TYPE *salt;
    ASN1_INTEGER *iter;
    ASN1_INTEGER *keylength;
    X509_ALGOR *prf;
};

typedef struct Netscape_spkac_st Netscape_spkac_st, *PNetscape_spkac_st;

struct Netscape_spkac_st {
    X509_PUBKEY *pubkey;
    ASN1_IA5STRING *challenge;
};

typedef struct PBE2PARAM_st PBE2PARAM_st, *PPBE2PARAM_st;

typedef struct PBE2PARAM_st PBE2PARAM;

struct PBE2PARAM_st {
    X509_ALGOR *keyfunc;
    X509_ALGOR *encryption;
};

typedef struct stack_st_X509_TRUST stack_st_X509_TRUST, *Pstack_st_X509_TRUST;

struct stack_st_X509_TRUST {
    _STACK stack;
};

typedef struct Netscape_spki_st Netscape_spki_st, *PNetscape_spki_st;

typedef struct Netscape_spki_st NETSCAPE_SPKI;

typedef struct Netscape_spkac_st NETSCAPE_SPKAC;

struct Netscape_spki_st {
    NETSCAPE_SPKAC *spkac;
    X509_ALGOR *sig_algor;
    ASN1_BIT_STRING *signature;
};

typedef struct x509_attributes_st x509_attributes_st, *Px509_attributes_st;

typedef struct x509_attributes_st X509_ATTRIBUTE;

typedef union anon_union_4_3_9d6904f2_for_value anon_union_4_3_9d6904f2_for_value, *Panon_union_4_3_9d6904f2_for_value;

typedef struct stack_st_ASN1_TYPE stack_st_ASN1_TYPE, *Pstack_st_ASN1_TYPE;

union anon_union_4_3_9d6904f2_for_value {
    char *ptr;
    struct stack_st_ASN1_TYPE *set;
    ASN1_TYPE *single;
};

struct x509_attributes_st {
    ASN1_OBJECT *object;
    int single;
    union anon_union_4_3_9d6904f2_for_value value;
};

struct stack_st_ASN1_TYPE {
    _STACK stack;
};

typedef struct x509_trust_st x509_trust_st, *Px509_trust_st;

struct x509_trust_st {
    int trust;
    int flags;
    int (*check_trust)(struct x509_trust_st *, X509 *, int);
    char *name;
    int arg1;
    void *arg2;
};

typedef struct X509_name_entry_st X509_name_entry_st, *PX509_name_entry_st;

typedef struct X509_name_entry_st X509_NAME_ENTRY;

struct X509_name_entry_st {
    ASN1_OBJECT *object;
    ASN1_STRING *value;
    int set;
    int size;
};

typedef struct x509_trust_st X509_TRUST;

typedef struct PBEPARAM_st PBEPARAM_st, *PPBEPARAM_st;

typedef struct PBEPARAM_st PBEPARAM;

struct PBEPARAM_st {
    ASN1_OCTET_STRING *salt;
    ASN1_INTEGER *iter;
};

typedef struct Netscape_certificate_sequence Netscape_certificate_sequence, *PNetscape_certificate_sequence;

typedef struct Netscape_certificate_sequence NETSCAPE_CERT_SEQUENCE;

struct Netscape_certificate_sequence {
    ASN1_OBJECT *type;
    struct stack_st_X509 *certs;
};

typedef struct x509_cert_pair_st x509_cert_pair_st, *Px509_cert_pair_st;

typedef struct x509_cert_pair_st X509_CERT_PAIR;

struct x509_cert_pair_st {
    X509 *forward;
    X509 *reverse;
};

typedef struct X509_extension_st X509_extension_st, *PX509_extension_st;

typedef struct X509_extension_st X509_EXTENSION;

struct X509_extension_st {
    ASN1_OBJECT *object;
    ASN1_BOOLEAN critical;
    ASN1_OCTET_STRING *value;
};

typedef struct stack_st_X509_NAME stack_st_X509_NAME, *Pstack_st_X509_NAME;

struct stack_st_X509_NAME {
    _STACK stack;
};

typedef struct stack_st_X509_ALGOR X509_ALGORS;

typedef struct seed_key_st seed_key_st, *Pseed_key_st;

typedef struct seed_key_st SEED_KEY_SCHEDULE;

struct seed_key_st {
    uint data[32];
};

typedef struct UA_Client_Subscription_s UA_Client_Subscription_s, *PUA_Client_Subscription_s;

typedef struct UA_Client_Subscription_s UA_Client_Subscription;

typedef struct anon_struct_8_2_19706e45_for_listEntry anon_struct_8_2_19706e45_for_listEntry, *Panon_struct_8_2_19706e45_for_listEntry;

typedef uint32_t UA_UInt32;

typedef struct UA_ListOfClientMonitoredItems UA_ListOfClientMonitoredItems, *PUA_ListOfClientMonitoredItems;

typedef struct UA_Client_MonitoredItem_s UA_Client_MonitoredItem_s, *PUA_Client_MonitoredItem_s;

typedef struct UA_DataValue UA_DataValue, *PUA_DataValue;


// WARNING! conflicting data type names: /DWARF/open62541.c/UA_Client_MonitoredItem_s/anon_struct_8_2_19706e45_for_listEntry - /DWARF/open62541.c/UA_Client_Subscription_s/anon_struct_8_2_19706e45_for_listEntry

typedef struct UA_NodeId UA_NodeId, *PUA_NodeId;

typedef struct UA_Variant UA_Variant, *PUA_Variant;

typedef uint32_t UA_StatusCode;

typedef int64_t UA_DateTime;

typedef uint16_t UA_UInt16;

typedef enum UA_NodeIdType {
    UA_NODEIDTYPE_NUMERIC=0,
    UA_NODEIDTYPE_STRING=3,
    UA_NODEIDTYPE_GUID=4,
    UA_NODEIDTYPE_BYTESTRING=5
} UA_NodeIdType;

typedef union anon_union_16_4_621dfe33_for_identifier anon_union_16_4_621dfe33_for_identifier, *Panon_union_16_4_621dfe33_for_identifier;

typedef struct UA_DataType UA_DataType, *PUA_DataType;

typedef enum UA_VariantStorageType {
    UA_VARIANT_DATA=0,
    UA_VARIANT_DATA_NODELETE=1
} UA_VariantStorageType;

typedef struct UA_String UA_String, *PUA_String;

typedef struct UA_Guid UA_Guid, *PUA_Guid;

typedef struct UA_String UA_ByteString;

typedef uint8_t UA_Byte;

typedef struct UA_DataTypeMember UA_DataTypeMember, *PUA_DataTypeMember;

struct UA_Guid {
    UA_UInt32 data1;
    UA_UInt16 data2;
    UA_UInt16 data3;
    UA_Byte data4[8];
};

struct UA_String {
    size_t length;
    UA_Byte *data;
};

union anon_union_16_4_621dfe33_for_identifier {
    UA_UInt32 numeric;
    struct UA_String string;
    struct UA_Guid guid;
    UA_ByteString byteString;
};

struct UA_NodeId {
    UA_UInt16 namespaceIndex;
    enum UA_NodeIdType identifierType;
    union anon_union_16_4_621dfe33_for_identifier identifier;
};

struct UA_DataType {
    char *typeName;
    struct UA_NodeId typeId;
    UA_UInt16 memSize;
    UA_UInt16 typeIndex;
    UA_Byte membersSize;
    UA_Boolean builtin:1;
    UA_Boolean fixedSize:1;
    UA_Boolean overlayable:1;
    UA_UInt16 binaryEncodingId;
    struct UA_DataTypeMember *members;
};

struct UA_Variant {
    struct UA_DataType *type;
    enum UA_VariantStorageType storageType;
    size_t arrayLength;
    void *data;
    size_t arrayDimensionsSize;
    UA_UInt32 *arrayDimensions;
};

struct UA_DataValue {
    UA_Boolean hasValue:1;
    UA_Boolean hasStatus:1;
    UA_Boolean hasSourceTimestamp:1;
    UA_Boolean hasServerTimestamp:1;
    UA_Boolean hasSourcePicoseconds:1;
    UA_Boolean hasServerPicoseconds:1;
    struct UA_Variant value;
    UA_StatusCode status;
    UA_DateTime sourceTimestamp;
    UA_UInt16 sourcePicoseconds;
    UA_DateTime serverTimestamp;
    UA_UInt16 serverPicoseconds;
};

struct UA_Client_MonitoredItem_s {
    struct anon_struct_8_2_19706e45_for_listEntry listEntry;
    UA_UInt32 MonitoredItemId;
    UA_UInt32 MonitoringMode;
    struct UA_NodeId monitoredNodeId;
    UA_UInt32 AttributeID;
    UA_UInt32 ClientHandle;
    UA_Double SamplingInterval;
    UA_UInt32 QueueSize;
    UA_Boolean DiscardOldest;
    void (*handler)(UA_UInt32, struct UA_DataValue *, void *);
    void *handlerContext;
};

struct anon_struct_8_2_19706e45_for_listEntry {
    struct UA_Client_Subscription_s *le_next;
    struct UA_Client_Subscription_s **le_prev;
};

struct UA_DataTypeMember {
    char *memberName;
    UA_UInt16 memberTypeIndex;
    UA_Byte padding;
    UA_Boolean namespaceZero:1;
    UA_Boolean isArray:1;
};

struct UA_ListOfClientMonitoredItems {
    struct UA_Client_MonitoredItem_s *lh_first;
};

struct UA_Client_Subscription_s {
    struct anon_struct_8_2_19706e45_for_listEntry listEntry;
    UA_UInt32 LifeTime;
    UA_UInt32 KeepAliveCount;
    UA_Double PublishingInterval;
    UA_UInt32 SubscriptionID;
    UA_UInt32 NotificationsPerPublish;
    UA_UInt32 Priority;
    struct UA_ListOfClientMonitoredItems MonitoredItems;
};

typedef struct UA_MethodNode UA_MethodNode, *PUA_MethodNode;

typedef enum UA_NodeClass {
    UA_NODECLASS_UNSPECIFIED=0,
    UA_NODECLASS_OBJECT=1,
    UA_NODECLASS_VARIABLE=2,
    UA_NODECLASS_METHOD=4,
    UA_NODECLASS_OBJECTTYPE=8,
    UA_NODECLASS_VARIABLETYPE=16,
    UA_NODECLASS_REFERENCETYPE=32,
    UA_NODECLASS_DATATYPE=64,
    UA_NODECLASS_VIEW=128
} UA_NodeClass;

typedef struct UA_QualifiedName UA_QualifiedName, *PUA_QualifiedName;

typedef struct UA_LocalizedText UA_LocalizedText, *PUA_LocalizedText;

typedef struct UA_ReferenceNode UA_ReferenceNode, *PUA_ReferenceNode;

typedef UA_StatusCode (*UA_MethodCallback)(void *, struct UA_NodeId, size_t, struct UA_Variant *, size_t, struct UA_Variant *);

typedef struct UA_ExpandedNodeId UA_ExpandedNodeId, *PUA_ExpandedNodeId;

struct UA_QualifiedName {
    UA_UInt16 namespaceIndex;
    struct UA_String name;
};

struct UA_LocalizedText {
    struct UA_String locale;
    struct UA_String text;
};

struct UA_MethodNode {
    struct UA_NodeId nodeId;
    enum UA_NodeClass nodeClass;
    struct UA_QualifiedName browseName;
    struct UA_LocalizedText displayName;
    struct UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
    size_t referencesSize;
    struct UA_ReferenceNode *references;
    UA_Boolean executable;
    UA_Boolean userExecutable;
    void *methodHandle;
    UA_MethodCallback attachedMethod;
};

struct UA_ExpandedNodeId {
    struct UA_NodeId nodeId;
    struct UA_String namespaceUri;
    UA_UInt32 serverIndex;
};

struct UA_ReferenceNode {
    struct UA_NodeId referenceTypeId;
    UA_Boolean isInverse;
    struct UA_ExpandedNodeId targetId;
};

typedef UA_StatusCode (*UA_copySignature)(void *, void *, struct UA_DataType *);

typedef struct UA_AsymmetricAlgorithmSecurityHeader UA_AsymmetricAlgorithmSecurityHeader, *PUA_AsymmetricAlgorithmSecurityHeader;

struct UA_AsymmetricAlgorithmSecurityHeader {
    UA_ByteString securityPolicyUri;
    UA_ByteString senderCertificate;
    UA_ByteString receiverCertificateThumbprint;
};

typedef struct UA_NotificationMessageEntry UA_NotificationMessageEntry, *PUA_NotificationMessageEntry;

typedef struct anon_struct_8_2_7cb2749d_for_listEntry anon_struct_8_2_7cb2749d_for_listEntry, *Panon_struct_8_2_7cb2749d_for_listEntry;

typedef struct UA_NotificationMessage UA_NotificationMessage, *PUA_NotificationMessage;

typedef struct UA_ExtensionObject UA_ExtensionObject, *PUA_ExtensionObject;

typedef enum UA_ExtensionObjectEncoding {
    UA_EXTENSIONOBJECT_ENCODED_NOBODY=0,
    UA_EXTENSIONOBJECT_ENCODED_BYTESTRING=1,
    UA_EXTENSIONOBJECT_ENCODED_XML=2,
    UA_EXTENSIONOBJECT_DECODED=3,
    UA_EXTENSIONOBJECT_DECODED_NODELETE=4
} UA_ExtensionObjectEncoding;

typedef union anon_union_32_2_2d7dbb79_for_content anon_union_32_2_2d7dbb79_for_content, *Panon_union_32_2_2d7dbb79_for_content;

typedef struct anon_struct_32_2_1c97a9e7_for_encoded anon_struct_32_2_1c97a9e7_for_encoded, *Panon_struct_32_2_1c97a9e7_for_encoded;

typedef struct anon_struct_8_2_391349cd_for_decoded anon_struct_8_2_391349cd_for_decoded, *Panon_struct_8_2_391349cd_for_decoded;

struct anon_struct_8_2_391349cd_for_decoded {
    struct UA_DataType *type;
    void *data;
};

struct anon_struct_32_2_1c97a9e7_for_encoded {
    struct UA_NodeId typeId;
    UA_ByteString body;
};

union anon_union_32_2_2d7dbb79_for_content {
    struct anon_struct_32_2_1c97a9e7_for_encoded encoded;
    struct anon_struct_8_2_391349cd_for_decoded decoded;
};

struct UA_ExtensionObject {
    enum UA_ExtensionObjectEncoding encoding;
    union anon_union_32_2_2d7dbb79_for_content content;
};

struct anon_struct_8_2_7cb2749d_for_listEntry {
    struct UA_NotificationMessageEntry *tqe_next;
    struct UA_NotificationMessageEntry **tqe_prev;
};

struct UA_NotificationMessage {
    UA_UInt32 sequenceNumber;
    UA_DateTime publishTime;
    size_t notificationDataSize;
    struct UA_ExtensionObject *notificationData;
};

struct UA_NotificationMessageEntry {
    struct anon_struct_8_2_7cb2749d_for_listEntry listEntry;
    struct UA_NotificationMessage message;
};

typedef struct UA_TcpHelloMessage UA_TcpHelloMessage, *PUA_TcpHelloMessage;

struct UA_TcpHelloMessage {
    UA_UInt32 protocolVersion;
    UA_UInt32 receiveBufferSize;
    UA_UInt32 sendBufferSize;
    UA_UInt32 maxMessageSize;
    UA_UInt32 maxChunkCount;
    struct UA_String endpointUrl;
};

typedef struct UA_Session UA_Session, *PUA_Session;

typedef struct UA_ApplicationDescription UA_ApplicationDescription, *PUA_ApplicationDescription;

typedef struct UA_SecureChannel UA_SecureChannel, *PUA_SecureChannel;

typedef struct ContinuationPointList ContinuationPointList, *PContinuationPointList;

typedef struct UA_ListOfUASubscriptions UA_ListOfUASubscriptions, *PUA_ListOfUASubscriptions;

typedef struct UA_ListOfQueuedPublishResponses UA_ListOfQueuedPublishResponses, *PUA_ListOfQueuedPublishResponses;

typedef enum UA_ApplicationType {
    UA_APPLICATIONTYPE_SERVER=0,
    UA_APPLICATIONTYPE_CLIENT=1,
    UA_APPLICATIONTYPE_CLIENTANDSERVER=2,
    UA_APPLICATIONTYPE_DISCOVERYSERVER=3
} UA_ApplicationType;

typedef enum UA_MessageSecurityMode {
    UA_MESSAGESECURITYMODE_INVALID=0,
    UA_MESSAGESECURITYMODE_NONE=1,
    UA_MESSAGESECURITYMODE_SIGN=2,
    UA_MESSAGESECURITYMODE_SIGNANDENCRYPT=3
} UA_MessageSecurityMode;

typedef struct UA_ChannelSecurityToken UA_ChannelSecurityToken, *PUA_ChannelSecurityToken;

typedef struct UA_Connection UA_Connection, *PUA_Connection;

typedef struct session_pointerlist session_pointerlist, *Psession_pointerlist;

typedef struct chunk_pointerlist chunk_pointerlist, *Pchunk_pointerlist;

typedef struct ContinuationPointEntry ContinuationPointEntry, *PContinuationPointEntry;

typedef struct UA_Subscription UA_Subscription, *PUA_Subscription;

typedef struct UA_PublishResponseEntry UA_PublishResponseEntry, *PUA_PublishResponseEntry;

typedef enum UA_ConnectionState {
    UA_CONNECTION_OPENING=0,
    UA_CONNECTION_ESTABLISHED=1,
    UA_CONNECTION_CLOSED=2
} UA_ConnectionState;

typedef struct UA_ConnectionConfig UA_ConnectionConfig, *PUA_ConnectionConfig;

typedef int32_t UA_Int32;

typedef struct SessionEntry SessionEntry, *PSessionEntry;

typedef struct ChunkEntry ChunkEntry, *PChunkEntry;

typedef struct anon_struct_8_2_19706e45_for_pointers anon_struct_8_2_19706e45_for_pointers, *Panon_struct_8_2_19706e45_for_pointers;

typedef struct UA_BrowseDescription UA_BrowseDescription, *PUA_BrowseDescription;


// WARNING! conflicting data type names: /DWARF/open62541.c/UA_Subscription/anon_struct_8_2_19706e45_for_listEntry - /DWARF/open62541.c/UA_Client_Subscription_s/anon_struct_8_2_19706e45_for_listEntry

typedef enum UA_SubscriptionState {
    UA_SUBSCRIPTIONSTATE_NORMAL=0,
    UA_SUBSCRIPTIONSTATE_LATE=1,
    UA_SUBSCRIPTIONSTATE_KEEPALIVE=2
} UA_SubscriptionState;

typedef struct UA_ListOfUAMonitoredItems UA_ListOfUAMonitoredItems, *PUA_ListOfUAMonitoredItems;

typedef struct UA_ListOfNotificationMessages UA_ListOfNotificationMessages, *PUA_ListOfNotificationMessages;

typedef struct anon_struct_4_1_9d7b2fe9_for_listEntry anon_struct_4_1_9d7b2fe9_for_listEntry, *Panon_struct_4_1_9d7b2fe9_for_listEntry;

typedef struct UA_PublishResponse UA_PublishResponse, *PUA_PublishResponse;


// WARNING! conflicting data type names: /DWARF/open62541.c/SessionEntry/anon_struct_8_2_19706e45_for_pointers - /DWARF/open62541.c/ContinuationPointEntry/anon_struct_8_2_19706e45_for_pointers


// WARNING! conflicting data type names: /DWARF/open62541.c/ChunkEntry/anon_struct_8_2_19706e45_for_pointers - /DWARF/open62541.c/ContinuationPointEntry/anon_struct_8_2_19706e45_for_pointers

typedef enum UA_BrowseDirection {
    UA_BROWSEDIRECTION_FORWARD=0,
    UA_BROWSEDIRECTION_INVERSE=1,
    UA_BROWSEDIRECTION_BOTH=2
} UA_BrowseDirection;

typedef struct UA_MonitoredItem UA_MonitoredItem, *PUA_MonitoredItem;

typedef struct UA_ResponseHeader UA_ResponseHeader, *PUA_ResponseHeader;

typedef struct UA_DiagnosticInfo UA_DiagnosticInfo, *PUA_DiagnosticInfo;


// WARNING! conflicting data type names: /DWARF/open62541.c/UA_MonitoredItem/anon_struct_8_2_19706e45_for_listEntry - /DWARF/open62541.c/UA_Client_Subscription_s/anon_struct_8_2_19706e45_for_listEntry

typedef enum UA_MonitoredItemType {
    UA_MONITOREDITEMTYPE_CHANGENOTIFY=1,
    UA_MONITOREDITEMTYPE_STATUSNOTIFY=2,
    UA_MONITOREDITEMTYPE_EVENTNOTIFY=4
} UA_MonitoredItemType;

typedef enum UA_TimestampsToReturn {
    UA_TIMESTAMPSTORETURN_SOURCE=0,
    UA_TIMESTAMPSTORETURN_SERVER=1,
    UA_TIMESTAMPSTORETURN_BOTH=2,
    UA_TIMESTAMPSTORETURN_NEITHER=3
} UA_TimestampsToReturn;

typedef enum UA_MonitoringMode {
    UA_MONITORINGMODE_DISABLED=0,
    UA_MONITORINGMODE_SAMPLING=1,
    UA_MONITORINGMODE_REPORTING=2
} UA_MonitoringMode;

typedef enum UA_DataChangeTrigger {
    UA_DATACHANGETRIGGER_STATUS=0,
    UA_DATACHANGETRIGGER_STATUSVALUE=1,
    UA_DATACHANGETRIGGER_STATUSVALUETIMESTAMP=2
} UA_DataChangeTrigger;

typedef struct QueueOfQueueDataValues QueueOfQueueDataValues, *PQueueOfQueueDataValues;

typedef struct MonitoredItem_queuedValue MonitoredItem_queuedValue, *PMonitoredItem_queuedValue;


// WARNING! conflicting data type names: /DWARF/open62541.c/MonitoredItem_queuedValue/anon_struct_8_2_7cb2749d_for_listEntry - /DWARF/open62541.c/UA_NotificationMessageEntry/anon_struct_8_2_7cb2749d_for_listEntry

struct UA_ListOfNotificationMessages {
    struct UA_NotificationMessageEntry *tqh_first;
    struct UA_NotificationMessageEntry **tqh_last;
};

struct UA_ConnectionConfig {
    UA_UInt32 protocolVersion;
    UA_UInt32 sendBufferSize;
    UA_UInt32 recvBufferSize;
    UA_UInt32 maxMessageSize;
    UA_UInt32 maxChunkCount;
};

struct UA_Connection {
    enum UA_ConnectionState state;
    struct UA_ConnectionConfig localConf;
    struct UA_ConnectionConfig remoteConf;
    struct UA_SecureChannel *channel;
    UA_Int32 sockfd;
    void *handle;
    UA_ByteString incompleteMessage;
    UA_StatusCode (*getSendBuffer)(struct UA_Connection *, size_t, UA_ByteString *);
    void (*releaseSendBuffer)(struct UA_Connection *, UA_ByteString *);
    UA_StatusCode (*send)(struct UA_Connection *, UA_ByteString *);
    UA_StatusCode (*recv)(struct UA_Connection *, UA_ByteString *, UA_UInt32);
    void (*releaseRecvBuffer)(struct UA_Connection *, UA_ByteString *);
    void (*close)(struct UA_Connection *);
};

struct anon_struct_4_1_9d7b2fe9_for_listEntry {
    struct UA_PublishResponseEntry *sqe_next;
};

struct UA_BrowseDescription {
    struct UA_NodeId nodeId;
    enum UA_BrowseDirection browseDirection;
    struct UA_NodeId referenceTypeId;
    UA_Boolean includeSubtypes;
    UA_UInt32 nodeClassMask;
    UA_UInt32 resultMask;
};

struct UA_DiagnosticInfo {
    UA_Boolean hasSymbolicId:1;
    UA_Boolean hasNamespaceUri:1;
    UA_Boolean hasLocalizedText:1;
    UA_Boolean hasLocale:1;
    UA_Boolean hasAdditionalInfo:1;
    UA_Boolean hasInnerStatusCode:1;
    UA_Boolean hasInnerDiagnosticInfo:1;
    UA_Int32 symbolicId;
    UA_Int32 namespaceUri;
    UA_Int32 localizedText;
    UA_Int32 locale;
    struct UA_String additionalInfo;
    UA_StatusCode innerStatusCode;
    struct UA_DiagnosticInfo *innerDiagnosticInfo;
};

struct UA_ResponseHeader {
    UA_DateTime timestamp;
    UA_UInt32 requestHandle;
    UA_StatusCode serviceResult;
    struct UA_DiagnosticInfo serviceDiagnostics;
    size_t stringTableSize;
    struct UA_String *stringTable;
    struct UA_ExtensionObject additionalHeader;
};

struct UA_PublishResponse {
    struct UA_ResponseHeader responseHeader;
    UA_UInt32 subscriptionId;
    size_t availableSequenceNumbersSize;
    UA_UInt32 *availableSequenceNumbers;
    UA_Boolean moreNotifications;
    struct UA_NotificationMessage notificationMessage;
    size_t resultsSize;
    UA_StatusCode *results;
    size_t diagnosticInfosSize;
    struct UA_DiagnosticInfo *diagnosticInfos;
};

struct UA_PublishResponseEntry {
    struct anon_struct_4_1_9d7b2fe9_for_listEntry listEntry;
    UA_UInt32 requestId;
    struct UA_PublishResponse response;
};

struct ChunkEntry {
    struct anon_struct_8_2_19706e45_for_pointers pointers;
    UA_UInt32 requestId;
    UA_ByteString bytes;
};

struct UA_ChannelSecurityToken {
    UA_UInt32 channelId;
    UA_UInt32 tokenId;
    UA_DateTime createdAt;
    UA_UInt32 revisedLifetime;
};

struct UA_ListOfQueuedPublishResponses {
    struct UA_PublishResponseEntry *sqh_first;
    struct UA_PublishResponseEntry **sqh_last;
};

struct ContinuationPointList {
    struct ContinuationPointEntry *lh_first;
};

struct UA_ListOfUASubscriptions {
    struct UA_Subscription *lh_first;
};

struct UA_ApplicationDescription {
    struct UA_String applicationUri;
    struct UA_String productUri;
    struct UA_LocalizedText applicationName;
    enum UA_ApplicationType applicationType;
    struct UA_String gatewayServerUri;
    struct UA_String discoveryProfileUri;
    size_t discoveryUrlsSize;
    struct UA_String *discoveryUrls;
};

struct UA_Session {
    struct UA_ApplicationDescription clientDescription;
    UA_Boolean activated;
    struct UA_String sessionName;
    struct UA_NodeId authenticationToken;
    struct UA_NodeId sessionId;
    UA_UInt32 maxRequestMessageSize;
    UA_UInt32 maxResponseMessageSize;
    UA_Double timeout;
    UA_DateTime validTill;
    struct UA_SecureChannel *channel;
    UA_UInt16 availableContinuationPoints;
    struct ContinuationPointList continuationPoints;
    UA_UInt32 lastSubscriptionID;
    struct UA_ListOfUASubscriptions serverSubscriptions;
    struct UA_ListOfQueuedPublishResponses responseQueue;
};

struct session_pointerlist {
    struct SessionEntry *lh_first;
};

struct chunk_pointerlist {
    struct ChunkEntry *lh_first;
};

struct UA_SecureChannel {
    enum UA_MessageSecurityMode securityMode;
    struct UA_ChannelSecurityToken securityToken;
    struct UA_ChannelSecurityToken nextSecurityToken;
    struct UA_AsymmetricAlgorithmSecurityHeader clientAsymAlgSettings;
    struct UA_AsymmetricAlgorithmSecurityHeader serverAsymAlgSettings;
    UA_ByteString clientNonce;
    UA_ByteString serverNonce;
    UA_UInt32 receiveSequenceNumber;
    UA_UInt32 sendSequenceNumber;
    struct UA_Connection *connection;
    struct session_pointerlist sessions;
    struct chunk_pointerlist chunks;
};

struct UA_ListOfUAMonitoredItems {
    struct UA_MonitoredItem *lh_first;
};

struct MonitoredItem_queuedValue {
    struct anon_struct_8_2_7cb2749d_for_listEntry listEntry;
    UA_UInt32 clientHandle;
    struct UA_DataValue value;
};

struct anon_struct_8_2_19706e45_for_pointers {
    struct ContinuationPointEntry *le_next;
    struct ContinuationPointEntry **le_prev;
};

struct ContinuationPointEntry {
    struct anon_struct_8_2_19706e45_for_pointers pointers;
    UA_ByteString identifier;
    struct UA_BrowseDescription browseDescription;
    UA_UInt32 continuationIndex;
    UA_UInt32 maxReferences;
};

struct SessionEntry {
    struct anon_struct_8_2_19706e45_for_pointers pointers;
    struct UA_Session *session;
};

struct QueueOfQueueDataValues {
    struct MonitoredItem_queuedValue *tqh_first;
    struct MonitoredItem_queuedValue **tqh_last;
};

struct UA_MonitoredItem {
    struct anon_struct_8_2_19706e45_for_listEntry listEntry;
    struct UA_Subscription *subscription;
    UA_UInt32 itemId;
    enum UA_MonitoredItemType monitoredItemType;
    enum UA_TimestampsToReturn timestampsToReturn;
    enum UA_MonitoringMode monitoringMode;
    struct UA_NodeId monitoredNodeId;
    UA_UInt32 attributeID;
    UA_UInt32 clientHandle;
    UA_Double samplingInterval;
    UA_UInt32 currentQueueSize;
    UA_UInt32 maxQueueSize;
    UA_Boolean discardOldest;
    struct UA_String indexRange;
    enum UA_DataChangeTrigger trigger;
    struct UA_Guid sampleJobGuid;
    UA_Boolean sampleJobIsRegistered;
    UA_ByteString lastSampledValue;
    struct QueueOfQueueDataValues queue;
};

struct UA_Subscription {
    struct anon_struct_8_2_19706e45_for_listEntry listEntry;
    struct UA_Session *session;
    UA_UInt32 lifeTimeCount;
    UA_UInt32 maxKeepAliveCount;
    UA_Double publishingInterval;
    UA_UInt32 subscriptionID;
    UA_UInt32 notificationsPerPublish;
    UA_Boolean publishingEnabled;
    UA_UInt32 priority;
    enum UA_SubscriptionState state;
    UA_UInt32 sequenceNumber;
    UA_UInt32 currentKeepAliveCount;
    UA_UInt32 currentLifetimeCount;
    UA_UInt32 lastMonitoredItemId;
    struct UA_Guid publishJobGuid;
    UA_Boolean publishJobIsRegistered;
    struct UA_ListOfUAMonitoredItems monitoredItems;
    struct UA_ListOfNotificationMessages retransmissionQueue;
    UA_UInt32 retransmissionQueueSize;
};

typedef struct UA_SecureChannelManager UA_SecureChannelManager, *PUA_SecureChannelManager;

typedef struct channel_list channel_list, *Pchannel_list;

typedef struct UA_Server UA_Server, *PUA_Server;

typedef struct channel_list_entry channel_list_entry, *Pchannel_list_entry;

typedef struct UA_EndpointDescription UA_EndpointDescription, *PUA_EndpointDescription;

typedef struct UA_SessionManager UA_SessionManager, *PUA_SessionManager;

typedef struct UA_NodeStore UA_NodeStore, *PUA_NodeStore;

typedef struct RepeatedJobsList RepeatedJobsList, *PRepeatedJobsList;

typedef struct DelayedJobsList DelayedJobsList, *PDelayedJobsList;

typedef struct UA_ServerConfig UA_ServerConfig, *PUA_ServerConfig;


// WARNING! conflicting data type names: /DWARF/open62541.c/channel_list_entry/anon_struct_8_2_19706e45_for_pointers - /DWARF/open62541.c/ContinuationPointEntry/anon_struct_8_2_19706e45_for_pointers

typedef struct UA_UserTokenPolicy UA_UserTokenPolicy, *PUA_UserTokenPolicy;

typedef struct session_list session_list, *Psession_list;

typedef struct UA_NodeStoreEntry UA_NodeStoreEntry, *PUA_NodeStoreEntry;

typedef struct RepeatedJob RepeatedJob, *PRepeatedJob;

typedef struct UA_DelayedJob UA_DelayedJob, *PUA_DelayedJob;

typedef enum UA_LogLevel {
    UA_LOGLEVEL_TRACE=0,
    UA_LOGLEVEL_DEBUG=1,
    UA_LOGLEVEL_INFO=2,
    UA_LOGLEVEL_WARNING=3,
    UA_LOGLEVEL_ERROR=4,
    UA_LOGLEVEL_FATAL=5
} UA_LogLevel;

typedef enum UA_LogCategory {
    UA_LOGCATEGORY_NETWORK=0,
    UA_LOGCATEGORY_SECURECHANNEL=1,
    UA_LOGCATEGORY_SESSION=2,
    UA_LOGCATEGORY_SERVER=3,
    UA_LOGCATEGORY_CLIENT=4,
    UA_LOGCATEGORY_USERLAND=5
} UA_LogCategory;

typedef void (*UA_Logger)(enum UA_LogLevel, enum UA_LogCategory, char *, ...);

typedef struct UA_BuildInfo UA_BuildInfo, *PUA_BuildInfo;

typedef struct UA_ServerNetworkLayer UA_ServerNetworkLayer, *PUA_ServerNetworkLayer;

typedef struct UA_Job UA_Job, *PUA_Job;

typedef struct UA_UsernamePasswordLogin UA_UsernamePasswordLogin, *PUA_UsernamePasswordLogin;

typedef struct UA_DoubleRange UA_DoubleRange, *PUA_DoubleRange;

typedef struct UA_UInt32Range UA_UInt32Range, *PUA_UInt32Range;

typedef enum UA_UserTokenType {
    UA_USERTOKENTYPE_ANONYMOUS=0,
    UA_USERTOKENTYPE_USERNAME=1,
    UA_USERTOKENTYPE_CERTIFICATE=2,
    UA_USERTOKENTYPE_ISSUEDTOKEN=3,
    UA_USERTOKENTYPE_KERBEROS=4
} UA_UserTokenType;

typedef struct session_list_entry session_list_entry, *Psession_list_entry;

typedef struct UA_Node UA_Node, *PUA_Node;

typedef struct anon_struct_8_2_19706e45_for_next anon_struct_8_2_19706e45_for_next, *Panon_struct_8_2_19706e45_for_next;

typedef uint64_t UA_UInt64;

typedef struct anon_struct_4_1_94fc07a4_for_next anon_struct_4_1_94fc07a4_for_next, *Panon_struct_4_1_94fc07a4_for_next;

typedef enum anon_enum_32 {
    IPPROTO_IP=0,
    PTHREAD_CANCEL_DEFERRED=0,
    UA_BROWSERESULTMASK_NONE=0,
    UA_JOBTYPE_NOTHING=0,
    UA_NODECLASS_UNSPECIFIED=0,
    IPPROTO_ICMP=1,
    LOGFLAG_FILE=1,
    PTHREAD_CANCEL_ASYNCHRONOUS=1,
    UA_ATTRIBUTEID_NODEID=1,
    UA_BROWSERESULTMASK_REFERENCETYPEID=1,
    UA_JOBTYPE_DETACHCONNECTION=1,
    UA_NODECLASS_OBJECT=1,
    XML_PARSE_RECOVER=1,
    _ISblank=1,
    IPPROTO_IGMP=2,
    LOGFLAG_STDOUT=2,
    UA_ATTRIBUTEID_NODECLASS=2,
    UA_BROWSERESULTMASK_ISFORWARD=2,
    UA_JOBTYPE_BINARYMESSAGE_NETWORKLAYER=2,
    UA_NODECLASS_VARIABLE=2,
    XML_PARSE_NOENT=2,
    _IScntrl=2,
    UA_ATTRIBUTEID_BROWSENAME=3,
    UA_BROWSERESULTMASK_REFERENCETYPEINFO=3,
    UA_JOBTYPE_BINARYMESSAGE_ALLOCATED=3,
    IPPROTO_IPIP=4,
    LOGFLAG_STDERR=4,
    UA_ATTRIBUTEID_DISPLAYNAME=4,
    UA_BROWSERESULTMASK_NODECLASS=4,
    UA_JOBTYPE_METHODCALL=4,
    UA_NODECLASS_METHOD=4,
    XML_PARSE_DTDLOAD=4,
    _ISpunct=4,
    UA_ATTRIBUTEID_DESCRIPTION=5,
    UA_JOBTYPE_METHODCALL_DELAYED=5,
    IPPROTO_TCP=6,
    UA_ATTRIBUTEID_WRITEMASK=6,
    UA_ATTRIBUTEID_USERWRITEMASK=7,
    IPPROTO_EGP=8,
    LOGFLAG_SYSLOG=8,
    UA_ATTRIBUTEID_ISABSTRACT=8,
    UA_BROWSERESULTMASK_BROWSENAME=8,
    UA_NODECLASS_OBJECTTYPE=8,
    XML_PARSE_DTDATTR=8,
    _ISalnum=8,
    UA_ATTRIBUTEID_SYMMETRIC=9,
    UA_ATTRIBUTEID_INVERSENAME=10,
    UA_ATTRIBUTEID_CONTAINSNOLOOPS=11,
    IPPROTO_PUP=12,
    UA_ATTRIBUTEID_EVENTNOTIFIER=12,
    UA_ATTRIBUTEID_VALUE=13,
    UA_ATTRIBUTEID_DATATYPE=14,
    UA_ATTRIBUTEID_VALUERANK=15,
    LOGFLAG_ERROR=16,
    UA_ATTRIBUTEID_ARRAYDIMENSIONS=16,
    UA_BROWSERESULTMASK_DISPLAYNAME=16,
    UA_NODECLASS_VARIABLETYPE=16,
    XML_PARSE_DTDVALID=16,
    IPPROTO_UDP=17,
    UA_ATTRIBUTEID_ACCESSLEVEL=17,
    UA_ATTRIBUTEID_USERACCESSLEVEL=18,
    UA_ATTRIBUTEID_MINIMUMSAMPLINGINTERVAL=19,
    UA_ATTRIBUTEID_HISTORIZING=20,
    UA_ATTRIBUTEID_EXECUTABLE=21,
    IPPROTO_IDP=22,
    UA_ATTRIBUTEID_USEREXECUTABLE=22,
    IPPROTO_TP=29,
    LOGFLAG_INFO=32,
    UA_BROWSERESULTMASK_TYPEDEFINITION=32,
    UA_NODECLASS_REFERENCETYPE=32,
    XML_PARSE_NOERROR=32,
    IPPROTO_DCCP=33,
    IPPROTO_IPV6=41,
    IPPROTO_RSVP=46,
    IPPROTO_GRE=47,
    IPPROTO_ESP=50,
    IPPROTO_AH=51,
    UA_BROWSERESULTMASK_TARGETINFO=60,
    UA_BROWSERESULTMASK_ALL=63,
    LOGFLAG_DEBUG=64,
    UA_NODECLASS_DATATYPE=64,
    XML_PARSE_NOWARNING=64,
    IPPROTO_MTP=92,
    IPPROTO_BEETPH=94,
    IPPROTO_ENCAP=98,
    IPPROTO_PIM=103,
    IPPROTO_COMP=108,
    LOGFLAG_TRACE=128,
    UA_NODECLASS_VIEW=128,
    XML_PARSE_PEDANTIC=128,
    IPPROTO_SCTP=132,
    IPPROTO_UDPLITE=136,
    IPPROTO_MPLS=137,
    IPPROTO_RAW=255,
    IPPROTO_MAX=256,
    LOGFLAG_WARN=256,
    XML_PARSE_NOBLANKS=256,
    _ISupper=256,
    XML_PARSE_SAX1=512,
    _ISlower=512,
    XML_PARSE_XINCLUDE=1024,
    _ISalpha=1024,
    XML_PARSE_NONET=2048,
    _ISdigit=2048,
    XML_PARSE_NODICT=4096,
    _ISxdigit=4096,
    XML_PARSE_NSCLEAN=8192,
    _ISspace=8192,
    XML_PARSE_NOCDATA=16384,
    _ISprint=16384,
    XML_PARSE_NOXINCNODE=32768,
    _ISgraph=32768,
    XML_PARSE_COMPACT=65536,
    XML_PARSE_OLD10=131072,
    XML_PARSE_NOBASEFIX=262144,
    XML_PARSE_HUGE=524288,
    XML_PARSE_OLDSAX=1048576,
    XML_PARSE_IGNORE_ENC=2097152,
    XML_PARSE_BIG_LINES=4194304,
    XML_PARSE_NOXXE=8388608,
    UA_CHUNKTYPE_ABORT=1090519040,
    UA_CHUNKTYPE_INTERMEDIATE=1124073472,
    UA_CHUNKTYPE_FINAL=1174405120
} anon_enum_32;

typedef union anon_union_12_3_a85eb80d_for_job anon_union_12_3_a85eb80d_for_job, *Panon_union_12_3_a85eb80d_for_job;


// WARNING! conflicting data type names: /DWARF/open62541.c/session_list_entry/anon_struct_8_2_19706e45_for_pointers - /DWARF/open62541.c/ContinuationPointEntry/anon_struct_8_2_19706e45_for_pointers

typedef struct anon_struct_12_2_85b339b0_for_binaryMessage anon_struct_12_2_85b339b0_for_binaryMessage, *Panon_struct_12_2_85b339b0_for_binaryMessage;

typedef struct anon_struct_8_2_a8376dd4_for_methodCall anon_struct_8_2_a8376dd4_for_methodCall, *Panon_struct_8_2_a8376dd4_for_methodCall;

typedef void (*UA_ServerCallback)(struct UA_Server *, void *);

struct anon_struct_4_1_94fc07a4_for_next {
    struct UA_DelayedJob *sle_next;
};

struct anon_struct_12_2_85b339b0_for_binaryMessage {
    struct UA_Connection *connection;
    UA_ByteString message;
};

struct anon_struct_8_2_a8376dd4_for_methodCall {
    void *data;
    UA_ServerCallback method;
};

union anon_union_12_3_a85eb80d_for_job {
    struct UA_Connection *closeConnection;
    struct anon_struct_12_2_85b339b0_for_binaryMessage binaryMessage;
    struct anon_struct_8_2_a8376dd4_for_methodCall methodCall;
};

struct UA_Job {
    enum anon_enum_32 type;
    union anon_union_12_3_a85eb80d_for_job job;
};

struct UA_DelayedJob {
    struct anon_struct_4_1_94fc07a4_for_next next;
    struct UA_Job job;
};

struct UA_UInt32Range {
    UA_UInt32 min;
    UA_UInt32 max;
};

struct UA_BuildInfo {
    struct UA_String productUri;
    struct UA_String manufacturerName;
    struct UA_String productName;
    struct UA_String softwareVersion;
    struct UA_String buildNumber;
    UA_DateTime buildDate;
};

struct UA_DoubleRange {
    UA_Double min;
    UA_Double max;
};

struct UA_ServerConfig {
    UA_UInt16 nThreads;
    UA_Logger logger;
    struct UA_BuildInfo buildInfo;
    struct UA_ApplicationDescription applicationDescription;
    UA_ByteString serverCertificate;
    size_t networkLayersSize;
    struct UA_ServerNetworkLayer *networkLayers;
    UA_Boolean enableAnonymousLogin;
    UA_Boolean enableUsernamePasswordLogin;
    size_t usernamePasswordLoginsSize;
    struct UA_UsernamePasswordLogin *usernamePasswordLogins;
    UA_UInt16 maxSecureChannels;
    UA_UInt32 maxSecurityTokenLifetime;
    UA_UInt16 maxSessions;
    UA_Double maxSessionTimeout;
    struct UA_DoubleRange publishingIntervalLimits;
    struct UA_UInt32Range lifeTimeCountLimits;
    struct UA_UInt32Range keepAliveCountLimits;
    UA_UInt32 maxNotificationsPerPublish;
    UA_UInt32 maxRetransmissionQueueSize;
    struct UA_DoubleRange samplingIntervalLimits;
    struct UA_UInt32Range queueSizeLimits;
};

struct RepeatedJobsList {
    struct RepeatedJob *lh_first;
};

struct UA_Node {
    struct UA_NodeId nodeId;
    enum UA_NodeClass nodeClass;
    struct UA_QualifiedName browseName;
    struct UA_LocalizedText displayName;
    struct UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
    size_t referencesSize;
    struct UA_ReferenceNode *references;
};

struct DelayedJobsList {
    struct UA_DelayedJob *slh_first;
};

struct channel_list {
    struct channel_list_entry *lh_first;
};

struct UA_SecureChannelManager {
    struct channel_list channels;
    UA_UInt32 currentChannelCount;
    UA_UInt32 lastChannelId;
    UA_UInt32 lastTokenId;
    struct UA_Server *server;
};

struct session_list {
    struct session_list_entry *lh_first;
};

struct UA_SessionManager {
    struct session_list sessions;
    UA_UInt32 currentSessionCount;
    struct UA_Server *server;
};

struct UA_Server {
    UA_DateTime startTime;
    size_t endpointDescriptionsSize;
    struct UA_EndpointDescription *endpointDescriptions;
    struct UA_SecureChannelManager secureChannelManager;
    struct UA_SessionManager sessionManager;
    struct UA_NodeStore *nodestore;
    size_t namespacesSize;
    struct UA_String *namespaces;
    struct RepeatedJobsList repeatedJobs;
    struct DelayedJobsList delayedCallbacks;
    struct UA_ServerConfig config;
};

struct UA_EndpointDescription {
    struct UA_String endpointUrl;
    struct UA_ApplicationDescription server;
    UA_ByteString serverCertificate;
    enum UA_MessageSecurityMode securityMode;
    struct UA_String securityPolicyUri;
    size_t userIdentityTokensSize;
    struct UA_UserTokenPolicy *userIdentityTokens;
    struct UA_String transportProfileUri;
    UA_Byte securityLevel;
};

struct anon_struct_8_2_19706e45_for_next {
    struct RepeatedJob *le_next;
    struct RepeatedJob **le_prev;
};

struct UA_NodeStoreEntry {
    struct UA_NodeStoreEntry *orig;
    struct UA_Node node;
};

struct UA_UsernamePasswordLogin {
    struct UA_String username;
    struct UA_String password;
};

struct session_list_entry {
    struct anon_struct_8_2_19706e45_for_pointers pointers;
    struct UA_Session session;
};

struct UA_UserTokenPolicy {
    struct UA_String policyId;
    enum UA_UserTokenType tokenType;
    struct UA_String issuedTokenType;
    struct UA_String issuerEndpointUrl;
    struct UA_String securityPolicyUri;
};

struct channel_list_entry {
    struct UA_SecureChannel channel;
    struct anon_struct_8_2_19706e45_for_pointers pointers;
};

struct RepeatedJob {
    struct anon_struct_8_2_19706e45_for_next next;
    UA_DateTime nextTime;
    UA_UInt64 interval;
    struct UA_Guid id;
    struct UA_Job job;
};

struct UA_ServerNetworkLayer {
    void *handle;
    struct UA_String discoveryUrl;
    UA_StatusCode (*start)(struct UA_ServerNetworkLayer *, UA_Logger);
    size_t (*getJobs)(struct UA_ServerNetworkLayer *, struct UA_Job **, UA_UInt16);
    size_t (*stop)(struct UA_ServerNetworkLayer *, struct UA_Job **);
    void (*deleteMembers)(struct UA_ServerNetworkLayer *);
};

struct UA_NodeStore {
    struct UA_NodeStoreEntry **entries;
    UA_UInt32 size;
    UA_UInt32 count;
    UA_UInt32 sizePrimeIndex;
};

typedef struct UA_Client_MonitoredItem_s UA_Client_MonitoredItem;

typedef enum type_equivalence {
    TYPE_EQUIVALENCE_NONE=0,
    TYPE_EQUIVALENCE_ENUM=1,
    TYPE_EQUIVALENCE_OPAQUE=2
} type_equivalence;

typedef void (*UA_Service)(struct UA_Server *, struct UA_Session *, void *, void *);

typedef struct UA_Client UA_Client, *PUA_Client;

typedef enum UA_ClientState {
    UA_CLIENTSTATE_READY=0,
    UA_CLIENTSTATE_CONNECTED=1,
    UA_CLIENTSTATE_FAULTED=2,
    UA_CLIENTSTATE_ERRORED=3
} UA_ClientState;

typedef enum UA_Client_Authentication {
    UA_CLIENTAUTHENTICATION_NONE=0,
    UA_CLIENTAUTHENTICATION_USERNAME=1
} UA_Client_Authentication;

typedef struct UA_ListOfUnacknowledgedNotificationNumbers UA_ListOfUnacknowledgedNotificationNumbers, *PUA_ListOfUnacknowledgedNotificationNumbers;

typedef struct UA_ListOfClientSubscriptionItems UA_ListOfClientSubscriptionItems, *PUA_ListOfClientSubscriptionItems;

typedef struct UA_ClientConfig UA_ClientConfig, *PUA_ClientConfig;

typedef struct UA_Client_NotificationsAckNumber_s UA_Client_NotificationsAckNumber_s, *PUA_Client_NotificationsAckNumber_s;

typedef UA_Connection (*UA_ConnectClientConnection)(struct UA_ConnectionConfig, char *, UA_Logger);


// WARNING! conflicting data type names: /DWARF/open62541.c/UA_Client_NotificationsAckNumber_s/anon_struct_8_2_19706e45_for_listEntry - /DWARF/open62541.c/UA_Client_Subscription_s/anon_struct_8_2_19706e45_for_listEntry

typedef struct UA_SubscriptionAcknowledgement UA_SubscriptionAcknowledgement, *PUA_SubscriptionAcknowledgement;

struct UA_ListOfUnacknowledgedNotificationNumbers {
    struct UA_Client_NotificationsAckNumber_s *lh_first;
};

struct UA_SubscriptionAcknowledgement {
    UA_UInt32 subscriptionId;
    UA_UInt32 sequenceNumber;
};

struct UA_Client_NotificationsAckNumber_s {
    struct anon_struct_8_2_19706e45_for_listEntry listEntry;
    struct UA_SubscriptionAcknowledgement subAck;
};

struct UA_ListOfClientSubscriptionItems {
    struct UA_Client_Subscription_s *lh_first;
};

struct UA_ClientConfig {
    UA_UInt32 timeout;
    UA_UInt32 secureChannelLifeTime;
    UA_Logger logger;
    struct UA_ConnectionConfig localConnectionConfig;
    UA_ConnectClientConnection connectionFunc;
};

struct UA_Client {
    enum UA_ClientState state;
    struct UA_Connection *connection;
    struct UA_SecureChannel *channel;
    struct UA_String endpointUrl;
    UA_UInt32 requestId;
    enum UA_Client_Authentication authenticationMethod;
    struct UA_String username;
    struct UA_String password;
    struct UA_UserTokenPolicy token;
    struct UA_NodeId authenticationToken;
    UA_UInt32 requestHandle;
    UA_UInt32 monitoredItemHandles;
    struct UA_ListOfUnacknowledgedNotificationNumbers pendingNotificationsAcks;
    struct UA_ListOfClientSubscriptionItems subscriptions;
    struct UA_ClientConfig config;
    UA_DateTime scRenewAt;
};

typedef struct UA_VariableTypeNode UA_VariableTypeNode, *PUA_VariableTypeNode;

typedef enum UA_ValueSource {
    UA_VALUESOURCE_DATA=0,
    UA_VALUESOURCE_DATASOURCE=1
} UA_ValueSource;

typedef union anon_union_80_2_91199e5c_for_value anon_union_80_2_91199e5c_for_value, *Panon_union_80_2_91199e5c_for_value;

typedef struct anon_struct_80_2_a144a237_for_data anon_struct_80_2_a144a237_for_data, *Panon_struct_80_2_a144a237_for_data;

typedef struct UA_DataSource UA_DataSource, *PUA_DataSource;

typedef struct UA_NumericRange UA_NumericRange, *PUA_NumericRange;

typedef struct UA_ValueCallback UA_ValueCallback, *PUA_ValueCallback;

typedef struct UA_NumericRangeDimension UA_NumericRangeDimension, *PUA_NumericRangeDimension;

struct UA_ValueCallback {
    void *handle;
    void (*onRead)(void *, struct UA_NodeId, struct UA_Variant *, struct UA_NumericRange *);
    void (*onWrite)(void *, struct UA_NodeId, struct UA_Variant *, struct UA_NumericRange *);
};

struct anon_struct_80_2_a144a237_for_data {
    struct UA_DataValue value;
    struct UA_ValueCallback callback;
};

struct UA_DataSource {
    void *handle;
    UA_StatusCode (*read)(void *, struct UA_NodeId, UA_Boolean, struct UA_NumericRange *, struct UA_DataValue *, int);
    UA_StatusCode (*write)(void *, struct UA_NodeId, struct UA_Variant *, struct UA_NumericRange *);
};

union anon_union_80_2_91199e5c_for_value {
    struct anon_struct_80_2_a144a237_for_data data;
    struct UA_DataSource dataSource;
};

struct UA_VariableTypeNode {
    struct UA_NodeId nodeId;
    enum UA_NodeClass nodeClass;
    struct UA_QualifiedName browseName;
    struct UA_LocalizedText displayName;
    struct UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
    size_t referencesSize;
    struct UA_ReferenceNode *references;
    struct UA_NodeId dataType;
    UA_Int32 valueRank;
    size_t arrayDimensionsSize;
    UA_UInt32 *arrayDimensions;
    enum UA_ValueSource valueSource;
    union anon_union_80_2_91199e5c_for_value value;
    UA_Boolean isAbstract;
};

struct UA_NumericRangeDimension {
    UA_UInt32 min;
    UA_UInt32 max;
};

struct UA_NumericRange {
    size_t dimensionsSize;
    struct UA_NumericRangeDimension *dimensions;
};

typedef struct UA_VariableNode UA_VariableNode, *PUA_VariableNode;

struct UA_VariableNode {
    struct UA_NodeId nodeId;
    enum UA_NodeClass nodeClass;
    struct UA_QualifiedName browseName;
    struct UA_LocalizedText displayName;
    struct UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
    size_t referencesSize;
    struct UA_ReferenceNode *references;
    struct UA_NodeId dataType;
    UA_Int32 valueRank;
    size_t arrayDimensionsSize;
    UA_UInt32 *arrayDimensions;
    enum UA_ValueSource valueSource;
    union anon_union_80_2_91199e5c_for_value value;
    UA_Byte accessLevel;
    UA_Byte userAccessLevel;
    UA_Double minimumSamplingInterval;
    UA_Boolean historizing;
};

typedef size_t (*UA_calcSizeBinarySignature)(void *, struct UA_DataType *);

typedef struct UA_TcpAcknowledgeMessage UA_TcpAcknowledgeMessage, *PUA_TcpAcknowledgeMessage;

struct UA_TcpAcknowledgeMessage {
    UA_UInt32 protocolVersion;
    UA_UInt32 receiveBufferSize;
    UA_UInt32 sendBufferSize;
    UA_UInt32 maxMessageSize;
    UA_UInt32 maxChunkCount;
};

typedef struct ResponseDescription ResponseDescription, *PResponseDescription;

struct ResponseDescription {
    struct UA_Client *client;
    UA_Boolean processed;
    UA_UInt32 requestId;
    void *response;
    struct UA_DataType *responseType;
};

typedef UA_StatusCode (*UA_exchangeEncodeBuffer)(void *, UA_ByteString *, size_t);

typedef UA_StatusCode (*UA_encodeBinarySignature)(void *, struct UA_DataType *);

typedef struct UA_SequenceHeader UA_SequenceHeader, *PUA_SequenceHeader;

struct UA_SequenceHeader {
    UA_UInt32 sequenceNumber;
    UA_UInt32 requestId;
};

typedef struct pcg_state_setseq_64 pcg_state_setseq_64, *Ppcg_state_setseq_64;

struct pcg_state_setseq_64 {
    uint64_t state;
    uint64_t inc;
};

typedef struct UA_ReferenceTypeNode UA_ReferenceTypeNode, *PUA_ReferenceTypeNode;

struct UA_ReferenceTypeNode {
    struct UA_NodeId nodeId;
    enum UA_NodeClass nodeClass;
    struct UA_QualifiedName browseName;
    struct UA_LocalizedText displayName;
    struct UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
    size_t referencesSize;
    struct UA_ReferenceNode *references;
    UA_Boolean isAbstract;
    UA_Boolean symmetric;
    struct UA_LocalizedText inverseName;
};

typedef struct UA_ChunkInfo UA_ChunkInfo, *PUA_ChunkInfo;

struct UA_ChunkInfo {
    struct UA_SecureChannel *channel;
    UA_UInt32 requestId;
    UA_UInt32 messageType;
    UA_UInt16 chunksSoFar;
    size_t messageSizeSoFar;
    UA_Boolean final;
    UA_StatusCode errorCode;
};

typedef struct ConnectionMapping ConnectionMapping, *PConnectionMapping;

struct ConnectionMapping {
    struct UA_Connection *connection;
    UA_Int32 sockfd;
};

typedef struct UA_TcpMessageHeader UA_TcpMessageHeader, *PUA_TcpMessageHeader;

struct UA_TcpMessageHeader {
    UA_UInt32 messageTypeAndChunkType;
    UA_UInt32 messageSize;
};

typedef struct UA_SecureConversationMessageHeader UA_SecureConversationMessageHeader, *PUA_SecureConversationMessageHeader;

struct UA_SecureConversationMessageHeader {
    struct UA_TcpMessageHeader messageHeader;
    UA_UInt32 secureChannelId;
};

typedef struct UA_ViewNode UA_ViewNode, *PUA_ViewNode;

struct UA_ViewNode {
    struct UA_NodeId nodeId;
    enum UA_NodeClass nodeClass;
    struct UA_QualifiedName browseName;
    struct UA_LocalizedText displayName;
    struct UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
    size_t referencesSize;
    struct UA_ReferenceNode *references;
    UA_Byte eventNotifier;
    UA_Boolean containsNoLoops;
};

typedef struct addMethodCallback addMethodCallback, *PaddMethodCallback;

struct addMethodCallback {
    UA_MethodCallback callback;
    void *handle;
};

typedef struct UA_ObjectNode UA_ObjectNode, *PUA_ObjectNode;

struct UA_ObjectNode {
    struct UA_NodeId nodeId;
    enum UA_NodeClass nodeClass;
    struct UA_QualifiedName browseName;
    struct UA_LocalizedText displayName;
    struct UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
    size_t referencesSize;
    struct UA_ReferenceNode *references;
    UA_Byte eventNotifier;
    void *instanceHandle;
};

typedef struct ServerNetworkLayerTCP ServerNetworkLayerTCP, *PServerNetworkLayerTCP;

struct ServerNetworkLayerTCP {
    struct UA_ConnectionConfig conf;
    UA_UInt16 port;
    UA_Logger logger;
    UA_Int32 serversockfd;
    size_t mappingsSize;
    struct ConnectionMapping *mappings;
};

typedef void (*UA_deleteMembersSignature)(void *, struct UA_DataType *);

typedef struct UA_Client_NotificationsAckNumber_s UA_Client_NotificationsAckNumber;

typedef UA_StatusCode (*UA_decodeBinarySignature)(void *, struct UA_DataType *);

typedef UA_UInt32 hash_t;

typedef UA_StatusCode (*UA_EditNodeCallback)(struct UA_Server *, struct UA_Session *, struct UA_Node *, void *);

typedef enum UA_MessageType {
    UA_MESSAGETYPE_MSG=4674381,
    UA_MESSAGETYPE_ACK=4932417,
    UA_MESSAGETYPE_HEL=4998472,
    UA_MESSAGETYPE_OPN=5132367,
    UA_MESSAGETYPE_CLO=5196867
} UA_MessageType;

typedef struct UA_ObjectTypeNode UA_ObjectTypeNode, *PUA_ObjectTypeNode;

typedef struct UA_ObjectLifecycleManagement UA_ObjectLifecycleManagement, *PUA_ObjectLifecycleManagement;

struct UA_ObjectLifecycleManagement {
    void * (*constructor)(struct UA_NodeId);
    void (*destructor)(struct UA_NodeId, void *);
};

struct UA_ObjectTypeNode {
    struct UA_NodeId nodeId;
    enum UA_NodeClass nodeClass;
    struct UA_QualifiedName browseName;
    struct UA_LocalizedText displayName;
    struct UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
    size_t referencesSize;
    struct UA_ReferenceNode *references;
    UA_Boolean isAbstract;
    struct UA_ObjectLifecycleManagement lifecycleManagement;
};

typedef struct pcg_state_setseq_64 pcg32_random_t;

typedef struct UA_DataTypeNode UA_DataTypeNode, *PUA_DataTypeNode;

struct UA_DataTypeNode {
    struct UA_NodeId nodeId;
    enum UA_NodeClass nodeClass;
    struct UA_QualifiedName browseName;
    struct UA_LocalizedText displayName;
    struct UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
    size_t referencesSize;
    struct UA_ReferenceNode *references;
    UA_Boolean isAbstract;
};

typedef void (*UA_NodeStore_nodeVisitor)(struct UA_Node *);

typedef enum UA_VARIANT_ENCODINGMASKTYPE {
    UA_VARIANT_ENCODINGMASKTYPE_TYPEID_MASK=63,
    UA_VARIANT_ENCODINGMASKTYPE_DIMENSIONS=64,
    UA_VARIANT_ENCODINGMASKTYPE_ARRAY=128
} UA_VARIANT_ENCODINGMASKTYPE;

typedef struct UA_SymmetricAlgorithmSecurityHeader UA_SymmetricAlgorithmSecurityHeader, *PUA_SymmetricAlgorithmSecurityHeader;

struct UA_SymmetricAlgorithmSecurityHeader {
    UA_UInt32 tokenId;
};

typedef struct UA_CloseSecureChannelRequest UA_CloseSecureChannelRequest, *PUA_CloseSecureChannelRequest;

typedef struct UA_RequestHeader UA_RequestHeader, *PUA_RequestHeader;

struct UA_RequestHeader {
    struct UA_NodeId authenticationToken;
    UA_DateTime timestamp;
    UA_UInt32 requestHandle;
    UA_UInt32 returnDiagnostics;
    struct UA_String auditEntryId;
    UA_UInt32 timeoutHint;
    struct UA_ExtensionObject additionalHeader;
};

struct UA_CloseSecureChannelRequest {
    struct UA_RequestHeader requestHeader;
};

typedef struct UA_UserNameIdentityToken UA_UserNameIdentityToken, *PUA_UserNameIdentityToken;

struct UA_UserNameIdentityToken {
    struct UA_String policyId;
    struct UA_String userName;
    UA_ByteString password;
    struct UA_String encryptionAlgorithm;
};

typedef struct UA_BrowsePathResult UA_BrowsePathResult, *PUA_BrowsePathResult;

typedef struct UA_BrowsePathTarget UA_BrowsePathTarget, *PUA_BrowsePathTarget;

struct UA_BrowsePathResult {
    UA_StatusCode statusCode;
    size_t targetsSize;
    struct UA_BrowsePathTarget *targets;
};

struct UA_BrowsePathTarget {
    struct UA_ExpandedNodeId targetId;
    UA_UInt32 remainingPathIndex;
};

typedef struct UA_CreateSessionResponse UA_CreateSessionResponse, *PUA_CreateSessionResponse;

typedef struct UA_SignedSoftwareCertificate UA_SignedSoftwareCertificate, *PUA_SignedSoftwareCertificate;

typedef struct UA_SignatureData UA_SignatureData, *PUA_SignatureData;

struct UA_SignatureData {
    struct UA_String algorithm;
    UA_ByteString signature;
};

struct UA_CreateSessionResponse {
    struct UA_ResponseHeader responseHeader;
    struct UA_NodeId sessionId;
    struct UA_NodeId authenticationToken;
    UA_Double revisedSessionTimeout;
    UA_ByteString serverNonce;
    UA_ByteString serverCertificate;
    size_t serverEndpointsSize;
    struct UA_EndpointDescription *serverEndpoints;
    size_t serverSoftwareCertificatesSize;
    struct UA_SignedSoftwareCertificate *serverSoftwareCertificates;
    struct UA_SignatureData serverSignature;
    UA_UInt32 maxRequestMessageSize;
};

struct UA_SignedSoftwareCertificate {
    UA_ByteString certificateData;
    UA_ByteString signature;
};

typedef struct UA_PublishRequest UA_PublishRequest, *PUA_PublishRequest;

struct UA_PublishRequest {
    struct UA_RequestHeader requestHeader;
    size_t subscriptionAcknowledgementsSize;
    struct UA_SubscriptionAcknowledgement *subscriptionAcknowledgements;
};

typedef struct UA_WriteResponse UA_WriteResponse, *PUA_WriteResponse;

struct UA_WriteResponse {
    struct UA_ResponseHeader responseHeader;
    size_t resultsSize;
    UA_StatusCode *results;
    size_t diagnosticInfosSize;
    struct UA_DiagnosticInfo *diagnosticInfos;
};

typedef struct UA_CallRequest UA_CallRequest, *PUA_CallRequest;

typedef struct UA_CallMethodRequest UA_CallMethodRequest, *PUA_CallMethodRequest;

struct UA_CallMethodRequest {
    struct UA_NodeId objectId;
    struct UA_NodeId methodId;
    size_t inputArgumentsSize;
    struct UA_Variant *inputArguments;
};

struct UA_CallRequest {
    struct UA_RequestHeader requestHeader;
    size_t methodsToCallSize;
    struct UA_CallMethodRequest *methodsToCall;
};

typedef struct UA_ViewAttributes UA_ViewAttributes, *PUA_ViewAttributes;

struct UA_ViewAttributes {
    UA_UInt32 specifiedAttributes;
    struct UA_LocalizedText displayName;
    struct UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
    UA_Boolean containsNoLoops;
    UA_Byte eventNotifier;
};

typedef struct UA_SetPublishingModeRequest UA_SetPublishingModeRequest, *PUA_SetPublishingModeRequest;

struct UA_SetPublishingModeRequest {
    struct UA_RequestHeader requestHeader;
    UA_Boolean publishingEnabled;
    size_t subscriptionIdsSize;
    UA_UInt32 *subscriptionIds;
};

typedef struct UA_StatusCodeDescription UA_StatusCodeDescription, *PUA_StatusCodeDescription;

struct UA_StatusCodeDescription {
    UA_StatusCode code;
    char *name;
    char *explanation;
};

typedef struct UA_CreateSessionRequest UA_CreateSessionRequest, *PUA_CreateSessionRequest;

struct UA_CreateSessionRequest {
    struct UA_RequestHeader requestHeader;
    struct UA_ApplicationDescription clientDescription;
    struct UA_String serverUri;
    struct UA_String endpointUrl;
    struct UA_String sessionName;
    UA_ByteString clientNonce;
    UA_ByteString clientCertificate;
    UA_Double requestedSessionTimeout;
    UA_UInt32 maxResponseMessageSize;
};

typedef struct UA_AddNodesItem UA_AddNodesItem, *PUA_AddNodesItem;

struct UA_AddNodesItem {
    struct UA_ExpandedNodeId parentNodeId;
    struct UA_NodeId referenceTypeId;
    struct UA_ExpandedNodeId requestedNewNodeId;
    struct UA_QualifiedName browseName;
    enum UA_NodeClass nodeClass;
    struct UA_ExtensionObject nodeAttributes;
    struct UA_ExpandedNodeId typeDefinition;
};

typedef struct UA_SetPublishingModeResponse UA_SetPublishingModeResponse, *PUA_SetPublishingModeResponse;

struct UA_SetPublishingModeResponse {
    struct UA_ResponseHeader responseHeader;
    size_t resultsSize;
    UA_StatusCode *results;
    size_t diagnosticInfosSize;
    struct UA_DiagnosticInfo *diagnosticInfos;
};

typedef struct UA_RepublishRequest UA_RepublishRequest, *PUA_RepublishRequest;

struct UA_RepublishRequest {
    struct UA_RequestHeader requestHeader;
    UA_UInt32 subscriptionId;
    UA_UInt32 retransmitSequenceNumber;
};

typedef struct UA_AnonymousIdentityToken UA_AnonymousIdentityToken, *PUA_AnonymousIdentityToken;

struct UA_AnonymousIdentityToken {
    struct UA_String policyId;
};

typedef struct UA_RelativePath UA_RelativePath, *PUA_RelativePath;

typedef struct UA_RelativePathElement UA_RelativePathElement, *PUA_RelativePathElement;

struct UA_RelativePathElement {
    struct UA_NodeId referenceTypeId;
    UA_Boolean isInverse;
    UA_Boolean includeSubtypes;
    struct UA_QualifiedName targetName;
};

struct UA_RelativePath {
    size_t elementsSize;
    struct UA_RelativePathElement *elements;
};

typedef struct UA_UnregisterNodesRequest UA_UnregisterNodesRequest, *PUA_UnregisterNodesRequest;

struct UA_UnregisterNodesRequest {
    struct UA_RequestHeader requestHeader;
    size_t nodesToUnregisterSize;
    struct UA_NodeId *nodesToUnregister;
};

typedef struct UA_GetEndpointsResponse UA_GetEndpointsResponse, *PUA_GetEndpointsResponse;

struct UA_GetEndpointsResponse {
    struct UA_ResponseHeader responseHeader;
    size_t endpointsSize;
    struct UA_EndpointDescription *endpoints;
};

typedef enum UA_SecurityTokenRequestType {
    UA_SECURITYTOKENREQUESTTYPE_ISSUE=0,
    UA_SECURITYTOKENREQUESTTYPE_RENEW=1
} UA_SecurityTokenRequestType;

typedef struct UA_CreateSubscriptionResponse UA_CreateSubscriptionResponse, *PUA_CreateSubscriptionResponse;

struct UA_CreateSubscriptionResponse {
    struct UA_ResponseHeader responseHeader;
    UA_UInt32 subscriptionId;
    UA_Double revisedPublishingInterval;
    UA_UInt32 revisedLifetimeCount;
    UA_UInt32 revisedMaxKeepAliveCount;
};

typedef struct UA_DeleteSubscriptionsRequest UA_DeleteSubscriptionsRequest, *PUA_DeleteSubscriptionsRequest;

struct UA_DeleteSubscriptionsRequest {
    struct UA_RequestHeader requestHeader;
    size_t subscriptionIdsSize;
    UA_UInt32 *subscriptionIds;
};

typedef struct UA_RegisterNodesRequest UA_RegisterNodesRequest, *PUA_RegisterNodesRequest;

struct UA_RegisterNodesRequest {
    struct UA_RequestHeader requestHeader;
    size_t nodesToRegisterSize;
    struct UA_NodeId *nodesToRegister;
};

typedef struct UA_ModifySubscriptionRequest UA_ModifySubscriptionRequest, *PUA_ModifySubscriptionRequest;

struct UA_ModifySubscriptionRequest {
    struct UA_RequestHeader requestHeader;
    UA_UInt32 subscriptionId;
    UA_Double requestedPublishingInterval;
    UA_UInt32 requestedLifetimeCount;
    UA_UInt32 requestedMaxKeepAliveCount;
    UA_UInt32 maxNotificationsPerPublish;
    UA_Byte priority;
};

typedef struct UA_DeleteNodesItem UA_DeleteNodesItem, *PUA_DeleteNodesItem;

struct UA_DeleteNodesItem {
    struct UA_NodeId nodeId;
    UA_Boolean deleteTargetReferences;
};

typedef struct UA_AddReferencesRequest UA_AddReferencesRequest, *PUA_AddReferencesRequest;

typedef struct UA_AddReferencesItem UA_AddReferencesItem, *PUA_AddReferencesItem;

struct UA_AddReferencesRequest {
    struct UA_RequestHeader requestHeader;
    size_t referencesToAddSize;
    struct UA_AddReferencesItem *referencesToAdd;
};

struct UA_AddReferencesItem {
    struct UA_NodeId sourceNodeId;
    struct UA_NodeId referenceTypeId;
    UA_Boolean isForward;
    struct UA_String targetServerUri;
    struct UA_ExpandedNodeId targetNodeId;
    enum UA_NodeClass targetNodeClass;
};

typedef struct UA_CloseSessionRequest UA_CloseSessionRequest, *PUA_CloseSessionRequest;

struct UA_CloseSessionRequest {
    struct UA_RequestHeader requestHeader;
    UA_Boolean deleteSubscriptions;
};

typedef struct UA_DataChangeNotification UA_DataChangeNotification, *PUA_DataChangeNotification;

typedef struct UA_MonitoredItemNotification UA_MonitoredItemNotification, *PUA_MonitoredItemNotification;

struct UA_DataChangeNotification {
    size_t monitoredItemsSize;
    struct UA_MonitoredItemNotification *monitoredItems;
    size_t diagnosticInfosSize;
    struct UA_DiagnosticInfo *diagnosticInfos;
};

struct UA_MonitoredItemNotification {
    UA_UInt32 clientHandle;
    struct UA_DataValue value;
};

typedef struct UA_DeleteReferencesItem UA_DeleteReferencesItem, *PUA_DeleteReferencesItem;

struct UA_DeleteReferencesItem {
    struct UA_NodeId sourceNodeId;
    struct UA_NodeId referenceTypeId;
    UA_Boolean isForward;
    struct UA_ExpandedNodeId targetNodeId;
    UA_Boolean deleteBidirectional;
};

typedef struct UA_MonitoredItemModifyRequest UA_MonitoredItemModifyRequest, *PUA_MonitoredItemModifyRequest;

typedef struct UA_MonitoringParameters UA_MonitoringParameters, *PUA_MonitoringParameters;

struct UA_MonitoringParameters {
    UA_UInt32 clientHandle;
    UA_Double samplingInterval;
    struct UA_ExtensionObject filter;
    UA_UInt32 queueSize;
    UA_Boolean discardOldest;
};

struct UA_MonitoredItemModifyRequest {
    UA_UInt32 monitoredItemId;
    struct UA_MonitoringParameters requestedParameters;
};

typedef struct UA_DeleteMonitoredItemsRequest UA_DeleteMonitoredItemsRequest, *PUA_DeleteMonitoredItemsRequest;

struct UA_DeleteMonitoredItemsRequest {
    struct UA_RequestHeader requestHeader;
    UA_UInt32 subscriptionId;
    size_t monitoredItemIdsSize;
    UA_UInt32 *monitoredItemIds;
};

typedef struct UA_BrowseResponse UA_BrowseResponse, *PUA_BrowseResponse;

typedef struct UA_BrowseResult UA_BrowseResult, *PUA_BrowseResult;

typedef struct UA_ReferenceDescription UA_ReferenceDescription, *PUA_ReferenceDescription;

struct UA_BrowseResponse {
    struct UA_ResponseHeader responseHeader;
    size_t resultsSize;
    struct UA_BrowseResult *results;
    size_t diagnosticInfosSize;
    struct UA_DiagnosticInfo *diagnosticInfos;
};

struct UA_ReferenceDescription {
    struct UA_NodeId referenceTypeId;
    UA_Boolean isForward;
    struct UA_ExpandedNodeId nodeId;
    struct UA_QualifiedName browseName;
    struct UA_LocalizedText displayName;
    enum UA_NodeClass nodeClass;
    struct UA_ExpandedNodeId typeDefinition;
};

struct UA_BrowseResult {
    UA_StatusCode statusCode;
    UA_ByteString continuationPoint;
    size_t referencesSize;
    struct UA_ReferenceDescription *references;
};

typedef struct UA_ActivateSessionRequest UA_ActivateSessionRequest, *PUA_ActivateSessionRequest;

struct UA_ActivateSessionRequest {
    struct UA_RequestHeader requestHeader;
    struct UA_SignatureData clientSignature;
    size_t clientSoftwareCertificatesSize;
    struct UA_SignedSoftwareCertificate *clientSoftwareCertificates;
    size_t localeIdsSize;
    struct UA_String *localeIds;
    struct UA_ExtensionObject userIdentityToken;
    struct UA_SignatureData userTokenSignature;
};

typedef struct UA_MonitoredItemModifyResult UA_MonitoredItemModifyResult, *PUA_MonitoredItemModifyResult;

struct UA_MonitoredItemModifyResult {
    UA_StatusCode statusCode;
    UA_Double revisedSamplingInterval;
    UA_UInt32 revisedQueueSize;
    struct UA_ExtensionObject filterResult;
};

typedef struct UA_CloseSessionResponse UA_CloseSessionResponse, *PUA_CloseSessionResponse;

struct UA_CloseSessionResponse {
    struct UA_ResponseHeader responseHeader;
};

typedef struct UA_OpenSecureChannelRequest UA_OpenSecureChannelRequest, *PUA_OpenSecureChannelRequest;

struct UA_OpenSecureChannelRequest {
    struct UA_RequestHeader requestHeader;
    UA_UInt32 clientProtocolVersion;
    enum UA_SecurityTokenRequestType requestType;
    enum UA_MessageSecurityMode securityMode;
    UA_ByteString clientNonce;
    UA_UInt32 requestedLifetime;
};

typedef struct UA_MethodAttributes UA_MethodAttributes, *PUA_MethodAttributes;

struct UA_MethodAttributes {
    UA_UInt32 specifiedAttributes;
    struct UA_LocalizedText displayName;
    struct UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
    UA_Boolean executable;
    UA_Boolean userExecutable;
};

typedef struct UA_SubscriptionSettings UA_SubscriptionSettings, *PUA_SubscriptionSettings;

struct UA_SubscriptionSettings {
    UA_Double requestedPublishingInterval;
    UA_UInt32 requestedLifetimeCount;
    UA_UInt32 requestedMaxKeepAliveCount;
    UA_UInt32 maxNotificationsPerPublish;
    UA_Boolean publishingEnabled;
    UA_Byte priority;
};

typedef struct UA_VariableTypeAttributes UA_VariableTypeAttributes, *PUA_VariableTypeAttributes;

struct UA_VariableTypeAttributes {
    UA_UInt32 specifiedAttributes;
    struct UA_LocalizedText displayName;
    struct UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
    struct UA_Variant value;
    struct UA_NodeId dataType;
    UA_Int32 valueRank;
    size_t arrayDimensionsSize;
    UA_UInt32 *arrayDimensions;
    UA_Boolean isAbstract;
};

typedef struct UA_GetEndpointsRequest UA_GetEndpointsRequest, *PUA_GetEndpointsRequest;

struct UA_GetEndpointsRequest {
    struct UA_RequestHeader requestHeader;
    struct UA_String endpointUrl;
    size_t localeIdsSize;
    struct UA_String *localeIds;
    size_t profileUrisSize;
    struct UA_String *profileUris;
};

typedef struct UA_CreateMonitoredItemsRequest UA_CreateMonitoredItemsRequest, *PUA_CreateMonitoredItemsRequest;

typedef struct UA_MonitoredItemCreateRequest UA_MonitoredItemCreateRequest, *PUA_MonitoredItemCreateRequest;

typedef struct UA_ReadValueId UA_ReadValueId, *PUA_ReadValueId;

struct UA_ReadValueId {
    struct UA_NodeId nodeId;
    UA_UInt32 attributeId;
    struct UA_String indexRange;
    struct UA_QualifiedName dataEncoding;
};

struct UA_MonitoredItemCreateRequest {
    struct UA_ReadValueId itemToMonitor;
    enum UA_MonitoringMode monitoringMode;
    struct UA_MonitoringParameters requestedParameters;
};

struct UA_CreateMonitoredItemsRequest {
    struct UA_RequestHeader requestHeader;
    UA_UInt32 subscriptionId;
    enum UA_TimestampsToReturn timestampsToReturn;
    size_t itemsToCreateSize;
    struct UA_MonitoredItemCreateRequest *itemsToCreate;
};

typedef struct UA_CallResponse UA_CallResponse, *PUA_CallResponse;

typedef struct UA_CallMethodResult UA_CallMethodResult, *PUA_CallMethodResult;

struct UA_CallMethodResult {
    UA_StatusCode statusCode;
    size_t inputArgumentResultsSize;
    UA_StatusCode *inputArgumentResults;
    size_t inputArgumentDiagnosticInfosSize;
    struct UA_DiagnosticInfo *inputArgumentDiagnosticInfos;
    size_t outputArgumentsSize;
    struct UA_Variant *outputArguments;
};

struct UA_CallResponse {
    struct UA_ResponseHeader responseHeader;
    size_t resultsSize;
    struct UA_CallMethodResult *results;
    size_t diagnosticInfosSize;
    struct UA_DiagnosticInfo *diagnosticInfos;
};

typedef struct UA_ModifyMonitoredItemsRequest UA_ModifyMonitoredItemsRequest, *PUA_ModifyMonitoredItemsRequest;

struct UA_ModifyMonitoredItemsRequest {
    struct UA_RequestHeader requestHeader;
    UA_UInt32 subscriptionId;
    enum UA_TimestampsToReturn timestampsToReturn;
    size_t itemsToModifySize;
    struct UA_MonitoredItemModifyRequest *itemsToModify;
};

typedef struct UA_ObjectAttributes UA_ObjectAttributes, *PUA_ObjectAttributes;

struct UA_ObjectAttributes {
    UA_UInt32 specifiedAttributes;
    struct UA_LocalizedText displayName;
    struct UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
    UA_Byte eventNotifier;
};

typedef struct UA_RegisterNodesResponse UA_RegisterNodesResponse, *PUA_RegisterNodesResponse;

struct UA_RegisterNodesResponse {
    struct UA_ResponseHeader responseHeader;
    size_t registeredNodeIdsSize;
    struct UA_NodeId *registeredNodeIds;
};

typedef struct UA_ReferenceTypeAttributes UA_ReferenceTypeAttributes, *PUA_ReferenceTypeAttributes;

struct UA_ReferenceTypeAttributes {
    UA_UInt32 specifiedAttributes;
    struct UA_LocalizedText displayName;
    struct UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
    UA_Boolean isAbstract;
    UA_Boolean symmetric;
    struct UA_LocalizedText inverseName;
};

typedef struct UA_AddNodesResult UA_AddNodesResult, *PUA_AddNodesResult;

struct UA_AddNodesResult {
    UA_StatusCode statusCode;
    struct UA_NodeId addedNodeId;
};

typedef struct UA_DataTypeAttributes UA_DataTypeAttributes, *PUA_DataTypeAttributes;

struct UA_DataTypeAttributes {
    UA_UInt32 specifiedAttributes;
    struct UA_LocalizedText displayName;
    struct UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
    UA_Boolean isAbstract;
};

typedef struct UA_MonitoredItemCreateResult UA_MonitoredItemCreateResult, *PUA_MonitoredItemCreateResult;

struct UA_MonitoredItemCreateResult {
    UA_StatusCode statusCode;
    UA_UInt32 monitoredItemId;
    UA_Double revisedSamplingInterval;
    UA_UInt32 revisedQueueSize;
    struct UA_ExtensionObject filterResult;
};

typedef struct UA_InstantiationCallback UA_InstantiationCallback, *PUA_InstantiationCallback;

struct UA_InstantiationCallback {
    UA_StatusCode (*method)(struct UA_NodeId, struct UA_NodeId, void *);
    void *handle;
};

typedef struct UA_SetMonitoringModeRequest UA_SetMonitoringModeRequest, *PUA_SetMonitoringModeRequest;

struct UA_SetMonitoringModeRequest {
    struct UA_RequestHeader requestHeader;
    UA_UInt32 subscriptionId;
    enum UA_MonitoringMode monitoringMode;
    size_t monitoredItemIdsSize;
    UA_UInt32 *monitoredItemIds;
};

typedef struct UA_DeleteReferencesRequest UA_DeleteReferencesRequest, *PUA_DeleteReferencesRequest;

struct UA_DeleteReferencesRequest {
    struct UA_RequestHeader requestHeader;
    size_t referencesToDeleteSize;
    struct UA_DeleteReferencesItem *referencesToDelete;
};

typedef struct UA_ActivateSessionResponse UA_ActivateSessionResponse, *PUA_ActivateSessionResponse;

struct UA_ActivateSessionResponse {
    struct UA_ResponseHeader responseHeader;
    UA_ByteString serverNonce;
    size_t resultsSize;
    UA_StatusCode *results;
    size_t diagnosticInfosSize;
    struct UA_DiagnosticInfo *diagnosticInfos;
};

typedef struct UA_FindServersResponse UA_FindServersResponse, *PUA_FindServersResponse;

struct UA_FindServersResponse {
    struct UA_ResponseHeader responseHeader;
    size_t serversSize;
    struct UA_ApplicationDescription *servers;
};

typedef struct UA_BrowseNextRequest UA_BrowseNextRequest, *PUA_BrowseNextRequest;

struct UA_BrowseNextRequest {
    struct UA_RequestHeader requestHeader;
    UA_Boolean releaseContinuationPoints;
    size_t continuationPointsSize;
    UA_ByteString *continuationPoints;
};

typedef struct UA_ObjectTypeAttributes UA_ObjectTypeAttributes, *PUA_ObjectTypeAttributes;

struct UA_ObjectTypeAttributes {
    UA_UInt32 specifiedAttributes;
    struct UA_LocalizedText displayName;
    struct UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
    UA_Boolean isAbstract;
};

typedef struct UA_BrowseRequest UA_BrowseRequest, *PUA_BrowseRequest;

typedef struct UA_ViewDescription UA_ViewDescription, *PUA_ViewDescription;

struct UA_ViewDescription {
    struct UA_NodeId viewId;
    UA_DateTime timestamp;
    UA_UInt32 viewVersion;
};

struct UA_BrowseRequest {
    struct UA_RequestHeader requestHeader;
    struct UA_ViewDescription view;
    UA_UInt32 requestedMaxReferencesPerNode;
    size_t nodesToBrowseSize;
    struct UA_BrowseDescription *nodesToBrowse;
};

typedef struct UA_RepublishResponse UA_RepublishResponse, *PUA_RepublishResponse;

struct UA_RepublishResponse {
    struct UA_ResponseHeader responseHeader;
    struct UA_NotificationMessage notificationMessage;
};

typedef struct UA_CreateSubscriptionRequest UA_CreateSubscriptionRequest, *PUA_CreateSubscriptionRequest;

struct UA_CreateSubscriptionRequest {
    struct UA_RequestHeader requestHeader;
    UA_Double requestedPublishingInterval;
    UA_UInt32 requestedLifetimeCount;
    UA_UInt32 requestedMaxKeepAliveCount;
    UA_UInt32 maxNotificationsPerPublish;
    UA_Boolean publishingEnabled;
    UA_Byte priority;
};

typedef struct UA_ModifySubscriptionResponse UA_ModifySubscriptionResponse, *PUA_ModifySubscriptionResponse;

struct UA_ModifySubscriptionResponse {
    struct UA_ResponseHeader responseHeader;
    UA_Double revisedPublishingInterval;
    UA_UInt32 revisedLifetimeCount;
    UA_UInt32 revisedMaxKeepAliveCount;
};

typedef struct UA_ModifyMonitoredItemsResponse UA_ModifyMonitoredItemsResponse, *PUA_ModifyMonitoredItemsResponse;

struct UA_ModifyMonitoredItemsResponse {
    struct UA_ResponseHeader responseHeader;
    size_t resultsSize;
    struct UA_MonitoredItemModifyResult *results;
    size_t diagnosticInfosSize;
    struct UA_DiagnosticInfo *diagnosticInfos;
};

typedef struct UA_TranslateBrowsePathsToNodeIdsResponse UA_TranslateBrowsePathsToNodeIdsResponse, *PUA_TranslateBrowsePathsToNodeIdsResponse;

struct UA_TranslateBrowsePathsToNodeIdsResponse {
    struct UA_ResponseHeader responseHeader;
    size_t resultsSize;
    struct UA_BrowsePathResult *results;
    size_t diagnosticInfosSize;
    struct UA_DiagnosticInfo *diagnosticInfos;
};

typedef struct UA_DeleteSubscriptionsResponse UA_DeleteSubscriptionsResponse, *PUA_DeleteSubscriptionsResponse;

struct UA_DeleteSubscriptionsResponse {
    struct UA_ResponseHeader responseHeader;
    size_t resultsSize;
    UA_StatusCode *results;
    size_t diagnosticInfosSize;
    struct UA_DiagnosticInfo *diagnosticInfos;
};

typedef struct UA_DeleteNodesResponse UA_DeleteNodesResponse, *PUA_DeleteNodesResponse;

struct UA_DeleteNodesResponse {
    struct UA_ResponseHeader responseHeader;
    size_t resultsSize;
    UA_StatusCode *results;
    size_t diagnosticInfosSize;
    struct UA_DiagnosticInfo *diagnosticInfos;
};

typedef struct UA_WriteValue UA_WriteValue, *PUA_WriteValue;

struct UA_WriteValue {
    struct UA_NodeId nodeId;
    UA_UInt32 attributeId;
    struct UA_String indexRange;
    struct UA_DataValue value;
};

typedef struct UA_CreateMonitoredItemsResponse UA_CreateMonitoredItemsResponse, *PUA_CreateMonitoredItemsResponse;

struct UA_CreateMonitoredItemsResponse {
    struct UA_ResponseHeader responseHeader;
    size_t resultsSize;
    struct UA_MonitoredItemCreateResult *results;
    size_t diagnosticInfosSize;
    struct UA_DiagnosticInfo *diagnosticInfos;
};

typedef struct UA_AddNodesRequest UA_AddNodesRequest, *PUA_AddNodesRequest;

struct UA_AddNodesRequest {
    struct UA_RequestHeader requestHeader;
    size_t nodesToAddSize;
    struct UA_AddNodesItem *nodesToAdd;
};

typedef int64_t UA_Int64;

typedef struct UA_SetMonitoringModeResponse UA_SetMonitoringModeResponse, *PUA_SetMonitoringModeResponse;

struct UA_SetMonitoringModeResponse {
    struct UA_ResponseHeader responseHeader;
    size_t resultsSize;
    UA_StatusCode *results;
    size_t diagnosticInfosSize;
    struct UA_DiagnosticInfo *diagnosticInfos;
};

typedef struct UA_BrowseNextResponse UA_BrowseNextResponse, *PUA_BrowseNextResponse;

struct UA_BrowseNextResponse {
    struct UA_ResponseHeader responseHeader;
    size_t resultsSize;
    struct UA_BrowseResult *results;
    size_t diagnosticInfosSize;
    struct UA_DiagnosticInfo *diagnosticInfos;
};

typedef struct UA_OpenSecureChannelResponse UA_OpenSecureChannelResponse, *PUA_OpenSecureChannelResponse;

struct UA_OpenSecureChannelResponse {
    struct UA_ResponseHeader responseHeader;
    UA_UInt32 serverProtocolVersion;
    struct UA_ChannelSecurityToken securityToken;
    UA_ByteString serverNonce;
};

typedef struct UA_WriteRequest UA_WriteRequest, *PUA_WriteRequest;

struct UA_WriteRequest {
    struct UA_RequestHeader requestHeader;
    size_t nodesToWriteSize;
    struct UA_WriteValue *nodesToWrite;
};

typedef struct UA_DeleteReferencesResponse UA_DeleteReferencesResponse, *PUA_DeleteReferencesResponse;

struct UA_DeleteReferencesResponse {
    struct UA_ResponseHeader responseHeader;
    size_t resultsSize;
    UA_StatusCode *results;
    size_t diagnosticInfosSize;
    struct UA_DiagnosticInfo *diagnosticInfos;
};

typedef struct UA_Argument UA_Argument, *PUA_Argument;

struct UA_Argument {
    struct UA_String name;
    struct UA_NodeId dataType;
    UA_Int32 valueRank;
    size_t arrayDimensionsSize;
    UA_UInt32 *arrayDimensions;
    struct UA_LocalizedText description;
};

typedef struct UA_ReadResponse UA_ReadResponse, *PUA_ReadResponse;

struct UA_ReadResponse {
    struct UA_ResponseHeader responseHeader;
    size_t resultsSize;
    struct UA_DataValue *results;
    size_t diagnosticInfosSize;
    struct UA_DiagnosticInfo *diagnosticInfos;
};

typedef enum UA_AttributeId {
    UA_ATTRIBUTEID_NODEID=1,
    UA_ATTRIBUTEID_NODECLASS=2,
    UA_ATTRIBUTEID_BROWSENAME=3,
    UA_ATTRIBUTEID_DISPLAYNAME=4,
    UA_ATTRIBUTEID_DESCRIPTION=5,
    UA_ATTRIBUTEID_WRITEMASK=6,
    UA_ATTRIBUTEID_USERWRITEMASK=7,
    UA_ATTRIBUTEID_ISABSTRACT=8,
    UA_ATTRIBUTEID_SYMMETRIC=9,
    UA_ATTRIBUTEID_INVERSENAME=10,
    UA_ATTRIBUTEID_CONTAINSNOLOOPS=11,
    UA_ATTRIBUTEID_EVENTNOTIFIER=12,
    UA_ATTRIBUTEID_VALUE=13,
    UA_ATTRIBUTEID_DATATYPE=14,
    UA_ATTRIBUTEID_VALUERANK=15,
    UA_ATTRIBUTEID_ARRAYDIMENSIONS=16,
    UA_ATTRIBUTEID_ACCESSLEVEL=17,
    UA_ATTRIBUTEID_USERACCESSLEVEL=18,
    UA_ATTRIBUTEID_MINIMUMSAMPLINGINTERVAL=19,
    UA_ATTRIBUTEID_HISTORIZING=20,
    UA_ATTRIBUTEID_EXECUTABLE=21,
    UA_ATTRIBUTEID_USEREXECUTABLE=22
} UA_AttributeId;

typedef struct UA_VariableAttributes UA_VariableAttributes, *PUA_VariableAttributes;

struct UA_VariableAttributes {
    UA_UInt32 specifiedAttributes;
    struct UA_LocalizedText displayName;
    struct UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
    struct UA_Variant value;
    struct UA_NodeId dataType;
    UA_Int32 valueRank;
    size_t arrayDimensionsSize;
    UA_UInt32 *arrayDimensions;
    UA_Byte accessLevel;
    UA_Byte userAccessLevel;
    UA_Double minimumSamplingInterval;
    UA_Boolean historizing;
};

typedef struct UA_TranslateBrowsePathsToNodeIdsRequest UA_TranslateBrowsePathsToNodeIdsRequest, *PUA_TranslateBrowsePathsToNodeIdsRequest;

typedef struct UA_BrowsePath UA_BrowsePath, *PUA_BrowsePath;

struct UA_TranslateBrowsePathsToNodeIdsRequest {
    struct UA_RequestHeader requestHeader;
    size_t browsePathsSize;
    struct UA_BrowsePath *browsePaths;
};

struct UA_BrowsePath {
    struct UA_NodeId startingNode;
    struct UA_RelativePath relativePath;
};

typedef struct UA_AddReferencesResponse UA_AddReferencesResponse, *PUA_AddReferencesResponse;

struct UA_AddReferencesResponse {
    struct UA_ResponseHeader responseHeader;
    size_t resultsSize;
    UA_StatusCode *results;
    size_t diagnosticInfosSize;
    struct UA_DiagnosticInfo *diagnosticInfos;
};

typedef struct UA_NodeAttributes UA_NodeAttributes, *PUA_NodeAttributes;

struct UA_NodeAttributes {
    UA_UInt32 specifiedAttributes;
    struct UA_LocalizedText displayName;
    struct UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
};

typedef struct UA_DataChangeFilter UA_DataChangeFilter, *PUA_DataChangeFilter;

struct UA_DataChangeFilter {
    enum UA_DataChangeTrigger trigger;
    UA_UInt32 deadbandType;
    UA_Double deadbandValue;
};

typedef struct UA_AddNodesResponse UA_AddNodesResponse, *PUA_AddNodesResponse;

struct UA_AddNodesResponse {
    struct UA_ResponseHeader responseHeader;
    size_t resultsSize;
    struct UA_AddNodesResult *results;
    size_t diagnosticInfosSize;
    struct UA_DiagnosticInfo *diagnosticInfos;
};

typedef UA_StatusCode (*UA_NodeIteratorCallback)(struct UA_NodeId, UA_Boolean, struct UA_NodeId, void *);

typedef enum UA_ServerState {
    UA_SERVERSTATE_RUNNING=0,
    UA_SERVERSTATE_FAILED=1,
    UA_SERVERSTATE_NOCONFIGURATION=2,
    UA_SERVERSTATE_SUSPENDED=3,
    UA_SERVERSTATE_SHUTDOWN=4,
    UA_SERVERSTATE_TEST=5,
    UA_SERVERSTATE_COMMUNICATIONFAULT=6,
    UA_SERVERSTATE_UNKNOWN=7
} UA_ServerState;

typedef struct UA_ServerStatusDataType UA_ServerStatusDataType, *PUA_ServerStatusDataType;

struct UA_ServerStatusDataType {
    UA_DateTime startTime;
    UA_DateTime currentTime;
    enum UA_ServerState state;
    struct UA_BuildInfo buildInfo;
    UA_UInt32 secondsTillShutdown;
    struct UA_LocalizedText shutdownReason;
};

typedef void (*UA_MonitoredItemHandlingFunction)(UA_UInt32, struct UA_DataValue *, void *);

typedef struct UA_DeleteNodesRequest UA_DeleteNodesRequest, *PUA_DeleteNodesRequest;

struct UA_DeleteNodesRequest {
    struct UA_RequestHeader requestHeader;
    size_t nodesToDeleteSize;
    struct UA_DeleteNodesItem *nodesToDelete;
};

typedef struct UA_UnregisterNodesResponse UA_UnregisterNodesResponse, *PUA_UnregisterNodesResponse;

struct UA_UnregisterNodesResponse {
    struct UA_ResponseHeader responseHeader;
};

typedef struct UA_DeleteMonitoredItemsResponse UA_DeleteMonitoredItemsResponse, *PUA_DeleteMonitoredItemsResponse;

struct UA_DeleteMonitoredItemsResponse {
    struct UA_ResponseHeader responseHeader;
    size_t resultsSize;
    UA_StatusCode *results;
    size_t diagnosticInfosSize;
    struct UA_DiagnosticInfo *diagnosticInfos;
};

typedef struct UA_DateTimeStruct UA_DateTimeStruct, *PUA_DateTimeStruct;

struct UA_DateTimeStruct {
    UA_UInt16 nanoSec;
    UA_UInt16 microSec;
    UA_UInt16 milliSec;
    UA_UInt16 sec;
    UA_UInt16 min;
    UA_UInt16 hour;
    UA_UInt16 day;
    UA_UInt16 month;
    UA_UInt16 year;
};

typedef struct UA_ReadRequest UA_ReadRequest, *PUA_ReadRequest;

struct UA_ReadRequest {
    struct UA_RequestHeader requestHeader;
    UA_Double maxAge;
    enum UA_TimestampsToReturn timestampsToReturn;
    size_t nodesToReadSize;
    struct UA_ReadValueId *nodesToRead;
};

typedef struct UA_FindServersRequest UA_FindServersRequest, *PUA_FindServersRequest;

struct UA_FindServersRequest {
    struct UA_RequestHeader requestHeader;
    struct UA_String endpointUrl;
    size_t localeIdsSize;
    struct UA_String *localeIds;
    size_t serverUrisSize;
    struct UA_String *serverUris;
};

typedef struct MD5state_st MD5state_st, *PMD5state_st;

typedef struct MD5state_st MD5_CTX;

struct MD5state_st {
    uint A;
    uint B;
    uint C;
    uint D;
    uint Nl;
    uint Nh;
    uint data[16];
    uint num;
};

typedef int (evp_verify_method)(int, uchar *, uint, uchar *, uint, void *);

typedef struct evp_Encode_Ctx_st evp_Encode_Ctx_st, *Pevp_Encode_Ctx_st;

typedef struct evp_Encode_Ctx_st EVP_ENCODE_CTX;

struct evp_Encode_Ctx_st {
    int num;
    int length;
    uchar enc_data[80];
    int line_num;
    int expect_nl;
};

typedef int (evp_sign_method)(int, uchar *, uint, uchar *, uint *, void *);

typedef struct evp_cipher_info_st evp_cipher_info_st, *Pevp_cipher_info_st;

struct evp_cipher_info_st {
    EVP_CIPHER *cipher;
    uchar iv[16];
};


// WARNING! conflicting data type names: /DWARF/evp.h/evp_cipher_ctx_st - /ossl_typ.h/evp_cipher_ctx_st

typedef struct evp_cipher_info_st EVP_CIPHER_INFO;


// WARNING! conflicting data type names: /DWARF/evp.h/evp_cipher_st - /ossl_typ.h/evp_cipher_st

typedef struct asn1_const_ctx_st asn1_const_ctx_st, *Pasn1_const_ctx_st;

typedef struct asn1_const_ctx_st ASN1_const_CTX;

struct asn1_const_ctx_st {
    uchar *p;
    int eos;
    int error;
    int inf;
    int tag;
    int xclass;
    long slen;
    uchar *max;
    uchar *q;
    uchar **pp;
    int line;
};

typedef struct asn1_string_table_st asn1_string_table_st, *Pasn1_string_table_st;

typedef struct asn1_string_table_st ASN1_STRING_TABLE;

struct asn1_string_table_st {
    int nid;
    long minsize;
    long maxsize;
    ulong mask;
    ulong flags;
};

typedef struct asn1_ctx_st asn1_ctx_st, *Pasn1_ctx_st;

typedef struct asn1_ctx_st ASN1_CTX;

struct asn1_ctx_st {
    uchar *p;
    int eos;
    int error;
    int inf;
    int tag;
    int xclass;
    long slen;
    uchar *max;
    uchar *q;
    uchar **pp;
    int line;
};

typedef struct stack_st_ASN1_TYPE ASN1_SEQUENCE_ANY;

typedef struct stack_st_ASN1_STRING_TABLE stack_st_ASN1_STRING_TABLE, *Pstack_st_ASN1_STRING_TABLE;

struct stack_st_ASN1_STRING_TABLE {
    _STACK stack;
};


// WARNING! conflicting data type names: /DWARF/asn1.h/asn1_type_st - /asn1.h/asn1_type_st


// WARNING! conflicting data type names: /DWARF/asn1.h/asn1_object_st - /asn1.h/asn1_object_st

typedef union anon_union_4_21_c3daea44_for_value anon_union_4_21_c3daea44_for_value, *Panon_union_4_21_c3daea44_for_value;

union anon_union_4_21_c3daea44_for_value {
    char *ptr;
    ASN1_BOOLEAN boolean;
    ASN1_STRING *asn1_string;
    ASN1_OBJECT *object;
    ASN1_INTEGER *integer;
    ASN1_ENUMERATED *enumerated;
    ASN1_BIT_STRING *bit_string;
    ASN1_OCTET_STRING *octet_string;
    ASN1_PRINTABLESTRING *printablestring;
    ASN1_T61STRING *t61string;
    ASN1_IA5STRING *ia5string;
    ASN1_GENERALSTRING *generalstring;
    ASN1_BMPSTRING *bmpstring;
    ASN1_UNIVERSALSTRING *universalstring;
    ASN1_UTCTIME *utctime;
    ASN1_GENERALIZEDTIME *generalizedtime;
    ASN1_VISIBLESTRING *visiblestring;
    ASN1_UTF8STRING *utf8string;
    ASN1_STRING *set;
    ASN1_STRING *sequence;
    ASN1_VALUE *asn1_value;
};

typedef struct in_addr in_addr, *Pin_addr;

typedef uint32_t in_addr_t;

struct in_addr {
    in_addr_t s_addr;
};

typedef struct in6_addr in6_addr, *Pin6_addr;

typedef union anon_union_16_3_a3f0114d_for___in6_u anon_union_16_3_a3f0114d_for___in6_u, *Panon_union_16_3_a3f0114d_for___in6_u;

union anon_union_16_3_a3f0114d_for___in6_u {
    uint8_t __u6_addr8[16];
    uint16_t __u6_addr16[8];
    uint32_t __u6_addr32[4];
};

struct in6_addr {
    union anon_union_16_3_a3f0114d_for___in6_u __in6_u;
};

typedef uint16_t in_port_t;

typedef struct sockaddr_in sockaddr_in, *Psockaddr_in;

struct sockaddr_in {
    sa_family_t sin_family;
    in_port_t sin_port;
    struct in_addr sin_addr;
    uchar sin_zero[8];
};

typedef struct stack_st_ENGINE stack_st_ENGINE, *Pstack_st_ENGINE;

struct stack_st_ENGINE {
    _STACK stack;
};

typedef struct st_engine_table st_engine_table, *Pst_engine_table;

typedef struct st_engine_table ENGINE_TABLE;

typedef struct lhash_st_ENGINE_PILE lhash_st_ENGINE_PILE, *Plhash_st_ENGINE_PILE;

struct lhash_st_ENGINE_PILE {
    int dummy;
};

struct st_engine_table {
    struct lhash_st_ENGINE_PILE piles;
};

typedef struct st_engine_cleanup_item st_engine_cleanup_item, *Pst_engine_cleanup_item;

typedef void (ENGINE_CLEANUP_CB)(void);

struct st_engine_cleanup_item {
    ENGINE_CLEANUP_CB *cb;
};

typedef struct stack_st_ENGINE_CLEANUP_ITEM stack_st_ENGINE_CLEANUP_ITEM, *Pstack_st_ENGINE_CLEANUP_ITEM;

struct stack_st_ENGINE_CLEANUP_ITEM {
    _STACK stack;
};


// WARNING! conflicting data type names: /DWARF/eng_int.h/engine_st - /ossl_typ.h/engine_st

typedef struct st_engine_cleanup_item ENGINE_CLEANUP_ITEM;

typedef struct EVP_SEED_KEY EVP_SEED_KEY, *PEVP_SEED_KEY;

struct EVP_SEED_KEY {
    SEED_KEY_SCHEDULE ks;
};

typedef struct st_ex_class_item st_ex_class_item, *Pst_ex_class_item;

typedef struct st_ex_class_item EX_CLASS_ITEM;

struct st_ex_class_item {
    int class_index;
    struct stack_st_CRYPTO_EX_DATA_FUNCS *meth;
    int meth_num;
};

typedef struct lhash_st_EX_CLASS_ITEM lhash_st_EX_CLASS_ITEM, *Plhash_st_EX_CLASS_ITEM;

struct lhash_st_EX_CLASS_ITEM {
    int dummy;
};

typedef struct dso_st dso_st, *Pdso_st;

typedef struct dso_st DSO;

typedef struct dso_meth_st dso_meth_st, *Pdso_meth_st;

typedef struct dso_meth_st DSO_METHOD;

typedef char * (*DSO_NAME_CONVERTER_FUNC)(DSO *, char *);

typedef char * (*DSO_MERGER_FUNC)(DSO *, char *, char *);

struct dso_st {
    DSO_METHOD *meth;
    struct stack_st_void *meth_data;
    int references;
    int flags;
    CRYPTO_EX_DATA ex_data;
    DSO_NAME_CONVERTER_FUNC name_converter;
    DSO_MERGER_FUNC merger;
    char *filename;
    char *loaded_filename;
};

struct dso_meth_st {
    char *name;
    int (*dso_load)(DSO *);
    int (*dso_unload)(DSO *);
    void * (*dso_bind_var)(DSO *, char *);
    DSO_FUNC_TYPE (*dso_bind_func)(DSO *, char *);
    long (*dso_ctrl)(DSO *, int, long, void *);
    DSO_NAME_CONVERTER_FUNC dso_name_converter;
    DSO_MERGER_FUNC dso_merger;
    int (*init)(DSO *);
    int (*finish)(DSO *);
    int (*pathbyaddr)(void *, char *, int);
    void * (*globallookup)(char *);
};


// WARNING! conflicting data type names: /DWARF/pthreadtypes.h/__pthread_internal_slist - /pthreadtypes.h/__pthread_internal_slist


// WARNING! conflicting data type names: /DWARF/pthreadtypes.h/pthread_mutex_t - /pthreadtypes.h/pthread_mutex_t


// WARNING! conflicting data type names: /DWARF/pthreadtypes.h/__pthread_slist_t - /pthreadtypes.h/__pthread_slist_t


// WARNING! conflicting data type names: /DWARF/pthreadtypes.h/__pthread_mutex_s - /pthreadtypes.h/__pthread_mutex_s

typedef union anon_union_4_2_9a799d16_for___pthread_mutex_s_5 anon_union_4_2_9a799d16_for___pthread_mutex_s_5, *Panon_union_4_2_9a799d16_for___pthread_mutex_s_5;

union anon_union_4_2_9a799d16_for___pthread_mutex_s_5 {
    int __spins;
    __pthread_slist_t __list;
};

typedef struct EVP_RC2_KEY EVP_RC2_KEY, *PEVP_RC2_KEY;

typedef struct rc2_key_st rc2_key_st, *Prc2_key_st;

typedef struct rc2_key_st RC2_KEY;

struct rc2_key_st {
    uint data[64];
};

struct EVP_RC2_KEY {
    int key_bits;
    RC2_KEY ks;
};

typedef struct MD4state_st MD4state_st, *PMD4state_st;

struct MD4state_st {
    uint A;
    uint B;
    uint C;
    uint D;
    uint Nl;
    uint Nh;
    uint data[16];
    uint num;
};

typedef struct MD4state_st MD4_CTX;

typedef struct CMAC_CTX_st CMAC_CTX_st, *PCMAC_CTX_st;

typedef struct CMAC_CTX_st CMAC_CTX;

struct CMAC_CTX_st {
    EVP_CIPHER_CTX cctx;
    uchar k1[32];
    uchar k2[32];
    uchar tbl[32];
    uchar last_block[32];
    int nlast_block;
};

typedef struct Logger Logger, *PLogger;

struct Logger {
    char *domain;
    int fd;
    DWORD flags;
};

typedef struct tagMODIFY tagMODIFY, *PtagMODIFY;

typedef union idatainfo idatainfo, *Pidatainfo;

typedef union idatainfo IDATAINFO;

typedef struct anon_struct_4_2_828fa5aa_for_idatainfo_0 anon_struct_4_2_828fa5aa_for_idatainfo_0, *Panon_struct_4_2_828fa5aa_for_idatainfo_0;

typedef struct anon_struct_8_2_098b3ce4_for_idatainfo_1 anon_struct_8_2_098b3ce4_for_idatainfo_1, *Panon_struct_8_2_098b3ce4_for_idatainfo_1;

typedef struct anon_struct_60_1_91a03e77_for_idatainfo_2 anon_struct_60_1_91a03e77_for_idatainfo_2, *Panon_struct_60_1_91a03e77_for_idatainfo_2;

struct anon_struct_4_2_828fa5aa_for_idatainfo_0 {
    WORD_T wOldValue;
    WORD_T wNewValue;
};

struct anon_struct_8_2_098b3ce4_for_idatainfo_1 {
    DWORD_T dwOldValue;
    DWORD_T dwNewValue;
};

struct anon_struct_60_1_91a03e77_for_idatainfo_2 {
    WORD_T wBuffer[30];
};

union idatainfo {
    struct anon_struct_4_2_828fa5aa_for_idatainfo_0 field_0;
    struct anon_struct_8_2_098b3ce4_for_idatainfo_1 field_1;
    struct anon_struct_60_1_91a03e77_for_idatainfo_2 field_2;
};

struct tagMODIFY {
    WORD_T wDataType;
    char cLoginID[8];
    WORD_T wDataID;
    IDATAINFO Data;
};

typedef struct tagCOMMMAP tagCOMMMAP, *PtagCOMMMAP;

typedef struct tagCOMMMAP COMMMAP;

typedef void (*pFUNC)(void *, WORD);

struct tagCOMMMAP {
    DWORD dwProtocolID;
    pFUNC pFunc;
};

typedef struct tagENERGY tagENERGY, *PtagENERGY;

struct tagENERGY {
    DWORD_T tmTotalEnergyConsumption;
};

typedef struct tagTEMPER tagTEMPER, *PtagTEMPER;

typedef struct tagTEMPER TEMPER;

struct tagTEMPER {
    DWORD dwShotCount;
    WORD wTempReal[20];
    WORD wTempSet[20];
};

typedef struct tagMONITOR tagMONITOR, *PtagMONITOR;

typedef struct tagMONITOR MONITOR;

struct tagMONITOR {
    DWORD_T ulShotCount;
    DWORD_T dwCycletime;
    DWORD_T dwInjecttime;
    DWORD_T tmTurnTime;
    DWORD_T tmChargeTime;
    WORD_T tmClpClsTime;
    WORD_T tmClpClsProtectTime;
    WORD_T tmClpClsHighTime;
    WORD_T tmClpOpnPosi;
    WORD_T tmClpOpnTime;
    WORD_T tmTurnPress;
    WORD_T tmInjStartPosi;
    WORD_T tmTurnPosi;
    WORD_T tmInjEndPosi;
    WORD_T tmInjEnd;
    WORD_T tmChargeRPM;
    WORD_T tmInjBackTime;
    WORD_T tmEjectTime;
    WORD_T tmClpClsHighPres;
    WORD_T tmInjHighPress;
    WORD_T tmChargeHighPress;
    WORD_T tmEjectAdvTime;
    WORD_T tmEjectRetTime;
    char other_data[26];
    WORD_T tmInjMaxSpeed;
    DWORD_T tmFetchTime;
    char reserve[12];
    DWORD_T tmInjTimeB;
    DWORD_T tmTurnTimeB;
    DWORD_T tmChargeTimeB;
    WORD_T tmTurnPressB;
    WORD_T tmInjStartPosiB;
    WORD_T tmTurnPosiB;
    WORD_T tmInjEndPosiB;
    WORD_T tmInjEndB;
    WORD_T tmChargeRPMB;
    WORD_T tmInjBackTimeB;
    WORD_T tmEjectTimeB;
    WORD_T tmEjectFWDTimeB;
    WORD_T tmEjectBWDTimeB;
    WORD_T tmInjMaxPressB;
    WORD_T tmChargeMaxPressB;
    WORD_T unknowndata1;
    WORD_T unknowndata2;
    WORD_T unknowndata3;
    WORD_T unknowndata4;
    WORD_T unknowndata5;
    WORD_T unknowndata6;
    DWORD_T tmbcBarCode1_1;
    DWORD_T tmbcBarCode1_2;
    DWORD_T tmbcBarCode1_3;
    DWORD_T tmbcBarCode2_1;
    DWORD_T tmbcBarCode2_2;
    DWORD_T tmbcBarCode2_3;
    DWORD_T tmbcMaterialSpec_1;
    DWORD_T tmbcMaterialSpec_2;
    DWORD_T tmbcMaterialSpec_3;
    DWORD_T tmbcMaterialLotA_1;
    DWORD_T tmbcMaterialLotA_2;
    DWORD_T tmbcMaterialLotA_3;
    DWORD_T tmbcMaterialLotB_1;
    DWORD_T tmbcMaterialLotB_2;
    DWORD_T tmbcMaterialLotB_3;
    DWORD_T tmbcShiftNo;
    DWORD_T tmbcOperator;
    DWORD_T tmbcVINo;
    WORD_T tmbcCoolTime_1;
    WORD_T tmbcCoolTime_2;
};

typedef struct tagMLDH tagMLDH, *PtagMLDH;

typedef struct tagMLDH MLDH;

struct tagMLDH {
    WORD_T wSource;
    WORD_T wMhdrLength;
    WORD_T wMoldSerALength;
    WORD_T wMoldSerBLength;
};

typedef union tagINETDATATYPE tagINETDATATYPE, *PtagINETDATATYPE;

typedef struct BITs BITs, *PBITs;

struct BITs {
    ushort wData:16;
    char bySubType:8;
    char byType:6;
    char byEcho:2;
};

union tagINETDATATYPE {
    struct BITs bits;
    ulong dwDataType;
};

typedef struct tagUSER tagUSER, *PtagUSER;

struct tagUSER {
    char szUserID[8];
    char szPassword[8];
    char szName[8];
    WORD wPriv;
};

typedef struct tagBOUND_A tagBOUND_A, *PtagBOUND_A;

struct tagBOUND_A {
    DWORD_T tmCycleTimeMax;
    DWORD_T tmInjTimeMax;
    DWORD_T tmTurnTimeMax;
    DWORD_T tmChargeTimeMax;
    WORD_T tmClpClsTimeMax;
    char reserve1[4];
    WORD_T tmClpOpnPosiMax;
    WORD_T tmClpOpnTimeMax;
    WORD_T tmTurnPressMax;
    WORD_T tmInjStartPosiMax;
    WORD_T tmTurnPosiMax;
    WORD_T tmInjEndPosiMax;
    char reserve2[4];
    WORD_T tmInjBackTimeMax;
    WORD_T tmEjectTimeMax;
    char reserve3[2];
    WORD_T tmInjMaxPressMax;
    WORD_T tmChargeMaxPressMax;
    char reserve4[48];
    DWORD_T tmCycleTimeMin;
    DWORD_T tmInjTimeMin;
    DWORD_T tmTurnTimeMin;
    DWORD_T tmChargeTimeMin;
    WORD_T tmClpClsTimeMin;
    char reserve21[4];
    WORD_T tmClpOpnPosiMin;
    WORD_T tmClpOpnTimeMin;
    WORD_T tmTurnPressMin;
    WORD_T tmInjStartPosiMin;
    WORD_T tmTurnPosiMin;
    WORD_T tmInjEndPosiMin;
    char reserve22[4];
    WORD_T tmInjBackTimeMin;
    WORD_T tmEjectTimeMin;
    char reserve23[2];
    WORD_T tmInjMaxPressMin;
    WORD_T tmChargeMaxPressMin;
    char reserve24[48];
};

typedef struct tagTIME tagTIME, *PtagTIME;

struct tagTIME {
    BYTE bHour;
    BYTE bMinute;
    BYTE bSecond;
    BYTE bmSecond;
};

typedef struct tagOPERSTATE tagOPERSTATE, *PtagOPERSTATE;

typedef struct tagOPERSTATE OPERSTATE;

struct tagOPERSTATE {
    WORD_T wProdState;
    WORD_T wOperState;
    WORD_T wErrorState;
    WORD_T wHeatState;
    WORD_T wMotorState;
    DWORD_T tmInferior;
    WORD_T wReverse;
    char wTEST[36];
    DWORD_T tmPlanCount;
    DWORD_T dwShotCountCurrent;
    DWORD_T dwCycleTime;
    WORD_T wtmLotNumber;
    WORD_T wReverse1;
    DWORD_T dwReverse2;
    DWORD_T dwReverse3;
    DWORD_T dwReverse4;
    WORD_T wPowerRatio;
    DWORD_T dwTotalElectricity;
    WORD_T wtmBadShotCount;
};

typedef union tagINETDATATYPE INETDATATYPE;

typedef struct tagCboxErrorData tagCboxErrorData, *PtagCboxErrorData;

struct tagCboxErrorData {
    WORD_T g_DBErrorUnicode[32];
};

typedef struct tagERROR tagERROR, *PtagERROR;

typedef struct tagERROR ERROR;

typedef struct tagDATE tagDATE, *PtagDATE;

typedef struct tagDATE DATE;

typedef struct tagTIME TIME;

struct tagDATE {
    BYTE bDay;
    BYTE bMonth;
    WORD_T wYear;
    BYTE bWeek;
};

struct tagERROR {
    WORD_T wErrorCode;
    WORD_T wShotCount1;
    WORD_T wShotCount2;
    DATE dateStart;
    char unknow;
    TIME timeStart;
    DATE dateFixed;
    char stay;
    TIME timeFixed;
};

typedef struct tagBOUND_A BOUND_A;

typedef struct tagINTHEADER tagINTHEADER, *PtagINTHEADER;

typedef struct tagINTHEADER INTHEADER;

struct tagINTHEADER {
    WORD_T dwVersion;
    WORD_T dwLength;
    WORD_T dwReserved;
    WORD_T dwSpecia;
    ulong dwDirection;
    INETDATATYPE DataType;
};

typedef struct tagUSER USER;

typedef struct tagCboxErrorData CboxErrorData;

typedef struct tagENERGY ENERGY;

typedef struct tagMODIFY MODIFY;

typedef union tagBCCODE tagBCCODE, *PtagBCCODE;

union tagBCCODE {
    ulong dwValue;
    uchar byte[4];
};

typedef struct tagBOUND_AB tagBOUND_AB, *PtagBOUND_AB;

struct tagBOUND_AB {
    DWORD_T tmCycleTimeMax;
    DWORD_T tmInjTimeMax;
    DWORD_T tmTurnTimeMax;
    DWORD_T tmChargeTimeMax;
    WORD_T tmClpClsTimeMax;
    char reserve1[4];
    WORD_T tmClpOpnPosiMax;
    WORD_T tmClpOpnTimeMax;
    WORD_T tmTurnPressMax;
    WORD_T tmInjStartPosiMax;
    WORD_T tmTurnPosiMax;
    WORD_T tmInjEndPosiMax;
    char reserve2[4];
    WORD_T tmInjBackTimeMax;
    WORD_T tmEjectTimeMax;
    char reserve3[2];
    WORD_T tmInjMaxPressMax;
    WORD_T tmChargeMaxPressMax;
    char reserve4[48];
    DWORD_T tmCycleTimeMin;
    DWORD_T tmInjTimeMin;
    DWORD_T tmTurnTimeMin;
    DWORD_T tmChargeTimeMin;
    WORD_T tmClpClsTimeMin;
    char reserve21[4];
    WORD_T tmClpOpnPosiMin;
    WORD_T tmClpOpnTimeMin;
    WORD_T tmTurnPressMin;
    WORD_T tmInjStartPosiMin;
    WORD_T tmTurnPosiMin;
    WORD_T tmInjEndPosiMin;
    char reserve22[4];
    WORD_T tmInjBackTimeMin;
    WORD_T tmEjectTimeMin;
    char reserve23[2];
    WORD_T tmInjMaxPressMin;
    WORD_T tmChargeMaxPressMin;
    char reserve24[48];
    char reserve5[96];
    DWORD_T tmInjTimeMaxB;
    DWORD_T tmTurnTimeMaxB;
    DWORD_T tmChargeTimeMaxB;
    WORD_T tmTurnPressMaxB;
    WORD_T tmInjStartPosiMaxB;
    WORD_T tmTurnPosiMaxB;
    WORD_T tmInjEndPosiMaxB;
    char reserve6[4];
    WORD_T tmInjBackTimeMaxB;
    WORD_T tmEjectTimeMaxB;
    char reserve8[4];
    WORD_T tmInjMaxPressMaxB;
    WORD_T tmChargeMaxPressMaxB;
    char reserve7[12];
    DWORD_T tmInjTimeMinB;
    DWORD_T tmTurnTimeMinB;
    DWORD_T tmChargeTimeMinB;
    WORD_T tmTurnPressMinB;
    WORD_T tmInjStartPosiMinB;
    WORD_T tmTurnPosiMinB;
    WORD_T tmInjEndPosiMinB;
    char reserve26[4];
    WORD_T tmInjBackTimeMinB;
    WORD_T tmEjectTimeMinB;
    char reserve28[4];
    WORD_T tmInjMaxPressMinB;
    WORD_T tmChargeMaxPressMinB;
    char reserve27[12];
};

typedef struct tagBOUND_AB BOUND_AB;

typedef union tagBCCODE BCCode;

typedef struct rsa_oaep_params_st rsa_oaep_params_st, *Prsa_oaep_params_st;

typedef struct rsa_oaep_params_st RSA_OAEP_PARAMS;

struct rsa_oaep_params_st {
    X509_ALGOR *hashFunc;
    X509_ALGOR *maskGenFunc;
    X509_ALGOR *pSourceFunc;
};

typedef struct rsa_pss_params_st rsa_pss_params_st, *Prsa_pss_params_st;

struct rsa_pss_params_st {
    X509_ALGOR *hashAlgorithm;
    X509_ALGOR *maskGenAlgorithm;
    ASN1_INTEGER *saltLength;
    ASN1_INTEGER *trailerField;
};

typedef struct rsa_pss_params_st RSA_PSS_PARAMS;

typedef struct EVP_IDEA_KEY EVP_IDEA_KEY, *PEVP_IDEA_KEY;

typedef struct idea_key_st idea_key_st, *Pidea_key_st;

typedef struct idea_key_st IDEA_KEY_SCHEDULE;

struct idea_key_st {
    uint data[9][6];
};

struct EVP_IDEA_KEY {
    IDEA_KEY_SCHEDULE ks;
};

typedef struct b64_struct b64_struct, *Pb64_struct;

struct b64_struct {
    int buf_len;
    int buf_off;
    int tmp_len;
    int tmp_nl;
    int encode;
    int start;
    int cont;
    EVP_ENCODE_CTX base64;
    char buf[1502];
    char tmp[1024];
};

typedef struct b64_struct BIO_B64_CTX;

typedef struct sockaddr_un sockaddr_un, *Psockaddr_un;

struct sockaddr_un {
    sa_family_t sun_family;
    char sun_path[108];
};


// WARNING! conflicting data type names: /DWARF/time.h/timespec - /time.h/timespec

typedef struct tm tm, *Ptm;

struct tm {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
    long tm_gmtoff;
    char *tm_zone;
};

typedef struct timezone timezone, *Ptimezone;

struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};

typedef struct timeval timeval, *Ptimeval;

struct timeval {
    __time_t tv_sec;
    __suseconds_t tv_usec;
};

typedef enum xmlAttributeType {
    XML_ATTRIBUTE_CDATA=1,
    XML_ATTRIBUTE_ID=2,
    XML_ATTRIBUTE_IDREF=3,
    XML_ATTRIBUTE_IDREFS=4,
    XML_ATTRIBUTE_ENTITY=5,
    XML_ATTRIBUTE_ENTITIES=6,
    XML_ATTRIBUTE_NMTOKEN=7,
    XML_ATTRIBUTE_NMTOKENS=8,
    XML_ATTRIBUTE_ENUMERATION=9,
    XML_ATTRIBUTE_NOTATION=10
} xmlAttributeType;

typedef struct _xmlNs _xmlNs, *P_xmlNs;

typedef struct _xmlNs xmlNs;

typedef enum xmlElementType {
    XML_ELEMENT_NODE=1,
    XML_ATTRIBUTE_NODE=2,
    XML_TEXT_NODE=3,
    XML_CDATA_SECTION_NODE=4,
    XML_ENTITY_REF_NODE=5,
    XML_ENTITY_NODE=6,
    XML_PI_NODE=7,
    XML_COMMENT_NODE=8,
    XML_DOCUMENT_NODE=9,
    XML_DOCUMENT_TYPE_NODE=10,
    XML_DOCUMENT_FRAG_NODE=11,
    XML_NOTATION_NODE=12,
    XML_HTML_DOCUMENT_NODE=13,
    XML_DTD_NODE=14,
    XML_ELEMENT_DECL=15,
    XML_ATTRIBUTE_DECL=16,
    XML_ENTITY_DECL=17,
    XML_NAMESPACE_DECL=18,
    XML_XINCLUDE_START=19,
    XML_XINCLUDE_END=20
} xmlElementType;

typedef enum xmlElementType xmlNsType;

typedef struct _xmlDoc _xmlDoc, *P_xmlDoc;

typedef struct _xmlNode _xmlNode, *P_xmlNode;

typedef struct _xmlDtd _xmlDtd, *P_xmlDtd;

typedef struct _xmlAttr _xmlAttr, *P_xmlAttr;

struct _xmlNs {
    struct _xmlNs *next;
    xmlNsType type;
    xmlChar *href;
    xmlChar *prefix;
    void *_private;
    struct _xmlDoc *context;
};

struct _xmlAttr {
    void *_private;
    enum xmlElementType type;
    xmlChar *name;
    struct _xmlNode *children;
    struct _xmlNode *last;
    struct _xmlNode *parent;
    struct _xmlAttr *next;
    struct _xmlAttr *prev;
    struct _xmlDoc *doc;
    xmlNs *ns;
    enum xmlAttributeType atype;
    void *psvi;
};

struct _xmlDoc {
    void *_private;
    enum xmlElementType type;
    char *name;
    struct _xmlNode *children;
    struct _xmlNode *last;
    struct _xmlNode *parent;
    struct _xmlNode *next;
    struct _xmlNode *prev;
    struct _xmlDoc *doc;
    int compression;
    int standalone;
    struct _xmlDtd *intSubset;
    struct _xmlDtd *extSubset;
    struct _xmlNs *oldNs;
    xmlChar *version;
    xmlChar *encoding;
    void *ids;
    void *refs;
    xmlChar *URL;
    int charset;
    struct _xmlDict *dict;
    void *psvi;
    int parseFlags;
    int properties;
};

struct _xmlNode {
    void *_private;
    enum xmlElementType type;
    xmlChar *name;
    struct _xmlNode *children;
    struct _xmlNode *last;
    struct _xmlNode *parent;
    struct _xmlNode *next;
    struct _xmlNode *prev;
    struct _xmlDoc *doc;
    xmlNs *ns;
    xmlChar *content;
    struct _xmlAttr *properties;
    xmlNs *nsDef;
    void *psvi;
    ushort line;
    ushort extra;
};

struct _xmlDtd {
    void *_private;
    enum xmlElementType type;
    xmlChar *name;
    struct _xmlNode *children;
    struct _xmlNode *last;
    struct _xmlDoc *parent;
    struct _xmlNode *next;
    struct _xmlNode *prev;
    struct _xmlDoc *doc;
    void *notations;
    void *elements;
    void *attributes;
    void *entities;
    xmlChar *ExternalID;
    xmlChar *SystemID;
    void *pentities;
};

typedef xmlNs *xmlNsPtr;

typedef struct _xmlDoc xmlDoc;

typedef xmlDoc *xmlDocPtr;

typedef struct _xmlNode xmlNode;

typedef xmlNode *xmlNodePtr;

typedef struct EVP_PBE_CTL EVP_PBE_CTL, *PEVP_PBE_CTL;

struct EVP_PBE_CTL {
    int pbe_type;
    int pbe_nid;
    int cipher_nid;
    int md_nid;
    int (*keygen)(EVP_CIPHER_CTX *, char *, int, ASN1_TYPE *, EVP_CIPHER *, EVP_MD *, int);
};

typedef struct stack_st_EVP_PBE_CTL stack_st_EVP_PBE_CTL, *Pstack_st_EVP_PBE_CTL;

struct stack_st_EVP_PBE_CTL {
    _STACK stack;
};

typedef struct added_obj_st added_obj_st, *Padded_obj_st;

typedef struct added_obj_st ADDED_OBJ;

struct added_obj_st {
    int type;
    ASN1_OBJECT *obj;
};

typedef struct lhash_st_ADDED_OBJ lhash_st_ADDED_OBJ, *Plhash_st_ADDED_OBJ;

struct lhash_st_ADDED_OBJ {
    int dummy;
};

typedef char * (*xmlStrdupFunc)(char *);

typedef void (*xmlFreeFunc)(void *);

typedef void * (*xmlMallocFunc)(size_t);

typedef void * (*xmlReallocFunc)(void *, size_t);

typedef struct EC_PKEY_CTX EC_PKEY_CTX, *PEC_PKEY_CTX;

struct EC_PKEY_CTX {
    EC_GROUP *gen_group;
    EVP_MD *md;
    EC_KEY *co_key;
    char cofactor_mode;
    char kdf_type;
    EVP_MD *kdf_md;
    uchar *kdf_ukm;
    size_t kdf_ukmlen;
    size_t kdf_outlen;
};

typedef struct st_engine_pile st_engine_pile, *Pst_engine_pile;

struct st_engine_pile {
    int nid;
    struct stack_st_ENGINE *sk;
    ENGINE *funct;
    int uptodate;
};

typedef struct st_engine_pile ENGINE_PILE;

typedef struct st_engine_pile_doall st_engine_pile_doall, *Pst_engine_pile_doall;

typedef struct st_engine_pile_doall ENGINE_PILE_DOALL;

struct st_engine_pile_doall {
    void (*cb)(int, struct stack_st_ENGINE *, ENGINE *, void *);
    void *arg;
};

typedef struct DSA_PKEY_CTX DSA_PKEY_CTX, *PDSA_PKEY_CTX;

struct DSA_PKEY_CTX {
    int nbits;
    int qbits;
    EVP_MD *pmd;
    int gentmp[2];
    EVP_MD *md;
};

typedef struct lhash_st_MEM lhash_st_MEM, *Plhash_st_MEM;

struct lhash_st_MEM {
    int dummy;
};

typedef struct mem_leak_st mem_leak_st, *Pmem_leak_st;

struct mem_leak_st {
    BIO *bio;
    int chunks;
    long bytes;
};

typedef struct lhash_st_APP_INFO lhash_st_APP_INFO, *Plhash_st_APP_INFO;

struct lhash_st_APP_INFO {
    int dummy;
};

typedef void * (*PCRYPTO_MEM_LEAK_CB)(ulong, char *, int, int, void *);

typedef struct mem_st mem_st, *Pmem_st;

typedef struct app_mem_info_st app_mem_info_st, *Papp_mem_info_st;

typedef struct app_mem_info_st APP_INFO;

struct mem_st {
    void *addr;
    int num;
    char *file;
    int line;
    CRYPTO_THREADID threadid;
    ulong order;
    time_t time;
    APP_INFO *app_info;
};

struct app_mem_info_st {
    CRYPTO_THREADID threadid;
    char *file;
    int line;
    char *info;
    struct app_mem_info_st *next;
    int references;
};

typedef struct mem_st MEM;

typedef struct mem_leak_st MEM_LEAK;

typedef struct lhash_st lhash_st, *Plhash_st;

typedef struct lhash_st _LHASH;

typedef struct lhash_node_st lhash_node_st, *Plhash_node_st;

typedef struct lhash_node_st LHASH_NODE;

typedef int (*LHASH_COMP_FN_TYPE)(void *, void *);

typedef ulong (*LHASH_HASH_FN_TYPE)(void *);

struct lhash_node_st {
    void *data;
    struct lhash_node_st *next;
    ulong hash;
};

struct lhash_st {
    LHASH_NODE **b;
    LHASH_COMP_FN_TYPE comp;
    LHASH_HASH_FN_TYPE hash;
    uint num_nodes;
    uint num_alloc_nodes;
    uint p;
    uint pmax;
    ulong up_load;
    ulong down_load;
    ulong num_items;
    ulong num_expands;
    ulong num_expand_reallocs;
    ulong num_contracts;
    ulong num_contract_reallocs;
    ulong num_hash_calls;
    ulong num_comp_calls;
    ulong num_insert;
    ulong num_replace;
    ulong num_delete;
    ulong num_no_delete;
    ulong num_retrieve;
    ulong num_retrieve_miss;
    ulong num_hash_comps;
    int error;
};

typedef void (*LHASH_DOALL_ARG_FN_TYPE)(void *, void *);

typedef void (*LHASH_DOALL_FN_TYPE)(void *);

typedef struct stack_st_EVP_PKEY_ASN1_METHOD stack_st_EVP_PKEY_ASN1_METHOD, *Pstack_st_EVP_PKEY_ASN1_METHOD;

struct stack_st_EVP_PKEY_ASN1_METHOD {
    _STACK stack;
};

typedef struct stack_st_OPENSSL_BLOCK stack_st_OPENSSL_BLOCK, *Pstack_st_OPENSSL_BLOCK;

struct stack_st_OPENSSL_BLOCK {
    _STACK stack;
};

typedef void *OPENSSL_BLOCK;

typedef char *OPENSSL_STRING;

typedef __pid_t pid_t;

typedef struct DER_ENC DER_ENC, *PDER_ENC;

struct DER_ENC {
    uchar *data;
    int length;
    ASN1_VALUE *field;
};

typedef struct stack_st_MIME_PARAM stack_st_MIME_PARAM, *Pstack_st_MIME_PARAM;

struct stack_st_MIME_PARAM {
    _STACK stack;
};

typedef struct MIME_HEADER MIME_HEADER, *PMIME_HEADER;

struct MIME_HEADER {
    char *name;
    char *value;
    struct stack_st_MIME_PARAM *params;
};

typedef struct MIME_PARAM MIME_PARAM, *PMIME_PARAM;

struct MIME_PARAM {
    char *param_name;
    char *param_value;
};

typedef struct stack_st_MIME_HEADER stack_st_MIME_HEADER, *Pstack_st_MIME_HEADER;

struct stack_st_MIME_HEADER {
    _STACK stack;
};

typedef union anon_union_16_2_94730052 anon_union_16_2_94730052, *Panon_union_16_2_94730052;

union anon_union_16_2_94730052 {
    size_t t[4];
    uchar c[16];
};

typedef struct enc_struct enc_struct, *Penc_struct;

struct enc_struct {
    int buf_len;
    int buf_off;
    int cont;
    int finished;
    int ok;
    EVP_CIPHER_CTX cipher;
    char buf[4162];
};

typedef struct enc_struct BIO_ENC_CTX;


// WARNING! conflicting data type names: /DWARF/siginfo.h/siginfo_t - /siginfo.h/siginfo_t

typedef union anon_union_116_8_26c2b70a_for__sifields anon_union_116_8_26c2b70a_for__sifields, *Panon_union_116_8_26c2b70a_for__sifields;

typedef struct anon_struct_8_2_0a3d7222_for__kill anon_struct_8_2_0a3d7222_for__kill, *Panon_struct_8_2_0a3d7222_for__kill;

typedef struct anon_struct_12_3_5124685d_for__timer anon_struct_12_3_5124685d_for__timer, *Panon_struct_12_3_5124685d_for__timer;

typedef struct anon_struct_12_3_9bedbd60_for__rt anon_struct_12_3_9bedbd60_for__rt, *Panon_struct_12_3_9bedbd60_for__rt;

typedef struct anon_struct_20_5_7a025f54_for__sigchld anon_struct_20_5_7a025f54_for__sigchld, *Panon_struct_20_5_7a025f54_for__sigchld;

typedef struct anon_struct_8_2_895adaa1_for__sigfault anon_struct_8_2_895adaa1_for__sigfault, *Panon_struct_8_2_895adaa1_for__sigfault;

typedef struct anon_struct_8_2_686959ae_for__sigpoll anon_struct_8_2_686959ae_for__sigpoll, *Panon_struct_8_2_686959ae_for__sigpoll;

typedef struct anon_struct_12_3_fe5e7108_for__sigsys anon_struct_12_3_fe5e7108_for__sigsys, *Panon_struct_12_3_fe5e7108_for__sigsys;

struct anon_struct_8_2_895adaa1_for__sigfault {
    void *si_addr;
    short si_addr_lsb;
};

struct anon_struct_12_3_9bedbd60_for__rt {
    __pid_t si_pid;
    __uid_t si_uid;
    sigval_t si_sigval;
};

struct anon_struct_8_2_0a3d7222_for__kill {
    __pid_t si_pid;
    __uid_t si_uid;
};

struct anon_struct_8_2_686959ae_for__sigpoll {
    long si_band;
    int si_fd;
};

struct anon_struct_12_3_5124685d_for__timer {
    int si_tid;
    int si_overrun;
    sigval_t si_sigval;
};

struct anon_struct_20_5_7a025f54_for__sigchld {
    __pid_t si_pid;
    __uid_t si_uid;
    int si_status;
    __clock_t si_utime;
    __clock_t si_stime;
};

struct anon_struct_12_3_fe5e7108_for__sigsys {
    void *_call_addr;
    int _syscall;
    uint _arch;
};

union anon_union_116_8_26c2b70a_for__sifields {
    int _pad[29];
    struct anon_struct_8_2_0a3d7222_for__kill _kill;
    struct anon_struct_12_3_5124685d_for__timer _timer;
    struct anon_struct_12_3_9bedbd60_for__rt _rt;
    struct anon_struct_20_5_7a025f54_for__sigchld _sigchld;
    struct anon_struct_8_2_895adaa1_for__sigfault _sigfault;
    struct anon_struct_8_2_686959ae_for__sigpoll _sigpoll;
    struct anon_struct_12_3_fe5e7108_for__sigsys _sigsys;
};

typedef struct conf_imodule_st conf_imodule_st, *Pconf_imodule_st;

typedef struct conf_imodule_st CONF_IMODULE;

typedef struct conf_module_st conf_module_st, *Pconf_module_st;

typedef struct conf_module_st CONF_MODULE;

struct conf_imodule_st {
    CONF_MODULE *pmod;
    char *name;
    char *value;
    ulong flags;
    void *usr_data;
};

struct conf_module_st {
    DSO *dso;
    char *name;
    int (*init)(CONF_IMODULE *, CONF *);
    void (*finish)(CONF_IMODULE *);
    int links;
    void *usr_data;
};

typedef struct stack_st_CONF_IMODULE stack_st_CONF_IMODULE, *Pstack_st_CONF_IMODULE;

struct stack_st_CONF_IMODULE {
    _STACK stack;
};

typedef struct stack_st_CONF_MODULE stack_st_CONF_MODULE, *Pstack_st_CONF_MODULE;

struct stack_st_CONF_MODULE {
    _STACK stack;
};

typedef struct CONF_VALUE CONF_VALUE, *PCONF_VALUE;

struct CONF_VALUE {
    char *section;
    char *name;
    char *value;
};

typedef struct rc4_key_st rc4_key_st, *Prc4_key_st;

typedef struct rc4_key_st RC4_KEY;

struct rc4_key_st {
    uchar x;
    uchar y;
    uchar data[256];
};

typedef struct sigaction sigaction, *Psigaction;

typedef union anon_union_4_2_5ad2d23e_for___sigaction_handler anon_union_4_2_5ad2d23e_for___sigaction_handler, *Panon_union_4_2_5ad2d23e_for___sigaction_handler;

union anon_union_4_2_5ad2d23e_for___sigaction_handler {
    __sighandler_t sa_handler;
    void (*sa_sigaction)(int, struct siginfo_t *, void *);
};

struct sigaction {
    union anon_union_4_2_5ad2d23e_for___sigaction_handler __sigaction_handler;
    struct __sigset_t sa_mask;
    int sa_flags;
    void (*sa_restorer)(void);
};

typedef struct mdc2_ctx_st mdc2_ctx_st, *Pmdc2_ctx_st;

typedef struct mdc2_ctx_st MDC2_CTX;

struct mdc2_ctx_st {
    uint num;
    uchar data[8];
    DES_cblock h;
    DES_cblock hh;
    int pad_type;
};

typedef union anon_union_16_3_4e909ff4 anon_union_16_3_4e909ff4, *Panon_union_16_3_4e909ff4;

union anon_union_16_3_4e909ff4 {
    u64 u[2];
    u32 d[4];
    u8 c[16];
};

typedef union anon_union_16_2_94730053 anon_union_16_2_94730053, *Panon_union_16_2_94730053;

union anon_union_16_2_94730053 {
    u64 u[2];
    u8 c[16];
};

typedef struct EC_builtin_curve EC_builtin_curve, *PEC_builtin_curve;

struct EC_builtin_curve {
    int nid;
    char *comment;
};

typedef struct ENGINE_CMD_DEFN_st ENGINE_CMD_DEFN_st, *PENGINE_CMD_DEFN_st;

typedef struct ENGINE_CMD_DEFN_st ENGINE_CMD_DEFN;

struct ENGINE_CMD_DEFN_st {
    uint cmd_num;
    char *cmd_name;
    char *cmd_desc;
    uint cmd_flags;
};

typedef int (*ENGINE_DIGESTS_PTR)(ENGINE *, EVP_MD **, int **, int);

typedef int (*ENGINE_GEN_INT_FUNC_PTR)(ENGINE *);

typedef int (*ENGINE_SSL_CLIENT_CERT_PTR)(ENGINE *, SSL *, struct stack_st_X509_NAME *, X509 **, EVP_PKEY **, struct stack_st_X509 **, UI_METHOD *, void *);

typedef int (*ENGINE_PKEY_ASN1_METHS_PTR)(ENGINE *, EVP_PKEY_ASN1_METHOD **, int **, int);

typedef int (*ENGINE_PKEY_METHS_PTR)(ENGINE *, EVP_PKEY_METHOD **, int **, int);

typedef int (*ENGINE_CIPHERS_PTR)(ENGINE *, EVP_CIPHER **, int **, int);

typedef EVP_PKEY * (*ENGINE_LOAD_KEY_PTR)(ENGINE *, char *, UI_METHOD *, void *);

typedef int (*ENGINE_CTRL_FUNC_PTR)(ENGINE *, int, long, void *, void (*)(void));

typedef struct stack_st_X509_NAME_ENTRY STACK_OF_X509_NAME_ENTRY;

typedef struct stack_st_STACK_OF_X509_NAME_ENTRY stack_st_STACK_OF_X509_NAME_ENTRY, *Pstack_st_STACK_OF_X509_NAME_ENTRY;

struct stack_st_STACK_OF_X509_NAME_ENTRY {
    _STACK stack;
};

typedef union anon_union_4_2_94730013 anon_union_4_2_94730013, *Panon_union_4_2_94730013;

union anon_union_4_2_94730013 {
    struct stack_st_STACK_OF_X509_NAME_ENTRY *s;
    ASN1_VALUE *a;
};

typedef union anon_union_4_2_94730018 anon_union_4_2_94730018, *Panon_union_4_2_94730018;

union anon_union_4_2_94730018 {
    X509_NAME *x;
    ASN1_VALUE *a;
};

typedef struct EVP_DES_KEY EVP_DES_KEY, *PEVP_DES_KEY;

typedef union anon_union_128_2_8c9ca482_for_ks anon_union_128_2_8c9ca482_for_ks, *Panon_union_128_2_8c9ca482_for_ks;

union anon_union_128_2_8c9ca482_for_ks {
    double align;
    DES_key_schedule ks;
};

struct EVP_DES_KEY {
    union anon_union_128_2_8c9ca482_for_ks ks;
    union anon_union_4_1_ba1d3b44_for_stream stream;
};

typedef struct stack_st_CRYPTO_dynlock stack_st_CRYPTO_dynlock, *Pstack_st_CRYPTO_dynlock;

struct stack_st_CRYPTO_dynlock {
    _STACK stack;
};

typedef hashval_t (*htab_hash)(void *);

typedef int (*htab_eq)(void *, void *);

typedef struct EVP_RC4_KEY EVP_RC4_KEY, *PEVP_RC4_KEY;

struct EVP_RC4_KEY {
    RC4_KEY ks;
};

typedef struct _xmlXPathCompExpr _xmlXPathCompExpr, *P_xmlXPathCompExpr;

struct _xmlXPathCompExpr {
};

typedef struct _dont_use_rtx_here_ _dont_use_rtx_here_, *P_dont_use_rtx_here_;

struct _dont_use_rtx_here_ {
};


// WARNING! conflicting data type names: /DWARF/_UNCATEGORIZED_/ASN1_VALUE_st - /asn1.h/ASN1_VALUE_st

typedef struct _xmlXPathContext _xmlXPathContext, *P_xmlXPathContext;

typedef struct _xmlXPathContext xmlXPathContext;

typedef struct _xmlXPathType _xmlXPathType, *P_xmlXPathType;

typedef struct _xmlXPathType xmlXPathType;

typedef xmlXPathType *xmlXPathTypePtr;

typedef struct _xmlXPathAxis _xmlXPathAxis, *P_xmlXPathAxis;

typedef struct _xmlXPathAxis xmlXPathAxis;

typedef xmlXPathAxis *xmlXPathAxisPtr;

typedef struct _xmlXPathObject _xmlXPathObject, *P_xmlXPathObject;

typedef struct _xmlXPathObject xmlXPathObject;

typedef xmlXPathObject *xmlXPathObjectPtr;

typedef xmlXPathObjectPtr (*xmlXPathVariableLookupFunc)(void *, xmlChar *, xmlChar *);

typedef struct _xmlXPathParserContext _xmlXPathParserContext, *P_xmlXPathParserContext;

typedef struct _xmlXPathParserContext xmlXPathParserContext;

typedef xmlXPathParserContext *xmlXPathParserContextPtr;

typedef void (*xmlXPathFunction)(xmlXPathParserContextPtr, int);

typedef xmlXPathFunction (*xmlXPathFuncLookupFunc)(void *, xmlChar *, xmlChar *);

typedef int (*xmlXPathConvertFunc)(xmlXPathObjectPtr, int);

typedef xmlXPathObjectPtr (*xmlXPathAxisFunc)(xmlXPathParserContextPtr, xmlXPathObjectPtr);

typedef enum xmlXPathObjectType {
    XPATH_UNDEFINED=0,
    XPATH_NODESET=1,
    XPATH_BOOLEAN=2,
    XPATH_NUMBER=3,
    XPATH_STRING=4,
    XPATH_POINT=5,
    XPATH_RANGE=6,
    XPATH_LOCATIONSET=7,
    XPATH_USERS=8,
    XPATH_XSLT_TREE=9
} xmlXPathObjectType;

typedef struct _xmlNodeSet _xmlNodeSet, *P_xmlNodeSet;

typedef struct _xmlNodeSet xmlNodeSet;

typedef xmlNodeSet *xmlNodeSetPtr;

typedef xmlXPathContext *xmlXPathContextPtr;

typedef struct _xmlXPathCompExpr xmlXPathCompExpr;

typedef xmlXPathCompExpr *xmlXPathCompExprPtr;

struct _xmlXPathContext {
    xmlDocPtr doc;
    xmlNodePtr node;
    int nb_variables_unused;
    int max_variables_unused;
    xmlHashTablePtr varHash;
    int nb_types;
    int max_types;
    xmlXPathTypePtr types;
    int nb_funcs_unused;
    int max_funcs_unused;
    xmlHashTablePtr funcHash;
    int nb_axis;
    int max_axis;
    xmlXPathAxisPtr axis;
    xmlNsPtr *namespaces;
    int nsNr;
    void *user;
    int contextSize;
    int proximityPosition;
    int xptr;
    xmlNodePtr here;
    xmlNodePtr origin;
    xmlHashTablePtr nsHash;
    xmlXPathVariableLookupFunc varLookupFunc;
    void *varLookupData;
    void *extra;
    xmlChar *function;
    xmlChar *functionURI;
    xmlXPathFuncLookupFunc funcLookupFunc;
    void *funcLookupData;
    xmlNsPtr *tmpNsList;
    int tmpNsNr;
    void *userData;
    xmlStructuredErrorFunc error;
    xmlError lastError;
    xmlNodePtr debugNode;
    xmlDictPtr dict;
    int flags;
    void *cache;
};

struct _xmlXPathParserContext {
    xmlChar *cur;
    xmlChar *base;
    int error;
    xmlXPathContextPtr context;
    xmlXPathObjectPtr value;
    int valueNr;
    int valueMax;
    xmlXPathObjectPtr *valueTab;
    xmlXPathCompExprPtr comp;
    int xptr;
    xmlNodePtr ancestor;
    int valueFrame;
};

struct _xmlNodeSet {
    int nodeNr;
    int nodeMax;
    xmlNodePtr *nodeTab;
};

struct _xmlXPathType {
    xmlChar *name;
    xmlXPathConvertFunc func;
};

struct _xmlXPathAxis {
    xmlChar *name;
    xmlXPathAxisFunc func;
};

struct _xmlXPathObject {
    enum xmlXPathObjectType type;
    xmlNodeSetPtr nodesetval;
    int boolval;
    double floatval;
    xmlChar *stringval;
    void *user;
    int index;
    void *user2;
    int index2;
};

typedef struct _IO_FILE_plus _IO_FILE_plus, *P_IO_FILE_plus;

struct _IO_FILE_plus {
};

typedef struct RSA_PKEY_CTX RSA_PKEY_CTX, *PRSA_PKEY_CTX;

struct RSA_PKEY_CTX {
    int nbits;
    BIGNUM *pub_exp;
    int gentmp[2];
    int pad_mode;
    EVP_MD *md;
    EVP_MD *mgf1md;
    int saltlen;
    uchar *tbuf;
    uchar *oaep_label;
    size_t oaep_labellen;
};

typedef struct MYBLOB MYBLOB, *PMYBLOB;

struct MYBLOB {
    uchar *pbData;
    int cbData;
};

typedef struct RIPEMD160state_st RIPEMD160state_st, *PRIPEMD160state_st;

typedef struct RIPEMD160state_st RIPEMD160_CTX;

struct RIPEMD160state_st {
    uint A;
    uint B;
    uint C;
    uint D;
    uint E;
    uint Nl;
    uint Nh;
    uint data[16];
    uint num;
};

typedef struct EVP_RC4_HMAC_MD5 EVP_RC4_HMAC_MD5, *PEVP_RC4_HMAC_MD5;

struct EVP_RC4_HMAC_MD5 {
    RC4_KEY ks;
    MD5_CTX head;
    MD5_CTX tail;
    MD5_CTX md;
    size_t payload_length;
};

typedef struct EC_CURVE_DATA EC_CURVE_DATA, *PEC_CURVE_DATA;

struct EC_CURVE_DATA {
    int field_type;
    int seed_len;
    int param_len;
    uint cofactor;
};

typedef struct anon_struct_468_2_fe4040c2 anon_struct_468_2_fe4040c2, *Panon_struct_468_2_fe4040c2;

struct anon_struct_468_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[452];
};

typedef struct anon_struct_184_2_fe4040c2 anon_struct_184_2_fe4040c2, *Panon_struct_184_2_fe4040c2;

struct anon_struct_184_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[168];
};

typedef struct EC_NIST_NAME EC_NIST_NAME, *PEC_NIST_NAME;

struct EC_NIST_NAME {
    char *name;
    int nid;
};

typedef struct anon_struct_188_2_fe4040c2 anon_struct_188_2_fe4040c2, *Panon_struct_188_2_fe4040c2;

struct anon_struct_188_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[170];
};

typedef struct anon_struct_432_2_fe4040c2 anon_struct_432_2_fe4040c2, *Panon_struct_432_2_fe4040c2;

struct anon_struct_432_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[416];
};

typedef struct anon_struct_228_2_fe4040c2.conflict anon_struct_228_2_fe4040c2.conflict, *Panon_struct_228_2_fe4040c2.conflict;

struct anon_struct_228_2_fe4040c2.conflict {
    struct EC_CURVE_DATA h;
    uchar data[210];
};

typedef struct anon_struct_208_2_fe4040c2 anon_struct_208_2_fe4040c2, *Panon_struct_208_2_fe4040c2;

struct anon_struct_208_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[192];
};

typedef struct anon_struct_164_2_fe4040c2 anon_struct_164_2_fe4040c2, *Panon_struct_164_2_fe4040c2;

struct anon_struct_164_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[146];
};

typedef struct anon_struct_308_2_fe4040c2 anon_struct_308_2_fe4040c2, *Panon_struct_308_2_fe4040c2;

struct anon_struct_308_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[290];
};

typedef struct anon_struct_144_2_fe4040c2 anon_struct_144_2_fe4040c2, *Panon_struct_144_2_fe4040c2;

struct anon_struct_144_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[126];
};

typedef struct anon_struct_324_2_fe4040c2 anon_struct_324_2_fe4040c2, *Panon_struct_324_2_fe4040c2;

struct anon_struct_324_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[308];
};

typedef struct anon_struct_160_2_fe4040c2 anon_struct_160_2_fe4040c2, *Panon_struct_160_2_fe4040c2;

struct anon_struct_160_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[144];
};

typedef struct anon_struct_108_2_fe4040c2 anon_struct_108_2_fe4040c2, *Panon_struct_108_2_fe4040c2;

struct anon_struct_108_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[90];
};

typedef struct anon_struct_328_2_fe4040c2 anon_struct_328_2_fe4040c2, *Panon_struct_328_2_fe4040c2;

struct anon_struct_328_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[312];
};

typedef struct anon_struct_140_2_fe4040c2 anon_struct_140_2_fe4040c2, *Panon_struct_140_2_fe4040c2;

struct anon_struct_140_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[122];
};

typedef struct anon_struct_340_2_fe4040c2 anon_struct_340_2_fe4040c2, *Panon_struct_340_2_fe4040c2;

struct anon_struct_340_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[324];
};

typedef struct anon_struct_448_2_fe4040c2 anon_struct_448_2_fe4040c2, *Panon_struct_448_2_fe4040c2;

struct anon_struct_448_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[432];
};

typedef struct anon_struct_228_2_fe4040c2 anon_struct_228_2_fe4040c2, *Panon_struct_228_2_fe4040c2;

struct anon_struct_228_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[212];
};

typedef struct anon_struct_348_2_fe4040c2 anon_struct_348_2_fe4040c2, *Panon_struct_348_2_fe4040c2;

struct anon_struct_348_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[332];
};

typedef struct anon_struct_128_2_fe4040c2 anon_struct_128_2_fe4040c2, *Panon_struct_128_2_fe4040c2;

struct anon_struct_128_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[110];
};

typedef struct anon_struct_300_2_fe4040c2 anon_struct_300_2_fe4040c2, *Panon_struct_300_2_fe4040c2;

struct anon_struct_300_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[282];
};

typedef struct anon_struct_120_2_fe4040c2 anon_struct_120_2_fe4040c2, *Panon_struct_120_2_fe4040c2;

struct anon_struct_120_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[104];
};

typedef struct anon_struct_196_2_fe4040c2 anon_struct_196_2_fe4040c2, *Panon_struct_196_2_fe4040c2;

struct anon_struct_196_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[180];
};

typedef struct anon_struct_156_2_fe4040c2 anon_struct_156_2_fe4040c2, *Panon_struct_156_2_fe4040c2;

struct anon_struct_156_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[138];
};

typedef struct anon_struct_252_2_fe4040c2.conflict anon_struct_252_2_fe4040c2.conflict, *Panon_struct_252_2_fe4040c2.conflict;

struct anon_struct_252_2_fe4040c2.conflict {
    struct EC_CURVE_DATA h;
    uchar data[234];
};

typedef struct anon_struct_256_2_fe4040c2 anon_struct_256_2_fe4040c2, *Panon_struct_256_2_fe4040c2;

struct anon_struct_256_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[240];
};

typedef struct anon_struct_400_2_fe4040c2 anon_struct_400_2_fe4040c2, *Panon_struct_400_2_fe4040c2;

struct anon_struct_400_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[384];
};

typedef struct anon_struct_192_2_fe4040c2 anon_struct_192_2_fe4040c2, *Panon_struct_192_2_fe4040c2;

struct anon_struct_192_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[174];
};

typedef struct anon_struct_304_2_fe4040c2 anon_struct_304_2_fe4040c2, *Panon_struct_304_2_fe4040c2;

struct anon_struct_304_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[288];
};

typedef struct _ec_list_element_st _ec_list_element_st, *P_ec_list_element_st;

typedef struct _ec_list_element_st ec_list_element;

struct _ec_list_element_st {
    int nid;
    struct EC_CURVE_DATA *data;
    EC_METHOD * (*meth)(void);
    char *comment;
};

typedef struct anon_struct_180_2_fe4040c2.conflict anon_struct_180_2_fe4040c2.conflict, *Panon_struct_180_2_fe4040c2.conflict;

struct anon_struct_180_2_fe4040c2.conflict {
    struct EC_CURVE_DATA h;
    uchar data[162];
};

typedef struct anon_struct_204_2_fe4040c2 anon_struct_204_2_fe4040c2, *Panon_struct_204_2_fe4040c2;

struct anon_struct_204_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[188];
};

typedef struct anon_struct_216_2_fe4040c2 anon_struct_216_2_fe4040c2, *Panon_struct_216_2_fe4040c2;

struct anon_struct_216_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[200];
};

typedef struct anon_struct_180_2_fe4040c2 anon_struct_180_2_fe4040c2, *Panon_struct_180_2_fe4040c2;

struct anon_struct_180_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[164];
};

typedef struct anon_struct_252_2_fe4040c2 anon_struct_252_2_fe4040c2, *Panon_struct_252_2_fe4040c2;

struct anon_struct_252_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[236];
};

typedef struct anon_struct_136_2_fe4040c2 anon_struct_136_2_fe4040c2, *Panon_struct_136_2_fe4040c2;

struct anon_struct_136_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[120];
};

typedef struct anon_struct_232_2_fe4040c2 anon_struct_232_2_fe4040c2, *Panon_struct_232_2_fe4040c2;

struct anon_struct_232_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[216];
};

typedef struct anon_struct_132_2_fe4040c2 anon_struct_132_2_fe4040c2, *Panon_struct_132_2_fe4040c2;

struct anon_struct_132_2_fe4040c2 {
    struct EC_CURVE_DATA h;
    uchar data[116];
};

typedef struct doall_sorted doall_sorted, *Pdoall_sorted;

struct doall_sorted {
    int type;
    int n;
    OBJ_NAME **names;
};

typedef struct doall doall, *Pdoall;

struct doall {
    int type;
    void (*fn)(OBJ_NAME *, void *);
    void *arg;
};

typedef struct stack_st_NAME_FUNCS stack_st_NAME_FUNCS, *Pstack_st_NAME_FUNCS;

struct stack_st_NAME_FUNCS {
    _STACK stack;
};

typedef struct lhash_st_OBJ_NAME lhash_st_OBJ_NAME, *Plhash_st_OBJ_NAME;

struct lhash_st_OBJ_NAME {
    int dummy;
};

typedef struct name_funcs_st name_funcs_st, *Pname_funcs_st;

struct name_funcs_st {
    ulong (*hash_func)(char *);
    int (*cmp_func)(char *, char *);
    void (*free_func)(char *, int, char *);
};

typedef struct name_funcs_st NAME_FUNCS;

typedef struct SCT_st SCT_st, *PSCT_st;

typedef struct SCT_st SCT;

struct SCT_st {
    uchar *sct;
    ushort sctlen;
    uchar version;
    uchar *logid;
    ushort logidlen;
    ulonglong timestamp;
    uchar *ext;
    ushort extlen;
    uchar hash_alg;
    uchar sig_alg;
    uchar *sig;
    ushort siglen;
};

typedef struct stack_st_SCT stack_st_SCT, *Pstack_st_SCT;

struct stack_st_SCT {
    _STACK stack;
};

typedef struct _xmlXPathContext xmlXPathContext.conflict;


// WARNING! conflicting data type names: /DWARF/netdb.h/addrinfo - /netdb.h/addrinfo


// WARNING! conflicting data type names: /DWARF/setjmp.h/__jmp_buf - /setjmp.h/__jmp_buf

typedef struct __jmp_buf_tag __jmp_buf_tag, *P__jmp_buf_tag;

struct __jmp_buf_tag {
    __jmp_buf __jmpbuf;
    int __mask_was_saved;
    struct __sigset_t __saved_mask;
    undefined field3_0x184;
    undefined field4_0x185;
    undefined field5_0x186;
    undefined field6_0x187;
};

typedef struct __jmp_buf_tag sigjmp_buf[1];

typedef enum processor_type {
    arm2=0,
    arm250=1,
    arm3=2,
    arm6=3,
    arm60=4,
    arm600=5,
    arm610=6,
    arm620=7,
    arm7=8,
    arm7d=9,
    arm7di=10,
    arm70=11,
    arm700=12,
    arm700i=13,
    arm710=14,
    arm720=15,
    arm710c=16,
    arm7100=17,
    arm7500=18,
    arm7500fe=19,
    arm7m=20,
    arm7dm=21,
    arm7dmi=22,
    arm8=23,
    arm810=24,
    strongarm=25,
    strongarm110=26,
    strongarm1100=27,
    strongarm1110=28,
    fa526=29,
    fa626=30,
    arm7tdmi=31,
    arm7tdmis=32,
    arm710t=33,
    arm720t=34,
    arm740t=35,
    arm9=36,
    arm9tdmi=37,
    arm920=38,
    arm920t=39,
    arm922t=40,
    arm940t=41,
    ep9312=42,
    arm10tdmi=43,
    arm1020t=44,
    arm9e=45,
    arm946es=46,
    arm966es=47,
    arm968es=48,
    arm10e=49,
    arm1020e=50,
    arm1022e=51,
    xscale=52,
    iwmmxt=53,
    iwmmxt2=54,
    fa606te=55,
    fa626te=56,
    fmp626=57,
    fa726te=58,
    arm926ejs=59,
    arm1026ejs=60,
    arm1136js=61,
    arm1136jfs=62,
    arm1176jzs=63,
    arm1176jzfs=64,
    mpcorenovfp=65,
    mpcore=66,
    arm1156t2s=67,
    arm1156t2fs=68,
    cortexm1=69,
    cortexm0=70,
    cortexm0plus=71,
    cortexm1smallmultiply=72,
    cortexm0smallmultiply=73,
    cortexm0plussmallmultiply=74,
    genericv7a=75,
    cortexa5=76,
    cortexa7=77,
    cortexa8=78,
    cortexa9=79,
    cortexa12=80,
    cortexa15=81,
    cortexa17=82,
    cortexr4=83,
    cortexr4f=84,
    cortexr5=85,
    cortexr7=86,
    cortexr8=87,
    cortexm7=88,
    cortexm4=89,
    cortexm3=90,
    marvell_pj4=91,
    cortexa15cortexa7=92,
    cortexa17cortexa7=93,
    cortexa32=94,
    cortexa35=95,
    cortexa53=96,
    cortexa57=97,
    cortexa72=98,
    exynosm1=99,
    qdf24xx=100,
    xgene1=101,
    cortexa57cortexa53=102,
    cortexa72cortexa53=103,
    arm_none=104
} processor_type;

typedef struct ifmap ifmap, *Pifmap;

struct ifmap {
    ulong mem_start;
    ulong mem_end;
    ushort base_addr;
    uchar irq;
    uchar dma;
    uchar port;
};

typedef struct ifreq ifreq, *Pifreq;

typedef union anon_union_16_1_990b9991_for_ifr_ifrn anon_union_16_1_990b9991_for_ifr_ifrn, *Panon_union_16_1_990b9991_for_ifr_ifrn;

typedef union anon_union_16_12_14072ea3_for_ifr_ifru anon_union_16_12_14072ea3_for_ifr_ifru, *Panon_union_16_12_14072ea3_for_ifr_ifru;

union anon_union_16_12_14072ea3_for_ifr_ifru {
    struct sockaddr ifru_addr;
    struct sockaddr ifru_dstaddr;
    struct sockaddr ifru_broadaddr;
    struct sockaddr ifru_netmask;
    struct sockaddr ifru_hwaddr;
    short ifru_flags;
    int ifru_ivalue;
    int ifru_mtu;
    struct ifmap ifru_map;
    char ifru_slave[16];
    char ifru_newname[16];
    __caddr_t ifru_data;
};

union anon_union_16_1_990b9991_for_ifr_ifrn {
    char ifrn_name[16];
};

struct ifreq {
    union anon_union_16_1_990b9991_for_ifr_ifrn ifr_ifrn;
    union anon_union_16_12_14072ea3_for_ifr_ifru ifr_ifru;
};

typedef struct ocsp_basic_response_st ocsp_basic_response_st, *Pocsp_basic_response_st;

typedef struct ocsp_basic_response_st OCSP_BASICRESP;

typedef struct ocsp_response_data_st ocsp_response_data_st, *Pocsp_response_data_st;

typedef struct ocsp_response_data_st OCSP_RESPDATA;

typedef struct stack_st_OCSP_SINGLERESP stack_st_OCSP_SINGLERESP, *Pstack_st_OCSP_SINGLERESP;

struct ocsp_response_data_st {
    ASN1_INTEGER *version;
    OCSP_RESPID *responderId;
    ASN1_GENERALIZEDTIME *producedAt;
    struct stack_st_OCSP_SINGLERESP *responses;
    struct stack_st_X509_EXTENSION *responseExtensions;
};

struct ocsp_basic_response_st {
    OCSP_RESPDATA *tbsResponseData;
    X509_ALGOR *signatureAlgorithm;
    ASN1_BIT_STRING *signature;
    struct stack_st_X509 *certs;
};

struct stack_st_OCSP_SINGLERESP {
    _STACK stack;
};

typedef struct ocsp_service_locator_st ocsp_service_locator_st, *Pocsp_service_locator_st;

typedef struct ocsp_service_locator_st OCSP_SERVICELOC;

struct ocsp_service_locator_st {
    X509_NAME *issuer;
    struct stack_st_ACCESS_DESCRIPTION *locator;
};

typedef struct stack_st_OCSP_ONEREQ stack_st_OCSP_ONEREQ, *Pstack_st_OCSP_ONEREQ;

struct stack_st_OCSP_ONEREQ {
    _STACK stack;
};

typedef struct ocsp_signature_st ocsp_signature_st, *Pocsp_signature_st;

typedef struct ocsp_signature_st OCSP_SIGNATURE;

struct ocsp_signature_st {
    X509_ALGOR *signatureAlgorithm;
    ASN1_BIT_STRING *signature;
    struct stack_st_X509 *certs;
};

typedef struct ocsp_one_request_st ocsp_one_request_st, *Pocsp_one_request_st;

typedef struct ocsp_one_request_st OCSP_ONEREQ;

typedef struct ocsp_cert_id_st ocsp_cert_id_st, *Pocsp_cert_id_st;

typedef struct ocsp_cert_id_st OCSP_CERTID;

struct ocsp_cert_id_st {
    X509_ALGOR *hashAlgorithm;
    ASN1_OCTET_STRING *issuerNameHash;
    ASN1_OCTET_STRING *issuerKeyHash;
    ASN1_INTEGER *serialNumber;
};

struct ocsp_one_request_st {
    OCSP_CERTID *reqCert;
    struct stack_st_X509_EXTENSION *singleRequestExtensions;
};

typedef struct ocsp_revoked_info_st ocsp_revoked_info_st, *Pocsp_revoked_info_st;

typedef struct ocsp_revoked_info_st OCSP_REVOKEDINFO;

struct ocsp_revoked_info_st {
    ASN1_GENERALIZEDTIME *revocationTime;
    ASN1_ENUMERATED *revocationReason;
};

typedef struct ocsp_req_info_st ocsp_req_info_st, *Pocsp_req_info_st;

typedef struct ocsp_req_info_st OCSP_REQINFO;

struct ocsp_req_info_st {
    ASN1_INTEGER *version;
    GENERAL_NAME *requestorName;
    struct stack_st_OCSP_ONEREQ *requestList;
    struct stack_st_X509_EXTENSION *requestExtensions;
};

typedef struct ocsp_single_response_st ocsp_single_response_st, *Pocsp_single_response_st;

typedef struct ocsp_cert_status_st ocsp_cert_status_st, *Pocsp_cert_status_st;

typedef struct ocsp_cert_status_st OCSP_CERTSTATUS;

typedef union anon_union_4_3_a2494087_for_value anon_union_4_3_a2494087_for_value, *Panon_union_4_3_a2494087_for_value;

union anon_union_4_3_a2494087_for_value {
    ASN1_NULL *good;
    OCSP_REVOKEDINFO *revoked;
    ASN1_NULL *unknown;
};

struct ocsp_single_response_st {
    OCSP_CERTID *certId;
    OCSP_CERTSTATUS *certStatus;
    ASN1_GENERALIZEDTIME *thisUpdate;
    ASN1_GENERALIZEDTIME *nextUpdate;
    struct stack_st_X509_EXTENSION *singleExtensions;
};

struct ocsp_cert_status_st {
    int type;
    union anon_union_4_3_a2494087_for_value value;
};

typedef struct ocsp_request_st ocsp_request_st, *Pocsp_request_st;

typedef struct ocsp_request_st OCSP_REQUEST;

struct ocsp_request_st {
    OCSP_REQINFO *tbsRequest;
    OCSP_SIGNATURE *optionalSignature;
};

typedef struct ocsp_single_response_st OCSP_SINGLERESP;

typedef struct ocsp_crl_id_st ocsp_crl_id_st, *Pocsp_crl_id_st;

typedef struct ocsp_crl_id_st OCSP_CRLID;

struct ocsp_crl_id_st {
    ASN1_IA5STRING *crlUrl;
    ASN1_INTEGER *crlNum;
    ASN1_GENERALIZEDTIME *crlTime;
};


// WARNING! conflicting data type names: /stdarg.h/__gnuc_va_list - /DWARF/stdarg.h/__gnuc_va_list


// WARNING! conflicting data type names: /time.h/time_t - /DWARF/time.h/time_t

typedef __clockid_t clockid_t;


// WARNING! conflicting data type names: /time.h/timeval - /DWARF/time.h/timeval

typedef struct timezone *__timezone_ptr_t;


// WARNING! conflicting data type names: /sigaction.h/sigaction - /DWARF/sigaction.h/sigaction

typedef union _union_1051 _union_1051, *P_union_1051;


// WARNING! conflicting data type names: /signal.h/__sighandler_t - /DWARF/signal.h/__sighandler_t

union _union_1051 {
    __sighandler_t sa_handler;
    void (*sa_sigaction)(int, siginfo_t *, void *);
};


// WARNING! conflicting data type names: /in.h/in_addr - /DWARF/in.h/in_addr


// WARNING! conflicting data type names: /in.h/in_addr_t - /DWARF/in.h/in_addr_t


// WARNING! conflicting data type names: /pthread.h/__jmp_buf_tag - /DWARF/setjmp.h/__jmp_buf_tag


// WARNING! conflicting data type names: /select.h/__fd_mask - /DWARF/__fd_mask


// WARNING! conflicting data type names: /select.h/fd_set - /DWARF/select.h/fd_set

typedef int (*__compar_fn_t)(void *, void *);

typedef struct Elf32_Shdr Elf32_Shdr, *PElf32_Shdr;

typedef enum Elf_SectionHeaderType_ARM {
    SHT_NULL=0,
    SHT_PROGBITS=1,
    SHT_SYMTAB=2,
    SHT_STRTAB=3,
    SHT_RELA=4,
    SHT_HASH=5,
    SHT_DYNAMIC=6,
    SHT_NOTE=7,
    SHT_NOBITS=8,
    SHT_REL=9,
    SHT_SHLIB=10,
    SHT_DYNSYM=11,
    SHT_INIT_ARRAY=14,
    SHT_FINI_ARRAY=15,
    SHT_PREINIT_ARRAY=16,
    SHT_GROUP=17,
    SHT_SYMTAB_SHNDX=18,
    SHT_ANDROID_REL=1610612737,
    SHT_ANDROID_RELA=1610612738,
    SHT_GNU_ATTRIBUTES=1879048181,
    SHT_GNU_HASH=1879048182,
    SHT_GNU_LIBLIST=1879048183,
    SHT_CHECKSUM=1879048184,
    SHT_SUNW_move=1879048186,
    SHT_SUNW_COMDAT=1879048187,
    SHT_SUNW_syminfo=1879048188,
    SHT_GNU_verdef=1879048189,
    SHT_GNU_verneed=1879048190,
    SHT_GNU_versym=1879048191,
    SHT_ARM_EXIDX=1879048193,
    SHT_ARM_PREEMPTMAP=1879048194,
    SHT_ARM_ATTRIBUTES=1879048195,
    SHT_ARM_DEBUGOVERLAY=1879048196,
    SHT_ARM_OVERLAYSECTION=1879048197
} Elf_SectionHeaderType_ARM;

struct Elf32_Shdr {
    dword sh_name;
    enum Elf_SectionHeaderType_ARM sh_type;
    dword sh_flags;
    dword sh_addr;
    dword sh_offset;
    dword sh_size;
    dword sh_link;
    dword sh_info;
    dword sh_addralign;
    dword sh_entsize;
};

typedef struct Elf32_Sym Elf32_Sym, *PElf32_Sym;

struct Elf32_Sym {
    dword st_name;
    dword st_value;
    dword st_size;
    byte st_info;
    byte st_other;
    word st_shndx;
};

typedef struct Elf32_Phdr Elf32_Phdr, *PElf32_Phdr;

typedef enum Elf_ProgramHeaderType_ARM {
    PT_NULL=0,
    PT_LOAD=1,
    PT_DYNAMIC=2,
    PT_INTERP=3,
    PT_NOTE=4,
    PT_SHLIB=5,
    PT_PHDR=6,
    PT_TLS=7,
    PT_GNU_EH_FRAME=1685382480,
    PT_GNU_STACK=1685382481,
    PT_GNU_RELRO=1685382482,
    PT_ARM_EXIDX=1879048192
} Elf_ProgramHeaderType_ARM;

struct Elf32_Phdr {
    enum Elf_ProgramHeaderType_ARM p_type;
    dword p_offset;
    dword p_vaddr;
    dword p_paddr;
    dword p_filesz;
    dword p_memsz;
    dword p_flags;
    dword p_align;
};

typedef struct Elf32_Rel Elf32_Rel, *PElf32_Rel;

struct Elf32_Rel {
    dword r_offset; // location to apply the relocation action
    dword r_info; // the symbol table index and the type of relocation
};

typedef struct NoteAbiTag NoteAbiTag, *PNoteAbiTag;

struct NoteAbiTag {
    dword namesz; // Length of name field
    dword descsz; // Length of description field
    dword type; // Vendor specific type
    char name[4]; // Vendor name
    dword abiType; // 0 == Linux
    dword requiredKernelVersion[3]; // Major.minor.patch
};

typedef enum Elf32_DynTag_ARM {
    DT_NULL=0,
    DT_NEEDED=1,
    DT_PLTRELSZ=2,
    DT_PLTGOT=3,
    DT_HASH=4,
    DT_STRTAB=5,
    DT_SYMTAB=6,
    DT_RELA=7,
    DT_RELASZ=8,
    DT_RELAENT=9,
    DT_STRSZ=10,
    DT_SYMENT=11,
    DT_INIT=12,
    DT_FINI=13,
    DT_SONAME=14,
    DT_RPATH=15,
    DT_SYMBOLIC=16,
    DT_REL=17,
    DT_RELSZ=18,
    DT_RELENT=19,
    DT_PLTREL=20,
    DT_DEBUG=21,
    DT_TEXTREL=22,
    DT_JMPREL=23,
    DT_BIND_NOW=24,
    DT_INIT_ARRAY=25,
    DT_FINI_ARRAY=26,
    DT_INIT_ARRAYSZ=27,
    DT_FINI_ARRAYSZ=28,
    DT_RUNPATH=29,
    DT_FLAGS=30,
    DT_PREINIT_ARRAY=32,
    DT_PREINIT_ARRAYSZ=33,
    DT_RELRSZ=35,
    DT_RELR=36,
    DT_RELRENT=37,
    DT_ANDROID_REL=1610612751,
    DT_ANDROID_RELSZ=1610612752,
    DT_ANDROID_RELA=1610612753,
    DT_ANDROID_RELASZ=1610612754,
    DT_ANDROID_RELR=1879040000,
    DT_ANDROID_RELRSZ=1879040001,
    DT_ANDROID_RELRENT=1879040003,
    DT_GNU_PRELINKED=1879047669,
    DT_GNU_CONFLICTSZ=1879047670,
    DT_GNU_LIBLISTSZ=1879047671,
    DT_CHECKSUM=1879047672,
    DT_PLTPADSZ=1879047673,
    DT_MOVEENT=1879047674,
    DT_MOVESZ=1879047675,
    DT_FEATURE_1=1879047676,
    DT_POSFLAG_1=1879047677,
    DT_SYMINSZ=1879047678,
    DT_SYMINENT=1879047679,
    DT_GNU_XHASH=1879047924,
    DT_GNU_HASH=1879047925,
    DT_TLSDESC_PLT=1879047926,
    DT_TLSDESC_GOT=1879047927,
    DT_GNU_CONFLICT=1879047928,
    DT_GNU_LIBLIST=1879047929,
    DT_CONFIG=1879047930,
    DT_DEPAUDIT=1879047931,
    DT_AUDIT=1879047932,
    DT_PLTPAD=1879047933,
    DT_MOVETAB=1879047934,
    DT_SYMINFO=1879047935,
    DT_VERSYM=1879048176,
    DT_RELACOUNT=1879048185,
    DT_RELCOUNT=1879048186,
    DT_FLAGS_1=1879048187,
    DT_VERDEF=1879048188,
    DT_VERDEFNUM=1879048189,
    DT_VERNEED=1879048190,
    DT_VERNEEDNUM=1879048191,
    DT_AUXILIARY=2147483645,
    DT_FILTER=2147483647
} Elf32_DynTag_ARM;

typedef struct Elf32_Dyn_ARM Elf32_Dyn_ARM, *PElf32_Dyn_ARM;

struct Elf32_Dyn_ARM {
    enum Elf32_DynTag_ARM d_tag;
    dword d_val;
};

typedef struct GnuBuildId GnuBuildId, *PGnuBuildId;

struct GnuBuildId {
    dword namesz; // Length of name field
    dword descsz; // Length of description field
    dword type; // Vendor specific type
    char name[4]; // Vendor name
    byte hash[20];
};

typedef struct Elf32_Ehdr Elf32_Ehdr, *PElf32_Ehdr;

struct Elf32_Ehdr {
    byte e_ident_magic_num;
    char e_ident_magic_str[3];
    byte e_ident_class;
    byte e_ident_data;
    byte e_ident_version;
    byte e_ident_osabi;
    byte e_ident_abiversion;
    byte e_ident_pad[7];
    word e_type;
    word e_machine;
    dword e_version;
    dword e_entry;
    dword e_phoff;
    dword e_shoff;
    dword e_flags;
    word e_ehsize;
    word e_phentsize;
    word e_phnum;
    word e_shentsize;
    word e_shnum;
    word e_shstrndx;
};


// WARNING! conflicting data type names: /stdint.h/uint32_t - /DWARF/uint32_t


// WARNING! conflicting data type names: /stdint.h/uint16_t - /DWARF/uint16_t




void _init(void);
int open(char *__file,int __oflag,...);
void qsort(void *__base,size_t __nmemb,size_t __size,__compar_fn_t __compar);
char * strerror(int __errnum);
int fileno(FILE *__stream);
void __sigsetjmp(void);
void xmlGetProp(void);
void abort(void);
int connect(int __fd,sockaddr *__addr,socklen_t __len);
int vprintf(char *__format,__gnuc_va_list __arg);
tm * localtime(time_t *__timer);
int memcmp(void *__s1,void *__s2,size_t __n);
void getauxval(void);
void xmlStrcmp(void);
int clock_gettime(clockid_t __clock_id,timespec *__tp);
void __libc_start_main(void);
void compress(void);
char * inet_ntoa(in_addr __in);
__sighandler_t signal(int __sig,__sighandler_t __handler);
void xmlParseFile(void);
void __isoc99_sscanf(void);
int vsnprintf(char *__s,size_t __maxlen,char *__format,__gnuc_va_list __arg);
in_addr_t inet_addr(char *__cp);
double pow(double __x,double __y);
char * strncpy(char *__dest,char *__src,size_t __n);
int fclose(FILE *__stream);
char * fgets(char *__s,int __n,FILE *__stream);
ssize_t recv(int __fd,void *__buf,size_t __n,int __flags);
char * getenv(char *__name);
int system(char *__command);
char * strchr(char *__s,int __c);
int putchar(int __c);
int strcasecmp(char *__s1,char *__s2);
int listen(int __fd,int __n);
void * calloc(size_t __nmemb,size_t __size);
ssize_t sendto(int __fd,void *__buf,size_t __n,int __flags,sockaddr *__addr,socklen_t __addr_len);
void dlclose(void);
uint16_t htons(uint16_t __hostshort);
FILE * fopen(char *__filename,char *__modes);
void * memset(void *__s,int __c,size_t __n);
char * gai_strerror(int __ecode);
void freeaddrinfo(addrinfo *__ai);
char * strrchr(char *__s,int __c);
void xmlFreeDoc(void);
void xmlReadFile(void);
void perror(char *__s);
void __assert_fail(char *__assertion,char *__file,uint __line,char *__function);
void dlopen(void);
int usleep(__useconds_t __useconds);
void siglongjmp(__jmp_buf_tag *__env,int __val);
__uid_t getuid(void);
void free(void *__ptr);
ssize_t read(int __fd,void *__buf,size_t __nbytes);
ssize_t write(int __fd,void *__buf,size_t __n);
int access(char *__name,int __type);
void openlog(char *__ident,int __option,int __facility);
int gettimeofday(timeval *__tv,__timezone_ptr_t __tz);
int fseek(FILE *__stream,long __off,int __whence);
int accept(int __fd,sockaddr *__addr,socklen_t *__addr_len);
longlong atoll(char *__nptr);
int pthread_mutex_unlock(pthread_mutex_t *__mutex);
int socket(int __domain,int __type,int __protocol);
int getaddrinfo(char *__name,char *__service,addrinfo *__req,addrinfo **__pai);
int fflush(FILE *__stream);
int ioctl(int __fd,ulong __request,...);
uint16_t ntohs(uint16_t __netshort);
int pthread_mutex_lock(pthread_mutex_t *__mutex);
size_t strlen(char *__s);
ulong strtoul(char *__nptr,char **__endptr,int __base);
int pthread_create(pthread_t *__newthread,pthread_attr_t *__attr,__start_routine *__start_routine,void *__arg);
void * memcpy(void *__dest,void *__src,size_t __n);
FILE * fopen64(char *__filename,char *__modes);
void xmlXPathNewContext(void);
__int32_t ** __ctype_tolower_loc(void);
int feof(FILE *__stream);
long ftell(FILE *__stream);
long strtol(char *__nptr,char **__endptr,int __base);
void xmlXPathFreeObject(void);
char * strcpy(char *__dest,char *__src);
int printf(char *__format,...);
int raise(int __sig);
int atoi(char *__nptr);
int pthread_mutex_init(pthread_mutex_t *__mutex,pthread_mutexattr_t *__mutexattr);
void xmlMemoryDump(void);
int shutdown(int __fd,int __how);
int bind(int __fd,sockaddr *__addr,socklen_t __len);
char * strstr(char *__haystack,char *__needle);
int select(int __nfds,fd_set *__readfds,fd_set *__writefds,fd_set *__exceptfds,timeval *__timeout);
int close(int __fd);
size_t fwrite(void *__ptr,size_t __size,size_t __n,FILE *__s);
void xmlXPathFreeContext(void);
int strncasecmp(char *__s1,char *__s2,size_t __n);
time_t time(time_t *__timer);
ushort ** __ctype_b_loc(void);
int fprintf(FILE *__stream,char *__format,...);
void * malloc(size_t __size);
int sigprocmask(int __how,sigset_t *__set,sigset_t *__oset);
int gethostname(char *__name,size_t __len);
int sigaction(int __sig,sigaction *__act,sigaction *__oact);
int sigdelset(sigset_t *__set,int __signo);
tm * gmtime_r(time_t *__timer,tm *__tp);
int poll(pollfd *__fds,nfds_t __nfds,int __timeout);
void dlerror(void);
int fputc(int __c,FILE *__stream);
void xmlCleanupParser(void);
void xmlXPathEvalExpression(void);
ssize_t send(int __fd,void *__buf,size_t __n,int __flags);
char * strcat(char *__dest,char *__src);
void * memmove(void *__dest,void *__src,size_t __n);
int sigfillset(sigset_t *__set);
int puts(char *__s);
size_t strftime(char *__s,size_t __maxsize,char *__format,tm *__tp);
__pid_t getpid(void);
void closelog(void);
int fcntl(int __fd,int __cmd,...);
void bzero(void *__s,size_t __n);
uint32_t htonl(uint32_t __hostlong);
void xmlDocGetRootElement(void);
int __fxstat(int __ver,int __fildes,stat *__stat_buf);
int vfprintf(FILE *__s,char *__format,__gnuc_va_list __arg);
int snprintf(char *__s,size_t __maxlen,char *__format,...);
size_t fread(void *__ptr,size_t __size,size_t __n,FILE *__stream);
void xmlKeepBlanksDefault(void);
int strncmp(char *__s1,char *__s2,size_t __n);
int ferror(FILE *__stream);
int getpeername(int __fd,sockaddr *__addr,socklen_t *__len);
int pthread_detach(pthread_t __th);
void * realloc(void *__ptr,size_t __size);
ssize_t recvfrom(int __fd,void *__buf,size_t __n,int __flags,sockaddr *__addr,socklen_t *__addr_len);
int setsockopt(int __fd,int __level,int __optname,void *__optval,socklen_t __optlen);
void * memchr(void *__s,int __c,size_t __n);
void uncompress(void);
void dladdr(void);
int strcmp(char *__s1,char *__s2);
void exit(int __status);
int pthread_setcanceltype(int __type,int *__oldtype);
int * __errno_location(void);
pthread_t pthread_self(void);
void dlsym(void);
int sprintf(char *__s,char *__format,...);
void vsyslog(int __pri,char *__fmt,__gnuc_va_list __ap);
int fputs(char *__s,FILE *__stream);
void OPENSSL_cpuid_setup(void);
void processEntry _start(undefined4 param_1,undefined4 param_2);
void call_weak_fn(void);
void deregister_tm_clones(void);
void register_tm_clones(void);
void __do_global_dtors_aux(void);
void frame_dummy(void);
UA_String * UA_STRING(UA_String *__return_storage_ptr__,char *chars);
UA_NodeId *UA_NODEID_NUMERIC(UA_NodeId *__return_storage_ptr__,UA_UInt16 nsIndex,UA_UInt32 identifier);
UA_QualifiedName *UA_QUALIFIEDNAME(UA_QualifiedName *__return_storage_ptr__,UA_UInt16 nsIndex,char *chars);
UA_LocalizedText *UA_LOCALIZEDTEXT(UA_LocalizedText *__return_storage_ptr__,char *locale,char *text);
UA_LocalizedText *UA_LOCALIZEDTEXT_ALLOC(UA_LocalizedText *__return_storage_ptr__,char *locale,char *text);
void UA_String_deleteMembers(UA_String *p);
void UA_ByteString_deleteMembers(UA_ByteString *p);
void UA_LocalizedText_deleteMembers(UA_LocalizedText *p);
void UA_VariableAttributes_init(UA_VariableAttributes *p);
void UA_ObjectAttributes_init(UA_ObjectAttributes *p);
UA_StatusCode UA_Server_writeDisplayName(UA_Server *server,UA_NodeId nodeId,UA_LocalizedText displayName);
UA_StatusCode UA_Server_addObjectNode(UA_Server *server,UA_NodeId requestedNewNodeId,UA_NodeId parentNodeId,UA_NodeId referenceTypeId,UA_QualifiedName browseName,UA_NodeId typeDefinition,UA_ObjectAttributes attr,UA_InstantiationCallback *instantiationCallback,UA_NodeId *outNewNodeId);
UA_ByteString * loadCertificate(UA_ByteString *__return_storage_ptr__);
void stopHandler(int sign);
UA_StatusCode readTimeData(void *handle,UA_NodeId nodeId,UA_Boolean sourceTimeStamp,UA_NumericRange *range,UA_DataValue *value,int index);
UA_StatusCode helloWorld(void *methodHandle,UA_NodeId objectId,size_t inputSize,UA_Variant *input,size_t outputSize,UA_Variant *output);
UA_StatusCode noargMethod(void *methodHandle,UA_NodeId objectId,size_t inputSize,UA_Variant *input,size_t outputSize,UA_Variant *output);
UA_StatusCode outargMethod(void *methodHandle,UA_NodeId objectId,size_t inputSize,UA_Variant *input,size_t outputSize,UA_Variant *output);
int main(int argc,char **argv);
void CreateCRC32Table(void);
uint GetCRC32B(uint CRCCode,char *pData,uint Length);
uint GetCRC32(char *pData,uint Length);
int DestroyTimer(void);
void AddDnCounter(long *plCounter);
void DeleteDnCounter(long *plCounter);
void AddUpCounter(long *plCounter);
void DeleteUpCounter(long *plCounter);
void RunTimer(void);
void background(void);
void * Timer_Run(void *data);
int InitTimer(void);
uint16_t Data2Str(uint8_t *pData,char *buf,uint16_t u16DataLen);
uint16_t Str2Data(char *buf,uint8_t *pData,uint16_t u16BufLen);
_Bool logInit(char *domain);
_Bool logClose(void);
void logSetFlags(DWORD logflags);
DWORD logGetFlags(void);
DWORD logRemoveFlags(DWORD mask);
DWORD logAddFlags(DWORD mask);
char * currentTimeString(void);
void logMsg(char *format,va_list args,_Bool isError);
void logError(char *format,...);
void logInfo(char *format,...);
void logDebug(char *format,...);
void logTrace(char *format,...);
void logWarn(char *format,...);
ulong parseBlackList(char *fileName);
xmlXPathObjectPtr getNodeset(xmlDocPtr pdoc,xmlChar *xpath);
int parseMoldData_54_52_xml(char *file_name);
char * MD5_check(void);
int base64_decode(char *in_str,int in_len,char *out_str);
size_t b64_encoded_size(size_t inlen);
char * b64_encode(uchar *in,size_t len);
RSA * ReadPrivateKey(char *p_KeyPath);
Signmes * test_RSA_sign(Signmes *__return_storage_ptr__,char *data,int ptf_en_length);
char * my_decrypt(char *msg_buff,char *path_key,int oldmessage_len);
RSA * ReadCraftPublicKeyFromFile(char *p_KeyPath);
RSA * ReadCraftPrivateKeyFromFile(char *p_KeyPath,char *Pass);
char * RSA_EncryptFromFile(char *str,char *key_path,int *en_len);
char * RSA_DecryptFromFile(char *str,char *key_path,char *Pass,int *de_len);
int AES_ECB_EncryptFromStr(uchar *aes_key,uchar *aes_iv,char *in_str,int in_len,uchar *out_str);
int AES_ECB_DecryptFromStr(uchar *aes_key,uchar *aes_iv,char *in_str,int in_len,uchar *out_str);
RSA * ReadCraftPublicKeyFromStr(char *p_KeyStr);
RSA * ReadCraftPrivateKeyFromStr(char *p_KeyStr,char *Pass);
char * RSA_EncryptFromStr(char *str,char *key_str,int *en_len);
char * RSA_DecryptFromStr(char *str,char *key_str,char *Pass,int *de_len);
int B64_Encode(char *in_str,int in_len,char *out_str);
int B64_Decode(char *in_str,int in_len,char *out_str);
char * ZlibCompress(char *src,int srcLen,int *comprLen);
char * ZlibUnCompress(char *compr,int comprLen,int *uncomprLen);
UA_String * UA_STRING(UA_String *__return_storage_ptr__,char *chars);
UA_Boolean UA_ByteString_equal(UA_ByteString *string1,UA_ByteString *string2);
UA_NodeId *UA_NODEID_NUMERIC(UA_NodeId *__return_storage_ptr__,UA_UInt16 nsIndex,UA_UInt32 identifier);
UA_NodeId * UA_NODEID_GUID(UA_NodeId *__return_storage_ptr__,UA_UInt16 nsIndex,UA_Guid guid);
UA_ExpandedNodeId *UA_EXPANDEDNODEID_NUMERIC(UA_ExpandedNodeId *__return_storage_ptr__,UA_UInt16 nsIndex,UA_UInt32 identifier);
UA_Boolean UA_QualifiedName_isNull(UA_QualifiedName *q);
UA_QualifiedName *UA_QUALIFIEDNAME(UA_QualifiedName *__return_storage_ptr__,UA_UInt16 nsIndex,char *chars);
UA_QualifiedName *UA_QUALIFIEDNAME_ALLOC(UA_QualifiedName *__return_storage_ptr__,UA_UInt16 nsIndex,char *chars);
UA_LocalizedText *UA_LOCALIZEDTEXT(UA_LocalizedText *__return_storage_ptr__,char *locale,char *text);
UA_LocalizedText *UA_LOCALIZEDTEXT_ALLOC(UA_LocalizedText *__return_storage_ptr__,char *locale,char *text);
UA_Boolean UA_Variant_isScalar(UA_Variant *v);
void UA_init(void *p,UA_DataType *type);
UA_Boolean * UA_Boolean_new(void);
UA_Byte * UA_Byte_new(void);
UA_UInt16 * UA_UInt16_new(void);
UA_Int32 * UA_Int32_new(void);
UA_UInt32 * UA_UInt32_new(void);
UA_Double * UA_Double_new(void);
void UA_String_init(UA_String *p);
UA_StatusCode UA_String_copy(UA_String *src,UA_String *dst);
void UA_String_deleteMembers(UA_String *p);
void UA_DateTime_init(UA_DateTime *p);
UA_Guid * UA_Guid_new(void);
UA_StatusCode UA_Guid_copy(UA_Guid *src,UA_Guid *dst);
void UA_ByteString_init(UA_ByteString *p);
UA_StatusCode UA_ByteString_copy(UA_ByteString *src,UA_ByteString *dst);
void UA_ByteString_deleteMembers(UA_ByteString *p);
void UA_NodeId_init(UA_NodeId *p);
UA_NodeId * UA_NodeId_new(void);
UA_StatusCode UA_NodeId_copy(UA_NodeId *src,UA_NodeId *dst);
void UA_NodeId_deleteMembers(UA_NodeId *p);
void UA_NodeId_delete(UA_NodeId *p);
void UA_ExpandedNodeId_init(UA_ExpandedNodeId *p);
UA_StatusCode UA_ExpandedNodeId_copy(UA_ExpandedNodeId *src,UA_ExpandedNodeId *dst);
UA_StatusCode UA_QualifiedName_copy(UA_QualifiedName *src,UA_QualifiedName *dst);
void UA_QualifiedName_deleteMembers(UA_QualifiedName *p);
UA_LocalizedText * UA_LocalizedText_new(void);
UA_StatusCode UA_LocalizedText_copy(UA_LocalizedText *src,UA_LocalizedText *dst);
void UA_LocalizedText_deleteMembers(UA_LocalizedText *p);
void UA_ExtensionObject_init(UA_ExtensionObject *p);
void UA_DataValue_init(UA_DataValue *p);
UA_StatusCode UA_DataValue_copy(UA_DataValue *src,UA_DataValue *dst);
void UA_DataValue_deleteMembers(UA_DataValue *p);
void UA_Variant_init(UA_Variant *p);
UA_StatusCode UA_Variant_copy(UA_Variant *src,UA_Variant *dst);
void UA_Variant_deleteMembers(UA_Variant *p);
void UA_RequestHeader_deleteMembers(UA_RequestHeader *p);
void UA_CloseSecureChannelRequest_init(UA_CloseSecureChannelRequest *p);
void UA_CloseSecureChannelRequest_deleteMembers(UA_CloseSecureChannelRequest *p);
void UA_AddNodesResult_init(UA_AddNodesResult *p);
void UA_VariableAttributes_init(UA_VariableAttributes *p);
UA_StatusCode UA_NotificationMessage_copy(UA_NotificationMessage *src,UA_NotificationMessage *dst);
void UA_NotificationMessage_deleteMembers(UA_NotificationMessage *p);
void UA_CallMethodRequest_init(UA_CallMethodRequest *p);
void UA_AnonymousIdentityToken_init(UA_AnonymousIdentityToken *p);
UA_AnonymousIdentityToken * UA_AnonymousIdentityToken_new(void);
void UA_CallRequest_init(UA_CallRequest *p);
void UA_MethodAttributes_init(UA_MethodAttributes *p);
void UA_DeleteReferencesItem_init(UA_DeleteReferencesItem *p);
void UA_DeleteReferencesItem_deleteMembers(UA_DeleteReferencesItem *p);
void UA_WriteValue_init(UA_WriteValue *p);
void UA_ReferenceNode_init(UA_ReferenceNode *p);
void UA_ReferenceNode_deleteMembers(UA_ReferenceNode *p);
void UA_Argument_init(UA_Argument *p);
UA_StatusCode UA_BuildInfo_copy(UA_BuildInfo *src,UA_BuildInfo *dst);
UA_StatusCode UA_NodeClass_copy(UA_NodeClass *src,UA_NodeClass *dst);
void UA_ChannelSecurityToken_init(UA_ChannelSecurityToken *p);
UA_StatusCode UA_ChannelSecurityToken_copy(UA_ChannelSecurityToken *src,UA_ChannelSecurityToken *dst);
void UA_ChannelSecurityToken_deleteMembers(UA_ChannelSecurityToken *p);
void UA_DeleteNodesItem_init(UA_DeleteNodesItem *p);
void UA_ReadValueId_init(UA_ReadValueId *p);
void UA_ResponseHeader_deleteMembers(UA_ResponseHeader *p);
void UA_DeleteSubscriptionsRequest_init(UA_DeleteSubscriptionsRequest *p);
void UA_DeleteMonitoredItemsResponse_deleteMembers(UA_DeleteMonitoredItemsResponse *p);
void UA_DeleteNodesRequest_init(UA_DeleteNodesRequest *p);
void UA_PublishResponse_init(UA_PublishResponse *p);
void UA_PublishResponse_deleteMembers(UA_PublishResponse *p);
void UA_UserNameIdentityToken_init(UA_UserNameIdentityToken *p);
UA_UserNameIdentityToken * UA_UserNameIdentityToken_new(void);
void UA_ActivateSessionRequest_init(UA_ActivateSessionRequest *p);
void UA_ActivateSessionRequest_deleteMembers(UA_ActivateSessionRequest *p);
void UA_OpenSecureChannelResponse_init(UA_OpenSecureChannelResponse *p);
void UA_OpenSecureChannelResponse_deleteMembers(UA_OpenSecureChannelResponse *p);
UA_ServerState * UA_ServerState_new(void);
void UA_ActivateSessionResponse_deleteMembers(UA_ActivateSessionResponse *p);
void UA_WriteResponse_deleteMembers(UA_WriteResponse *p);
void UA_CreateSubscriptionRequest_init(UA_CreateSubscriptionRequest *p);
void UA_OpenSecureChannelRequest_init(UA_OpenSecureChannelRequest *p);
void UA_OpenSecureChannelRequest_deleteMembers(UA_OpenSecureChannelRequest *p);
void UA_CloseSessionRequest_init(UA_CloseSessionRequest *p);
void UA_CloseSessionRequest_deleteMembers(UA_CloseSessionRequest *p);
void UA_UserTokenPolicy_init(UA_UserTokenPolicy *p);
UA_StatusCode UA_UserTokenPolicy_copy(UA_UserTokenPolicy *src,UA_UserTokenPolicy *dst);
void UA_UserTokenPolicy_deleteMembers(UA_UserTokenPolicy *p);
void UA_DeleteMonitoredItemsRequest_init(UA_DeleteMonitoredItemsRequest *p);
void UA_WriteRequest_init(UA_WriteRequest *p);
void UA_ObjectAttributes_init(UA_ObjectAttributes *p);
void UA_BrowseDescription_init(UA_BrowseDescription *p);
UA_BrowseDescription * UA_BrowseDescription_new(void);
UA_StatusCode UA_BrowseDescription_copy(UA_BrowseDescription *src,UA_BrowseDescription *dst);
void UA_BrowseDescription_deleteMembers(UA_BrowseDescription *p);
void UA_GetEndpointsRequest_init(UA_GetEndpointsRequest *p);
void UA_PublishRequest_init(UA_PublishRequest *p);
void UA_PublishRequest_deleteMembers(UA_PublishRequest *p);
void UA_AddNodesResponse_deleteMembers(UA_AddNodesResponse *p);
UA_DataChangeNotification * UA_DataChangeNotification_new(void);
void UA_ReferenceDescription_init(UA_ReferenceDescription *p);
void UA_AddReferencesItem_init(UA_AddReferencesItem *p);
void UA_CreateSubscriptionResponse_deleteMembers(UA_CreateSubscriptionResponse *p);
void UA_DeleteSubscriptionsResponse_deleteMembers(UA_DeleteSubscriptionsResponse *p);
void UA_DeleteReferencesResponse_deleteMembers(UA_DeleteReferencesResponse *p);
void UA_CreateMonitoredItemsResponse_deleteMembers(UA_CreateMonitoredItemsResponse *p);
void UA_CallResponse_deleteMembers(UA_CallResponse *p);
void UA_DeleteNodesResponse_deleteMembers(UA_DeleteNodesResponse *p);
void UA_MonitoredItemCreateRequest_init(UA_MonitoredItemCreateRequest *p);
void UA_DeleteReferencesRequest_init(UA_DeleteReferencesRequest *p);
void UA_ReadResponse_deleteMembers(UA_ReadResponse *p);
void UA_AddReferencesRequest_init(UA_AddReferencesRequest *p);
void UA_ReadRequest_init(UA_ReadRequest *p);
void UA_AddNodesItem_init(UA_AddNodesItem *p);
UA_ServerStatusDataType * UA_ServerStatusDataType_new(void);
void UA_AddReferencesResponse_deleteMembers(UA_AddReferencesResponse *p);
void UA_CloseSessionResponse_deleteMembers(UA_CloseSessionResponse *p);
void UA_ApplicationDescription_init(UA_ApplicationDescription *p);
UA_StatusCode UA_ApplicationDescription_copy(UA_ApplicationDescription *src,UA_ApplicationDescription *dst);
void UA_ApplicationDescription_deleteMembers(UA_ApplicationDescription *p);
void UA_ApplicationDescription_delete(UA_ApplicationDescription *p);
void UA_CreateMonitoredItemsRequest_init(UA_CreateMonitoredItemsRequest *p);
void UA_AddNodesRequest_init(UA_AddNodesRequest *p);
void UA_BrowseRequest_init(UA_BrowseRequest *p);
void UA_BrowseRequest_deleteMembers(UA_BrowseRequest *p);
void UA_BrowseResult_init(UA_BrowseResult *p);
void UA_BrowseResult_deleteMembers(UA_BrowseResult *p);
void UA_CreateSessionRequest_init(UA_CreateSessionRequest *p);
void UA_CreateSessionRequest_deleteMembers(UA_CreateSessionRequest *p);
UA_StatusCode UA_EndpointDescription_copy(UA_EndpointDescription *src,UA_EndpointDescription *dst);
void UA_GetEndpointsResponse_init(UA_GetEndpointsResponse *p);
void UA_GetEndpointsResponse_deleteMembers(UA_GetEndpointsResponse *p);
void UA_BrowseResponse_deleteMembers(UA_BrowseResponse *p);
void UA_CreateSessionResponse_init(UA_CreateSessionResponse *p);
void UA_CreateSessionResponse_deleteMembers(UA_CreateSessionResponse *p);
UA_ReadResponse *UA_Client_Service_read(UA_ReadResponse *__return_storage_ptr__,UA_Client *client,UA_ReadRequest request);
UA_WriteResponse *UA_Client_Service_write(UA_WriteResponse *__return_storage_ptr__,UA_Client *client,UA_WriteRequest request);
UA_CallResponse *UA_Client_Service_call(UA_CallResponse *__return_storage_ptr__,UA_Client *client,UA_CallRequest request);
UA_AddNodesResponse *UA_Client_Service_addNodes(UA_AddNodesResponse *__return_storage_ptr__,UA_Client *client,UA_AddNodesRequest request);
UA_AddReferencesResponse *UA_Client_Service_addReferences(UA_AddReferencesResponse *__return_storage_ptr__,UA_Client *client,UA_AddReferencesRequest request);
UA_DeleteNodesResponse *UA_Client_Service_deleteNodes(UA_DeleteNodesResponse *__return_storage_ptr__,UA_Client *client,UA_DeleteNodesRequest request);
UA_DeleteReferencesResponse *UA_Client_Service_deleteReferences(UA_DeleteReferencesResponse *__return_storage_ptr__,UA_Client *client,UA_DeleteReferencesRequest request);
UA_BrowseResponse *UA_Client_Service_browse(UA_BrowseResponse *__return_storage_ptr__,UA_Client *client,UA_BrowseRequest request);
UA_CreateMonitoredItemsResponse *UA_Client_Service_createMonitoredItems(UA_CreateMonitoredItemsResponse *__return_storage_ptr__,UA_Client *client,UA_CreateMonitoredItemsRequest request);
UA_DeleteMonitoredItemsResponse *UA_Client_Service_deleteMonitoredItems(UA_DeleteMonitoredItemsResponse *__return_storage_ptr__,UA_Client *client,UA_DeleteMonitoredItemsRequest request);
UA_CreateSubscriptionResponse *UA_Client_Service_createSubscription(UA_CreateSubscriptionResponse *__return_storage_ptr__,UA_Client *client,UA_CreateSubscriptionRequest request);
UA_DeleteSubscriptionsResponse *UA_Client_Service_deleteSubscriptions(UA_DeleteSubscriptionsResponse *__return_storage_ptr__,UA_Client *client,UA_DeleteSubscriptionsRequest request);
UA_PublishResponse *UA_Client_Service_publish(UA_PublishResponse *__return_storage_ptr__,UA_Client *client,UA_PublishRequest request);
void * UA_atomic_xchg(void **addr,void *newptr);
void * UA_atomic_cmpxchg(void **addr,void *expected,void *newptr);
uint32_t UA_atomic_add(uint32_t *addr,uint32_t increase);
UA_StatusCode UA_UInt32_encodeBinary(UA_UInt32 *src,UA_ByteString *dst,size_t *offset);
UA_StatusCode UA_UInt32_decodeBinary(UA_ByteString *src,size_t *offset,UA_UInt32 *dst);
UA_StatusCode UA_String_encodeBinary(UA_String *src,UA_ByteString *dst,size_t *offset);
UA_StatusCode UA_NodeId_encodeBinary(UA_NodeId *src,UA_ByteString *dst,size_t *offset);
UA_StatusCode UA_NodeId_decodeBinary(UA_ByteString *src,size_t *offset,UA_NodeId *dst);
UA_StatusCode UA_RequestHeader_decodeBinary(UA_ByteString *src,size_t *offset,UA_RequestHeader *dst);
UA_StatusCode UA_OpenSecureChannelResponse_encodeBinary(UA_OpenSecureChannelResponse *src,UA_ByteString *dst,size_t *offset);
UA_StatusCode UA_OpenSecureChannelResponse_decodeBinary(UA_ByteString *src,size_t *offset,UA_OpenSecureChannelResponse *dst);
UA_StatusCode UA_OpenSecureChannelRequest_encodeBinary(UA_OpenSecureChannelRequest *src,UA_ByteString *dst,size_t *offset);
UA_StatusCode UA_OpenSecureChannelRequest_decodeBinary(UA_ByteString *src,size_t *offset,UA_OpenSecureChannelRequest *dst);
void UA_TcpHelloMessage_deleteMembers(UA_TcpHelloMessage *p);
void UA_AsymmetricAlgorithmSecurityHeader_init(UA_AsymmetricAlgorithmSecurityHeader *p);
void UA_AsymmetricAlgorithmSecurityHeader_deleteMembers(UA_AsymmetricAlgorithmSecurityHeader *p);
void UA_TcpAcknowledgeMessage_deleteMembers(UA_TcpAcknowledgeMessage *p);
void UA_SequenceHeader_init(UA_SequenceHeader *p);
UA_StatusCode UA_TcpHelloMessage_encodeBinary(UA_TcpHelloMessage *src,UA_ByteString *dst,size_t *offset);
UA_StatusCode UA_TcpHelloMessage_decodeBinary(UA_ByteString *src,size_t *offset,UA_TcpHelloMessage *dst);
UA_StatusCode UA_AsymmetricAlgorithmSecurityHeader_encodeBinary(UA_AsymmetricAlgorithmSecurityHeader *src,UA_ByteString *dst,size_t *offset);
UA_StatusCode UA_AsymmetricAlgorithmSecurityHeader_decodeBinary(UA_ByteString *src,size_t *offset,UA_AsymmetricAlgorithmSecurityHeader *dst);
UA_StatusCode UA_TcpAcknowledgeMessage_encodeBinary(UA_TcpAcknowledgeMessage *src,UA_ByteString *dst,size_t *offset);
UA_StatusCode UA_TcpAcknowledgeMessage_decodeBinary(UA_ByteString *src,size_t *offset,UA_TcpAcknowledgeMessage *dst);
UA_StatusCode UA_SequenceHeader_encodeBinary(UA_SequenceHeader *src,UA_ByteString *dst,size_t *offset);
UA_StatusCode UA_SequenceHeader_decodeBinary(UA_ByteString *src,size_t *offset,UA_SequenceHeader *dst);
UA_StatusCode UA_TcpMessageHeader_encodeBinary(UA_TcpMessageHeader *src,UA_ByteString *dst,size_t *offset);
UA_StatusCode UA_TcpMessageHeader_decodeBinary(UA_ByteString *src,size_t *offset,UA_TcpMessageHeader *dst);
UA_StatusCode UA_SymmetricAlgorithmSecurityHeader_encodeBinary(UA_SymmetricAlgorithmSecurityHeader *src,UA_ByteString *dst,size_t *offset);
UA_StatusCode UA_SecureConversationMessageHeader_encodeBinary(UA_SecureConversationMessageHeader *src,UA_ByteString *dst,size_t *offset);
UA_StatusCode UA_SecureConversationMessageHeader_decodeBinary(UA_ByteString *src,size_t *offset,UA_SecureConversationMessageHeader *dst);
hash_t mod(hash_t h,hash_t size);
hash_t mod2(hash_t h,hash_t size);
hash_t hash_array(UA_Byte *data,UA_UInt32 len,UA_UInt32 seed);
hash_t hash(UA_NodeId *n);
UA_DataType * UA_findDataType(UA_NodeId *typeId);
void UA_random_seed(UA_UInt64 seed);
UA_UInt32 UA_UInt32_random(void);
UA_String * UA_String_fromChars(UA_String *__return_storage_ptr__,char *src);
UA_Boolean UA_String_equal(UA_String *string1,UA_String *string2);
void String_deleteMembers(UA_String *s,UA_DataType *_);
UA_DateTimeStruct * UA_DateTime_toStruct(UA_DateTimeStruct *__return_storage_ptr__,UA_DateTime t);
void printNumber(UA_UInt16 n,UA_Byte *pos,size_t digits);
UA_String * UA_DateTime_toString(UA_String *__return_storage_ptr__,UA_DateTime t);
UA_Boolean UA_Guid_equal(UA_Guid *g1,UA_Guid *g2);
UA_Guid * UA_Guid_random(UA_Guid *__return_storage_ptr__);
UA_StatusCode UA_ByteString_allocBuffer(UA_ByteString *bs,size_t length);
void NodeId_deleteMembers(UA_NodeId *p,UA_DataType *_);
UA_StatusCode NodeId_copy(UA_NodeId *src,UA_NodeId *dst,UA_DataType *_);
UA_Boolean UA_NodeId_isNull(UA_NodeId *p);
UA_Boolean UA_NodeId_equal(UA_NodeId *n1,UA_NodeId *n2);
void ExpandedNodeId_deleteMembers(UA_ExpandedNodeId *p,UA_DataType *_);
UA_StatusCode ExpandedNodeId_copy(UA_ExpandedNodeId *src,UA_ExpandedNodeId *dst,UA_DataType *_);
void ExtensionObject_deleteMembers(UA_ExtensionObject *p,UA_DataType *_);
UA_StatusCode ExtensionObject_copy(UA_ExtensionObject *src,UA_ExtensionObject *dst,UA_DataType *_);
void Variant_deletemembers(UA_Variant *p,UA_DataType *_);
UA_StatusCode Variant_copy(UA_Variant *src,UA_Variant *dst,UA_DataType *_);
void UA_Variant_setScalar(UA_Variant *v,void *p,UA_DataType *type);
UA_StatusCode UA_Variant_setScalarCopy(UA_Variant *v,void *p,UA_DataType *type);
void UA_Variant_setArray(UA_Variant *v,void *array,size_t arraySize,UA_DataType *type);
UA_StatusCode UA_Variant_setArrayCopy(UA_Variant *v,void *array,size_t arraySize,UA_DataType *type);
UA_StatusCode computeStrides(UA_Variant *v,UA_NumericRange range,size_t *total,size_t *block,size_t *stride,size_t *first);
UA_Boolean isStringLike(UA_DataType *type);
UA_StatusCode copySubString(UA_String *src,UA_String *dst,UA_NumericRangeDimension *dim);
UA_StatusCode UA_Variant_copyRange(UA_Variant *orig_src,UA_Variant *dst,UA_NumericRange range);
UA_StatusCode Variant_setRange(UA_Variant *v,void *array,size_t arraySize,UA_NumericRange range,UA_Boolean copy);
UA_StatusCode UA_Variant_setRange(UA_Variant *v,void *array,size_t arraySize,UA_NumericRange range);
UA_StatusCode UA_Variant_setRangeCopy(UA_Variant *v,void *array,size_t arraySize,UA_NumericRange range);
void LocalizedText_deleteMembers(UA_LocalizedText *p,UA_DataType *_);
UA_StatusCode LocalizedText_copy(UA_LocalizedText *src,UA_LocalizedText *dst,UA_DataType *_);
void DataValue_deleteMembers(UA_DataValue *p,UA_DataType *_);
UA_StatusCode DataValue_copy(UA_DataValue *src,UA_DataValue *dst,UA_DataType *_);
void DiagnosticInfo_deleteMembers(UA_DiagnosticInfo *p,UA_DataType *_);
UA_StatusCode DiagnosticInfo_copy(UA_DiagnosticInfo *src,UA_DiagnosticInfo *dst,UA_DataType *_);
void * UA_new(UA_DataType *type);
UA_StatusCode copyByte(UA_Byte *src,UA_Byte *dst,UA_DataType *_);
UA_StatusCode copy2Byte(UA_UInt16 *src,UA_UInt16 *dst,UA_DataType *_);
UA_StatusCode copy4Byte(UA_UInt32 *src,UA_UInt32 *dst,UA_DataType *_);
UA_StatusCode copy8Byte(UA_UInt64 *src,UA_UInt64 *dst,UA_DataType *_);
UA_StatusCode copyGuid(UA_Guid *src,UA_Guid *dst,UA_DataType *_);
UA_StatusCode copy_noInit(void *src,void *dst,UA_DataType *type);
UA_StatusCode UA_copy(void *src,void *dst,UA_DataType *type);
void nopDeleteMembers(void *p,UA_DataType *type);
void deleteMembers_noInit(void *p,UA_DataType *type);
void UA_deleteMembers(void *p,UA_DataType *type);
void UA_delete(void *p,UA_DataType *type);
void * UA_Array_new(size_t size,UA_DataType *type);
UA_StatusCode UA_Array_copy(void *src,size_t src_size,void **dst,UA_DataType *type);
void UA_Array_delete(void *p,size_t size,UA_DataType *type);
UA_StatusCode exchangeBuffer(void);
void UA_encode16(UA_UInt16 v,UA_Byte *buf);
void UA_decode16(UA_Byte *buf,UA_UInt16 *v);
void UA_encode32(UA_UInt32 v,UA_Byte *buf);
void UA_decode32(UA_Byte *buf,UA_UInt32 *v);
void UA_encode64(UA_UInt64 v,UA_Byte *buf);
void UA_decode64(UA_Byte *buf,UA_UInt64 *v);
UA_StatusCode Boolean_encodeBinary(UA_Boolean *src,UA_DataType *_);
UA_StatusCode Boolean_decodeBinary(UA_Boolean *dst,UA_DataType *_);
UA_StatusCode Byte_encodeBinary(UA_Byte *src,UA_DataType *_);
UA_StatusCode Byte_decodeBinary(UA_Byte *dst,UA_DataType *_);
UA_StatusCode UInt16_encodeBinary(UA_UInt16 *src,UA_DataType *_);
UA_StatusCode UInt16_decodeBinary(UA_UInt16 *dst,UA_DataType *_);
UA_StatusCode UInt32_encodeBinary(UA_UInt32 *src,UA_DataType *_);
UA_StatusCode Int32_encodeBinary(UA_Int32 *src);
UA_StatusCode StatusCode_encodeBinary(UA_StatusCode *src);
UA_StatusCode UInt32_decodeBinary(UA_UInt32 *dst,UA_DataType *_);
UA_StatusCode Int32_decodeBinary(UA_Int32 *dst);
UA_StatusCode StatusCode_decodeBinary(UA_StatusCode *dst);
UA_StatusCode UInt64_encodeBinary(UA_UInt64 *src,UA_DataType *_);
UA_StatusCode DateTime_encodeBinary(UA_DateTime *src);
UA_StatusCode UInt64_decodeBinary(UA_UInt64 *dst,UA_DataType *_);
UA_StatusCode DateTime_decodeBinary(UA_DateTime *dst);
UA_StatusCode Array_encodeBinary(void *src,size_t length,UA_DataType *type);
UA_StatusCode Array_decodeBinary(void **dst,size_t *out_length,UA_DataType *type);
UA_StatusCode String_encodeBinary(UA_String *src,UA_DataType *_);
UA_StatusCode String_decodeBinary(UA_String *dst,UA_DataType *_);
UA_StatusCode ByteString_encodeBinary(UA_ByteString *src);
UA_StatusCode ByteString_decodeBinary(UA_ByteString *dst);
UA_StatusCode Guid_encodeBinary(UA_Guid *src,UA_DataType *_);
UA_StatusCode Guid_decodeBinary(UA_Guid *dst,UA_DataType *_);
UA_StatusCode NodeId_encodeBinary(UA_NodeId *src,UA_DataType *_);
UA_StatusCode NodeId_decodeBinary(UA_NodeId *dst,UA_DataType *_);
UA_StatusCode ExpandedNodeId_encodeBinary(UA_ExpandedNodeId *src,UA_DataType *_);
UA_StatusCode ExpandedNodeId_decodeBinary(UA_ExpandedNodeId *dst,UA_DataType *_);
UA_StatusCode LocalizedText_encodeBinary(UA_LocalizedText *src,UA_DataType *_);
UA_StatusCode LocalizedText_decodeBinary(UA_LocalizedText *dst,UA_DataType *_);
UA_StatusCode findDataTypeByBinary(UA_NodeId *typeId,UA_DataType **findtype);
UA_StatusCode ExtensionObject_encodeBinary(UA_ExtensionObject *src,UA_DataType *_);
UA_StatusCode ExtensionObject_decodeBinary(UA_ExtensionObject *dst,UA_DataType *_);
UA_StatusCode Variant_encodeBinary(UA_Variant *src,UA_DataType *_);
UA_StatusCode Variant_decodeBinary(UA_Variant *dst,UA_DataType *_);
UA_StatusCode DataValue_encodeBinary(UA_DataValue *src,UA_DataType *_);
UA_StatusCode DataValue_decodeBinary(UA_DataValue *dst,UA_DataType *_);
UA_StatusCode DiagnosticInfo_encodeBinary(UA_DiagnosticInfo *src,UA_DataType *_);
UA_StatusCode DiagnosticInfo_decodeBinary(UA_DiagnosticInfo *dst,UA_DataType *_);
UA_StatusCode UA_encodeBinaryInternal(void *src,UA_DataType *type);
UA_StatusCode UA_encodeBinary(void *src,UA_DataType *type,UA_exchangeEncodeBuffer callback,void *handle,UA_ByteString *dst,size_t *offset);
UA_StatusCode UA_decodeBinaryInternal(void *dst,UA_DataType *type);
UA_StatusCode UA_decodeBinary(UA_ByteString *src,size_t *offset,void *dst,UA_DataType *type);
size_t Array_calcSizeBinary(void *src,size_t length,UA_DataType *type);
size_t calcSizeBinaryMemSize(void *p,UA_DataType *type);
size_t String_calcSizeBinary(UA_String *p,UA_DataType *_);
size_t Guid_calcSizeBinary(UA_Guid *p,UA_DataType *_);
size_t NodeId_calcSizeBinary(UA_NodeId *src,UA_DataType *_);
size_t ExpandedNodeId_calcSizeBinary(UA_ExpandedNodeId *src,UA_DataType *_);
size_t LocalizedText_calcSizeBinary(UA_LocalizedText *src,UA_DataType *_);
size_t ExtensionObject_calcSizeBinary(UA_ExtensionObject *src,UA_DataType *_);
size_t Variant_calcSizeBinary(UA_Variant *src,UA_DataType *_);
size_t DataValue_calcSizeBinary(UA_DataValue *src,UA_DataType *_);
size_t DiagnosticInfo_calcSizeBinary(UA_DiagnosticInfo *src,UA_DataType *_);
size_t UA_calcSizeBinary(void *p,UA_DataType *type);
void UA_Connection_deleteMembers(UA_Connection *connection);
UA_StatusCode UA_Connection_completeMessages(UA_Connection *connection,UA_ByteString *message,UA_Boolean *realloced);
void UA_Connection_detachSecureChannel(UA_Connection *connection);
void UA_Connection_attachSecureChannel(UA_Connection *connection,UA_SecureChannel *channel);
UA_StatusCode UA_EndpointUrl_split_ptr(char *endpointUrl,char *hostname,char **port,char **path);
UA_StatusCode UA_EndpointUrl_split(char *endpointUrl,char *hostname,UA_UInt16 *port,char **path);
size_t UA_readNumber(UA_Byte *buf,size_t buflen,UA_UInt32 *number);
void UA_SecureChannel_init(UA_SecureChannel *channel);
void UA_SecureChannel_deleteMembersCleanup(UA_SecureChannel *channel);
UA_StatusCode UA_SecureChannel_generateNonce(UA_ByteString *nonce);
void UA_SecureChannel_attachSession(UA_SecureChannel *channel,UA_Session *session);
void UA_SecureChannel_detachSession(UA_SecureChannel *channel,UA_Session *session);
UA_Session * UA_SecureChannel_getSession(UA_SecureChannel *channel,UA_NodeId *token);
void UA_SecureChannel_revolveTokens(UA_SecureChannel *channel);
UA_StatusCode UA_SecureChannel_sendChunk(UA_ChunkInfo *ci,UA_ByteString *dst,size_t offset);
UA_StatusCode UA_SecureChannel_sendBinaryMessage(UA_SecureChannel *channel,UA_UInt32 requestId,void *content,UA_DataType *contentType);
void UA_SecureChannel_removeChunk(UA_SecureChannel *channel,UA_UInt32 requestId);
void appendChunk(ChunkEntry *ch,UA_ByteString *msg,size_t offset,size_t chunklength);
void UA_SecureChannel_appendChunk(UA_SecureChannel *channel,UA_UInt32 requestId,UA_ByteString *msg,size_t offset,size_t chunklength);
UA_ByteString *UA_SecureChannel_finalizeChunk(UA_ByteString *__return_storage_ptr__,UA_SecureChannel *channel,UA_UInt32 requestId,UA_ByteString *msg,size_t offset,size_t chunklength,UA_Boolean *deleteChunk);
UA_StatusCode UA_SecureChannel_processSequenceNumber(UA_SecureChannel *channel,UA_UInt32 SequenceNumber);
UA_StatusCode UA_SecureChannel_processChunks(UA_SecureChannel *channel,UA_ByteString *chunks,UA_ProcessMessageCallback *callback,void *application);
void UA_Session_init(UA_Session *session);
void UA_Session_deleteMembersCleanup(UA_Session *session,UA_Server *server);
void UA_Session_updateLifetime(UA_Session *session);
void UA_Session_addSubscription(UA_Session *session,UA_Subscription *newSubscription);
UA_StatusCode UA_Session_deleteSubscription(UA_Server *server,UA_Session *session,UA_UInt32 subscriptionID);
UA_Subscription * UA_Session_getSubscriptionByID(UA_Session *session,UA_UInt32 subscriptionID);
UA_UInt32 UA_Session_getUniqueSubscriptionID(UA_Session *session);
UA_UInt16 UA_Server_addNamespace(UA_Server *server,char *name);
UA_StatusCode UA_Server_forEachChildNodeCall(UA_Server *server,UA_NodeId parentNodeId,UA_NodeIteratorCallback callback,void *handle);
UA_StatusCode addReferenceInternal(UA_Server *server,UA_NodeId sourceId,UA_NodeId refTypeId,UA_ExpandedNodeId targetId,UA_Boolean isForward);
UA_AddNodesResult *addNodeInternal(UA_AddNodesResult *__return_storage_ptr__,UA_Server *server,UA_Node *node,UA_NodeId parentNodeId,UA_NodeId referenceTypeId);
UA_AddNodesResult *addNodeInternalWithType(UA_AddNodesResult *__return_storage_ptr__,UA_Server *server,UA_Node *node,UA_NodeId parentNodeId,UA_NodeId referenceTypeId,UA_NodeId typeIdentifier);
void deleteInstanceChildren(UA_Server *server,UA_NodeId *objectNodeId);
void UA_Server_delete(UA_Server *server);
void UA_Server_cleanup(UA_Server *server,void *_);
UA_StatusCode readStatus(void *handle,UA_NodeId nodeid,UA_Boolean sourceTimeStamp,UA_NumericRange *range,UA_DataValue *value,int index);
UA_StatusCode readServiceLevel(void *handle,UA_NodeId nodeid,UA_Boolean sourceTimeStamp,UA_NumericRange *range,UA_DataValue *value,int index);
UA_StatusCode readAuditing(void *handle,UA_NodeId nodeid,UA_Boolean sourceTimeStamp,UA_NumericRange *range,UA_DataValue *value,int index);
UA_StatusCode readNamespaces(void *handle,UA_NodeId nodeid,UA_Boolean sourceTimestamp,UA_NumericRange *range,UA_DataValue *value,int index);
UA_StatusCode readCurrentTime(void *handle,UA_NodeId nodeid,UA_Boolean sourceTimeStamp,UA_NumericRange *range,UA_DataValue *value,int index);
void copyNames(UA_Node *node,char *name);
void addDataTypeNode(UA_Server *server,char *name,UA_UInt32 datatypeid,UA_Boolean isAbstract,UA_UInt32 parent);
void addObjectTypeNode(UA_Server *server,char *name,UA_UInt32 objecttypeid,UA_UInt32 parent,UA_UInt32 parentreference);
UA_VariableTypeNode *createVariableTypeNode(UA_Server *server,char *name,UA_UInt32 variabletypeid,UA_Boolean abstract);
UA_StatusCode GetMonitoredItems(void *handle,UA_NodeId objectId,size_t inputSize,UA_Variant *input,size_t outputSize,UA_Variant *output);
UA_Server * UA_Server_new(UA_ServerConfig config);
void sendError(UA_SecureChannel *channel,UA_ByteString *msg,size_t offset,UA_DataType *responseType,UA_UInt32 requestId,UA_StatusCode error);
void getServicePointers(UA_UInt32 requestTypeId,UA_DataType **requestType,UA_DataType **responseType,UA_Service *service,UA_Boolean *requiresSession);
void processHEL(UA_Connection *connection,UA_ByteString *msg,size_t *offset);
void processOPN(UA_Server *server,UA_Connection *connection,UA_UInt32 channelId,UA_ByteString *msg);
void processMSG(UA_Server *server,UA_SecureChannel *channel,UA_UInt32 requestId,UA_ByteString *msg);
void UA_Server_processSecureChannelMessage(UA_Server *server,UA_SecureChannel *channel,UA_MessageType messagetype,UA_UInt32 requestId,UA_ByteString *message);
void UA_Server_processBinaryMessage(UA_Server *server,UA_Connection *connection,UA_ByteString *message);
size_t readDimension(UA_Byte *buf,size_t buflen,UA_NumericRangeDimension *dim);
UA_StatusCode parse_numericrange(UA_String *str,UA_NumericRange *range);
UA_StatusCode getTypeHierarchy(UA_NodeStore *ns,UA_Node *rootRef,UA_Boolean inverse,UA_NodeId **typeHierarchy,size_t *typeHierarchySize);
UA_Boolean isNodeInTree(UA_NodeStore *ns,UA_NodeId *leafNode,UA_NodeId *nodeToFind,UA_NodeId *referenceTypeIds,size_t referenceTypeIdsSize);
UA_Node * getNodeType(UA_Server *server,UA_Node *node);
UA_VariableTypeNode * getVariableNodeType(UA_Server *server,UA_VariableNode *node);
UA_ObjectTypeNode * getObjectNodeType(UA_Server *server,UA_ObjectNode *node);
UA_Boolean UA_Node_hasSubTypeOrInstances(UA_Node *node);
UA_StatusCode UA_Server_editNode(UA_Server *server,UA_Session *session,UA_NodeId *nodeId,UA_EditNodeCallback callback,void *data);
void processJob(UA_Server *server,UA_Job *job);
void addRepeatedJob(UA_Server *server,RepeatedJob *rj);
UA_StatusCode UA_Server_addRepeatedJob(UA_Server *server,UA_Job job,UA_UInt32 intervalMs,UA_Guid *jobId);
UA_DateTime processRepeatedJobs(UA_Server *server,UA_DateTime current,UA_Boolean *dispatched);
void removeRepeatedJob(UA_Server *server,UA_Guid *jobId);
UA_StatusCode UA_Server_removeRepeatedJob(UA_Server *server,UA_Guid jobId);
void UA_Server_deleteAllRepeatedJobs(UA_Server *server);
UA_StatusCode UA_Server_delayedCallback(UA_Server *server,UA_ServerCallback callback,void *data);
void processDelayedCallbacks(UA_Server *server);
UA_StatusCode UA_Server_run_startup(UA_Server *server);
void completeMessages(UA_Server *server,UA_Job *job);
UA_UInt16 UA_Server_run_iterate(UA_Server *server,UA_Boolean waitInternal);
UA_StatusCode UA_Server_run_shutdown(UA_Server *server);
UA_StatusCode UA_Server_run(UA_Server *server,UA_Boolean *running);
UA_StatusCode UA_SecureChannelManager_init(UA_SecureChannelManager *cm,UA_Server *server);
void UA_SecureChannelManager_deleteMembers(UA_SecureChannelManager *cm);
void removeSecureChannel(UA_SecureChannelManager *cm,channel_list_entry *entry);
void UA_SecureChannelManager_cleanupTimedOut(UA_SecureChannelManager *cm,UA_DateTime nowMonotonic);
UA_Boolean purgeFirstChannelWithoutSession(UA_SecureChannelManager *cm);
UA_StatusCode UA_SecureChannelManager_open(UA_SecureChannelManager *cm,UA_Connection *conn,UA_OpenSecureChannelRequest *request,UA_OpenSecureChannelResponse *response);
UA_StatusCode UA_SecureChannelManager_renew(UA_SecureChannelManager *cm,UA_Connection *conn,UA_OpenSecureChannelRequest *request,UA_OpenSecureChannelResponse *response);
UA_SecureChannel * UA_SecureChannelManager_get(UA_SecureChannelManager *cm,UA_UInt32 channelId);
UA_StatusCode UA_SecureChannelManager_close(UA_SecureChannelManager *cm,UA_UInt32 channelId);
UA_StatusCode UA_SessionManager_init(UA_SessionManager *sm,UA_Server *server);
void UA_SessionManager_deleteMembers(UA_SessionManager *sm);
void removeSessionEntry(UA_SessionManager *sm,session_list_entry *sentry);
void UA_SessionManager_cleanupTimedOut(UA_SessionManager *sm,UA_DateTime nowMonotonic);
UA_Session * UA_SessionManager_getSession(UA_SessionManager *sm,UA_NodeId *token);
UA_StatusCode UA_SessionManager_createSession(UA_SessionManager *sm,UA_SecureChannel *channel,UA_CreateSessionRequest *request,UA_Session **session);
UA_StatusCode UA_SessionManager_removeSession(UA_SessionManager *sm,UA_NodeId *token);
void UA_Node_deleteMembersAnyNodeClass(UA_Node *node);
UA_StatusCode UA_ObjectNode_copy(UA_ObjectNode *src,UA_ObjectNode *dst);
UA_StatusCode UA_CommonVariableNode_copy(UA_VariableNode *src,UA_VariableNode *dst);
UA_StatusCode UA_VariableNode_copy(UA_VariableNode *src,UA_VariableNode *dst);
UA_StatusCode UA_VariableTypeNode_copy(UA_VariableTypeNode *src,UA_VariableTypeNode *dst);
UA_StatusCode UA_MethodNode_copy(UA_MethodNode *src,UA_MethodNode *dst);
UA_StatusCode UA_ObjectTypeNode_copy(UA_ObjectTypeNode *src,UA_ObjectTypeNode *dst);
UA_StatusCode UA_ReferenceTypeNode_copy(UA_ReferenceTypeNode *src,UA_ReferenceTypeNode *dst);
UA_StatusCode UA_DataTypeNode_copy(UA_DataTypeNode *src,UA_DataTypeNode *dst);
UA_StatusCode UA_ViewNode_copy(UA_ViewNode *src,UA_ViewNode *dst);
UA_StatusCode UA_Node_copyAnyNodeClass(UA_Node *src,UA_Node *dst);
UA_UInt16 higher_prime_index(hash_t n);
UA_NodeStoreEntry * instantiateEntry(UA_NodeClass nodeClass);
void deleteEntry(UA_NodeStoreEntry *entry);
UA_NodeStoreEntry ** findNode(UA_NodeStore *ns,UA_NodeId *nodeid);
UA_NodeStoreEntry ** findSlot(UA_NodeStore *ns,UA_NodeId *nodeid);
UA_StatusCode expand(UA_NodeStore *ns);
UA_NodeStore * UA_NodeStore_new(void);
void UA_NodeStore_delete(UA_NodeStore *ns);
UA_Node * UA_NodeStore_newNode(UA_NodeClass class);
void UA_NodeStore_deleteNode(UA_Node *node);
UA_StatusCode UA_NodeStore_insert(UA_NodeStore *ns,UA_Node *node);
UA_StatusCode UA_NodeStore_replace(UA_NodeStore *ns,UA_Node *node);
UA_Node * UA_NodeStore_get(UA_NodeStore *ns,UA_NodeId *nodeid);
UA_Node * UA_NodeStore_getCopy(UA_NodeStore *ns,UA_NodeId *nodeid);
UA_StatusCode UA_NodeStore_remove(UA_NodeStore *ns,UA_NodeId *nodeid);
void UA_NodeStore_iterate(UA_NodeStore *ns,UA_NodeStore_nodeVisitor visitor);
void Service_FindServers(UA_Server *server,UA_Session *session,UA_FindServersRequest *request,UA_FindServersResponse *response);
void Service_GetEndpoints(UA_Server *server,UA_Session *session,UA_GetEndpointsRequest *request,UA_GetEndpointsResponse *response);
void Service_OpenSecureChannel(UA_Server *server,UA_Connection *connection,UA_OpenSecureChannelRequest *request,UA_OpenSecureChannelResponse *response);
void Service_CloseSecureChannel(UA_Server *server,UA_SecureChannel *channel);
void Service_CreateSession(UA_Server *server,UA_SecureChannel *channel,UA_CreateSessionRequest *request,UA_CreateSessionResponse *response);
void Service_ActivateSession(UA_Server *server,UA_SecureChannel *channel,UA_Session *session,UA_ActivateSessionRequest *request,UA_ActivateSessionResponse *response);
void Service_CloseSession(UA_Server *server,UA_Session *session,UA_CloseSessionRequest *request,UA_CloseSessionResponse *response);
void forceVariantSetScalar(UA_Variant *v,void *p,UA_DataType *t);
type_equivalence typeEquivalence(UA_DataType *t);
UA_StatusCode compatibleValueRankArrayDimensions(UA_Int32 valueRank,size_t arrayDimensionsSize);
UA_StatusCode compatibleValueRankValue(UA_Int32 valueRank,UA_Variant *value);
UA_StatusCode compatibleArrayDimensions(size_t constraintArrayDimensionsSize,UA_UInt32 *constraintArrayDimensions,size_t testArrayDimensionsSize,UA_UInt32 *testArrayDimensions);
UA_Variant *convertToMatchingValue(UA_Server *server,UA_Variant *value,UA_NodeId *targetDataTypeId,UA_Variant *editableValue);
UA_StatusCode typeCheckValue(UA_Server *server,UA_NodeId *targetDataTypeId,UA_Int32 targetValueRank,size_t targetArrayDimensionsSize,UA_UInt32 *targetArrayDimensions,UA_Variant *value,UA_NumericRange *range,UA_Variant *editableValue);
UA_StatusCode readArrayDimensionsAttribute(UA_VariableNode *vn,UA_DataValue *v);
UA_StatusCode writeArrayDimensionsAttribute(UA_Server *server,UA_VariableNode *node,size_t arrayDimensionsSize,UA_UInt32 *arrayDimensions);
UA_StatusCode writeValueRankAttributeWithVT(UA_Server *server,UA_VariableNode *node,UA_Int32 valueRank);
UA_StatusCode writeValueRankAttribute(UA_VariableNode *node,UA_Int32 valueRank,UA_Int32 constraintValueRank);
UA_StatusCode writeDataTypeAttributeWithVT(UA_Server *server,UA_VariableNode *node,UA_NodeId *dataType);
UA_StatusCode writeDataTypeAttribute(UA_Server *server,UA_VariableNode *node,UA_NodeId *dataType,UA_NodeId *constraintDataType);
UA_StatusCode readValueAttributeFromNode(UA_VariableNode *vn,UA_DataValue *v,UA_NumericRange *rangeptr);
UA_StatusCode readValueAttributeFromDataSource(UA_VariableNode *vn,UA_DataValue *v,UA_TimestampsToReturn timestamps,UA_NumericRange *rangeptr);
UA_StatusCode readValueAttributeComplete(UA_VariableNode *vn,UA_TimestampsToReturn timestamps,UA_String *indexRange,UA_DataValue *v);
UA_StatusCode readValueAttribute(UA_VariableNode *vn,UA_DataValue *v);
UA_StatusCode writeValueAttributeWithoutRange(UA_VariableNode *node,UA_DataValue *value);
UA_StatusCode writeValueAttributeWithRange(UA_VariableNode *node,UA_DataValue *value,UA_NumericRange *rangeptr);
UA_StatusCode writeValueAttribute(UA_Server *server,UA_VariableNode *node,UA_DataValue *value,UA_String *indexRange);
UA_StatusCode readIsAbstractAttribute(UA_Node *node,UA_Variant *v);
UA_StatusCode writeIsAbstractAttribute(UA_Node *node,UA_Boolean value);
void Service_Read_single(UA_Server *server,UA_Session *session,UA_TimestampsToReturn timestamps,UA_ReadValueId *id,UA_DataValue *v);
void Service_Read(UA_Server *server,UA_Session *session,UA_ReadRequest *request,UA_ReadResponse *response);
UA_DataValue *UA_Server_read(UA_DataValue *__return_storage_ptr__,UA_Server *server,UA_ReadValueId *item,UA_TimestampsToReturn timestamps);
UA_StatusCode __UA_Server_read(UA_Server *server,UA_NodeId *nodeId,UA_AttributeId attributeId,void *v);
UA_StatusCode CopyAttributeIntoNode(UA_Server *server,UA_Session *session,UA_Node *node,UA_WriteValue *wvalue);
void Service_Write(UA_Server *server,UA_Session *session,UA_WriteRequest *request,UA_WriteResponse *response);
UA_StatusCode UA_Server_write(UA_Server *server,UA_WriteValue *value);
UA_StatusCode __UA_Server_write(UA_Server *server,UA_NodeId *nodeId,UA_AttributeId attributeId,UA_DataType *attr_type,void *value);
UA_StatusCode checkParentReference(UA_Server *server,UA_Session *session,UA_NodeClass nodeClass,UA_NodeId *parentNodeId,UA_NodeId *referenceTypeId);
UA_StatusCode copyExistingVariable(UA_Server *server,UA_Session *session,UA_NodeId *variable,UA_NodeId *referenceType,UA_NodeId *parent,UA_InstantiationCallback *instantiationCallback);
UA_StatusCode copyExistingObject(UA_Server *server,UA_Session *session,UA_NodeId *object,UA_NodeId *referenceType,UA_NodeId *parent,UA_InstantiationCallback *instantiationCallback);
UA_StatusCode setObjectInstanceHandle(UA_Server *server,UA_Session *session,UA_ObjectNode *node,_func_void_ptr_UA_NodeId *constructor);
UA_StatusCode instantiateNode(UA_Server *server,UA_Session *session,UA_NodeId *nodeId,UA_NodeClass nodeClass,UA_NodeId *typeId,UA_InstantiationCallback *instantiationCallback);
UA_StatusCode instanceFindAggregateByBrowsename(UA_Server *server,UA_Session *session,UA_NodeId *searchInstance,UA_QualifiedName *browseName,UA_NodeId *outInstanceNodeId);
UA_StatusCode copyChildNodesToNode(UA_Server *server,UA_Session *session,UA_NodeId *sourceNodeId,UA_NodeId *destinationNodeId,UA_InstantiationCallback *instantiationCallback);
UA_StatusCode Service_AddNodes_existing(UA_Server *server,UA_Session *session,UA_Node *node,UA_NodeId *parentNodeId,UA_NodeId *referenceTypeId,UA_NodeId *typeDefinition,UA_InstantiationCallback *instantiationCallback,UA_NodeId *addedNodeId);
UA_StatusCode copyStandardAttributes(UA_Node *node,UA_AddNodesItem *item,UA_NodeAttributes *attr);
UA_StatusCode copyCommonVariableAttributes(UA_Server *server,UA_VariableNode *node,UA_AddNodesItem *item,UA_VariableAttributes *attr);
UA_StatusCode copyVariableNodeAttributes(UA_Server *server,UA_VariableNode *vnode,UA_AddNodesItem *item,UA_VariableAttributes *attr);
UA_StatusCode copyVariableTypeNodeAttributes(UA_Server *server,UA_VariableTypeNode *vtnode,UA_AddNodesItem *item,UA_VariableTypeAttributes *attr);
UA_StatusCode copyObjectNodeAttributes(UA_ObjectNode *onode,UA_ObjectAttributes *attr);
UA_StatusCode copyReferenceTypeNodeAttributes(UA_ReferenceTypeNode *rtnode,UA_ReferenceTypeAttributes *attr);
UA_StatusCode copyObjectTypeNodeAttributes(UA_ObjectTypeNode *otnode,UA_ObjectTypeAttributes *attr);
UA_StatusCode copyViewNodeAttributes(UA_ViewNode *vnode,UA_ViewAttributes *attr);
UA_StatusCode copyDataTypeNodeAttributes(UA_DataTypeNode *dtnode,UA_DataTypeAttributes *attr);
UA_StatusCode createNodeFromAttributes(UA_Server *server,UA_AddNodesItem *item,UA_Node **newNode);
void Service_AddNodes_single(UA_Server *server,UA_Session *session,UA_AddNodesItem *item,UA_AddNodesResult *result,UA_InstantiationCallback *instantiationCallback);
void Service_AddNodes(UA_Server *server,UA_Session *session,UA_AddNodesRequest *request,UA_AddNodesResponse *response);
UA_StatusCode __UA_Server_addNode(UA_Server *server,UA_NodeClass nodeClass,UA_NodeId requestedNewNodeId,UA_NodeId parentNodeId,UA_NodeId referenceTypeId,UA_QualifiedName browseName,UA_NodeId typeDefinition,UA_NodeAttributes *attr,UA_DataType *attributeType,UA_InstantiationCallback *instantiationCallback,UA_NodeId *outNewNodeId);
UA_StatusCode UA_Server_addDataSourceVariableNode(UA_Server *server,UA_NodeId requestedNewNodeId,UA_NodeId parentNodeId,UA_NodeId referenceTypeId,UA_QualifiedName browseName,UA_NodeId typeDefinition,UA_VariableAttributes attr,UA_DataSource dataSource,UA_NodeId *outNewNodeId,int index);
UA_StatusCode UA_Server_addMethodNode(UA_Server *server,UA_NodeId requestedNewNodeId,UA_NodeId parentNodeId,UA_NodeId referenceTypeId,UA_QualifiedName browseName,UA_MethodAttributes attr,UA_MethodCallback method,void *handle,size_t inputArgumentsSize,UA_Argument *inputArguments,size_t outputArgumentsSize,UA_Argument *outputArguments,UA_NodeId *outNewNodeId);
UA_StatusCode addOneWayReference(UA_Server *server,UA_Session *session,UA_Node *node,UA_AddReferencesItem *item);
UA_StatusCode Service_AddReferences_single(UA_Server *server,UA_Session *session,UA_AddReferencesItem *item);
void Service_AddReferences(UA_Server *server,UA_Session *session,UA_AddReferencesRequest *request,UA_AddReferencesResponse *response);
UA_StatusCode UA_Server_addReference(UA_Server *server,UA_NodeId sourceId,UA_NodeId refTypeId,UA_ExpandedNodeId targetId,UA_Boolean isForward);
UA_StatusCode Service_DeleteNodes_single(UA_Server *server,UA_Session *session,UA_NodeId *nodeId,UA_Boolean deleteReferences);
void Service_DeleteNodes(UA_Server *server,UA_Session *session,UA_DeleteNodesRequest *request,UA_DeleteNodesResponse *response);
UA_StatusCode UA_Server_deleteNode(UA_Server *server,UA_NodeId nodeId,UA_Boolean deleteReferences);
UA_StatusCode deleteOneWayReference(UA_Server *server,UA_Session *session,UA_Node *node,UA_DeleteReferencesItem *item);
UA_StatusCode Service_DeleteReferences_single(UA_Server *server,UA_Session *session,UA_DeleteReferencesItem *item);
void Service_DeleteReferences(UA_Server *server,UA_Session *session,UA_DeleteReferencesRequest *request,UA_DeleteReferencesResponse *response);
UA_StatusCode UA_Server_deleteReference(UA_Server *server,UA_NodeId sourceNodeId,UA_NodeId referenceTypeId,UA_Boolean isForward,UA_ExpandedNodeId targetNodeId,UA_Boolean deleteBidirectional);
UA_StatusCode setValueCallback(UA_Server *server,UA_Session *session,UA_VariableNode *node,UA_ValueCallback *callback);
UA_StatusCode UA_Server_setVariableNode_valueCallback(UA_Server *server,UA_NodeId nodeId,UA_ValueCallback callback);
UA_StatusCode setDataSource(UA_Server *server,UA_Session *session,UA_VariableNode *node,UA_DataSource *dataSource);
UA_StatusCode UA_Server_setVariableNode_dataSource(UA_Server *server,UA_NodeId nodeId,UA_DataSource dataSource);
UA_StatusCode setOLM(UA_Server *server,UA_Session *session,UA_ObjectTypeNode *node,UA_ObjectLifecycleManagement *olm);
UA_StatusCode UA_Server_setObjectTypeNode_lifecycleManagement(UA_Server *server,UA_NodeId nodeId,UA_ObjectLifecycleManagement olm);
UA_StatusCode editMethodCallback(UA_Server *server,UA_Session *session,UA_Node *node,void *handle);
UA_StatusCode UA_Server_setMethodNode_callback(UA_Server *server,UA_NodeId methodNodeId,UA_MethodCallback method,void *handle);
UA_StatusCode fillReferenceDescription(UA_NodeStore *ns,UA_Node *curr,UA_ReferenceNode *ref,UA_UInt32 mask,UA_ReferenceDescription *descr);
UA_Node * returnRelevantNode(UA_Server *server,UA_BrowseDescription *descr,UA_Boolean return_all,UA_ReferenceNode *reference,UA_NodeId *relevant,size_t relevant_count,UA_Boolean *isExternal);
void removeCp(ContinuationPointEntry *cp,UA_Session *session);
void Service_Browse_single(UA_Server *server,UA_Session *session,ContinuationPointEntry *cp,UA_BrowseDescription *descr,UA_UInt32 maxrefs,UA_BrowseResult *result);
void Service_Browse(UA_Server *server,UA_Session *session,UA_BrowseRequest *request,UA_BrowseResponse *response);
UA_BrowseResult *UA_Server_browse(UA_BrowseResult *__return_storage_ptr__,UA_Server *server,UA_UInt32 maxrefs,UA_BrowseDescription *descr);
void UA_Server_browseNext_single(UA_Server *server,UA_Session *session,UA_Boolean releaseContinuationPoint,UA_ByteString *continuationPoint,UA_BrowseResult *result);
void Service_BrowseNext(UA_Server *server,UA_Session *session,UA_BrowseNextRequest *request,UA_BrowseNextResponse *response);
UA_BrowseResult *UA_Server_browseNext(UA_BrowseResult *__return_storage_ptr__,UA_Server *server,UA_Boolean releaseContinuationPoint,UA_ByteString *continuationPoint);
UA_StatusCode walkBrowsePath(UA_Server *server,UA_Session *session,UA_Node *node,UA_RelativePath *path,size_t pathindex,UA_BrowsePathTarget **targets,size_t *targets_size,size_t *target_count);
void Service_TranslateBrowsePathsToNodeIds_single(UA_Server *server,UA_Session *session,UA_BrowsePath *path,UA_BrowsePathResult *result);
void Service_TranslateBrowsePathsToNodeIds(UA_Server *server,UA_Session *session,UA_TranslateBrowsePathsToNodeIdsRequest *request,UA_TranslateBrowsePathsToNodeIdsResponse *response);
void Service_RegisterNodes(UA_Server *server,UA_Session *session,UA_RegisterNodesRequest *request,UA_RegisterNodesResponse *response);
void Service_UnregisterNodes(UA_Server *server,UA_Session *session,UA_UnregisterNodesRequest *request,UA_UnregisterNodesResponse *response);
UA_VariableNode *getArgumentsVariableNode(UA_Server *server,UA_MethodNode *ofMethod,UA_String withBrowseName);
UA_StatusCode argumentsConformsToDefinition(UA_Server *server,UA_VariableNode *argRequirements,size_t argsSize,UA_Variant *args);
void Service_Call_single(UA_Server *server,UA_Session *session,UA_CallMethodRequest *request,UA_CallMethodResult *result);
void Service_Call(UA_Server *server,UA_Session *session,UA_CallRequest *request,UA_CallResponse *response);
UA_MonitoredItem * UA_MonitoredItem_new(void);
void MonitoredItem_delete(UA_Server *server,UA_MonitoredItem *monitoredItem);
void ensureSpaceInMonitoredItemQueue(UA_MonitoredItem *mon);
UA_StatusCode detectValueChange(UA_MonitoredItem *mon,UA_DataValue *value,UA_ByteString *encoding,UA_Boolean *changed);
void UA_MoniteredItem_SampleCallback(UA_Server *server,UA_MonitoredItem *monitoredItem);
UA_StatusCode MonitoredItem_registerSampleJob(UA_Server *server,UA_MonitoredItem *mon);
UA_StatusCode MonitoredItem_unregisterSampleJob(UA_Server *server,UA_MonitoredItem *mon);
UA_Subscription * UA_Subscription_new(UA_Session *session,UA_UInt32 subscriptionID);
void UA_Subscription_deleteMembers(UA_Subscription *subscription,UA_Server *server);
UA_MonitoredItem * UA_Subscription_getMonitoredItem(UA_Subscription *sub,UA_UInt32 monitoredItemID);
UA_StatusCode UA_Subscription_deleteMonitoredItem(UA_Server *server,UA_Subscription *sub,UA_UInt32 monitoredItemID);
size_t countQueuedNotifications(UA_Subscription *sub,UA_Boolean *moreNotifications);
void UA_Subscription_addRetransmissionMessage(UA_Server *server,UA_Subscription *sub,UA_NotificationMessageEntry *entry);
UA_StatusCode UA_Subscription_removeRetransmissionMessage(UA_Subscription *sub,UA_UInt32 sequenceNumber);
UA_StatusCode prepareNotificationMessage(UA_Subscription *sub,UA_NotificationMessage *message,size_t notifications);
void UA_Subscription_publishCallback(UA_Server *server,UA_Subscription *sub);
UA_StatusCode Subscription_registerPublishJob(UA_Server *server,UA_Subscription *sub);
UA_StatusCode Subscription_unregisterPublishJob(UA_Server *server,UA_Subscription *sub);
void UA_Subscription_answerPublishRequestsNoSubscription(UA_Server *server,UA_NodeId *sessionToken);
void setSubscriptionSettings(UA_Server *server,UA_Subscription *subscription,UA_Double requestedPublishingInterval,UA_UInt32 requestedLifetimeCount,UA_UInt32 requestedMaxKeepAliveCount,UA_UInt32 maxNotificationsPerPublish,UA_Byte priority);
void Service_CreateSubscription(UA_Server *server,UA_Session *session,UA_CreateSubscriptionRequest *request,UA_CreateSubscriptionResponse *response);
void Service_ModifySubscription(UA_Server *server,UA_Session *session,UA_ModifySubscriptionRequest *request,UA_ModifySubscriptionResponse *response);
void Service_SetPublishingMode(UA_Server *server,UA_Session *session,UA_SetPublishingModeRequest *request,UA_SetPublishingModeResponse *response);
void setMonitoredItemSettings(UA_Server *server,UA_MonitoredItem *mon,UA_MonitoringMode monitoringMode,UA_MonitoringParameters *params);
void Service_CreateMonitoredItems_single(UA_Server *server,UA_Session *session,UA_Subscription *sub,UA_TimestampsToReturn timestampsToReturn,UA_MonitoredItemCreateRequest *request,UA_MonitoredItemCreateResult *result);
void Service_CreateMonitoredItems(UA_Server *server,UA_Session *session,UA_CreateMonitoredItemsRequest *request,UA_CreateMonitoredItemsResponse *response);
void Service_ModifyMonitoredItems_single(UA_Server *server,UA_Session *session,UA_Subscription *sub,UA_MonitoredItemModifyRequest *request,UA_MonitoredItemModifyResult *result);
void Service_ModifyMonitoredItems(UA_Server *server,UA_Session *session,UA_ModifyMonitoredItemsRequest *request,UA_ModifyMonitoredItemsResponse *response);
void Service_SetMonitoringMode(UA_Server *server,UA_Session *session,UA_SetMonitoringModeRequest *request,UA_SetMonitoringModeResponse *response);
void Service_Publish(UA_Server *server,UA_Session *session,UA_PublishRequest *request,UA_UInt32 requestId);
void Service_DeleteSubscriptions(UA_Server *server,UA_Session *session,UA_DeleteSubscriptionsRequest *request,UA_DeleteSubscriptionsResponse *response);
void Service_DeleteMonitoredItems(UA_Server *server,UA_Session *session,UA_DeleteMonitoredItemsRequest *request,UA_DeleteMonitoredItemsResponse *response);
void Service_Republish(UA_Server *server,UA_Session *session,UA_RepublishRequest *request,UA_RepublishResponse *response);
UA_StatusCode Connection_receiveChunk(UA_Connection *connection,UA_ByteString *message,UA_Boolean *realloced,UA_UInt32 timeout);
void UA_Client_init(UA_Client *client,UA_ClientConfig config);
UA_Client * UA_Client_new(UA_ClientConfig config);
void UA_Client_deleteMembers(UA_Client *client);
void UA_Client_reset(UA_Client *client);
void UA_Client_delete(UA_Client *client);
UA_ClientState UA_Client_getState(UA_Client *client);
UA_StatusCode HelAckHandshake(UA_Client *client);
UA_StatusCode SecureChannelHandshake(UA_Client *client,UA_Boolean renew);
UA_StatusCode ActivateSession(UA_Client *client);
UA_StatusCode GetEndpoints(UA_Client *client,size_t *endpointDescriptionsSize,UA_EndpointDescription **endpointDescriptions);
UA_StatusCode EndpointsHandshake(UA_Client *client);
UA_StatusCode SessionHandshake(UA_Client *client);
UA_StatusCode CloseSession(UA_Client *client);
UA_StatusCode CloseSecureChannel(UA_Client *client);
UA_StatusCode UA_Client_getEndpoints(UA_Client *client,char *serverUrl,size_t *endpointDescriptionsSize,UA_EndpointDescription **endpointDescriptions);
UA_StatusCode UA_Client_connect_username(UA_Client *client,char *endpointUrl,char *username,char *password);
UA_StatusCode UA_Client_connect(UA_Client *client,char *endpointUrl);
UA_StatusCode UA_Client_disconnect(UA_Client *client);
UA_StatusCode UA_Client_manuallyRenewSecureChannel(UA_Client *client);
void processServiceResponse(ResponseDescription *rd,UA_SecureChannel *channel,UA_MessageType messageType,UA_UInt32 requestId,UA_ByteString *message);
void __UA_Client_Service(UA_Client *client,void *r,UA_DataType *requestType,void *response,UA_DataType *responseType);
UA_StatusCode UA_Client_NamespaceGetIndex(UA_Client *client,UA_String *namespaceUri,UA_UInt16 *namespaceIndex);
UA_StatusCode UA_Client_forEachChildNodeCall(UA_Client *client,UA_NodeId parentNodeId,UA_NodeIteratorCallback callback,void *handle);
UA_StatusCode UA_Client_addReference(UA_Client *client,UA_NodeId sourceNodeId,UA_NodeId referenceTypeId,UA_Boolean isForward,UA_String targetServerUri,UA_ExpandedNodeId targetNodeId,UA_NodeClass targetNodeClass);
UA_StatusCode UA_Client_deleteReference(UA_Client *client,UA_NodeId sourceNodeId,UA_NodeId referenceTypeId,UA_Boolean isForward,UA_ExpandedNodeId targetNodeId,UA_Boolean deleteBidirectional);
UA_StatusCode UA_Client_deleteNode(UA_Client *client,UA_NodeId nodeId,UA_Boolean deleteTargetReferences);
UA_StatusCode __UA_Client_addNode(UA_Client *client,UA_NodeClass nodeClass,UA_NodeId requestedNewNodeId,UA_NodeId parentNodeId,UA_NodeId referenceTypeId,UA_QualifiedName browseName,UA_NodeId typeDefinition,UA_NodeAttributes *attr,UA_DataType *attributeType,UA_NodeId *outNewNodeId);
UA_StatusCode UA_Client_call(UA_Client *client,UA_NodeId objectId,UA_NodeId methodId,size_t inputSize,UA_Variant *input,size_t *outputSize,UA_Variant **output);
UA_StatusCode __UA_Client_writeAttribute(UA_Client *client,UA_NodeId *nodeId,UA_AttributeId attributeId,void *in,UA_DataType *inDataType);
UA_StatusCode UA_Client_writeArrayDimensionsAttribute(UA_Client *client,UA_NodeId nodeId,UA_Int32 *newArrayDimensions,size_t newArrayDimensionsSize);
UA_StatusCode __UA_Client_readAttribute(UA_Client *client,UA_NodeId *nodeId,UA_AttributeId attributeId,void *out,UA_DataType *outDataType);
UA_StatusCode UA_Client_readArrayDimensionsAttribute(UA_Client *client,UA_NodeId nodeId,UA_Int32 **outArrayDimensions,size_t *outArrayDimensionsSize);
UA_StatusCode UA_Client_Subscriptions_new(UA_Client *client,UA_SubscriptionSettings settings,UA_UInt32 *newSubscriptionId);
UA_StatusCode UA_Client_Subscriptions_remove(UA_Client *client,UA_UInt32 subscriptionId);
void UA_Client_Subscriptions_forceDelete(UA_Client *client,UA_Client_Subscription *sub);
UA_StatusCode UA_Client_Subscriptions_addMonitoredItem(UA_Client *client,UA_UInt32 subscriptionId,UA_NodeId nodeId,UA_UInt32 attributeID,UA_MonitoredItemHandlingFunction handlingFunction,void *handlingContext,UA_UInt32 *newMonitoredItemId);
UA_StatusCode UA_Client_Subscriptions_removeMonitoredItem(UA_Client *client,UA_UInt32 subscriptionId,UA_UInt32 monitoredItemId);
void UA_Client_processPublishResponse(UA_Client *client,UA_PublishRequest *request,UA_PublishResponse *response);
UA_StatusCode UA_Client_Subscriptions_manuallySendPublishRequest(UA_Client *client);
void socket_close(UA_Connection *connection);
UA_StatusCode socket_write(UA_Connection *connection,UA_ByteString *buf);
UA_StatusCode socket_recv(UA_Connection *connection,UA_ByteString *response,UA_UInt32 timeout);
UA_StatusCode socket_set_nonblocking(int sockfd);
void FreeConnectionCallback(UA_Server *server,void *ptr);
UA_StatusCode ServerNetworkLayerGetSendBuffer(UA_Connection *connection,size_t length,UA_ByteString *buf);
void ServerNetworkLayerReleaseSendBuffer(UA_Connection *connection,UA_ByteString *buf);
void ServerNetworkLayerReleaseRecvBuffer(UA_Connection *connection,UA_ByteString *buf);
UA_Int32 setFDSet(ServerNetworkLayerTCP *layer,fd_set *fdset);
void ServerNetworkLayerTCP_closeConnection(UA_Connection *connection);
UA_StatusCode ServerNetworkLayerTCP_add(ServerNetworkLayerTCP *layer,UA_Int32 newsockfd);
UA_StatusCode ServerNetworkLayerTCP_start(UA_ServerNetworkLayer *nl,UA_Logger logger);
size_t ServerNetworkLayerTCP_getJobs(UA_ServerNetworkLayer *nl,UA_Job **jobs,UA_UInt16 timeout);
size_t ServerNetworkLayerTCP_stop(UA_ServerNetworkLayer *nl,UA_Job **jobs);
void ServerNetworkLayerTCP_deleteMembers(UA_ServerNetworkLayer *nl);
UA_ServerNetworkLayer *UA_ServerNetworkLayerTCP(UA_ServerNetworkLayer *__return_storage_ptr__,UA_ConnectionConfig conf,UA_UInt16 port);
UA_StatusCode ClientNetworkLayerGetBuffer(UA_Connection *connection,size_t length,UA_ByteString *buf);
void ClientNetworkLayerReleaseBuffer(UA_Connection *connection,UA_ByteString *buf);
void ClientNetworkLayerClose(UA_Connection *connection);
UA_Connection *UA_ClientConnectionTCP(UA_Connection *__return_storage_ptr__,UA_ConnectionConfig localConf,char *endpointUrl,UA_Logger logger);
UA_DateTime UA_DateTime_now(void);
UA_DateTime UA_DateTime_nowMonotonic(void);
void UA_Log_Stdout(UA_LogLevel level,UA_LogCategory category,char *msg,...);
int __secs_to_tm(longlong t,tm *tm);
void pcg32_srandom_r(pcg32_random_t *rng,uint64_t initial_state,uint64_t initseq);
uint32_t pcg32_random_r(pcg32_random_t *rng);
UA_StatusCodeDescription * UA_StatusCode_description(UA_StatusCode code);
void DealTemperature(void *pData,WORD wLength);
void DealMonitor(void *pData,WORD wLength);
void DealUpdate(void *pData,WORD wLength);
void DealHMIBound(void *pData,WORD wLength);
void DealError(void *pData,WORD wLength);
void DealEnergy(void *pData,WORD wLength);
void DealMachineStatus(void *pData,WORD wLength);
void DealInferiorStatus(void *pData,WORD wLength);
void DealXml(void *pData,WORD wLength);
void DealidentificationA(void *pData,WORD wLength);
void DealidentificationB(void *pData,WORD wLength);
void DealVersion(void *pData,WORD wLength);
void DealHMIproVersion(void *pData,WORD wLength);
void DealGetMachine(void *pData,WORD wLength);
void DealGetMoldset(void *pData,WORD wLength);
void DealOnLineStatus(void *pData,WORD wLength);
void DealLineStatus(void *pData,WORD wLength);
void DealGetUser(void *pData,WORD wLength);
void compare_get_value(char *name,DBVALUE value);
void * pthread_inet(void);
void put_value_0121_moldset(void);
void put_value_0021_error(void);
void put_value_0013_UpdateCommon(void);
void put_value_0026_energy(void);
void put_value_0010_temper_set(void);
void put_value_0010_temper_current(void);
void put_value_0040_instant(void);
void put_value_0011_monitor(void);
void EncryptString(char *input,char *output,uint16_t inputlen);
void DecryptString(char *input,char *output,uint16_t inputlen);
void encry(void *pData,char *msg_buff);
void Dealidentification_rsa(void *pData,WORD wLength);
char * Dealidentification_self(void *pData,WORD wLength);
void FindtmClpSPMode(void);
void ChangeMode(void);
void SendBoundApplication(void);
void SendOPState(BYTE *byData);
void N2A(char *psz,WORD_T *pLen,DWORD dwValue,int nPrecision);
void SendMonitor(BYTE *byData);
void SendModify(BYTE *byData);
void GetAlarmUnicode(char *psz,WORD_T wErrorCode,WORD_T *pLen);
BOOL_T GetAlarmState(ERROR tagError);
void SendError(BYTE *byData);
void GetMoldSet(BYTE *byData);
ulong ParaseNetData_HMI(char *byData,int wLength);
void GetTemper(BYTE *byData);
void GetEnergy(BYTE *byData);
void GetXml(BYTE *byData);
int get_local_ip(char *eth_inf,char *ip);
int get_local_mac(char *eth_inf,char *mac);
int MD5_Init(MD5_CTX *c);
void md5_block_data_order(MD5_CTX *c,void *data_,size_t num);
int MD5_Update(MD5_CTX *c,void *data_,size_t len);
void MD5_Transform(MD5_CTX *c,uchar *data);
int MD5_Final(uchar *md,MD5_CTX *c);
int SHA224_Init(SHA256_CTX *c);
int SHA256_Init(SHA256_CTX *c);
void SHA256_Transform(SHA256_CTX *c,uchar *data);
int SHA256_Final(uchar *md,SHA256_CTX *c);
uchar * SHA224(uchar *d,size_t n,uchar *md);
uchar * SHA256(uchar *d,size_t n,uchar *md);
int SHA224_Final(uchar *md,SHA256_CTX *c);
void sha256_block_data_order(undefined1 (*param_1) [16],undefined1 (*param_2) [16],int param_3);
void sha256_block_data_order_neon(int *param_1,undefined1 (*param_2) [16],int param_3);
void sha256_block_data_order_armv8(undefined1 (*param_1) [16],undefined1 (*param_2) [16],int param_3);
void RSA_set_default_method(RSA_METHOD *meth);
RSA_METHOD * RSA_get_default_method(void);
RSA_METHOD * RSA_get_method(RSA *rsa);
int RSA_set_method(RSA *rsa,RSA_METHOD *meth);
RSA * RSA_new_method(ENGINE *engine);
RSA * RSA_new(void);
void RSA_free(RSA *r);
int RSA_up_ref(RSA *r);
int RSA_get_ex_new_index(long argl,void *argp,CRYPTO_EX_new *new_func,CRYPTO_EX_dup *dup_func,CRYPTO_EX_free *free_func);
int RSA_set_ex_data(RSA *r,int idx,void *arg);
void * RSA_get_ex_data(RSA *r,int idx);
int RSA_memory_lock(RSA *r);
int RSA_sign(int type,uchar *m,uint m_len,uchar *sigret,uint *siglen,RSA *rsa);
int int_rsa_verify(int dtype,uchar *m,uint m_len,uchar *rm,size_t *prm_len,uchar *sigbuf,size_t siglen,RSA *rsa);
int RSA_verify(int dtype,uchar *m,uint m_len,uchar *sigbuf,uint siglen,RSA *rsa);
int RSA_size(RSA *r);
int RSA_public_encrypt(int flen,uchar *from,uchar *to,RSA *rsa,int padding);
int RSA_private_encrypt(int flen,uchar *from,uchar *to,RSA *rsa,int padding);
int RSA_private_decrypt(int flen,uchar *from,uchar *to,RSA *rsa,int padding);
int RSA_public_decrypt(int flen,uchar *from,uchar *to,RSA *rsa,int padding);
int RSA_flags(RSA *r);
void RSA_blinding_off(RSA *rsa);
BN_BLINDING * RSA_setup_blinding(RSA *rsa,BN_CTX *in_ctx);
int RSA_blinding_on(RSA *rsa,BN_CTX *ctx);
int engine_unlocked_init(ENGINE *e);
int engine_unlocked_finish(ENGINE *e,int unlock_for_handlers);
int ENGINE_init(ENGINE *e);
int ENGINE_finish(ENGINE *e);
void engine_unregister_all_RSA(void);
void ENGINE_unregister_RSA(ENGINE *e);
int ENGINE_register_RSA(ENGINE *e);
void ENGINE_register_all_RSA(void);
int ENGINE_set_default_RSA(ENGINE *e);
ENGINE * ENGINE_get_default_RSA(void);
RSA_METHOD * ENGINE_get_RSA(ENGINE *e);
int ENGINE_set_RSA(ENGINE *e,RSA_METHOD *rsa_meth);
int BIO_set(BIO *bio,BIO_METHOD *method);
BIO * BIO_new(BIO_METHOD *method);
int BIO_free(BIO *a);
void BIO_vfree(BIO *a);
void BIO_clear_flags(BIO *b,int flags);
int BIO_test_flags(BIO *b,int flags);
void BIO_set_flags(BIO *b,int flags);
_func_long_bio_st_ptr_int_char_ptr_int_long_long * BIO_get_callback(BIO *b);
void BIO_set_callback(BIO *b,_func_long_bio_st_ptr_int_char_ptr_int_long_long *cb);
void BIO_set_callback_arg(BIO *b,char *arg);
char * BIO_get_callback_arg(BIO *b);
char * BIO_method_name(BIO *b);
int BIO_method_type(BIO *b);
int BIO_read(BIO *b,void *out,int outl);
int BIO_write(BIO *b,void *in,int inl);
int BIO_puts(BIO *b,char *in);
int BIO_gets(BIO *b,char *in,int inl);
int BIO_indent(BIO *b,int indent,int max);
long BIO_ctrl(BIO *b,int cmd,long larg,void *parg);
long BIO_int_ctrl(BIO *b,int cmd,long larg,int iarg);
char * BIO_ptr_ctrl(BIO *b,int cmd,long larg);
long BIO_callback_ctrl(BIO *b,int cmd,bio_info_cb *fp);
size_t BIO_ctrl_pending(BIO *bio);
size_t BIO_ctrl_wpending(BIO *bio);
BIO * BIO_push(BIO *b,BIO *bio);
BIO * BIO_pop(BIO *b);
BIO * BIO_get_retry_BIO(BIO *bio,int *reason);
int BIO_get_retry_reason(BIO *bio);
BIO * BIO_find_type(BIO *bio,int type);
BIO * BIO_next(BIO *b);
void BIO_free_all(BIO *bio);
BIO * BIO_dup_chain(BIO *in);
void BIO_copy_next_retry(BIO *b);
int BIO_get_ex_new_index(long argl,void *argp,CRYPTO_EX_new *new_func,CRYPTO_EX_dup *dup_func,CRYPTO_EX_free *free_func);
int BIO_set_ex_data(BIO *bio,int idx,void *data);
void * BIO_get_ex_data(BIO *bio,int idx);
ulong BIO_number_read(BIO *bio);
ulong BIO_number_written(BIO *bio);
int mem_new(BIO *bi);
int mem_read(BIO *b,char *out,int outl);
int mem_gets(BIO *bp,char *buf,int size);
int mem_free(BIO *a);
long mem_ctrl(BIO *b,int cmd,long num,void *ptr);
int mem_write(BIO *b,char *in,int inl);
int mem_puts(BIO *bp,char *str);
BIO_METHOD * BIO_s_mem(void);
BIO * BIO_new_mem_buf(void *buf,int len);
int RAND_set_rand_method(RAND_METHOD *meth);
RAND_METHOD * RAND_get_rand_method(void);
int RAND_set_rand_engine(ENGINE *engine);
void RAND_cleanup(void);
void RAND_seed(void *buf,int num);
void RAND_add(void *buf,int num,double entropy);
int RAND_bytes(uchar *buf,int num);
int RAND_pseudo_bytes(uchar *buf,int num);
int RAND_status(void);
ulong err_string_data_LHASH_HASH(void *arg);
int err_string_data_LHASH_COMP(void *arg1,void *arg2);
int int_err_get_next_lib(void);
void int_err_del(void);
void ERR_STATE_free(ERR_STATE *s);
void int_thread_release(lhash_st_ERR_STATE **hash);
lhash_st_ERR_STATE * int_thread_get(int create);
lhash_st_ERR_STRING_DATA * int_err_get(int create);
int err_state_LHASH_COMP(void *arg1,void *arg2);
ulong err_state_LHASH_HASH(void *arg);
void err_fns_check(void);
ERR_STRING_DATA * int_err_del_item(ERR_STRING_DATA *d);
void int_thread_del_item(ERR_STATE *d);
ERR_STATE * int_thread_set_item(ERR_STATE *d);
ERR_STRING_DATA * int_err_set_item(ERR_STRING_DATA *d);
ERR_STATE * int_thread_get_item(ERR_STATE *d);
ERR_STRING_DATA * int_err_get_item(ERR_STRING_DATA *d);
ERR_FNS * ERR_get_implementation(void);
int ERR_set_implementation(ERR_FNS *fns);
void ERR_load_ERR_strings(void);
void ERR_load_strings(int lib,ERR_STRING_DATA *str);
void ERR_unload_strings(int lib,ERR_STRING_DATA *str);
void ERR_free_strings(void);
lhash_st_ERR_STRING_DATA * ERR_get_string_table(void);
lhash_st_ERR_STATE * ERR_get_err_state_table(void);
void ERR_release_err_state_table(lhash_st_ERR_STATE **hash);
char * ERR_lib_error_string(ulong e);
char * ERR_func_error_string(ulong e);
char * ERR_reason_error_string(ulong e);
void ERR_error_string_n(ulong e,char *buf,size_t len);
char * ERR_error_string(ulong e,char *ret);
void ERR_remove_thread_state(CRYPTO_THREADID *id);
void ERR_remove_state(ulong pid);
ERR_STATE * ERR_get_state(void);
void ERR_put_error(int lib,int func,int reason,char *file,int line);
void ERR_clear_error(void);
ulong get_error_values(int inc,int top,char **file,int *line,char **data,int *flags);
ulong ERR_get_error(void);
ulong ERR_get_error_line(char **file,int *line);
ulong ERR_get_error_line_data(char **file,int *line,char **data,int *flags);
ulong ERR_peek_error_line(char **file,int *line);
ulong ERR_peek_error_line_data(char **file,int *line,char **data,int *flags);
ulong ERR_peek_last_error_line(char **file,int *line);
ulong ERR_peek_last_error_line_data(char **file,int *line,char **data,int *flags);
ulong ERR_peek_error(void);
ulong ERR_peek_last_error(void);
int ERR_get_next_error_library(void);
void ERR_set_error_data(char *data,int flags);
void ERR_add_error_vdata(int num,va_list args);
void ERR_add_error_data(int num,...);
int ERR_set_mark(void);
int ERR_pop_to_mark(void);
void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *ctx);
EVP_CIPHER_CTX * EVP_CIPHER_CTX_new(void);
int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx,uchar *out,int *outl,uchar *in,int inl);
int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx,uchar *out,int *outl);
int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx,uchar *out,int *outl);
int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx,uchar *out,int *outl,uchar *in,int inl);
int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx,uchar *out,int *outl,uchar *in,int inl);
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx,uchar *out,int *outl);
int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx,uchar *out,int *outl);
int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx,uchar *out,int *outl);
int EVP_CipherFinal(EVP_CIPHER_CTX *ctx,uchar *out,int *outl);
int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *c);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *ctx,int pad);
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx,int type,int arg,void *ptr);
int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx,EVP_CIPHER *cipher,ENGINE *impl,uchar *key,uchar *iv,int enc);
int EVP_CipherInit(EVP_CIPHER_CTX *ctx,EVP_CIPHER *cipher,uchar *key,uchar *iv,int enc);
int EVP_EncryptInit(EVP_CIPHER_CTX *ctx,EVP_CIPHER *cipher,uchar *key,uchar *iv);
int EVP_DecryptInit(EVP_CIPHER_CTX *ctx,EVP_CIPHER *cipher,uchar *key,uchar *iv);
int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,EVP_CIPHER *cipher,ENGINE *impl,uchar *key,uchar *iv);
int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,EVP_CIPHER *cipher,ENGINE *impl,uchar *key,uchar *iv);
int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *c,int keylen);
int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx,uchar *key);
int EVP_CIPHER_CTX_copy(EVP_CIPHER_CTX *out,EVP_CIPHER_CTX *in);
int aes_ecb_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t len);
int aes_xts_ctrl(EVP_CIPHER_CTX *c,int type,int arg,void *ptr);
int aes_cbc_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t len);
int aes_init_key(EVP_CIPHER_CTX *ctx,uchar *key,uchar *iv,int enc);
int aes_ofb_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t len);
int aes_cfb_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t len);
int aes_cfb1_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t len);
int aes_cfb8_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t len);
int aes_ctr_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t len);
int aes_xts_init_key(EVP_CIPHER_CTX *ctx,uchar *key,uchar *iv,int enc);
int aes_wrap_init_key(EVP_CIPHER_CTX *ctx,uchar *key,uchar *iv,int enc);
int aes_gcm_ctrl(EVP_CIPHER_CTX *c,int type,int arg,void *ptr);
int aes_gcm_cleanup(EVP_CIPHER_CTX *c);
int aes_gcm_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t len);
int aes_gcm_init_key(EVP_CIPHER_CTX *ctx,uchar *key,uchar *iv,int enc);
int aes_xts_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t len);
int aes_ccm_ctrl(EVP_CIPHER_CTX *c,int type,int arg,void *ptr);
int aes_ccm_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t len);
int aes_ccm_init_key(EVP_CIPHER_CTX *ctx,uchar *key,uchar *iv,int enc);
int aes_wrap_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inlen);
EVP_CIPHER * EVP_aes_128_cbc(void);
EVP_CIPHER * EVP_aes_128_ecb(void);
EVP_CIPHER * EVP_aes_128_ofb(void);
EVP_CIPHER * EVP_aes_128_cfb128(void);
EVP_CIPHER * EVP_aes_128_cfb1(void);
EVP_CIPHER * EVP_aes_128_cfb8(void);
EVP_CIPHER * EVP_aes_128_ctr(void);
EVP_CIPHER * EVP_aes_192_cbc(void);
EVP_CIPHER * EVP_aes_192_ecb(void);
EVP_CIPHER * EVP_aes_192_ofb(void);
EVP_CIPHER * EVP_aes_192_cfb128(void);
EVP_CIPHER * EVP_aes_192_cfb1(void);
EVP_CIPHER * EVP_aes_192_cfb8(void);
EVP_CIPHER * EVP_aes_192_ctr(void);
EVP_CIPHER * EVP_aes_256_cbc(void);
EVP_CIPHER * EVP_aes_256_ecb(void);
EVP_CIPHER * EVP_aes_256_ofb(void);
EVP_CIPHER * EVP_aes_256_cfb128(void);
EVP_CIPHER * EVP_aes_256_cfb1(void);
EVP_CIPHER * EVP_aes_256_cfb8(void);
EVP_CIPHER * EVP_aes_256_ctr(void);
EVP_CIPHER * EVP_aes_128_gcm(void);
EVP_CIPHER * EVP_aes_192_gcm(void);
EVP_CIPHER * EVP_aes_256_gcm(void);
EVP_CIPHER * EVP_aes_128_xts(void);
EVP_CIPHER * EVP_aes_256_xts(void);
EVP_CIPHER * EVP_aes_128_ccm(void);
EVP_CIPHER * EVP_aes_192_ccm(void);
EVP_CIPHER * EVP_aes_256_ccm(void);
EVP_CIPHER * EVP_aes_128_wrap(void);
EVP_CIPHER * EVP_aes_192_wrap(void);
EVP_CIPHER * EVP_aes_256_wrap(void);
void do_all_cipher_fn(OBJ_NAME *nm,void *arg);
void do_all_md_fn(OBJ_NAME *nm,void *arg);
int EVP_add_cipher(EVP_CIPHER *c);
int EVP_add_digest(EVP_MD *md);
EVP_CIPHER * EVP_get_cipherbyname(char *name);
EVP_MD * EVP_get_digestbyname(char *name);
void EVP_cleanup(void);
void EVP_CIPHER_do_all(_func_void_EVP_CIPHER_ptr_char_ptr_char_ptr_void_ptr *fn,void *arg);
void EVP_CIPHER_do_all_sorted(_func_void_EVP_CIPHER_ptr_char_ptr_char_ptr_void_ptr *fn,void *arg);
void EVP_MD_do_all(_func_void_EVP_MD_ptr_char_ptr_char_ptr_void_ptr *fn,void *arg);
void EVP_MD_do_all_sorted(_func_void_EVP_MD_ptr_char_ptr_char_ptr_void_ptr *fn,void *arg);
long b64_callback_ctrl(BIO *b,int cmd,bio_info_cb *fp);
int b64_free(BIO *a);
int b64_new(BIO *bi);
int b64_read(BIO *b,char *out,int outl);
int b64_write(BIO *b,char *in,int inl);
long b64_ctrl(BIO *b,int cmd,long num,void *ptr);
int b64_puts(BIO *b,char *str);
BIO_METHOD * BIO_f_base64(void);
void OPENSSL_add_all_algorithms_noconf(void);
void OpenSSL_add_all_ciphers(void);
void OpenSSL_add_all_digests(void);
int EVP_CIPHER_block_size(EVP_CIPHER *e);
int EVP_CIPHER_CTX_block_size(EVP_CIPHER_CTX *ctx);
int EVP_Cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,uint inl);
EVP_CIPHER * EVP_CIPHER_CTX_cipher(EVP_CIPHER_CTX *ctx);
ulong EVP_CIPHER_flags(EVP_CIPHER *cipher);
ulong EVP_CIPHER_CTX_flags(EVP_CIPHER_CTX *ctx);
void * EVP_CIPHER_CTX_get_app_data(EVP_CIPHER_CTX *ctx);
void EVP_CIPHER_CTX_set_app_data(EVP_CIPHER_CTX *ctx,void *data);
int EVP_CIPHER_iv_length(EVP_CIPHER *cipher);
int EVP_CIPHER_CTX_iv_length(EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_get_asn1_iv(EVP_CIPHER_CTX *c,ASN1_TYPE *type);
int EVP_CIPHER_asn1_to_param(EVP_CIPHER_CTX *c,ASN1_TYPE *type);
int EVP_CIPHER_set_asn1_iv(EVP_CIPHER_CTX *c,ASN1_TYPE *type);
int EVP_CIPHER_key_length(EVP_CIPHER *cipher);
int EVP_CIPHER_CTX_key_length(EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_nid(EVP_CIPHER *cipher);
int EVP_CIPHER_type(EVP_CIPHER *ctx);
int EVP_CIPHER_CTX_nid(EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_param_to_asn1(EVP_CIPHER_CTX *c,ASN1_TYPE *type);
int EVP_MD_block_size(EVP_MD *md);
int EVP_MD_type(EVP_MD *md);
int EVP_MD_pkey_type(EVP_MD *md);
int EVP_MD_size(EVP_MD *md);
ulong EVP_MD_flags(EVP_MD *md);
EVP_MD * EVP_MD_CTX_md(EVP_MD_CTX *ctx);
void EVP_MD_CTX_set_flags(EVP_MD_CTX *ctx,int flags);
void EVP_MD_CTX_clear_flags(EVP_MD_CTX *ctx,int flags);
int EVP_MD_CTX_test_flags(EVP_MD_CTX *ctx,int flags);
void EVP_CIPHER_CTX_set_flags(EVP_CIPHER_CTX *ctx,int flags);
void EVP_CIPHER_CTX_clear_flags(EVP_CIPHER_CTX *ctx,int flags);
int EVP_CIPHER_CTX_test_flags(EVP_CIPHER_CTX *ctx,int flags);
int pbe2_cmp_BSEARCH_CMP_FN(void *a_,void *b_);
int pbe_cmp(EVP_PBE_CTL **a,EVP_PBE_CTL **b);
void free_evp_pbe_ctl(EVP_PBE_CTL *pbe);
int EVP_PBE_alg_add_type(int pbe_type,int pbe_nid,int cipher_nid,int md_nid,EVP_PBE_KEYGEN *keygen);
int EVP_PBE_alg_add(int nid,EVP_CIPHER *cipher,EVP_MD *md,EVP_PBE_KEYGEN *keygen);
int EVP_PBE_find(int type,int pbe_nid,int *pcnid,int *pmnid,EVP_PBE_KEYGEN **pkeygen);
int EVP_PBE_CipherInit(ASN1_OBJECT *pbe_obj,char *pass,int passlen,ASN1_TYPE *param,EVP_CIPHER_CTX *ctx,int en_de);
void EVP_PBE_cleanup(void);
void PKCS5_PBE_add(void);
int PKCS5_PBE_keyivgen(EVP_CIPHER_CTX *cctx,char *pass,int passlen,ASN1_TYPE *param,EVP_CIPHER *cipher,EVP_MD *md,int en_de);
int PKCS5_PBKDF2_HMAC(char *pass,int passlen,uchar *salt,int saltlen,int iter,EVP_MD *digest,int keylen,uchar *out);
int PKCS5_PBKDF2_HMAC_SHA1(char *pass,int passlen,uchar *salt,int saltlen,int iter,int keylen,uchar *out);
int PKCS5_v2_PBKDF2_keyivgen(EVP_CIPHER_CTX *ctx,char *pass,int passlen,ASN1_TYPE *param,EVP_CIPHER *c,EVP_MD *md,int en_de);
int PKCS5_v2_PBE_keyivgen(EVP_CIPHER_CTX *ctx,char *pass,int passlen,ASN1_TYPE *param,EVP_CIPHER *c,EVP_MD *md,int en_de);
EVP_CIPHER * EVP_aes_128_cbc_hmac_sha1(void);
EVP_CIPHER * EVP_aes_256_cbc_hmac_sha1(void);
undefined4 EVP_aes_128_cbc_hmac_sha256(void);
EVP_CIPHER * EVP_aes_256_cbc_hmac_sha256(void);
int rc4_hmac_md5_ctrl(EVP_CIPHER_CTX *ctx,int type,int arg,void *ptr);
int rc4_hmac_md5_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t len);
int rc4_hmac_md5_init_key(EVP_CIPHER_CTX *ctx,uchar *inkey,uchar *iv,int enc);
EVP_CIPHER * EVP_rc4_hmac_md5(void);
int i2d_ASN1_OBJECT(ASN1_OBJECT *a,uchar **pp);
int a2d_ASN1_OBJECT(uchar *out,int olen,char *buf,int num);
int i2t_ASN1_OBJECT(char *buf,int buf_len,ASN1_OBJECT *a);
int i2a_ASN1_OBJECT(BIO *bp,ASN1_OBJECT *a);
ASN1_OBJECT * ASN1_OBJECT_new(void);
void ASN1_OBJECT_free(ASN1_OBJECT *a);
ASN1_OBJECT * c2i_ASN1_OBJECT(ASN1_OBJECT **a,uchar **pp,long len);
ASN1_OBJECT * d2i_ASN1_OBJECT(ASN1_OBJECT **a,uchar **pp,long length);
ASN1_OBJECT * ASN1_OBJECT_create(int nid,uchar *data,int len,char *sn,char *ln);
ASN1_INTEGER * ASN1_INTEGER_dup(ASN1_INTEGER *x);
int ASN1_INTEGER_cmp(ASN1_INTEGER *x,ASN1_INTEGER *y);
int i2c_ASN1_INTEGER(ASN1_INTEGER *a,uchar **pp);
ASN1_INTEGER * c2i_ASN1_INTEGER(ASN1_INTEGER **a,uchar **pp,long len);
ASN1_INTEGER * d2i_ASN1_UINTEGER(ASN1_INTEGER **a,uchar **pp,long length);
int ASN1_INTEGER_set(ASN1_INTEGER *a,long v);
long ASN1_INTEGER_get(ASN1_INTEGER *a);
ASN1_INTEGER * BN_to_ASN1_INTEGER(BIGNUM *bn,ASN1_INTEGER *ai);
BIGNUM * ASN1_INTEGER_to_BN(ASN1_INTEGER *ai,BIGNUM *bn);
int ASN1_TYPE_get(ASN1_TYPE *a);
void ASN1_TYPE_set(ASN1_TYPE *a,int type,void *value);
int ASN1_TYPE_set1(ASN1_TYPE *a,int type,void *value);
int ASN1_TYPE_cmp(ASN1_TYPE *a,ASN1_TYPE *b);
X509_SIG * d2i_X509_SIG(X509_SIG **a,uchar **in,long len);
int i2d_X509_SIG(X509_SIG *a,uchar **out);
X509_SIG * X509_SIG_new(void);
void X509_SIG_free(X509_SIG *a);
void asn1_primitive_clear(ASN1_VALUE **pval,ASN1_ITEM *it);
void asn1_item_clear(ASN1_VALUE **pval,ASN1_ITEM *it);
int ASN1_primitive_new(ASN1_VALUE **pval,ASN1_ITEM *it);
int asn1_item_ex_combine_new(ASN1_VALUE **pval,ASN1_ITEM *it,int combine);
int ASN1_item_ex_new(ASN1_VALUE **pval,ASN1_ITEM *it);
ASN1_VALUE * ASN1_item_new(ASN1_ITEM *it);
int ASN1_template_new(ASN1_VALUE **pval,ASN1_TEMPLATE *tt);
void ASN1_primitive_free(ASN1_VALUE **pval,ASN1_ITEM *it);
void asn1_item_combine_free(ASN1_VALUE **pval,ASN1_ITEM *it,int combine);
void ASN1_item_free(ASN1_VALUE *val,ASN1_ITEM *it);
void ASN1_item_ex_free(ASN1_VALUE **pval,ASN1_ITEM *it);
void ASN1_template_free(ASN1_VALUE **pval,ASN1_TEMPLATE *tt);
int der_cmp(void *a,void *b);
int asn1_ex_i2c(ASN1_VALUE **pval,uchar *cout,int *putype,ASN1_ITEM *it);
int asn1_i2d_ex_primitive(ASN1_VALUE **pval,uchar **out,ASN1_ITEM *it,int tag,int aclass);
int ASN1_item_ex_i2d(ASN1_VALUE **pval,uchar **out,ASN1_ITEM *it,int tag,int aclass);
int asn1_item_flags_i2d(ASN1_VALUE *val,uchar **out,ASN1_ITEM *it,int flags);
int ASN1_item_ndef_i2d(ASN1_VALUE *val,uchar **out,ASN1_ITEM *it);
int ASN1_item_i2d(ASN1_VALUE *val,uchar **out,ASN1_ITEM *it);
int asn1_template_ex_i2d(ASN1_VALUE **pval,uchar **out,ASN1_TEMPLATE *tt,int tag,int iclass);
int ASN1_template_i2d(ASN1_VALUE **pval,uchar **out,ASN1_TEMPLATE *tt);
int asn1_check_tlen(long *olen,int *otag,uchar *oclass,char *inf,char *cst,uchar **in,long len,int exptag,int expclass,char opt,ASN1_TLC *ctx);
int asn1_collect(BUF_MEM *buf,uchar **in,long len,char inf,int tag,int aclass,int depth);
ulong ASN1_tag2bit(int tag);
int asn1_ex_c2i(ASN1_VALUE **pval,uchar *cont,int len,int utype,char *free_cont,ASN1_ITEM *it);
int asn1_d2i_ex_primitive(ASN1_VALUE **pval,uchar **in,long inlen,ASN1_ITEM *it,int tag,int aclass,char opt,ASN1_TLC *ctx);
int ASN1_item_ex_d2i(ASN1_VALUE **pval,uchar **in,long len,ASN1_ITEM *it,int tag,int aclass,char opt,ASN1_TLC *ctx);
ASN1_VALUE * ASN1_item_d2i(ASN1_VALUE **pval,uchar **in,long len,ASN1_ITEM *it);
int asn1_template_noexp_d2i(ASN1_VALUE **val,uchar **in,long len,ASN1_TEMPLATE *tt,char opt,ASN1_TLC *ctx);
int asn1_template_ex_d2i(ASN1_VALUE **val,uchar **in,long inlen,ASN1_TEMPLATE *tt,char opt,ASN1_TLC *ctx);
int ASN1_template_d2i(ASN1_VALUE **pval,uchar **in,long len,ASN1_TEMPLATE *tt);
int asn1_get_choice_selector(ASN1_VALUE **pval,ASN1_ITEM *it);
int asn1_set_choice_selector(ASN1_VALUE **pval,int value,ASN1_ITEM *it);
int asn1_do_lock(ASN1_VALUE **pval,int op,ASN1_ITEM *it);
void asn1_enc_init(ASN1_VALUE **pval,ASN1_ITEM *it);
void asn1_enc_free(ASN1_VALUE **pval,ASN1_ITEM *it);
int asn1_enc_save(ASN1_VALUE **pval,uchar *in,int inlen,ASN1_ITEM *it);
int asn1_enc_restore(int *len,uchar **out,ASN1_VALUE **pval,ASN1_ITEM *it);
ASN1_VALUE ** asn1_get_field_ptr(ASN1_VALUE **pval,ASN1_TEMPLATE *tt);
ASN1_TEMPLATE * asn1_do_adb(ASN1_VALUE **pval,ASN1_TEMPLATE *tt,int nullerr);
ASN1_INTEGER * d2i_ASN1_INTEGER(ASN1_INTEGER **a,uchar **in,long len);
int i2d_ASN1_INTEGER(ASN1_INTEGER *a,uchar **out);
ASN1_INTEGER * ASN1_INTEGER_new(void);
void ASN1_INTEGER_free(ASN1_INTEGER *a);
ASN1_ENUMERATED * d2i_ASN1_ENUMERATED(ASN1_ENUMERATED **a,uchar **in,long len);
int i2d_ASN1_ENUMERATED(ASN1_ENUMERATED *a,uchar **out);
ASN1_ENUMERATED * ASN1_ENUMERATED_new(void);
void ASN1_ENUMERATED_free(ASN1_ENUMERATED *a);
ASN1_BIT_STRING * d2i_ASN1_BIT_STRING(ASN1_BIT_STRING **a,uchar **in,long len);
int i2d_ASN1_BIT_STRING(ASN1_BIT_STRING *a,uchar **out);
ASN1_BIT_STRING * ASN1_BIT_STRING_new(void);
void ASN1_BIT_STRING_free(ASN1_BIT_STRING *a);
ASN1_OCTET_STRING * d2i_ASN1_OCTET_STRING(ASN1_OCTET_STRING **a,uchar **in,long len);
int i2d_ASN1_OCTET_STRING(ASN1_OCTET_STRING *a,uchar **out);
ASN1_OCTET_STRING * ASN1_OCTET_STRING_new(void);
void ASN1_OCTET_STRING_free(ASN1_OCTET_STRING *a);
ASN1_NULL * d2i_ASN1_NULL(ASN1_NULL **a,uchar **in,long len);
int i2d_ASN1_NULL(ASN1_NULL *a,uchar **out);
ASN1_NULL * ASN1_NULL_new(void);
void ASN1_NULL_free(ASN1_NULL *a);
ASN1_UTF8STRING * d2i_ASN1_UTF8STRING(ASN1_UTF8STRING **a,uchar **in,long len);
int i2d_ASN1_UTF8STRING(ASN1_UTF8STRING *a,uchar **out);
ASN1_UTF8STRING * ASN1_UTF8STRING_new(void);
void ASN1_UTF8STRING_free(ASN1_UTF8STRING *a);
ASN1_PRINTABLESTRING * d2i_ASN1_PRINTABLESTRING(ASN1_PRINTABLESTRING **a,uchar **in,long len);
int i2d_ASN1_PRINTABLESTRING(ASN1_PRINTABLESTRING *a,uchar **out);
ASN1_PRINTABLESTRING * ASN1_PRINTABLESTRING_new(void);
void ASN1_PRINTABLESTRING_free(ASN1_PRINTABLESTRING *a);
ASN1_T61STRING * d2i_ASN1_T61STRING(ASN1_T61STRING **a,uchar **in,long len);
int i2d_ASN1_T61STRING(ASN1_T61STRING *a,uchar **out);
ASN1_T61STRING * ASN1_T61STRING_new(void);
void ASN1_T61STRING_free(ASN1_T61STRING *a);
ASN1_IA5STRING * d2i_ASN1_IA5STRING(ASN1_IA5STRING **a,uchar **in,long len);
int i2d_ASN1_IA5STRING(ASN1_IA5STRING *a,uchar **out);
ASN1_IA5STRING * ASN1_IA5STRING_new(void);
void ASN1_IA5STRING_free(ASN1_IA5STRING *a);
ASN1_GENERALSTRING * d2i_ASN1_GENERALSTRING(ASN1_GENERALSTRING **a,uchar **in,long len);
int i2d_ASN1_GENERALSTRING(ASN1_GENERALSTRING *a,uchar **out);
ASN1_GENERALSTRING * ASN1_GENERALSTRING_new(void);
void ASN1_GENERALSTRING_free(ASN1_GENERALSTRING *a);
ASN1_UTCTIME * d2i_ASN1_UTCTIME(ASN1_UTCTIME **a,uchar **in,long len);
int i2d_ASN1_UTCTIME(ASN1_UTCTIME *a,uchar **out);
ASN1_UTCTIME * ASN1_UTCTIME_new(void);
void ASN1_UTCTIME_free(ASN1_UTCTIME *a);
ASN1_GENERALIZEDTIME * d2i_ASN1_GENERALIZEDTIME(ASN1_GENERALIZEDTIME **a,uchar **in,long len);
int i2d_ASN1_GENERALIZEDTIME(ASN1_GENERALIZEDTIME *a,uchar **out);
ASN1_GENERALIZEDTIME * ASN1_GENERALIZEDTIME_new(void);
void ASN1_GENERALIZEDTIME_free(ASN1_GENERALIZEDTIME *a);
ASN1_VISIBLESTRING * d2i_ASN1_VISIBLESTRING(ASN1_VISIBLESTRING **a,uchar **in,long len);
int i2d_ASN1_VISIBLESTRING(ASN1_VISIBLESTRING *a,uchar **out);
ASN1_VISIBLESTRING * ASN1_VISIBLESTRING_new(void);
void ASN1_VISIBLESTRING_free(ASN1_VISIBLESTRING *a);
ASN1_UNIVERSALSTRING * d2i_ASN1_UNIVERSALSTRING(ASN1_UNIVERSALSTRING **a,uchar **in,long len);
int i2d_ASN1_UNIVERSALSTRING(ASN1_UNIVERSALSTRING *a,uchar **out);
ASN1_UNIVERSALSTRING * ASN1_UNIVERSALSTRING_new(void);
void ASN1_UNIVERSALSTRING_free(ASN1_UNIVERSALSTRING *a);
ASN1_BMPSTRING * d2i_ASN1_BMPSTRING(ASN1_BMPSTRING **a,uchar **in,long len);
int i2d_ASN1_BMPSTRING(ASN1_BMPSTRING *a,uchar **out);
ASN1_BMPSTRING * ASN1_BMPSTRING_new(void);
void ASN1_BMPSTRING_free(ASN1_BMPSTRING *a);
ASN1_TYPE * d2i_ASN1_TYPE(ASN1_TYPE **a,uchar **in,long len);
int i2d_ASN1_TYPE(ASN1_TYPE *a,uchar **out);
ASN1_TYPE * ASN1_TYPE_new(void);
void ASN1_TYPE_free(ASN1_TYPE *a);
ASN1_STRING * d2i_ASN1_PRINTABLE(ASN1_STRING **a,uchar **in,long len);
int i2d_ASN1_PRINTABLE(ASN1_STRING *a,uchar **out);
ASN1_STRING * ASN1_PRINTABLE_new(void);
void ASN1_PRINTABLE_free(ASN1_STRING *a);
ASN1_STRING * d2i_DISPLAYTEXT(ASN1_STRING **a,uchar **in,long len);
int i2d_DISPLAYTEXT(ASN1_STRING *a,uchar **out);
ASN1_STRING * DISPLAYTEXT_new(void);
void DISPLAYTEXT_free(ASN1_STRING *a);
ASN1_STRING * d2i_DIRECTORYSTRING(ASN1_STRING **a,uchar **in,long len);
int i2d_DIRECTORYSTRING(ASN1_STRING *a,uchar **out);
ASN1_STRING * DIRECTORYSTRING_new(void);
void DIRECTORYSTRING_free(ASN1_STRING *a);
ASN1_SEQUENCE_ANY * d2i_ASN1_SEQUENCE_ANY(ASN1_SEQUENCE_ANY **a,uchar **in,long len);
int i2d_ASN1_SEQUENCE_ANY(ASN1_SEQUENCE_ANY *a,uchar **out);
ASN1_SEQUENCE_ANY * d2i_ASN1_SET_ANY(ASN1_SEQUENCE_ANY **a,uchar **in,long len);
int i2d_ASN1_SET_ANY(ASN1_SEQUENCE_ANY *a,uchar **out);
int ASN1_const_check_infinite_end(uchar **p,long len);
int ASN1_check_infinite_end(uchar **p,long len);
int _asn1_Finish(ASN1_const_CTX *c);
int ASN1_get_object(uchar **pp,long *plength,int *ptag,int *pclass,long omax);
void ASN1_put_object(uchar **pp,int constructed,int length,int tag,int xclass);
int ASN1_put_eoc(uchar **pp);
int ASN1_object_size(int constructed,int length,int tag);
int asn1_Finish(ASN1_CTX *c);
int asn1_const_Finish(ASN1_const_CTX *c);
int asn1_GetSequence(ASN1_const_CTX *c,long *length);
int ASN1_STRING_set(ASN1_STRING *str,void *_data,int len);
int ASN1_STRING_copy(ASN1_STRING *dst,ASN1_STRING *str);
void ASN1_STRING_set0(ASN1_STRING *str,void *data,int len);
ASN1_STRING * ASN1_STRING_type_new(int type);
ASN1_STRING * ASN1_STRING_new(void);
void ASN1_STRING_free(ASN1_STRING *a);
ASN1_STRING * ASN1_STRING_dup(ASN1_STRING *str);
void ASN1_STRING_clear_free(ASN1_STRING *a);
int ASN1_STRING_cmp(ASN1_STRING *a,ASN1_STRING *b);
void asn1_add_error(uchar *address,int offset);
int ASN1_STRING_length(ASN1_STRING *x);
void ASN1_STRING_length_set(ASN1_STRING *x,int len);
int ASN1_STRING_type(ASN1_STRING *x);
uchar * ASN1_STRING_data(ASN1_STRING *x);
int ASN1_TYPE_set_octetstring(ASN1_TYPE *a,uchar *data,int len);
int ASN1_TYPE_get_octetstring(ASN1_TYPE *a,uchar *data,int max_len);
int ASN1_TYPE_set_int_octetstring(ASN1_TYPE *a,long num,uchar *data,int len);
int ASN1_TYPE_get_int_octetstring(ASN1_TYPE *a,long *num,uchar *data,int max_len);
PBEPARAM * d2i_PBEPARAM(PBEPARAM **a,uchar **in,long len);
int i2d_PBEPARAM(PBEPARAM *a,uchar **out);
PBEPARAM * PBEPARAM_new(void);
void PBEPARAM_free(PBEPARAM *a);
int PKCS5_pbe_set0_algor(X509_ALGOR *algor,int alg,int iter,uchar *salt,int saltlen);
X509_ALGOR * PKCS5_pbe_set(int alg,int iter,uchar *salt,int saltlen);
PBE2PARAM * d2i_PBE2PARAM(PBE2PARAM **a,uchar **in,long len);
int i2d_PBE2PARAM(PBE2PARAM *a,uchar **out);
PBE2PARAM * PBE2PARAM_new(void);
void PBE2PARAM_free(PBE2PARAM *a);
PBKDF2PARAM * d2i_PBKDF2PARAM(PBKDF2PARAM **a,uchar **in,long len);
int i2d_PBKDF2PARAM(PBKDF2PARAM *a,uchar **out);
PBKDF2PARAM * PBKDF2PARAM_new(void);
void PBKDF2PARAM_free(PBKDF2PARAM *a);
X509_ALGOR * PKCS5_pbkdf2_set(int iter,uchar *salt,int saltlen,int prf_nid,int keylen);
X509_ALGOR *PKCS5_pbe2_set_iv(EVP_CIPHER *cipher,int iter,uchar *salt,int saltlen,uchar *aiv,int prf_nid);
X509_ALGOR * PKCS5_pbe2_set(EVP_CIPHER *cipher,int iter,uchar *salt,int saltlen);
RSA * pkey_get_rsa(EVP_PKEY *key,RSA **rsa);
DSA * pkey_get_dsa(EVP_PKEY *key,DSA **dsa);
EC_KEY * pkey_get_eckey(EVP_PKEY *key,EC_KEY **eckey);
X509_REQ * PEM_read_bio_X509_REQ(BIO *bp,X509_REQ **x,pem_password_cb *cb,void *u);
X509_REQ * PEM_read_X509_REQ(FILE *fp,X509_REQ **x,pem_password_cb *cb,void *u);
int PEM_write_bio_X509_REQ(BIO *bp,X509_REQ *x);
int PEM_write_X509_REQ(FILE *fp,X509_REQ *x);
int PEM_write_bio_X509_REQ_NEW(BIO *bp,X509_REQ *x);
int PEM_write_X509_REQ_NEW(FILE *fp,X509_REQ *x);
X509_CRL * PEM_read_bio_X509_CRL(BIO *bp,X509_CRL **x,pem_password_cb *cb,void *u);
X509_CRL * PEM_read_X509_CRL(FILE *fp,X509_CRL **x,pem_password_cb *cb,void *u);
int PEM_write_bio_X509_CRL(BIO *bp,X509_CRL *x);
int PEM_write_X509_CRL(FILE *fp,X509_CRL *x);
PKCS7 * PEM_read_bio_PKCS7(BIO *bp,PKCS7 **x,pem_password_cb *cb,void *u);
PKCS7 * PEM_read_PKCS7(FILE *fp,PKCS7 **x,pem_password_cb *cb,void *u);
int PEM_write_bio_PKCS7(BIO *bp,PKCS7 *x);
int PEM_write_PKCS7(FILE *fp,PKCS7 *x);
NETSCAPE_CERT_SEQUENCE *PEM_read_bio_NETSCAPE_CERT_SEQUENCE(BIO *bp,NETSCAPE_CERT_SEQUENCE **x,pem_password_cb *cb,void *u);
NETSCAPE_CERT_SEQUENCE *PEM_read_NETSCAPE_CERT_SEQUENCE(FILE *fp,NETSCAPE_CERT_SEQUENCE **x,pem_password_cb *cb,void *u);
int PEM_write_bio_NETSCAPE_CERT_SEQUENCE(BIO *bp,NETSCAPE_CERT_SEQUENCE *x);
int PEM_write_NETSCAPE_CERT_SEQUENCE(FILE *fp,NETSCAPE_CERT_SEQUENCE *x);
RSA * PEM_read_bio_RSAPrivateKey(BIO *bp,RSA **rsa,pem_password_cb *cb,void *u);
RSA * PEM_read_RSAPrivateKey(FILE *fp,RSA **rsa,pem_password_cb *cb,void *u);
int PEM_write_bio_RSAPrivateKey(BIO *bp,RSA *x,EVP_CIPHER *enc,uchar *kstr,int klen,pem_password_cb *cb,void *u);
int PEM_write_RSAPrivateKey(FILE *fp,RSA *x,EVP_CIPHER *enc,uchar *kstr,int klen,pem_password_cb *cb,void *u);
RSA * PEM_read_bio_RSAPublicKey(BIO *bp,RSA **x,pem_password_cb *cb,void *u);
RSA * PEM_read_RSAPublicKey(FILE *fp,RSA **x,pem_password_cb *cb,void *u);
int PEM_write_bio_RSAPublicKey(BIO *bp,RSA *x);
int PEM_write_RSAPublicKey(FILE *fp,RSA *x);
RSA * PEM_read_bio_RSA_PUBKEY(BIO *bp,RSA **x,pem_password_cb *cb,void *u);
RSA * PEM_read_RSA_PUBKEY(FILE *fp,RSA **x,pem_password_cb *cb,void *u);
int PEM_write_bio_RSA_PUBKEY(BIO *bp,RSA *x);
int PEM_write_RSA_PUBKEY(FILE *fp,RSA *x);
DSA * PEM_read_bio_DSAPrivateKey(BIO *bp,DSA **dsa,pem_password_cb *cb,void *u);
int PEM_write_bio_DSAPrivateKey(BIO *bp,DSA *x,EVP_CIPHER *enc,uchar *kstr,int klen,pem_password_cb *cb,void *u);
int PEM_write_DSAPrivateKey(FILE *fp,DSA *x,EVP_CIPHER *enc,uchar *kstr,int klen,pem_password_cb *cb,void *u);
DSA * PEM_read_bio_DSA_PUBKEY(BIO *bp,DSA **x,pem_password_cb *cb,void *u);
DSA * PEM_read_DSA_PUBKEY(FILE *fp,DSA **x,pem_password_cb *cb,void *u);
int PEM_write_bio_DSA_PUBKEY(BIO *bp,DSA *x);
int PEM_write_DSA_PUBKEY(FILE *fp,DSA *x);
DSA * PEM_read_DSAPrivateKey(FILE *fp,DSA **dsa,pem_password_cb *cb,void *u);
DSA * PEM_read_bio_DSAparams(BIO *bp,DSA **x,pem_password_cb *cb,void *u);
DSA * PEM_read_DSAparams(FILE *fp,DSA **x,pem_password_cb *cb,void *u);
int PEM_write_bio_DSAparams(BIO *bp,DSA *x);
int PEM_write_DSAparams(FILE *fp,DSA *x);
EC_KEY * PEM_read_bio_ECPrivateKey(BIO *bp,EC_KEY **key,pem_password_cb *cb,void *u);
EC_GROUP * PEM_read_bio_ECPKParameters(BIO *bp,EC_GROUP **x,pem_password_cb *cb,void *u);
EC_GROUP * PEM_read_ECPKParameters(FILE *fp,EC_GROUP **x,pem_password_cb *cb,void *u);
int PEM_write_bio_ECPKParameters(BIO *bp,EC_GROUP *x);
int PEM_write_ECPKParameters(FILE *fp,EC_GROUP *x);
int PEM_write_bio_ECPrivateKey(BIO *bp,EC_KEY *x,EVP_CIPHER *enc,uchar *kstr,int klen,pem_password_cb *cb,void *u);
int PEM_write_ECPrivateKey(FILE *fp,EC_KEY *x,EVP_CIPHER *enc,uchar *kstr,int klen,pem_password_cb *cb,void *u);
EC_KEY * PEM_read_bio_EC_PUBKEY(BIO *bp,EC_KEY **x,pem_password_cb *cb,void *u);
EC_KEY * PEM_read_EC_PUBKEY(FILE *fp,EC_KEY **x,pem_password_cb *cb,void *u);
int PEM_write_bio_EC_PUBKEY(BIO *bp,EC_KEY *x);
int PEM_write_EC_PUBKEY(FILE *fp,EC_KEY *x);
EC_KEY * PEM_read_ECPrivateKey(FILE *fp,EC_KEY **eckey,pem_password_cb *cb,void *u);
int PEM_write_bio_DHparams(BIO *bp,DH *x);
int PEM_write_DHparams(FILE *fp,DH *x);
int PEM_write_bio_DHxparams(BIO *bp,DH *x);
int PEM_write_DHxparams(FILE *fp,DH *x);
EVP_PKEY * PEM_read_bio_PUBKEY(BIO *bp,EVP_PKEY **x,pem_password_cb *cb,void *u);
EVP_PKEY * PEM_read_PUBKEY(FILE *fp,EVP_PKEY **x,pem_password_cb *cb,void *u);
int PEM_write_bio_PUBKEY(BIO *bp,EVP_PKEY *x);
int PEM_write_PUBKEY(FILE *fp,EVP_PKEY *x);
void * PEM_ASN1_read_bio(d2i_of_void *d2i,char *name,BIO *bp,void **x,pem_password_cb *cb,void *u);
EVP_PKEY * PEM_read_bio_PrivateKey(BIO *bp,EVP_PKEY **x,pem_password_cb *cb,void *u);
int PEM_write_bio_PrivateKey(BIO *bp,EVP_PKEY *x,EVP_CIPHER *enc,uchar *kstr,int klen,pem_password_cb *cb,void *u);
EVP_PKEY * PEM_read_bio_Parameters(BIO *bp,EVP_PKEY **x);
int PEM_write_bio_Parameters(BIO *bp,EVP_PKEY *x);
EVP_PKEY * PEM_read_PrivateKey(FILE *fp,EVP_PKEY **x,pem_password_cb *cb,void *u);
int PEM_write_PrivateKey(FILE *fp,EVP_PKEY *x,EVP_CIPHER *enc,uchar *kstr,int klen,pem_password_cb *cb,void *u);
DH * PEM_read_bio_DHparams(BIO *bp,DH **x,pem_password_cb *cb,void *u);
DH * PEM_read_DHparams(FILE *fp,DH **x,pem_password_cb *cb,void *u);
int pk7_cb(int operation,ASN1_VALUE **pval,ASN1_ITEM *it,void *exarg);
int si_cb(int operation,ASN1_VALUE **pval,ASN1_ITEM *it,void *exarg);
int ri_cb(int operation,ASN1_VALUE **pval,ASN1_ITEM *it,void *exarg);
PKCS7 * d2i_PKCS7(PKCS7 **a,uchar **in,long len);
int i2d_PKCS7(PKCS7 *a,uchar **out);
PKCS7 * PKCS7_new(void);
void PKCS7_free(PKCS7 *a);
int i2d_PKCS7_NDEF(PKCS7 *a,uchar **out);
PKCS7 * PKCS7_dup(PKCS7 *x);
PKCS7_SIGNED * d2i_PKCS7_SIGNED(PKCS7_SIGNED **a,uchar **in,long len);
int i2d_PKCS7_SIGNED(PKCS7_SIGNED *a,uchar **out);
PKCS7_SIGNED * PKCS7_SIGNED_new(void);
void PKCS7_SIGNED_free(PKCS7_SIGNED *a);
PKCS7_SIGNER_INFO * d2i_PKCS7_SIGNER_INFO(PKCS7_SIGNER_INFO **a,uchar **in,long len);
int i2d_PKCS7_SIGNER_INFO(PKCS7_SIGNER_INFO *a,uchar **out);
PKCS7_SIGNER_INFO * PKCS7_SIGNER_INFO_new(void);
void PKCS7_SIGNER_INFO_free(PKCS7_SIGNER_INFO *a);
PKCS7_ISSUER_AND_SERIAL *d2i_PKCS7_ISSUER_AND_SERIAL(PKCS7_ISSUER_AND_SERIAL **a,uchar **in,long len);
int i2d_PKCS7_ISSUER_AND_SERIAL(PKCS7_ISSUER_AND_SERIAL *a,uchar **out);
PKCS7_ISSUER_AND_SERIAL * PKCS7_ISSUER_AND_SERIAL_new(void);
void PKCS7_ISSUER_AND_SERIAL_free(PKCS7_ISSUER_AND_SERIAL *a);
PKCS7_ENVELOPE * d2i_PKCS7_ENVELOPE(PKCS7_ENVELOPE **a,uchar **in,long len);
int i2d_PKCS7_ENVELOPE(PKCS7_ENVELOPE *a,uchar **out);
PKCS7_ENVELOPE * PKCS7_ENVELOPE_new(void);
void PKCS7_ENVELOPE_free(PKCS7_ENVELOPE *a);
PKCS7_RECIP_INFO * d2i_PKCS7_RECIP_INFO(PKCS7_RECIP_INFO **a,uchar **in,long len);
int i2d_PKCS7_RECIP_INFO(PKCS7_RECIP_INFO *a,uchar **out);
PKCS7_RECIP_INFO * PKCS7_RECIP_INFO_new(void);
void PKCS7_RECIP_INFO_free(PKCS7_RECIP_INFO *a);
PKCS7_ENC_CONTENT * d2i_PKCS7_ENC_CONTENT(PKCS7_ENC_CONTENT **a,uchar **in,long len);
int i2d_PKCS7_ENC_CONTENT(PKCS7_ENC_CONTENT *a,uchar **out);
PKCS7_ENC_CONTENT * PKCS7_ENC_CONTENT_new(void);
void PKCS7_ENC_CONTENT_free(PKCS7_ENC_CONTENT *a);
PKCS7_SIGN_ENVELOPE * d2i_PKCS7_SIGN_ENVELOPE(PKCS7_SIGN_ENVELOPE **a,uchar **in,long len);
int i2d_PKCS7_SIGN_ENVELOPE(PKCS7_SIGN_ENVELOPE *a,uchar **out);
PKCS7_SIGN_ENVELOPE * PKCS7_SIGN_ENVELOPE_new(void);
void PKCS7_SIGN_ENVELOPE_free(PKCS7_SIGN_ENVELOPE *a);
PKCS7_ENCRYPT * d2i_PKCS7_ENCRYPT(PKCS7_ENCRYPT **a,uchar **in,long len);
int i2d_PKCS7_ENCRYPT(PKCS7_ENCRYPT *a,uchar **out);
PKCS7_ENCRYPT * PKCS7_ENCRYPT_new(void);
void PKCS7_ENCRYPT_free(PKCS7_ENCRYPT *a);
PKCS7_DIGEST * d2i_PKCS7_DIGEST(PKCS7_DIGEST **a,uchar **in,long len);
int i2d_PKCS7_DIGEST(PKCS7_DIGEST *a,uchar **out);
PKCS7_DIGEST * PKCS7_DIGEST_new(void);
void PKCS7_DIGEST_free(PKCS7_DIGEST *a);
int PKCS7_print_ctx(BIO *out,PKCS7 *x,int indent,ASN1_PCTX *pctx);
long PKCS7_ctrl(PKCS7 *p7,int cmd,long larg,char *parg);
int PKCS7_set_content(PKCS7 *p7,PKCS7 *p7_data);
int PKCS7_set_type(PKCS7 *p7,int type);
int PKCS7_content_new(PKCS7 *p7,int type);
int PKCS7_set0_type_other(PKCS7 *p7,int type,ASN1_TYPE *other);
int PKCS7_add_signer(PKCS7 *p7,PKCS7_SIGNER_INFO *psi);
int PKCS7_add_certificate(PKCS7 *p7,X509 *x509);
int PKCS7_add_crl(PKCS7 *p7,X509_CRL *crl);
int PKCS7_SIGNER_INFO_set(PKCS7_SIGNER_INFO *p7i,X509 *x509,EVP_PKEY *pkey,EVP_MD *dgst);
PKCS7_SIGNER_INFO * PKCS7_add_signature(PKCS7 *p7,X509 *x509,EVP_PKEY *pkey,EVP_MD *dgst);
int PKCS7_set_digest(PKCS7 *p7,EVP_MD *md);
stack_st_PKCS7_SIGNER_INFO * PKCS7_get_signer_info(PKCS7 *p7);
void PKCS7_SIGNER_INFO_get0_algs(PKCS7_SIGNER_INFO *si,EVP_PKEY **pk,X509_ALGOR **pdig,X509_ALGOR **psig);
void PKCS7_RECIP_INFO_get0_alg(PKCS7_RECIP_INFO *ri,X509_ALGOR **penc);
int PKCS7_add_recipient_info(PKCS7 *p7,PKCS7_RECIP_INFO *ri);
int PKCS7_RECIP_INFO_set(PKCS7_RECIP_INFO *p7i,X509 *x509);
PKCS7_RECIP_INFO * PKCS7_add_recipient(PKCS7 *p7,X509 *x509);
X509 * PKCS7_cert_from_signer_info(PKCS7 *p7,PKCS7_SIGNER_INFO *si);
int PKCS7_set_cipher(PKCS7 *p7,EVP_CIPHER *cipher);
int PKCS7_stream(uchar ***boundary,PKCS7 *p7);
int pkcs7_decrypt_rinfo(uchar **pek,int *peklen,PKCS7_RECIP_INFO *ri,EVP_PKEY *pkey);
ASN1_TYPE * get_attribute(stack_st_X509_ATTRIBUTE *sk,int nid);
int add_attribute(stack_st_X509_ATTRIBUTE **sk,int nid,int atrtype,void *value);
ASN1_OCTET_STRING * PKCS7_get_octet_string(PKCS7 *p7);
int PKCS7_bio_add_digest(BIO **pbio,X509_ALGOR *alg);
BIO * PKCS7_find_digest(EVP_MD_CTX **pmd,BIO *bio,int nid);
BIO * PKCS7_dataInit(PKCS7 *p7,BIO *bio);
BIO * PKCS7_dataDecode(PKCS7 *p7,EVP_PKEY *pkey,BIO *in_bio,X509 *pcert);
int PKCS7_SIGNER_INFO_sign(PKCS7_SIGNER_INFO *si);
PKCS7_ISSUER_AND_SERIAL * PKCS7_get_issuer_and_serial(PKCS7 *p7,int idx);
ASN1_TYPE * PKCS7_get_signed_attribute(PKCS7_SIGNER_INFO *si,int nid);
int PKCS7_dataFinal(PKCS7 *p7,BIO *bio);
ASN1_TYPE * PKCS7_get_attribute(PKCS7_SIGNER_INFO *si,int nid);
ASN1_OCTET_STRING * PKCS7_digest_from_attributes(stack_st_X509_ATTRIBUTE *sk);
int PKCS7_signatureVerify(BIO *bio,PKCS7 *p7,PKCS7_SIGNER_INFO *si,X509 *x509);
int PKCS7_dataVerify(X509_STORE *cert_store,X509_STORE_CTX *ctx,BIO *bio,PKCS7 *p7,PKCS7_SIGNER_INFO *si);
int PKCS7_set_signed_attributes(PKCS7_SIGNER_INFO *p7si,stack_st_X509_ATTRIBUTE *sk);
int PKCS7_set_attributes(PKCS7_SIGNER_INFO *p7si,stack_st_X509_ATTRIBUTE *sk);
int PKCS7_add_signed_attribute(PKCS7_SIGNER_INFO *p7si,int nid,int atrtype,void *value);
int PKCS7_add_attribute(PKCS7_SIGNER_INFO *p7si,int nid,int atrtype,void *value);
int PKCS7_add_attrib_smimecap(PKCS7_SIGNER_INFO *si,stack_st_X509_ALGOR *cap);
stack_st_X509_ALGOR * PKCS7_get_smimecap(PKCS7_SIGNER_INFO *si);
int PKCS7_simple_smimecap(stack_st_X509_ALGOR *sk,int nid,int arg);
int PKCS7_add_attrib_content_type(PKCS7_SIGNER_INFO *si,ASN1_OBJECT *coid);
int PKCS7_add0_attrib_signing_time(PKCS7_SIGNER_INFO *si,ASN1_TIME *t);
int PKCS7_add1_attrib_digest(PKCS7_SIGNER_INFO *si,uchar *md,int mdlen);
void PKCS12_PBE_add(void);
int PKCS12_PBE_keyivgen(EVP_CIPHER_CTX *ctx,char *pass,int passlen,ASN1_TYPE *param,EVP_CIPHER *cipher,EVP_MD *md,int en_de);
int PKCS12_key_gen_uni(uchar *pass,int passlen,uchar *salt,int saltlen,int id,int iter,int n,uchar *out,EVP_MD *md_type);
int PKCS12_key_gen_asc(char *pass,int passlen,uchar *salt,int saltlen,int id,int iter,int n,uchar *out,EVP_MD *md_type);
uchar * OPENSSL_asc2uni(char *asc,int asclen,uchar **uni,int *unilen);
char * OPENSSL_uni2asc(uchar *uni,int unilen);
int i2d_PKCS12_bio(BIO *bp,PKCS12 *p12);
int i2d_PKCS12_fp(FILE *fp,PKCS12 *p12);
PKCS12 * d2i_PKCS12_bio(BIO *bp,PKCS12 **p12);
PKCS12 * d2i_PKCS12_fp(FILE *fp,PKCS12 **p12);
PKCS12_SAFEBAG * PKCS12_x5092certbag(X509 *x509);
PKCS12_SAFEBAG * PKCS12_x509crl2certbag(X509_CRL *crl);
X509 * PKCS12_certbag2x509(PKCS12_SAFEBAG *bag);
X509_CRL * PKCS12_certbag2x509crl(PKCS12_SAFEBAG *bag);
PKCS8_PRIV_KEY_INFO * PKCS8_decrypt(X509_SIG *p8,char *pass,int passlen);
int CRYPTO_get_new_lockid(char *name);
int CRYPTO_num_locks(void);
_func_CRYPTO_dynlock_value_ptr_char_ptr_int * CRYPTO_get_dynlock_create_callback(void);
_func_void_int_CRYPTO_dynlock_value_ptr_char_ptr_int * CRYPTO_get_dynlock_lock_callback(void);
_func_void_CRYPTO_dynlock_value_ptr_char_ptr_int * CRYPTO_get_dynlock_destroy_callback(void);
void CRYPTO_set_dynlock_create_callback(_func_CRYPTO_dynlock_value_ptr_char_ptr_int *func);
void CRYPTO_set_dynlock_lock_callback(_func_void_int_CRYPTO_dynlock_value_ptr_char_ptr_int *func);
void CRYPTO_set_dynlock_destroy_callback(_func_void_CRYPTO_dynlock_value_ptr_char_ptr_int *func);
_func_void_int_int_char_ptr_int * CRYPTO_get_locking_callback(void);
_func_int_int_ptr_int_int_char_ptr_int * CRYPTO_get_add_lock_callback(void);
void CRYPTO_set_locking_callback(_func_void_int_int_char_ptr_int *func);
void CRYPTO_set_add_lock_callback(_func_int_int_ptr_int_int_char_ptr_int *func);
void CRYPTO_THREADID_set_numeric(CRYPTO_THREADID *id,ulong val);
void CRYPTO_THREADID_set_pointer(CRYPTO_THREADID *id,void *ptr);
int CRYPTO_THREADID_set_callback(_func_void_CRYPTO_THREADID_ptr *func);
_func_void_CRYPTO_THREADID_ptr * CRYPTO_THREADID_get_callback(void);
void CRYPTO_THREADID_current(CRYPTO_THREADID *id);
int CRYPTO_THREADID_cmp(CRYPTO_THREADID *a,CRYPTO_THREADID *b);
void CRYPTO_THREADID_cpy(CRYPTO_THREADID *dest,CRYPTO_THREADID *src);
ulong CRYPTO_THREADID_hash(CRYPTO_THREADID *id);
_func_ulong * CRYPTO_get_id_callback(void);
void CRYPTO_set_id_callback(_func_ulong *func);
ulong CRYPTO_thread_id(void);
char * CRYPTO_get_lock_name(int type);
ulong * OPENSSL_ia32cap_loc(void);
void OPENSSL_showfatal(char *fmta,...);
int OPENSSL_isservice(void);
void OpenSSLDie(char *file,int line,char *assertion);
void CRYPTO_lock(int mode,int type,char *file,int line);
int CRYPTO_get_new_dynlockid(void);
void CRYPTO_destroy_dynlockid(int i);
CRYPTO_dynlock_value * CRYPTO_get_dynlock_value(int i);
int CRYPTO_add_lock(int *pointer,int amount,int type,char *file,int line);
void * OPENSSL_stderr(void);
int CRYPTO_memcmp(void *in_a,void *in_b,size_t len);
void * default_malloc_ex(size_t __size);
void * default_realloc_ex(void *__ptr,size_t __size);
void * default_malloc_locked_ex(size_t __size);
int CRYPTO_set_mem_functions(_func_void_ptr_size_t *m,_func_void_ptr_void_ptr_size_t *r,_func_void_void_ptr *f);
int CRYPTO_set_mem_ex_functions(_func_void_ptr_size_t_char_ptr_int *m,_func_void_ptr_void_ptr_size_t_char_ptr_int *r,_func_void_void_ptr *f);
int CRYPTO_set_locked_mem_functions(_func_void_ptr_size_t *m,_func_void_void_ptr *f);
int CRYPTO_set_locked_mem_ex_functions(_func_void_ptr_size_t_char_ptr_int *m,_func_void_void_ptr *f);
int CRYPTO_set_mem_debug_functions(_func_void_void_ptr_int_char_ptr_int_int *m,_func_void_void_ptr_void_ptr_int_char_ptr_int_int *r,_func_void_void_ptr_int *f,_func_void_long *so,_func_long *go);
void CRYPTO_get_mem_functions(_func_void_ptr_size_t **m,_func_void_ptr_void_ptr_size_t **r,_func_void_void_ptr **f);
void CRYPTO_get_mem_ex_functions(_func_void_ptr_size_t_char_ptr_int **m,_func_void_ptr_void_ptr_size_t_char_ptr_int **r,_func_void_void_ptr **f);
void CRYPTO_get_locked_mem_functions(_func_void_ptr_size_t **m,_func_void_void_ptr **f);
void CRYPTO_get_locked_mem_ex_functions(_func_void_ptr_size_t_char_ptr_int **m,_func_void_void_ptr **f);
void CRYPTO_get_mem_debug_functions(_func_void_void_ptr_int_char_ptr_int_int **m,_func_void_void_ptr_void_ptr_int_char_ptr_int_int **r,_func_void_void_ptr_int **f,_func_void_long **so,_func_long **go);
void * CRYPTO_malloc_locked(int num,char *file,int line);
void CRYPTO_free_locked(void *str);
void * CRYPTO_malloc(int num,char *file,int line);
char * CRYPTO_strdup(char *str,char *file,int line);
void * CRYPTO_realloc(void *str,int num,char *file,int line);
void * CRYPTO_realloc_clean(void *str,int old_len,int num,char *file,int line);
void CRYPTO_free(void *str);
void * CRYPTO_remalloc(void *a,int num,char *file,int line);
void CRYPTO_set_mem_debug_options(long bits);
long CRYPTO_get_mem_debug_options(void);
int mem_LHASH_COMP(void *arg1,void *arg2);
ulong mem_LHASH_HASH(void *arg);
void cb_leak_LHASH_DOALL_ARG(void *arg1,void *arg2);
int app_info_LHASH_COMP(void *arg1,void *arg2);
void app_info_free(APP_INFO *inf);
ulong app_info_LHASH_HASH(void *arg);
APP_INFO * pop_info(void);
void print_leak_doall_arg(MEM *m,MEM_LEAK *l);
void print_leak_LHASH_DOALL_ARG(void *arg1,void *arg2);
int CRYPTO_mem_ctrl(int mode);
int CRYPTO_is_mem_check_on(void);
void CRYPTO_dbg_set_options(long bits);
long CRYPTO_dbg_get_options(void);
int CRYPTO_push_info_(char *info,char *file,int line);
int CRYPTO_pop_info(void);
int CRYPTO_remove_all_info(void);
void CRYPTO_dbg_malloc(void *addr,int num,char *file,int line,int before_p);
void CRYPTO_dbg_free(void *addr,int before_p);
void CRYPTO_dbg_realloc(void *addr1,void *addr2,int num,char *file,int line,int before_p);
void CRYPTO_mem_leaks(BIO *b);
void CRYPTO_mem_leaks_fp(FILE *fp);
void CRYPTO_mem_leaks_cb(CRYPTO_MEM_LEAK_CB *cb);
ulong ex_class_item_LHASH_HASH(void *arg);
int ex_class_item_LHASH_COMP(void *arg1,void *arg2);
void impl_check(void);
int int_new_class(void);
void def_cleanup_util_cb(CRYPTO_EX_DATA_FUNCS *funcs);
int ex_data_check(void);
EX_CLASS_ITEM * def_get_class(int class_index);
void int_cleanup(void);
void def_cleanup_cb(void *a_void);
int int_get_new_index(int class_index,long argl,void *argp,CRYPTO_EX_new *new_func,CRYPTO_EX_dup *dup_func,CRYPTO_EX_free *free_func);
CRYPTO_EX_DATA_IMPL * CRYPTO_get_ex_data_implementation(void);
int CRYPTO_set_ex_data_implementation(CRYPTO_EX_DATA_IMPL *i);
int CRYPTO_ex_data_new_class(void);
void CRYPTO_cleanup_all_ex_data(void);
int CRYPTO_get_ex_new_index(int class_index,long argl,void *argp,CRYPTO_EX_new *new_func,CRYPTO_EX_dup *dup_func,CRYPTO_EX_free *free_func);
int CRYPTO_new_ex_data(int class_index,void *obj,CRYPTO_EX_DATA *ad);
int CRYPTO_dup_ex_data(int class_index,CRYPTO_EX_DATA *to,CRYPTO_EX_DATA *from);
void CRYPTO_free_ex_data(int class_index,void *obj,CRYPTO_EX_DATA *ad);
int CRYPTO_set_ex_data(CRYPTO_EX_DATA *ad,int idx,void *val);
void * CRYPTO_get_ex_data(CRYPTO_EX_DATA *ad,int idx);
void int_free_ex_data(int class_index,void *obj,CRYPTO_EX_DATA *ad);
int int_dup_ex_data(int class_index,CRYPTO_EX_DATA *to,CRYPTO_EX_DATA *from);
int int_new_ex_data(int class_index,void *obj,CRYPTO_EX_DATA *ad);
void OPENSSL_init(void);
void ill_handler(int sig);
ulong OPENSSL_rdtsc(void);
int OPENSSL_atomic_add(int *param_1,int param_2);
void OPENSSL_cleanse(void *ptr,size_t len);
void _armv7_neon_probe(void);
undefined8 _armv7_tick(void);
void OPENSSL_wipe_cpu(void);
undefined4 OPENSSL_instrument_bus(void);
undefined4 OPENSSL_instrument_bus2(void);
int obj_name_LHASH_COMP(void *arg1,void *arg2);
int do_all_sorted_cmp(void *n1_,void *n2_);
ulong obj_name_LHASH_HASH(void *arg);
void name_funcs_free(NAME_FUNCS *ptr);
void do_all_fn_LHASH_DOALL_ARG(void *arg1,void *arg2);
void do_all_sorted_fn(OBJ_NAME *name,void *d_);
int OBJ_NAME_init(void);
int OBJ_NAME_new_index(_func_ulong_char_ptr *hash_func,_func_int_char_ptr_char_ptr *cmp_func,_func_void_char_ptr_int_char_ptr *free_func);
char * OBJ_NAME_get(char *name,int type);
int OBJ_NAME_add(char *name,int type,char *data);
int OBJ_NAME_remove(char *name,int type);
void names_lh_free_LHASH_DOALL(void *arg);
void OBJ_NAME_do_all(int type,_func_void_OBJ_NAME_ptr_void_ptr *fn,void *arg);
void OBJ_NAME_do_all_sorted(int type,_func_void_OBJ_NAME_ptr_void_ptr *fn,void *arg);
void OBJ_NAME_cleanup(int type);
void cleanup1_LHASH_DOALL(void *arg);
void cleanup2_LHASH_DOALL(void *arg);
void cleanup3_LHASH_DOALL(void *arg);
int added_obj_LHASH_COMP(void *arg1,void *arg2);
int ln_cmp_BSEARCH_CMP_FN(void *a_,void *b_);
int sn_cmp_BSEARCH_CMP_FN(void *a_,void *b_);
ulong added_obj_LHASH_HASH(void *arg);
int obj_cmp_BSEARCH_CMP_FN(void *a_,void *b_);
void check_defer(int nid);
void OBJ_cleanup(void);
int OBJ_new_nid(int num);
int OBJ_add_object(ASN1_OBJECT *obj);
ASN1_OBJECT * OBJ_nid2obj(int n);
char * OBJ_nid2sn(int n);
char * OBJ_nid2ln(int n);
void * OBJ_bsearch_ex_(void *key,void *base_,int num,int size,_func_int_void_ptr_void_ptr *cmp,int flags);
void * OBJ_bsearch_(void *key,void *base,int num,int size,_func_int_void_ptr_void_ptr *cmp);
int OBJ_obj2nid(ASN1_OBJECT *a);
int OBJ_obj2txt(char *buf,int buf_len,ASN1_OBJECT *a,int no_name);
int OBJ_ln2nid(char *s);
int OBJ_sn2nid(char *s);
ASN1_OBJECT * OBJ_txt2obj(char *s,int no_name);
int OBJ_txt2nid(char *s);
int OBJ_create(char *oid,char *sn,char *ln);
int OBJ_create_objects(BIO *in);
ASN1_OBJECT * OBJ_dup(ASN1_OBJECT *o);
int OBJ_cmp(ASN1_OBJECT *a,ASN1_OBJECT *b);
int sig_cmp_BSEARCH_CMP_FN(void *a_,void *b_);
int sig_sk_cmp(nid_triple **a,nid_triple **b);
int sigx_cmp(nid_triple **a,nid_triple **b);
int sigx_cmp_BSEARCH_CMP_FN(void *a_,void *b_);
void sid_free(nid_triple *tt);
int OBJ_find_sigid_algs(int signid,int *pdig_nid,int *ppkey_nid);
int OBJ_find_sigid_by_algs(int *psignid,int dig_nid,int pkey_nid);
int OBJ_add_sigid(int signid,int dig_id,int pkey_id);
void OBJ_sigid_free(void);
int HMAC_Init_ex(HMAC_CTX *ctx,void *key,int len,EVP_MD *md,ENGINE *impl);
int HMAC_Update(HMAC_CTX *ctx,uchar *data,size_t len);
int HMAC_Final(HMAC_CTX *ctx,uchar *md,uint *len);
void HMAC_CTX_init(HMAC_CTX *ctx);
int HMAC_Init(HMAC_CTX *ctx,void *key,int len,EVP_MD *md);
int HMAC_CTX_copy(HMAC_CTX *dctx,HMAC_CTX *sctx);
void HMAC_CTX_cleanup(HMAC_CTX *ctx);
uchar * HMAC(EVP_MD *evp_md,void *key,int key_len,uchar *d,size_t n,uchar *md,uint *md_len);
void HMAC_CTX_set_flags(HMAC_CTX *ctx,ulong flags);
char * AES_options(void);
int AES_set_encrypt_key(uchar *userKey,int bits,AES_KEY *key);
int AES_set_decrypt_key(uchar *userKey,int bits,AES_KEY *key);
void AES_cbc_encrypt(uchar *in,uchar *out,size_t len,AES_KEY *key,uchar *ivec,int enc);
void AES_encrypt(uchar *in,uchar *out,AES_KEY *key);
undefined8 _armv4_AES_encrypt(uint param_1,uint param_2,uint param_3,uint param_4);
int private_AES_set_encrypt_key(uchar *userKey,int bits,AES_KEY *key);
int private_AES_set_decrypt_key(uchar *userKey,int bits,AES_KEY *key);
undefined4 AES_set_enc2dec_key(undefined4 *param_1,undefined4 *param_2);
void AES_decrypt(uchar *in,uchar *out,AES_KEY *key);
undefined8 _armv4_AES_decrypt(uint param_1,uint param_2,uint param_3,uint param_4);
uint _bsaes_decrypt8(undefined4 param_1,undefined4 param_2);
uint _bsaes_encrypt8(undefined4 param_1,undefined4 param_2);
uint _bsaes_encrypt8_alt(undefined4 param_1,undefined4 param_2);
void _bsaes_key_convert(void);
void bsaes_cbc_encrypt(uchar *param_1,uchar *param_2,uint param_3,void *param_4,uint *param_5,undefined *param_6);
void bsaes_ctr32_encrypt_blocks(uint *param_1,uint *param_2,uint param_3,AES_KEY *param_4,undefined1 (*param_5) [16]);
void bsaes_xts_encrypt(undefined1 (*param_1) [16],uint *param_2,uint param_3,AES_KEY *param_4,AES_KEY *param_5,uchar *param_6);
void bsaes_xts_decrypt(undefined1 (*param_1) [16],undefined1 (*param_2) [16],uint param_3,AES_KEY *param_4,AES_KEY *param_5,uchar *param_6);
undefined4 aes_v8_set_encrypt_key(undefined1 (*param_1) [16],uint param_2,undefined8 *param_3);
int aes_v8_set_decrypt_key(undefined1 (*param_1) [16],uint param_2,undefined8 *param_3);
void aes_v8_encrypt(undefined1 (*param_1) [16],undefined8 *param_2,undefined8 *param_3);
void aes_v8_decrypt(undefined1 (*param_1) [16],undefined8 *param_2,undefined8 *param_3);
void aes_v8_cbc_encrypt(undefined1 (*param_1) [16],undefined8 *param_2,uint param_3,undefined1 (*param_4) [16],undefined1 (*param_5) [16],int param_6);
void aes_v8_ctr32_encrypt_blocks(undefined1 (*param_1) [16],undefined8 *param_2,uint param_3,undefined8 *param_4,undefined1 (*param_5) [16]);
void RC4(RC4_KEY *key,size_t len,uchar *indata,uchar *outdata);
void RC4_set_key(RC4_KEY *key,int len,uchar *data);
void CRYPTO_cbc128_encrypt(uchar *in,uchar *out,size_t len,void *key,uchar *ivec,block128_f block);
void CRYPTO_cbc128_decrypt(uchar *in,uchar *out,size_t len,void *key,uchar *ivec,block128_f block);
void CRYPTO_ctr128_encrypt(uchar *in,uchar *out,size_t len,void *key,uchar *ivec,uchar *ecount_buf,uint *num,block128_f block);
void CRYPTO_ctr128_encrypt_ctr32(uchar *in,uchar *out,size_t len,void *key,uchar *ivec,uchar *ecount_buf,uint *num,ctr128_f func);
void cfbr_encrypt_block(uchar *in,uchar *out,int nbits,void *key,uchar *ivec,int enc,block128_f block);
void CRYPTO_cfb128_encrypt(uchar *in,uchar *out,size_t len,void *key,uchar *ivec,int *num,int enc,block128_f block);
void CRYPTO_cfb128_1_encrypt(uchar *in,uchar *out,size_t bits,void *key,uchar *ivec,int *num,int enc,block128_f block);
void CRYPTO_cfb128_8_encrypt(uchar *in,uchar *out,size_t length,void *key,uchar *ivec,int *num,int enc,block128_f block);
void CRYPTO_ofb128_encrypt(uchar *in,uchar *out,size_t len,void *key,uchar *ivec,int *num,block128_f block);
void CRYPTO_gcm128_init(GCM128_CONTEXT *ctx,void *key,block128_f block);
void CRYPTO_gcm128_setiv(GCM128_CONTEXT *ctx,uchar *iv,size_t len);
int CRYPTO_gcm128_aad(GCM128_CONTEXT *ctx,uchar *aad,size_t len);
int CRYPTO_gcm128_encrypt(GCM128_CONTEXT *ctx,uchar *in,uchar *out,size_t len);
int CRYPTO_gcm128_decrypt(GCM128_CONTEXT *ctx,uchar *in,uchar *out,size_t len);
int CRYPTO_gcm128_encrypt_ctr32(GCM128_CONTEXT *ctx,uchar *in,uchar *out,size_t len,ctr128_f stream);
int CRYPTO_gcm128_decrypt_ctr32(GCM128_CONTEXT *ctx,uchar *in,uchar *out,size_t len,ctr128_f stream);
int CRYPTO_gcm128_finish(GCM128_CONTEXT *ctx,uchar *tag,size_t len);
void CRYPTO_gcm128_tag(GCM128_CONTEXT *ctx,uchar *tag,size_t len);
GCM128_CONTEXT * CRYPTO_gcm128_new(void *key,block128_f block);
void CRYPTO_gcm128_release(GCM128_CONTEXT *ctx);
void CRYPTO_ccm128_init(CCM128_CONTEXT *ctx,uint M,uint L,void *key,block128_f block);
int CRYPTO_ccm128_setiv(CCM128_CONTEXT *ctx,uchar *nonce,size_t nlen,size_t mlen);
void CRYPTO_ccm128_aad(CCM128_CONTEXT *ctx,uchar *aad,size_t alen);
int CRYPTO_ccm128_encrypt(CCM128_CONTEXT *ctx,uchar *inp,uchar *out,size_t len);
int CRYPTO_ccm128_decrypt(CCM128_CONTEXT *ctx,uchar *inp,uchar *out,size_t len);
int CRYPTO_ccm128_encrypt_ccm64(CCM128_CONTEXT *ctx,uchar *inp,uchar *out,size_t len,ccm128_f stream);
int CRYPTO_ccm128_decrypt_ccm64(CCM128_CONTEXT *ctx,uchar *inp,uchar *out,size_t len,ccm128_f stream);
size_t CRYPTO_ccm128_tag(CCM128_CONTEXT *ctx,uchar *tag,size_t len);
int CRYPTO_xts128_encrypt(XTS128_CONTEXT *ctx,uchar *iv,uchar *inp,uchar *out,size_t len,int enc);
size_t CRYPTO_128_wrap(void *key,uchar *iv,uchar *out,uchar *in,size_t inlen,block128_f block);
size_t CRYPTO_128_unwrap(void *key,uchar *iv,uchar *out,uchar *in,size_t inlen,block128_f block);
void rem_4bit_get(uint *param_1,int param_2);
void gcm_ghash_4bit(uint *param_1,int param_2,int param_3,int param_4);
void gcm_gmult_4bit(uint *param_1,int param_2);
void gcm_init_neon(undefined8 *param_1,undefined8 *param_2);
void gcm_gmult_neon(undefined8 *param_1,ulonglong *param_2,undefined8 *param_3);
void gcm_ghash_neon(undefined8 *param_1,ulonglong *param_2,undefined8 *param_3,int param_4);
void gcm_init_v8(undefined8 *param_1,undefined1 (*param_2) [16]);
void gcm_gmult_v8(undefined1 (*param_1) [16],undefined8 *param_2);
void gcm_ghash_v8(undefined1 (*param_1) [16],undefined8 *param_2,undefined1 (*param_3) [16],uint param_4);
int BN_uadd(BIGNUM *r,BIGNUM *a,BIGNUM *b);
int BN_usub(BIGNUM *r,BIGNUM *a,BIGNUM *b);
int BN_add(BIGNUM *r,BIGNUM *a,BIGNUM *b);
int BN_sub(BIGNUM *r,BIGNUM *a,BIGNUM *b);
uint * bn_expand_internal(BIGNUM *b,int words);
void BN_set_params(int mult,int high,int low,int mont);
int BN_get_params(int which);
BIGNUM * BN_value_one(void);
int BN_num_bits_word(uint l);
int BN_num_bits(BIGNUM *a);
void BN_clear_free(BIGNUM *a);
void BN_free(BIGNUM *a);
void BN_init(BIGNUM *a);
BIGNUM * BN_new(void);
BIGNUM * bn_expand2(BIGNUM *b,int words);
BIGNUM * BN_copy(BIGNUM *a,BIGNUM *b);
BIGNUM * BN_dup(BIGNUM *a);
BIGNUM * bn_dup_expand(BIGNUM *b,int words);
void BN_swap(BIGNUM *a,BIGNUM *b);
void BN_clear(BIGNUM *a);
uint BN_get_word(BIGNUM *a);
int BN_set_word(BIGNUM *a,uint w);
BIGNUM * BN_bin2bn(uchar *s,int len,BIGNUM *ret);
int BN_bn2bin(BIGNUM *a,uchar *to);
int BN_ucmp(BIGNUM *a,BIGNUM *b);
int BN_cmp(BIGNUM *a,BIGNUM *b);
int BN_set_bit(BIGNUM *a,int n);
int BN_clear_bit(BIGNUM *a,int n);
int BN_is_bit_set(BIGNUM *a,int n);
int BN_mask_bits(BIGNUM *a,int n);
void BN_set_negative(BIGNUM *a,int b);
int bn_cmp_words(uint *a,uint *b,int n);
int bn_cmp_part_words(uint *a,uint *b,int cl,int dl);
void BN_consttime_swap(uint condition,BIGNUM *a,BIGNUM *b,int nwords);
void BN_CTX_init(BN_CTX *ctx);
BN_CTX * BN_CTX_new(void);
void BN_CTX_free(BN_CTX *ctx);
void BN_CTX_start(BN_CTX *ctx);
void BN_CTX_end(BN_CTX *ctx);
BIGNUM * BN_CTX_get(BN_CTX *ctx);
uint bn_sub_part_words(uint *r,uint *a,uint *b,int cl,int dl);
uint bn_add_part_words(uint *r,uint *a,uint *b,int cl,int dl);
void bn_mul_normal(uint *r,uint *a,int na,uint *b,int nb);
void bn_mul_recursive(uint *r,uint *a,uint *b,int n2,int dna,int dnb,uint *t);
void bn_mul_high(uint *r,uint *a,uint *b,uint *l,int n2,uint *t);
void bn_mul_part_recursive(uint *r,uint *a,uint *b,int n,int tna,int tnb,uint *t);
int BN_mul(BIGNUM *r,BIGNUM *a,BIGNUM *b,BN_CTX *ctx);
void bn_mul_low_normal(uint *r,uint *a,uint *b,int n);
void bn_mul_low_recursive(uint *r,uint *a,uint *b,int n2,uint *t);
char * BN_bn2hex(BIGNUM *a);
char * BN_bn2dec(BIGNUM *a);
int BN_hex2bn(BIGNUM **bn,char *a);
int BN_dec2bn(BIGNUM **bn,char *a);
int BN_asc2bn(BIGNUM **bn,char *a);
int BN_print(BIO *bp,BIGNUM *a);
int BN_print_fp(FILE *fp,BIGNUM *a);
char * BN_options(void);
int BN_lshift1(BIGNUM *r,BIGNUM *a);
int BN_rshift1(BIGNUM *r,BIGNUM *a);
int BN_lshift(BIGNUM *r,BIGNUM *a,int n);
int BN_rshift(BIGNUM *r,BIGNUM *a,int n);
uint BN_mod_word(BIGNUM *a,uint w);
uint BN_div_word(BIGNUM *a,uint w);
int BN_sub_word(BIGNUM *a,uint w);
int BN_add_word(BIGNUM *a,uint w);
int BN_mul_word(BIGNUM *a,uint w);
void BN_BLINDING_free(BN_BLINDING *r);
BN_BLINDING * BN_BLINDING_new(BIGNUM *A,BIGNUM *Ai,BIGNUM *mod);
int BN_BLINDING_invert_ex(BIGNUM *n,BIGNUM *r,BN_BLINDING *b,BN_CTX *ctx);
int BN_BLINDING_invert(BIGNUM *n,BN_BLINDING *b,BN_CTX *ctx);
ulong BN_BLINDING_get_thread_id(BN_BLINDING *b);
void BN_BLINDING_set_thread_id(BN_BLINDING *b,ulong n);
CRYPTO_THREADID * BN_BLINDING_thread_id(BN_BLINDING *b);
ulong BN_BLINDING_get_flags(BN_BLINDING *b);
void BN_BLINDING_set_flags(BN_BLINDING *b,ulong flags);
BN_BLINDING *BN_BLINDING_create_param(BN_BLINDING *b,BIGNUM *e,BIGNUM *m,BN_CTX *ctx,_func_int_BIGNUM_ptr_BIGNUM_ptr_BIGNUM_ptr_BIGNUM_ptr_BN_CTX_ptr_BN_MONT_CTX_ptr*bn_mod_exp,BN_MONT_CTX *m_ctx);
int BN_BLINDING_update(BN_BLINDING *b,BN_CTX *ctx);
int BN_BLINDING_convert_ex(BIGNUM *n,BIGNUM *r,BN_BLINDING *b,BN_CTX *ctx);
int BN_BLINDING_convert(BIGNUM *n,BN_BLINDING *b,BN_CTX *ctx);
int BN_gcd(BIGNUM *r,BIGNUM *in_a,BIGNUM *in_b,BN_CTX *ctx);
BIGNUM * BN_mod_inverse(BIGNUM *in,BIGNUM *a,BIGNUM *n,BN_CTX *ctx);
uint bn_mul_add_words(uint *rp,uint *ap,int num,uint w);
uint bn_mul_words(uint *rp,uint *ap,int num,uint w);
void bn_sqr_words(uint *r,uint *a,int n);
uint bn_div_words(uint h,uint l,uint d);
uint bn_add_words(uint *r,uint *a,uint *b,int n);
uint bn_sub_words(uint *r,uint *a,uint *b,int n);
void bn_mul_comba8(uint *r,uint *a,uint *b);
void bn_mul_comba4(uint *r,uint *a,uint *b);
void bn_sqr_comba8(uint *r,uint *a);
void bn_sqr_comba4(uint *r,uint *a);
EC_GROUP * ec_asn1_pkparameters2group(ECPKPARAMETERS *params);
int EC_GROUP_get_basis_type(EC_GROUP *group);
int EC_GROUP_get_trinomial_basis(EC_GROUP *group,uint *k);
int EC_GROUP_get_pentanomial_basis(EC_GROUP *group,uint *k1,uint *k2,uint *k3);
X9_62_PENTANOMIAL * X9_62_PENTANOMIAL_new(void);
void X9_62_PENTANOMIAL_free(X9_62_PENTANOMIAL *a);
X9_62_CHARACTERISTIC_TWO * X9_62_CHARACTERISTIC_TWO_new(void);
void X9_62_CHARACTERISTIC_TWO_free(X9_62_CHARACTERISTIC_TWO *a);
ECPARAMETERS * ECPARAMETERS_new(void);
void ECPARAMETERS_free(ECPARAMETERS *a);
ECPKPARAMETERS * d2i_ECPKPARAMETERS(ECPKPARAMETERS **a,uchar **in,long len);
int i2d_ECPKPARAMETERS(ECPKPARAMETERS *a,uchar **out);
ECPKPARAMETERS * ECPKPARAMETERS_new(void);
void ECPKPARAMETERS_free(ECPKPARAMETERS *a);
ECPKPARAMETERS * ec_asn1_group2pkparameters(EC_GROUP *group,ECPKPARAMETERS *params);
EC_PRIVATEKEY * d2i_EC_PRIVATEKEY(EC_PRIVATEKEY **a,uchar **in,long len);
int i2d_EC_PRIVATEKEY(EC_PRIVATEKEY *a,uchar **out);
EC_PRIVATEKEY * EC_PRIVATEKEY_new(void);
void EC_PRIVATEKEY_free(EC_PRIVATEKEY *a);
EC_GROUP * d2i_ECPKParameters(EC_GROUP **a,uchar **in,long len);
int i2d_ECPKParameters(EC_GROUP *a,uchar **out);
EC_KEY * d2i_ECPrivateKey(EC_KEY **a,uchar **in,long len);
int i2d_ECPrivateKey(EC_KEY *a,uchar **out);
int i2d_ECParameters(EC_KEY *a,uchar **out);
EC_KEY * d2i_ECParameters(EC_KEY **a,uchar **in,long len);
EC_KEY * o2i_ECPublicKey(EC_KEY **a,uchar **in,long len);
int i2o_ECPublicKey(EC_KEY *a,uchar **out);
EC_KEY * EC_KEY_new(void);
void EC_KEY_free(EC_KEY *r);
EC_KEY * EC_KEY_new_by_curve_name(int nid);
EC_KEY * EC_KEY_copy(EC_KEY *dest,EC_KEY *src);
EC_KEY * EC_KEY_dup(EC_KEY *ec_key);
int EC_KEY_up_ref(EC_KEY *r);
int EC_KEY_generate_key(EC_KEY *eckey);
int EC_KEY_check_key(EC_KEY *eckey);
EC_GROUP * EC_KEY_get0_group(EC_KEY *key);
int EC_KEY_set_group(EC_KEY *key,EC_GROUP *group);
BIGNUM * EC_KEY_get0_private_key(EC_KEY *key);
int EC_KEY_set_private_key(EC_KEY *key,BIGNUM *priv_key);
EC_POINT * EC_KEY_get0_public_key(EC_KEY *key);
int EC_KEY_set_public_key(EC_KEY *key,EC_POINT *pub_key);
int EC_KEY_set_public_key_affine_coordinates(EC_KEY *key,BIGNUM *x,BIGNUM *y);
uint EC_KEY_get_enc_flags(EC_KEY *key);
void EC_KEY_set_enc_flags(EC_KEY *key,uint flags);
point_conversion_form_t EC_KEY_get_conv_form(EC_KEY *key);
void EC_KEY_set_conv_form(EC_KEY *key,point_conversion_form_t cform);
void * EC_KEY_get_key_method_data(EC_KEY *key,_func_void_ptr_void_ptr *dup_func,_func_void_void_ptr *free_func,_func_void_void_ptr *clear_free_func);
void * EC_KEY_insert_key_method_data(EC_KEY *key,void *data,_func_void_ptr_void_ptr *dup_func,_func_void_void_ptr *free_func,_func_void_void_ptr *clear_free_func);
void EC_KEY_set_asn1_flag(EC_KEY *key,int flag);
int EC_KEY_precompute_mult(EC_KEY *key,BN_CTX *ctx);
int EC_KEY_get_flags(EC_KEY *key);
void EC_KEY_set_flags(EC_KEY *key,int flags);
void EC_KEY_clear_flags(EC_KEY *key,int flags);
int EC_POINT_set_compressed_coordinates_GFp(EC_GROUP *group,EC_POINT *point,BIGNUM *x,int y_bit,BN_CTX *ctx);
int EC_POINT_set_compressed_coordinates_GF2m(EC_GROUP *group,EC_POINT *point,BIGNUM *x,int y_bit,BN_CTX *ctx);
size_t EC_POINT_point2oct(EC_GROUP *group,EC_POINT *point,point_conversion_form_t form,uchar *buf,size_t len,BN_CTX *ctx);
int EC_POINT_oct2point(EC_GROUP *group,EC_POINT *point,uchar *buf,size_t len,BN_CTX *ctx);
int RSA_eay_init(RSA *rsa);
int RSA_eay_finish(RSA *rsa);
int RSA_eay_mod_exp(BIGNUM *r0,BIGNUM *I,RSA *rsa,BN_CTX *ctx);
BN_BLINDING * rsa_get_blinding(RSA *rsa,int *local,BN_CTX *ctx);
int RSA_eay_public_decrypt(int flen,uchar *from,uchar *to,RSA *rsa,int padding);
int RSA_eay_public_encrypt(int flen,uchar *from,uchar *to,RSA *rsa,int padding);
int rsa_blinding_convert(BN_BLINDING *b,BIGNUM *f,BIGNUM *unblind,BN_CTX *ctx);
int RSA_eay_private_decrypt(int flen,uchar *from,uchar *to,RSA *rsa,int padding);
int RSA_eay_private_encrypt(int flen,uchar *from,uchar *to,RSA *rsa,int padding);
RSA_METHOD * RSA_PKCS1_SSLeay(void);
int RSA_padding_add_PKCS1_type_1(uchar *to,int tlen,uchar *from,int flen);
int RSA_padding_check_PKCS1_type_1(uchar *to,int tlen,uchar *from,int flen,int num);
int RSA_padding_add_PKCS1_type_2(uchar *to,int tlen,uchar *from,int flen);
int RSA_padding_check_PKCS1_type_2(uchar *to,int tlen,uchar *from,int flen,int num);
int RSA_padding_add_SSLv23(uchar *to,int tlen,uchar *from,int flen);
int RSA_padding_check_SSLv23(uchar *to,int tlen,uchar *from,int flen,int num);
int RSA_padding_add_none(uchar *to,int tlen,uchar *from,int flen);
int RSA_padding_check_none(uchar *to,int tlen,uchar *from,int flen,int num);
int PKCS1_MGF1(uchar *mask,long len,uchar *seed,long seedlen,EVP_MD *dgst);
int RSA_padding_add_PKCS1_OAEP_mgf1(uchar *to,int tlen,uchar *from,int flen,uchar *param,int plen,EVP_MD *md,EVP_MD *mgf1md);
int RSA_padding_add_PKCS1_OAEP(uchar *to,int tlen,uchar *from,int flen,uchar *param,int plen);
int RSA_padding_check_PKCS1_OAEP_mgf1(uchar *to,int tlen,uchar *from,int flen,int num,uchar *param,int plen,EVP_MD *md,EVP_MD *mgf1md);
int RSA_padding_check_PKCS1_OAEP(uchar *to,int tlen,uchar *from,int flen,int num,uchar *param,int plen);
int RSA_padding_add_X931(uchar *to,int tlen,uchar *from,int flen);
int RSA_padding_check_X931(uchar *to,int tlen,uchar *from,int flen,int num);
int RSA_X931_hash_id(int nid);
int rsa_cb(int operation,ASN1_VALUE **pval,ASN1_ITEM *it,void *exarg);
RSA_PSS_PARAMS * d2i_RSA_PSS_PARAMS(RSA_PSS_PARAMS **a,uchar **in,long len);
int i2d_RSA_PSS_PARAMS(RSA_PSS_PARAMS *a,uchar **out);
RSA_PSS_PARAMS * RSA_PSS_PARAMS_new(void);
void RSA_PSS_PARAMS_free(RSA_PSS_PARAMS *a);
RSA_OAEP_PARAMS * d2i_RSA_OAEP_PARAMS(RSA_OAEP_PARAMS **a,uchar **in,long len);
int i2d_RSA_OAEP_PARAMS(RSA_OAEP_PARAMS *a,uchar **out);
RSA_OAEP_PARAMS * RSA_OAEP_PARAMS_new(void);
void RSA_OAEP_PARAMS_free(RSA_OAEP_PARAMS *a);
RSA * d2i_RSAPrivateKey(RSA **a,uchar **in,long len);
int i2d_RSAPrivateKey(RSA *a,uchar **out);
RSA * d2i_RSAPublicKey(RSA **a,uchar **in,long len);
int i2d_RSAPublicKey(RSA *a,uchar **out);
RSA * RSAPublicKey_dup(RSA *rsa);
RSA * RSAPrivateKey_dup(RSA *rsa);
void DSA_set_default_method(DSA_METHOD *meth);
DSA_METHOD * DSA_get_default_method(void);
int DSA_set_method(DSA *dsa,DSA_METHOD *meth);
DSA * DSA_new_method(ENGINE *engine);
DSA * DSA_new(void);
void DSA_free(DSA *r);
int DSA_up_ref(DSA *r);
int DSA_size(DSA *r);
int DSA_get_ex_new_index(long argl,void *argp,CRYPTO_EX_new *new_func,CRYPTO_EX_dup *dup_func,CRYPTO_EX_free *free_func);
int DSA_set_ex_data(DSA *d,int idx,void *arg);
void * DSA_get_ex_data(DSA *d,int idx);
DH * DSA_dup_DH(DSA *r);
int sig_cb(int operation,ASN1_VALUE **pval,ASN1_ITEM *it,void *exarg);
int dsa_cb(int operation,ASN1_VALUE **pval,ASN1_ITEM *it,void *exarg);
DSA_SIG * d2i_DSA_SIG(DSA_SIG **a,uchar **in,long len);
int i2d_DSA_SIG(DSA_SIG *a,uchar **out);
DSA * d2i_DSAPrivateKey(DSA **a,uchar **in,long len);
int i2d_DSAPrivateKey(DSA *a,uchar **out);
DSA * d2i_DSAparams(DSA **a,uchar **in,long len);
int i2d_DSAparams(DSA *a,uchar **out);
DSA * d2i_DSAPublicKey(DSA **a,uchar **in,long len);
int i2d_DSAPublicKey(DSA *a,uchar **out);
DSA * DSAparams_dup(DSA *dsa);
int DSA_sign(int type,uchar *dgst,int dlen,uchar *sig,uint *siglen,DSA *dsa);
int DSA_verify(int type,uchar *dgst,int dgst_len,uchar *sigbuf,int siglen,DSA *dsa);
int DSA_do_verify(uchar *dgst,int dgst_len,DSA_SIG *sig,DSA *dsa);
DSA_SIG * DSA_do_sign(uchar *dgst,int dlen,DSA *dsa);
int DSA_sign_setup(DSA *dsa,BN_CTX *ctx_in,BIGNUM **kinvp,BIGNUM **rp);
DSA_SIG * DSA_SIG_new(void);
void DSA_SIG_free(DSA_SIG *sig);
int dsa_init(DSA *dsa);
int dsa_finish(DSA *dsa);
int dsa_do_verify(uchar *dgst,int dgst_len,DSA_SIG *sig,DSA *dsa);
DSA_SIG * dsa_do_sign(uchar *dgst,int dlen,DSA *dsa);
int dsa_sign_setup(DSA *dsa,BN_CTX *ctx_in,BIGNUM **kinvp,BIGNUM **rp);
DSA_METHOD * DSA_OpenSSL(void);
int dh_cb(int operation,ASN1_VALUE **pval,ASN1_ITEM *it,void *exarg);
DH * d2i_DHparams(DH **a,uchar **in,long len);
int i2d_DHparams(DH *a,uchar **out);
int_dhx942_dh * d2i_int_dhx(int_dhx942_dh **a,uchar **in,long len);
int i2d_int_dhx(int_dhx942_dh *a,uchar **out);
DH * d2i_DHxparams(DH **a,uchar **pp,long length);
int i2d_DHxparams(DH *dh,uchar **pp);
void DH_set_default_method(DH_METHOD *meth);
DH_METHOD * DH_get_default_method(void);
int DH_set_method(DH *dh,DH_METHOD *meth);
DH * DH_new_method(ENGINE *engine);
DH * DH_new(void);
void DH_free(DH *r);
int DH_up_ref(DH *r);
int DH_get_ex_new_index(long argl,void *argp,CRYPTO_EX_new *new_func,CRYPTO_EX_dup *dup_func,CRYPTO_EX_free *free_func);
int DH_set_ex_data(DH *d,int idx,void *arg);
void * DH_get_ex_data(DH *d,int idx);
int DH_size(DH *dh);
void engine_cleanup_cb_free(ENGINE_CLEANUP_ITEM *item);
ENGINE * ENGINE_new(void);
void engine_set_all_null(ENGINE *e);
int engine_free_util(ENGINE *e,int locked);
int ENGINE_free(ENGINE *e);
void engine_cleanup_add_first(undefined1 *cb);
void engine_cleanup_add_last(undefined1 *cb);
void ENGINE_cleanup(void);
int ENGINE_get_ex_new_index(long argl,void *argp,CRYPTO_EX_new *new_func,CRYPTO_EX_dup *dup_func,CRYPTO_EX_free *free_func);
int ENGINE_set_ex_data(ENGINE *e,int idx,void *arg);
void * ENGINE_get_ex_data(ENGINE *e,int idx);
int ENGINE_set_id(ENGINE *e,char *id);
int ENGINE_set_name(ENGINE *e,char *name);
int ENGINE_set_destroy_function(ENGINE *e,ENGINE_GEN_INT_FUNC_PTR destroy_f);
int ENGINE_set_init_function(ENGINE *e,ENGINE_GEN_INT_FUNC_PTR init_f);
int ENGINE_set_finish_function(ENGINE *e,ENGINE_GEN_INT_FUNC_PTR finish_f);
int ENGINE_set_ctrl_function(ENGINE *e,ENGINE_CTRL_FUNC_PTR ctrl_f);
int ENGINE_set_flags(ENGINE *e,int flags);
int ENGINE_set_cmd_defns(ENGINE *e,ENGINE_CMD_DEFN *defns);
char * ENGINE_get_id(ENGINE *e);
char * ENGINE_get_name(ENGINE *e);
ENGINE_GEN_INT_FUNC_PTR ENGINE_get_destroy_function(ENGINE *e);
ENGINE_GEN_INT_FUNC_PTR ENGINE_get_init_function(ENGINE *e);
ENGINE_GEN_INT_FUNC_PTR ENGINE_get_finish_function(ENGINE *e);
ENGINE_CTRL_FUNC_PTR ENGINE_get_ctrl_function(ENGINE *e);
int ENGINE_get_flags(ENGINE *e);
ENGINE_CMD_DEFN * ENGINE_get_cmd_defns(ENGINE *e);
void * ENGINE_get_static_state(void);
ENGINE * ENGINE_get_first(void);
ENGINE * ENGINE_get_last(void);
ENGINE * ENGINE_get_next(ENGINE *e);
ENGINE * ENGINE_get_prev(ENGINE *e);
int ENGINE_add(ENGINE *e);
int ENGINE_remove(ENGINE *e);
void engine_list_cleanup(void);
ENGINE * ENGINE_by_id(char *id);
int ENGINE_up_ref(ENGINE *e);
int ENGINE_ctrl(ENGINE *e,int cmd,long i,void *p,_func_void *f);
int ENGINE_cmd_is_executable(ENGINE *e,int cmd);
int ENGINE_ctrl_cmd(ENGINE *e,char *cmd_name,long i,void *p,_func_void *f,int cmd_optional);
int ENGINE_ctrl_cmd_string(ENGINE *e,char *cmd_name,char *arg,int cmd_optional);
ulong engine_pile_LHASH_HASH(void *arg);
int engine_pile_LHASH_COMP(void *arg1,void *arg2);
void int_cb_LHASH_DOALL_ARG(void *arg1,void *arg2);
void int_unregister_cb_LHASH_DOALL_ARG(void *arg1,void *arg2);
void int_cleanup_cb_LHASH_DOALL(void *arg);
uint ENGINE_get_table_flags(void);
void ENGINE_set_table_flags(uint flags);
int engine_table_register(ENGINE_TABLE **table,undefined1 *cleanup,ENGINE *e,int *nids,int num_nids,int setdefault);
void engine_table_unregister(ENGINE_TABLE **table,ENGINE *e);
void engine_table_cleanup(ENGINE_TABLE **table);
ENGINE * engine_table_select(ENGINE_TABLE **table,int nid);
void engine_table_doall(ENGINE_TABLE *table,engine_table_doall_cb *cb,void *arg);
void engine_unregister_all_DSA(void);
void ENGINE_unregister_DSA(ENGINE *e);
int ENGINE_register_DSA(ENGINE *e);
void ENGINE_register_all_DSA(void);
int ENGINE_set_default_DSA(ENGINE *e);
ENGINE * ENGINE_get_default_DSA(void);
DSA_METHOD * ENGINE_get_DSA(ENGINE *e);
int ENGINE_set_DSA(ENGINE *e,DSA_METHOD *dsa_meth);
void engine_unregister_all_DH(void);
void ENGINE_unregister_DH(ENGINE *e);
int ENGINE_register_DH(ENGINE *e);
void ENGINE_register_all_DH(void);
int ENGINE_set_default_DH(ENGINE *e);
ENGINE * ENGINE_get_default_DH(void);
DH_METHOD * ENGINE_get_DH(ENGINE *e);
int ENGINE_set_DH(ENGINE *e,DH_METHOD *dh_meth);
void engine_unregister_all_RAND(void);
void ENGINE_unregister_RAND(ENGINE *e);
int ENGINE_register_RAND(ENGINE *e);
void ENGINE_register_all_RAND(void);
int ENGINE_set_default_RAND(ENGINE *e);
ENGINE * ENGINE_get_default_RAND(void);
RAND_METHOD * ENGINE_get_RAND(ENGINE *e);
int ENGINE_set_RAND(ENGINE *e,RAND_METHOD *rand_meth);
void engine_unregister_all_ciphers(void);
void ENGINE_unregister_ciphers(ENGINE *e);
int ENGINE_register_ciphers(ENGINE *e);
void ENGINE_register_all_ciphers(void);
int ENGINE_set_default_ciphers(ENGINE *e);
ENGINE * ENGINE_get_cipher_engine(int nid);
ENGINE_CIPHERS_PTR ENGINE_get_ciphers(ENGINE *e);
EVP_CIPHER * ENGINE_get_cipher(ENGINE *e,int nid);
int ENGINE_set_ciphers(ENGINE *e,ENGINE_CIPHERS_PTR f);
void engine_unregister_all_pkey_meths(void);
void ENGINE_unregister_pkey_meths(ENGINE *e);
int ENGINE_register_pkey_meths(ENGINE *e);
void ENGINE_register_all_pkey_meths(void);
int ENGINE_set_default_pkey_meths(ENGINE *e);
ENGINE * ENGINE_get_pkey_meth_engine(int nid);
ENGINE_PKEY_METHS_PTR ENGINE_get_pkey_meths(ENGINE *e);
EVP_PKEY_METHOD * ENGINE_get_pkey_meth(ENGINE *e,int nid);
int ENGINE_set_pkey_meths(ENGINE *e,ENGINE_PKEY_METHS_PTR f);
void engine_pkey_meths_free(ENGINE *e);
void engine_unregister_all_pkey_asn1_meths(void);
void look_str_cb(int nid,stack_st_ENGINE *sk,ENGINE *def,void *arg);
void ENGINE_unregister_pkey_asn1_meths(ENGINE *e);
int ENGINE_register_pkey_asn1_meths(ENGINE *e);
void ENGINE_register_all_pkey_asn1_meths(void);
int ENGINE_set_default_pkey_asn1_meths(ENGINE *e);
ENGINE * ENGINE_get_pkey_asn1_meth_engine(int nid);
ENGINE_PKEY_ASN1_METHS_PTR ENGINE_get_pkey_asn1_meths(ENGINE *e);
EVP_PKEY_ASN1_METHOD * ENGINE_get_pkey_asn1_meth(ENGINE *e,int nid);
int ENGINE_set_pkey_asn1_meths(ENGINE *e,ENGINE_PKEY_ASN1_METHS_PTR f);
void engine_pkey_asn1_meths_free(ENGINE *e);
EVP_PKEY_ASN1_METHOD * ENGINE_get_pkey_asn1_meth_str(ENGINE *e,char *str,int len);
EVP_PKEY_ASN1_METHOD * ENGINE_pkey_asn1_find_str(ENGINE **pe,char *str,int len);
BUF_MEM * BUF_MEM_new(void);
void BUF_MEM_free(BUF_MEM *a);
int BUF_MEM_grow(BUF_MEM *str,size_t len);
int BUF_MEM_grow_clean(BUF_MEM *str,size_t len);
void BUF_reverse(uchar *out,uchar *in,size_t size);
size_t BUF_strnlen(char *str,size_t maxlen);
char * BUF_strndup(char *str,size_t siz);
char * BUF_strdup(char *str);
void * BUF_memdup(void *data,size_t siz);
size_t BUF_strlcpy(char *dst,char *src,size_t size);
size_t BUF_strlcat(char *dst,char *src,size_t size);
int null_new(BIO *bi);
int null_free(BIO *a);
int null_write(BIO *b,char *in,int inl);
long null_ctrl(BIO *b,int cmd,long num,void *ptr);
int null_gets(BIO *bp,char *buf,int size);
int null_puts(BIO *bp,char *str);
undefined4 null_read(void);
BIO_METHOD * BIO_s_null(void);
int file_new(BIO *bi);
int file_gets(BIO *bp,char *buf,int size);
int file_free(BIO *a);
int file_free(BIO *a);
long file_ctrl(BIO *b,int cmd,long num,void *ptr);
int file_read(BIO *b,char *out,int outl);
int file_puts(BIO *bp,char *str);
int file_write(BIO *b,char *in,int inl);
BIO_METHOD * BIO_s_file(void);
BIO * BIO_new_file(char *filename,char *mode);
BIO * BIO_new_fp(FILE *stream,int close_flag);
int doapr_outch(char **sbuffer,char **buffer,size_t *currlen,size_t *maxlen,int c);
int fmtint(char **sbuffer,char **buffer,size_t *currlen,size_t *maxlen,longlong value,int base,int min,int max,int flags);
int _dopr(char **sbuffer,char **buffer,size_t *maxlen,size_t *retlen,int *truncated,char *format,va_list args);
int BIO_vprintf(BIO *bio,char *format,va_list args);
int BIO_printf(BIO *bio,char *format,...);
int BIO_vsnprintf(char *buf,size_t n,char *format,va_list args);
int BIO_snprintf(char *buf,size_t n,char *format,...);
_func_int_void_ptr_void_ptr * sk_set_cmp_func(_STACK *sk,_func_int_void_ptr_void_ptr *c);
_STACK * sk_new(_func_int_void_ptr_void_ptr *c);
_STACK * sk_new_null(void);
int sk_insert(_STACK *st,void *data,int loc);
void * sk_delete(_STACK *st,int loc);
void * sk_delete_ptr(_STACK *st,void *p);
int sk_push(_STACK *st,void *data);
int sk_unshift(_STACK *st,void *data);
void * sk_shift(_STACK *st);
void * sk_pop(_STACK *st);
void sk_zero(_STACK *st);
void sk_free(_STACK *st);
_STACK * sk_dup(_STACK *sk);
_STACK * sk_deep_copy(_STACK *sk,_func_void_ptr_void_ptr *copy_func,_func_void_void_ptr *free_func);
void sk_pop_free(_STACK *st,_func_void_void_ptr *func);
int sk_num(_STACK *st);
void * sk_value(_STACK *st,int i);
void * sk_set(_STACK *st,int i,void *value);
void sk_sort(_STACK *st);
int internal_find(_STACK *st,void *data,int ret_val_options);
int sk_find(_STACK *st,void *data);
int sk_find_ex(_STACK *st,void *data);
int sk_is_sorted(_STACK *st);
LHASH_NODE ** getrn(_LHASH *lh,void *data,ulong *rhash);
ulong lh_strhash(char *c);
_LHASH * lh_new(LHASH_HASH_FN_TYPE h,LHASH_COMP_FN_TYPE c);
void lh_free(_LHASH *lh);
void * lh_insert(_LHASH *lh,void *data);
void * lh_delete(_LHASH *lh,void *data);
void * lh_retrieve(_LHASH *lh,void *data);
void lh_doall(_LHASH *lh,LHASH_DOALL_FN_TYPE func);
void lh_doall_arg(_LHASH *lh,LHASH_DOALL_ARG_FN_TYPE func,void *arg);
ulong lh_num_items(_LHASH *lh);
int ssleay_rand_status(void);
void ssleay_rand_cleanup(void);
void ssleay_rand_add(void *buf,int num,double add);
void ssleay_rand_add(void *buf,int num,double add);
void ssleay_rand_seed(void *buf,int num);
RAND_METHOD * RAND_SSLeay(void);
int ssleay_rand_bytes(uchar *buf,int num,int pseudo,int lock);
int ssleay_rand_pseudo_bytes(uchar *buf,int num);
int ssleay_rand_nopseudo_bytes(uchar *buf,int num);
int RAND_poll(void);
void EVP_EncodeInit(EVP_ENCODE_CTX *ctx);
int EVP_EncodeBlock(uchar *t,uchar *f,int dlen);
void EVP_EncodeUpdate(EVP_ENCODE_CTX *ctx,uchar *out,int *outl,uchar *in,int inl);
void EVP_EncodeFinal(EVP_ENCODE_CTX *ctx,uchar *out,int *outl);
void EVP_DecodeInit(EVP_ENCODE_CTX *ctx);
int EVP_DecodeBlock(uchar *t,uchar *f,int n);
int EVP_DecodeUpdate(EVP_ENCODE_CTX *ctx,uchar *out,int *outl,uchar *in,int inl);
int EVP_DecodeFinal(EVP_ENCODE_CTX *ctx,uchar *out,int *outl);
void EVP_MD_CTX_init(EVP_MD_CTX *ctx);
EVP_MD_CTX * EVP_MD_CTX_create(void);
int EVP_DigestInit_ex(EVP_MD_CTX *ctx,EVP_MD *type,ENGINE *impl);
int EVP_DigestInit(EVP_MD_CTX *ctx,EVP_MD *type);
int EVP_DigestUpdate(EVP_MD_CTX *ctx,void *data,size_t count);
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx,uchar *md,uint *size);
int EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx);
int EVP_DigestFinal(EVP_MD_CTX *ctx,uchar *md,uint *size);
int EVP_MD_CTX_copy_ex(EVP_MD_CTX *out,EVP_MD_CTX *in);
int EVP_MD_CTX_copy(EVP_MD_CTX *out,EVP_MD_CTX *in);
int EVP_Digest(void *data,size_t count,uchar *md,uint *size,EVP_MD *type,ENGINE *impl);
void EVP_MD_CTX_destroy(EVP_MD_CTX *ctx);
int des_ctrl(EVP_CIPHER_CTX *c,int type,int arg,void *ptr);
int des_init_key(EVP_CIPHER_CTX *ctx,uchar *key,uchar *iv,int enc);
int des_cfb64_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int des_ofb_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int des_ecb_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int des_cfb1_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int des_cfb8_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int des_cbc_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
EVP_CIPHER * EVP_des_cbc(void);
EVP_CIPHER * EVP_des_cfb64(void);
EVP_CIPHER * EVP_des_ofb(void);
EVP_CIPHER * EVP_des_ecb(void);
EVP_CIPHER * EVP_des_cfb1(void);
EVP_CIPHER * EVP_des_cfb8(void);
int bf_cbc_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int bf_init_key(EVP_CIPHER_CTX *ctx,uchar *key,uchar *iv,int enc);
int bf_cfb64_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int bf_ofb_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int bf_ecb_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
EVP_CIPHER * EVP_bf_cbc(void);
EVP_CIPHER * EVP_bf_cfb64(void);
EVP_CIPHER * EVP_bf_ofb(void);
EVP_CIPHER * EVP_bf_ecb(void);
int idea_cbc_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int idea_cfb64_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int idea_ofb_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int idea_ecb_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int idea_init_key(EVP_CIPHER_CTX *ctx,uchar *key,uchar *iv,int enc);
EVP_CIPHER * EVP_idea_cbc(void);
EVP_CIPHER * EVP_idea_cfb64(void);
EVP_CIPHER * EVP_idea_ofb(void);
EVP_CIPHER * EVP_idea_ecb(void);
int des_ede_cbc_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int des_ede3_init_key(EVP_CIPHER_CTX *ctx,uchar *key,uchar *iv,int enc);
int des_ede_init_key(EVP_CIPHER_CTX *ctx,uchar *key,uchar *iv,int enc);
int des_ede_cfb64_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int des_ede_ofb_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int des_ede_ecb_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int des_ede3_cfb1_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int des_ede3_cfb8_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int des_ede3_wrap_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int des3_ctrl(EVP_CIPHER_CTX *c,int type,int arg,void *ptr);
EVP_CIPHER * EVP_des_ede_cbc(void);
EVP_CIPHER * EVP_des_ede_cfb64(void);
EVP_CIPHER * EVP_des_ede_ofb(void);
EVP_CIPHER * EVP_des_ede_ecb(void);
EVP_CIPHER * EVP_des_ede3_cbc(void);
EVP_CIPHER * EVP_des_ede3_cfb64(void);
EVP_CIPHER * EVP_des_ede3_ofb(void);
EVP_CIPHER * EVP_des_ede3_ecb(void);
EVP_CIPHER * EVP_des_ede3_cfb1(void);
EVP_CIPHER * EVP_des_ede3_cfb8(void);
EVP_CIPHER * EVP_des_ede(void);
EVP_CIPHER * EVP_des_ede3(void);
EVP_CIPHER * EVP_des_ede3_wrap(void);
int camellia_ecb_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t len);
int camellia_cbc_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t len);
int camellia_ofb_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t len);
int camellia_cfb_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t len);
int camellia_cfb1_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t len);
int camellia_cfb8_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t len);
int camellia_init_key(EVP_CIPHER_CTX *ctx,uchar *key,uchar *iv,int enc);
EVP_CIPHER * EVP_camellia_128_cbc(void);
EVP_CIPHER * EVP_camellia_128_ecb(void);
EVP_CIPHER * EVP_camellia_128_ofb(void);
EVP_CIPHER * EVP_camellia_128_cfb128(void);
EVP_CIPHER * EVP_camellia_128_cfb1(void);
EVP_CIPHER * EVP_camellia_128_cfb8(void);
EVP_CIPHER * EVP_camellia_192_cbc(void);
EVP_CIPHER * EVP_camellia_192_ecb(void);
EVP_CIPHER * EVP_camellia_192_ofb(void);
EVP_CIPHER * EVP_camellia_192_cfb128(void);
EVP_CIPHER * EVP_camellia_192_cfb1(void);
EVP_CIPHER * EVP_camellia_192_cfb8(void);
EVP_CIPHER * EVP_camellia_256_cbc(void);
EVP_CIPHER * EVP_camellia_256_ecb(void);
EVP_CIPHER * EVP_camellia_256_ofb(void);
EVP_CIPHER * EVP_camellia_256_cfb128(void);
EVP_CIPHER * EVP_camellia_256_cfb1(void);
EVP_CIPHER * EVP_camellia_256_cfb8(void);
int rc4_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int rc4_init_key(EVP_CIPHER_CTX *ctx,uchar *key,uchar *iv,int enc);
EVP_CIPHER * EVP_rc4(void);
EVP_CIPHER * EVP_rc4_40(void);
int seed_cbc_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int seed_init_key(EVP_CIPHER_CTX *ctx,uchar *key,uchar *iv,int enc);
int seed_cfb128_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int seed_ofb_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int seed_ecb_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
EVP_CIPHER * EVP_seed_cbc(void);
EVP_CIPHER * EVP_seed_cfb128(void);
EVP_CIPHER * EVP_seed_ofb(void);
EVP_CIPHER * EVP_seed_ecb(void);
int desx_cbc_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int desx_cbc_init_key(EVP_CIPHER_CTX *ctx,uchar *key,uchar *iv,int enc);
EVP_CIPHER * EVP_desx_cbc(void);
int rc2_get_asn1_type_and_iv(EVP_CIPHER_CTX *c,ASN1_TYPE *type);
int rc2_set_asn1_type_and_iv(EVP_CIPHER_CTX *c,ASN1_TYPE *type);
int rc2_cbc_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int rc2_init_key(EVP_CIPHER_CTX *ctx,uchar *key,uchar *iv,int enc);
int rc2_cfb64_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int rc2_ofb_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int rc2_ecb_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int rc2_ctrl(EVP_CIPHER_CTX *c,int type,int arg,void *ptr);
EVP_CIPHER * EVP_rc2_cbc(void);
EVP_CIPHER * EVP_rc2_cfb64(void);
EVP_CIPHER * EVP_rc2_ofb(void);
EVP_CIPHER * EVP_rc2_ecb(void);
EVP_CIPHER * EVP_rc2_64_cbc(void);
EVP_CIPHER * EVP_rc2_40_cbc(void);
int cast5_cbc_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int cast_init_key(EVP_CIPHER_CTX *ctx,uchar *key,uchar *iv,int enc);
int cast5_cfb64_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int cast5_ofb_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
int cast5_ecb_cipher(EVP_CIPHER_CTX *ctx,uchar *out,uchar *in,size_t inl);
EVP_CIPHER * EVP_cast5_cbc(void);
EVP_CIPHER * EVP_cast5_cfb64(void);
EVP_CIPHER * EVP_cast5_ofb(void);
EVP_CIPHER * EVP_cast5_ecb(void);
int final(EVP_MD_CTX *ctx,uchar *md);
int update(EVP_MD_CTX *ctx,void *data,size_t count);
int init(EVP_MD_CTX *ctx);
EVP_MD * EVP_md4(void);
int final(EVP_MD_CTX *ctx,uchar *md);
int update(EVP_MD_CTX *ctx,void *data,size_t count);
int init(EVP_MD_CTX *ctx);
EVP_MD * EVP_md5(void);
int final(EVP_MD_CTX *ctx,uchar *md);
int update(EVP_MD_CTX *ctx,void *data,size_t count);
int init(EVP_MD_CTX *ctx);
EVP_MD * EVP_sha(void);
int final(EVP_MD_CTX *ctx,uchar *md);
int update(EVP_MD_CTX *ctx,void *data,size_t count);
int init(EVP_MD_CTX *ctx);
int final256(EVP_MD_CTX *ctx,uchar *md);
int update256(EVP_MD_CTX *ctx,void *data,size_t count);
int init224(EVP_MD_CTX *ctx);
int init256(EVP_MD_CTX *ctx);
int final512(EVP_MD_CTX *ctx,uchar *md);
int update512(EVP_MD_CTX *ctx,void *data,size_t count);
int init384(EVP_MD_CTX *ctx);
int init512(EVP_MD_CTX *ctx);
EVP_MD * EVP_sha1(void);
EVP_MD * EVP_sha224(void);
EVP_MD * EVP_sha256(void);
EVP_MD * EVP_sha384(void);
EVP_MD * EVP_sha512(void);
int final(EVP_MD_CTX *ctx,uchar *md);
int update(EVP_MD_CTX *ctx,void *data,size_t count);
int init(EVP_MD_CTX *ctx);
EVP_MD * EVP_whirlpool(void);
int final(EVP_MD_CTX *ctx,uchar *md);
int update(EVP_MD_CTX *ctx,void *data,size_t count);
int init(EVP_MD_CTX *ctx);
EVP_MD * EVP_dss(void);
int final(EVP_MD_CTX *ctx,uchar *md);
int update(EVP_MD_CTX *ctx,void *data,size_t count);
int init(EVP_MD_CTX *ctx);
EVP_MD * EVP_dss1(void);
int final(EVP_MD_CTX *ctx,uchar *md);
int update(EVP_MD_CTX *ctx,void *data,size_t count);
int init(EVP_MD_CTX *ctx);
EVP_MD * EVP_mdc2(void);
int final(EVP_MD_CTX *ctx,uchar *md);
int update(EVP_MD_CTX *ctx,void *data,size_t count);
int init(EVP_MD_CTX *ctx);
EVP_MD * EVP_ripemd160(void);
int final(EVP_MD_CTX *ctx,uchar *md);
int update(EVP_MD_CTX *ctx,void *data,size_t count);
int init(EVP_MD_CTX *ctx);
EVP_MD * EVP_ecdsa(void);
int EVP_SignFinal(EVP_MD_CTX *ctx,uchar *sigret,uint *siglen,EVP_PKEY *pkey);
int EVP_VerifyFinal(EVP_MD_CTX *ctx,uchar *sigbuf,uint siglen,EVP_PKEY *pkey);
void EVP_PKEY_free_it(EVP_PKEY *x);
int pkey_set_type(EVP_PKEY *pkey,int type,char *str,int len);
int unsup_alg(BIO *out,EVP_PKEY *pkey,int indent,char *kstr);
int EVP_PKEY_bits(EVP_PKEY *pkey);
int EVP_PKEY_size(EVP_PKEY *pkey);
int EVP_PKEY_save_parameters(EVP_PKEY *pkey,int mode);
int EVP_PKEY_missing_parameters(EVP_PKEY *pkey);
int EVP_PKEY_cmp_parameters(EVP_PKEY *a,EVP_PKEY *b);
int EVP_PKEY_copy_parameters(EVP_PKEY *to,EVP_PKEY *from);
int EVP_PKEY_cmp(EVP_PKEY *a,EVP_PKEY *b);
EVP_PKEY * EVP_PKEY_new(void);
int EVP_PKEY_set_type(EVP_PKEY *pkey,int type);
int EVP_PKEY_set_type_str(EVP_PKEY *pkey,char *str,int len);
int EVP_PKEY_assign(EVP_PKEY *pkey,int type,void *key);
void * EVP_PKEY_get0(EVP_PKEY *pkey);
int EVP_PKEY_set1_RSA(EVP_PKEY *pkey,RSA *key);
RSA * EVP_PKEY_get1_RSA(EVP_PKEY *pkey);
int EVP_PKEY_set1_DSA(EVP_PKEY *pkey,DSA *key);
DSA * EVP_PKEY_get1_DSA(EVP_PKEY *pkey);
int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey,EC_KEY *key);
EC_KEY * EVP_PKEY_get1_EC_KEY(EVP_PKEY *pkey);
int EVP_PKEY_set1_DH(EVP_PKEY *pkey,DH *key);
DH * EVP_PKEY_get1_DH(EVP_PKEY *pkey);
int EVP_PKEY_type(int type);
int EVP_PKEY_id(EVP_PKEY *pkey);
int EVP_PKEY_base_id(EVP_PKEY *pkey);
void EVP_PKEY_free(EVP_PKEY *x);
int EVP_PKEY_print_public(BIO *out,EVP_PKEY *pkey,int indent,ASN1_PCTX *pctx);
int EVP_PKEY_print_private(BIO *out,EVP_PKEY *pkey,int indent,ASN1_PCTX *pctx);
int EVP_PKEY_print_params(BIO *out,EVP_PKEY *pkey,int indent,ASN1_PCTX *pctx);
int EVP_PKEY_get_default_digest_nid(EVP_PKEY *pkey,int *pnid);
long md_callback_ctrl(BIO *b,int cmd,bio_info_cb *fp);
int md_free(BIO *a);
int md_new(BIO *bi);
long md_ctrl(BIO *b,int cmd,long num,void *ptr);
int md_gets(BIO *bp,char *buf,int size);
int md_read(BIO *b,char *out,int outl);
int md_write(BIO *b,char *in,int inl);
BIO_METHOD * BIO_f_md(void);
long enc_callback_ctrl(BIO *b,int cmd,bio_info_cb *fp);
int enc_free(BIO *a);
int enc_new(BIO *bi);
int enc_read(BIO *b,char *out,int outl);
int enc_write(BIO *b,char *in,int inl);
long enc_ctrl(BIO *b,int cmd,long num,void *ptr);
BIO_METHOD * BIO_f_cipher(void);
void BIO_set_cipher(BIO *b,EVP_CIPHER *c,uchar *k,uchar *i,int e);
EVP_PKEY * EVP_PKCS82PKEY(PKCS8_PRIV_KEY_INFO *p8);
PKCS8_PRIV_KEY_INFO * EVP_PKEY2PKCS8_broken(EVP_PKEY *pkey,int broken);
PKCS8_PRIV_KEY_INFO * EVP_PKEY2PKCS8(EVP_PKEY *pkey);
PKCS8_PRIV_KEY_INFO * PKCS8_set_broken(PKCS8_PRIV_KEY_INFO *p8,int broken);
int EVP_PKEY_get_attr_count(EVP_PKEY *key);
int EVP_PKEY_get_attr_by_NID(EVP_PKEY *key,int nid,int lastpos);
int EVP_PKEY_get_attr_by_OBJ(EVP_PKEY *key,ASN1_OBJECT *obj,int lastpos);
X509_ATTRIBUTE * EVP_PKEY_get_attr(EVP_PKEY *key,int loc);
X509_ATTRIBUTE * EVP_PKEY_delete_attr(EVP_PKEY *key,int loc);
int EVP_PKEY_add1_attr(EVP_PKEY *key,X509_ATTRIBUTE *attr);
int EVP_PKEY_add1_attr_by_OBJ(EVP_PKEY *key,ASN1_OBJECT *obj,int type,uchar *bytes,int len);
int EVP_PKEY_add1_attr_by_NID(EVP_PKEY *key,int nid,int type,uchar *bytes,int len);
int EVP_PKEY_add1_attr_by_txt(EVP_PKEY *key,char *attrname,int type,uchar *bytes,int len);
int pmeth_cmp(EVP_PKEY_METHOD **a,EVP_PKEY_METHOD **b);
int pmeth_cmp_BSEARCH_CMP_FN(void *a_,void *b_);
EVP_PKEY_METHOD * EVP_PKEY_meth_find(int type);
EVP_PKEY_METHOD * EVP_PKEY_meth_new(int id,int flags);
void EVP_PKEY_meth_get0_info(int *ppkey_id,int *pflags,EVP_PKEY_METHOD *meth);
void EVP_PKEY_meth_copy(EVP_PKEY_METHOD *dst,EVP_PKEY_METHOD *src);
void EVP_PKEY_meth_free(EVP_PKEY_METHOD *pmeth);
int EVP_PKEY_meth_add0(EVP_PKEY_METHOD *pmeth);
void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);
EVP_PKEY_CTX * int_ctx_new(EVP_PKEY *pkey,ENGINE *e,int id);
EVP_PKEY_CTX * EVP_PKEY_CTX_new(EVP_PKEY *pkey,ENGINE *e);
EVP_PKEY_CTX * EVP_PKEY_CTX_new_id(int id,ENGINE *e);
EVP_PKEY_CTX * EVP_PKEY_CTX_dup(EVP_PKEY_CTX *pctx);
int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx,int keytype,int optype,int cmd,int p1,void *p2);
int EVP_PKEY_CTX_ctrl_str(EVP_PKEY_CTX *ctx,char *name,char *value);
int EVP_PKEY_CTX_get_operation(EVP_PKEY_CTX *ctx);
void EVP_PKEY_CTX_set0_keygen_info(EVP_PKEY_CTX *ctx,int *dat,int datlen);
void EVP_PKEY_CTX_set_data(EVP_PKEY_CTX *ctx,void *data);
void * EVP_PKEY_CTX_get_data(EVP_PKEY_CTX *ctx);
EVP_PKEY * EVP_PKEY_CTX_get0_pkey(EVP_PKEY_CTX *ctx);
EVP_PKEY * EVP_PKEY_CTX_get0_peerkey(EVP_PKEY_CTX *ctx);
void EVP_PKEY_CTX_set_app_data(EVP_PKEY_CTX *ctx,void *data);
void * EVP_PKEY_CTX_get_app_data(EVP_PKEY_CTX *ctx);
void EVP_PKEY_meth_set_init(EVP_PKEY_METHOD *pmeth,EVP_PKEY_gen_cb *init);
void EVP_PKEY_meth_set_copy(EVP_PKEY_METHOD *pmeth,_func_int_EVP_PKEY_CTX_ptr_EVP_PKEY_CTX_ptr *copy);
void EVP_PKEY_meth_set_cleanup(EVP_PKEY_METHOD *pmeth,_func_void_EVP_PKEY_CTX_ptr *cleanup);
void EVP_PKEY_meth_set_paramgen(EVP_PKEY_METHOD *pmeth,EVP_PKEY_gen_cb *paramgen_init,_func_int_EVP_PKEY_CTX_ptr_EVP_PKEY_ptr *paramgen);
void EVP_PKEY_meth_set_keygen(EVP_PKEY_METHOD *pmeth,EVP_PKEY_gen_cb *keygen_init,_func_int_EVP_PKEY_CTX_ptr_EVP_PKEY_ptr *keygen);
void EVP_PKEY_meth_set_sign(EVP_PKEY_METHOD *pmeth,EVP_PKEY_gen_cb *sign_init,_func_int_EVP_PKEY_CTX_ptr_uchar_ptr_size_t_ptr_uchar_ptr_size_t *sign);
void EVP_PKEY_meth_set_verify(EVP_PKEY_METHOD *pmeth,EVP_PKEY_gen_cb *verify_init,_func_int_EVP_PKEY_CTX_ptr_uchar_ptr_size_t_uchar_ptr_size_t *verify);
void EVP_PKEY_meth_set_verify_recover(EVP_PKEY_METHOD *pmeth,EVP_PKEY_gen_cb *verify_recover_init,_func_int_EVP_PKEY_CTX_ptr_uchar_ptr_size_t_ptr_uchar_ptr_size_t *verify_recover);
void EVP_PKEY_meth_set_signctx(EVP_PKEY_METHOD *pmeth,_func_int_EVP_PKEY_CTX_ptr_EVP_MD_CTX_ptr *signctx_init,_func_int_EVP_PKEY_CTX_ptr_uchar_ptr_size_t_ptr_EVP_MD_CTX_ptr *signctx);
void EVP_PKEY_meth_set_verifyctx(EVP_PKEY_METHOD *pmeth,_func_int_EVP_PKEY_CTX_ptr_EVP_MD_CTX_ptr *verifyctx_init,_func_int_EVP_PKEY_CTX_ptr_uchar_ptr_int_EVP_MD_CTX_ptr *verifyctx);
void EVP_PKEY_meth_set_encrypt(EVP_PKEY_METHOD *pmeth,EVP_PKEY_gen_cb *encrypt_init,_func_int_EVP_PKEY_CTX_ptr_uchar_ptr_size_t_ptr_uchar_ptr_size_t *encryptfn);
void EVP_PKEY_meth_set_decrypt(EVP_PKEY_METHOD *pmeth,EVP_PKEY_gen_cb *decrypt_init,_func_int_EVP_PKEY_CTX_ptr_uchar_ptr_size_t_ptr_uchar_ptr_size_t *decrypt);
void EVP_PKEY_meth_set_derive(EVP_PKEY_METHOD *pmeth,EVP_PKEY_gen_cb *derive_init,_func_int_EVP_PKEY_CTX_ptr_uchar_ptr_size_t_ptr *derive);
void EVP_PKEY_meth_set_ctrl(EVP_PKEY_METHOD *pmeth,_func_int_EVP_PKEY_CTX_ptr_int_int_void_ptr *ctrl,_func_int_EVP_PKEY_CTX_ptr_char_ptr_char_ptr *ctrl_str);
int EVP_PKEY_sign_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_sign(EVP_PKEY_CTX *ctx,uchar *sig,size_t *siglen,uchar *tbs,size_t tbslen);
int EVP_PKEY_verify_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_verify(EVP_PKEY_CTX *ctx,uchar *sig,size_t siglen,uchar *tbs,size_t tbslen);
int EVP_PKEY_verify_recover_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_verify_recover(EVP_PKEY_CTX *ctx,uchar *rout,size_t *routlen,uchar *sig,size_t siglen);
int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx,uchar *out,size_t *outlen,uchar *in,size_t inlen);
int EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx,uchar *out,size_t *outlen,uchar *in,size_t inlen);
int EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx,EVP_PKEY *peer);
int EVP_PKEY_derive(EVP_PKEY_CTX *ctx,uchar *key,size_t *pkeylen);
int do_sigver_init(EVP_MD_CTX *ctx,EVP_PKEY_CTX **pctx,EVP_MD *type,ENGINE *e,EVP_PKEY *pkey,int ver);
int EVP_DigestSignInit(EVP_MD_CTX *ctx,EVP_PKEY_CTX **pctx,EVP_MD *type,ENGINE *e,EVP_PKEY *pkey);
int EVP_DigestVerifyInit(EVP_MD_CTX *ctx,EVP_PKEY_CTX **pctx,EVP_MD *type,ENGINE *e,EVP_PKEY *pkey);
int EVP_DigestSignFinal(EVP_MD_CTX *ctx,uchar *sigret,size_t *siglen);
int EVP_DigestVerifyFinal(EVP_MD_CTX *ctx,uchar *sig,size_t siglen);
int ASN1_BIT_STRING_set(ASN1_BIT_STRING *x,uchar *d,int len);
int i2c_ASN1_BIT_STRING(ASN1_BIT_STRING *a,uchar **pp);
ASN1_BIT_STRING * c2i_ASN1_BIT_STRING(ASN1_BIT_STRING **a,uchar **pp,long len);
int ASN1_BIT_STRING_set_bit(ASN1_BIT_STRING *a,int n,int value);
int ASN1_BIT_STRING_get_bit(ASN1_BIT_STRING *a,int n);
int ASN1_BIT_STRING_check(ASN1_BIT_STRING *a,uchar *flags,int flags_len);
ASN1_OCTET_STRING * ASN1_OCTET_STRING_dup(ASN1_OCTET_STRING *x);
int ASN1_OCTET_STRING_cmp(ASN1_OCTET_STRING *a,ASN1_OCTET_STRING *b);
int ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *x,uchar *d,int len);
void * ASN1_dup(i2d_of_void *i2d,d2i_of_void *d2i,void *x);
void * ASN1_item_dup(ASN1_ITEM *it,void *x);
int asn1_d2i_read_bio(BIO *in,BUF_MEM **pb);
void * ASN1_d2i_bio(_func_void_ptr *xnew,d2i_of_void *d2i,BIO *in,void **x);
void * ASN1_d2i_fp(_func_void_ptr *xnew,d2i_of_void *d2i,FILE *in,void **x);
void * ASN1_item_d2i_bio(ASN1_ITEM *it,BIO *in,void *x);
void * ASN1_item_d2i_fp(ASN1_ITEM *it,FILE *in,void *x);
int ASN1_i2d_bio(i2d_of_void *i2d,BIO *out,uchar *x);
int ASN1_i2d_fp(i2d_of_void *i2d,FILE *out,void *x);
int ASN1_item_i2d_bio(ASN1_ITEM *it,BIO *out,void *x);
int ASN1_item_i2d_fp(ASN1_ITEM *it,FILE *out,void *x);
X509_ALGOR * d2i_X509_ALGOR(X509_ALGOR **a,uchar **in,long len);
int i2d_X509_ALGOR(X509_ALGOR *a,uchar **out);
X509_ALGOR * X509_ALGOR_new(void);
void X509_ALGOR_free(X509_ALGOR *a);
X509_ALGORS * d2i_X509_ALGORS(X509_ALGORS **a,uchar **in,long len);
int i2d_X509_ALGORS(X509_ALGORS *a,uchar **out);
X509_ALGOR * X509_ALGOR_dup(X509_ALGOR *x);
int X509_ALGOR_set0(X509_ALGOR *alg,ASN1_OBJECT *aobj,int ptype,void *pval);
void X509_ALGOR_get0(ASN1_OBJECT **paobj,int *pptype,void **ppval,X509_ALGOR *algor);
void X509_ALGOR_set_md(X509_ALGOR *alg,EVP_MD *md);
int X509_ALGOR_cmp(X509_ALGOR *a,X509_ALGOR *b);
int pubkey_cb(int operation,ASN1_VALUE **pval,ASN1_ITEM *it,void *exarg);
X509_PUBKEY * d2i_X509_PUBKEY(X509_PUBKEY **a,uchar **in,long len);
int i2d_X509_PUBKEY(X509_PUBKEY *a,uchar **out);
X509_PUBKEY * X509_PUBKEY_new(void);
void X509_PUBKEY_free(X509_PUBKEY *a);
int X509_PUBKEY_set(X509_PUBKEY **x,EVP_PKEY *pkey);
EVP_PKEY * X509_PUBKEY_get(X509_PUBKEY *key);
EVP_PKEY * d2i_PUBKEY(EVP_PKEY **a,uchar **pp,long length);
int i2d_PUBKEY(EVP_PKEY *a,uchar **pp);
RSA * d2i_RSA_PUBKEY(RSA **a,uchar **pp,long length);
int i2d_RSA_PUBKEY(RSA *a,uchar **pp);
DSA * d2i_DSA_PUBKEY(DSA **a,uchar **pp,long length);
int i2d_DSA_PUBKEY(DSA *a,uchar **pp);
EC_KEY * d2i_EC_PUBKEY(EC_KEY **a,uchar **pp,long length);
int i2d_EC_PUBKEY(EC_KEY *a,uchar **pp);
int X509_PUBKEY_set0_param(X509_PUBKEY *pub,ASN1_OBJECT *aobj,int ptype,void *pval,uchar *penc,int penclen);
int X509_PUBKEY_get0_param(ASN1_OBJECT **ppkalg,uchar **pk,int *ppklen,X509_ALGOR **pa,X509_PUBKEY *pub);
int rinf_cb(int operation,ASN1_VALUE **pval,ASN1_ITEM *it,void *exarg);
X509_REQ_INFO * d2i_X509_REQ_INFO(X509_REQ_INFO **a,uchar **in,long len);
int i2d_X509_REQ_INFO(X509_REQ_INFO *a,uchar **out);
X509_REQ_INFO * X509_REQ_INFO_new(void);
void X509_REQ_INFO_free(X509_REQ_INFO *a);
X509_REQ * d2i_X509_REQ(X509_REQ **a,uchar **in,long len);
int i2d_X509_REQ(X509_REQ *a,uchar **out);
X509_REQ * X509_REQ_new(void);
void X509_REQ_free(X509_REQ *a);
X509_REQ * X509_REQ_dup(X509_REQ *x);
X509_ATTRIBUTE * d2i_X509_ATTRIBUTE(X509_ATTRIBUTE **a,uchar **in,long len);
int i2d_X509_ATTRIBUTE(X509_ATTRIBUTE *a,uchar **out);
X509_ATTRIBUTE * X509_ATTRIBUTE_new(void);
void X509_ATTRIBUTE_free(X509_ATTRIBUTE *a);
X509_ATTRIBUTE * X509_ATTRIBUTE_dup(X509_ATTRIBUTE *x);
X509_ATTRIBUTE * X509_ATTRIBUTE_create(int nid,int atrtype,void *value);
int bn_i2c(ASN1_VALUE **pval,uchar *cont,int *putype,ASN1_ITEM *it);
void bn_free(ASN1_VALUE **pval,ASN1_ITEM *it);
int bn_new(ASN1_VALUE **pval,ASN1_ITEM *it);
int bn_c2i(ASN1_VALUE **pval,uchar *cont,int len,int utype,char *free_cont,ASN1_ITEM *it);
int bn_print(BIO *out,ASN1_VALUE **pval,ASN1_ITEM *it,int indent,ASN1_PCTX *pctx);
int long_new(ASN1_VALUE **pval,ASN1_ITEM *it);
void long_free(ASN1_VALUE **pval,ASN1_ITEM *it);
int long_print(BIO *out,ASN1_VALUE **pval,ASN1_ITEM *it,int indent,ASN1_PCTX *pctx);
int long_i2c(ASN1_VALUE **pval,uchar *cont,int *putype,ASN1_ITEM *it);
int long_c2i(ASN1_VALUE **pval,uchar *cont,int len,int utype,char *free_cont,ASN1_ITEM *it);
void X509_NAME_ENTRY_free(X509_NAME_ENTRY *a);
int x509_name_ex_print(BIO *out,ASN1_VALUE **pval,int indent,char *fname,ASN1_PCTX *pctx);
int i2d_name_canon(stack_st_STACK_OF_X509_NAME_ENTRY *_intname,uchar **in);
void local_sk_X509_NAME_ENTRY_pop_free(stack_st_X509_NAME_ENTRY *ne);
void local_sk_X509_NAME_ENTRY_free(stack_st_X509_NAME_ENTRY *ne);
void x509_name_ex_free(ASN1_VALUE **pval,ASN1_ITEM *it);
int x509_name_ex_new(ASN1_VALUE **val,ASN1_ITEM *it);
X509_NAME_ENTRY * d2i_X509_NAME_ENTRY(X509_NAME_ENTRY **a,uchar **in,long len);
int i2d_X509_NAME_ENTRY(X509_NAME_ENTRY *a,uchar **out);
X509_NAME_ENTRY * X509_NAME_ENTRY_new(void);
int x509_name_canon(X509_NAME *a);
int x509_name_ex_i2d(ASN1_VALUE **val,uchar **out,ASN1_ITEM *it,int tag,int aclass);
X509_NAME_ENTRY * X509_NAME_ENTRY_dup(X509_NAME_ENTRY *x);
X509_NAME * d2i_X509_NAME(X509_NAME **a,uchar **in,long len);
int i2d_X509_NAME(X509_NAME *a,uchar **out);
X509_NAME * X509_NAME_new(void);
void X509_NAME_free(X509_NAME *a);
int x509_name_ex_d2i(ASN1_VALUE **val,uchar **in,long len,ASN1_ITEM *it,int tag,int aclass,char opt,ASN1_TLC *ctx);
X509_NAME * X509_NAME_dup(X509_NAME *x);
int X509_NAME_set(X509_NAME **xn,X509_NAME *name);
int x509_cb(int operation,ASN1_VALUE **pval,ASN1_ITEM *it,void *exarg);
X509_CINF * d2i_X509_CINF(X509_CINF **a,uchar **in,long len);
int i2d_X509_CINF(X509_CINF *a,uchar **out);
X509_CINF * X509_CINF_new(void);
void X509_CINF_free(X509_CINF *a);
X509 * d2i_X509(X509 **a,uchar **in,long len);
int i2d_X509(X509 *a,uchar **out);
int i2d_x509_aux_internal(X509 *a,uchar **pp);
X509 * X509_new(void);
void X509_free(X509 *a);
X509 * X509_dup(X509 *x);
int X509_get_ex_new_index(long argl,void *argp,CRYPTO_EX_new *new_func,CRYPTO_EX_dup *dup_func,CRYPTO_EX_free *free_func);
int X509_set_ex_data(X509 *r,int idx,void *arg);
void * X509_get_ex_data(X509 *r,int idx);
X509 * d2i_X509_AUX(X509 **a,uchar **pp,long length);
int i2d_X509_AUX(X509 *a,uchar **pp);
int i2d_re_X509_tbs(X509 *x,uchar **pp);
void X509_get0_signature(ASN1_BIT_STRING **psig,X509_ALGOR **palg,X509 *x);
int X509_get_signature_nid(X509 *x);
X509_CERT_AUX * d2i_X509_CERT_AUX(X509_CERT_AUX **a,uchar **in,long len);
int i2d_X509_CERT_AUX(X509_CERT_AUX *a,uchar **out);
X509_CERT_AUX * X509_CERT_AUX_new(void);
void X509_CERT_AUX_free(X509_CERT_AUX *a);
int X509_alias_set1(X509 *x,uchar *name,int len);
int X509_keyid_set1(X509 *x,uchar *id,int len);
uchar * X509_alias_get0(X509 *x,int *len);
uchar * X509_keyid_get0(X509 *x,int *len);
int X509_add1_trust_object(X509 *x,ASN1_OBJECT *obj);
int X509_add1_reject_object(X509 *x,ASN1_OBJECT *obj);
void X509_trust_clear(X509 *x);
void X509_reject_clear(X509 *x);
X509_CERT_PAIR * d2i_X509_CERT_PAIR(X509_CERT_PAIR **a,uchar **in,long len);
int i2d_X509_CERT_PAIR(X509_CERT_PAIR *a,uchar **out);
X509_CERT_PAIR * X509_CERT_PAIR_new(void);
void X509_CERT_PAIR_free(X509_CERT_PAIR *a);
int crl_inf_cb(int operation,ASN1_VALUE **pval,ASN1_ITEM *it,void *exarg);
int X509_REVOKED_cmp(X509_REVOKED **a,X509_REVOKED **b);
int def_crl_verify(X509_CRL *crl,EVP_PKEY *r);
int crl_cb(int operation,ASN1_VALUE **pval,ASN1_ITEM *it,void *exarg);
int def_crl_lookup(X509_CRL *crl,X509_REVOKED **ret,ASN1_INTEGER *serial,X509_NAME *issuer);
X509_REVOKED * d2i_X509_REVOKED(X509_REVOKED **a,uchar **in,long len);
int i2d_X509_REVOKED(X509_REVOKED *a,uchar **out);
X509_REVOKED * X509_REVOKED_new(void);
void X509_REVOKED_free(X509_REVOKED *a);
X509_REVOKED * X509_REVOKED_dup(X509_REVOKED *x);
X509_CRL_INFO * d2i_X509_CRL_INFO(X509_CRL_INFO **a,uchar **in,long len);
int i2d_X509_CRL_INFO(X509_CRL_INFO *a,uchar **out);
X509_CRL_INFO * X509_CRL_INFO_new(void);
void X509_CRL_INFO_free(X509_CRL_INFO *a);
X509_CRL * d2i_X509_CRL(X509_CRL **a,uchar **in,long len);
int i2d_X509_CRL(X509_CRL *a,uchar **out);
X509_CRL * X509_CRL_new(void);
void X509_CRL_free(X509_CRL *a);
X509_CRL * X509_CRL_dup(X509_CRL *x);
int X509_CRL_add0_revoked(X509_CRL *crl,X509_REVOKED *rev);
int X509_CRL_verify(X509_CRL *crl,EVP_PKEY *r);
int X509_CRL_get0_by_serial(X509_CRL *crl,X509_REVOKED **ret,ASN1_INTEGER *serial);
int X509_CRL_get0_by_cert(X509_CRL *crl,X509_REVOKED **ret,X509 *x);
void X509_CRL_set_default_method(X509_CRL_METHOD *meth);
X509_CRL_METHOD *X509_CRL_METHOD_new(_func_int_X509_CRL_ptr *crl_init,_func_int_X509_CRL_ptr *crl_free,_func_int_X509_CRL_ptr_X509_REVOKED_ptr_ptr_ASN1_INTEGER_ptr_X509_NAME_ptr*crl_lookup,_func_int_X509_CRL_ptr_EVP_PKEY_ptr *crl_verify);
void X509_CRL_METHOD_free(X509_CRL_METHOD *m);
void X509_CRL_set_meth_data(X509_CRL *crl,void *dat);
void * X509_CRL_get_meth_data(X509_CRL *crl);
int nsseq_cb(int operation,ASN1_VALUE **pval,ASN1_ITEM *it,void *exarg);
NETSCAPE_CERT_SEQUENCE * d2i_NETSCAPE_CERT_SEQUENCE(NETSCAPE_CERT_SEQUENCE **a,uchar **in,long len);
int i2d_NETSCAPE_CERT_SEQUENCE(NETSCAPE_CERT_SEQUENCE *a,uchar **out);
NETSCAPE_CERT_SEQUENCE * NETSCAPE_CERT_SEQUENCE_new(void);
void NETSCAPE_CERT_SEQUENCE_free(NETSCAPE_CERT_SEQUENCE *a);
EVP_PKEY * d2i_PrivateKey(int type,EVP_PKEY **a,uchar **pp,long length);
EVP_PKEY * d2i_AutoPrivateKey(EVP_PKEY **a,uchar **pp,long length);
int i2d_PrivateKey(EVP_PKEY *a,uchar **pp);
int asn1_print_fsname(BIO *out,int indent,char *fname,char *sname,ASN1_PCTX *pctx);
ASN1_PCTX * ASN1_PCTX_new(void);
void ASN1_PCTX_free(ASN1_PCTX *p);
ulong ASN1_PCTX_get_flags(ASN1_PCTX *p);
void ASN1_PCTX_set_flags(ASN1_PCTX *p,ulong flags);
ulong ASN1_PCTX_get_nm_flags(ASN1_PCTX *p);
void ASN1_PCTX_set_nm_flags(ASN1_PCTX *p,ulong flags);
ulong ASN1_PCTX_get_cert_flags(ASN1_PCTX *p);
void ASN1_PCTX_set_cert_flags(ASN1_PCTX *p,ulong flags);
ulong ASN1_PCTX_get_oid_flags(ASN1_PCTX *p);
void ASN1_PCTX_set_oid_flags(ASN1_PCTX *p,ulong flags);
ulong ASN1_PCTX_get_str_flags(ASN1_PCTX *p);
void ASN1_PCTX_set_str_flags(ASN1_PCTX *p,ulong flags);
int asn1_template_print_ctx(BIO *out,ASN1_VALUE **fld,int indent,ASN1_TEMPLATE *tt,ASN1_PCTX *pctx);
int asn1_item_print_ctx(BIO *out,ASN1_VALUE **fld,int indent,ASN1_ITEM *it,char *fname,char *sname,int nohdr,ASN1_PCTX *pctx);
int ASN1_item_print(BIO *out,ASN1_VALUE *ifld,int indent,ASN1_ITEM *it,ASN1_PCTX *pctx);
int ameth_cmp(EVP_PKEY_ASN1_METHOD **a,EVP_PKEY_ASN1_METHOD **b);
int ameth_cmp_BSEARCH_CMP_FN(void *a_,void *b_);
int EVP_PKEY_asn1_get_count(void);
EVP_PKEY_ASN1_METHOD * EVP_PKEY_asn1_get0(int idx);
EVP_PKEY_ASN1_METHOD * EVP_PKEY_asn1_find(ENGINE **pe,int type);
EVP_PKEY_ASN1_METHOD * EVP_PKEY_asn1_find_str(ENGINE **pe,char *str,int len);
int EVP_PKEY_asn1_add0(EVP_PKEY_ASN1_METHOD *ameth);
int EVP_PKEY_asn1_get0_info(int *ppkey_id,int *ppkey_base_id,int *ppkey_flags,char **pinfo,char **ppem_str,EVP_PKEY_ASN1_METHOD *ameth);
EVP_PKEY_ASN1_METHOD * EVP_PKEY_get0_asn1(EVP_PKEY *pkey);
void EVP_PKEY_asn1_copy(EVP_PKEY_ASN1_METHOD *dst,EVP_PKEY_ASN1_METHOD *src);
void EVP_PKEY_asn1_free(EVP_PKEY_ASN1_METHOD *ameth);
EVP_PKEY_ASN1_METHOD * EVP_PKEY_asn1_new(int id,int flags,char *pem_str,char *info);
int EVP_PKEY_asn1_add_alias(int to,int from);
void EVP_PKEY_asn1_set_public(EVP_PKEY_ASN1_METHOD *ameth,_func_int_EVP_PKEY_ptr_X509_PUBKEY_ptr *pub_decode,_func_int_X509_PUBKEY_ptr_EVP_PKEY_ptr *pub_encode,_func_int_EVP_PKEY_ptr_EVP_PKEY_ptr *pub_cmp,_func_int_BIO_ptr_EVP_PKEY_ptr_int_ASN1_PCTX_ptr *pub_print,_func_int_EVP_PKEY_ptr *pkey_size,_func_int_EVP_PKEY_ptr *pkey_bits);
void EVP_PKEY_asn1_set_private(EVP_PKEY_ASN1_METHOD *ameth,_func_int_EVP_PKEY_ptr_PKCS8_PRIV_KEY_INFO_ptr *priv_decode,_func_int_PKCS8_PRIV_KEY_INFO_ptr_EVP_PKEY_ptr *priv_encode,_func_int_BIO_ptr_EVP_PKEY_ptr_int_ASN1_PCTX_ptr *priv_print);
void EVP_PKEY_asn1_set_param(EVP_PKEY_ASN1_METHOD *ameth,_func_int_EVP_PKEY_ptr_uchar_ptr_ptr_int *param_decode,_func_int_EVP_PKEY_ptr_uchar_ptr_ptr *param_encode,_func_int_EVP_PKEY_ptr *param_missing,_func_int_EVP_PKEY_ptr_EVP_PKEY_ptr *param_copy,_func_int_EVP_PKEY_ptr_EVP_PKEY_ptr *param_cmp,_func_int_BIO_ptr_EVP_PKEY_ptr_int_ASN1_PCTX_ptr *param_print);
void EVP_PKEY_asn1_set_free(EVP_PKEY_ASN1_METHOD *ameth,_func_void_EVP_PKEY_ptr *pkey_free);
void EVP_PKEY_asn1_set_ctrl(EVP_PKEY_ASN1_METHOD *ameth,_func_int_EVP_PKEY_ptr_int_long_void_ptr *pkey_ctrl);
void EVP_PKEY_asn1_set_item(EVP_PKEY_ASN1_METHOD *ameth,_func_int_EVP_MD_CTX_ptr_ASN1_ITEM_ptr_void_ptr_X509_ALGOR_ptr_ASN1_BIT_STRING_ptr_EVP_PKEY_ptr*item_verify,_func_int_EVP_MD_CTX_ptr_ASN1_ITEM_ptr_void_ptr_X509_ALGOR_ptr_X509_ALGOR_ptr_ASN1_BIT_STRING_ptr*item_sign);
X509_EXTENSION * d2i_X509_EXTENSION(X509_EXTENSION **a,uchar **in,long len);
int i2d_X509_EXTENSION(X509_EXTENSION *a,uchar **out);
X509_EXTENSION * X509_EXTENSION_new(void);
void X509_EXTENSION_free(X509_EXTENSION *a);
X509_EXTENSIONS * d2i_X509_EXTENSIONS(X509_EXTENSIONS **a,uchar **in,long len);
int i2d_X509_EXTENSIONS(X509_EXTENSIONS *a,uchar **out);
X509_EXTENSION * X509_EXTENSION_dup(X509_EXTENSION *x);
char * ASN1_tag2str(int tag);
int asn1_parse2(BIO *bp,uchar **pp,long length,int offset,int depth,int indent,int dump);
int ASN1_parse(BIO *bp,uchar *pp,long len,int indent);
int ASN1_parse_dump(BIO *bp,uchar *pp,long len,int indent,int dump);
ASN1_STRING *int_d2i_ASN1_bytes(ASN1_STRING **a,uchar **pp,long length,int Ptag,int Pclass,int depth,int *perr);
ASN1_STRING * d2i_ASN1_type_bytes(ASN1_STRING **a,uchar **pp,long length,int type);
int i2d_ASN1_bytes(ASN1_STRING *a,uchar **pp,int tag,int xclass);
ASN1_STRING * d2i_ASN1_bytes(ASN1_STRING **a,uchar **pp,long length,int Ptag,int Pclass);
stack_st_OPENSSL_BLOCK *ASN1_seq_unpack(uchar *buf,int len,d2i_of_void *d2i,_func_void_OPENSSL_BLOCK *free_func);
uchar * ASN1_seq_pack(stack_st_OPENSSL_BLOCK *safes,i2d_of_void *i2d,uchar **buf,int *len);
void * ASN1_unpack_string(ASN1_STRING *oct,d2i_of_void *d2i);
ASN1_STRING * ASN1_pack_string(void *obj,i2d_of_void *i2d,ASN1_STRING **oct);
ASN1_STRING * ASN1_item_pack(void *obj,ASN1_ITEM *it,ASN1_STRING **oct);
void * ASN1_item_unpack(ASN1_STRING *oct,ASN1_ITEM *it);
int pkey_cb(int operation,ASN1_VALUE **pval,ASN1_ITEM *it,void *exarg);
PKCS8_PRIV_KEY_INFO * d2i_PKCS8_PRIV_KEY_INFO(PKCS8_PRIV_KEY_INFO **a,uchar **in,long len);
int i2d_PKCS8_PRIV_KEY_INFO(PKCS8_PRIV_KEY_INFO *a,uchar **out);
PKCS8_PRIV_KEY_INFO * PKCS8_PRIV_KEY_INFO_new(void);
void PKCS8_PRIV_KEY_INFO_free(PKCS8_PRIV_KEY_INFO *a);
int PKCS8_pkey_set0(PKCS8_PRIV_KEY_INFO *priv,ASN1_OBJECT *aobj,int version,int ptype,void *pval,uchar *penc,int penclen);
int PKCS8_pkey_get0(ASN1_OBJECT **ppkalg,uchar **pk,int *ppklen,X509_ALGOR **pa,PKCS8_PRIV_KEY_INFO *p8);
int PEM_def_callback(char *buf,int num,int w,void *key);
void PEM_proc_type(char *buf,int type);
void PEM_dek_info(char *buf,char *type,int len,char *str);
void * PEM_ASN1_read(d2i_of_void *d2i,char *name,FILE *fp,void **x,pem_password_cb *cb,void *u);
int PEM_do_header(EVP_CIPHER_INFO *cipher,uchar *data,long *plen,pem_password_cb *callback,void *u);
int PEM_get_EVP_CIPHER_INFO(char *header,EVP_CIPHER_INFO *cipher);
int PEM_write_bio(BIO *bp,char *name,char *header,uchar *data,long len);
int PEM_ASN1_write_bio(i2d_of_void *i2d,char *name,BIO *bp,void *x,EVP_CIPHER *enc,uchar *kstr,int klen,pem_password_cb *callback,void *u);
int PEM_ASN1_write(i2d_of_void *i2d,char *name,FILE *fp,void *x,EVP_CIPHER *enc,uchar *kstr,int klen,pem_password_cb *callback,void *u);
int PEM_write(FILE *fp,char *name,char *header,uchar *data,long len);
int PEM_read_bio(BIO *bp,char **name,char **header,uchar **data,long *len);
int PEM_read(FILE *fp,char **name,char **header,uchar **data,long *len);
int pem_check_suffix(char *pem_str,char *suffix);
int PEM_bytes_read_bio(uchar **pdata,long *plen,char **pnm,char *name,BIO *bp,pem_password_cb *cb,void *u);
EVP_PKEY * d2i_PKCS8PrivateKey_bio(BIO *bp,EVP_PKEY **x,pem_password_cb *cb,void *u);
EVP_PKEY * d2i_PKCS8PrivateKey_fp(FILE *fp,EVP_PKEY **x,pem_password_cb *cb,void *u);
X509_SIG * PEM_read_bio_PKCS8(BIO *bp,X509_SIG **x,pem_password_cb *cb,void *u);
X509_SIG * PEM_read_PKCS8(FILE *fp,X509_SIG **x,pem_password_cb *cb,void *u);
int PEM_write_bio_PKCS8(BIO *bp,X509_SIG *x);
int PEM_write_PKCS8(FILE *fp,X509_SIG *x);
PKCS8_PRIV_KEY_INFO *PEM_read_bio_PKCS8_PRIV_KEY_INFO(BIO *bp,PKCS8_PRIV_KEY_INFO **x,pem_password_cb *cb,void *u);
PKCS8_PRIV_KEY_INFO *PEM_read_PKCS8_PRIV_KEY_INFO(FILE *fp,PKCS8_PRIV_KEY_INFO **x,pem_password_cb *cb,void *u);
int PEM_write_bio_PKCS8_PRIV_KEY_INFO(BIO *bp,PKCS8_PRIV_KEY_INFO *x);
int do_pk8pkey(BIO *bp,EVP_PKEY *x,int isder,int nid,EVP_CIPHER *enc,char *kstr,int klen,pem_password_cb *cb,void *u);
int PEM_write_bio_PKCS8PrivateKey_nid(BIO *bp,EVP_PKEY *x,int nid,char *kstr,int klen,pem_password_cb *cb,void *u);
int PEM_write_bio_PKCS8PrivateKey(BIO *bp,EVP_PKEY *x,EVP_CIPHER *enc,char *kstr,int klen,pem_password_cb *cb,void *u);
int i2d_PKCS8PrivateKey_bio(BIO *bp,EVP_PKEY *x,EVP_CIPHER *enc,char *kstr,int klen,pem_password_cb *cb,void *u);
int i2d_PKCS8PrivateKey_nid_bio(BIO *bp,EVP_PKEY *x,int nid,char *kstr,int klen,pem_password_cb *cb,void *u);
int do_pk8pkey_fp(FILE *fp,EVP_PKEY *x,int isder,int nid,EVP_CIPHER *enc,char *kstr,int klen,pem_password_cb *cb,void *u);
int i2d_PKCS8PrivateKey_fp(FILE *fp,EVP_PKEY *x,EVP_CIPHER *enc,char *kstr,int klen,pem_password_cb *cb,void *u);
int i2d_PKCS8PrivateKey_nid_fp(FILE *fp,EVP_PKEY *x,int nid,char *kstr,int klen,pem_password_cb *cb,void *u);
int PEM_write_PKCS8PrivateKey_nid(FILE *fp,EVP_PKEY *x,int nid,char *kstr,int klen,pem_password_cb *cb,void *u);
int PEM_write_PKCS8PrivateKey(FILE *fp,EVP_PKEY *x,EVP_CIPHER *enc,char *kstr,int klen,pem_password_cb *cb,void *u);
int PEM_write_PKCS8_PRIV_KEY_INFO(FILE *fp,PKCS8_PRIV_KEY_INFO *x);
int check_suite_b(EVP_PKEY *pkey,int sign_nid,ulong *pflags);
ulong X509_issuer_and_serial_hash(X509 *a);
int X509_CRL_match(X509_CRL *a,X509_CRL *b);
X509_NAME * X509_get_issuer_name(X509 *a);
X509_NAME * X509_get_subject_name(X509 *a);
ASN1_INTEGER * X509_get_serialNumber(X509 *a);
int X509_cmp(X509 *a,X509 *b);
int X509_NAME_cmp(X509_NAME *a,X509_NAME *b);
int X509_issuer_and_serial_cmp(X509 *a,X509 *b);
int X509_issuer_name_cmp(X509 *a,X509 *b);
int X509_subject_name_cmp(X509 *a,X509 *b);
int X509_CRL_cmp(X509_CRL *a,X509_CRL *b);
ulong X509_NAME_hash(X509_NAME *x);
ulong X509_issuer_name_hash(X509 *x);
ulong X509_subject_name_hash(X509 *x);
ulong X509_NAME_hash_old(X509_NAME *x);
ulong X509_issuer_name_hash_old(X509 *x);
ulong X509_subject_name_hash_old(X509 *x);
X509 * X509_find_by_issuer_and_serial(stack_st_X509 *sk,X509_NAME *name,ASN1_INTEGER *serial);
X509 * X509_find_by_subject(stack_st_X509 *sk,X509_NAME *name);
EVP_PKEY * X509_get_pubkey(X509 *x);
ASN1_BIT_STRING * X509_get0_pubkey_bitstr(X509 *x);
int X509_check_private_key(X509 *x,EVP_PKEY *k);
int X509_chain_check_suiteb(int *perror_depth,X509 *x,stack_st_X509 *chain,ulong flags);
int X509_CRL_check_suiteb(X509_CRL *crl,EVP_PKEY *pk,ulong flags);
stack_st_X509 * X509_chain_up_ref(stack_st_X509 *chain);
char * X509_NAME_oneline(X509_NAME *a,char *buf,int len);
int null_callback(int ok,X509_STORE_CTX *e);
X509 * find_issuer(X509_STORE_CTX *ctx,stack_st_X509 *sk,X509 *x);
int get_issuer_sk(X509 **issuer,X509_STORE_CTX *ctx,X509 *x);
int crl_extension_match(X509_CRL *a,X509_CRL *b,int nid);
int check_issued(X509_STORE_CTX *ctx,X509 *x,X509 *issuer);
int check_policy(X509_STORE_CTX *ctx);
int cert_crl(X509_STORE_CTX *ctx,X509_CRL *crl,X509 *x);
ASN1_TIME * X509_time_adj_ex(ASN1_TIME *s,int offset_day,long offset_sec,time_t *in_tm);
ASN1_TIME * X509_time_adj(ASN1_TIME *s,long offset_sec,time_t *in_tm);
int X509_cmp_time(ASN1_TIME *ctm,time_t *cmp_time);
int internal_verify(X509_STORE_CTX *ctx);
int X509_cmp_current_time(ASN1_TIME *ctm);
int check_crl_time(X509_STORE_CTX *ctx,X509_CRL *crl,int notify);
int get_crl_sk(X509_STORE_CTX *ctx,X509_CRL **pcrl,X509_CRL **pdcrl,X509 **pissuer,int *pscore,uint *preasons,stack_st_X509_CRL *crls);
int check_revocation(X509_STORE_CTX *ctx);
ASN1_TIME * X509_gmtime_adj(ASN1_TIME *s,long adj);
int X509_get_pubkey_parameters(EVP_PKEY *pkey,stack_st_X509 *chain);
int X509_verify_cert(X509_STORE_CTX *ctx);
X509_CRL * X509_CRL_diff(X509_CRL *base,X509_CRL *newer,EVP_PKEY *skey,EVP_MD *md,uint flags);
int X509_STORE_CTX_get_ex_new_index(long argl,void *argp,CRYPTO_EX_new *new_func,CRYPTO_EX_dup *dup_func,CRYPTO_EX_free *free_func);
int X509_STORE_CTX_set_ex_data(X509_STORE_CTX *ctx,int idx,void *data);
void * X509_STORE_CTX_get_ex_data(X509_STORE_CTX *ctx,int idx);
int X509_STORE_CTX_get_error(X509_STORE_CTX *ctx);
void X509_STORE_CTX_set_error(X509_STORE_CTX *ctx,int err);
int X509_STORE_CTX_get_error_depth(X509_STORE_CTX *ctx);
X509 * X509_STORE_CTX_get_current_cert(X509_STORE_CTX *ctx);
stack_st_X509 * X509_STORE_CTX_get_chain(X509_STORE_CTX *ctx);
stack_st_X509 * X509_STORE_CTX_get1_chain(X509_STORE_CTX *ctx);
X509 * X509_STORE_CTX_get0_current_issuer(X509_STORE_CTX *ctx);
X509_CRL * X509_STORE_CTX_get0_current_crl(X509_STORE_CTX *ctx);
X509_STORE_CTX * X509_STORE_CTX_get0_parent_ctx(X509_STORE_CTX *ctx);
void X509_STORE_CTX_set_cert(X509_STORE_CTX *ctx,X509 *x);
void X509_STORE_CTX_set_chain(X509_STORE_CTX *ctx,stack_st_X509 *sk);
void X509_STORE_CTX_set0_crls(X509_STORE_CTX *ctx,stack_st_X509_CRL *sk);
int X509_STORE_CTX_purpose_inherit(X509_STORE_CTX *ctx,int def_purpose,int purpose,int trust);
int X509_STORE_CTX_set_purpose(X509_STORE_CTX *ctx,int purpose);
int X509_STORE_CTX_set_trust(X509_STORE_CTX *ctx,int trust);
X509_STORE_CTX * X509_STORE_CTX_new(void);
void X509_STORE_CTX_trusted_stack(X509_STORE_CTX *ctx,stack_st_X509 *sk);
void X509_STORE_CTX_cleanup(X509_STORE_CTX *ctx);
void X509_STORE_CTX_free(X509_STORE_CTX *ctx);
int X509_STORE_CTX_init(X509_STORE_CTX *ctx,X509_STORE *store,X509 *x509,stack_st_X509 *chain);
void X509_STORE_CTX_set_depth(X509_STORE_CTX *ctx,int depth);
void X509_STORE_CTX_set_flags(X509_STORE_CTX *ctx,ulong flags);
void X509_STORE_CTX_set_time(X509_STORE_CTX *ctx,ulong flags,time_t t);
void X509_STORE_CTX_set_verify_cb(X509_STORE_CTX *ctx,_func_int_int_X509_STORE_CTX_ptr *verify_cb);
X509_POLICY_TREE * X509_STORE_CTX_get0_policy_tree(X509_STORE_CTX *ctx);
int X509_STORE_CTX_get_explicit_policy(X509_STORE_CTX *ctx);
int X509_STORE_CTX_set_default(X509_STORE_CTX *ctx,char *name);
X509_VERIFY_PARAM * X509_STORE_CTX_get0_param(X509_STORE_CTX *ctx);
void X509_STORE_CTX_set0_param(X509_STORE_CTX *ctx,X509_VERIFY_PARAM *param);
int check_crl(X509_STORE_CTX *ctx,X509_CRL *crl);
int X509_CRL_set_version(X509_CRL *x,long version);
int X509_CRL_set_issuer_name(X509_CRL *x,X509_NAME *name);
int X509_CRL_set_lastUpdate(X509_CRL *x,ASN1_TIME *tm);
int X509_CRL_set_nextUpdate(X509_CRL *x,ASN1_TIME *tm);
int X509_CRL_sort(X509_CRL *c);
int X509_REVOKED_set_revocationDate(X509_REVOKED *x,ASN1_TIME *tm);
int X509_REVOKED_set_serialNumber(X509_REVOKED *x,ASN1_INTEGER *serial);
int X509_NAME_entry_count(X509_NAME *name);
int X509_NAME_get_index_by_OBJ(X509_NAME *name,ASN1_OBJECT *obj,int lastpos);
int X509_NAME_get_index_by_NID(X509_NAME *name,int nid,int lastpos);
X509_NAME_ENTRY * X509_NAME_get_entry(X509_NAME *name,int loc);
X509_NAME_ENTRY * X509_NAME_delete_entry(X509_NAME *name,int loc);
int X509_NAME_add_entry(X509_NAME *name,X509_NAME_ENTRY *ne,int loc,int set);
int X509_NAME_ENTRY_set_object(X509_NAME_ENTRY *ne,ASN1_OBJECT *obj);
int X509_NAME_ENTRY_set_data(X509_NAME_ENTRY *ne,int type,uchar *bytes,int len);
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_OBJ(X509_NAME_ENTRY **ne,ASN1_OBJECT *obj,int type,uchar *bytes,int len);
int X509_NAME_add_entry_by_OBJ(X509_NAME *name,ASN1_OBJECT *obj,int type,uchar *bytes,int len,int loc,int set);
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_txt(X509_NAME_ENTRY **ne,char *field,int type,uchar *bytes,int len);
int X509_NAME_add_entry_by_txt(X509_NAME *name,char *field,int type,uchar *bytes,int len,int loc,int set);
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_NID(X509_NAME_ENTRY **ne,int nid,int type,uchar *bytes,int len);
int X509_NAME_add_entry_by_NID(X509_NAME *name,int nid,int type,uchar *bytes,int len,int loc,int set);
ASN1_OBJECT * X509_NAME_ENTRY_get_object(X509_NAME_ENTRY *ne);
ASN1_STRING * X509_NAME_ENTRY_get_data(X509_NAME_ENTRY *ne);
int X509_NAME_get_text_by_OBJ(X509_NAME *name,ASN1_OBJECT *obj,char *buf,int len);
int X509_NAME_get_text_by_NID(X509_NAME *name,int nid,char *buf,int len);
int X509v3_get_ext_count(stack_st_X509_EXTENSION *x);
int X509v3_get_ext_by_OBJ(stack_st_X509_EXTENSION *sk,ASN1_OBJECT *obj,int lastpos);
int X509v3_get_ext_by_NID(stack_st_X509_EXTENSION *x,int nid,int lastpos);
int X509v3_get_ext_by_critical(stack_st_X509_EXTENSION *sk,int crit,int lastpos);
X509_EXTENSION * X509v3_get_ext(stack_st_X509_EXTENSION *x,int loc);
X509_EXTENSION * X509v3_delete_ext(stack_st_X509_EXTENSION *x,int loc);
stack_st_X509_EXTENSION * X509v3_add_ext(stack_st_X509_EXTENSION **x,X509_EXTENSION *ex,int loc);
int X509_EXTENSION_set_object(X509_EXTENSION *ex,ASN1_OBJECT *obj);
int X509_EXTENSION_set_critical(X509_EXTENSION *ex,int crit);
int X509_EXTENSION_set_data(X509_EXTENSION *ex,ASN1_OCTET_STRING *data);
X509_EXTENSION *X509_EXTENSION_create_by_OBJ(X509_EXTENSION **ex,ASN1_OBJECT *obj,int crit,ASN1_OCTET_STRING *data);
X509_EXTENSION *X509_EXTENSION_create_by_NID(X509_EXTENSION **ex,int nid,int crit,ASN1_OCTET_STRING *data);
ASN1_OBJECT * X509_EXTENSION_get_object(X509_EXTENSION *ex);
ASN1_OCTET_STRING * X509_EXTENSION_get_data(X509_EXTENSION *ex);
int X509_EXTENSION_get_critical(X509_EXTENSION *ex);
int X509_CRL_get_ext_count(X509_CRL *x);
int X509_CRL_get_ext_by_NID(X509_CRL *x,int nid,int lastpos);
int X509_CRL_get_ext_by_OBJ(X509_CRL *x,ASN1_OBJECT *obj,int lastpos);
int X509_CRL_get_ext_by_critical(X509_CRL *x,int crit,int lastpos);
X509_EXTENSION * X509_CRL_get_ext(X509_CRL *x,int loc);
X509_EXTENSION * X509_CRL_delete_ext(X509_CRL *x,int loc);
void * X509_CRL_get_ext_d2i(X509_CRL *x,int nid,int *crit,int *idx);
int X509_CRL_add1_ext_i2d(X509_CRL *x,int nid,void *value,int crit,ulong flags);
int X509_CRL_add_ext(X509_CRL *x,X509_EXTENSION *ex,int loc);
int X509_get_ext_count(X509 *x);
int X509_get_ext_by_NID(X509 *x,int nid,int lastpos);
int X509_get_ext_by_OBJ(X509 *x,ASN1_OBJECT *obj,int lastpos);
int X509_get_ext_by_critical(X509 *x,int crit,int lastpos);
X509_EXTENSION * X509_get_ext(X509 *x,int loc);
X509_EXTENSION * X509_delete_ext(X509 *x,int loc);
int X509_add_ext(X509 *x,X509_EXTENSION *ex,int loc);
void * X509_get_ext_d2i(X509 *x,int nid,int *crit,int *idx);
int X509_add1_ext_i2d(X509 *x,int nid,void *value,int crit,ulong flags);
int X509_REVOKED_get_ext_count(X509_REVOKED *x);
int X509_REVOKED_get_ext_by_NID(X509_REVOKED *x,int nid,int lastpos);
int X509_REVOKED_get_ext_by_OBJ(X509_REVOKED *x,ASN1_OBJECT *obj,int lastpos);
int X509_REVOKED_get_ext_by_critical(X509_REVOKED *x,int crit,int lastpos);
X509_EXTENSION * X509_REVOKED_get_ext(X509_REVOKED *x,int loc);
X509_EXTENSION * X509_REVOKED_delete_ext(X509_REVOKED *x,int loc);
int X509_REVOKED_add_ext(X509_REVOKED *x,X509_EXTENSION *ex,int loc);
void * X509_REVOKED_get_ext_d2i(X509_REVOKED *x,int nid,int *crit,int *idx);
int X509_REVOKED_add1_ext_i2d(X509_REVOKED *x,int nid,void *value,int crit,ulong flags);
int X509at_get_attr_count(stack_st_X509_ATTRIBUTE *x);
int X509at_get_attr_by_OBJ(stack_st_X509_ATTRIBUTE *sk,ASN1_OBJECT *obj,int lastpos);
int X509at_get_attr_by_NID(stack_st_X509_ATTRIBUTE *x,int nid,int lastpos);
X509_ATTRIBUTE * X509at_get_attr(stack_st_X509_ATTRIBUTE *x,int loc);
X509_ATTRIBUTE * X509at_delete_attr(stack_st_X509_ATTRIBUTE *x,int loc);
stack_st_X509_ATTRIBUTE * X509at_add1_attr(stack_st_X509_ATTRIBUTE **x,X509_ATTRIBUTE *attr);
int X509_ATTRIBUTE_set1_object(X509_ATTRIBUTE *attr,ASN1_OBJECT *obj);
int X509_ATTRIBUTE_set1_data(X509_ATTRIBUTE *attr,int attrtype,void *data,int len);
X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_OBJ(X509_ATTRIBUTE **attr,ASN1_OBJECT *obj,int atrtype,void *data,int len);
stack_st_X509_ATTRIBUTE *X509at_add1_attr_by_OBJ(stack_st_X509_ATTRIBUTE **x,ASN1_OBJECT *obj,int type,uchar *bytes,int len);
X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_NID(X509_ATTRIBUTE **attr,int nid,int atrtype,void *data,int len);
stack_st_X509_ATTRIBUTE *X509at_add1_attr_by_NID(stack_st_X509_ATTRIBUTE **x,int nid,int type,uchar *bytes,int len);
X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_txt(X509_ATTRIBUTE **attr,char *atrname,int type,uchar *bytes,int len);
stack_st_X509_ATTRIBUTE *X509at_add1_attr_by_txt(stack_st_X509_ATTRIBUTE **x,char *attrname,int type,uchar *bytes,int len);
int X509_ATTRIBUTE_count(X509_ATTRIBUTE *attr);
ASN1_OBJECT * X509_ATTRIBUTE_get0_object(X509_ATTRIBUTE *attr);
ASN1_TYPE * X509_ATTRIBUTE_get0_type(X509_ATTRIBUTE *attr,int idx);
void * X509_ATTRIBUTE_get0_data(X509_ATTRIBUTE *attr,int idx,int atrtype,void *data);
void * X509at_get0_data_by_OBJ(stack_st_X509_ATTRIBUTE *x,ASN1_OBJECT *obj,int lastpos,int type);
int x509_object_cmp(X509_OBJECT **a,X509_OBJECT **b);
void cleanup(X509_OBJECT *a);
int x509_object_idx_cnt(stack_st_X509_OBJECT *h,int type,X509_NAME *name,int *pnmatch);
X509_LOOKUP * X509_LOOKUP_new(X509_LOOKUP_METHOD *method);
void X509_LOOKUP_free(X509_LOOKUP *ctx);
int X509_LOOKUP_init(X509_LOOKUP *ctx);
int X509_LOOKUP_shutdown(X509_LOOKUP *ctx);
int X509_LOOKUP_ctrl(X509_LOOKUP *ctx,int cmd,char *argc,long argl,char **ret);
int X509_LOOKUP_by_subject(X509_LOOKUP *ctx,int type,X509_NAME *name,X509_OBJECT *ret);
int X509_LOOKUP_by_issuer_serial(X509_LOOKUP *ctx,int type,X509_NAME *name,ASN1_INTEGER *serial,X509_OBJECT *ret);
int X509_LOOKUP_by_fingerprint(X509_LOOKUP *ctx,int type,uchar *bytes,int len,X509_OBJECT *ret);
int X509_LOOKUP_by_alias(X509_LOOKUP *ctx,int type,char *str,int len,X509_OBJECT *ret);
X509_STORE * X509_STORE_new(void);
void X509_STORE_free(X509_STORE *vfy);
X509_LOOKUP * X509_STORE_add_lookup(X509_STORE *v,X509_LOOKUP_METHOD *m);
void X509_OBJECT_up_ref_count(X509_OBJECT *a);
void X509_OBJECT_free_contents(X509_OBJECT *a);
int X509_OBJECT_idx_by_subject(stack_st_X509_OBJECT *h,int type,X509_NAME *name);
X509_OBJECT * X509_OBJECT_retrieve_by_subject(stack_st_X509_OBJECT *h,int type,X509_NAME *name);
int X509_STORE_get_by_subject(X509_STORE_CTX *vs,int type,X509_NAME *name,X509_OBJECT *ret);
stack_st_X509 * X509_STORE_get1_certs(X509_STORE_CTX *ctx,X509_NAME *nm);
stack_st_X509_CRL * X509_STORE_get1_crls(X509_STORE_CTX *ctx,X509_NAME *nm);
X509_OBJECT * X509_OBJECT_retrieve_match(stack_st_X509_OBJECT *h,X509_OBJECT *x);
int X509_STORE_add_cert(X509_STORE *ctx,X509 *x);
int X509_STORE_add_crl(X509_STORE *ctx,X509_CRL *x);
int X509_STORE_CTX_get1_issuer(X509 **issuer,X509_STORE_CTX *ctx,X509 *x);
int X509_STORE_set_flags(X509_STORE *ctx,ulong flags);
int X509_STORE_set_depth(X509_STORE *ctx,int depth);
int X509_STORE_set_purpose(X509_STORE *ctx,int purpose);
int X509_STORE_set_trust(X509_STORE *ctx,int trust);
int X509_STORE_set1_param(X509_STORE *ctx,X509_VERIFY_PARAM *param);
void X509_STORE_set_verify_cb(X509_STORE *ctx,_func_int_int_X509_STORE_CTX_ptr *verify_cb);
void X509_STORE_set_lookup_crls_cb(X509_STORE *ctx,_func_stack_st_X509_CRL_ptr_X509_STORE_CTX_ptr_X509_NAME_ptr *cb);
X509_STORE * X509_STORE_CTX_get0_store(X509_STORE_CTX *ctx);
int X509_verify(X509 *a,EVP_PKEY *r);
int X509_REQ_verify(X509_REQ *a,EVP_PKEY *r);
int NETSCAPE_SPKI_verify(NETSCAPE_SPKI *a,EVP_PKEY *r);
int X509_sign(X509 *x,EVP_PKEY *pkey,EVP_MD *md);
int X509_sign_ctx(X509 *x,EVP_MD_CTX *ctx);
int X509_http_nbio(OCSP_REQ_CTX *rctx,X509 **pcert);
int X509_REQ_sign(X509_REQ *x,EVP_PKEY *pkey,EVP_MD *md);
int X509_REQ_sign_ctx(X509_REQ *x,EVP_MD_CTX *ctx);
int X509_CRL_sign(X509_CRL *x,EVP_PKEY *pkey,EVP_MD *md);
int X509_CRL_sign_ctx(X509_CRL *x,EVP_MD_CTX *ctx);
int X509_CRL_http_nbio(OCSP_REQ_CTX *rctx,X509_CRL **pcrl);
int NETSCAPE_SPKI_sign(NETSCAPE_SPKI *x,EVP_PKEY *pkey,EVP_MD *md);
X509 * d2i_X509_fp(FILE *fp,X509 **x509);
int i2d_X509_fp(FILE *fp,X509 *x509);
X509 * d2i_X509_bio(BIO *bp,X509 **x509);
int i2d_X509_bio(BIO *bp,X509 *x509);
X509_CRL * d2i_X509_CRL_fp(FILE *fp,X509_CRL **crl);
int i2d_X509_CRL_fp(FILE *fp,X509_CRL *crl);
X509_CRL * d2i_X509_CRL_bio(BIO *bp,X509_CRL **crl);
int i2d_X509_CRL_bio(BIO *bp,X509_CRL *crl);
PKCS7 * d2i_PKCS7_fp(FILE *fp,PKCS7 **p7);
int i2d_PKCS7_fp(FILE *fp,PKCS7 *p7);
PKCS7 * d2i_PKCS7_bio(BIO *bp,PKCS7 **p7);
int i2d_PKCS7_bio(BIO *bp,PKCS7 *p7);
X509_REQ * d2i_X509_REQ_fp(FILE *fp,X509_REQ **req);
int i2d_X509_REQ_fp(FILE *fp,X509_REQ *req);
X509_REQ * d2i_X509_REQ_bio(BIO *bp,X509_REQ **req);
int i2d_X509_REQ_bio(BIO *bp,X509_REQ *req);
RSA * d2i_RSAPrivateKey_fp(FILE *fp,RSA **rsa);
int i2d_RSAPrivateKey_fp(FILE *fp,RSA *rsa);
RSA * d2i_RSAPublicKey_fp(FILE *fp,RSA **rsa);
RSA * d2i_RSA_PUBKEY_fp(FILE *fp,RSA **rsa);
int i2d_RSAPublicKey_fp(FILE *fp,RSA *rsa);
int i2d_RSA_PUBKEY_fp(FILE *fp,RSA *rsa);
RSA * d2i_RSAPrivateKey_bio(BIO *bp,RSA **rsa);
int i2d_RSAPrivateKey_bio(BIO *bp,RSA *rsa);
RSA * d2i_RSAPublicKey_bio(BIO *bp,RSA **rsa);
RSA * d2i_RSA_PUBKEY_bio(BIO *bp,RSA **rsa);
int i2d_RSAPublicKey_bio(BIO *bp,RSA *rsa);
int i2d_RSA_PUBKEY_bio(BIO *bp,RSA *rsa);
DSA * d2i_DSAPrivateKey_fp(FILE *fp,DSA **dsa);
int i2d_DSAPrivateKey_fp(FILE *fp,DSA *dsa);
DSA * d2i_DSA_PUBKEY_fp(FILE *fp,DSA **dsa);
int i2d_DSA_PUBKEY_fp(FILE *fp,DSA *dsa);
DSA * d2i_DSAPrivateKey_bio(BIO *bp,DSA **dsa);
int i2d_DSAPrivateKey_bio(BIO *bp,DSA *dsa);
DSA * d2i_DSA_PUBKEY_bio(BIO *bp,DSA **dsa);
int i2d_DSA_PUBKEY_bio(BIO *bp,DSA *dsa);
EC_KEY * d2i_EC_PUBKEY_fp(FILE *fp,EC_KEY **eckey);
int i2d_EC_PUBKEY_fp(FILE *fp,EC_KEY *eckey);
EC_KEY * d2i_ECPrivateKey_fp(FILE *fp,EC_KEY **eckey);
int i2d_ECPrivateKey_fp(FILE *fp,EC_KEY *eckey);
EC_KEY * d2i_EC_PUBKEY_bio(BIO *bp,EC_KEY **eckey);
int i2d_EC_PUBKEY_bio(BIO *bp,EC_KEY *ecdsa);
EC_KEY * d2i_ECPrivateKey_bio(BIO *bp,EC_KEY **eckey);
int i2d_ECPrivateKey_bio(BIO *bp,EC_KEY *eckey);
int X509_pubkey_digest(X509 *data,EVP_MD *type,uchar *md,uint *len);
int X509_digest(X509 *data,EVP_MD *type,uchar *md,uint *len);
int X509_CRL_digest(X509_CRL *data,EVP_MD *type,uchar *md,uint *len);
int X509_REQ_digest(X509_REQ *data,EVP_MD *type,uchar *md,uint *len);
int X509_NAME_digest(X509_NAME *data,EVP_MD *type,uchar *md,uint *len);
int PKCS7_ISSUER_AND_SERIAL_digest(PKCS7_ISSUER_AND_SERIAL *data,EVP_MD *type,uchar *md,uint *len);
X509_SIG * d2i_PKCS8_fp(FILE *fp,X509_SIG **p8);
int i2d_PKCS8_fp(FILE *fp,X509_SIG *p8);
X509_SIG * d2i_PKCS8_bio(BIO *bp,X509_SIG **p8);
int i2d_PKCS8_bio(BIO *bp,X509_SIG *p8);
PKCS8_PRIV_KEY_INFO * d2i_PKCS8_PRIV_KEY_INFO_fp(FILE *fp,PKCS8_PRIV_KEY_INFO **p8inf);
int i2d_PKCS8_PRIV_KEY_INFO_fp(FILE *fp,PKCS8_PRIV_KEY_INFO *p8inf);
int i2d_PKCS8PrivateKeyInfo_fp(FILE *fp,EVP_PKEY *key);
int i2d_PrivateKey_fp(FILE *fp,EVP_PKEY *pkey);
EVP_PKEY * d2i_PrivateKey_fp(FILE *fp,EVP_PKEY **a);
int i2d_PUBKEY_fp(FILE *fp,EVP_PKEY *pkey);
EVP_PKEY * d2i_PUBKEY_fp(FILE *fp,EVP_PKEY **a);
PKCS8_PRIV_KEY_INFO * d2i_PKCS8_PRIV_KEY_INFO_bio(BIO *bp,PKCS8_PRIV_KEY_INFO **p8inf);
int i2d_PKCS8_PRIV_KEY_INFO_bio(BIO *bp,PKCS8_PRIV_KEY_INFO *p8inf);
int i2d_PKCS8PrivateKeyInfo_bio(BIO *bp,EVP_PKEY *key);
int i2d_PrivateKey_bio(BIO *bp,EVP_PKEY *pkey);
EVP_PKEY * d2i_PrivateKey_bio(BIO *bp,EVP_PKEY **a);
int i2d_PUBKEY_bio(BIO *bp,EVP_PKEY *pkey);
EVP_PKEY * d2i_PUBKEY_bio(BIO *bp,EVP_PKEY **a);
int tr_cmp(X509_TRUST **a,X509_TRUST **b);
int obj_trust(int id,X509 *x,int flags);
int trust_compat(X509_TRUST *trust,X509 *x,int flags);
void trtable_free(X509_TRUST *p);
int trust_1oid(X509_TRUST *trust,X509 *x,int flags);
int trust_1oidany(X509_TRUST *trust,X509 *x,int flags);
_func_int_int_X509_ptr_int * X509_TRUST_set_default(_func_int_int_X509_ptr_int *trust);
int X509_TRUST_get_count(void);
X509_TRUST * X509_TRUST_get0(int idx);
int X509_TRUST_get_by_id(int id);
int X509_check_trust(X509 *x,int id,int flags);
int X509_TRUST_set(int *t,int trust);
int X509_TRUST_add(int id,int flags,_func_int_X509_TRUST_ptr_X509_ptr_int *ck,char *name,int arg1,void *arg2);
void X509_TRUST_cleanup(void);
int X509_TRUST_get_flags(X509_TRUST *xp);
char * X509_TRUST_get0_name(X509_TRUST *xp);
int X509_TRUST_get_trust(X509_TRUST *xp);
void str_free(char *s);
void x509_verify_param_zero(X509_VERIFY_PARAM *param);
void X509_VERIFY_PARAM_free(X509_VERIFY_PARAM *param);
char * str_copy(char *s);
int int_x509_param_set1(char **pdest,size_t *pdestlen,char *src,size_t srclen);
int param_cmp(X509_VERIFY_PARAM **a,X509_VERIFY_PARAM **b);
int table_cmp_BSEARCH_CMP_FN(void *a_,void *b_);
int int_x509_param_set_hosts(X509_VERIFY_PARAM_ID *id,int mode,char *name,size_t namelen);
X509_VERIFY_PARAM * X509_VERIFY_PARAM_new(void);
int X509_VERIFY_PARAM_set1_name(X509_VERIFY_PARAM *param,char *name);
int X509_VERIFY_PARAM_set_flags(X509_VERIFY_PARAM *param,ulong flags);
int X509_VERIFY_PARAM_clear_flags(X509_VERIFY_PARAM *param,ulong flags);
ulong X509_VERIFY_PARAM_get_flags(X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_set_purpose(X509_VERIFY_PARAM *param,int purpose);
int X509_VERIFY_PARAM_set_trust(X509_VERIFY_PARAM *param,int trust);
void X509_VERIFY_PARAM_set_depth(X509_VERIFY_PARAM *param,int depth);
void X509_VERIFY_PARAM_set_time(X509_VERIFY_PARAM *param,time_t t);
int X509_VERIFY_PARAM_add0_policy(X509_VERIFY_PARAM *param,ASN1_OBJECT *policy);
int X509_VERIFY_PARAM_set1_policies(X509_VERIFY_PARAM *param,stack_st_ASN1_OBJECT *policies);
int X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM *param,char *name,size_t namelen);
int X509_VERIFY_PARAM_add1_host(X509_VERIFY_PARAM *param,char *name,size_t namelen);
void X509_VERIFY_PARAM_set_hostflags(X509_VERIFY_PARAM *param,uint flags);
char * X509_VERIFY_PARAM_get0_peername(X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_set1_email(X509_VERIFY_PARAM *param,char *email,size_t emaillen);
int X509_VERIFY_PARAM_set1_ip(X509_VERIFY_PARAM *param,uchar *ip,size_t iplen);
int X509_VERIFY_PARAM_inherit(X509_VERIFY_PARAM *dest,X509_VERIFY_PARAM *src);
int X509_VERIFY_PARAM_set1(X509_VERIFY_PARAM *to,X509_VERIFY_PARAM *from);
int X509_VERIFY_PARAM_set1_ip_asc(X509_VERIFY_PARAM *param,char *ipasc);
int X509_VERIFY_PARAM_get_depth(X509_VERIFY_PARAM *param);
char * X509_VERIFY_PARAM_get0_name(X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_add0_table(X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_get_count(void);
X509_VERIFY_PARAM * X509_VERIFY_PARAM_get0(int id);
X509_VERIFY_PARAM * X509_VERIFY_PARAM_lookup(char *name);
void X509_VERIFY_PARAM_table_cleanup(void);
int ext_cmp(X509V3_EXT_METHOD **a,X509V3_EXT_METHOD **b);
int ext_cmp_BSEARCH_CMP_FN(void *a_,void *b_);
void ext_list_free(X509V3_EXT_METHOD *ext);
int X509V3_EXT_add(X509V3_EXT_METHOD *ext);
X509V3_EXT_METHOD * X509V3_EXT_get_nid(int nid);
X509V3_EXT_METHOD * X509V3_EXT_get(X509_EXTENSION *ext);
int X509V3_EXT_free(int nid,void *ext_data);
int X509V3_EXT_add_list(X509V3_EXT_METHOD *extlist);
int X509V3_EXT_add_alias(int nid_to,int nid_from);
void X509V3_EXT_cleanup(void);
int X509V3_add_standard_extensions(void);
void * X509V3_EXT_d2i(X509_EXTENSION *ext);
void * X509V3_get_d2i(stack_st_X509_EXTENSION *x,int nid,int *crit,int *idx);
int X509V3_add1_i2d(stack_st_X509_EXTENSION **x,int nid,void *value,int crit,ulong flags);
int equal_nocase(uchar *pattern,size_t pattern_len,uchar *subject,size_t subject_len,uint flags);
void X509V3_conf_free(CONF_VALUE *conf);
void str_free(OPENSSL_STRING str);
int sk_strcmp(char **a,char **b);
char * strip_spaces(char *name);
int equal_case(uchar *pattern,size_t pattern_len,uchar *subject,size_t subject_len,uint flags);
int equal_wildcard(uchar *pattern,size_t pattern_len,uchar *subject,size_t subject_len,uint flags);
int do_check_string(ASN1_STRING *a,int cmp_type,equal_fn equal,uint flags,char *b,size_t blen,char **peername);
int do_x509_check(X509 *x,char *chk,size_t chklen,uint flags,int check_type,char **peername);
int ipv4_from_asc(uchar *v4,char *in);
int ipv6_cb(char *elem,int len,void *usr);
int equal_email(uchar *a,size_t a_len,uchar *b,size_t b_len,uint unused_flags);
int X509V3_add_value(char *name,char *value,stack_st_CONF_VALUE **extlist);
int X509V3_add_value_uchar(char *name,uchar *value,stack_st_CONF_VALUE **extlist);
int X509V3_add_value_bool(char *name,int asn1_bool,stack_st_CONF_VALUE **extlist);
int X509V3_add_value_bool_nf(char *name,int asn1_bool,stack_st_CONF_VALUE **extlist);
char * i2s_ASN1_ENUMERATED(X509V3_EXT_METHOD *method,ASN1_ENUMERATED *a);
char * i2s_ASN1_INTEGER(X509V3_EXT_METHOD *method,ASN1_INTEGER *a);
ASN1_INTEGER * s2i_ASN1_INTEGER(X509V3_EXT_METHOD *method,char *value);
int X509V3_add_value_int(char *name,ASN1_INTEGER *aint,stack_st_CONF_VALUE **extlist);
int X509V3_get_value_bool(CONF_VALUE *value,int *asn1_bool);
int X509V3_get_value_int(CONF_VALUE *value,ASN1_INTEGER **aint);
stack_st_CONF_VALUE * X509V3_parse_list(char *line);
char * hex_to_string(uchar *buffer,long len);
uchar * string_to_hex(char *str,long *len);
int name_cmp(char *name,char *cmp);
void X509_email_free(stack_st_OPENSSL_STRING *sk);
int append_ia5(stack_st_OPENSSL_STRING **sk,ASN1_IA5STRING *email);
stack_st_OPENSSL_STRING * get_email(X509_NAME *name,GENERAL_NAMES *gens);
stack_st_OPENSSL_STRING * X509_get1_email(X509 *x);
stack_st_OPENSSL_STRING * X509_REQ_get1_email(X509_REQ *x);
stack_st_OPENSSL_STRING * X509_get1_ocsp(X509 *x);
int X509_check_host(X509 *x,char *chk,size_t chklen,uint flags,char **peername);
int X509_check_email(X509 *x,char *chk,size_t chklen,uint flags);
int X509_check_ip(X509 *x,uchar *chk,size_t chklen,uint flags);
int a2i_ipadd(uchar *ipout,char *ipasc);
int X509_check_ip_asc(X509 *x,char *ipasc,uint flags);
ASN1_OCTET_STRING * a2i_IPADDRESS(char *ipasc);
ASN1_OCTET_STRING * a2i_IPADDRESS_NC(char *ipasc);
int X509V3_NAME_from_section(X509_NAME *nm,stack_st_CONF_VALUE *dn_sk,ulong chtype);
GENERAL_NAME * d2i_GENERAL_NAME(GENERAL_NAME **a,uchar **in,long len);
int i2d_GENERAL_NAME(GENERAL_NAME *a,uchar **out);
OTHERNAME * d2i_OTHERNAME(OTHERNAME **a,uchar **in,long len);
int i2d_OTHERNAME(OTHERNAME *a,uchar **out);
OTHERNAME * OTHERNAME_new(void);
void OTHERNAME_free(OTHERNAME *a);
EDIPARTYNAME * d2i_EDIPARTYNAME(EDIPARTYNAME **a,uchar **in,long len);
int i2d_EDIPARTYNAME(EDIPARTYNAME *a,uchar **out);
EDIPARTYNAME * EDIPARTYNAME_new(void);
void EDIPARTYNAME_free(EDIPARTYNAME *a);
GENERAL_NAME * GENERAL_NAME_new(void);
void GENERAL_NAME_free(GENERAL_NAME *a);
GENERAL_NAMES * d2i_GENERAL_NAMES(GENERAL_NAMES **a,uchar **in,long len);
int i2d_GENERAL_NAMES(GENERAL_NAMES *a,uchar **out);
GENERAL_NAMES * GENERAL_NAMES_new(void);
void GENERAL_NAMES_free(GENERAL_NAMES *a);
GENERAL_NAME * GENERAL_NAME_dup(GENERAL_NAME *a);
int OTHERNAME_cmp(OTHERNAME *a,OTHERNAME *b);
int GENERAL_NAME_cmp(GENERAL_NAME *a,GENERAL_NAME *b);
void GENERAL_NAME_set0_value(GENERAL_NAME *a,int type,void *value);
void * GENERAL_NAME_get0_value(GENERAL_NAME *a,int *ptype);
int GENERAL_NAME_set0_othername(GENERAL_NAME *gen,ASN1_OBJECT *oid,ASN1_TYPE *value);
int GENERAL_NAME_get0_otherName(GENERAL_NAME *gen,ASN1_OBJECT **poid,ASN1_TYPE **pvalue);
int copy_email(X509V3_CTX *ctx,GENERAL_NAMES *gens,int move_p);
stack_st_CONF_VALUE *i2v_GENERAL_NAME(X509V3_EXT_METHOD *method,GENERAL_NAME *gen,stack_st_CONF_VALUE *ret);
stack_st_CONF_VALUE *i2v_GENERAL_NAMES(X509V3_EXT_METHOD *method,GENERAL_NAMES *gens,stack_st_CONF_VALUE *ret);
int GENERAL_NAME_print(BIO *out,GENERAL_NAME *gen);
GENERAL_NAME *a2i_GENERAL_NAME(GENERAL_NAME *out,X509V3_EXT_METHOD *method,X509V3_CTX *ctx,int gen_type,char *value,int is_nc);
GENERAL_NAME *v2i_GENERAL_NAME_ex(GENERAL_NAME *out,X509V3_EXT_METHOD *method,X509V3_CTX *ctx,CONF_VALUE *cnf,int is_nc);
GENERAL_NAME * v2i_GENERAL_NAME(X509V3_EXT_METHOD *method,X509V3_CTX *ctx,CONF_VALUE *cnf);
GENERAL_NAMES * v2i_issuer_alt(X509V3_EXT_METHOD *method,X509V3_CTX *ctx,stack_st_CONF_VALUE *nval);
GENERAL_NAMES * v2i_subject_alt(X509V3_EXT_METHOD *method,X509V3_CTX *ctx,stack_st_CONF_VALUE *nval);
GENERAL_NAMES *v2i_GENERAL_NAMES(X509V3_EXT_METHOD *method,X509V3_CTX *ctx,stack_st_CONF_VALUE *nval);
char * i2s_ASN1_OCTET_STRING(X509V3_EXT_METHOD *method,ASN1_OCTET_STRING *oct);
ASN1_OCTET_STRING * s2i_ASN1_OCTET_STRING(X509V3_EXT_METHOD *method,X509V3_CTX *ctx,char *str);
ASN1_OCTET_STRING * s2i_skey_id(X509V3_EXT_METHOD *method,X509V3_CTX *ctx,char *str);
AUTHORITY_KEYID *v2i_AUTHORITY_KEYID(X509V3_EXT_METHOD *method,X509V3_CTX *ctx,stack_st_CONF_VALUE *values);
stack_st_CONF_VALUE *i2v_AUTHORITY_KEYID(X509V3_EXT_METHOD *method,AUTHORITY_KEYID *akeyid,stack_st_CONF_VALUE *extlist);
int i2r_PKEY_USAGE_PERIOD(X509V3_EXT_METHOD *method,PKEY_USAGE_PERIOD *usage,BIO *out,int indent);
PKEY_USAGE_PERIOD * d2i_PKEY_USAGE_PERIOD(PKEY_USAGE_PERIOD **a,uchar **in,long len);
int i2d_PKEY_USAGE_PERIOD(PKEY_USAGE_PERIOD *a,uchar **out);
PKEY_USAGE_PERIOD * PKEY_USAGE_PERIOD_new(void);
void PKEY_USAGE_PERIOD_free(PKEY_USAGE_PERIOD *a);
void * s2i_asn1_int(X509V3_EXT_METHOD *meth,X509V3_CTX *ctx,char *value);
char * i2s_ASN1_ENUMERATED_TABLE(X509V3_EXT_METHOD *method,ASN1_ENUMERATED *e);
int sxnet_i2r(X509V3_EXT_METHOD *method,SXNET *sx,BIO *out,int indent);
SXNETID * d2i_SXNETID(SXNETID **a,uchar **in,long len);
int i2d_SXNETID(SXNETID *a,uchar **out);
SXNETID * SXNETID_new(void);
void SXNETID_free(SXNETID *a);
SXNET * d2i_SXNET(SXNET **a,uchar **in,long len);
int i2d_SXNET(SXNET *a,uchar **out);
SXNET * SXNET_new(void);
void SXNET_free(SXNET *a);
ASN1_OCTET_STRING * SXNET_get_id_INTEGER(SXNET *sx,ASN1_INTEGER *zone);
int SXNET_add_id_INTEGER(SXNET **psx,ASN1_INTEGER *zone,char *user,int userlen);
int SXNET_add_id_asc(SXNET **psx,char *zone,char *user,int userlen);
SXNET * sxnet_v2i(X509V3_EXT_METHOD *method,X509V3_CTX *ctx,stack_st_CONF_VALUE *nval);
int SXNET_add_id_ulong(SXNET **psx,ulong lzone,char *user,int userlen);
ASN1_OCTET_STRING * SXNET_get_id_asc(SXNET *sx,char *zone);
ASN1_OCTET_STRING * SXNET_get_id_ulong(SXNET *sx,ulong lzone);
void print_qualifiers(BIO *out,stack_st_POLICYQUALINFO *quals,int indent);
int i2r_certpol(X509V3_EXT_METHOD *method,stack_st_POLICYINFO *pol,BIO *out,int indent);
void POLICYINFO_free(POLICYINFO *a);
CERTIFICATEPOLICIES * d2i_CERTIFICATEPOLICIES(CERTIFICATEPOLICIES **a,uchar **in,long len);
int i2d_CERTIFICATEPOLICIES(CERTIFICATEPOLICIES *a,uchar **out);
CERTIFICATEPOLICIES * CERTIFICATEPOLICIES_new(void);
void CERTIFICATEPOLICIES_free(CERTIFICATEPOLICIES *a);
POLICYINFO * d2i_POLICYINFO(POLICYINFO **a,uchar **in,long len);
int i2d_POLICYINFO(POLICYINFO *a,uchar **out);
POLICYINFO * POLICYINFO_new(void);
POLICYQUALINFO * d2i_POLICYQUALINFO(POLICYQUALINFO **a,uchar **in,long len);
int i2d_POLICYQUALINFO(POLICYQUALINFO *a,uchar **out);
POLICYQUALINFO * POLICYQUALINFO_new(void);
void POLICYQUALINFO_free(POLICYQUALINFO *a);
USERNOTICE * d2i_USERNOTICE(USERNOTICE **a,uchar **in,long len);
int i2d_USERNOTICE(USERNOTICE *a,uchar **out);
USERNOTICE * USERNOTICE_new(void);
void USERNOTICE_free(USERNOTICE *a);
NOTICEREF * d2i_NOTICEREF(NOTICEREF **a,uchar **in,long len);
int i2d_NOTICEREF(NOTICEREF *a,uchar **out);
NOTICEREF * NOTICEREF_new(void);
stack_st_POLICYINFO * r2i_certpol(X509V3_EXT_METHOD *method,X509V3_CTX *ctx,char *value);
void NOTICEREF_free(NOTICEREF *a);
void X509_POLICY_NODE_print(BIO *out,X509_POLICY_NODE *node,int indent);
int print_reasons(BIO *out,char *rname,ASN1_BIT_STRING *rflags,int indent);
int print_gens(BIO *out,stack_st_GENERAL_NAME *gens,int indent);
int dpn_cb(int operation,ASN1_VALUE **pval,ASN1_ITEM *it,void *exarg);
int set_reasons(ASN1_BIT_STRING **preas,char *value);
void DIST_POINT_free(DIST_POINT *a);
int print_distpoint(BIO *out,DIST_POINT_NAME *dpn,int indent,DIST_POINT_NAME *dpn_1);
int i2r_crldp(X509V3_EXT_METHOD *method,void *pcrldp,BIO *out,int indent);
int i2r_idp(X509V3_EXT_METHOD *method,void *pidp,BIO *out,int indent);
stack_st_GENERAL_NAME * gnames_from_sectname(X509V3_CTX *ctx,char *sect);
DIST_POINT_NAME * d2i_DIST_POINT_NAME(DIST_POINT_NAME **a,uchar **in,long len);
int i2d_DIST_POINT_NAME(DIST_POINT_NAME *a,uchar **out);
DIST_POINT_NAME * DIST_POINT_NAME_new(void);
int set_dist_point_name(DIST_POINT_NAME **pdp,X509V3_CTX *ctx,CONF_VALUE *cnf,CONF_VALUE *cnf_1);
void DIST_POINT_NAME_free(DIST_POINT_NAME *a);
DIST_POINT * d2i_DIST_POINT(DIST_POINT **a,uchar **in,long len);
int i2d_DIST_POINT(DIST_POINT *a,uchar **out);
DIST_POINT * DIST_POINT_new(void);
void * v2i_crld(X509V3_EXT_METHOD *method,X509V3_CTX *ctx,stack_st_CONF_VALUE *nval);
CRL_DIST_POINTS * d2i_CRL_DIST_POINTS(CRL_DIST_POINTS **a,uchar **in,long len);
int i2d_CRL_DIST_POINTS(CRL_DIST_POINTS *a,uchar **out);
CRL_DIST_POINTS * CRL_DIST_POINTS_new(void);
void CRL_DIST_POINTS_free(CRL_DIST_POINTS *a);
ISSUING_DIST_POINT * d2i_ISSUING_DIST_POINT(ISSUING_DIST_POINT **a,uchar **in,long len);
int i2d_ISSUING_DIST_POINT(ISSUING_DIST_POINT *a,uchar **out);
ISSUING_DIST_POINT * ISSUING_DIST_POINT_new(void);
void ISSUING_DIST_POINT_free(ISSUING_DIST_POINT *a);
void * v2i_idp(X509V3_EXT_METHOD *method,X509V3_CTX *ctx,stack_st_CONF_VALUE *nval);
int DIST_POINT_set_dpname(DIST_POINT_NAME *dpn,X509_NAME *iname);
int xp_cmp(X509_PURPOSE **a,X509_PURPOSE **b);
int nid_cmp_BSEARCH_CMP_FN(void *a_,void *b_);
int check_ca(X509 *x);
int check_ssl_ca(X509 *x);
int check_purpose_ssl_client(X509_PURPOSE *xp,X509 *x,int ca);
int check_purpose_ssl_server(X509_PURPOSE *xp,X509 *x,int ca);
int check_purpose_ns_ssl_server(X509_PURPOSE *xp,X509 *x,int ca);
int ocsp_helper(X509_PURPOSE *xp,X509 *x,int ca);
int no_check(X509_PURPOSE *xp,X509 *x,int ca);
void xptable_free(X509_PURPOSE *p);
int purpose_smime(X509 *x,int ca);
int check_purpose_smime_sign(X509_PURPOSE *xp,X509 *x,int ca);
int check_purpose_smime_encrypt(X509_PURPOSE *xp,X509 *x,int ca);
int check_purpose_crl_sign(X509_PURPOSE *xp,X509 *x,int ca);
int check_purpose_timestamp_sign(X509_PURPOSE *xp,X509 *x,int ca);
int X509_PURPOSE_get_count(void);
X509_PURPOSE * X509_PURPOSE_get0(int idx);
int X509_PURPOSE_get_by_sname(char *sname);
int X509_PURPOSE_get_by_id(int purpose);
int X509_PURPOSE_set(int *p,int purpose);
int X509_PURPOSE_add(int id,int trust,int flags,_func_int_X509_PURPOSE_ptr_X509_ptr_int *ck,char *name,char *sname,void *arg);
void X509_PURPOSE_cleanup(void);
int X509_PURPOSE_get_id(X509_PURPOSE *xp);
char * X509_PURPOSE_get0_name(X509_PURPOSE *xp);
char * X509_PURPOSE_get0_sname(X509_PURPOSE *xp);
int X509_PURPOSE_get_trust(X509_PURPOSE *xp);
int X509_supported_extension(X509_EXTENSION *ex);
int X509_check_akid(X509 *issuer,AUTHORITY_KEYID *akid);
void x509v3_cache_extensions(X509 *x);
int X509_check_purpose(X509 *x,int id,int ca);
int X509_check_ca(X509 *x);
int X509_check_issued(X509 *issuer,X509 *subject);
stack_st_CONF_VALUE *i2v_AUTHORITY_INFO_ACCESS(X509V3_EXT_METHOD *method,AUTHORITY_INFO_ACCESS *ainfo,stack_st_CONF_VALUE *ret);
void ACCESS_DESCRIPTION_free(ACCESS_DESCRIPTION *a);
ACCESS_DESCRIPTION * d2i_ACCESS_DESCRIPTION(ACCESS_DESCRIPTION **a,uchar **in,long len);
int i2d_ACCESS_DESCRIPTION(ACCESS_DESCRIPTION *a,uchar **out);
ACCESS_DESCRIPTION * ACCESS_DESCRIPTION_new(void);
AUTHORITY_INFO_ACCESS *v2i_AUTHORITY_INFO_ACCESS(X509V3_EXT_METHOD *method,X509V3_CTX *ctx,stack_st_CONF_VALUE *nval);
AUTHORITY_INFO_ACCESS * d2i_AUTHORITY_INFO_ACCESS(AUTHORITY_INFO_ACCESS **a,uchar **in,long len);
int i2d_AUTHORITY_INFO_ACCESS(AUTHORITY_INFO_ACCESS *a,uchar **out);
AUTHORITY_INFO_ACCESS * AUTHORITY_INFO_ACCESS_new(void);
void AUTHORITY_INFO_ACCESS_free(AUTHORITY_INFO_ACCESS *a);
int i2a_ACCESS_DESCRIPTION(BIO *bp,ACCESS_DESCRIPTION *a);
int i2r_ocsp_nocheck(X509V3_EXT_METHOD *method,void *nocheck,BIO *out,int indent);
int i2d_ocsp_nonce(void *a,uchar **pp);
void * ocsp_nonce_new(void);
void ocsp_nonce_free(void *a);
void * s2i_ocsp_nocheck(X509V3_EXT_METHOD *method,X509V3_CTX *ctx,char *str);
int i2r_ocsp_crlid(X509V3_EXT_METHOD *method,void *in,BIO *bp,int ind);
int i2r_ocsp_acutoff(X509V3_EXT_METHOD *method,void *cutoff,BIO *bp,int ind);
int i2r_object(X509V3_EXT_METHOD *method,void *oid,BIO *bp,int ind);
int i2r_ocsp_nonce(X509V3_EXT_METHOD *method,void *nonce,BIO *out,int indent);
void * d2i_ocsp_nonce(void *a,uchar **pp,long length);
int i2r_ocsp_serviceloc(X509V3_EXT_METHOD *method,void *in,BIO *bp,int ind);
AUTHORITY_KEYID * d2i_AUTHORITY_KEYID(AUTHORITY_KEYID **a,uchar **in,long len);
int i2d_AUTHORITY_KEYID(AUTHORITY_KEYID *a,uchar **out);
AUTHORITY_KEYID * AUTHORITY_KEYID_new(void);
void AUTHORITY_KEYID_free(AUTHORITY_KEYID *a);
stack_st_CONF_VALUE *i2v_POLICY_MAPPINGS(X509V3_EXT_METHOD *method,void *a,stack_st_CONF_VALUE *ext_list);
void POLICY_MAPPING_free(POLICY_MAPPING *a);
POLICY_MAPPING * POLICY_MAPPING_new(void);
void * v2i_POLICY_MAPPINGS(X509V3_EXT_METHOD *method,X509V3_CTX *ctx,stack_st_CONF_VALUE *nval);
stack_st_CONF_VALUE *i2v_POLICY_CONSTRAINTS(X509V3_EXT_METHOD *method,void *a,stack_st_CONF_VALUE *extlist);
POLICY_CONSTRAINTS * POLICY_CONSTRAINTS_new(void);
void POLICY_CONSTRAINTS_free(POLICY_CONSTRAINTS *a);
void * v2i_POLICY_CONSTRAINTS(X509V3_EXT_METHOD *method,X509V3_CTX *ctx,stack_st_CONF_VALUE *values);
int do_i2r_name_constraints(X509V3_EXT_METHOD *method,stack_st_GENERAL_SUBTREE *trees,BIO *bp,int ind,char *name);
int i2r_NAME_CONSTRAINTS(X509V3_EXT_METHOD *method,void *a,BIO *bp,int ind);
int nc_match_single(GENERAL_NAME *gen,GENERAL_NAME *base);
int nc_match(GENERAL_NAME *gen,NAME_CONSTRAINTS *nc);
GENERAL_SUBTREE * GENERAL_SUBTREE_new(void);
void GENERAL_SUBTREE_free(GENERAL_SUBTREE *a);
NAME_CONSTRAINTS * NAME_CONSTRAINTS_new(void);
void NAME_CONSTRAINTS_free(NAME_CONSTRAINTS *a);
void * v2i_NAME_CONSTRAINTS(X509V3_EXT_METHOD *method,X509V3_CTX *ctx,stack_st_CONF_VALUE *nval);
int NAME_CONSTRAINTS_check(X509 *x,NAME_CONSTRAINTS *nc);
PROXY_POLICY * d2i_PROXY_POLICY(PROXY_POLICY **a,uchar **in,long len);
int i2d_PROXY_POLICY(PROXY_POLICY *a,uchar **out);
PROXY_POLICY * PROXY_POLICY_new(void);
void PROXY_POLICY_free(PROXY_POLICY *a);
PROXY_CERT_INFO_EXTENSION *d2i_PROXY_CERT_INFO_EXTENSION(PROXY_CERT_INFO_EXTENSION **a,uchar **in,long len);
int i2d_PROXY_CERT_INFO_EXTENSION(PROXY_CERT_INFO_EXTENSION *a,uchar **out);
PROXY_CERT_INFO_EXTENSION * PROXY_CERT_INFO_EXTENSION_new(void);
void PROXY_CERT_INFO_EXTENSION_free(PROXY_CERT_INFO_EXTENSION *a);
int process_pci_value(CONF_VALUE *val,ASN1_OBJECT **language,ASN1_INTEGER **pathlen,ASN1_OCTET_STRING **policy);
PROXY_CERT_INFO_EXTENSION * r2i_pci(X509V3_EXT_METHOD *method,X509V3_CTX *ctx,char *value);
int i2r_pci(X509V3_EXT_METHOD *method,PROXY_CERT_INFO_EXTENSION *pci,BIO *out,int indent);
int policy_data_cmp(X509_POLICY_DATA **a,X509_POLICY_DATA **b);
void policy_cache_free(X509_POLICY_CACHE *cache);
X509_POLICY_CACHE * policy_cache_set(X509 *x);
X509_POLICY_DATA * policy_cache_find_data(X509_POLICY_CACHE *cache,ASN1_OBJECT *id);
void policy_data_free(X509_POLICY_DATA *data);
X509_POLICY_DATA * policy_data_new(POLICYINFO *policy,ASN1_OBJECT *cid,int crit);
int policy_cache_set_mapping(X509 *x,POLICY_MAPPINGS *maps);
void exnode_free(X509_POLICY_NODE *node);
int tree_add_unmatched(X509_POLICY_LEVEL *curr,X509_POLICY_CACHE *cache,ASN1_OBJECT *id,X509_POLICY_NODE *node,X509_POLICY_TREE *tree);
int tree_add_auth_node(stack_st_X509_POLICY_NODE **pnodes,X509_POLICY_NODE *pcy);
void X509_policy_tree_free(X509_POLICY_TREE *tree);
int X509_policy_check(X509_POLICY_TREE **ptree,int *pexplicit_policy,stack_st_X509 *certs,stack_st_ASN1_OBJECT *policy_oids,uint flags);
int X509_policy_tree_level_count(X509_POLICY_TREE *tree);
X509_POLICY_LEVEL * X509_policy_tree_get0_level(X509_POLICY_TREE *tree,int i);
stack_st_X509_POLICY_NODE * X509_policy_tree_get0_policies(X509_POLICY_TREE *tree);
stack_st_X509_POLICY_NODE * X509_policy_tree_get0_user_policies(X509_POLICY_TREE *tree);
int X509_policy_level_node_count(X509_POLICY_LEVEL *level);
X509_POLICY_NODE * X509_policy_level_get0_node(X509_POLICY_LEVEL *level,int i);
ASN1_OBJECT * X509_policy_node_get0_policy(X509_POLICY_NODE *node);
stack_st_POLICYQUALINFO * X509_policy_node_get0_qualifiers(X509_POLICY_NODE *node);
X509_POLICY_NODE * X509_policy_node_get0_parent(X509_POLICY_NODE *node);
int i2r_SCT_LIST(X509V3_EXT_METHOD *method,stack_st_SCT *sct_list,BIO *out,int indent);
void SCT_free(SCT *sct);
void SCT_LIST_free(stack_st_SCT *a);
stack_st_SCT * d2i_SCT_LIST(stack_st_SCT **a,uchar **pp,long length);
CONF_MODULE * module_add(DSO *dso,char *name,conf_init_func *ifunc,conf_finish_func *ffunc);
int CONF_modules_load(CONF *cnf,char *appname,ulong flags);
void CONF_modules_finish(void);
void CONF_modules_unload(int all);
int CONF_module_add(char *name,conf_init_func *ifunc,conf_finish_func *ffunc);
void CONF_modules_free(void);
char * CONF_imodule_get_name(CONF_IMODULE *md);
char * CONF_imodule_get_value(CONF_IMODULE *md);
void * CONF_imodule_get_usr_data(CONF_IMODULE *md);
void CONF_imodule_set_usr_data(CONF_IMODULE *md,void *usr_data);
CONF_MODULE * CONF_imodule_get_module(CONF_IMODULE *md);
ulong CONF_imodule_get_flags(CONF_IMODULE *md);
void CONF_imodule_set_flags(CONF_IMODULE *md,ulong flags);
void * CONF_module_get_usr_data(CONF_MODULE *pmod);
void CONF_module_set_usr_data(CONF_MODULE *pmod,void *usr_data);
char * CONF_get1_default_config_file(void);
int CONF_modules_load_file(char *filename,char *appname,ulong flags);
int CONF_parse_list(char *list_,int sep,int nospc,_func_int_char_ptr_int_void_ptr *list_cb,void *arg);
PKCS12_SAFEBAG * PKCS12_item_pack_safebag(void *obj,ASN1_ITEM *it,int nid1,int nid2);
PKCS12_SAFEBAG * PKCS12_MAKE_KEYBAG(PKCS8_PRIV_KEY_INFO *p8);
PKCS12_SAFEBAG *PKCS12_MAKE_SHKEYBAG(int pbe_nid,char *pass,int passlen,uchar *salt,int saltlen,int iter,PKCS8_PRIV_KEY_INFO *p8);
PKCS7 * PKCS12_pack_p7data(stack_st_PKCS12_SAFEBAG *sk);
stack_st_PKCS12_SAFEBAG * PKCS12_unpack_p7data(PKCS7 *p7);
PKCS7 * PKCS12_pack_p7encdata(int pbe_nid,char *pass,int passlen,uchar *salt,int saltlen,int iter,stack_st_PKCS12_SAFEBAG *bags);
stack_st_PKCS12_SAFEBAG * PKCS12_unpack_p7encdata(PKCS7 *p7,char *pass,int passlen);
PKCS8_PRIV_KEY_INFO * PKCS12_decrypt_skey(PKCS12_SAFEBAG *bag,char *pass,int passlen);
int PKCS12_pack_authsafes(PKCS12 *p12,stack_st_PKCS7 *safes);
stack_st_PKCS7 * PKCS12_unpack_authsafes(PKCS12 *p12);
PKCS12 * d2i_PKCS12(PKCS12 **a,uchar **in,long len);
int i2d_PKCS12(PKCS12 *a,uchar **out);
PKCS12 * PKCS12_new(void);
void PKCS12_free(PKCS12 *a);
PKCS12_MAC_DATA * d2i_PKCS12_MAC_DATA(PKCS12_MAC_DATA **a,uchar **in,long len);
int i2d_PKCS12_MAC_DATA(PKCS12_MAC_DATA *a,uchar **out);
PKCS12_MAC_DATA * PKCS12_MAC_DATA_new(void);
void PKCS12_MAC_DATA_free(PKCS12_MAC_DATA *a);
PKCS12_BAGS * d2i_PKCS12_BAGS(PKCS12_BAGS **a,uchar **in,long len);
int i2d_PKCS12_BAGS(PKCS12_BAGS *a,uchar **out);
PKCS12_BAGS * PKCS12_BAGS_new(void);
void PKCS12_BAGS_free(PKCS12_BAGS *a);
PKCS12_SAFEBAG * d2i_PKCS12_SAFEBAG(PKCS12_SAFEBAG **a,uchar **in,long len);
int i2d_PKCS12_SAFEBAG(PKCS12_SAFEBAG *a,uchar **out);
PKCS12_SAFEBAG * PKCS12_SAFEBAG_new(void);
void PKCS12_SAFEBAG_free(PKCS12_SAFEBAG *a);
uchar * PKCS12_pbe_crypt(X509_ALGOR *algor,char *pass,int passlen,uchar *in,int inlen,uchar **data,int *datalen,int en_de);
void * PKCS12_item_decrypt_d2i(X509_ALGOR *algor,ASN1_ITEM *it,char *pass,int passlen,ASN1_OCTET_STRING *oct,int zbuf);
ASN1_OCTET_STRING *PKCS12_item_i2d_encrypt(X509_ALGOR *algor,ASN1_ITEM *it,char *pass,int passlen,void *obj,int zbuf);
X509_SIG *PKCS8_encrypt(int pbe_nid,EVP_CIPHER *cipher,char *pass,int passlen,uchar *salt,int saltlen,int iter,PKCS8_PRIV_KEY_INFO *p8inf);
OCSP_SIGNATURE * d2i_OCSP_SIGNATURE(OCSP_SIGNATURE **a,uchar **in,long len);
int i2d_OCSP_SIGNATURE(OCSP_SIGNATURE *a,uchar **out);
OCSP_SIGNATURE * OCSP_SIGNATURE_new(void);
void OCSP_SIGNATURE_free(OCSP_SIGNATURE *a);
OCSP_CERTID * d2i_OCSP_CERTID(OCSP_CERTID **a,uchar **in,long len);
int i2d_OCSP_CERTID(OCSP_CERTID *a,uchar **out);
OCSP_CERTID * OCSP_CERTID_new(void);
void OCSP_CERTID_free(OCSP_CERTID *a);
OCSP_ONEREQ * d2i_OCSP_ONEREQ(OCSP_ONEREQ **a,uchar **in,long len);
int i2d_OCSP_ONEREQ(OCSP_ONEREQ *a,uchar **out);
OCSP_ONEREQ * OCSP_ONEREQ_new(void);
void OCSP_ONEREQ_free(OCSP_ONEREQ *a);
OCSP_REQINFO * d2i_OCSP_REQINFO(OCSP_REQINFO **a,uchar **in,long len);
int i2d_OCSP_REQINFO(OCSP_REQINFO *a,uchar **out);
OCSP_REQINFO * OCSP_REQINFO_new(void);
void OCSP_REQINFO_free(OCSP_REQINFO *a);
OCSP_REQUEST * d2i_OCSP_REQUEST(OCSP_REQUEST **a,uchar **in,long len);
int i2d_OCSP_REQUEST(OCSP_REQUEST *a,uchar **out);
OCSP_REQUEST * OCSP_REQUEST_new(void);
void OCSP_REQUEST_free(OCSP_REQUEST *a);
OCSP_RESPBYTES * d2i_OCSP_RESPBYTES(OCSP_RESPBYTES **a,uchar **in,long len);
int i2d_OCSP_RESPBYTES(OCSP_RESPBYTES *a,uchar **out);
OCSP_RESPBYTES * OCSP_RESPBYTES_new(void);
void OCSP_RESPBYTES_free(OCSP_RESPBYTES *a);
OCSP_RESPONSE * d2i_OCSP_RESPONSE(OCSP_RESPONSE **a,uchar **in,long len);
int i2d_OCSP_RESPONSE(OCSP_RESPONSE *a,uchar **out);
OCSP_RESPONSE * OCSP_RESPONSE_new(void);
void OCSP_RESPONSE_free(OCSP_RESPONSE *a);
OCSP_RESPID * d2i_OCSP_RESPID(OCSP_RESPID **a,uchar **in,long len);
int i2d_OCSP_RESPID(OCSP_RESPID *a,uchar **out);
OCSP_RESPID * OCSP_RESPID_new(void);
void OCSP_RESPID_free(OCSP_RESPID *a);
OCSP_REVOKEDINFO * d2i_OCSP_REVOKEDINFO(OCSP_REVOKEDINFO **a,uchar **in,long len);
int i2d_OCSP_REVOKEDINFO(OCSP_REVOKEDINFO *a,uchar **out);
OCSP_REVOKEDINFO * OCSP_REVOKEDINFO_new(void);
void OCSP_REVOKEDINFO_free(OCSP_REVOKEDINFO *a);
OCSP_CERTSTATUS * d2i_OCSP_CERTSTATUS(OCSP_CERTSTATUS **a,uchar **in,long len);
int i2d_OCSP_CERTSTATUS(OCSP_CERTSTATUS *a,uchar **out);
OCSP_CERTSTATUS * OCSP_CERTSTATUS_new(void);
void OCSP_CERTSTATUS_free(OCSP_CERTSTATUS *a);
OCSP_SINGLERESP * d2i_OCSP_SINGLERESP(OCSP_SINGLERESP **a,uchar **in,long len);
int i2d_OCSP_SINGLERESP(OCSP_SINGLERESP *a,uchar **out);
OCSP_SINGLERESP * OCSP_SINGLERESP_new(void);
void OCSP_SINGLERESP_free(OCSP_SINGLERESP *a);
OCSP_RESPDATA * d2i_OCSP_RESPDATA(OCSP_RESPDATA **a,uchar **in,long len);
int i2d_OCSP_RESPDATA(OCSP_RESPDATA *a,uchar **out);
OCSP_RESPDATA * OCSP_RESPDATA_new(void);
void OCSP_RESPDATA_free(OCSP_RESPDATA *a);
OCSP_BASICRESP * d2i_OCSP_BASICRESP(OCSP_BASICRESP **a,uchar **in,long len);
int i2d_OCSP_BASICRESP(OCSP_BASICRESP *a,uchar **out);
OCSP_BASICRESP * OCSP_BASICRESP_new(void);
void OCSP_BASICRESP_free(OCSP_BASICRESP *a);
OCSP_CRLID * d2i_OCSP_CRLID(OCSP_CRLID **a,uchar **in,long len);
int i2d_OCSP_CRLID(OCSP_CRLID *a,uchar **out);
OCSP_CRLID * OCSP_CRLID_new(void);
void OCSP_CRLID_free(OCSP_CRLID *a);
OCSP_SERVICELOC * d2i_OCSP_SERVICELOC(OCSP_SERVICELOC **a,uchar **in,long len);
int i2d_OCSP_SERVICELOC(OCSP_SERVICELOC *a,uchar **out);
OCSP_SERVICELOC * OCSP_SERVICELOC_new(void);
void OCSP_SERVICELOC_free(OCSP_SERVICELOC *a);
void OCSP_REQ_CTX_free(OCSP_REQ_CTX *rctx);
OCSP_REQ_CTX * OCSP_REQ_CTX_new(BIO *io,int maxline);
BIO * OCSP_REQ_CTX_get0_mem_bio(OCSP_REQ_CTX *rctx);
void OCSP_set_max_response_length(OCSP_REQ_CTX *rctx,ulong len);
int OCSP_REQ_CTX_i2d(OCSP_REQ_CTX *rctx,ASN1_ITEM *it,ASN1_VALUE *val);
int OCSP_REQ_CTX_http(OCSP_REQ_CTX *rctx,char *op,char *path);
int OCSP_REQ_CTX_set1_req(OCSP_REQ_CTX *rctx,OCSP_REQUEST *req);
int OCSP_REQ_CTX_add1_header(OCSP_REQ_CTX *rctx,char *name,char *value);
OCSP_REQ_CTX * OCSP_sendreq_new(BIO *io,char *path,OCSP_REQUEST *req,int maxline);
int OCSP_REQ_CTX_nbio(OCSP_REQ_CTX *rctx);
int OCSP_REQ_CTX_nbio_d2i(OCSP_REQ_CTX *rctx,ASN1_VALUE **pval,ASN1_ITEM *it);
int OCSP_sendreq_nbio(OCSP_RESPONSE **presp,OCSP_REQ_CTX *rctx);
OCSP_RESPONSE * OCSP_sendreq_bio(BIO *b,char *path,OCSP_REQUEST *req);
int cmac_size(EVP_PKEY *pkey);
void cmac_key_free(EVP_PKEY *pkey);
int pkey_cmac_ctrl(EVP_PKEY_CTX *ctx,int type,int p1,void *p2);
int pkey_cmac_ctrl_str(EVP_PKEY_CTX *ctx,char *type,char *value);
int cmac_signctx(EVP_PKEY_CTX *ctx,uchar *sig,size_t *siglen,EVP_MD_CTX *mctx);
int cmac_signctx_init(EVP_PKEY_CTX *ctx,EVP_MD_CTX *mctx);
int int_update(EVP_MD_CTX *ctx,void *data,size_t count);
int pkey_cmac_init(EVP_PKEY_CTX *ctx);
int pkey_cmac_copy(EVP_PKEY_CTX *dst,EVP_PKEY_CTX *src);
void pkey_cmac_cleanup(EVP_PKEY_CTX *ctx);
int pkey_cmac_keygen(EVP_PKEY_CTX *ctx,EVP_PKEY *pkey);
int MD4_Init(MD4_CTX *c);
void md4_block_data_order(MD4_CTX *c,void *data_,size_t num);
int MD4_Update(MD4_CTX *c,void *data_,size_t len);
void MD4_Transform(MD4_CTX *c,uchar *data);
int MD4_Final(uchar *md,MD4_CTX *c);
void sha_block_data_order(SHA_CTX *c,void *p,size_t num);
int SHA_Update(SHA_CTX *c,void *data_,size_t len);
void SHA_Transform(SHA_CTX *c,uchar *data);
int SHA_Final(uchar *md,SHA_CTX *c);
int SHA_Init(SHA_CTX *c);
void SHA1_Transform(SHA_CTX *c,uchar *data);
int SHA1_Final(uchar *md,SHA_CTX *c);
int SHA1_Init(SHA_CTX *c);
uchar * SHA1(uchar *d,size_t n,uchar *md);
int SHA384_Init(SHA512_CTX *c);
int SHA512_Init(SHA512_CTX *c);
int SHA512_Final(uchar *md,SHA512_CTX *c);
int SHA384_Final(uchar *md,SHA512_CTX *c);
int SHA512_Update(SHA512_CTX *c,void *_data,size_t len);
int SHA384_Update(SHA512_CTX *c,void *data,size_t len);
void SHA512_Transform(SHA512_CTX *c,uchar *data);
uchar * SHA384(uchar *d,size_t n,uchar *md);
uchar * SHA512(uchar *d,size_t n,uchar *md);
void sha1_block_data_order(undefined1 (*param_1) [16],undefined1 (*param_2) [16],int param_3);
void sha1_block_data_order_neon(uint *param_1,undefined1 (*param_2) [16],int param_3);
void sha1_block_data_order_armv8(undefined1 (*param_1) [16],undefined1 (*param_2) [16],int param_3);
void sha512_block_data_order(undefined1 (*param_1) [16],uint *param_2,int param_3);
void mdc2_body(MDC2_CTX *c,uchar *in,size_t len);
int MDC2_Init(MDC2_CTX *c);
int MDC2_Update(MDC2_CTX *c,uchar *in,size_t len);
int MDC2_Final(uchar *md,MDC2_CTX *c);
int hmac_size(EVP_PKEY *pkey);
int hmac_pkey_ctrl(EVP_PKEY *pkey,int op,long arg1,void *arg2);
int old_hmac_encode(EVP_PKEY *pkey,uchar **pder);
int old_hmac_decode(EVP_PKEY *pkey,uchar **pder,int derlen);
void hmac_key_free(EVP_PKEY *pkey);
int pkey_hmac_ctrl(EVP_PKEY_CTX *ctx,int type,int p1,void *p2);
int hmac_signctx(EVP_PKEY_CTX *ctx,uchar *sig,size_t *siglen,EVP_MD_CTX *mctx);
int hmac_signctx_init(EVP_PKEY_CTX *ctx,EVP_MD_CTX *mctx);
int int_update(EVP_MD_CTX *ctx,void *data,size_t count);
int pkey_hmac_keygen(EVP_PKEY_CTX *ctx,EVP_PKEY *pkey);
void pkey_hmac_cleanup(EVP_PKEY_CTX *ctx);
int pkey_hmac_init(EVP_PKEY_CTX *ctx);
int pkey_hmac_ctrl_str(EVP_PKEY_CTX *ctx,char *type,char *value);
int pkey_hmac_copy(EVP_PKEY_CTX *dst,EVP_PKEY_CTX *src);
int RIPEMD160_Init(RIPEMD160_CTX *c);
void ripemd160_block_data_order(RIPEMD160_CTX *ctx,void *p,size_t num);
int RIPEMD160_Update(RIPEMD160_CTX *c,void *data_,size_t len);
void RIPEMD160_Transform(RIPEMD160_CTX *c,uchar *data);
int RIPEMD160_Final(uchar *md,RIPEMD160_CTX *c);
int WHIRLPOOL_Init(WHIRLPOOL_CTX *c);
void WHIRLPOOL_BitUpdate(WHIRLPOOL_CTX *c,void *_inp,size_t bits);
int WHIRLPOOL_Update(WHIRLPOOL_CTX *c,void *_inp,size_t bytes);
int WHIRLPOOL_Final(uchar *md,WHIRLPOOL_CTX *c);
uchar * WHIRLPOOL(void *inp,size_t bytes,uchar *md);
void whirlpool_block(WHIRLPOOL_CTX *ctx,void *inp,size_t n);
void DES_set_odd_parity(DES_cblock *key);
int DES_check_key_parity(const_DES_cblock *key);
int DES_is_weak_key(const_DES_cblock *key);
void DES_set_key_unchecked(const_DES_cblock *key,DES_key_schedule *schedule);
int DES_set_key_checked(const_DES_cblock *key,DES_key_schedule *schedule);
int DES_set_key(const_DES_cblock *key,DES_key_schedule *schedule);
int DES_key_sched(const_DES_cblock *key,DES_key_schedule *schedule);
char * DES_options(void);
void DES_ecb_encrypt(const_DES_cblock *input,DES_cblock *output,DES_key_schedule *ks,int enc);
void DES_ecb3_encrypt(const_DES_cblock *input,DES_cblock *output,DES_key_schedule *ks1,DES_key_schedule *ks2,DES_key_schedule *ks3,int enc);
void DES_cfb64_encrypt(uchar *in,uchar *out,long length,DES_key_schedule *schedule,DES_cblock *ivec,int *num,int enc);
void DES_ede3_cfb64_encrypt(uchar *in,uchar *out,long length,DES_key_schedule *ks1,DES_key_schedule *ks2,DES_key_schedule *ks3,DES_cblock *ivec,int *num,int enc);
void DES_ede3_cfb_encrypt(uchar *in,uchar *out,int numbits,long length,DES_key_schedule *ks1,DES_key_schedule *ks2,DES_key_schedule *ks3,DES_cblock *ivec,int enc);
void DES_cfb_encrypt(uchar *in,uchar *out,int numbits,long length,DES_key_schedule *schedule,DES_cblock *ivec,int enc);
void DES_ede3_ofb64_encrypt(uchar *in,uchar *out,long length,DES_key_schedule *k1,DES_key_schedule *k2,DES_key_schedule *k3,DES_cblock *ivec,int *num);
void DES_ofb64_encrypt(uchar *in,uchar *out,long length,DES_key_schedule *schedule,DES_cblock *ivec,int *num);
void DES_encrypt1(uint *data,DES_key_schedule *ks,int enc);
void DES_encrypt2(uint *data,DES_key_schedule *ks,int enc);
void DES_encrypt3(uint *data,DES_key_schedule *ks1,DES_key_schedule *ks2,DES_key_schedule *ks3);
void DES_decrypt3(uint *data,DES_key_schedule *ks1,DES_key_schedule *ks2,DES_key_schedule *ks3);
void DES_ncbc_encrypt(uchar *in,uchar *out,long length,DES_key_schedule *_schedule,DES_cblock *ivec,int enc);
void DES_ede3_cbc_encrypt(uchar *input,uchar *output,long length,DES_key_schedule *ks1,DES_key_schedule *ks2,DES_key_schedule *ks3,DES_cblock *ivec,int enc);
void DES_xcbc_encrypt(uchar *in,uchar *out,long length,DES_key_schedule *schedule,DES_cblock *ivec,const_DES_cblock *inw,const_DES_cblock *outw,int enc);
void RC2_ecb_encrypt(uchar *in,uchar *out,RC2_KEY *ks,int encrypt);
void RC2_set_key(RC2_KEY *key,int len,uchar *data,int bits);
void RC2_encrypt(ulong *d,RC2_KEY *key);
void RC2_decrypt(ulong *d,RC2_KEY *key);
void RC2_cbc_encrypt(uchar *in,uchar *out,long length,RC2_KEY *ks,uchar *iv,int encrypt);
void RC2_cfb64_encrypt(uchar *in,uchar *out,long length,RC2_KEY *schedule,uchar *ivec,int *num,int encrypt);
void RC2_ofb64_encrypt(uchar *in,uchar *out,long length,RC2_KEY *schedule,uchar *ivec,int *num);
char * RC4_options(void);
void private_RC4_set_key(RC4_KEY *key,int len,uchar *data);
void idea_encrypt(ulong *d,IDEA_KEY_SCHEDULE *key);
void idea_cbc_encrypt(uchar *in,uchar *out,long length,IDEA_KEY_SCHEDULE *ks,uchar *iv,int encrypt);
void idea_cfb64_encrypt(uchar *in,uchar *out,long length,IDEA_KEY_SCHEDULE *schedule,uchar *ivec,int *num,int encrypt);
void idea_ofb64_encrypt(uchar *in,uchar *out,long length,IDEA_KEY_SCHEDULE *schedule,uchar *ivec,int *num);
char * idea_options(void);
void idea_ecb_encrypt(uchar *in,uchar *out,IDEA_KEY_SCHEDULE *ks);
void idea_set_encrypt_key(uchar *key,IDEA_KEY_SCHEDULE *ks);
void idea_set_decrypt_key(IDEA_KEY_SCHEDULE *ek,IDEA_KEY_SCHEDULE *dk);
void BF_set_key(BF_KEY *key,int len,uchar *data);
char * BF_options(void);
void BF_ecb_encrypt(uchar *in,uchar *out,BF_KEY *key,int encrypt);
void BF_encrypt(uint *data,BF_KEY *key);
void BF_decrypt(uint *data,BF_KEY *key);
void BF_cbc_encrypt(uchar *in,uchar *out,long length,BF_KEY *schedule,uchar *ivec,int encrypt);
void BF_cfb64_encrypt(uchar *in,uchar *out,long length,BF_KEY *schedule,uchar *ivec,int *num,int encrypt);
void BF_ofb64_encrypt(uchar *in,uchar *out,long length,BF_KEY *schedule,uchar *ivec,int *num);
void CAST_set_key(CAST_KEY *key,int len,uchar *data);
void CAST_ecb_encrypt(uchar *in,uchar *out,CAST_KEY *ks,int enc);
void CAST_encrypt(uint *data,CAST_KEY *key);
void CAST_decrypt(uint *data,CAST_KEY *key);
void CAST_cbc_encrypt(uchar *in,uchar *out,long length,CAST_KEY *ks,uchar *iv,int enc);
void CAST_cfb64_encrypt(uchar *in,uchar *out,long length,CAST_KEY *schedule,uchar *ivec,int *num,int enc);
void CAST_ofb64_encrypt(uchar *in,uchar *out,long length,CAST_KEY *schedule,uchar *ivec,int *num);
int Camellia_set_key(uchar *userKey,int bits,CAMELLIA_KEY *key);
int private_Camellia_set_key(uchar *userKey,int bits,CAMELLIA_KEY *key);
void Camellia_encrypt(uchar *in,uchar *out,CAMELLIA_KEY *key);
void Camellia_decrypt(uchar *in,uchar *out,CAMELLIA_KEY *key);
void Camellia_cbc_encrypt(uchar *in,uchar *out,size_t len,CAMELLIA_KEY *key,uchar *ivec,int enc);
void SEED_set_key(uchar *rawkey,SEED_KEY_SCHEDULE *ks);
void SEED_encrypt(uchar *s,uchar *d,SEED_KEY_SCHEDULE *ks);
void SEED_decrypt(uchar *s,uchar *d,SEED_KEY_SCHEDULE *ks);
void SEED_ecb_encrypt(uchar *in,uchar *out,SEED_KEY_SCHEDULE *ks,int enc);
void SEED_cbc_encrypt(uchar *in,uchar *out,size_t len,SEED_KEY_SCHEDULE *ks,uchar *ivec,int enc);
void SEED_cfb128_encrypt(uchar *in,uchar *out,size_t len,SEED_KEY_SCHEDULE *ks,uchar *ivec,int *num,int enc);
void SEED_ofb128_encrypt(uchar *in,uchar *out,size_t len,SEED_KEY_SCHEDULE *ks,uchar *ivec,int *num);
int BN_div(BIGNUM *dv,BIGNUM *rm,BIGNUM *num,BIGNUM *divisor,BN_CTX *ctx);
int MOD_EXP_CTIME_COPY_FROM_PREBUF(BIGNUM *b,int top,uchar *buf,int idx,int window);
int BN_exp(BIGNUM *r,BIGNUM *a,BIGNUM *p,BN_CTX *ctx);
int BN_mod_exp_recp(BIGNUM *r,BIGNUM *a,BIGNUM *p,BIGNUM *m,BN_CTX *ctx);
int BN_mod_exp_mont_consttime(BIGNUM *rr,BIGNUM *a,BIGNUM *p,BIGNUM *m,BN_CTX *ctx,BN_MONT_CTX *in_mont);
int BN_mod_exp_mont(BIGNUM *rr,BIGNUM *a,BIGNUM *p,BIGNUM *m,BN_CTX *ctx,BN_MONT_CTX *in_mont);
int BN_mod_exp_mont_word(BIGNUM *rr,uint a,BIGNUM *p,BIGNUM *m,BN_CTX *ctx,BN_MONT_CTX *in_mont);
int BN_mod_exp(BIGNUM *r,BIGNUM *a,BIGNUM *p,BIGNUM *m,BN_CTX *ctx);
int BN_mod_exp_simple(BIGNUM *r,BIGNUM *a,BIGNUM *p,BIGNUM *m,BN_CTX *ctx);
int BN_nnmod(BIGNUM *r,BIGNUM *m,BIGNUM *d,BN_CTX *ctx);
int BN_mod_add(BIGNUM *r,BIGNUM *a,BIGNUM *b,BIGNUM *m,BN_CTX *ctx);
int BN_mod_add_quick(BIGNUM *r,BIGNUM *a,BIGNUM *b,BIGNUM *m);
int BN_mod_sub(BIGNUM *r,BIGNUM *a,BIGNUM *b,BIGNUM *m,BN_CTX *ctx);
int BN_mod_sub_quick(BIGNUM *r,BIGNUM *a,BIGNUM *b,BIGNUM *m);
int BN_mod_mul(BIGNUM *r,BIGNUM *a,BIGNUM *b,BIGNUM *m,BN_CTX *ctx);
int BN_mod_sqr(BIGNUM *r,BIGNUM *a,BIGNUM *m,BN_CTX *ctx);
int BN_mod_lshift1(BIGNUM *r,BIGNUM *a,BIGNUM *m,BN_CTX *ctx);
int BN_mod_lshift1_quick(BIGNUM *r,BIGNUM *a,BIGNUM *m);
int BN_mod_lshift_quick(BIGNUM *r,BIGNUM *a,int n,BIGNUM *m);
int BN_mod_lshift(BIGNUM *r,BIGNUM *a,int n,BIGNUM *m,BN_CTX *ctx);
int bn_rand_range(int pseudo,BIGNUM *r,BIGNUM *range);
int bnrand(int pseudorand,BIGNUM *rnd,int bits,int top,int bottom);
int BN_rand(BIGNUM *rnd,int bits,int top,int bottom);
int BN_pseudo_rand(BIGNUM *rnd,int bits,int top,int bottom);
int BN_bntest_rand(BIGNUM *rnd,int bits,int top,int bottom);
int BN_rand_range(BIGNUM *r,BIGNUM *range);
int BN_pseudo_rand_range(BIGNUM *r,BIGNUM *range);
void bn_sqr_normal(uint *r,uint *a,int n,uint *tmp);
void bn_sqr_recursive(uint *r,uint *a,int n2,uint *t);
int BN_sqr(BIGNUM *r,BIGNUM *a,BN_CTX *ctx);
void BN_RECP_CTX_init(BN_RECP_CTX *recp);
BN_RECP_CTX * BN_RECP_CTX_new(void);
void BN_RECP_CTX_free(BN_RECP_CTX *recp);
int BN_RECP_CTX_set(BN_RECP_CTX *recp,BIGNUM *d,BN_CTX *ctx);
int BN_reciprocal(BIGNUM *r,BIGNUM *m,int len,BN_CTX *ctx);
int BN_div_recp(BIGNUM *dv,BIGNUM *rem,BIGNUM *m,BN_RECP_CTX *recp,BN_CTX *ctx);
int BN_mod_mul_reciprocal(BIGNUM *r,BIGNUM *x,BIGNUM *y,BN_RECP_CTX *recp,BN_CTX *ctx);
int BN_from_montgomery_word(BIGNUM *ret,BIGNUM *r,BN_MONT_CTX *mont);
int BN_mod_mul_montgomery(BIGNUM *r,BIGNUM *a,BIGNUM *b,BN_MONT_CTX *mont,BN_CTX *ctx);
int BN_from_montgomery(BIGNUM *ret,BIGNUM *a,BN_MONT_CTX *mont,BN_CTX *ctx);
void BN_MONT_CTX_init(BN_MONT_CTX *ctx);
BN_MONT_CTX * BN_MONT_CTX_new(void);
void BN_MONT_CTX_free(BN_MONT_CTX *mont);
int BN_MONT_CTX_set(BN_MONT_CTX *mont,BIGNUM *mod,BN_CTX *ctx);
BN_MONT_CTX * BN_MONT_CTX_copy(BN_MONT_CTX *to,BN_MONT_CTX *from);
BN_MONT_CTX * BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont,int lock,BIGNUM *mod,BN_CTX *ctx);
int BN_mod_exp2_mont(BIGNUM *rr,BIGNUM *a1,BIGNUM *p1,BIGNUM *a2,BIGNUM *p2,BIGNUM *m,BN_CTX *ctx,BN_MONT_CTX *in_mont);
EC_GROUP * EC_GROUP_new(EC_METHOD *meth);
EC_METHOD * EC_GROUP_method_of(EC_GROUP *group);
int EC_METHOD_get_field_type(EC_METHOD *meth);
EC_POINT * EC_GROUP_get0_generator(EC_GROUP *group);
BN_MONT_CTX * EC_GROUP_get_mont_data(EC_GROUP *group);
int EC_GROUP_get_order(EC_GROUP *group,BIGNUM *order,BN_CTX *ctx);
int EC_GROUP_get_cofactor(EC_GROUP *group,BIGNUM *cofactor,BN_CTX *ctx);
void EC_GROUP_set_curve_name(EC_GROUP *group,int nid);
int EC_GROUP_get_curve_name(EC_GROUP *group);
void EC_GROUP_set_asn1_flag(EC_GROUP *group,int flag);
int EC_GROUP_get_asn1_flag(EC_GROUP *group);
void EC_GROUP_set_point_conversion_form(EC_GROUP *group,point_conversion_form_t form);
point_conversion_form_t EC_GROUP_get_point_conversion_form(EC_GROUP *group);
size_t EC_GROUP_set_seed(EC_GROUP *group,uchar *p,size_t len);
uchar * EC_GROUP_get0_seed(EC_GROUP *group);
size_t EC_GROUP_get_seed_len(EC_GROUP *group);
int EC_GROUP_set_curve_GFp(EC_GROUP *group,BIGNUM *p,BIGNUM *a,BIGNUM *b,BN_CTX *ctx);
int EC_GROUP_get_curve_GFp(EC_GROUP *group,BIGNUM *p,BIGNUM *a,BIGNUM *b,BN_CTX *ctx);
int EC_GROUP_set_curve_GF2m(EC_GROUP *group,BIGNUM *p,BIGNUM *a,BIGNUM *b,BN_CTX *ctx);
int EC_GROUP_get_curve_GF2m(EC_GROUP *group,BIGNUM *p,BIGNUM *a,BIGNUM *b,BN_CTX *ctx);
int EC_GROUP_get_degree(EC_GROUP *group);
int EC_GROUP_check_discriminant(EC_GROUP *group,BN_CTX *ctx);
int EC_EX_DATA_set_data(EC_EXTRA_DATA **ex_data,void *data,_func_void_ptr_void_ptr *dup_func,_func_void_void_ptr *free_func,_func_void_void_ptr *clear_free_func);
void * EC_EX_DATA_get_data(EC_EXTRA_DATA *ex_data,_func_void_ptr_void_ptr *dup_func,_func_void_void_ptr *free_func,_func_void_void_ptr *clear_free_func);
void EC_EX_DATA_free_data(EC_EXTRA_DATA **ex_data,_func_void_ptr_void_ptr *dup_func,_func_void_void_ptr *free_func,_func_void_void_ptr *clear_free_func);
void EC_EX_DATA_clear_free_data(EC_EXTRA_DATA **ex_data,_func_void_ptr_void_ptr *dup_func,_func_void_void_ptr *free_func,_func_void_void_ptr *clear_free_func);
void EC_EX_DATA_free_all_data(EC_EXTRA_DATA **ex_data);
void EC_EX_DATA_clear_free_all_data(EC_EXTRA_DATA **ex_data);
EC_POINT * EC_POINT_new(EC_GROUP *group);
void EC_POINT_free(EC_POINT *point);
void EC_GROUP_free(EC_GROUP *group);
void EC_POINT_clear_free(EC_POINT *point);
void EC_GROUP_clear_free(EC_GROUP *group);
int EC_POINT_copy(EC_POINT *dest,EC_POINT *src);
int EC_GROUP_copy(EC_GROUP *dest,EC_GROUP *src);
EC_GROUP * EC_GROUP_dup(EC_GROUP *a);
EC_POINT * EC_POINT_dup(EC_POINT *a,EC_GROUP *group);
EC_METHOD * EC_POINT_method_of(EC_POINT *point);
int EC_POINT_set_to_infinity(EC_GROUP *group,EC_POINT *point);
int EC_POINT_set_Jprojective_coordinates_GFp(EC_GROUP *group,EC_POINT *point,BIGNUM *x,BIGNUM *y,BIGNUM *z,BN_CTX *ctx);
int EC_POINT_get_Jprojective_coordinates_GFp(EC_GROUP *group,EC_POINT *point,BIGNUM *x,BIGNUM *y,BIGNUM *z,BN_CTX *ctx);
int EC_POINT_set_affine_coordinates_GFp(EC_GROUP *group,EC_POINT *point,BIGNUM *x,BIGNUM *y,BN_CTX *ctx);
int EC_POINT_set_affine_coordinates_GF2m(EC_GROUP *group,EC_POINT *point,BIGNUM *x,BIGNUM *y,BN_CTX *ctx);
int EC_POINT_get_affine_coordinates_GFp(EC_GROUP *group,EC_POINT *point,BIGNUM *x,BIGNUM *y,BN_CTX *ctx);
int EC_POINT_get_affine_coordinates_GF2m(EC_GROUP *group,EC_POINT *point,BIGNUM *x,BIGNUM *y,BN_CTX *ctx);
int EC_POINT_add(EC_GROUP *group,EC_POINT *r,EC_POINT *a,EC_POINT *b,BN_CTX *ctx);
int EC_POINT_dbl(EC_GROUP *group,EC_POINT *r,EC_POINT *a,BN_CTX *ctx);
int EC_POINT_invert(EC_GROUP *group,EC_POINT *a,BN_CTX *ctx);
int EC_POINT_is_at_infinity(EC_GROUP *group,EC_POINT *point);
int EC_POINT_is_on_curve(EC_GROUP *group,EC_POINT *point,BN_CTX *ctx);
int EC_POINT_cmp(EC_GROUP *group,EC_POINT *a,EC_POINT *b,BN_CTX *ctx);
int EC_GROUP_cmp(EC_GROUP *a,EC_GROUP *b,BN_CTX *ctx);
int EC_POINT_make_affine(EC_GROUP *group,EC_POINT *point,BN_CTX *ctx);
int EC_POINTs_make_affine(EC_GROUP *group,size_t num,EC_POINT **points,BN_CTX *ctx);
int EC_POINTs_mul(EC_GROUP *group,EC_POINT *r,BIGNUM *scalar,size_t num,EC_POINT **points,BIGNUM **scalars,BN_CTX *ctx);
int EC_POINT_mul(EC_GROUP *group,EC_POINT *r,BIGNUM *g_scalar,EC_POINT *point,BIGNUM *p_scalar,BN_CTX *ctx);
int EC_GROUP_precompute_mult(EC_GROUP *group,BN_CTX *ctx);
int EC_GROUP_have_precompute_mult(EC_GROUP *group);
int ec_precompute_mont_data(EC_GROUP *group);
int EC_GROUP_set_generator(EC_GROUP *group,EC_POINT *generator,BIGNUM *order,BIGNUM *cofactor);
EC_GROUP * EC_GROUP_new_curve_GFp(BIGNUM *p,BIGNUM *a,BIGNUM *b,BN_CTX *ctx);
EC_GROUP * EC_GROUP_new_curve_GF2m(BIGNUM *p,BIGNUM *a,BIGNUM *b,BN_CTX *ctx);
void * ec_pre_comp_dup(void *src_);
char * compute_wNAF(BIGNUM *scalar,int w,size_t *ret_len);
void ec_pre_comp_free(void *pre_);
void ec_pre_comp_clear_free(void *pre_);
int ec_wNAF_mul(EC_GROUP *group,EC_POINT *r,BIGNUM *scalar,size_t num,EC_POINT **points,BIGNUM **scalars,BN_CTX *ctx);
int ec_wNAF_precompute_mult(EC_GROUP *group,BN_CTX *ctx);
int ec_wNAF_have_precompute_mult(EC_GROUP *group);
EC_GROUP * EC_GROUP_new_by_curve_name(int nid);
size_t EC_get_builtin_curves(EC_builtin_curve *r,size_t nitems);
char * EC_curve_nid2nist(int nid);
int EC_curve_nist2nid(char *name);
int ec_GF2m_simple_is_at_infinity(EC_GROUP *group,EC_POINT *point);
int ec_GF2m_simple_points_make_affine(EC_GROUP *group,size_t num,EC_POINT **points,BN_CTX *ctx);
int ec_GF2m_simple_group_init(EC_GROUP *group);
int ec_GF2m_simple_point_init(EC_POINT *point);
void ec_GF2m_simple_group_finish(EC_GROUP *group);
void ec_GF2m_simple_point_finish(EC_POINT *point);
void ec_GF2m_simple_group_clear_finish(EC_GROUP *group);
void ec_GF2m_simple_point_clear_finish(EC_POINT *point);
int ec_GF2m_simple_group_copy(EC_GROUP *dest,EC_GROUP *src);
int ec_GF2m_simple_group_set_curve(EC_GROUP *group,BIGNUM *p,BIGNUM *a,BIGNUM *b,BN_CTX *ctx);
int ec_GF2m_simple_group_get_degree(EC_GROUP *group);
int ec_GF2m_simple_group_check_discriminant(EC_GROUP *group,BN_CTX *ctx);
int ec_GF2m_simple_point_set_to_infinity(EC_GROUP *group,EC_POINT *point);
int ec_GF2m_simple_field_mul(EC_GROUP *group,BIGNUM *r,BIGNUM *a,BIGNUM *b,BN_CTX *ctx);
int ec_GF2m_simple_field_sqr(EC_GROUP *group,BIGNUM *r,BIGNUM *a,BN_CTX *ctx);
int ec_GF2m_simple_field_div(EC_GROUP *group,BIGNUM *r,BIGNUM *a,BIGNUM *b,BN_CTX *ctx);
int ec_GF2m_simple_group_get_curve(EC_GROUP *group,BIGNUM *p,BIGNUM *a,BIGNUM *b,BN_CTX *ctx);
int ec_GF2m_simple_point_copy(EC_POINT *dest,EC_POINT *src);
int ec_GF2m_simple_point_set_affine_coordinates(EC_GROUP *group,EC_POINT *point,BIGNUM *x,BIGNUM *y,BN_CTX *ctx);
int ec_GF2m_simple_point_get_affine_coordinates(EC_GROUP *group,EC_POINT *point,BIGNUM *x,BIGNUM *y,BN_CTX *ctx);
int ec_GF2m_simple_cmp(EC_GROUP *group,EC_POINT *a,EC_POINT *b,BN_CTX *ctx);
int ec_GF2m_simple_make_affine(EC_GROUP *group,EC_POINT *point,BN_CTX *ctx);
int ec_GF2m_simple_is_on_curve(EC_GROUP *group,EC_POINT *point,BN_CTX *ctx);
int ec_GF2m_simple_add(EC_GROUP *group,EC_POINT *r,EC_POINT *a,EC_POINT *b,BN_CTX *ctx);
int ec_GF2m_simple_dbl(EC_GROUP *group,EC_POINT *r,EC_POINT *a,BN_CTX *ctx);
int ec_GF2m_simple_invert(EC_GROUP *group,EC_POINT *point,BN_CTX *ctx);
EC_METHOD * EC_GF2m_simple_method(void);
int ec_GF2m_montgomery_point_multiply(EC_GROUP *group,EC_POINT *r,BIGNUM *scalar,EC_POINT *point,BN_CTX *ctx);
int ec_GF2m_simple_mul(EC_GROUP *group,EC_POINT *r,BIGNUM *scalar,size_t num,EC_POINT **points,BIGNUM **scalars,BN_CTX *ctx);
int ec_GF2m_precompute_mult(EC_GROUP *group,BN_CTX *ctx);
int ec_GF2m_have_precompute_mult(EC_GROUP *group);
int old_ec_priv_encode(EVP_PKEY *pkey,uchar **pder);
int ec_missing_parameters(EVP_PKEY *pkey);
void int_ec_free(EVP_PKEY *pkey);
EC_KEY * eckey_type2param(int ptype,void *pval);
int ec_pkey_ctrl(EVP_PKEY *pkey,int op,long arg1,void *arg2);
int do_EC_KEY_print(BIO *bp,EC_KEY *x,int off,int ktype);
int eckey_param_print(BIO *bp,EVP_PKEY *pkey,int indent,ASN1_PCTX *ctx);
int eckey_priv_print(BIO *bp,EVP_PKEY *pkey,int indent,ASN1_PCTX *ctx);
int eckey_pub_print(BIO *bp,EVP_PKEY *pkey,int indent,ASN1_PCTX *ctx);
int ec_cmp_parameters(EVP_PKEY *a,EVP_PKEY *b);
int ec_copy_parameters(EVP_PKEY *to,EVP_PKEY *from);
int eckey_param_encode(EVP_PKEY *pkey,uchar **pder);
int ec_bits(EVP_PKEY *pkey);
int int_ec_size(EVP_PKEY *pkey);
int eckey_priv_decode(EVP_PKEY *pkey,PKCS8_PRIV_KEY_INFO *p8);
int eckey_pub_cmp(EVP_PKEY *a,EVP_PKEY *b);
int eckey_pub_decode(EVP_PKEY *pkey,X509_PUBKEY *pubkey);
int old_ec_priv_decode(EVP_PKEY *pkey,uchar **pder,int derlen);
int eckey_param_decode(EVP_PKEY *pkey,uchar **pder,int derlen);
int eckey_param2type(int *pptype,void **ppval,EC_KEY *ec_key);
int eckey_priv_encode(PKCS8_PRIV_KEY_INFO *p8,EVP_PKEY *pkey);
int eckey_pub_encode(X509_PUBKEY *pk,EVP_PKEY *pkey);
int pkey_ec_ctrl_str(EVP_PKEY_CTX *ctx,char *type,char *value);
void pkey_ec_cleanup(EVP_PKEY_CTX *ctx);
int pkey_ec_ctrl(EVP_PKEY_CTX *ctx,int type,int p1,void *p2);
int pkey_ec_init(EVP_PKEY_CTX *ctx);
int pkey_ec_derive(EVP_PKEY_CTX *ctx,uchar *key,size_t *keylen);
int pkey_ec_kdf_derive(EVP_PKEY_CTX *ctx,uchar *key,size_t *keylen);
int pkey_ec_verify(EVP_PKEY_CTX *ctx,uchar *sig,size_t siglen,uchar *tbs,size_t tbslen);
int pkey_ec_sign(EVP_PKEY_CTX *ctx,uchar *sig,size_t *siglen,uchar *tbs,size_t tbslen);
int pkey_ec_paramgen(EVP_PKEY_CTX *ctx,EVP_PKEY *pkey);
int pkey_ec_keygen(EVP_PKEY_CTX *ctx,EVP_PKEY *pkey);
int pkey_ec_copy(EVP_PKEY_CTX *dst,EVP_PKEY_CTX *src);
int EC_KEY_print(BIO *bp,EC_KEY *x,int off);
int EC_KEY_print_fp(FILE *fp,EC_KEY *x,int off);
int ECParameters_print(BIO *bp,EC_KEY *x);
int ECParameters_print_fp(FILE *fp,EC_KEY *x);
int ECPKParameters_print(BIO *bp,EC_GROUP *x,int off);
int ECPKParameters_print_fp(FILE *fp,EC_GROUP *x,int off);
int ec_GFp_simple_set_compressed_coordinates(EC_GROUP *group,EC_POINT *point,BIGNUM *x_,int y_bit,BN_CTX *ctx);
size_t ec_GFp_simple_point2oct(EC_GROUP *group,EC_POINT *point,point_conversion_form_t form,uchar *buf,size_t len,BN_CTX *ctx);
int ec_GFp_simple_oct2point(EC_GROUP *group,EC_POINT *point,uchar *buf,size_t len,BN_CTX *ctx);
int ec_GF2m_simple_set_compressed_coordinates(EC_GROUP *group,EC_POINT *point,BIGNUM *x_,int y_bit,BN_CTX *ctx);
size_t ec_GF2m_simple_point2oct(EC_GROUP *group,EC_POINT *point,point_conversion_form_t form,uchar *buf,size_t len,BN_CTX *ctx);
int ec_GF2m_simple_oct2point(EC_GROUP *group,EC_POINT *point,uchar *buf,size_t len,BN_CTX *ctx);
int RSA_sign_ASN1_OCTET_STRING(int type,uchar *m,uint m_len,uchar *sigret,uint *siglen,RSA *rsa);
int RSA_verify_ASN1_OCTET_STRING(int dtype,uchar *m,uint m_len,uchar *sigbuf,uint siglen,RSA *rsa);
X509_ALGOR * rsa_mgf1_decode(X509_ALGOR *alg);
EVP_MD * rsa_algor_to_md(X509_ALGOR *alg);
int old_rsa_priv_encode(EVP_PKEY *pkey,uchar **pder);
void int_rsa_free(EVP_PKEY *pkey);
int rsa_bits(EVP_PKEY *pkey);
int int_rsa_size(EVP_PKEY *pkey);
int do_rsa_print(BIO *bp,RSA *x,int off,int priv);
int rsa_priv_print(BIO *bp,EVP_PKEY *pkey,int indent,ASN1_PCTX *ctx);
int rsa_pub_print(BIO *bp,EVP_PKEY *pkey,int indent,ASN1_PCTX *ctx);
int rsa_pub_encode(X509_PUBKEY *pk,EVP_PKEY *pkey);
int rsa_md_to_algor(X509_ALGOR **palg,EVP_MD *md);
int rsa_md_to_mgf1(X509_ALGOR **palg,EVP_MD *mgf1md);
ASN1_STRING * rsa_ctx_to_pss(EVP_PKEY_CTX *pkctx);
int rsa_item_sign(EVP_MD_CTX *ctx,ASN1_ITEM *it,void *asn,X509_ALGOR *alg1,X509_ALGOR *alg2,ASN1_BIT_STRING *sig);
RSA_PSS_PARAMS * rsa_pss_decode(X509_ALGOR *alg,X509_ALGOR **pmaskHash);
int rsa_sig_print(BIO *bp,X509_ALGOR *sigalg,ASN1_STRING *sig,int indent,ASN1_PCTX *pctx);
EVP_MD * rsa_mgf1_to_md(X509_ALGOR *alg,X509_ALGOR *maskHash);
int rsa_pss_to_ctx(EVP_MD_CTX *ctx,EVP_PKEY_CTX *pkctx,X509_ALGOR *sigalg,EVP_PKEY *pkey);
int rsa_item_verify(EVP_MD_CTX *ctx,ASN1_ITEM *it,void *asn,X509_ALGOR *sigalg,ASN1_BIT_STRING *sig,EVP_PKEY *pkey);
int old_rsa_priv_decode(EVP_PKEY *pkey,uchar **pder,int derlen);
int rsa_priv_decode(EVP_PKEY *pkey,PKCS8_PRIV_KEY_INFO *p8);
int rsa_pkey_ctrl(EVP_PKEY *pkey,int op,long arg1,void *arg2);
int rsa_priv_encode(PKCS8_PRIV_KEY_INFO *p8,EVP_PKEY *pkey);
int rsa_pub_cmp(EVP_PKEY *a,EVP_PKEY *b);
int rsa_pub_decode(EVP_PKEY *pkey,X509_PUBKEY *pubkey);
void pkey_rsa_cleanup(EVP_PKEY_CTX *ctx);
int pkey_rsa_ctrl_str(EVP_PKEY_CTX *ctx,char *type,char *value);
int pkey_rsa_init(EVP_PKEY_CTX *ctx);
int pkey_rsa_keygen(EVP_PKEY_CTX *ctx,EVP_PKEY *pkey);
int check_padding_md(EVP_MD *md,int padding);
int pkey_rsa_ctrl(EVP_PKEY_CTX *ctx,int type,int p1,void *p2);
int setup_tbuf(RSA_PKEY_CTX *ctx,EVP_PKEY_CTX *pk);
int pkey_rsa_decrypt(EVP_PKEY_CTX *ctx,uchar *out,size_t *outlen,uchar *in,size_t inlen);
int pkey_rsa_encrypt(EVP_PKEY_CTX *ctx,uchar *out,size_t *outlen,uchar *in,size_t inlen);
int pkey_rsa_verifyrecover(EVP_PKEY_CTX *ctx,uchar *rout,size_t *routlen,uchar *sig,size_t siglen);
int pkey_rsa_verify(EVP_PKEY_CTX *ctx,uchar *sig,size_t siglen,uchar *tbs,size_t tbslen);
int pkey_rsa_sign(EVP_PKEY_CTX *ctx,uchar *sig,size_t *siglen,uchar *tbs,size_t tbslen);
int pkey_rsa_copy(EVP_PKEY_CTX *dst,EVP_PKEY_CTX *src);
int dsa_missing_parameters(EVP_PKEY *pkey);
int old_dsa_priv_encode(EVP_PKEY *pkey,uchar **pder);
int dsa_pkey_ctrl(EVP_PKEY *pkey,int op,long arg1,void *arg2);
void int_dsa_free(EVP_PKEY *pkey);
int dsa_sig_print(BIO *bp,X509_ALGOR *sigalg,ASN1_STRING *sig,int indent,ASN1_PCTX *pctx);
int dsa_bits(EVP_PKEY *pkey);
int do_dsa_print(BIO *bp,DSA *x,int off,int ptype);
int dsa_param_print(BIO *bp,EVP_PKEY *pkey,int indent,ASN1_PCTX *ctx);
int dsa_priv_print(BIO *bp,EVP_PKEY *pkey,int indent,ASN1_PCTX *ctx);
int dsa_pub_print(BIO *bp,EVP_PKEY *pkey,int indent,ASN1_PCTX *ctx);
int dsa_pub_cmp(EVP_PKEY *a,EVP_PKEY *b);
int dsa_copy_parameters(EVP_PKEY *to,EVP_PKEY *from);
int dsa_param_encode(EVP_PKEY *pkey,uchar **pder);
int int_dsa_size(EVP_PKEY *pkey);
int dsa_priv_encode(PKCS8_PRIV_KEY_INFO *p8,EVP_PKEY *pkey);
int dsa_priv_decode(EVP_PKEY *pkey,PKCS8_PRIV_KEY_INFO *p8);
int dsa_pub_encode(X509_PUBKEY *pk,EVP_PKEY *pkey);
int dsa_pub_decode(EVP_PKEY *pkey,X509_PUBKEY *pubkey);
int old_dsa_priv_decode(EVP_PKEY *pkey,uchar **pder,int derlen);
int dsa_cmp_parameters(EVP_PKEY *a,EVP_PKEY *b);
int dsa_param_decode(EVP_PKEY *pkey,uchar **pder,int derlen);
int pkey_dsa_ctrl_str(EVP_PKEY_CTX *ctx,char *type,char *value);
int pkey_dsa_ctrl(EVP_PKEY_CTX *ctx,int type,int p1,void *p2);
int pkey_dsa_verify(EVP_PKEY_CTX *ctx,uchar *sig,size_t siglen,uchar *tbs,size_t tbslen);
int pkey_dsa_sign(EVP_PKEY_CTX *ctx,uchar *sig,size_t *siglen,uchar *tbs,size_t tbslen);
int pkey_dsa_paramgen(EVP_PKEY_CTX *ctx,EVP_PKEY *pkey);
void pkey_dsa_cleanup(EVP_PKEY_CTX *ctx);
int pkey_dsa_init(EVP_PKEY_CTX *ctx);
int pkey_dsa_keygen(EVP_PKEY_CTX *ctx,EVP_PKEY *pkey);
int pkey_dsa_copy(EVP_PKEY_CTX *dst,EVP_PKEY_CTX *src);
void ecdsa_data_free(void *data);
void ECDSA_set_default_method(ECDSA_METHOD *meth);
ECDSA_METHOD * ECDSA_get_default_method(void);
ECDSA_DATA * ECDSA_DATA_new_method(ENGINE *engine);
void * ecdsa_data_dup(void *data);
ECDSA_DATA * ecdsa_check(EC_KEY *key);
int ECDSA_set_method(EC_KEY *eckey,ECDSA_METHOD *meth);
int ECDSA_size(EC_KEY *r);
int ECDSA_get_ex_new_index(long argl,void *argp,CRYPTO_EX_new *new_func,CRYPTO_EX_dup *dup_func,CRYPTO_EX_free *free_func);
int ECDSA_set_ex_data(EC_KEY *d,int idx,void *arg);
void * ECDSA_get_ex_data(EC_KEY *d,int idx);
ECDSA_METHOD * ECDSA_METHOD_new(ECDSA_METHOD *ecdsa_meth);
void ECDSA_METHOD_set_sign(ECDSA_METHOD *ecdsa_method,_func_ECDSA_SIG_ptr_uchar_ptr_int_BIGNUM_ptr_BIGNUM_ptr_EC_KEY_ptr *ecdsa_do_sign);
void ECDSA_METHOD_set_sign_setup(ECDSA_METHOD *ecdsa_method,_func_int_EC_KEY_ptr_BN_CTX_ptr_BIGNUM_ptr_ptr_BIGNUM_ptr_ptr *ecdsa_sign_setup);
void ECDSA_METHOD_set_verify(ECDSA_METHOD *ecdsa_method,_func_int_uchar_ptr_int_ECDSA_SIG_ptr_EC_KEY_ptr *ecdsa_do_verify);
void ECDSA_METHOD_set_flags(ECDSA_METHOD *ecdsa_method,int flags);
void ECDSA_METHOD_set_name(ECDSA_METHOD *ecdsa_method,char *name);
void ECDSA_METHOD_free(ECDSA_METHOD *ecdsa_method);
void ECDSA_METHOD_set_app_data(ECDSA_METHOD *ecdsa_method,void *app);
void * ECDSA_METHOD_get_app_data(ECDSA_METHOD *ecdsa_method);
int ecdsa_do_verify(uchar *dgst,int dgst_len,ECDSA_SIG *sig,EC_KEY *eckey);
int ecdsa_sign_setup(EC_KEY *eckey,BN_CTX *ctx_in,BIGNUM **kinvp,BIGNUM **rp);
ECDSA_SIG * ecdsa_do_sign(uchar *dgst,int dgst_len,BIGNUM *in_kinv,BIGNUM *in_r,EC_KEY *eckey);
ECDSA_METHOD * ECDSA_OpenSSL(void);
ECDSA_SIG * ECDSA_do_sign_ex(uchar *dgst,int dlen,BIGNUM *kinv,BIGNUM *rp,EC_KEY *eckey);
ECDSA_SIG * ECDSA_do_sign(uchar *dgst,int dlen,EC_KEY *eckey);
int ECDSA_sign_ex(int type,uchar *dgst,int dlen,uchar *sig,uint *siglen,BIGNUM *kinv,BIGNUM *r,EC_KEY *eckey);
int ECDSA_sign(int type,uchar *dgst,int dlen,uchar *sig,uint *siglen,EC_KEY *eckey);
int ECDSA_sign_setup(EC_KEY *eckey,BN_CTX *ctx_in,BIGNUM **kinvp,BIGNUM **rp);
int ECDSA_do_verify(uchar *dgst,int dgst_len,ECDSA_SIG *sig,EC_KEY *eckey);
int ECDSA_verify(int type,uchar *dgst,int dgst_len,uchar *sigbuf,int sig_len,EC_KEY *eckey);
int dh_init(DH *dh);
int dh_finish(DH *dh);
int compute_key(uchar *key,BIGNUM *pub_key,DH *dh);
int generate_key(DH *dh);
int dh_bn_mod_exp(DH *dh,BIGNUM *r,BIGNUM *a,BIGNUM *p,BIGNUM *m,BN_CTX *ctx,BN_MONT_CTX *m_ctx);
int DH_generate_key(DH *dh);
int DH_compute_key(uchar *key,BIGNUM *pub_key,DH *dh);
int DH_compute_key_padded(uchar *key,BIGNUM *pub_key,DH *dh);
DH_METHOD * DH_OpenSSL(void);
int DH_check(DH *dh,int *ret);
int DH_check_pub_key(DH *dh,BIGNUM *pub_key,int *ret);
int dh_missing_parameters(EVP_PKEY *a);
void int_dh_free(EVP_PKEY *pkey);
int int_dh_bn_cpy(BIGNUM **dst,BIGNUM *src);
int dh_bits(EVP_PKEY *pkey);
int int_dh_size(EVP_PKEY *pkey);
int int_dh_param_copy(DH *to,DH *from,int is_x942);
int dh_copy_parameters(EVP_PKEY *to,EVP_PKEY *from);
int do_dh_print(BIO *bp,DH *x,int indent,ASN1_PCTX *ctx,int ptype);
int dh_param_print(BIO *bp,EVP_PKEY *pkey,int indent,ASN1_PCTX *ctx);
int dh_private_print(BIO *bp,EVP_PKEY *pkey,int indent,ASN1_PCTX *ctx);
int dh_public_print(BIO *bp,EVP_PKEY *pkey,int indent,ASN1_PCTX *ctx);
int dh_cmp_parameters(EVP_PKEY *a,EVP_PKEY *b);
int dh_pub_cmp(EVP_PKEY *a,EVP_PKEY *b);
int i2d_dhp(EVP_PKEY *pkey,DH *a,uchar **pp);
int dh_param_encode(EVP_PKEY *pkey,uchar **pder);
int dh_priv_encode(PKCS8_PRIV_KEY_INFO *p8,EVP_PKEY *pkey);
int dh_pub_encode(X509_PUBKEY *pk,EVP_PKEY *pkey);
DH * d2i_dhp(EVP_PKEY *pkey,uchar **pp,long length);
int dh_priv_decode(EVP_PKEY *pkey,PKCS8_PRIV_KEY_INFO *p8);
int dh_pub_decode(EVP_PKEY *pkey,X509_PUBKEY *pubkey);
int dh_param_decode(EVP_PKEY *pkey,uchar **pder,int derlen);
DH * DHparams_dup(DH *dh);
int dh_pkey_ctrl(EVP_PKEY *pkey,int op,long arg1,void *arg2);
int DHparams_print(BIO *bp,DH *x);
int pkey_dh_ctrl_str(EVP_PKEY_CTX *ctx,char *type,char *value);
int pkey_dh_ctrl(EVP_PKEY_CTX *ctx,int type,int p1,void *p2);
void pkey_dh_cleanup(EVP_PKEY_CTX *ctx);
int pkey_dh_init(EVP_PKEY_CTX *ctx);
int pkey_dh_derive(EVP_PKEY_CTX *ctx,uchar *key,size_t *keylen);
int pkey_dh_paramgen(EVP_PKEY_CTX *ctx,EVP_PKEY *pkey);
int pkey_dh_keygen(EVP_PKEY_CTX *ctx,EVP_PKEY *pkey);
int pkey_dh_copy(EVP_PKEY_CTX *dst,EVP_PKEY_CTX *src);
DH * DH_get_1024_160(void);
DH * DH_get_2048_224(void);
DH * DH_get_2048_256(void);
int skip_asn1(uchar **pp,long *plen,int exptag);
int DH_KDF_X9_42(uchar *out,size_t outlen,uchar *Z,size_t Zlen,ASN1_OBJECT *key_oid,uchar *ukm,size_t ukmlen,EVP_MD *md);
int ECDH_compute_key(void *out,size_t outlen,EC_POINT *pub_key,EC_KEY *eckey,_func_void_ptr_void_ptr_size_t_void_ptr_size_t_ptr *KDF);
int ECDH_KDF_X9_62(uchar *out,size_t outlen,uchar *Z,size_t Zlen,uchar *sinfo,size_t sinfolen,EVP_MD *md);
void DSO_set_default_method(DSO_METHOD *meth);
DSO_METHOD * DSO_get_default_method(void);
DSO_METHOD * DSO_get_method(DSO *dso);
DSO_METHOD * DSO_set_method(DSO *dso,DSO_METHOD *meth);
DSO * DSO_new_method(DSO_METHOD *meth);
DSO * DSO_new(void);
int DSO_free(DSO *dso);
int DSO_flags(DSO *dso);
int DSO_up_ref(DSO *dso);
void * DSO_bind_var(DSO *dso,char *symname);
DSO_FUNC_TYPE DSO_bind_func(DSO *dso,char *symname);
long DSO_ctrl(DSO *dso,int cmd,long larg,void *parg);
int DSO_set_name_converter(DSO *dso,DSO_NAME_CONVERTER_FUNC cb,DSO_NAME_CONVERTER_FUNC *oldcb);
char * DSO_get_filename(DSO *dso);
int DSO_set_filename(DSO *dso,char *filename);
DSO * DSO_load(DSO *dso,char *filename,DSO_METHOD *meth,int flags);
char * DSO_merge(DSO *dso,char *filespec1,char *filespec2);
char * DSO_convert_filename(DSO *dso,char *filename);
char * DSO_get_loaded_filename(DSO *dso);
int DSO_pathbyaddr(void *addr,char *path,int sz);
void * DSO_global_lookup(char *name);
DSO_METHOD * DSO_METHOD_openssl(void);
void engine_unregister_all_ECDSA(void);
void ENGINE_unregister_ECDSA(ENGINE *e);
int ENGINE_register_ECDSA(ENGINE *e);
void ENGINE_register_all_ECDSA(void);
int ENGINE_set_default_ECDSA(ENGINE *e);
ENGINE * ENGINE_get_default_ECDSA(void);
ECDSA_METHOD * ENGINE_get_ECDSA(ENGINE *e);
int ENGINE_set_ECDSA(ENGINE *e,ECDSA_METHOD *ecdsa_meth);
void engine_unregister_all_digests(void);
void ENGINE_unregister_digests(ENGINE *e);
int ENGINE_register_digests(ENGINE *e);
void ENGINE_register_all_digests(void);
int ENGINE_set_default_digests(ENGINE *e);
ENGINE * ENGINE_get_digest_engine(int nid);
ENGINE_DIGESTS_PTR ENGINE_get_digests(ENGINE *e);
EVP_MD * ENGINE_get_digest(ENGINE *e,int nid);
int ENGINE_set_digests(ENGINE *e,ENGINE_DIGESTS_PTR f);
int write_fp(void *data,size_t len,void *fp);
int write_bio(void *data,size_t len,void *bp);
int BIO_dump_indent_cb(_func_int_void_ptr_size_t_void_ptr *cb,void *u,char *s,int len,int indent);
int BIO_dump_cb(_func_int_void_ptr_size_t_void_ptr *cb,void *u,char *s,int len);
int BIO_dump_fp(FILE *fp,char *s,int len);
int BIO_dump_indent_fp(FILE *fp,char *s,int len,int indent);
int BIO_dump(BIO *bp,char *s,int len);
int BIO_dump_indent(BIO *bp,char *s,int len,int indent);
int BIO_hex_string(BIO *out,int indent,int width,uchar *data,int datalen);
int RAND_query_egd_bytes(char *path,uchar *buf,int bytes);
int RAND_egd_bytes(char *path,int bytes);
int RAND_egd(char *path);
void EVP_set_pw_prompt(char *prompt);
char * EVP_get_pw_prompt(void);
int EVP_read_pw_string_min(char *buf,int min,int len,char *prompt,int verify);
int EVP_read_pw_string(char *buf,int len,char *prompt,int verify);
int EVP_BytesToKey(EVP_CIPHER *type,EVP_MD *md,uchar *salt,uchar *data,int datal,int count,uchar *key,uchar *iv);
int trans_cb(int a,int b,BN_GENCB *gcb);
int EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_paramgen(EVP_PKEY_CTX *ctx,EVP_PKEY **ppkey);
int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_keygen(EVP_PKEY_CTX *ctx,EVP_PKEY **ppkey);
void EVP_PKEY_CTX_set_cb(EVP_PKEY_CTX *ctx,EVP_PKEY_gen_cb *cb);
EVP_PKEY_gen_cb * EVP_PKEY_CTX_get_cb(EVP_PKEY_CTX *ctx);
void evp_pkey_set_cb_translate(BN_GENCB *cb,EVP_PKEY_CTX *ctx);
int EVP_PKEY_CTX_get_keygen_info(EVP_PKEY_CTX *ctx,int idx);
EVP_PKEY * EVP_PKEY_new_mac_key(int type,ENGINE *e,uchar *key,int keylen);
int asn1_utctime_to_tm(tm *tm,ASN1_UTCTIME *d);
int ASN1_UTCTIME_check(ASN1_UTCTIME *d);
int ASN1_UTCTIME_set_string(ASN1_UTCTIME *s,char *str);
ASN1_UTCTIME * ASN1_UTCTIME_adj(ASN1_UTCTIME *s,time_t t,int offset_day,long offset_sec);
ASN1_UTCTIME * ASN1_UTCTIME_set(ASN1_UTCTIME *s,time_t t);
int ASN1_UTCTIME_cmp_time_t(ASN1_UTCTIME *s,time_t t);
int asn1_generalizedtime_to_tm(tm *tm,ASN1_GENERALIZEDTIME *d);
int ASN1_GENERALIZEDTIME_check(ASN1_GENERALIZEDTIME *d);
int ASN1_GENERALIZEDTIME_set_string(ASN1_GENERALIZEDTIME *s,char *str);
ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_adj(ASN1_GENERALIZEDTIME *s,time_t t,int offset_day,long offset_sec);
ASN1_GENERALIZEDTIME * ASN1_GENERALIZEDTIME_set(ASN1_GENERALIZEDTIME *s,time_t t);
int asn1_time_to_tm(tm *tm,ASN1_TIME *t);
ASN1_TIME * d2i_ASN1_TIME(ASN1_TIME **a,uchar **in,long len);
int i2d_ASN1_TIME(ASN1_TIME *a,uchar **out);
ASN1_TIME * ASN1_TIME_new(void);
void ASN1_TIME_free(ASN1_TIME *a);
ASN1_TIME * ASN1_TIME_adj(ASN1_TIME *s,time_t t,int offset_day,long offset_sec);
ASN1_TIME * ASN1_TIME_set(ASN1_TIME *s,time_t t);
int ASN1_TIME_check(ASN1_TIME *t);
ASN1_GENERALIZEDTIME * ASN1_TIME_to_generalizedtime(ASN1_TIME *t,ASN1_GENERALIZEDTIME **out);
int ASN1_TIME_set_string(ASN1_TIME *s,char *str);
int ASN1_TIME_diff(int *pday,int *psec,ASN1_TIME *from,ASN1_TIME *to);
int ASN1_PRINTABLE_type(uchar *s,int len);
int ASN1_UNIVERSALSTRING_to_string(ASN1_UNIVERSALSTRING *s);
int SetBlobCmp(void *elem1,void *elem2);
int i2d_ASN1_SET(stack_st_OPENSSL_BLOCK *a,uchar **pp,i2d_of_void *i2d,int ex_tag,int ex_class,int is_set);
stack_st_OPENSSL_BLOCK *d2i_ASN1_SET(stack_st_OPENSSL_BLOCK **a,uchar **pp,long length,d2i_of_void *d2i,_func_void_OPENSSL_BLOCK *free_func,int ex_tag,int ex_class);
int ASN1_ENUMERATED_set(ASN1_ENUMERATED *a,long v);
long ASN1_ENUMERATED_get(ASN1_ENUMERATED *a);
ASN1_ENUMERATED * BN_to_ASN1_ENUMERATED(BIGNUM *bn,ASN1_ENUMERATED *ai);
BIGNUM * ASN1_ENUMERATED_to_BN(ASN1_ENUMERATED *ai,BIGNUM *bn);
int ASN1_sign(i2d_of_void *i2d,X509_ALGOR *algor1,X509_ALGOR *algor2,ASN1_BIT_STRING *signature,char *data,EVP_PKEY *pkey,EVP_MD *type);
int ASN1_item_sign_ctx(ASN1_ITEM *it,X509_ALGOR *algor1,X509_ALGOR *algor2,ASN1_BIT_STRING *signature,void *asn,EVP_MD_CTX *ctx);
int ASN1_item_sign(ASN1_ITEM *it,X509_ALGOR *algor1,X509_ALGOR *algor2,ASN1_BIT_STRING *signature,void *asn,EVP_PKEY *pkey,EVP_MD *type);
int ASN1_digest(i2d_of_void *i2d,EVP_MD *type,char *data,uchar *md,uint *len);
int ASN1_item_digest(ASN1_ITEM *it,EVP_MD *type,void *asn,uchar *md,uint *len);
int ASN1_verify(i2d_of_void *i2d,X509_ALGOR *a,ASN1_BIT_STRING *signature,char *data,EVP_PKEY *pkey);
int ASN1_item_verify(ASN1_ITEM *it,X509_ALGOR *a,ASN1_BIT_STRING *signature,void *asn,EVP_PKEY *pkey);
int do_hex_dump(char_io *io_ch,void *arg,uchar *buf,int buflen);
int send_bio_chars(void *arg,void *buf,int len);
int do_esc_char(ulong c,uchar flags,char *do_quotes,char_io *io_ch,void *arg);
int do_buf(uchar *buf,int buflen,int type,uchar flags,char *quotes,char_io *io_ch,void *arg);
int do_print_ex(char_io *io_ch,void *arg,ulong lflags,ASN1_STRING *str);
int do_name_ex(char_io *io_ch,void *arg,X509_NAME *n,int indent,ulong flags);
int send_fp_chars(void *arg,void *buf,int len);
int X509_NAME_print_ex(BIO *out,X509_NAME *nm,int indent,ulong flags);
int X509_NAME_print_ex_fp(FILE *fp,X509_NAME *nm,int indent,ulong flags);
int ASN1_STRING_print_ex(BIO *out,ASN1_STRING *str,ulong flags);
int ASN1_STRING_print_ex_fp(FILE *fp,ASN1_STRING *str,ulong flags);
int ASN1_STRING_to_UTF8(uchar **out,ASN1_STRING *in);
X509_VAL * d2i_X509_VAL(X509_VAL **a,uchar **in,long len);
int i2d_X509_VAL(X509_VAL *a,uchar **out);
X509_VAL * X509_VAL_new(void);
void X509_VAL_free(X509_VAL *a);
NETSCAPE_SPKAC * d2i_NETSCAPE_SPKAC(NETSCAPE_SPKAC **a,uchar **in,long len);
int i2d_NETSCAPE_SPKAC(NETSCAPE_SPKAC *a,uchar **out);
NETSCAPE_SPKAC * NETSCAPE_SPKAC_new(void);
void NETSCAPE_SPKAC_free(NETSCAPE_SPKAC *a);
NETSCAPE_SPKI * d2i_NETSCAPE_SPKI(NETSCAPE_SPKI **a,uchar **in,long len);
int i2d_NETSCAPE_SPKI(NETSCAPE_SPKI *a,uchar **out);
NETSCAPE_SPKI * NETSCAPE_SPKI_new(void);
void NETSCAPE_SPKI_free(NETSCAPE_SPKI *a);
int X509_ocspid_print(BIO *bp,X509 *x);
int X509_signature_dump(BIO *bp,ASN1_STRING *sig,int indent);
int X509_signature_print(BIO *bp,X509_ALGOR *sigalg,ASN1_STRING *sig);
int ASN1_STRING_print(BIO *bp,ASN1_STRING *v);
int ASN1_GENERALIZEDTIME_print(BIO *bp,ASN1_GENERALIZEDTIME *tm);
int ASN1_UTCTIME_print(BIO *bp,ASN1_UTCTIME *tm);
int ASN1_TIME_print(BIO *bp,ASN1_TIME *tm);
int X509_print_ex(BIO *bp,X509 *x,ulong nmflags,ulong cflag);
int X509_print_ex_fp(FILE *fp,X509 *x,ulong nmflag,ulong cflag);
int X509_print_fp(FILE *fp,X509 *x);
int X509_print(BIO *bp,X509 *x);
int X509_NAME_print(BIO *bp,X509_NAME *name,int obase);
int X509_CERT_AUX_print(BIO *out,X509_CERT_AUX *aux,int indent);
int ASN1_bn_print(BIO *bp,char *number,BIGNUM *num,uchar *buf,int off);
int i2a_ASN1_INTEGER(BIO *bp,ASN1_INTEGER *a);
int a2i_ASN1_INTEGER(BIO *bp,ASN1_INTEGER *bs,char *buf,int size);
int i2a_ASN1_STRING(BIO *bp,ASN1_STRING *a,int type);
int a2i_ASN1_STRING(BIO *bp,ASN1_STRING *bs,char *buf,int size);
int i2d_ASN1_BOOLEAN(int a,uchar **pp);
int d2i_ASN1_BOOLEAN(int *a,uchar **pp,long length);
int parse_tagging(char *vstart,int vlen,int *ptag,int *pclass);
ASN1_TYPE * generate_v3(char *str,X509V3_CTX *cnf,int depth,int *perr);
int append_exp(tag_exp_arg *arg,int exp_tag,int exp_class,int exp_constructed,int exp_pad,int imp_ok);
int asn1_cb(char *elem,int len,void *bitstr);
int bitstr_cb(char *elem,int len,void *bitstr);
ASN1_TYPE * ASN1_generate_v3(char *str,X509V3_CTX *cnf);
ASN1_TYPE * ASN1_generate_nconf(char *str,CONF *nconf);
int sk_table_cmp(ASN1_STRING_TABLE **a,ASN1_STRING_TABLE **b);
int table_cmp_BSEARCH_CMP_FN(void *a_,void *b_);
void st_free(ASN1_STRING_TABLE *tbl);
void ASN1_STRING_set_default_mask(ulong mask);
ulong ASN1_STRING_get_default_mask(void);
int ASN1_STRING_set_default_mask_asc(char *p);
ASN1_STRING_TABLE * ASN1_STRING_TABLE_get(int nid);
ASN1_STRING * ASN1_STRING_set_by_NID(ASN1_STRING **out,uchar *in,int inlen,int inform,int nid);
int ASN1_STRING_TABLE_add(int nid,long minsize,long maxsize,ulong mask,ulong flags);
void ASN1_STRING_TABLE_cleanup(void);
char * X509_get_default_private_dir(void);
char * X509_get_default_cert_area(void);
char * X509_get_default_cert_dir(void);
char * X509_get_default_cert_file(void);
char * X509_get_default_cert_dir_env(void);
char * X509_get_default_cert_file_env(void);
X509_REQ * X509_to_X509_REQ(X509 *x,EVP_PKEY *pkey,EVP_MD *md);
EVP_PKEY * X509_REQ_get_pubkey(X509_REQ *req);
int X509_REQ_check_private_key(X509_REQ *x,EVP_PKEY *k);
int X509_REQ_extension_nid(int req_nid);
int * X509_REQ_get_extension_nids(void);
void X509_REQ_set_extension_nids(int *nids);
int X509_REQ_add_extensions_nid(X509_REQ *req,stack_st_X509_EXTENSION *exts,int nid);
int X509_REQ_add_extensions(X509_REQ *req,stack_st_X509_EXTENSION *exts);
int X509_REQ_get_attr_count(X509_REQ *req);
int X509_REQ_get_attr_by_NID(X509_REQ *req,int nid,int lastpos);
int X509_REQ_get_attr_by_OBJ(X509_REQ *req,ASN1_OBJECT *obj,int lastpos);
X509_ATTRIBUTE * X509_REQ_get_attr(X509_REQ *req,int loc);
stack_st_X509_EXTENSION * X509_REQ_get_extensions(X509_REQ *req);
X509_ATTRIBUTE * X509_REQ_delete_attr(X509_REQ *req,int loc);
int X509_REQ_add1_attr(X509_REQ *req,X509_ATTRIBUTE *attr);
int X509_REQ_add1_attr_by_OBJ(X509_REQ *req,ASN1_OBJECT *obj,int type,uchar *bytes,int len);
int X509_REQ_add1_attr_by_NID(X509_REQ *req,int nid,int type,uchar *bytes,int len);
int X509_REQ_add1_attr_by_txt(X509_REQ *req,char *attrname,int type,uchar *bytes,int len);
int X509_REQ_set_version(X509_REQ *x,long version);
int X509_REQ_set_subject_name(X509_REQ *x,X509_NAME *name);
int X509_REQ_set_pubkey(X509_REQ *x,EVP_PKEY *pkey);
stack_st_CONF_VALUE *i2v_BASIC_CONSTRAINTS(X509V3_EXT_METHOD *method,BASIC_CONSTRAINTS *bcons,stack_st_CONF_VALUE *extlist);
BASIC_CONSTRAINTS * d2i_BASIC_CONSTRAINTS(BASIC_CONSTRAINTS **a,uchar **in,long len);
int i2d_BASIC_CONSTRAINTS(BASIC_CONSTRAINTS *a,uchar **out);
BASIC_CONSTRAINTS * BASIC_CONSTRAINTS_new(void);
void BASIC_CONSTRAINTS_free(BASIC_CONSTRAINTS *a);
BASIC_CONSTRAINTS *v2i_BASIC_CONSTRAINTS(X509V3_EXT_METHOD *method,X509V3_CTX *ctx,stack_st_CONF_VALUE *values);
stack_st_CONF_VALUE *i2v_ASN1_BIT_STRING(X509V3_EXT_METHOD *method,ASN1_BIT_STRING *bits,stack_st_CONF_VALUE *ret);
ASN1_BIT_STRING *v2i_ASN1_BIT_STRING(X509V3_EXT_METHOD *method,X509V3_CTX *ctx,stack_st_CONF_VALUE *nval);
int v3_check_critical(char **value);
int v3_check_generic(char **value);
X509_EXTENSION * v3_generic_extension(char *ext,char *value,int crit,int gen_type,X509V3_CTX *ctx);
stack_st_CONF_VALUE * nconf_get_section(void *db,char *section);
char * nconf_get_string(void *db,char *section,char *value);
stack_st_CONF_VALUE * conf_lhash_get_section(void *db,char *section);
char * conf_lhash_get_string(void *db,char *section,char *value);
X509_EXTENSION *do_ext_i2d(X509V3_EXT_METHOD *method,int ext_nid,int crit,void *ext_struc,X509V3_EXT_METHOD *method_1);
X509_EXTENSION * do_ext_nconf(CONF *conf,X509V3_CTX *ctx,int ext_nid,int crit,char *value);
X509_EXTENSION * X509V3_EXT_nconf(CONF *conf,X509V3_CTX *ctx,char *name,char *value);
X509_EXTENSION * X509V3_EXT_nconf_nid(CONF *conf,X509V3_CTX *ctx,int ext_nid,char *value);
X509_EXTENSION * X509V3_EXT_i2d(int ext_nid,int crit,void *ext_struc);
int X509V3_EXT_add_nconf_sk(CONF *conf,X509V3_CTX *ctx,char *section,stack_st_X509_EXTENSION **sk);
int X509V3_EXT_add_nconf(CONF *conf,X509V3_CTX *ctx,char *section,X509 *cert);
int X509V3_EXT_CRL_add_nconf(CONF *conf,X509V3_CTX *ctx,char *section,X509_CRL *crl);
int X509V3_EXT_REQ_add_nconf(CONF *conf,X509V3_CTX *ctx,char *section,X509_REQ *req);
char * X509V3_get_string(X509V3_CTX *ctx,char *name,char *section);
stack_st_CONF_VALUE * X509V3_get_section(X509V3_CTX *ctx,char *section);
void X509V3_string_free(X509V3_CTX *ctx,char *str);
void X509V3_section_free(X509V3_CTX *ctx,stack_st_CONF_VALUE *section);
void X509V3_set_nconf(X509V3_CTX *ctx,CONF *conf);
void X509V3_set_ctx(X509V3_CTX *ctx,X509 *issuer,X509 *subj,X509_REQ *req,X509_CRL *crl,int flags);
X509_EXTENSION * X509V3_EXT_conf(lhash_st_CONF_VALUE *conf,X509V3_CTX *ctx,char *name,char *value);
X509_EXTENSION *X509V3_EXT_conf_nid(lhash_st_CONF_VALUE *conf,X509V3_CTX *ctx,int ext_nid,char *value);
void X509V3_set_conf_lhash(X509V3_CTX *ctx,lhash_st_CONF_VALUE *lhash);
int X509V3_EXT_add_conf(lhash_st_CONF_VALUE *conf,X509V3_CTX *ctx,char *section,X509 *cert);
int X509V3_EXT_CRL_add_conf(lhash_st_CONF_VALUE *conf,X509V3_CTX *ctx,char *section,X509_CRL *crl);
int X509V3_EXT_REQ_add_conf(lhash_st_CONF_VALUE *conf,X509V3_CTX *ctx,char *section,X509_REQ *req);
void * v2i_EXTENDED_KEY_USAGE(X509V3_EXT_METHOD *method,X509V3_CTX *ctx,stack_st_CONF_VALUE *nval);
stack_st_CONF_VALUE *i2v_EXTENDED_KEY_USAGE(X509V3_EXT_METHOD *method,void *a,stack_st_CONF_VALUE *ext_list);
EXTENDED_KEY_USAGE * d2i_EXTENDED_KEY_USAGE(EXTENDED_KEY_USAGE **a,uchar **in,long len);
int i2d_EXTENDED_KEY_USAGE(EXTENDED_KEY_USAGE *a,uchar **out);
EXTENDED_KEY_USAGE * EXTENDED_KEY_USAGE_new(void);
void EXTENDED_KEY_USAGE_free(EXTENDED_KEY_USAGE *a);
ASN1_IA5STRING * s2i_ASN1_IA5STRING(X509V3_EXT_METHOD *method,X509V3_CTX *ctx,char *str);
char * i2s_ASN1_IA5STRING(X509V3_EXT_METHOD *method,ASN1_IA5STRING *ia5);
int unknown_ext_print(BIO *out,X509_EXTENSION *ext,ulong flag,int indent,int supported);
void X509V3_EXT_val_prn(BIO *out,stack_st_CONF_VALUE *val,int indent,int ml);
int X509V3_EXT_print(BIO *out,X509_EXTENSION *ext,ulong flag,int indent);
int X509V3_extensions_print(BIO *bp,char *title,stack_st_X509_EXTENSION *exts,ulong flag,int indent);
int X509V3_EXT_print_fp(FILE *fp,X509_EXTENSION *ext,int flag,int indent);
int node_cmp(X509_POLICY_NODE **a,X509_POLICY_NODE **b);
stack_st_X509_POLICY_NODE * policy_node_cmp_new(void);
X509_POLICY_NODE * tree_find_sk(stack_st_X509_POLICY_NODE *nodes,ASN1_OBJECT *id);
X509_POLICY_NODE *level_find_node(X509_POLICY_LEVEL *level,X509_POLICY_NODE *parent,ASN1_OBJECT *id);
void policy_node_free(X509_POLICY_NODE *node);
X509_POLICY_NODE *level_add_node(X509_POLICY_LEVEL *level,X509_POLICY_DATA *data,X509_POLICY_NODE *parent,X509_POLICY_TREE *tree);
int policy_node_match(X509_POLICY_LEVEL *lvl,X509_POLICY_NODE *node,ASN1_OBJECT *oid);
void CONF_set_nconf(CONF *conf,lhash_st_CONF_VALUE *hash);
int CONF_set_default_method(CONF_METHOD *meth);
CONF * NCONF_new(CONF_METHOD *meth);
void NCONF_free(CONF *conf);
void NCONF_free_data(CONF *conf);
void CONF_free(lhash_st_CONF_VALUE *conf);
int NCONF_load(CONF *conf,char *file,long *eline);
int NCONF_load_bio(CONF *conf,BIO *bp,long *eline);
lhash_st_CONF_VALUE * CONF_load_bio(lhash_st_CONF_VALUE *conf,BIO *bp,long *eline);
lhash_st_CONF_VALUE * CONF_load(lhash_st_CONF_VALUE *conf,char *file,long *eline);
lhash_st_CONF_VALUE * CONF_load_fp(lhash_st_CONF_VALUE *conf,FILE *fp,long *eline);
int NCONF_load_fp(CONF *conf,FILE *fp,long *eline);
stack_st_CONF_VALUE * NCONF_get_section(CONF *conf,char *section);
stack_st_CONF_VALUE * CONF_get_section(lhash_st_CONF_VALUE *conf,char *section);
char * NCONF_get_string(CONF *conf,char *group,char *name);
char * CONF_get_string(lhash_st_CONF_VALUE *conf,char *group,char *name);
int NCONF_get_number_e(CONF *conf,char *group,char *name,long *result);
long CONF_get_number(lhash_st_CONF_VALUE *conf,char *group,char *name);
int NCONF_dump_bio(CONF *conf,BIO *out);
int CONF_dump_bio(lhash_st_CONF_VALUE *conf,BIO *out);
int CONF_dump_fp(lhash_st_CONF_VALUE *conf,FILE *out);
int NCONF_dump_fp(CONF *conf,FILE *out);
void value_free_stack_LHASH_DOALL(void *arg);
void value_free_hash_LHASH_DOALL_ARG(void *arg1,void *arg2);
int conf_value_LHASH_COMP(void *arg1,void *arg2);
ulong conf_value_LHASH_HASH(void *arg);
CONF_VALUE * _CONF_get_section(CONF *conf,char *section);
stack_st_CONF_VALUE * _CONF_get_section_values(CONF *conf,char *section);
int _CONF_add_string(CONF *conf,CONF_VALUE *section,CONF_VALUE *value);
char * _CONF_get_string(CONF *conf,char *section,char *name);
int _CONF_new_data(CONF *conf);
void _CONF_free_data(CONF *conf);
CONF_VALUE * _CONF_new_section(CONF *conf,char *section);
int def_init_default(CONF *conf);
int def_init_WIN32(CONF *conf);
int def_is_number(CONF *conf,char c);
int def_to_int(CONF *conf,char c);
int def_dump(CONF *conf,BIO *out);
void dump_value_LHASH_DOALL_ARG(void *arg1,void *arg2);
CONF * def_create(CONF_METHOD *meth);
int str_copy(CONF *conf,char *section,char **pto,char *from);
int def_destroy_data(CONF *conf);
int def_destroy(CONF *conf);
char * eat_alpha_numeric(CONF *conf,char *p);
int def_load_bio(CONF *conf,BIO *in,long *line);
int def_load(CONF *conf,char *name,long *line);
CONF_METHOD * NCONF_default(void);
CONF_METHOD * NCONF_WIN32(void);
void free_string(UI_STRING *uis);
int print_error(char *str,size_t len,UI *ui);
UI_STRING *general_allocate_prompt(UI *ui,char *prompt,int prompt_freeable,UI_string_types type,int input_flags,char *result_buf);
int general_allocate_boolean(UI *ui,char *prompt,char *action_desc,char *ok_chars,char *cancel_chars,int prompt_freeable,UI_string_types type,int input_flags,char *result_buf);
int general_allocate_string(UI *ui,char *prompt,int prompt_freeable,UI_string_types type,int input_flags,char *result_buf,int minsize,int maxsize,char *test_buf);
void UI_free(UI *ui);
int UI_add_input_string(UI *ui,char *prompt,int flags,char *result_buf,int minsize,int maxsize);
int UI_dup_input_string(UI *ui,char *prompt,int flags,char *result_buf,int minsize,int maxsize);
int UI_add_verify_string(UI *ui,char *prompt,int flags,char *result_buf,int minsize,int maxsize,char *test_buf);
int UI_dup_verify_string(UI *ui,char *prompt,int flags,char *result_buf,int minsize,int maxsize,char *test_buf);
int UI_add_input_boolean(UI *ui,char *prompt,char *action_desc,char *ok_chars,char *cancel_chars,int flags,char *result_buf);
int UI_dup_input_boolean(UI *ui,char *prompt,char *action_desc,char *ok_chars,char *cancel_chars,int flags,char *result_buf);
int UI_add_info_string(UI *ui,char *text);
int UI_dup_info_string(UI *ui,char *text);
int UI_add_error_string(UI *ui,char *text);
int UI_dup_error_string(UI *ui,char *text);
char * UI_construct_prompt(UI *ui,char *object_desc,char *object_name);
void * UI_add_user_data(UI *ui,void *user_data);
void * UI_get0_user_data(UI *ui);
int UI_process(UI *ui);
int UI_ctrl(UI *ui,int cmd,long i,void *p,_func_void *f);
int UI_get_ex_new_index(long argl,void *argp,CRYPTO_EX_new *new_func,CRYPTO_EX_dup *dup_func,CRYPTO_EX_free *free_func);
int UI_set_ex_data(UI *r,int idx,void *arg);
void * UI_get_ex_data(UI *r,int idx);
void UI_set_default_method(UI_METHOD *meth);
UI_METHOD * UI_get_default_method(void);
UI * UI_new_method(UI_METHOD *method);
UI * UI_new(void);
UI_METHOD * UI_get_method(UI *ui);
UI_METHOD * UI_set_method(UI *ui,UI_METHOD *meth);
UI_METHOD * UI_create_method(char *name);
void UI_destroy_method(UI_METHOD *ui_method);
int UI_method_set_opener(UI_METHOD *method,_func_int_UI_ptr *opener);
int UI_method_set_writer(UI_METHOD *method,_func_int_UI_ptr_UI_STRING_ptr *writer);
int UI_method_set_flusher(UI_METHOD *method,_func_int_UI_ptr *flusher);
int UI_method_set_reader(UI_METHOD *method,_func_int_UI_ptr_UI_STRING_ptr *reader);
int UI_method_set_closer(UI_METHOD *method,_func_int_UI_ptr *closer);
int UI_method_set_prompt_constructor(UI_METHOD *method,_func_char_ptr_UI_ptr_char_ptr_char_ptr *prompt_constructor);
_func_int_UI_ptr * UI_method_get_opener(UI_METHOD *method);
_func_int_UI_ptr_UI_STRING_ptr * UI_method_get_writer(UI_METHOD *method);
_func_int_UI_ptr * UI_method_get_flusher(UI_METHOD *method);
_func_int_UI_ptr_UI_STRING_ptr * UI_method_get_reader(UI_METHOD *method);
_func_int_UI_ptr * UI_method_get_closer(UI_METHOD *method);
_func_char_ptr_UI_ptr_char_ptr_char_ptr * UI_method_get_prompt_constructor(UI_METHOD *method);
UI_string_types UI_get_string_type(UI_STRING *uis);
int UI_get_input_flags(UI_STRING *uis);
char * UI_get0_output_string(UI_STRING *uis);
char * UI_get0_action_string(UI_STRING *uis);
char * UI_get0_result_string(UI_STRING *uis);
char * UI_get0_result(UI *ui,int i);
char * UI_get0_test_string(UI_STRING *uis);
int UI_get_result_minsize(UI_STRING *uis);
int UI_get_result_maxsize(UI_STRING *uis);
int UI_set_result(UI *ui,UI_STRING *uis,char *result);
void recsig(int i);
int close_console(UI *ui);
int write_string(UI *ui,UI_STRING *uis);
int read_string_inner(UI *ui,UI_STRING *uis,int echo,int strip_nl);
int read_string(UI *ui,UI_STRING *uis);
int open_console(UI *ui);
UI_METHOD * UI_OpenSSL(void);
int cms_rek_cb(int operation,ASN1_VALUE **pval,ASN1_ITEM *it,void *exarg);
int cms_kari_cb(int operation,ASN1_VALUE **pval,ASN1_ITEM *it,void *exarg);
int cms_cb(int operation,ASN1_VALUE **pval,ASN1_ITEM *it,void *exarg);
int cms_si_cb(int operation,ASN1_VALUE **pval,ASN1_ITEM *it,void *exarg);
int cms_ri_cb(int operation,ASN1_VALUE **pval,ASN1_ITEM *it,void *exarg);
int CMS_SharedInfo_encode(uchar **pder,X509_ALGOR *kekalg,ASN1_OCTET_STRING *ukm,int keylen);
int CMS_stream(uchar ***boundary,CMS_ContentInfo *cms);
CMS_ContentInfo * d2i_CMS_bio(BIO *bp,CMS_ContentInfo **cms);
int i2d_CMS_bio(BIO *bp,CMS_ContentInfo *cms);
CMS_ContentInfo * PEM_read_bio_CMS(BIO *bp,CMS_ContentInfo **x,pem_password_cb *cb,void *u);
CMS_ContentInfo * PEM_read_CMS(FILE *fp,CMS_ContentInfo **x,pem_password_cb *cb,void *u);
int PEM_write_bio_CMS(BIO *bp,CMS_ContentInfo *x);
int PEM_write_CMS(FILE *fp,CMS_ContentInfo *x);
BIO * BIO_new_CMS(BIO *out,CMS_ContentInfo *cms);
int i2d_CMS_bio_stream(BIO *out,CMS_ContentInfo *cms,BIO *in,int flags);
int PEM_write_bio_CMS_stream(BIO *out,CMS_ContentInfo *cms,BIO *in,int flags);
int SMIME_write_CMS(BIO *bio,CMS_ContentInfo *cms,BIO *data,int flags);
CMS_ContentInfo * SMIME_read_CMS(BIO *bio,BIO **bcont);
int cms_sd_asn1_ctrl(CMS_SignerInfo *si,int cmd);
CMS_SignedData * cms_get0_signed(CMS_ContentInfo *cms);
CMS_SignedData * cms_signed_data_init(CMS_ContentInfo *cms);
int CMS_SignedData_init(CMS_ContentInfo *cms);
int cms_set1_SignerIdentifier(CMS_SignerIdentifier *sid,X509 *cert,int type);
int cms_SignerIdentifier_get0_signer_id(CMS_SignerIdentifier *sid,ASN1_OCTET_STRING **keyid,X509_NAME **issuer,ASN1_INTEGER **sno);
int cms_SignerIdentifier_cert_cmp(CMS_SignerIdentifier *sid,X509 *cert);
EVP_PKEY_CTX * CMS_SignerInfo_get0_pkey_ctx(CMS_SignerInfo *si);
EVP_MD_CTX * CMS_SignerInfo_get0_md_ctx(CMS_SignerInfo *si);
stack_st_CMS_SignerInfo * CMS_get0_SignerInfos(CMS_ContentInfo *cms);
stack_st_X509 * CMS_get0_signers(CMS_ContentInfo *cms);
void CMS_SignerInfo_set1_signer_cert(CMS_SignerInfo *si,X509 *signer);
int CMS_SignerInfo_get0_signer_id(CMS_SignerInfo *si,ASN1_OCTET_STRING **keyid,X509_NAME **issuer,ASN1_INTEGER **sno);
int CMS_SignerInfo_cert_cmp(CMS_SignerInfo *si,X509 *cert);
int CMS_set1_signers_certs(CMS_ContentInfo *cms,stack_st_X509 *scerts,uint flags);
void CMS_SignerInfo_get0_algs(CMS_SignerInfo *si,EVP_PKEY **pk,X509 **signer,X509_ALGOR **pdig,X509_ALGOR **psig);
ASN1_OCTET_STRING * CMS_SignerInfo_get0_signature(CMS_SignerInfo *si);
int CMS_SignerInfo_sign(CMS_SignerInfo *si);
int cms_SignedData_final(CMS_ContentInfo *cms,BIO *chain);
int CMS_SignerInfo_verify(CMS_SignerInfo *si);
BIO * cms_SignedData_init_bio(CMS_ContentInfo *cms);
int CMS_SignerInfo_verify_content(CMS_SignerInfo *si,BIO *chain);
int CMS_add_smimecap(CMS_SignerInfo *si,stack_st_X509_ALGOR *algs);
int CMS_add_simple_smimecap(stack_st_X509_ALGOR **algs,int algnid,int keysize);
int cms_add_cipher_smcap(stack_st_X509_ALGOR **sk,int nid,int arg);
int CMS_add_standard_smimecap(stack_st_X509_ALGOR **smcap);
CMS_SignerInfo *CMS_add1_signer(CMS_ContentInfo *cms,X509 *signer,EVP_PKEY *pk,EVP_MD *md,uint flags);
CMS_EnvelopedData * cms_get0_enveloped(CMS_ContentInfo *cms);
int cms_env_asn1_ctrl(CMS_RecipientInfo *ri,int cmd);
stack_st_CMS_RecipientInfo * CMS_get0_RecipientInfos(CMS_ContentInfo *cms);
int CMS_RecipientInfo_type(CMS_RecipientInfo *ri);
EVP_PKEY_CTX * CMS_RecipientInfo_get0_pkey_ctx(CMS_RecipientInfo *ri);
CMS_ContentInfo * CMS_EnvelopedData_create(EVP_CIPHER *cipher);
int CMS_RecipientInfo_ktri_get0_algs(CMS_RecipientInfo *ri,EVP_PKEY **pk,X509 **recip,X509_ALGOR **palg);
int CMS_RecipientInfo_ktri_get0_signer_id(CMS_RecipientInfo *ri,ASN1_OCTET_STRING **keyid,X509_NAME **issuer,ASN1_INTEGER **sno);
int CMS_RecipientInfo_ktri_cert_cmp(CMS_RecipientInfo *ri,X509 *cert);
int CMS_RecipientInfo_set0_pkey(CMS_RecipientInfo *ri,EVP_PKEY *pkey);
int CMS_RecipientInfo_kekri_id_cmp(CMS_RecipientInfo *ri,uchar *id,size_t idlen);
CMS_RecipientInfo *CMS_add0_recipient_key(CMS_ContentInfo *cms,int nid,uchar *key,size_t keylen,uchar *id,size_t idlen,ASN1_GENERALIZEDTIME *date,ASN1_OBJECT *otherTypeId,ASN1_TYPE *otherType);
int CMS_RecipientInfo_kekri_get0_id(CMS_RecipientInfo *ri,X509_ALGOR **palg,ASN1_OCTET_STRING **pid,ASN1_GENERALIZEDTIME **pdate,ASN1_OBJECT **potherid,ASN1_TYPE **pothertype);
int CMS_RecipientInfo_set0_key(CMS_RecipientInfo *ri,uchar *key,size_t keylen);
int CMS_RecipientInfo_decrypt(CMS_ContentInfo *cms,CMS_RecipientInfo *ri);
int CMS_RecipientInfo_encrypt(CMS_ContentInfo *cms,CMS_RecipientInfo *ri);
BIO * cms_EnvelopedData_init_bio(CMS_ContentInfo *cms);
int cms_pkey_get_ri_type(EVP_PKEY *pk);
CMS_RecipientInfo * CMS_add1_recipient_cert(CMS_ContentInfo *cms,X509 *recip,uint flags);
BIO * cms_EncryptedContent_init_bio(CMS_EncryptedContentInfo *ec);
int cms_EncryptedContent_init(CMS_EncryptedContentInfo *ec,EVP_CIPHER *cipher,uchar *key,size_t keylen);
int CMS_EncryptedData_set1_key(CMS_ContentInfo *cms,EVP_CIPHER *ciph,uchar *key,size_t keylen);
BIO * cms_EncryptedData_init_bio(CMS_ContentInfo *cms);
int CMS_RecipientInfo_set0_password(CMS_RecipientInfo *ri,uchar *pass,ssize_t passlen);
CMS_RecipientInfo *CMS_add0_recipient_password(CMS_ContentInfo *cms,int iter,int wrap_nid,int pbe_nid,uchar *pass,ssize_t passlen,EVP_CIPHER *kekciph);
int cms_RecipientInfo_pwri_crypt(CMS_ContentInfo *cms,CMS_RecipientInfo *ri,int en_de);
int cms_kek_cipher(uchar **pout,size_t *poutlen,uchar *in,size_t inlen,CMS_KeyAgreeRecipientInfo *kari,int enc);
int CMS_RecipientInfo_kari_get0_alg(CMS_RecipientInfo *ri,X509_ALGOR **palg,ASN1_OCTET_STRING **pukm);
stack_st_CMS_RecipientEncryptedKey * CMS_RecipientInfo_kari_get0_reks(CMS_RecipientInfo *ri);
int CMS_RecipientInfo_kari_get0_orig_id(CMS_RecipientInfo *ri,X509_ALGOR **pubalg,ASN1_BIT_STRING **pubkey,ASN1_OCTET_STRING **keyid,X509_NAME **issuer,ASN1_INTEGER **sno);
int CMS_RecipientInfo_kari_orig_id_cmp(CMS_RecipientInfo *ri,X509 *cert);
int CMS_RecipientEncryptedKey_get0_id(CMS_RecipientEncryptedKey *rek,ASN1_OCTET_STRING **keyid,ASN1_GENERALIZEDTIME **tm,CMS_OtherKeyAttribute **other,X509_NAME **issuer,ASN1_INTEGER **sno);
int CMS_RecipientEncryptedKey_cert_cmp(CMS_RecipientEncryptedKey *rek,X509 *cert);
int CMS_RecipientInfo_kari_set0_pkey(CMS_RecipientInfo *ri,EVP_PKEY *pk);
EVP_CIPHER_CTX * CMS_RecipientInfo_kari_get0_ctx(CMS_RecipientInfo *ri);
int CMS_RecipientInfo_kari_decrypt(CMS_ContentInfo *cms,CMS_RecipientInfo *ri,CMS_RecipientEncryptedKey *rek);
int cms_RecipientInfo_kari_init(CMS_RecipientInfo *ri,X509 *recip,EVP_PKEY *pk,uint flags);
int cms_RecipientInfo_kari_encrypt(CMS_ContentInfo *cms,CMS_RecipientInfo *ri);
void make_kn(uchar *k1,uchar *l,int bl);
CMAC_CTX * CMAC_CTX_new(void);
void CMAC_CTX_cleanup(CMAC_CTX *ctx);
EVP_CIPHER_CTX * CMAC_CTX_get0_cipher_ctx(CMAC_CTX *ctx);
void CMAC_CTX_free(CMAC_CTX *ctx);
int CMAC_CTX_copy(CMAC_CTX *out,CMAC_CTX *in);
int CMAC_Init(CMAC_CTX *ctx,void *key,size_t keylen,EVP_CIPHER *cipher,ENGINE *impl);
int CMAC_Update(CMAC_CTX *ctx,void *in,size_t dlen);
int CMAC_Final(CMAC_CTX *ctx,uchar *out,size_t *poutlen);
int CMAC_resume(CMAC_CTX *ctx);
int julian_adj(tm *tm,int off_day,long offset_sec,long *pday,int *psec);
tm * OPENSSL_gmtime(time_t *timer,tm *result);
int OPENSSL_gmtime_adj(tm *tm,int off_day,long offset_sec);
int OPENSSL_gmtime_diff(int *pday,int *psec,tm *from,tm *to);
int AES_wrap_key(AES_KEY *key,uchar *iv,uchar *out,uchar *in,uint inlen);
int AES_unwrap_key(AES_KEY *key,uchar *iv,uchar *out,uchar *in,uint inlen);
int Camellia_Ekeygen(int keyBitLength,u8 *rawKey,uint *k);
void Camellia_EncryptBlock_Rounds(int grandRounds,u8 *plaintext,uint *keyTable,u8 *ciphertext);
void Camellia_EncryptBlock(int keyBitLength,u8 *plaintext,uint *keyTable,u8 *ciphertext);
void Camellia_DecryptBlock_Rounds(int grandRounds,u8 *ciphertext,uint *keyTable,u8 *plaintext);
void Camellia_DecryptBlock(int keyBitLength,u8 *plaintext,uint *keyTable,u8 *ciphertext);
int BN_kronecker(BIGNUM *a,BIGNUM *b,BN_CTX *ctx);
BIGNUM * BN_mod_sqrt(BIGNUM *in,BIGNUM *a,BIGNUM *p,BN_CTX *ctx);
int probable_prime(BIGNUM *rnd,int bits);
int BN_GENCB_call(BN_GENCB *cb,int a,int b);
int BN_is_prime_fasttest_ex(BIGNUM *a,int checks,BN_CTX *ctx_passed,int do_trial_division,BN_GENCB *cb);
int BN_generate_prime_ex(BIGNUM *ret,int bits,int safe,BIGNUM *add,BIGNUM *rem,BN_GENCB *cb);
int BN_is_prime_ex(BIGNUM *a,int checks,BN_CTX *ctx_passed,BN_GENCB *cb);
undefined4 bn_mul_mont(int *param_1,undefined1 (*param_2) [16],uint *param_3,uint *param_4,undefined4 *param_5,uint param_6);
void bn_mul8x_mont_neon(int *param_1,undefined1 (*param_2) [16],undefined4 param_3,undefined8 *param_4,undefined4 *param_5,int param_6);
int BN_GF2m_add(BIGNUM *r,BIGNUM *a,BIGNUM *b);
int BN_GF2m_mod_arr(BIGNUM *r,BIGNUM *a,int *p);
int BN_GF2m_mod_sqr_arr(BIGNUM *r,BIGNUM *a,int *p,BN_CTX *ctx);
int BN_GF2m_mod_mul_arr(BIGNUM *r,BIGNUM *a,BIGNUM *b,int *p,BN_CTX *ctx);
int BN_GF2m_mod_exp_arr(BIGNUM *r,BIGNUM *a,BIGNUM *b,int *p,BN_CTX *ctx);
int BN_GF2m_mod_sqrt_arr(BIGNUM *r,BIGNUM *a,int *p,BN_CTX *ctx);
int BN_GF2m_mod_solve_quad_arr(BIGNUM *r,BIGNUM *a_,int *p,BN_CTX *ctx);
int BN_GF2m_poly2arr(BIGNUM *a,int *p,int max);
int BN_GF2m_mod(BIGNUM *r,BIGNUM *a,BIGNUM *p);
int BN_GF2m_mod_inv(BIGNUM *r,BIGNUM *a,BIGNUM *p,BN_CTX *ctx);
int BN_GF2m_mod_mul(BIGNUM *r,BIGNUM *a,BIGNUM *b,BIGNUM *p,BN_CTX *ctx);
int BN_GF2m_mod_div(BIGNUM *r,BIGNUM *y,BIGNUM *x,BIGNUM *p,BN_CTX *ctx);
int BN_GF2m_mod_sqr(BIGNUM *r,BIGNUM *a,BIGNUM *p,BN_CTX *ctx);
int BN_GF2m_mod_exp(BIGNUM *r,BIGNUM *a,BIGNUM *b,BIGNUM *p,BN_CTX *ctx);
int BN_GF2m_mod_sqrt(BIGNUM *r,BIGNUM *a,BIGNUM *p,BN_CTX *ctx);
int BN_GF2m_mod_solve_quad(BIGNUM *r,BIGNUM *a,BIGNUM *p,BN_CTX *ctx);
int BN_GF2m_arr2poly(int *p,BIGNUM *a);
int BN_GF2m_mod_inv_arr(BIGNUM *r,BIGNUM *xx,int *p,BN_CTX *ctx);
int BN_GF2m_mod_div_arr(BIGNUM *r,BIGNUM *yy,BIGNUM *xx,int *p,BN_CTX *ctx);
int ec_GFp_mont_group_init(EC_GROUP *group);
void ec_GFp_mont_group_finish(EC_GROUP *group);
void ec_GFp_mont_group_clear_finish(EC_GROUP *group);
int ec_GFp_mont_group_set_curve(EC_GROUP *group,BIGNUM *p,BIGNUM *a,BIGNUM *b,BN_CTX *ctx);
int ec_GFp_mont_group_copy(EC_GROUP *dest,EC_GROUP *src);
int ec_GFp_mont_field_mul(EC_GROUP *group,BIGNUM *r,BIGNUM *a,BIGNUM *b,BN_CTX *ctx);
int ec_GFp_mont_field_sqr(EC_GROUP *group,BIGNUM *r,BIGNUM *a,BN_CTX *ctx);
int ec_GFp_mont_field_encode(EC_GROUP *group,BIGNUM *r,BIGNUM *a,BN_CTX *ctx);
int ec_GFp_mont_field_decode(EC_GROUP *group,BIGNUM *r,BIGNUM *a,BN_CTX *ctx);
int ec_GFp_mont_field_set_to_one(EC_GROUP *group,BIGNUM *r,BN_CTX *ctx);
EC_METHOD * EC_GFp_mont_method(void);
BIGNUM * EC_POINT_point2bn(EC_GROUP *group,EC_POINT *point,point_conversion_form_t form,BIGNUM *ret,BN_CTX *ctx);
EC_POINT * EC_POINT_bn2point(EC_GROUP *group,BIGNUM *bn,EC_POINT *point,BN_CTX *ctx);
char * EC_POINT_point2hex(EC_GROUP *group,EC_POINT *point,point_conversion_form_t form,BN_CTX *ctx);
EC_POINT * EC_POINT_hex2point(EC_GROUP *group,char *buf,EC_POINT *point,BN_CTX *ctx);
int RSA_generate_key_ex(RSA *rsa,int bits,BIGNUM *e_value,BN_GENCB *cb);
int RSA_verify_PKCS1_PSS_mgf1(RSA *rsa,uchar *mHash,EVP_MD *Hash,EVP_MD *mgf1Hash,uchar *EM,int sLen);
int RSA_verify_PKCS1_PSS(RSA *rsa,uchar *mHash,EVP_MD *Hash,uchar *EM,int sLen);
int RSA_padding_add_PKCS1_PSS_mgf1(RSA *rsa,uchar *EM,uchar *mHash,EVP_MD *Hash,EVP_MD *mgf1Hash,int sLen);
int RSA_padding_add_PKCS1_PSS(RSA *rsa,uchar *EM,uchar *mHash,EVP_MD *Hash,int sLen);
int dsa_builtin_paramgen(DSA *ret,size_t bits,size_t qbits,EVP_MD *evpmd,uchar *seed_in,size_t seed_len,uchar *seed_out,int *counter_ret,ulong *h_ret,BN_GENCB *cb);
int DSA_generate_parameters_ex(DSA *ret,int bits,uchar *seed_in,int seed_len,int *counter_ret,ulong *h_ret,BN_GENCB *cb);
int dsa_builtin_paramgen2(DSA *ret,size_t L,size_t N,EVP_MD *evpmd,uchar *seed_in,size_t seed_len,int idx,uchar *seed_out,int *counter_ret,ulong *h_ret,BN_GENCB *cb);
int dsa_paramgen_check_g(DSA *dsa);
int DSA_generate_key(DSA *dsa);
ECDSA_SIG * d2i_ECDSA_SIG(ECDSA_SIG **a,uchar **in,long len);
int i2d_ECDSA_SIG(ECDSA_SIG *a,uchar **out);
ECDSA_SIG * ECDSA_SIG_new(void);
void ECDSA_SIG_free(ECDSA_SIG *a);
int DH_generate_parameters_ex(DH *ret,int prime_len,int generator,BN_GENCB *cb);
void ecdh_data_free(void *data);
void ECDH_set_default_method(ECDH_METHOD *meth);
ECDH_METHOD * ECDH_get_default_method(void);
ECDH_DATA * ECDH_DATA_new_method(ENGINE *engine);
void * ecdh_data_dup(void *data);
ECDH_DATA * ecdh_check(EC_KEY *key);
int ECDH_set_method(EC_KEY *eckey,ECDH_METHOD *meth);
int ECDH_get_ex_new_index(long argl,void *argp,CRYPTO_EX_new *new_func,CRYPTO_EX_dup *dup_func,CRYPTO_EX_free *free_func);
int ECDH_set_ex_data(EC_KEY *d,int idx,void *arg);
void * ECDH_get_ex_data(EC_KEY *d,int idx);
int ecdh_compute_key(void *out,size_t outlen,EC_POINT *pub_key,EC_KEY *ecdh,_func_void_ptr_void_ptr_size_t_void_ptr_size_t_ptr *KDF);
ECDH_METHOD * ECDH_OpenSSL(void);
void * dlfcn_globallookup(char *name);
char * dlfcn_merger(DSO *dso,char *filespec1,char *filespec2);
char * dlfcn_name_converter(DSO *dso,char *filename);
DSO_FUNC_TYPE dlfcn_bind_func(DSO *dso,char *symname);
void * dlfcn_bind_var(DSO *dso,char *symname);
int dlfcn_load(DSO *dso);
int dlfcn_pathbyaddr(void *addr,char *path,int sz);
int dlfcn_unload(DSO *dso);
DSO_METHOD * DSO_METHOD_dlfcn(void);
void engine_unregister_all_ECDH(void);
void ENGINE_unregister_ECDH(ENGINE *e);
int ENGINE_register_ECDH(ENGINE *e);
void ENGINE_register_all_ECDH(void);
int ENGINE_set_default_ECDH(ENGINE *e);
ENGINE * ENGINE_get_default_ECDH(void);
ECDH_METHOD * ENGINE_get_ECDH(ENGINE *e);
int ENGINE_set_ECDH(ENGINE *e,ECDH_METHOD *ecdh_meth);
int print_fp(char *str,size_t len,void *fp);
int print_bio(char *str,size_t len,void *bp);
void ERR_print_errors_cb(_func_int_char_ptr_size_t_void_ptr *cb,void *u);
void ERR_print_errors_fp(FILE *fp);
void ERR_print_errors(BIO *bp);
int UTF8_getc(uchar *str,int len,ulong *val);
int UTF8_putc(uchar *str,int len,ulong value);
int in_utf8(ulong value,void *arg);
int cpy_asc(ulong value,void *arg);
int cpy_bmp(ulong value,void *arg);
int cpy_univ(ulong value,void *arg);
int cpy_utf8(ulong value,void *arg);
int out_utf8(ulong value,void *arg);
int type_str(ulong value,void *arg);
int traverse_string(uchar *p,int len,int inform,_func_int_ulong_void_ptr *rfunc,void *arg);
int ASN1_mbstring_ncopy(ASN1_STRING **out,uchar *in,int len,int inform,ulong mask,long minsize,long maxsize);
int ASN1_mbstring_copy(ASN1_STRING **out,uchar *in,int len,int inform,ulong mask);
int ndef_prefix_free(BIO *b,uchar **pbuf,int *plen,void *parg);
int ndef_suffix(BIO *b,uchar **pbuf,int *plen,void *parg);
int ndef_prefix(BIO *b,uchar **pbuf,int *plen,void *parg);
int ndef_suffix_free(BIO *b,uchar **pbuf,int *plen,void *parg);
BIO * BIO_new_NDEF(BIO *out,ASN1_VALUE *val,ASN1_ITEM *it);
void mime_param_free(MIME_PARAM *param);
void mime_hdr_free(MIME_HEADER *hdr);
int mime_hdr_cmp(MIME_HEADER **a,MIME_HEADER **b);
int mime_param_cmp(MIME_PARAM **a,MIME_PARAM **b);
int multi_split(BIO *bio,char *bound,stack_st_BIO **ret);
char * strip_start(char *name);
char * strip_end(char *name);
MIME_HEADER * mime_hdr_new(char *name,char *value);
int mime_hdr_addparam(MIME_HEADER *mhdr,char *name,char *value);
stack_st_MIME_HEADER * mime_parse_hdr(BIO *bio);
ASN1_VALUE * b64_read_asn1(BIO *bio,ASN1_ITEM *it);
MIME_HEADER * mime_hdr_find(stack_st_MIME_HEADER *hdrs,char *name);
ASN1_VALUE * SMIME_read_ASN1(BIO *bio,BIO **bcont,ASN1_ITEM *it);
int SMIME_crlf_copy(BIO *in,BIO *out,int flags);
int i2d_ASN1_bio_stream(BIO *out,ASN1_VALUE *val,BIO *in,int flags,ASN1_ITEM *it);
int B64_write_ASN1(BIO *out,ASN1_VALUE *val,BIO *in,int flags,ASN1_ITEM *it);
int PEM_write_bio_ASN1_stream(BIO *out,ASN1_VALUE *val,BIO *in,int flags,char *hdr,ASN1_ITEM *it);
int SMIME_write_ASN1(BIO *bio,ASN1_VALUE *val,BIO *data,int flags,int ctype_nid,int econt_nid,stack_st_X509_ALGOR *mdalgs,ASN1_ITEM *it);
int SMIME_text(BIO *in,BIO *out);
ASN1_OBJECT ** cms_get0_econtent_type(CMS_ContentInfo *cms);
stack_st_CMS_CertificateChoices ** cms_get0_certificate_choices(CMS_ContentInfo *cms);
stack_st_CMS_RevocationInfoChoice ** cms_get0_revocation_choices(CMS_ContentInfo *cms);
CMS_ContentInfo * d2i_CMS_ContentInfo(CMS_ContentInfo **a,uchar **in,long len);
int i2d_CMS_ContentInfo(CMS_ContentInfo *a,uchar **out);
CMS_ContentInfo * CMS_ContentInfo_new(void);
void CMS_ContentInfo_free(CMS_ContentInfo *a);
int CMS_ContentInfo_print_ctx(BIO *out,CMS_ContentInfo *x,int indent,ASN1_PCTX *pctx);
ASN1_OBJECT * CMS_get0_type(CMS_ContentInfo *cms);
ASN1_OCTET_STRING ** CMS_get0_content(CMS_ContentInfo *cms);
BIO * cms_content_bio(CMS_ContentInfo *cms);
BIO * CMS_dataInit(CMS_ContentInfo *cms,BIO *icont);
int CMS_dataFinal(CMS_ContentInfo *cms,BIO *cmsbio);
ASN1_OBJECT * CMS_get0_eContentType(CMS_ContentInfo *cms);
int CMS_set1_eContentType(CMS_ContentInfo *cms,ASN1_OBJECT *oid);
int CMS_is_detached(CMS_ContentInfo *cms);
int CMS_set_detached(CMS_ContentInfo *cms,int detached);
CMS_ContentInfo * cms_Data_create(void);
void cms_DigestAlgorithm_set(X509_ALGOR *alg,EVP_MD *md);
BIO * cms_DigestAlgorithm_init_bio(X509_ALGOR *digestAlgorithm);
int cms_DigestAlgorithm_find_ctx(EVP_MD_CTX *mctx,BIO *chain,X509_ALGOR *mdalg);
CMS_CertificateChoices * CMS_add0_CertificateChoices(CMS_ContentInfo *cms);
int CMS_add0_cert(CMS_ContentInfo *cms,X509 *cert);
int CMS_add1_cert(CMS_ContentInfo *cms,X509 *cert);
CMS_RevocationInfoChoice * CMS_add0_RevocationInfoChoice(CMS_ContentInfo *cms);
int CMS_add0_crl(CMS_ContentInfo *cms,X509_CRL *crl);
int CMS_add1_crl(CMS_ContentInfo *cms,X509_CRL *crl);
stack_st_X509 * CMS_get1_certs(CMS_ContentInfo *cms);
stack_st_X509_CRL * CMS_get1_crls(CMS_ContentInfo *cms);
int cms_ias_cert_cmp(CMS_IssuerAndSerialNumber *ias,X509 *cert);
int cms_keyid_cert_cmp(ASN1_OCTET_STRING *keyid,X509 *cert);
int cms_set1_ias(CMS_IssuerAndSerialNumber **pias,X509 *cert);
int cms_set1_keyid(ASN1_OCTET_STRING **pkeyid,X509 *cert);
int CMS_signed_get_attr_count(CMS_SignerInfo *si);
int CMS_signed_get_attr_by_NID(CMS_SignerInfo *si,int nid,int lastpos);
int CMS_signed_get_attr_by_OBJ(CMS_SignerInfo *si,ASN1_OBJECT *obj,int lastpos);
X509_ATTRIBUTE * CMS_signed_get_attr(CMS_SignerInfo *si,int loc);
X509_ATTRIBUTE * CMS_signed_delete_attr(CMS_SignerInfo *si,int loc);
int CMS_signed_add1_attr(CMS_SignerInfo *si,X509_ATTRIBUTE *attr);
int CMS_signed_add1_attr_by_OBJ(CMS_SignerInfo *si,ASN1_OBJECT *obj,int type,void *bytes,int len);
int CMS_signed_add1_attr_by_NID(CMS_SignerInfo *si,int nid,int type,void *bytes,int len);
int CMS_signed_add1_attr_by_txt(CMS_SignerInfo *si,char *attrname,int type,void *bytes,int len);
void * CMS_signed_get0_data_by_OBJ(CMS_SignerInfo *si,ASN1_OBJECT *oid,int lastpos,int type);
int CMS_unsigned_get_attr_count(CMS_SignerInfo *si);
int CMS_unsigned_get_attr_by_NID(CMS_SignerInfo *si,int nid,int lastpos);
int CMS_unsigned_get_attr_by_OBJ(CMS_SignerInfo *si,ASN1_OBJECT *obj,int lastpos);
X509_ATTRIBUTE * CMS_unsigned_get_attr(CMS_SignerInfo *si,int loc);
X509_ATTRIBUTE * CMS_unsigned_delete_attr(CMS_SignerInfo *si,int loc);
int CMS_unsigned_add1_attr(CMS_SignerInfo *si,X509_ATTRIBUTE *attr);
int CMS_unsigned_add1_attr_by_OBJ(CMS_SignerInfo *si,ASN1_OBJECT *obj,int type,void *bytes,int len);
int CMS_unsigned_add1_attr_by_NID(CMS_SignerInfo *si,int nid,int type,void *bytes,int len);
int CMS_unsigned_add1_attr_by_txt(CMS_SignerInfo *si,char *attrname,int type,void *bytes,int len);
void * CMS_unsigned_get0_data_by_OBJ(CMS_SignerInfo *si,ASN1_OBJECT *oid,int lastpos,int type);
CMS_ContentInfo * cms_DigestedData_create(EVP_MD *md);
BIO * cms_DigestedData_init_bio(CMS_ContentInfo *cms);
int cms_DigestedData_do_final(CMS_ContentInfo *cms,BIO *chain,int verify);
void mul_1x1_ialu(void);
void bn_GF2m_mul_2x2(uint *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5);
int ec_GFp_simple_is_at_infinity(EC_GROUP *group,EC_POINT *point);
int ec_GFp_simple_group_init(EC_GROUP *group);
int ec_GFp_simple_point_init(EC_POINT *point);
void ec_GFp_simple_group_finish(EC_GROUP *group);
void ec_GFp_simple_point_finish(EC_POINT *point);
void ec_GFp_simple_group_clear_finish(EC_GROUP *group);
void ec_GFp_simple_point_clear_finish(EC_POINT *point);
int ec_GFp_simple_group_get_degree(EC_GROUP *group);
int ec_GFp_simple_group_get_curve(EC_GROUP *group,BIGNUM *p,BIGNUM *a,BIGNUM *b,BN_CTX *ctx);
int ec_GFp_simple_set_Jprojective_coordinates_GFp(EC_GROUP *group,EC_POINT *point,BIGNUM *x,BIGNUM *y,BIGNUM *z,BN_CTX *ctx);
int ec_GFp_simple_get_Jprojective_coordinates_GFp(EC_GROUP *group,EC_POINT *point,BIGNUM *x,BIGNUM *y,BIGNUM *z,BN_CTX *ctx);
int ec_GFp_simple_field_sqr(EC_GROUP *group,BIGNUM *r,BIGNUM *a,BN_CTX *ctx);
int ec_GFp_simple_field_mul(EC_GROUP *group,BIGNUM *r,BIGNUM *a,BIGNUM *b,BN_CTX *ctx);
int ec_GFp_simple_group_check_discriminant(EC_GROUP *group,BN_CTX *ctx);
int ec_GFp_simple_point_set_to_infinity(EC_GROUP *group,EC_POINT *point);
int ec_GFp_simple_point_get_affine_coordinates(EC_GROUP *group,EC_POINT *point,BIGNUM *x,BIGNUM *y,BN_CTX *ctx);
int ec_GFp_simple_dbl(EC_GROUP *group,EC_POINT *r,EC_POINT *a,BN_CTX *ctx);
int ec_GFp_simple_group_copy(EC_GROUP *dest,EC_GROUP *src);
int ec_GFp_simple_point_copy(EC_POINT *dest,EC_POINT *src);
int ec_GFp_simple_group_set_curve(EC_GROUP *group,BIGNUM *p,BIGNUM *a,BIGNUM *b,BN_CTX *ctx);
int ec_GFp_simple_point_set_affine_coordinates(EC_GROUP *group,EC_POINT *point,BIGNUM *x,BIGNUM *y,BN_CTX *ctx);
int ec_GFp_simple_cmp(EC_GROUP *group,EC_POINT *a,EC_POINT *b,BN_CTX *ctx);
int ec_GFp_simple_add(EC_GROUP *group,EC_POINT *r,EC_POINT *a,EC_POINT *b,BN_CTX *ctx);
int ec_GFp_simple_invert(EC_GROUP *group,EC_POINT *point,BN_CTX *ctx);
int ec_GFp_simple_is_on_curve(EC_GROUP *group,EC_POINT *point,BN_CTX *ctx);
int ec_GFp_simple_make_affine(EC_GROUP *group,EC_POINT *point,BN_CTX *ctx);
int ec_GFp_simple_points_make_affine(EC_GROUP *group,size_t num,EC_POINT **points,BN_CTX *ctx);
EC_METHOD * EC_GFp_simple_method(void);
long buffer_callback_ctrl(BIO *b,int cmd,bio_info_cb *fp);
int buffer_free(BIO *a);
int buffer_new(BIO *bi);
int buffer_write(BIO *b,char *in,int inl);
long buffer_ctrl(BIO *b,int cmd,long num,void *ptr);
int buffer_gets(BIO *b,char *buf,int size);
int buffer_read(BIO *b,char *out,int outl);
int buffer_puts(BIO *b,char *str);
BIO_METHOD * BIO_f_buffer(void);
long asn1_bio_callback_ctrl(BIO *b,int cmd,bio_info_cb *fp);
int asn1_bio_free(BIO *b);
int asn1_bio_setup_ex(BIO *b,BIO_ASN1_BUF_CTX *ctx,asn1_ps_func *setup,asn1_bio_state_t ex_state,asn1_bio_state_t other_state);
int asn1_bio_gets(BIO *b,char *str,int size);
int asn1_bio_read(BIO *b,char *in,int inl);
int asn1_bio_flush_ex(BIO *b,BIO_ASN1_BUF_CTX *ctx,asn1_ps_func *cleanup,asn1_bio_state_t next);
long asn1_bio_ctrl(BIO *b,int cmd,long arg1,void *arg2);
int asn1_bio_write(BIO *b,char *in,int inl);
int asn1_bio_write(BIO *b,char *in,int inl);
int asn1_bio_puts(BIO *b,char *str);
int asn1_bio_new(BIO *b);
BIO_METHOD * BIO_f_asn1(void);
int BIO_asn1_set_prefix(BIO *b,asn1_ps_func *prefix,asn1_ps_func *prefix_free);
int BIO_asn1_get_prefix(BIO *b,asn1_ps_func **pprefix,asn1_ps_func **pprefix_free);
int BIO_asn1_set_suffix(BIO *b,asn1_ps_func *suffix,asn1_ps_func *suffix_free);
int BIO_asn1_get_suffix(BIO *b,asn1_ps_func **psuffix,asn1_ps_func **psuffix_free);
uint __aeabi_uidiv(uint param_1,uint param_2);
void __aeabi_uidivmod(uint param_1,uint param_2);
uint __aeabi_idiv(uint param_1,uint param_2);
uint .divsi3_skip_div0_test(uint param_1,uint param_2);
void __aeabi_idivmod(uint param_1,uint param_2);
int __aeabi_ldivmod(int param_1,int param_2,int param_3,int param_4);
undefined4 __aeabi_uldivmod(undefined4 param_1,undefined4 param_2,int param_3,int param_4);
void __aeabi_ldiv0(void);
DItype __fixdfdi(DFtype a);
UDItype __fixunsdfdi(DFtype a);
UDItype __udivmoddi4(UDItype n,UDItype d,UDItype *rp);
void __libc_csu_init(int argc,char **argv,char **envp);
void __libc_csu_fini(void);
void _fini(void);
undefined __gmon_start__();
int usleep(__useconds_t __useconds);
ssize_t send(int __fd, void * __buf, size_t __n, int __flags);
int clock_gettime(clockid_t __clock_id, timespec * __tp);
int getpeername(int __fd, sockaddr * __addr, socklen_t * __len);
undefined xmlParseFile();
undefined __isoc99_sscanf();
undefined uncompress();
ssize_t recv(int __fd, void * __buf, size_t __n, int __flags);
char * strrchr(char * __s, int __c);
int vfprintf(FILE * __s, char * __format, __gnuc_va_list __arg);
time_t time(time_t * __timer);
int __fxstat(int __ver, int __fildes, stat * __stat_buf);
int printf(char * __format, ...);
int strncmp(char * __s1, char * __s2, size_t __n);
void exit(int __status);
void vsyslog(int __pri, char * __fmt, __gnuc_va_list __ap);
int pthread_mutex_lock(pthread_mutex_t * __mutex);
int setsockopt(int __fd, int __level, int __optname, void * __optval, socklen_t __optlen);
int puts(char * __s);
int pthread_setcanceltype(int __type, int * __oldtype);
int pthread_mutex_unlock(pthread_mutex_t * __mutex);
undefined xmlStrcmp();
tm * localtime(time_t * __timer);
long ftell(FILE * __stream);
int sprintf(char * __s, char * __format, ...);
undefined dladdr();
int getaddrinfo(char * __name, char * __service, addrinfo * __req, addrinfo * * __pai);
void perror(char * __s);
int strcasecmp(char * __s1, char * __s2);
FILE * fopen64(char * __filename, char * __modes);
undefined dlsym();
int strcmp(char * __s1, char * __s2);
uint32_t htonl(uint32_t __hostlong);
__uid_t getuid(void);
void * memmove(void * __dest, void * __src, size_t __n);
int poll(pollfd * __fds, nfds_t __nfds, int __timeout);
__int32_t * * __ctype_tolower_loc(void);
uint16_t htons(uint16_t __hostshort);
size_t strftime(char * __s, size_t __maxsize, char * __format, tm * __tp);
int system(char * __command);
int memcmp(void * __s1, void * __s2, size_t __n);
int ioctl(int __fd, ulong __request, ...);
undefined xmlKeepBlanksDefault();
int access(char * __name, int __type);
undefined xmlDocGetRootElement();
int pthread_create(pthread_t * __newthread, pthread_attr_t * __attr, __start_routine * __start_routine, void * __arg);
int fclose(FILE * __stream);
int gettimeofday(timeval * __tv, __timezone_ptr_t __tz);
int select(int __nfds, fd_set * __readfds, fd_set * __writefds, fd_set * __exceptfds, timeval * __timeout);
char * strerror(int __errnum);
char * strstr(char * __haystack, char * __needle);
int snprintf(char * __s, size_t __maxlen, char * __format, ...);
int sigdelset(sigset_t * __set, int __signo);
void siglongjmp(__jmp_buf_tag * __env, int __val);
int sigprocmask(int __how, sigset_t * __set, sigset_t * __oset);
undefined xmlXPathFreeObject();
undefined xmlXPathFreeContext();
int strncasecmp(char * __s1, char * __s2, size_t __n);
size_t fread(void * __ptr, size_t __size, size_t __n, FILE * __stream);
int sigfillset(sigset_t * __set);
size_t strlen(char * __s);
int gethostname(char * __name, size_t __len);
undefined dlclose();
void closelog(void);
undefined xmlGetProp();
char * strncpy(char * __dest, char * __src, size_t __n);
int fcntl(int __fd, int __cmd, ...);
undefined xmlXPathEvalExpression();
int connect(int __fd, sockaddr * __addr, socklen_t __len);
__pid_t getpid(void);
void * memset(void * __s, int __c, size_t __n);
void openlog(char * __ident, int __option, int __facility);
longlong atoll(char * __nptr);
undefined getauxval();
int fileno(FILE * __stream);
int listen(int __fd, int __n);
int ferror(FILE * __stream);
size_t fwrite(void * __ptr, size_t __size, size_t __n, FILE * __s);
int * __errno_location(void);
undefined xmlCleanupParser();
ssize_t sendto(int __fd, void * __buf, size_t __n, int __flags, sockaddr * __addr, socklen_t __addr_len);
int sigaction(int __sig, sigaction * __act, sigaction * __oact);
char * strchr(char * __s, int __c);
undefined __libc_start_main();
ulong strtoul(char * __nptr, char * * __endptr, int __base);
FILE * fopen(char * __filename, char * __modes);
int bind(int __fd, sockaddr * __addr, socklen_t __len);
char * inet_ntoa(in_addr __in);
char * strcpy(char * __dest, char * __src);
int fseek(FILE * __stream, long __off, int __whence);
void * calloc(size_t __nmemb, size_t __size);
void * memchr(void * __s, int __c, size_t __n);
int shutdown(int __fd, int __how);
int close(int __fd);
char * getenv(char * __name);
int atoi(char * __nptr);
undefined xmlMemoryDump();
void * memcpy(void * __dest, void * __src, size_t __n);
ushort * * __ctype_b_loc(void);
int socket(int __domain, int __type, int __protocol);
in_addr_t inet_addr(char * __cp);
ssize_t read(int __fd, void * __buf, size_t __nbytes);
undefined dlerror();
char * gai_strerror(int __ecode);
tm * gmtime_r(time_t * __timer, tm * __tp);
void __assert_fail(char * __assertion, char * __file, uint __line, char * __function);
pthread_t pthread_self(void);
char * strcat(char * __dest, char * __src);
uint16_t ntohs(uint16_t __netshort);
void freeaddrinfo(addrinfo * __ai);
ssize_t recvfrom(int __fd, void * __buf, size_t __n, int __flags, sockaddr * __addr, socklen_t * __addr_len);
int putchar(int __c);
void abort(void);
int feof(FILE * __stream);
int fflush(FILE * __stream);
int fputc(int __c, FILE * __stream);
undefined xmlXPathNewContext();
undefined xmlReadFile();
int vprintf(char * __format, __gnuc_va_list __arg);
int raise(int __sig);
int pthread_mutex_init(pthread_mutex_t * __mutex, pthread_mutexattr_t * __mutexattr);
char * fgets(char * __s, int __n, FILE * __stream);
long strtol(char * __nptr, char * * __endptr, int __base);
int fputs(char * __s, FILE * __stream);
int open(char * __file, int __oflag, ...);
double pow(double __x, double __y);
undefined xmlFreeDoc();
undefined __sigsetjmp();
undefined compress();
ssize_t write(int __fd, void * __buf, size_t __n);
int fprintf(FILE * __stream, char * __format, ...);
__sighandler_t signal(int __sig, __sighandler_t __handler);
int accept(int __fd, sockaddr * __addr, socklen_t * __addr_len);
int pthread_detach(pthread_t __th);
void bzero(void * __s, size_t __n);
undefined dlopen();
void qsort(void * __base, size_t __nmemb, size_t __size, __compar_fn_t __compar);
int vsnprintf(char * __s, size_t __maxlen, char * __format, __gnuc_va_list __arg);

