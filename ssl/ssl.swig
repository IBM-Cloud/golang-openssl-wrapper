/*
 * SWIG interface file for libssl
 */
%module ssl
%{
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>
#include <openssl/bio.h>
#include <openssl/tls1.h>
// #include <openssl/pem.h>
%}

/*
 * Conditional compilation directives for stuff we don't want to support yet
 */

#define OPENSSL_NO_KRB5

%import "openssl/lhash.h"
%import "openssl/safestack.h"
%import "openssl/stack.h"
#define STACK_OF(type) struct stack_st_##type
#define LHASH_OF(type) struct lhash_st_##type
#define DECLARE_STACK_OF(type) \
STACK_OF(type) \
    { \
    _STACK stack; \
    };
%import "openssl/pem.h"
// %import "openssl/ssl.h"

typedef struct ssl_ctx_st {
    const SSL_METHOD *method;
    STACK_OF(SSL_CIPHER) *cipher_list;
    /* same as above but sorted for lookup */
    STACK_OF(SSL_CIPHER) *cipher_list_by_id;
    struct x509_store_st /* X509_STORE */ *cert_store;
    LHASH_OF(SSL_SESSION) *sessions;
    /*
     * Most session-ids that will be cached, default is
     * SSL_SESSION_CACHE_MAX_SIZE_DEFAULT. 0 is unlimited.
     */
    unsigned long session_cache_size;
    struct ssl_session_st *session_cache_head;
    struct ssl_session_st *session_cache_tail;
    /*
     * This can have one of 2 values, ored together, SSL_SESS_CACHE_CLIENT,
     * SSL_SESS_CACHE_SERVER, Default is SSL_SESSION_CACHE_SERVER, which
     * means only SSL_accept which cache SSL_SESSIONS.
     */
    int session_cache_mode;
    /*
     * If timeout is not 0, it is the default timeout value set when
     * SSL_new() is called.  This has been put in to make life easier to set
     * things up
     */
    long session_timeout;
    /*
     * If this callback is not null, it will be called each time a session id
     * is added to the cache.  If this function returns 1, it means that the
     * callback will do a SSL_SESSION_free() when it has finished using it.
     * Otherwise, on 0, it means the callback has finished with it. If
     * remove_session_cb is not null, it will be called when a session-id is
     * removed from the cache.  After the call, OpenSSL will
     * SSL_SESSION_free() it.
     */
    int (*new_session_cb) (struct ssl_st *ssl, SSL_SESSION *sess);
    void (*remove_session_cb) (struct ssl_ctx_st *ctx, SSL_SESSION *sess);
    SSL_SESSION *(*get_session_cb) (struct ssl_st *ssl,
                                    unsigned char *data, int len, int *copy);
    struct {
        int sess_connect;       /* SSL new conn - started */
        int sess_connect_renegotiate; /* SSL reneg - requested */
        int sess_connect_good;  /* SSL new conne/reneg - finished */
        int sess_accept;        /* SSL new accept - started */
        int sess_accept_renegotiate; /* SSL reneg - requested */
        int sess_accept_good;   /* SSL accept/reneg - finished */
        int sess_miss;          /* session lookup misses */
        int sess_timeout;       /* reuse attempt on timeouted session */
        int sess_cache_full;    /* session removed due to full cache */
        int sess_hit;           /* session reuse actually done */
        int sess_cb_hit;        /* session-id that was not in the cache was
                                 * passed back via the callback.  This
                                 * indicates that the application is
                                 * supplying session-id's from other
                                 * processes - spooky :-) */
    } stats;

    int references;

    /* if defined, these override the X509_verify_cert() calls */
    int (*app_verify_callback) (X509_STORE_CTX *, void *);
    void *app_verify_arg;
    /*
     * before OpenSSL 0.9.7, 'app_verify_arg' was ignored
     * ('app_verify_callback' was called with just one argument)
     */

    /* Default password callback. */
    pem_password_cb *default_passwd_callback;

    /* Default password callback user data. */
    void *default_passwd_callback_userdata;

    /* get client cert callback */
    int (*client_cert_cb) (SSL *ssl, X509 **x509, EVP_PKEY **pkey);

    /* cookie generate callback */
    int (*app_gen_cookie_cb) (SSL *ssl, unsigned char *cookie,
                              unsigned int *cookie_len);

    /* verify cookie callback */
    int (*app_verify_cookie_cb) (SSL *ssl, unsigned char *cookie,
                                 unsigned int cookie_len);

    CRYPTO_EX_DATA ex_data;

    const EVP_MD *rsa_md5;      /* For SSLv2 - name is 'ssl2-md5' */
    const EVP_MD *md5;          /* For SSLv3/TLSv1 'ssl3-md5' */
    const EVP_MD *sha1;         /* For SSLv3/TLSv1 'ssl3->sha1' */

    STACK_OF(X509) *extra_certs;
    STACK_OF(SSL_COMP) *comp_methods; /* stack of SSL_COMP, SSLv3/TLSv1 */

    /* Default values used when no per-SSL value is defined follow */

    /* used if SSL's info_callback is NULL */
    void (*info_callback) (const SSL *ssl, int type, int val);

    /* what we put in client cert requests */
    STACK_OF(X509_NAME) *client_CA;

    /*
     * Default values to use in SSL structures follow (these are copied by
     * SSL_new)
     */

    unsigned long options;
    unsigned long mode;
    long max_cert_list;

    struct cert_st /* CERT */ *cert;
    int read_ahead;

    /* callback that allows applications to peek at protocol messages */
    void (*msg_callback) (int write_p, int version, int content_type,
                          const void *buf, size_t len, SSL *ssl, void *arg);
    void *msg_callback_arg;

    int verify_mode;
    unsigned int sid_ctx_length;
    unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];
    /* called 'verify_callback' in the SSL */
    int (*default_verify_callback) (int ok, X509_STORE_CTX *ctx);

    /* Default generate session ID callback. */
    GEN_SESSION_CB generate_session_id;

    X509_VERIFY_PARAM *param;

#  if 0
    int purpose;                /* Purpose setting */
    int trust;                  /* Trust setting */
#  endif

    int quiet_shutdown;

    /*
     * Maximum amount of data to send in one fragment. actual record size can
     * be more than this due to padding and MAC overheads.
     */
    unsigned int max_send_fragment;

#  ifndef OPENSSL_NO_ENGINE
    /*
     * Engine to pass requests for client certs to
     */
    ENGINE *client_cert_engine;
#  endif

#  ifndef OPENSSL_NO_TLSEXT
    /* TLS extensions servername callback */
    int (*tlsext_servername_callback) (SSL *, int *, void *);
    void *tlsext_servername_arg;
    /* RFC 4507 session ticket keys */
    unsigned char tlsext_tick_key_name[16];
    unsigned char tlsext_tick_hmac_key[16];
    unsigned char tlsext_tick_aes_key[16];
    /* Callback to support customisation of ticket key setting */
    int (*tlsext_ticket_key_cb) (SSL *ssl,
                                 unsigned char *name, unsigned char *iv,
                                 EVP_CIPHER_CTX *ectx,
                                 HMAC_CTX *hctx, int enc);

    /* certificate status request info */
    /* Callback for status request */
    int (*tlsext_status_cb) (SSL *ssl, void *arg);
    void *tlsext_status_arg;

    /* draft-rescorla-tls-opaque-prf-input-00.txt information */
    int (*tlsext_opaque_prf_input_callback) (SSL *, void *peerinput,
                                             size_t len, void *arg);
    void *tlsext_opaque_prf_input_callback_arg;
#  endif

#  ifndef OPENSSL_NO_PSK
    char *psk_identity_hint;
    unsigned int (*psk_client_callback) (SSL *ssl, const char *hint,
                                         char *identity,
                                         unsigned int max_identity_len,
                                         unsigned char *psk,
                                         unsigned int max_psk_len);
    unsigned int (*psk_server_callback) (SSL *ssl, const char *identity,
                                         unsigned char *psk,
                                         unsigned int max_psk_len);
#  endif

#  ifndef OPENSSL_NO_BUF_FREELISTS
#   define SSL_MAX_BUF_FREELIST_LEN_DEFAULT 32
    unsigned int freelist_max_len;
    struct ssl3_buf_freelist_st *wbuf_freelist;
    struct ssl3_buf_freelist_st *rbuf_freelist;
#  endif
#  ifndef OPENSSL_NO_SRP
    SRP_CTX srp_ctx;            /* ctx for SRP authentication */
#  endif

#  ifndef OPENSSL_NO_TLSEXT

#   ifndef OPENSSL_NO_NEXTPROTONEG
    /* Next protocol negotiation information */
    /* (for experimental NPN extension). */

    /*
     * For a server, this contains a callback function by which the set of
     * advertised protocols can be provided.
     */
    int (*next_protos_advertised_cb) (SSL *s, const unsigned char **buf,
                                      unsigned int *len, void *arg);
    void *next_protos_advertised_cb_arg;
    /*
     * For a client, this contains a callback function that selects the next
     * protocol from the list provided by the server.
     */
    int (*next_proto_select_cb) (SSL *s, unsigned char **out,
                                 unsigned char *outlen,
                                 const unsigned char *in,
                                 unsigned int inlen, void *arg);
    void *next_proto_select_cb_arg;
#   endif
    /* SRTP profiles we are willing to do from RFC 5764 */
    STACK_OF(SRTP_PROTECTION_PROFILE) *srtp_profiles;

    /*
     * ALPN information (we are in the process of transitioning from NPN to
     * ALPN.)
     */

    /*-
     * For a server, this contains a callback function that allows the
     * server to select the protocol for the connection.
     *   out: on successful return, this must point to the raw protocol
     *        name (without the length prefix).
     *   outlen: on successful return, this contains the length of |*out|.
     *   in: points to the client's list of supported protocols in
     *       wire-format.
     *   inlen: the length of |in|.
     */
    int (*alpn_select_cb) (SSL *s,
                           const unsigned char **out,
                           unsigned char *outlen,
                           const unsigned char *in,
                           unsigned int inlen, void *arg);
    void *alpn_select_cb_arg;

    /*
     * For a client, this contains the list of supported protocols in wire
     * format.
     */
    unsigned char *alpn_client_proto_list;
    unsigned alpn_client_proto_list_len;

#   ifndef OPENSSL_NO_EC
    /* EC extension values inherited by SSL structure */
    size_t tlsext_ecpointformatlist_length;
    unsigned char *tlsext_ecpointformatlist;
    size_t tlsext_ellipticcurvelist_length;
    unsigned char *tlsext_ellipticcurvelist;
#   endif                       /* OPENSSL_NO_EC */
#  endif
} SSL_CTX;

/*
 * SSL
 */
typedef struct ssl_st {
    /*
     * protocol version (one of SSL2_VERSION, SSL3_VERSION, TLS1_VERSION,
     * DTLS1_VERSION)
     */
    int version;
    /* SSL_ST_CONNECT or SSL_ST_ACCEPT */
    int type;
    /* SSLv3 */
    const SSL_METHOD *method;
    /*
     * There are 2 BIO's even though they are normally both the same.  This
     * is so data can be read and written to different handlers
     */
#  ifndef OPENSSL_NO_BIO
    /* used by SSL_read */
    BIO *rbio;
    /* used by SSL_write */
    BIO *wbio;
    /* used during session-id reuse to concatenate messages */
    BIO *bbio;
#  else
    /* used by SSL_read */
    char *rbio;
    /* used by SSL_write */
    char *wbio;
    char *bbio;
#  endif
    /*
     * This holds a variable that indicates what we were doing when a 0 or -1
     * is returned.  This is needed for non-blocking IO so we know what
     * request needs re-doing when in SSL_accept or SSL_connect
     */
    int rwstate;
    /* true when we are actually in SSL_accept() or SSL_connect() */
    int in_handshake;
    int (*handshake_func) (SSL *);
    /*
     * Imagine that here's a boolean member "init" that is switched as soon
     * as SSL_set_{accept/connect}_state is called for the first time, so
     * that "state" and "handshake_func" are properly initialized.  But as
     * handshake_func is == 0 until then, we use this test instead of an
     * "init" member.
     */
    /* are we the server side? - mostly used by SSL_clear */
    int server;
    /*
     * Generate a new session or reuse an old one.
     * NB: For servers, the 'new' session may actually be a previously
     * cached session or even the previous session unless
     * SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION is set
     */
    int new_session;
    /* don't send shutdown packets */
    int quiet_shutdown;
    /* we have shut things down, 0x01 sent, 0x02 for received */
    int shutdown;
    /* where we are */
    int state;
    /* where we are when reading */
    int rstate;
    BUF_MEM *init_buf;          /* buffer used during init */
    void *init_msg;             /* pointer to handshake message body, set by
                                 * ssl3_get_message() */
    int init_num;               /* amount read/written */
    int init_off;               /* amount read/written */
    /* used internally to point at a raw packet */
    unsigned char *packet;
    unsigned int packet_length;
    struct ssl2_state_st *s2;   /* SSLv2 variables */
    struct ssl3_state_st *s3;   /* SSLv3 variables */
    struct dtls1_state_st *d1;  /* DTLSv1 variables */
    int read_ahead;             /* Read as many input bytes as possible (for
                                 * non-blocking reads) */
    /* callback that allows applications to peek at protocol messages */
    void (*msg_callback) (int write_p, int version, int content_type,
                          const void *buf, size_t len, SSL *ssl, void *arg);
    void *msg_callback_arg;
    int hit;                    /* reusing a previous session */
    X509_VERIFY_PARAM *param;
#  if 0
    int purpose;                /* Purpose setting */
    int trust;                  /* Trust setting */
#  endif
    /* crypto */
    STACK_OF(SSL_CIPHER) *cipher_list;
    STACK_OF(SSL_CIPHER) *cipher_list_by_id;
    /*
     * These are the ones being used, the ones in SSL_SESSION are the ones to
     * be 'copied' into these ones
     */
    int mac_flags;
    EVP_CIPHER_CTX *enc_read_ctx; /* cryptographic state */
    EVP_MD_CTX *read_hash;      /* used for mac generation */
#  ifndef OPENSSL_NO_COMP
    COMP_CTX *expand;           /* uncompress */
#  else
    char *expand;
#  endif
    EVP_CIPHER_CTX *enc_write_ctx; /* cryptographic state */
    EVP_MD_CTX *write_hash;     /* used for mac generation */
#  ifndef OPENSSL_NO_COMP
    COMP_CTX *compress;         /* compression */
#  else
    char *compress;
#  endif
    /* session info */
    /* client cert? */
    /* This is used to hold the server certificate used */
    struct cert_st /* CERT */ *cert;
    /*
     * the session_id_context is used to ensure sessions are only reused in
     * the appropriate context
     */
    unsigned int sid_ctx_length;
    unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];
    /* This can also be in the session once a session is established */
    SSL_SESSION *session;
    /* Default generate session ID callback. */
    GEN_SESSION_CB generate_session_id;
    /* Used in SSL2 and SSL3 */
    /*
     * 0 don't care about verify failure.
     * 1 fail if verify fails
     */
    int verify_mode;
    /* fail if callback returns 0 */
    int (*verify_callback) (int ok, X509_STORE_CTX *ctx);
    /* optional informational callback */
    void (*info_callback) (const SSL *ssl, int type, int val);
    /* error bytes to be written */
    int error;
    /* actual code */
    int error_code;
#  ifndef OPENSSL_NO_KRB5
    /* Kerberos 5 context */
    KSSL_CTX *kssl_ctx;
#  endif                        /* OPENSSL_NO_KRB5 */
#  ifndef OPENSSL_NO_PSK
    unsigned int (*psk_client_callback) (SSL *ssl, const char *hint,
                                         char *identity,
                                         unsigned int max_identity_len,
                                         unsigned char *psk,
                                         unsigned int max_psk_len);
    unsigned int (*psk_server_callback) (SSL *ssl, const char *identity,
                                         unsigned char *psk,
                                         unsigned int max_psk_len);
#  endif
    SSL_CTX *ctx;
    /*
     * set this flag to 1 and a sleep(1) is put into all SSL_read() and
     * SSL_write() calls, good for nbio debuging :-)
     */
    int debug;
    /* extra application data */
    long verify_result;
    CRYPTO_EX_DATA ex_data;
    /* for server side, keep the list of CA_dn we can use */
    STACK_OF(X509_NAME) *client_CA;
    int references;
    /* protocol behaviour */
    unsigned long options;
    /* API behaviour */
    unsigned long mode;
    long max_cert_list;
    int first_packet;
    /* what was passed, used for SSLv3/TLS rollback check */
    int client_version;
    unsigned int max_send_fragment;
#  ifndef OPENSSL_NO_TLSEXT
    /* TLS extension debug callback */
    void (*tlsext_debug_cb) (SSL *s, int client_server, int type,
                             unsigned char *data, int len, void *arg);
    void *tlsext_debug_arg;
    char *tlsext_hostname;
    /*-
     * no further mod of servername
     * 0 : call the servername extension callback.
     * 1 : prepare 2, allow last ack just after in server callback.
     * 2 : don't call servername callback, no ack in server hello
     */
    int servername_done;
    /* certificate status request info */
    /* Status type or -1 if no status type */
    int tlsext_status_type;
    /* Expect OCSP CertificateStatus message */
    int tlsext_status_expected;
    /* OCSP status request only */
    STACK_OF(OCSP_RESPID) *tlsext_ocsp_ids;
    X509_EXTENSIONS *tlsext_ocsp_exts;
    /* OCSP response received or to be sent */
    unsigned char *tlsext_ocsp_resp;
    int tlsext_ocsp_resplen;
    /* RFC4507 session ticket expected to be received or sent */
    int tlsext_ticket_expected;
#   ifndef OPENSSL_NO_EC
    size_t tlsext_ecpointformatlist_length;
    /* our list */
    unsigned char *tlsext_ecpointformatlist;
    size_t tlsext_ellipticcurvelist_length;
    /* our list */
    unsigned char *tlsext_ellipticcurvelist;
#   endif                       /* OPENSSL_NO_EC */
    /*
     * draft-rescorla-tls-opaque-prf-input-00.txt information to be used for
     * handshakes
     */
    void *tlsext_opaque_prf_input;
    size_t tlsext_opaque_prf_input_len;
    /* TLS Session Ticket extension override */
    TLS_SESSION_TICKET_EXT *tlsext_session_ticket;
    /* TLS Session Ticket extension callback */
    tls_session_ticket_ext_cb_fn tls_session_ticket_ext_cb;
    void *tls_session_ticket_ext_cb_arg;
    /* TLS pre-shared secret session resumption */
    tls_session_secret_cb_fn tls_session_secret_cb;
    void *tls_session_secret_cb_arg;
    SSL_CTX *initial_ctx;       /* initial ctx, used to store sessions */
#   ifndef OPENSSL_NO_NEXTPROTONEG
    /*
     * Next protocol negotiation. For the client, this is the protocol that
     * we sent in NextProtocol and is set when handling ServerHello
     * extensions. For a server, this is the client's selected_protocol from
     * NextProtocol and is set when handling the NextProtocol message, before
     * the Finished message.
     */
    unsigned char *next_proto_negotiated;
    unsigned char next_proto_negotiated_len;
#   endif
#   define session_ctx initial_ctx
    /* What we'll do */
    STACK_OF(SRTP_PROTECTION_PROFILE) *srtp_profiles;
    /* What's been chosen */
    SRTP_PROTECTION_PROFILE *srtp_profile;
        /*-
         * Is use of the Heartbeat extension negotiated?
         * 0: disabled
         * 1: enabled
         * 2: enabled, but not allowed to send Requests
         */
    unsigned int tlsext_heartbeat;
    /* Indicates if a HeartbeatRequest is in flight */
    unsigned int tlsext_hb_pending;
    /* HeartbeatRequest sequence number */
    unsigned int tlsext_hb_seq;
#  else
#   define session_ctx ctx
#  endif                        /* OPENSSL_NO_TLSEXT */
    /*-
     * 1 if we are renegotiating.
     * 2 if we are a server and are inside a handshake
     * (i.e. not just sending a HelloRequest)
     */
    int renegotiate;
#  ifndef OPENSSL_NO_SRP
    /* ctx for SRP authentication */
    SRP_CTX srp_ctx;
#  endif
#  ifndef OPENSSL_NO_TLSEXT
    /*
     * For a client, this contains the list of supported protocols in wire
     * format.
     */
    unsigned char *alpn_client_proto_list;
    unsigned alpn_client_proto_list_len;
#  endif                        /* OPENSSL_NO_TLSEXT */
} SSL;

// typedef struct kssl_ctx_st {
//     /*      used by:    disposition:            */
//     char *service_name;         /* C,S default ok (kssl) */
//     char *service_host;         /* C input, REQUIRED */
//     char *client_princ;         /* S output from krb5 ticket */
//     char *keytab_file;          /* S NULL (/etc/krb5.keytab) */
//     char *cred_cache;           /* C NULL (default) */
//     krb5_enctype enctype;
//     int length;
//     krb5_octet FAR *key;
// } KSSL_CTX;

void SSL_load_error_strings(void);
int SSL_library_init(void);

SSL_CTX *SSL_CTX_new(const SSL_METHOD *method);
void SSL_CTX_free(SSL_CTX *ctx);

const SSL_METHOD *SSLv3_method(void); /* SSLv3 */
const SSL_METHOD *SSLv3_server_method(void); /* SSLv3 */
const SSL_METHOD *SSLv3_client_method(void); /* SSLv3 */

const SSL_METHOD *SSLv23_method(void); /* SSLv3 */
const SSL_METHOD *SSLv23_server_method(void); /* SSLv3 */
const SSL_METHOD *SSLv23_client_method(void); /* SSLv3 */

// The at https://www.openssl.org/docs/manmaster/ssl/SSL_CTX_new.html say
// that the SSLv23_*method functions are deprecated, use TLS* instead, but
// TLS* is not present in the most recent ssl.h nor in libssl itself.  be
// wary of OpenSSL docs...
// const SSL_METHOD *TLS_method(void);
// const SSL_METHOD *TLS_server_method(void);
// const SSL_METHOD *TLS_client_method(void);

/* Constants for the mode argument to SSL_CTX_set_verify */
#define SSL_VERIFY_NONE                 0x00
#define SSL_VERIFY_PEER                 0x01
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT 0x02
#define SSL_VERIFY_CLIENT_ONCE          0x04

void SSL_CTX_set_verify(SSL_CTX *ctx, int mode,
                        int (*callback) (int, X509_STORE_CTX *));
void SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth);

long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg);

// long SSL_CTX_set_options(SSL_CTX *ctx, long op);


// #define SSL_OP_NO_SSLv2                                 0x01000000L
// #define SSL_OP_NO_SSLv3                                 0x02000000L
// #define SSL_OP_NO_COMPRESSION                           0x00020000L

int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
                                    const char *CApath);

SSL *SSL_new(SSL_CTX *ctx);
void SSL_free(SSL *ssl);
int SSL_set_cipher_list(SSL *ssl, const char *str);
long SSL_set_tlsext_host_name(SSL *ssl, char *name);
int SSL_connect(SSL *ssl);
int SSL_get_error(SSL *ssl, int ret);


