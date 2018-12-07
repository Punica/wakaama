/*******************************************************************************
 *
 * Copyright (c) 2013, 2014 Intel Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * The Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    David Navarro, Intel Corporation - initial API and implementation
 *    
 *******************************************************************************/

#ifndef CONNECTION_H_
#define CONNECTION_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <liblwm2m.h>
#include <mbedtls/config.h>
#include <mbedtls/ssl.h>

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"

#if !defined(_MSC_VER)
#include <inttypes.h>
#endif

#if !defined(_WIN32)
#include <signal.h>
#endif

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#if defined(MBEDTLS_SSL_TICKET_C)
#include "mbedtls/ssl_ticket.h"
#endif

#if defined(MBEDTLS_SSL_COOKIE_C)
#include "mbedtls/ssl_cookie.h"
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION) && defined(MBEDTLS_FS_IO)
#define SNI_OPTION
#endif

#define LWM2M_STANDARD_PORT_STR "5683"
#define LWM2M_STANDARD_PORT      5683
#define LWM2M_DTLS_PORT_STR     "5684"
#define LWM2M_DTLS_PORT          5684
#define LWM2M_BSSERVER_PORT_STR "5685"
#define LWM2M_BSSERVER_PORT      5685

#define mbedtls_free        free
#define mbedtls_time        time
#define mbedtls_time_t      time_t
#define mbedtls_calloc      calloc
#define mbedtls_fprintf     fprintf
#define mbedtls_printf      printf

#define ALPN_LIST_SIZE  10
#define CURVE_LIST_SIZE 20

#define MEMORY_HEAP_SIZE        120000

#define DFL_SERVER_ADDR         "localhost"
#define DFL_SERVER_PORT         "4433"
#define DFL_RESPONSE_SIZE       -1
#define DFL_DEBUG_LEVEL         0
#define DFL_NBIO                0
#define DFL_EVENT               0
#define DFL_READ_TIMEOUT        0
#define DFL_CA_FILE             ""
#define DFL_CA_PATH             ""
#define DFL_CRT_FILE            ""
#define DFL_KEY_FILE            ""
#define DFL_CRT_FILE2           ""
#define DFL_KEY_FILE2           ""
#define DFL_ASYNC_OPERATIONS    "-"
#define DFL_ASYNC_PRIVATE_DELAY1 ( -1 )
#define DFL_ASYNC_PRIVATE_DELAY2 ( -1 )
#define DFL_ASYNC_PRIVATE_ERROR  ( 0 )
#define DFL_PSK                 "ABC123"
#define DFL_PSK_IDENTITY        "Client_identity"
#define DFL_ECJPAKE_PW          NULL
#define DFL_PSK_LIST            NULL
#define DFL_FORCE_CIPHER        0
#define DFL_VERSION_SUITES      NULL
#define DFL_RENEGOTIATION       MBEDTLS_SSL_RENEGOTIATION_DISABLED
#define DFL_ALLOW_LEGACY        -2
#define DFL_RENEGOTIATE         0
#define DFL_RENEGO_DELAY        -2
#define DFL_RENEGO_PERIOD       ( (uint64_t)-1 )
#define DFL_EXCHANGES           1
#define DFL_MIN_VERSION         -1
#define DFL_MAX_VERSION         -1
#define DFL_ARC4                -1
#define DFL_SHA1                -1
#define DFL_AUTH_MODE           -1
#define DFL_CERT_REQ_CA_LIST    MBEDTLS_SSL_CERT_REQ_CA_LIST_ENABLED
#define DFL_MFL_CODE            MBEDTLS_SSL_MAX_FRAG_LEN_NONE
#define DFL_TRUNC_HMAC          -1
#define DFL_TICKETS             MBEDTLS_SSL_SESSION_TICKETS_ENABLED
#define DFL_TICKET_TIMEOUT      86400
#define DFL_CACHE_MAX           -1
#define DFL_CACHE_TIMEOUT       -1
#define DFL_SNI                 NULL
#define DFL_ALPN_STRING         NULL
#define DFL_CURVES              NULL
#define DFL_DHM_FILE            NULL
#define DFL_TRANSPORT           MBEDTLS_SSL_TRANSPORT_DATAGRAM
#define DFL_COOKIES             1
#define DFL_ANTI_REPLAY         -1
#define DFL_HS_TO_MIN           0
#define DFL_HS_TO_MAX           0
#define DFL_DTLS_MTU            -1
#define DFL_BADMAC_LIMIT        -1
#define DFL_DGRAM_PACKING        1
#define DFL_EXTENDED_MS         -1
#define DFL_ETM                 -1
#define DFL_IO_BUF_LEN          200

#define PUT_UINT64_BE(out_be,in_le,i)                                   \
{                                                                       \
    (out_be)[(i) + 0] = (unsigned char)( ( (in_le) >> 56 ) & 0xFF );    \
    (out_be)[(i) + 1] = (unsigned char)( ( (in_le) >> 48 ) & 0xFF );    \
    (out_be)[(i) + 2] = (unsigned char)( ( (in_le) >> 40 ) & 0xFF );    \
    (out_be)[(i) + 3] = (unsigned char)( ( (in_le) >> 32 ) & 0xFF );    \
    (out_be)[(i) + 4] = (unsigned char)( ( (in_le) >> 24 ) & 0xFF );    \
    (out_be)[(i) + 5] = (unsigned char)( ( (in_le) >> 16 ) & 0xFF );    \
    (out_be)[(i) + 6] = (unsigned char)( ( (in_le) >> 8  ) & 0xFF );    \
    (out_be)[(i) + 7] = (unsigned char)( ( (in_le) >> 0  ) & 0xFF );    \
}

struct options
{
    const char *server_addr;    /* address on which the ssl service runs    */
    const char *server_port;    /* port on which the ssl service runs       */
    int debug_level;            /* level of debugging                       */
    int nbio;                   /* should I/O be blocking?                  */
    int event;                  /* loop or event-driven IO? level or edge triggered? */
    uint32_t read_timeout;      /* timeout on mbedtls_ssl_read() in milliseconds    */
    int response_size;          /* pad response with header to requested size */
    uint16_t buffer_size;       /* IO buffer size */
    const char *ca_file;        /* the file with the CA certificate(s)      */
    const char *ca_path;        /* the path with the CA certificate(s) reside */
    const char *crt_file;       /* the file with the server certificate     */
    const char *key_file;       /* the file with the server key             */
    const char *crt_file2;      /* the file with the 2nd server certificate */
    const char *key_file2;      /* the file with the 2nd server key         */
    const char *async_operations; /* supported SSL asynchronous operations  */
    int async_private_delay1;   /* number of times f_async_resume needs to be called for key 1, or -1 for no async */
    int async_private_delay2;   /* number of times f_async_resume needs to be called for key 2, or -1 for no async */
    int async_private_error;    /* inject error in async private callback */
    const char *psk;            /* the pre-shared key                       */
    const char *psk_identity;   /* the pre-shared key identity              */
    char *psk_list;             /* list of PSK id/key pairs for callback    */
    const char *ecjpake_pw;     /* the EC J-PAKE password                   */
    int force_ciphersuite[2];   /* protocol/ciphersuite to use, or all      */
    const char *version_suites; /* per-version ciphersuites                 */
    int renegotiation;          /* enable / disable renegotiation           */
    int allow_legacy;           /* allow legacy renegotiation               */
    int renegotiate;            /* attempt renegotiation?                   */
    int renego_delay;           /* delay before enforcing renegotiation     */
    uint64_t renego_period;     /* period for automatic renegotiation       */
    int exchanges;              /* number of data exchanges                 */
    int min_version;            /* minimum protocol version accepted        */
    int max_version;            /* maximum protocol version accepted        */
    int arc4;                   /* flag for arc4 suites support             */
    int allow_sha1;             /* flag for SHA-1 support                   */
    int auth_mode;              /* verify mode for connection               */
    int cert_req_ca_list;       /* should we send the CA list?              */
    unsigned char mfl_code;     /* code for maximum fragment length         */
    int trunc_hmac;             /* accept truncated hmac?                   */
    int tickets;                /* enable / disable session tickets         */
    int ticket_timeout;         /* session ticket lifetime                  */
    int cache_max;              /* max number of session cache entries      */
    int cache_timeout;          /* expiration delay of session cache entries */
    char *sni;                  /* string describing sni information        */
    const char *curves;         /* list of supported elliptic curves        */
    const char *alpn_string;    /* ALPN supported protocols                 */
    const char *dhm_file;       /* the file with the DH parameters          */
    int extended_ms;            /* allow negotiation of extended MS?        */
    int etm;                    /* allow negotiation of encrypt-then-MAC?   */
    int transport;              /* TLS or DTLS?                             */
    int cookies;                /* Use cookies for DTLS? -1 to break them   */
    int anti_replay;            /* Use anti-replay for DTLS? -1 for default */
    uint32_t hs_to_min;         /* Initial value of DTLS handshake timer    */
    uint32_t hs_to_max;         /* Max value of DTLS handshake timer        */
    int dtls_mtu;               /* UDP Maximum tranport unit for DTLS       */
    int dgram_packing;          /* allow/forbid datagram packing            */
    int badmac_limit;           /* Limit of records with bad MAC            */
} opt;

#if defined(SNI_OPTION)
typedef struct _sni_entry sni_entry;

struct _sni_entry {
    const char *name;
    mbedtls_x509_crt *cert;
    mbedtls_pk_context *key;
    mbedtls_x509_crt* ca;
    mbedtls_x509_crl* crl;
    int authmode;
    sni_entry *next;
};
#endif /* SNI_OPTION */ 

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
#define HEX2NUM( c )                    \
        if( c >= '0' && c <= '9' )      \
            c -= '0';                   \
        else if( c >= 'a' && c <= 'f' ) \
            c -= 'a' - 10;              \
        else if( c >= 'A' && c <= 'F' ) \
            c -= 'A' - 10;              \
        else                            \
            return( -1 );

typedef struct _psk_entry psk_entry;

struct _psk_entry
{
    const char *name;
    size_t key_len;
    unsigned char key[MBEDTLS_PSK_MAX_LEN];
    psk_entry *next;
};
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

#if defined(MBEDTLS_X509_CRT_PARSE_C)
static int ssl_sig_hashes_for_test[] = {
#if defined(MBEDTLS_SHA512_C)
    MBEDTLS_MD_SHA512,
    MBEDTLS_MD_SHA384,
#endif
#if defined(MBEDTLS_SHA256_C)
    MBEDTLS_MD_SHA256,
    MBEDTLS_MD_SHA224,
#endif
#if defined(MBEDTLS_SHA1_C)
    /* Allow SHA-1 as we use it extensively in tests. */
    MBEDTLS_MD_SHA1,
#endif
    MBEDTLS_MD_NONE
};
#endif /* MBEDTLS_X509_CRT_PARSE_C */

void my_debug( void *ctx, int level, const char *file, int line, const char *str );
int my_recv( void *ctx, unsigned char *buf, size_t len );
int my_send( void *ctx, const unsigned char *buf, size_t len );
int get_auth_mode( const char *s );
void sni_free( sni_entry *head );
sni_entry *sni_parse( char *sni_string );
int sni_callback( void *p_info, mbedtls_ssl_context *ssl, const unsigned char *name, size_t name_len );
int unhexify( unsigned char *output, const char *input, size_t *olen );
void psk_free( psk_entry *head );
psk_entry *psk_parse( char *psk_string );
int psk_callback( void *p_info, mbedtls_ssl_context *ssl, const unsigned char *name, size_t name_len );
int mbedtls_status_is_ssl_in_progress( int ret );

typedef struct _connection_t
{
    struct _connection_t *  next;
    mbedtls_net_context *   sock;
    mbedtls_ssl_context *   ssl;
} connection_t;

int create_socket(const char * portStr, int ai_family);

int connection_receive(uint8_t* buffer, connection_t* con);
connection_t * connection_find(connection_t * connList, struct sockaddr_storage * addr, size_t addrLen);
connection_t * connection_new_incoming(void);
connection_t * connection_create(connection_t * connList, int sock, char * host, char * port, int addressFamily);
int connection_select(uint32_t rw, uint32_t timeout);

void connection_free(connection_t * connList);

#endif

