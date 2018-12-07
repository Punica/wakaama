// TODO add license

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "mbedtlsconnection.h"
#include <liblwm2m.h>

static connection_t* connectionList = NULL;

mbedtls_net_context listen_fd;
unsigned char* buf = 0;
int version_suites[4][2];
unsigned char psk[MBEDTLS_PSK_MAX_LEN];
size_t psk_len = 0;
psk_entry *psk_info = NULL;
const char *pers = "ssl_server2";
unsigned char client_ip[16] = { 0 };
size_t cliip_len;
#if defined(MBEDTLS_SSL_COOKIE_C)
mbedtls_ssl_cookie_ctx cookie_ctx;
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
mbedtls_x509_crt_profile crt_profile_for_test;
#endif
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ssl_config conf;
#if defined(MBEDTLS_TIMING_C)
mbedtls_timing_delay_context timer;
#endif
#if defined(MBEDTLS_SSL_RENEGOTIATION)
unsigned char renego_period[8] = { 0 };
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C)
uint32_t flags;
mbedtls_x509_crt cacert;
mbedtls_x509_crt srvcert;
mbedtls_pk_context pkey;
mbedtls_x509_crt srvcert2;
mbedtls_pk_context pkey2;
int key_cert_init = 0, key_cert_init2 = 0;
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_FS_IO)
mbedtls_dhm_context dhm;
#endif
#if defined(MBEDTLS_SSL_CACHE_C)
mbedtls_ssl_cache_context cache;
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
mbedtls_ssl_ticket_context ticket_ctx;
#endif
#if defined(SNI_OPTION)
sni_entry *sni_info = NULL;
#endif
#if defined(MBEDTLS_ECP_C)
mbedtls_ecp_group_id curve_list[CURVE_LIST_SIZE];
const mbedtls_ecp_curve_info * curve_cur;
#endif
#if defined(MBEDTLS_SSL_ALPN)
const char *alpn_list[ALPN_LIST_SIZE];
#endif
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
unsigned char alloc_buf[MEMORY_HEAP_SIZE];
#endif

static int prv_init_mbedtls(const char * portStr, int addressFamily)
{
    (void)addressFamily;

    crt_profile_for_test = mbedtls_x509_crt_profile_default;
    int ret = 0, len, written, frags, exchanges_left;

    int i;
    char *p, *q;
    const int *list;

    mbedtls_net_init( &listen_fd );
    mbedtls_ssl_config_init( &conf );
    mbedtls_ctr_drbg_init( &ctr_drbg );
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_x509_crt_init( &cacert );
    mbedtls_x509_crt_init( &srvcert );
    mbedtls_pk_init( &pkey );
    mbedtls_x509_crt_init( &srvcert2 );
    mbedtls_pk_init( &pkey2 );
#endif
#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_FS_IO)
    mbedtls_dhm_init( &dhm );
#endif
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init( &cache );
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    mbedtls_ssl_ticket_init( &ticket_ctx );
#endif
#if defined(MBEDTLS_SSL_ALPN)
    memset( (void *) alpn_list, 0, sizeof( alpn_list ) );
#endif
#if defined(MBEDTLS_SSL_COOKIE_C)
    mbedtls_ssl_cookie_init( &cookie_ctx );
#endif

    opt.buffer_size         = DFL_IO_BUF_LEN;
    opt.server_addr         = DFL_SERVER_ADDR;
    opt.server_port         = portStr;
    opt.debug_level         = DFL_DEBUG_LEVEL;
    opt.event               = DFL_EVENT;
    opt.response_size       = DFL_RESPONSE_SIZE;
    opt.nbio                = DFL_NBIO;
    opt.read_timeout        = DFL_READ_TIMEOUT;
    opt.ca_file             = DFL_CA_FILE;
    opt.ca_path             = DFL_CA_PATH;
    opt.crt_file            = DFL_CRT_FILE;
    opt.key_file            = DFL_KEY_FILE;
    opt.crt_file2           = DFL_CRT_FILE2;
    opt.key_file2           = DFL_KEY_FILE2;
    opt.async_operations    = DFL_ASYNC_OPERATIONS;
    opt.async_private_delay1 = DFL_ASYNC_PRIVATE_DELAY1;
    opt.async_private_delay2 = DFL_ASYNC_PRIVATE_DELAY2;
    opt.async_private_error = DFL_ASYNC_PRIVATE_ERROR;
    opt.psk                 = DFL_PSK;
    opt.psk_identity        = DFL_PSK_IDENTITY;
    opt.psk_list            = DFL_PSK_LIST;
    opt.ecjpake_pw          = DFL_ECJPAKE_PW;
    opt.force_ciphersuite[0]= DFL_FORCE_CIPHER;
    opt.version_suites      = DFL_VERSION_SUITES;
    opt.renegotiation       = DFL_RENEGOTIATION;
    opt.allow_legacy        = DFL_ALLOW_LEGACY;
    opt.renegotiate         = DFL_RENEGOTIATE;
    opt.renego_delay        = DFL_RENEGO_DELAY;
    opt.renego_period       = DFL_RENEGO_PERIOD;
    opt.exchanges           = DFL_EXCHANGES;
    opt.min_version         = DFL_MIN_VERSION;
    opt.max_version         = DFL_MAX_VERSION;
    opt.arc4                = DFL_ARC4;
    opt.allow_sha1          = DFL_SHA1;
    opt.auth_mode           = DFL_AUTH_MODE;
    opt.cert_req_ca_list    = DFL_CERT_REQ_CA_LIST;
    opt.mfl_code            = DFL_MFL_CODE;
    opt.trunc_hmac          = DFL_TRUNC_HMAC;
    opt.tickets             = DFL_TICKETS;
    opt.ticket_timeout      = DFL_TICKET_TIMEOUT;
    opt.cache_max           = DFL_CACHE_MAX;
    opt.cache_timeout       = DFL_CACHE_TIMEOUT;
    opt.sni                 = DFL_SNI;
    opt.alpn_string         = DFL_ALPN_STRING;
    opt.curves              = DFL_CURVES;
    opt.dhm_file            = DFL_DHM_FILE;
    opt.transport           = DFL_TRANSPORT;
    opt.cookies             = DFL_COOKIES;
    opt.anti_replay         = DFL_ANTI_REPLAY;
    opt.hs_to_min           = DFL_HS_TO_MIN;
    opt.hs_to_max           = DFL_HS_TO_MAX;
    opt.dtls_mtu            = DFL_DTLS_MTU;
    opt.dgram_packing       = DFL_DGRAM_PACKING;
    opt.badmac_limit        = DFL_BADMAC_LIMIT;
    opt.extended_ms         = DFL_EXTENDED_MS;
    opt.etm                 = DFL_ETM;

    if( opt.event == 1 && opt.nbio != 1 )
    {
        fprintf(stderr, "Warning: event-driven IO mandates nbio=1 - overwrite\n" );
        opt.nbio = 1;
    }

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold( opt.debug_level );
#endif
    buf = mbedtls_calloc( 1, opt.buffer_size + 1 );
    if( buf == NULL )
    {
        return -1;
    }

    if( unhexify( psk, opt.psk, &psk_len ) != 0 )
    {
        return -1;
    }

    if( opt.psk_list != NULL )
    {
        if( ( psk_info = psk_parse( opt.psk_list ) ) == NULL )
        {
            return -1;
        }
    }

#if defined(MBEDTLS_ECP_C)
    if( opt.curves != NULL )
    {
        p = (char *) opt.curves;
        i = 0;

        if( strcmp( p, "none" ) == 0 )
        {
            curve_list[0] = MBEDTLS_ECP_DP_NONE;
        }
        else if( strcmp( p, "default" ) != 0 )
        {
            /* Leave room for a final NULL in curve list */
            while( i < CURVE_LIST_SIZE - 1 && *p != '\0' )
            {
                q = p;

                /* Terminate the current string */
                while( *p != ',' && *p != '\0' )
                    p++;
                if( *p == ',' )
                    *p++ = '\0';

                if( ( curve_cur = mbedtls_ecp_curve_info_from_name( q ) ) != NULL )
                {
                    curve_list[i++] = curve_cur->grp_id;
                }
                else
                {
                    fprintf(stderr, "unknown curve %s\n", q );
                    fprintf(stderr, "supported curves: " );
                    for( curve_cur = mbedtls_ecp_curve_list();
                         curve_cur->grp_id != MBEDTLS_ECP_DP_NONE;
                         curve_cur++ )
                    {
                        fprintf(stderr, "%s ", curve_cur->name );
                    }
                    fprintf(stderr, "\n" );
                    return -1;
                }
            }

            if( i == CURVE_LIST_SIZE - 1 && *p != '\0' )
            {
                fprintf(stderr, "curves list too long, maximum %d", CURVE_LIST_SIZE - 1);
                return -1;
            }

            curve_list[i] = MBEDTLS_ECP_DP_NONE;
        }
    }
#endif /* MBEDTLS_ECP_C */

#if defined(MBEDTLS_SSL_ALPN)
    if( opt.alpn_string != NULL )
    {
        p = (char *) opt.alpn_string;
        i = 0;

        /* Leave room for a final NULL in alpn_list */
        while( i < ALPN_LIST_SIZE - 1 && *p != '\0' )
        {
            alpn_list[i++] = p;

            /* Terminate the current string and move on to next one */
            while( *p != ',' && *p != '\0' )
                p++;
            if( *p == ',' )
                *p++ = '\0';
        }
    }
#endif /* MBEDTLS_SSL_ALPN */

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                       &entropy, (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )
    {
        return -1;
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if defined(MBEDTLS_FS_IO)
    if( strlen( opt.ca_path ) )
        if( strcmp( opt.ca_path, "none" ) == 0 )
            ret = 0;
        else
            ret = mbedtls_x509_crt_parse_path( &cacert, opt.ca_path );
    else if( strlen( opt.ca_file ) )
        if( strcmp( opt.ca_file, "none" ) == 0 )
            ret = 0;
        else
            ret = mbedtls_x509_crt_parse_file( &cacert, opt.ca_file );
    else
#endif
#if defined(MBEDTLS_CERTS_C)
        for( i = 0; mbedtls_test_cas[i] != NULL; i++ )
        {
            ret = mbedtls_x509_crt_parse( &cacert,
                                  (const unsigned char *) mbedtls_test_cas[i],
                                  mbedtls_test_cas_len[i] );
            if( ret != 0 )
                break;
        }
#endif
    if( ret < 0 )
    {
        return -1;
    }

#if defined(MBEDTLS_FS_IO)
    if( strlen( opt.crt_file ) && strcmp( opt.crt_file, "none" ) != 0 )
    {
        key_cert_init++;
        if( ( ret = mbedtls_x509_crt_parse_file( &srvcert, opt.crt_file ) ) != 0 )
        {
            fprintf(stderr, "mbedtls_x509_crt_parse_file returned -0x%x\n\n", -ret);
            return -1;
        }
    }
    if( strlen( opt.key_file ) && strcmp( opt.key_file, "none" ) != 0 )
    {
        key_cert_init++;
        if( ( ret = mbedtls_pk_parse_keyfile( &pkey, opt.key_file, "" ) ) != 0 )
        {
            fprintf(stderr, "mbedtls_pk_parse_keyfile returned -0x%x\n\n", -ret );
            return -1;
        }
    }
    if( key_cert_init == 1 )
    {
        fprintf(stderr, "crt_file without key_file or vice-versa\n\n" );
        return -1;
    }

    if( strlen( opt.crt_file2 ) && strcmp( opt.crt_file2, "none" ) != 0 )
    {
        key_cert_init2++;
        if( ( ret = mbedtls_x509_crt_parse_file( &srvcert2, opt.crt_file2 ) ) != 0 )
        {
            fprintf(stderr, "mbedtls_x509_crt_parse_file(2) returned -0x%x\n\n",
                    -ret );
            return -1;
        }
    }
    if( strlen( opt.key_file2 ) && strcmp( opt.key_file2, "none" ) != 0 )
    {
        key_cert_init2++;
        if( ( ret = mbedtls_pk_parse_keyfile( &pkey2, opt.key_file2, "" ) ) != 0 )
        {
            fprintf(stderr, "mbedtls_pk_parse_keyfile(2) returned -0x%x\n\n",
                            -ret );
            return -1;
        }
    }
    if( key_cert_init2 == 1 )
    {
        fprintf(stderr, "crt_file2 without key_file2 or vice-versa\n\n" );
        return -1;
    }
#endif
    if( key_cert_init == 0 &&
        strcmp( opt.crt_file, "none" ) != 0 &&
        strcmp( opt.key_file, "none" ) != 0 &&
        key_cert_init2 == 0 &&
        strcmp( opt.crt_file2, "none" ) != 0 &&
        strcmp( opt.key_file2, "none" ) != 0 )
    {
#if defined(MBEDTLS_RSA_C)
        if( ( ret = mbedtls_x509_crt_parse( &srvcert,
                                    (const unsigned char *) mbedtls_test_srv_crt_rsa,
                                    mbedtls_test_srv_crt_rsa_len ) ) != 0 )
        {
            fprintf(stderr, "mbedtls_x509_crt_parse returned -0x%x\n\n",
                            -ret );
            return -1;
        }
        if( ( ret = mbedtls_pk_parse_key( &pkey,
                                  (const unsigned char *) mbedtls_test_srv_key_rsa,
                                  mbedtls_test_srv_key_rsa_len, NULL, 0 ) ) != 0 )
        {
            fprintf(stderr, "mbedtls_pk_parse_key returned -0x%x\n\n",
                            -ret );
            return -1;
        }
        key_cert_init = 2;
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECDSA_C)
        if( ( ret = mbedtls_x509_crt_parse( &srvcert2,
                                    (const unsigned char *) mbedtls_test_srv_crt_ec,
                                    mbedtls_test_srv_crt_ec_len ) ) != 0 )
        {
            fprintf(stderr, "x509_crt_parse2 returned -0x%x\n\n",
                            -ret );
            return -1;
        }
        if( ( ret = mbedtls_pk_parse_key( &pkey2,
                                  (const unsigned char *) mbedtls_test_srv_key_ec,
                                  mbedtls_test_srv_key_ec_len, NULL, 0 ) ) != 0 )
        {
            fprintf(stderr, "pk_parse_key2 returned -0x%x\n\n",
                            -ret );
            return -1;
        }
        key_cert_init2 = 2;
#endif /* MBEDTLS_ECDSA_C */
    }
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_FS_IO)
    if( opt.dhm_file != NULL )
    {
        if( ( ret = mbedtls_dhm_parse_dhmfile( &dhm, opt.dhm_file ) ) != 0 )
        {
            fprintf(stderr, "mbedtls_dhm_parse_dhmfile returned -0x%04X\n\n",
                     -ret );
            return -1;
        }

    }
#endif

#if defined(SNI_OPTION)
    if( opt.sni != NULL )
    {
        if( ( sni_info = sni_parse( opt.sni ) ) == NULL )
        {
            return -1;
        }

        mbedtls_printf( " ok\n" );
    }
#endif /* SNI_OPTION */

    printf("Bind on udp://%s:%s/\r\n", opt.server_addr, opt.server_port);

    if( ( ret = mbedtls_net_bind( &listen_fd, opt.server_addr, opt.server_port, MBEDTLS_NET_PROTO_UDP ) ) != 0 )
    {
        fprintf(stderr, "mbedtls_net_bind returned -0x%x\n\n", -ret );
        return -1;
    }

    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_SERVER,
                    opt.transport,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        fprintf(stderr, "mbedtls_ssl_config_defaults returned -0x%x\n\n", -ret );
        return -1;
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    /* The default algorithms profile disables SHA-1, but our tests still
       rely on it heavily. Hence we allow it here. A real-world server
       should use the default profile unless there is a good reason not to. */
    if( opt.allow_sha1 > 0 )
    {
        crt_profile_for_test.allowed_mds |= MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA1 );
        mbedtls_ssl_conf_cert_profile( &conf, &crt_profile_for_test );
        mbedtls_ssl_conf_sig_hashes( &conf, ssl_sig_hashes_for_test );
    }
#endif /* MBEDTLS_X509_CRT_PARSE_C */

    if( opt.auth_mode != DFL_AUTH_MODE )
        mbedtls_ssl_conf_authmode( &conf, opt.auth_mode );

    if( opt.cert_req_ca_list != DFL_CERT_REQ_CA_LIST )
        mbedtls_ssl_conf_cert_req_ca_list( &conf, opt.cert_req_ca_list );

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( opt.hs_to_min != DFL_HS_TO_MIN || opt.hs_to_max != DFL_HS_TO_MAX )
        mbedtls_ssl_conf_handshake_timeout( &conf, opt.hs_to_min, opt.hs_to_max );
#endif /* MBEDTLS_SSL_PROTO_DTLS */

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    if( ( ret = mbedtls_ssl_conf_max_frag_len( &conf, opt.mfl_code ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_conf_max_frag_len returned %d\n\n", ret );
        return -1;
    };
#endif

#if defined(MBEDTLS_SSL_TRUNCATED_HMAC)
    if( opt.trunc_hmac != DFL_TRUNC_HMAC )
        mbedtls_ssl_conf_truncated_hmac( &conf, opt.trunc_hmac );
#endif

#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
    if( opt.extended_ms != DFL_EXTENDED_MS )
        mbedtls_ssl_conf_extended_master_secret( &conf, opt.extended_ms );
#endif

#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    if( opt.etm != DFL_ETM )
        mbedtls_ssl_conf_encrypt_then_mac( &conf, opt.etm );
#endif

#if defined(MBEDTLS_SSL_ALPN)
    if( opt.alpn_string != NULL )
        if( ( ret = mbedtls_ssl_conf_alpn_protocols( &conf, alpn_list ) ) != 0 )
        {
            fprintf(stderr, "mbedtls_ssl_conf_alpn_protocols returned %d\n\n", ret );
            return -1;
        }
#endif

    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );

#if defined(MBEDTLS_SSL_CACHE_C)
    if( opt.cache_max != -1 )
        mbedtls_ssl_cache_set_max_entries( &cache, opt.cache_max );

    if( opt.cache_timeout != -1 )
        mbedtls_ssl_cache_set_timeout( &cache, opt.cache_timeout );

    mbedtls_ssl_conf_session_cache( &conf, &cache,
                                   mbedtls_ssl_cache_get,
                                   mbedtls_ssl_cache_set );
#endif

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    if( opt.tickets == MBEDTLS_SSL_SESSION_TICKETS_ENABLED )
    {
        if( ( ret = mbedtls_ssl_ticket_setup( &ticket_ctx,
                        mbedtls_ctr_drbg_random, &ctr_drbg,
                        MBEDTLS_CIPHER_AES_256_GCM,
                        opt.ticket_timeout ) ) != 0 )
        {
            fprintf(stderr, "mbedtls_ssl_ticket_setup returned %d\n\n", ret );
            return -1;
        }

        mbedtls_ssl_conf_session_tickets_cb( &conf,
                mbedtls_ssl_ticket_write,
                mbedtls_ssl_ticket_parse,
                &ticket_ctx );
    }
#endif

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( opt.transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
#if defined(MBEDTLS_SSL_COOKIE_C)
        if( opt.cookies > 0 )
        {
            if( ( ret = mbedtls_ssl_cookie_setup( &cookie_ctx,
                                          mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
            {
                fprintf(stderr, "mbedtls_ssl_cookie_setup returned %d\n\n", ret );
                return -1;
            }

            mbedtls_ssl_conf_dtls_cookies( &conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check,
                                       &cookie_ctx );
        }
        else
#endif /* MBEDTLS_SSL_COOKIE_C */
#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY)
        if( opt.cookies == 0 )
        {
            mbedtls_ssl_conf_dtls_cookies( &conf, NULL, NULL, NULL );
        }
        else
#endif /* MBEDTLS_SSL_DTLS_HELLO_VERIFY */
        {
            ; /* Nothing to do */
        }

#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
        if( opt.anti_replay != DFL_ANTI_REPLAY )
            mbedtls_ssl_conf_dtls_anti_replay( &conf, opt.anti_replay );
#endif

#if defined(MBEDTLS_SSL_DTLS_BADMAC_LIMIT)
        if( opt.badmac_limit != DFL_BADMAC_LIMIT )
            mbedtls_ssl_conf_dtls_badmac_limit( &conf, opt.badmac_limit );
#endif
    }
#endif /* MBEDTLS_SSL_PROTO_DTLS */

    if( opt.force_ciphersuite[0] != DFL_FORCE_CIPHER )
        mbedtls_ssl_conf_ciphersuites( &conf, opt.force_ciphersuite );

#if defined(MBEDTLS_ARC4_C)
    if( opt.arc4 != DFL_ARC4 )
        mbedtls_ssl_conf_arc4_support( &conf, opt.arc4 );
#endif

    if( opt.version_suites != NULL )
    {
        mbedtls_ssl_conf_ciphersuites_for_version( &conf, version_suites[0],
                                          MBEDTLS_SSL_MAJOR_VERSION_3,
                                          MBEDTLS_SSL_MINOR_VERSION_0 );
        mbedtls_ssl_conf_ciphersuites_for_version( &conf, version_suites[1],
                                          MBEDTLS_SSL_MAJOR_VERSION_3,
                                          MBEDTLS_SSL_MINOR_VERSION_1 );
        mbedtls_ssl_conf_ciphersuites_for_version( &conf, version_suites[2],
                                          MBEDTLS_SSL_MAJOR_VERSION_3,
                                          MBEDTLS_SSL_MINOR_VERSION_2 );
        mbedtls_ssl_conf_ciphersuites_for_version( &conf, version_suites[3],
                                          MBEDTLS_SSL_MAJOR_VERSION_3,
                                          MBEDTLS_SSL_MINOR_VERSION_3 );
    }

    if( opt.allow_legacy != DFL_ALLOW_LEGACY )
        mbedtls_ssl_conf_legacy_renegotiation( &conf, opt.allow_legacy );
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    mbedtls_ssl_conf_renegotiation( &conf, opt.renegotiation );

    if( opt.renego_delay != DFL_RENEGO_DELAY )
        mbedtls_ssl_conf_renegotiation_enforced( &conf, opt.renego_delay );

    if( opt.renego_period != DFL_RENEGO_PERIOD )
    {
        PUT_UINT64_BE( renego_period, opt.renego_period, 0 );
        mbedtls_ssl_conf_renegotiation_period( &conf, renego_period );
    }
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if( strcmp( opt.ca_path, "none" ) != 0 &&
        strcmp( opt.ca_file, "none" ) != 0 )
    {
        mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
    }
    if( key_cert_init )
    {
        mbedtls_pk_context *pk = &pkey;
        if( ( ret = mbedtls_ssl_conf_own_cert( &conf, &srvcert, pk ) ) != 0 )
        {
            fprintf(stderr, "mbedtls_ssl_conf_own_cert returned %d\n\n", ret );
            return -1;
        }
    }
    if( key_cert_init2 )
    {
        mbedtls_pk_context *pk = &pkey2;
        if( ( ret = mbedtls_ssl_conf_own_cert( &conf, &srvcert2, pk ) ) != 0 )
        {
            fprintf(stderr, "mbedtls_ssl_conf_own_cert returned %d\n\n", ret );
            return -1;
        }
    }

#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(SNI_OPTION)
    if( opt.sni != NULL )
    {
        mbedtls_ssl_conf_sni( &conf, sni_callback, sni_info );
    }
#endif

#if defined(MBEDTLS_ECP_C)
    if( opt.curves != NULL &&
        strcmp( opt.curves, "default" ) != 0 )
    {
        mbedtls_ssl_conf_curves( &conf, curve_list );
    }
#endif

    if( strlen( opt.psk ) != 0 && strlen( opt.psk_identity ) != 0 )
    {
        ret = mbedtls_ssl_conf_psk( &conf, psk, psk_len,
                           (const unsigned char *) opt.psk_identity,
                           strlen( opt.psk_identity ) );
        if( ret != 0 )
        {
            fprintf(stderr, "mbedtls_ssl_conf_psk returned -0x%04X\n\n", - ret );
            return -1;
        }
    }

    if( opt.psk_list != NULL )
        mbedtls_ssl_conf_psk_cb( &conf, psk_callback, psk_info );

#if defined(MBEDTLS_DHM_C)
    /*
     * Use different group than default DHM group
     */
#if defined(MBEDTLS_FS_IO)
    if( opt.dhm_file != NULL )
        ret = mbedtls_ssl_conf_dh_param_ctx( &conf, &dhm );
#endif
    if( ret != 0 )
    {
        fprintf(stderr, "mbedtls_ssl_conf_dh_param returned -0x%04X\n\n", - ret );
        return -1;
    }
#endif

    if( opt.min_version != DFL_MIN_VERSION )
        mbedtls_ssl_conf_min_version( &conf, MBEDTLS_SSL_MAJOR_VERSION_3, opt.min_version );

    if( opt.max_version != DFL_MIN_VERSION )
        mbedtls_ssl_conf_max_version( &conf, MBEDTLS_SSL_MAJOR_VERSION_3, opt.max_version );

    return 0;
}

static int prv_ssl_init(connection_t* connP)
{
    mbedtls_ssl_init(connP->ssl);
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if(opt.dgram_packing != DFL_DGRAM_PACKING)
        mbedtls_ssl_set_datagram_packing(connP->ssl, opt.dgram_packing);
#endif /* MBEDTLS_SSL_PROTO_DTLS */

    if(opt.nbio == 2)
        mbedtls_ssl_set_bio(connP->ssl, connP->sock, my_send, my_recv, NULL);
    else
        mbedtls_ssl_set_bio(connP->ssl, connP->sock, mbedtls_net_send, mbedtls_net_recv, opt.nbio == 0 ? mbedtls_net_recv_timeout : NULL);

//    ret = mbedtls_ssl_setup(&connP->ssl, &conf);
    mbedtls_ssl_setup(connP->ssl, &conf);

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( opt.dtls_mtu != DFL_DTLS_MTU )
        mbedtls_ssl_set_mtu(connP->ssl, opt.dtls_mtu);
#endif
#if defined(MBEDTLS_TIMING_C)
    mbedtls_ssl_set_timer_cb(connP->ssl, &timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay);
#endif

    mbedtls_ssl_session_reset(connP->ssl);

    return 0;
} 

int create_socket(const char * portStr, int addressFamily)
{
    return prv_init_mbedtls(portStr, addressFamily);
}

void mbedtls_step(lwm2m_context_t *lwm2m, time_t timeout)
{
    int ret;

    if(connectionList != NULL)
    {
        connection_t* connP_curr = connectionList;

        while(connP_curr != NULL)
        {
            ret = mbedtls_net_poll(connP_curr->sock, MBEDTLS_NET_POLL_READ, 0);
            if(ret & MBEDTLS_NET_POLL_READ)
            {
                ret = mbedtls_ssl_read(connP_curr->ssl, buf, opt.buffer_size - 1);
                if(ret > 0)
                {
                    lwm2m_handle_packet(lwm2m, buf, ret, connP_curr);
                }
            }
            connP_curr = connP_curr->next;
        }
    }

    ret = mbedtls_net_poll(&listen_fd, MBEDTLS_NET_POLL_READ, timeout * 1000);
    if(ret & MBEDTLS_NET_POLL_READ)
    {
        connection_t* connP = connection_new_incoming();
        unsigned char client_ip[16] = { 0 };
        size_t cliip_len;

hello_verify:
        mbedtls_net_accept(&listen_fd, connP->sock, client_ip, sizeof(client_ip), &cliip_len);
        mbedtls_ssl_set_client_transport_id(connP->ssl, client_ip, cliip_len);

        ret = mbedtls_ssl_read(connP->ssl, buf, opt.buffer_size - 1);
        if(ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED)
        {
            mbedtls_net_free(connP->sock);
            mbedtls_ssl_session_reset(connP->ssl);
            goto hello_verify;
        }
        else if(ret > 0)
        {
            lwm2m_handle_packet(lwm2m, buf, ret, connP);
        }
    }
}

connection_t * connection_new_incoming(void)
{
    connection_t * connP;

    connP = (connection_t *)malloc(sizeof(connection_t));
    if (connP != NULL)
    {
        connP->sock = (mbedtls_net_context*)malloc(sizeof(mbedtls_net_context));
        mbedtls_net_init(connP->sock);

        connP->ssl = (mbedtls_ssl_context*)malloc(sizeof(mbedtls_ssl_context));
        prv_ssl_init(connP);

        connP->next = connectionList;
        connectionList = connP;
    }

    return connP;
}

void connection_free(connection_t * connList)
{
    while (connList != NULL)
    {
        connection_t * nextP;

        nextP = connList->next;
        free(connList);

        connList = nextP;
    }
}

uint8_t lwm2m_buffer_send(void * sessionH,
                          uint8_t * buffer,
                          size_t length,
                          void * userdata)
{
    connection_t * connP = (connection_t*) sessionH;

    if (connP == NULL)
    {
        fprintf(stderr, "#> failed sending %lu bytes, missing connection\r\n", length);
        return COAP_500_INTERNAL_SERVER_ERROR ;
    }

    if(mbedtls_ssl_write(connP->ssl, buffer, length) < 0)
    {
        fprintf(stderr, "#> failed sending %lu bytes\r\n", length);
        return COAP_500_INTERNAL_SERVER_ERROR ;
    }

    return COAP_NO_ERROR;
}

bool lwm2m_session_is_equal(void * session1,
                            void * session2,
                            void * userData)
{
    return (session1 == session2);
}
