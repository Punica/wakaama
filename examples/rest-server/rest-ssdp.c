/*
 * MIT License
 *
 * Copyright (c) 2018 8devices
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "rest-ssdp.h"

#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "logging.h"


#define SSDP_PORT "1900"
#define SSDP_GROUP "ff05::c"
#define SSDP_RESPONSE   "HTTP/1.1 200 OK\r\n"                               \
                        "CACHE-CONTROL: max-age=1800\r\n"                   \
                        "EXT:\r\n"                                          \
                        "LOCATION: *\r\n"                                   \
                        "SERVER: OS/0.1 UPnP/1.0 X/0.1\r\n"                 \
                        "ST: urn:8devices-com:service:lwm2m:1\r\n"          \
                        "USN: uuid:754cb08a-7ea1-485f-8202-9f16234083f2"    \
                        "::urn:8devices-com:service:lwm2m:1\r\n"            \
                        "\r\n"

typedef struct ssdp_t
{
    ssdp_param_t    s_params;
    int             s_sock;
    pthread_t       s_thread;
} ssdp_t;

static ssdp_status_t ssdp_sock_open(ssdp_t *ssdp);
static ssdp_status_t ssdp_sock_close(ssdp_t *ssdp);
static void *ssdp_run(void *arg);
static int ssdp_request_is_valid(char *buf);

ssdp_t *ssdp_init(ssdp_param_t *params)
{
    log_message(LOG_LEVEL_DEBUG, "[SSDP] %s(): params=%p\n", __func__, params);

    ssdp_t *ssdp = calloc(1, sizeof(ssdp_t));

    if (ssdp == NULL)
    {
        log_message(LOG_LEVEL_ERROR, "[SSDP] Failed to allocate memory!\n");
        return NULL;
    }

    memcpy(&ssdp->s_params, params, sizeof(ssdp->s_params));

    ssdp->s_sock = -1;

    ssdp->s_thread = 0;

    return ssdp;
}

void ssdp_free(ssdp_t *ssdp)
{
    log_message(LOG_LEVEL_DEBUG, "[SSDP] %s(): ssdp=%p\n", __func__, ssdp);

    free(ssdp);
}

ssdp_status_t ssdp_start(ssdp_t *ssdp)
{
    int status;

    log_message(LOG_LEVEL_DEBUG, "[SSDP] %s(): ssdp=%p\n", __func__, ssdp);

    ssdp_stop(ssdp);

    status = ssdp_sock_open(ssdp);
    if (status != SSDP_OK)
    {
        log_message(LOG_LEVEL_ERROR, "[SSDP] Failed to open socket (%d)!\n", status);
        return status;
    }

    status = pthread_create(&ssdp->s_thread, NULL, &ssdp_run, ssdp);
    if (status != 0)
    {
        ssdp->s_thread = 0;
        log_message(LOG_LEVEL_ERROR, "[SSDP] Failed to create thread (%d)!\n", status);
        return SSDP_ERROR;
    }

#ifdef _GNU_SOURCE
    pthread_setname_np(ssdp->s_thread, "ssdp_server");
#endif

    return SSDP_OK;
}

ssdp_status_t ssdp_stop(ssdp_t *ssdp)
{
    int status;
    void *retval;

    log_message(LOG_LEVEL_DEBUG, "[SSDP] %s(): ssdp=%p\n", __func__, ssdp);

    if (ssdp->s_thread == 0)
    {
        return SSDP_OK;
    }

    status = pthread_cancel(ssdp->s_thread);
    if (status != 0)
    {
        log_message(LOG_LEVEL_ERROR, "[SSDP] Failed to cancel thread (%d)!\n", status);
        return SSDP_ERROR;
    }

    status = pthread_join(ssdp->s_thread, &retval);
    if (status != 0)
    {
        log_message(LOG_LEVEL_ERROR, "[SSDP] Failed to join thread (%d)!\n", status);
        return SSDP_ERROR;
    }

    ssdp->s_thread = 0;

    status = ssdp_sock_close(ssdp);
    if (status != SSDP_OK)
    {
        log_message(LOG_LEVEL_ERROR, "[SSDP] Failed to close socket (%d)!\n", status);
        return status;
    }

    return SSDP_OK;
}

ssdp_status_t ssdp_sock_open(ssdp_t *ssdp)
{
    int status;
    struct addrinfo hints;
    struct addrinfo *addr = NULL;

    log_message(LOG_LEVEL_DEBUG, "[SSDP] %s(): ssdp=%p\n", __func__, ssdp);

    /* Resolve the multicast group address */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;
    status = getaddrinfo(SSDP_GROUP, SSDP_PORT, &hints, &addr);
    if (status != 0)
    {
        log_message(LOG_LEVEL_ERROR, "[SSDP] Failed to resolve multicast address (%d)!\n", status);
        goto exit;
    }

    /* Create socket for receiving datagrams */
    ssdp->s_sock = socket(addr->ai_family, addr->ai_socktype, 0);
    if (ssdp->s_sock < 0)
    {
        log_message(LOG_LEVEL_ERROR, "[SSDP] Failed to create socket (%d)!\n", errno);
        status = -1;
        goto exit;
    }

    /*
     * Enable SO_REUSEADDR to allow multiple instances of this
     * application to receive copies of the multicast datagrams.
     */
    status = setsockopt(ssdp->s_sock, SOL_SOCKET, SO_REUSEADDR, &(int) { 1 }, sizeof(int));
    if (status != 0)
    {
        log_message(LOG_LEVEL_ERROR, "[SSDP] Failed to set sock options (%d)!\n", status);
        goto exit;
    }

    /* Bind the local address to the multicast port */
    status = bind(ssdp->s_sock, addr->ai_addr, addr->ai_addrlen);
    if (status != 0)
    {
        log_message(LOG_LEVEL_ERROR, "[SSDP] Failed to bind socket (%d)!\n", status);
        goto exit;
    }

    /* Join the multicast group. We do this seperately depending on whether we
     * are using IPv4 or IPv6.
     */
    if (addr->ai_family == PF_INET &&
        addr->ai_addrlen == sizeof(struct sockaddr_in))
    {
        struct ip_mreq request; // Multicast address join structure

        /* Specify the multicast group */
        memcpy(&request.imr_multiaddr,
               &((struct sockaddr_in *)(addr->ai_addr))->sin_addr,
               sizeof(request.imr_multiaddr));

        /* Accept multicast from any interface */
        request.imr_interface.s_addr = htonl(INADDR_ANY);

        /* Join the multicast address */
        status = setsockopt(ssdp->s_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                            &request, sizeof(request));
        if (status != 0)
        {
            log_message(LOG_LEVEL_ERROR, "[SSDP] Failed to join multicast group (%d)!\n", status);
            goto exit;
        }
    }
    else if (addr->ai_family == PF_INET6 &&
             addr->ai_addrlen == sizeof(struct sockaddr_in6))
    {
        struct ipv6_mreq request; // Multicast address join structure

        /* Specify the multicast group */
        memcpy(&request.ipv6mr_multiaddr,
               &((struct sockaddr_in6 *)(addr->ai_addr))->sin6_addr,
               sizeof(request.ipv6mr_multiaddr));

        /* Accept multicast from any interface */
        request.ipv6mr_interface = 0;

        /* Join the multicast address */
        status = setsockopt(ssdp->s_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
                            &request, sizeof(request));
        if (status != 0)
        {
            log_message(LOG_LEVEL_ERROR, "[SSDP] Failed to join multicast group (%d)!\n", status);
            goto exit;
        }
    }
    else
    {
        log_message(LOG_LEVEL_ERROR, "[SSDP] Unknown address type (family=%d, len=%d)!\n",
                    addr->ai_family, addr->ai_addrlen);
        status = -1;
        goto exit;
    }

    status = 0;

exit:
    if (status != 0)
    {
        ssdp_sock_close(ssdp);
    }

    if (addr)
    {
        freeaddrinfo(addr);
    }

    return (status == 0) ? SSDP_OK : SSDP_ERROR;
}

ssdp_status_t ssdp_sock_close(ssdp_t *ssdp)
{
    log_message(LOG_LEVEL_DEBUG, "[SSDP] %s(): ssdp=%p\n", __func__, ssdp);

    if (ssdp->s_sock != -1)
    {
        close(ssdp->s_sock);
        ssdp->s_sock = -1;
    }

    return SSDP_OK;
}

void *ssdp_run(void *arg)
{
    ssdp_t *ssdp = arg;
    char buf[1024];
    int len;

    log_message(LOG_LEVEL_DEBUG, "[SSDP] %s(): ssdp=%p\n", __func__, ssdp);

    struct sockaddr_storage clientaddr;
    socklen_t addrlen;

    char clienthost[NI_MAXHOST];
    char clientport[NI_MAXSERV];

    /* now just enter a read-print loop */
    while (1)
    {
        addrlen = sizeof(clientaddr);
        len = recvfrom(ssdp->s_sock, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&clientaddr, &addrlen);

        if (len < 0 || len >= sizeof(buf))
        {
            continue;
        }

        buf[len] = '\0';

        memset(clienthost, 0, sizeof(clienthost));
        memset(clientport, 0, sizeof(clientport));

        getnameinfo((struct sockaddr *)&clientaddr, addrlen,
                    clienthost, sizeof(clienthost),
                    clientport, sizeof(clientport),
                    NI_NUMERICHOST | NI_NUMERICSERV | NI_NOFQDN);

        log_message(LOG_LEVEL_DEBUG, "[SSDP] Request from [%s]:%s len=%d\n",
                    clienthost, clientport, len);

        log_message(LOG_LEVEL_TRACE, "----------\n%s\n----------\n", buf);

        if (ssdp_request_is_valid(buf))
        {
            len = snprintf(buf, sizeof(buf), SSDP_RESPONSE);

            log_message(LOG_LEVEL_DEBUG, "[SSDP] Sending response len=%d\n", len);
            len = sendto(ssdp->s_sock, buf, len, 0,
                         (struct sockaddr *)&clientaddr, sizeof(clientaddr));
            if (len < 0)
            {
                log_message(LOG_LEVEL_ERROR, "[SSDP] Failed to send response (%d)!\n", len);
            }
        }
    }

    return NULL;
}

int ssdp_request_is_valid(char *buf)
{
    char *line;
    char *saveptr;
    int i = 0;

    log_message(LOG_LEVEL_DEBUG, "[SSDP] %s(): buf=%p\n", __func__, buf);

    line = strtok_r(buf, "\r\n", &saveptr);

    while (line != NULL)
    {
        if (i == 0 && strcmp(line, "M-SEARCH * HTTP/1.1") != 0)
        {
            return 0;
        }

        if (strcmp(line, "ST: urn:8devices-com:service:lwm2m:1") == 0)
        {
            return 1;
        }

        line = strtok_r(NULL, "\r\n", &saveptr);
        i++;
    }

    return 0;
}

