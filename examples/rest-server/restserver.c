/*
 * MIT License
 *
 * Copyright (c) 2017 8devices
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

#include <sys/socket.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <liblwm2m.h>
#include <ulfius.h>

#include "connection.h"
#include "restserver.h"

static volatile int restserver_quit;
static void sigint_handler(int signo)
{
    restserver_quit = 1;
}

/**
 * Function called if we get a SIGPIPE. Does counting.
 * exmp. killall -13  restserver
 * @param sig will be SIGPIPE (ignored)
 */
static void sigpipe_handler(int sig)
{
    static volatile int sigpipe_cnt;
    sigpipe_cnt++;
    fprintf(stderr, "SIGPIPE occurs: %d times.\n",sigpipe_cnt);
}


/**
 * setup handlers to ignore SIGPIPE, handle SIGINT...
 */
static void init_signals(void)
{
    struct sigaction oldsig;
    struct sigaction sig;

    //signal(SIGINT, sigint_handler);//automaticaly do SA_RESTART, we must break system functions exmp. select
    memset(&sig, 0, sizeof(sig));
    sig.sa_handler = &sigint_handler;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags = 0;//break system functions open, read ... if SIGINT occurs
    if (0 != sigaction(SIGINT, &sig, &oldsig)) {
        fprintf(stderr, "Failed to install SIGINT handler: %s\n", strerror(errno));
    }

    //to stop valgrind
    if (0 != sigaction(SIGTERM, &sig, &oldsig)) {
        fprintf(stderr, "Failed to install SIGINT handler: %s\n", strerror(errno));
    }


    memset(&sig, 0, sizeof(sig));
    sig.sa_handler = &sigpipe_handler;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags = SA_RESTART;//dont break system functions open, read ... if SIGPIPE occurs SA_INTERRUPT, but select return interrupted
    if (0 != sigaction(SIGPIPE, &sig, &oldsig)) {
        fprintf(stderr, "Failed to install SIGPIPE handler: %s\n", strerror(errno));
    }
}


const char * binding_to_string(lwm2m_binding_t bind)
{
    switch (bind)
    {
    case BINDING_U:
        return "U";
    case BINDING_UQ:
        return "UQ";
    case BINDING_S:
        return "S";
    case BINDING_SQ:
        return "SQ";
    case BINDING_US:
        return "US";
    case BINDING_UQS:
        return "UQS";
    default:
        return "Unknown";
    }
}

void client_monitor_cb(uint16_t clientID, lwm2m_uri_t * uriP, int status, lwm2m_media_type_t format, uint8_t * data, int dataLength, void * userData)
{
    rest_context_t *rest = (rest_context_t *)userData;
    lwm2m_context_t *lwm2m = rest->lwm2m;
    lwm2m_client_t *client;
    lwm2m_client_object_t *obj;
    lwm2m_list_t *ins;

    client = (lwm2m_client_t *)lwm2m_list_find((lwm2m_list_t *)lwm2m->clientList, clientID);

    switch (status)
    {
    case COAP_201_CREATED:
    case COAP_204_CHANGED:
        if (status == COAP_201_CREATED)
        {
            rest_notif_registration_t *regNotif = rest_notif_registration_new();

            if (regNotif != NULL)
            {
                rest_notif_registration_set(regNotif, client->name);
                rest_notify_registration(rest, regNotif);
            }
            else
            {
                fprintf(stderr, "[MONITOR] Failed to allocate registration notification!\n");
            }

            fprintf(stdout, "[MONITOR] Client %d registered.\n", clientID);
        } 
        else 
        {
            rest_notif_update_t *updateNotif = rest_notif_update_new();

            if (updateNotif != NULL)
            {
                rest_notif_update_set(updateNotif, client->name);
                rest_notify_update(rest, updateNotif);
            }
            else
            {
                fprintf(stderr, "[MONITOR] Failed to allocate update notification!\n");
            }

            fprintf(stdout, "[MONITOR] Client %d updated.\n", clientID);
        }
        
        fprintf(stdout, "\tname: '%s'\n", client->name);
        fprintf(stdout, "\tbind: '%s'\n", binding_to_string(client->binding));
        fprintf(stdout, "\tlifetime: %d\n", client->lifetime);
        fprintf(stdout, "\tobjects: ");
        for (obj = client->objectList; obj != NULL; obj = obj->next)
        {
            if (obj->instanceList == NULL)
            {
                fprintf(stdout, "/%d, ", obj->id);
            }
            else
            {
                for (ins = obj->instanceList; ins != NULL; ins = ins->next)
                {
                    fprintf(stdout, "/%d/%d, ", obj->id, ins->id);
                }
            }
        }
        fprintf(stdout, "\n");
        break;

    case COAP_202_DELETED:
    {
        rest_notif_deregistration_t *deregNotif = rest_notif_deregistration_new();

        if (deregNotif != NULL)
        {
            rest_notif_deregistration_set(deregNotif, client->name);
            rest_notify_deregistration(rest, deregNotif);
        }
        else
        {
            fprintf(stderr, "[MONITOR] Failed to allocate deregistration notification!\n");
        }

        fprintf(stdout, "[MONITOR] Client %d deregistered.\n", clientID);
        break;
    }
    default:
        fprintf(stdout, "[MONITOR] Client %d status update %d.\n", clientID, status);
        break;
    }
}

int socket_receive(lwm2m_context_t *lwm2m, int sock)
{
    int nbytes;
    uint8_t buf[1500];
    struct sockaddr_storage addr;
    socklen_t addrLen = sizeof(addr);
    connection_t *con;
    static connection_t *connectionList = NULL;

    memset(buf, 0, sizeof(buf));

    nbytes = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &addrLen);

    if (nbytes < 0)
    {
        fprintf(stderr, "recvfrom() error: %d\n", nbytes);
        return -1;
    }

    con = connection_find(connectionList, &addr, addrLen);
    if (con == NULL)
    {
        con = connection_new_incoming(connectionList, sock, (struct sockaddr *)&addr, addrLen);
        if (con)
        {
            connectionList = con;
        }
    }

    if (con)
    {
        lwm2m_handle_packet(lwm2m, buf, nbytes, con);
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int sock;
    fd_set readfds;
    struct timeval tv;
    int res;
    rest_context_t rest;


    init_signals();


    rest_init(&rest);

    /* Socket section */
    sock = create_socket("5555", AF_INET6);
    if (sock < 0)
    {
        fprintf(stderr, "Failed to create socket!\n");
        return -1;
    }

    /* Server section */
    rest.lwm2m = lwm2m_init(NULL);
    if (rest.lwm2m == NULL)
    {
        fprintf(stderr, "Failed to create LwM2M server!\n");
        return -1;
    }
    
    lwm2m_set_monitoring_callback(rest.lwm2m, client_monitor_cb, &rest);

    /* REST server section */
    struct _u_instance instance;

    if (ulfius_init_instance(&instance, 8888, NULL, NULL) != U_OK)
    {
        fprintf(stderr, "Failed to initialize REST server!\n");
        return -1;
    }

    /*
     * mbed Device Connector based api
     * https://docs.mbed.com/docs/mbed-device-connector-web-interfaces/en/latest/api-reference/
     */

    // Endpoints
    ulfius_add_endpoint_by_val(&instance, "GET", "/endpoints", NULL, 10, &rest_endpoints_cb, &rest);
    ulfius_add_endpoint_by_val(&instance, "GET", "/endpoints", ":name", 10, &rest_endpoints_name_cb, &rest);

    // Resources
    ulfius_add_endpoint_by_val(&instance, "*", "/endpoints", ":name/*", 10, &rest_resources_rwe_cb, &rest);

    // Notifications
    ulfius_add_endpoint_by_val(&instance, "GET", "/notification/callback", NULL, 10, &rest_notifications_get_callback_cb, &rest);
    ulfius_add_endpoint_by_val(&instance, "PUT", "/notification/callback", NULL, 10, &rest_notifications_put_callback_cb, &rest);
    ulfius_add_endpoint_by_val(&instance, "GET", "/notification/pull", NULL, 10, &rest_notifications_pull_cb, &rest);

    // Subscriptions
    ulfius_add_endpoint_by_val(&instance, "PUT", "/subscriptions", ":name/*", 10, &rest_subscriptions_put_cb, &rest);
    ulfius_add_endpoint_by_val(&instance, "DELETE", "/subscriptions", ":name/*", 10, &rest_subscriptions_delete_cb, &rest);

    if (ulfius_start_framework(&instance) != U_OK)
    {
        fprintf(stderr, "Failed to start REST server!\n");
        return -1;
    }

    /* Main section */
    while (!restserver_quit)
    {
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);

        tv.tv_sec = 5;
        tv.tv_usec = 0;

        rest_lock(&rest);
        res = lwm2m_step(rest.lwm2m, &tv.tv_sec);
        if (res)
        {
            fprintf(stderr, "lwm2m_step() error: %d\n", res);
        }

        res = rest_step(&rest, &tv);
        if (res)
        {
            fprintf(stderr, "rest_step() error: %d\n", res);
        }
        rest_unlock(&rest);

        res = select(FD_SETSIZE, &readfds, NULL, NULL, &tv);
        if (res < 0)
        {
            if (errno == EINTR) {
                continue;
            }

            fprintf(stderr, "select() error: %d\n", res);
        }

        if (FD_ISSET(sock, &readfds))
        {
            rest_lock(&rest);
            socket_receive(rest.lwm2m, sock);
            rest_unlock(&rest);
        }

    }

    ulfius_stop_framework(&instance);
    ulfius_clean_instance(&instance);

    lwm2m_close(rest.lwm2m);
    rest_cleanup(&rest);

    return 0;
}

