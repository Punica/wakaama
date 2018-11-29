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
#include <string.h>

#include <liblwm2m.h>
#include <ulfius.h>

#include "connection.h"
#include "restserver.h"
#include "rest-ssdp.h"
#include "logging.h"
#include "settings.h"
#include "version.h"
#include "security.h"
#include "rest-list.h"
#include "rest-authentication.h"

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
    log_message(LOG_LEVEL_ERROR, "SIGPIPE occurs: %d times.\n", sigpipe_cnt);
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
    if (0 != sigaction(SIGINT, &sig, &oldsig))
    {
        log_message(LOG_LEVEL_FATAL, "Failed to install SIGINT handler: %s\n", strerror(errno));
    }

    //to stop valgrind
    if (0 != sigaction(SIGTERM, &sig, &oldsig))
    {
        log_message(LOG_LEVEL_FATAL, "Failed to install SIGTERM handler: %s\n", strerror(errno));
    }


    memset(&sig, 0, sizeof(sig));
    sig.sa_handler = &sigpipe_handler;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags = SA_RESTART;
    if (0 != sigaction(SIGPIPE, &sig, &oldsig))
    {
        log_message(LOG_LEVEL_FATAL, "Failed to install SIGPIPE handler: %s\n", strerror(errno));
    }
}


const char *binding_to_string(lwm2m_binding_t bind)
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


int rest_version_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    ulfius_set_string_body_response(resp, 200, RESTSERVER_VERSION);

    return U_CALLBACK_COMPLETE;
}

void client_monitor_cb(uint16_t clientID, lwm2m_uri_t *uriP, int status,
                       lwm2m_media_type_t format, uint8_t *data, int dataLength,
                       void *userData)
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
                log_message(LOG_LEVEL_ERROR, "[MONITOR] Failed to allocate registration notification!\n");
            }

            log_message(LOG_LEVEL_INFO, "[MONITOR] Client %d registered.\n", clientID);
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
                log_message(LOG_LEVEL_ERROR, "[MONITOR] Failed to allocate update notification!\n");
            }

            log_message(LOG_LEVEL_INFO, "[MONITOR] Client %d updated.\n", clientID);
        }

        log_message(LOG_LEVEL_DEBUG, "\tname: '%s'\n", client->name);
        log_message(LOG_LEVEL_DEBUG, "\tbind: '%s'\n", binding_to_string(client->binding));
        log_message(LOG_LEVEL_DEBUG, "\tlifetime: %d\n", client->lifetime);
        log_message(LOG_LEVEL_DEBUG, "\tobjects: ");
        for (obj = client->objectList; obj != NULL; obj = obj->next)
        {
            if (obj->instanceList == NULL)
            {
                log_message(LOG_LEVEL_DEBUG, "/%d, ", obj->id);
            }
            else
            {
                for (ins = obj->instanceList; ins != NULL; ins = ins->next)
                {
                    log_message(LOG_LEVEL_DEBUG, "/%d/%d, ", obj->id, ins->id);
                }
            }
        }
        log_message(LOG_LEVEL_DEBUG, "\n");
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
            log_message(LOG_LEVEL_ERROR, "[MONITOR] Failed to allocate deregistration notification!\n");
        }

        log_message(LOG_LEVEL_INFO, "[MONITOR] Client %d deregistered.\n", clientID);
        break;
    }
    default:
        log_message(LOG_LEVEL_INFO, "[MONITOR] Client %d status update %d.\n", clientID, status);
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
        log_message(LOG_LEVEL_FATAL, "recvfrom() error: %d\n", nbytes);
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
    char coap_port[6];
    ssdp_t *ssdp;
    ssdp_param_t ssdp_params;

    static settings_t settings =
    {
        .http = {
            .port = 8888,
            .security = {
                .private_key = NULL,
                .certificate = NULL,
                .private_key_file = NULL,
                .certificate_file = NULL,
                .jwt = {
                    .initialised = false,
                    .algorithm = JWT_ALG_HS512,
                    .secret_key = NULL,
                    .secret_key_length = 32,
                    .users_list = NULL,
                    .expiration_time = 3600,
                },
            },
        },
        .coap = {
            .port = 5555,
        },
        .logging = {
            .level = LOG_LEVEL_WARN,
            .timestamp = false,
            .human_readable_timestamp = false,
        },
    };

    settings.http.security.jwt.users_list = rest_list_new();
    settings.http.security.jwt.secret_key = (unsigned char *) malloc(
                                                settings.http.security.jwt.secret_key_length * sizeof(unsigned char));
    rest_get_random(settings.http.security.jwt.secret_key,
                    settings.http.security.jwt.secret_key_length);

    if (settings_init(argc, argv, &settings) != 0)
    {
        return -1;
    }

    logging_init(&settings.logging);

    init_signals();

    rest_init(&rest);

    /* Socket section */
    snprintf(coap_port, sizeof(coap_port), "%d", settings.coap.port);
    log_message(LOG_LEVEL_INFO, "Creating coap socket on port %s\n", coap_port);
    sock = create_socket(coap_port, AF_INET6);
    if (sock < 0)
    {
        log_message(LOG_LEVEL_FATAL, "Failed to create socket!\n");
        return -1;
    }

    /* Server section */
    rest.lwm2m = lwm2m_init(NULL);
    if (rest.lwm2m == NULL)
    {
        log_message(LOG_LEVEL_FATAL, "Failed to create LwM2M server!\n");
        return -1;
    }

    lwm2m_set_monitoring_callback(rest.lwm2m, client_monitor_cb, &rest);

    /* REST server section */
    struct _u_instance instance;

    log_message(LOG_LEVEL_INFO, "Creating http socket on port %u\n", settings.http.port);
    if (ulfius_init_instance(&instance, settings.http.port, NULL, NULL) != U_OK)
    {
        log_message(LOG_LEVEL_FATAL, "Failed to initialize REST server!\n");
        return -1;
    }

    /*
     * mbed Device Connector based api
     * https://docs.mbed.com/docs/mbed-device-connector-web-interfaces/en/latest/api-reference/
     */

    // Endpoints
    ulfius_add_endpoint_by_val(&instance, "GET", "/endpoints", NULL, 10,
                               &rest_endpoints_cb, &rest);
    ulfius_add_endpoint_by_val(&instance, "GET", "/endpoints", ":name", 10,
                               &rest_endpoints_name_cb, &rest);

    // Resources
    ulfius_add_endpoint_by_val(&instance, "*", "/endpoints", ":name/*", 10,
                               &rest_resources_rwe_cb, &rest);

    // Notifications
    ulfius_add_endpoint_by_val(&instance, "GET", "/notification/callback", NULL, 10,
                               &rest_notifications_get_callback_cb, &rest);
    ulfius_add_endpoint_by_val(&instance, "PUT", "/notification/callback", NULL, 10,
                               &rest_notifications_put_callback_cb, &rest);
    ulfius_add_endpoint_by_val(&instance, "DELETE", "/notification/callback", NULL, 10,
                               &rest_notifications_delete_callback_cb, &rest);
    ulfius_add_endpoint_by_val(&instance, "GET", "/notification/pull", NULL, 10,
                               &rest_notifications_pull_cb, &rest);

    // Subscriptions
    ulfius_add_endpoint_by_val(&instance, "PUT", "/subscriptions", ":name/*", 10,
                               &rest_subscriptions_put_cb, &rest);
    ulfius_add_endpoint_by_val(&instance, "DELETE", "/subscriptions", ":name/*", 10,
                               &rest_subscriptions_delete_cb, &rest);

    // Version
    ulfius_add_endpoint_by_val(&instance, "GET", "/version", NULL, 1, &rest_version_cb, NULL);

    // JWT authentication
    ulfius_add_endpoint_by_val(&instance, "POST", "/authenticate", NULL, 1, &rest_authenticate_cb,
                               (void *)&settings.http.security.jwt);
    ulfius_add_endpoint_by_val(&instance, "*", "*", NULL, 3, &rest_validate_jwt_cb,
                               (void *)&settings.http.security.jwt);

    if (settings.http.security.private_key != NULL || settings.http.security.certificate != NULL)
    {
        if (security_load(&(settings.http.security)) != 0)
        {
            return -1;
        }

        if (ulfius_start_secure_framework(&instance,
                                          settings.http.security.private_key_file,
                                          settings.http.security.certificate_file) != U_OK)
        {
            log_message(LOG_LEVEL_FATAL, "Failed to start REST server!\n");
            return -1;
        }

        if (!settings.http.security.jwt.initialised)
        {
            log_message(LOG_LEVEL_WARN, "Encryption without authentication is unadvisable!\n");
        }

        security_unload(&(settings.http.security));
    }
    else
    {
        if (ulfius_start_framework(&instance) != U_OK)
        {
            log_message(LOG_LEVEL_FATAL, "Failed to start REST server!\n");
            return -1;
        }

        if (settings.http.security.jwt.initialised)
        {
            log_message(LOG_LEVEL_WARN, "Authentication without encryption is unadvisable!\n");
        }
    }

    if (settings.http.security.jwt.initialised)
    {
        if (settings.http.security.jwt.users_list->head == NULL)
        {
            log_message(LOG_LEVEL_WARN, "JWT is initialised but no users are configured properly!\n");
        }
        if (settings.http.security.jwt.secret_key == NULL)
        {
            log_message(LOG_LEVEL_WARN, "JWT is initialised but secret key is unavalable!\n");
        }
    }

    /* SSDP service section */
    log_message(LOG_LEVEL_INFO, "Starting SSDP service...\n");

    memset(&ssdp_params, 0, sizeof(ssdp_params));
    ssdp_params.coap_port = coap_port;

    ssdp = ssdp_init(&ssdp_params);
    if (ssdp == NULL)
    {
        log_message(LOG_LEVEL_FATAL, "Failed to allocate SSDP service\n");
        return -1;
    }

    if (ssdp_start(ssdp) != SSDP_OK)
    {
        log_message(LOG_LEVEL_FATAL, "Failed to start SSDP service!\n");
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
            log_message(LOG_LEVEL_ERROR, "lwm2m_step() error: %d\n", res);
        }

        res = rest_step(&rest, &tv);
        if (res)
        {
            log_message(LOG_LEVEL_ERROR, "rest_step() error: %d\n", res);
        }
        rest_unlock(&rest);

        res = select(FD_SETSIZE, &readfds, NULL, NULL, &tv);
        if (res < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }

            log_message(LOG_LEVEL_ERROR, "select() error: %d\n", res);
        }

        if (FD_ISSET(sock, &readfds))
        {
            rest_lock(&rest);
            socket_receive(rest.lwm2m, sock);
            rest_unlock(&rest);
        }

    }

    ssdp_stop(ssdp);
    ssdp_free(ssdp);

    ulfius_stop_framework(&instance);
    ulfius_clean_instance(&instance);

    lwm2m_close(rest.lwm2m);
    rest_cleanup(&rest);

    jwt_cleanup(&settings.http.security.jwt);

    return 0;
}

