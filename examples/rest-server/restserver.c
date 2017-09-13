
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include <liblwm2m.h>
#include <ulfius.h>

#include "connection.h"
#include "restserver.h"


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

    memset(&rest, 0, sizeof(rest_context_t));

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
    ulfius_add_endpoint_by_val(&instance, "PUT", "/notification/callback", NULL, 10, &rest_notifications_put_callback_cb, &rest);
    ulfius_add_endpoint_by_val(&instance, "GET", "/notification/pull", NULL, 10, &rest_notifications_pull_cb, &rest);

    // Subscriptions
    ulfius_add_endpoint_by_val(&instance, "PUT", "/subscriptions", ":name/*", 10, &rest_subscriptions_put_cb, &rest);

    if (ulfius_start_framework(&instance) != U_OK)
    {
        fprintf(stderr, "Failed to start REST server!\n");
        return -1;
    }

    /* Main section */
    while (1)
    {
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);

        tv.tv_sec = 5;
        tv.tv_usec = 0;

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

        res = select(FD_SETSIZE, &readfds, NULL, NULL, &tv);
        if (res < 0)
        {
            fprintf(stderr, "select() error: %d\n", res);
        }

        if (FD_ISSET(sock, &readfds))
        {
            socket_receive(rest.lwm2m, sock);
        }

    }

    ulfius_stop_framework(&instance);
    ulfius_clean_instance(&instance);
}

