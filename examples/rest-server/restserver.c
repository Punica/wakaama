
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include <liblwm2m.h>
#include <ulfius.h>

#include "connection.h"


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
    lwm2m_context_t *lwm2m = (lwm2m_context_t *)userData;
    lwm2m_client_t *client;
    lwm2m_client_object_t *obj;
    lwm2m_list_t *ins;

    switch (status)
    {
    case COAP_201_CREATED:
    case COAP_204_CHANGED:

        if (status == COAP_201_CREATED)
        {
            fprintf(stdout, "[MONITOR] Client %d registered.\n", clientID);
        } 
        else 
        {
            fprintf(stdout, "[MONITOR] Client %d updated.\n", clientID);
        }
        
        client = (lwm2m_client_t *)lwm2m_list_find((lwm2m_list_t *)lwm2m->clientList, clientID);
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
        fprintf(stdout, "[MONITOR] Client %d deregistered.\n", clientID);
        break;
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
    socklen_t addrLen;
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

json_t * client_to_json(lwm2m_client_t *client)
{
    lwm2m_client_object_t *obj;
    lwm2m_list_t *ins;
    char buf[20]; // 13 bytes should be enough (i.e. max string "/65535/65535\0")

    json_t *jclient = json_object();
    json_object_set_new(jclient, "name", json_string(client->name));
    json_object_set_new(jclient, "bind", json_string(binding_to_string(client->binding)));
    json_object_set_new(jclient, "lifetime", json_integer(client->lifetime));

    json_t *jobjects = json_array();
    for (obj = client->objectList; obj != NULL; obj = obj->next)
    {
        if (obj->instanceList == NULL)
        {
            snprintf(buf, sizeof(buf), "/%d", obj->id);
            json_array_append_new(jobjects, json_string(buf));
        }
        else
        {
            for (ins = obj->instanceList; ins != NULL; ins = ins->next)
            {
                snprintf(buf, sizeof(buf), "/%d/%d", obj->id, ins->id);
                json_array_append_new(jobjects, json_string(buf));
            }
        }
    }
    json_object_set_new(jclient, "objects", jobjects);

    return jclient;
}


int rest_clients_id_cb(const struct _u_request *req, struct _u_response *resp, void *context)
{
    lwm2m_context_t *lwm2m = (lwm2m_context_t *)context;
    lwm2m_client_t *client;
    uint32_t id = -1;

    const char *sid = u_map_get(req->map_url, "id");
    if (sscanf(sid, "%u", &id) != 1)
    {
        return U_CALLBACK_CONTINUE;
    }

    client = (lwm2m_client_t *)lwm2m_list_find((lwm2m_list_t *)lwm2m->clientList, id);
    if (client == NULL)
    {
        return U_CALLBACK_CONTINUE;
    }

    ulfius_set_json_body_response(resp, 200, client_to_json(client));
    return U_CALLBACK_CONTINUE;
}

int rest_clients_cb(const struct _u_request *req, struct _u_response *resp, void *context)
{
    lwm2m_context_t *lwm2m = (lwm2m_context_t *)context;
    lwm2m_client_t *client;

    json_t *jbody = json_object();
    json_t *jclients = json_array();
    for (client = lwm2m->clientList; client != NULL; client = client->next)
    {
        json_array_append_new(jclients, client_to_json(client));
    }
    json_object_set_new(jbody, "clients", jclients);

    ulfius_set_json_body_response(resp, 200, jbody);
    return U_CALLBACK_CONTINUE;
}

int main(int argc, char *argv[])
{
    int sock;
    struct sockaddr_in saddr;
    fd_set readfds;
    struct timeval tv;
    int res;
    lwm2m_context_t *lwm2m;


    /* Socket section */
    sock = create_socket("5432", AF_INET6);
    if (sock < 0)
    {
        fprintf(stderr, "Failed to create socket!\n");
        return -1;
    }

    /* Server section */
    lwm2m = lwm2m_init(NULL);
    if (lwm2m == NULL)
    {
        fprintf(stderr, "Failed to create LwM2M server!\n");
        return -1;
    }
    
    lwm2m_set_monitoring_callback(lwm2m, client_monitor_cb, lwm2m);

    /* REST server section */
    struct _u_instance instance;

    if (ulfius_init_instance(&instance, 8888, NULL, NULL) != U_OK)
    {
        fprintf(stderr, "Failed to initialize REST server!\n");
        return -1;
    }

    ulfius_add_endpoint_by_val(&instance, "GET", "/clients", NULL, 0, &rest_clients_cb, lwm2m);
    ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/clients/:id", 0, &rest_clients_id_cb, lwm2m);

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

        res = lwm2m_step(lwm2m, &tv.tv_sec);
        if (res)
        {
            fprintf(stderr, "lwm2m_step() error: %d\n", res);
        }

        res = select(FD_SETSIZE, &readfds, NULL, NULL, &tv);
        if (res < 0)
        {
            fprintf(stderr, "select() error: %d\n", res);
        }

        if (FD_ISSET(sock, &readfds))
        {
            socket_receive(lwm2m, sock);
        }

    }

    ulfius_stop_framework(&instance);
    ulfius_clean_instance(&instance);
}
