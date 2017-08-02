
#include "restserver.h"


static json_t * endpoint_to_json(lwm2m_client_t *client)
{
    bool queue;

    switch (client->binding)
    {
    case BINDING_UQ:
    case BINDING_SQ:
    case BINDING_UQS:
        queue = true;
        break;
    default:
        queue = false;
        break;
    }

    json_t *jclient = json_object();
    json_object_set_new(jclient, "name", json_string(client->name));
    json_object_set_new(jclient, "status", json_string("ACTIVE"));
    json_object_set_new(jclient, "q", json_boolean(queue));

    return jclient;
}

static json_t * endpoint_resources_to_json(lwm2m_client_t *client)
{
    lwm2m_client_object_t *obj;
    lwm2m_list_t *ins;
    char buf[20]; // 13 bytes should be enough (i.e. max string "/65535/65535\0")

    json_t *jobjects = json_array();
    for (obj = client->objectList; obj != NULL; obj = obj->next)
    {
        if (obj->instanceList == NULL)
        {
            snprintf(buf, sizeof(buf), "/%d", obj->id);
            json_t *jobject = json_object();
            json_object_set_new(jobject, "uri", json_string(buf));
            json_array_append_new(jobjects, jobject);
        }
        else
        {
            for (ins = obj->instanceList; ins != NULL; ins = ins->next)
            {
                snprintf(buf, sizeof(buf), "/%d/%d", obj->id, ins->id);
                json_t *jobject = json_object();
                json_object_set_new(jobject, "uri", json_string(buf));
                json_array_append_new(jobjects, jobject);
            }
        }
    }

    return jobjects;
}

lwm2m_client_t * rest_endpoints_find_client(lwm2m_client_t *list, const char *name)
{
    lwm2m_client_t *client;

    if (name == NULL)
        return NULL;

    for (client = list; client != NULL; client = client->next)
    {
        if (strcmp(client->name, name) == 0)
        {
            return client;
        }
    }

    return NULL;
}

int rest_endpoints_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    rest_context_t *rest = (rest_context_t *)context;
    lwm2m_client_t *client;

    json_t *jclients = json_array();
    for (client = rest->lwm2m->clientList; client != NULL; client = client->next)
    {
        json_array_append_new(jclients, endpoint_to_json(client));
    }

    ulfius_set_json_body_response(resp, 200, jclients);
    return U_CALLBACK_CONTINUE;
}

int rest_endpoints_name_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    rest_context_t *rest = (rest_context_t *)context;
    lwm2m_client_t *client;
    const char *name = u_map_get(req->map_url, "name");

    client = rest_endpoints_find_client(rest->lwm2m->clientList, name);
    if (client == NULL)
    {
        ulfius_set_string_body_response(resp, 404, "");
        return U_CALLBACK_CONTINUE;
    }

    ulfius_set_json_body_response(resp, 200, endpoint_resources_to_json(client));
    return U_CALLBACK_CONTINUE;
}

