
#include <string.h>

#include "restserver.h"


static void rest_observe_cb(uint16_t clientID, lwm2m_uri_t *uriP, int count, lwm2m_media_type_t format,
                          uint8_t *data, int dataLength, void *context)
{
    rest_async_context_t *ctx = (rest_async_context_t *)context;
    rest_async_cookie_t *cookie;

    fprintf(stdout, "[OBSERVE-RESPONSE] id=%s count=%d data=%p\n", ctx->cookie->id, count, data);

    cookie = rest_async_cookie_clone(ctx->cookie);
    if (cookie == NULL)
    {
        fprintf(stdout, "[OBSERVE-RESPONSE] Error! Failed to clone a cookie.\n");
        return;
    }

    // Where data is NULL, the count parameter represents CoAP error code
    rest_async_cookie_set(cookie, 
            (data == NULL) ? coap_to_http_status(count) : HTTP_200_OK,
            data, dataLength);

    rest_add_async_response(ctx->rest, cookie);
}

int rest_subscriptions_put_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    rest_context_t *rest = (rest_context_t *)context;
    const char *name;
    lwm2m_client_t *client;
    char path[100];
    size_t len;
    lwm2m_uri_t uri;
    json_t *jresponse;
    lwm2m_observation_t *targetP;
    rest_async_context_t *async_context = NULL;
    int res;

    /*
     * IMPORTANT!!! Error handling is split into two parts:
     * First, validate client request and, in case of an error, fail fast and
     * return any related 4xx code.
     * Second, once the request is validated, start allocating neccessary
     * resources and, in case of an error, jump (goto) to cleanup section at
     * the end of the function.
     */

    /* Find requested client */
    name = u_map_get(req->map_url, "name");
    client = rest_endpoints_find_client(rest->lwm2m->clientList, name);
    if (client == NULL)
    {
        ulfius_set_empty_body_response(resp, 404);
        return U_CALLBACK_CONTINUE;
    }

    /* Reconstruct and validate client path */
    len = snprintf(path, sizeof(path), "/subscriptions/%s/", name);

    if (req->http_url == NULL || strlen(req->http_url) >= sizeof(path) || len >= sizeof(path))
    {
        fprintf(stderr, "%s(): invalid http request (%s)!\n", __func__, req->http_url);
        return U_CALLBACK_ERROR;
    }

    // this is probaly redundant if there's only one matching ulfius filter
    if (strncmp(path, req->http_url, len) != 0)
    {
        ulfius_set_empty_body_response(resp, 404);
        return U_CALLBACK_CONTINUE;
    }

    /* Extract and convert resource path */
    strcpy(path, &req->http_url[len-1]);

    if (lwm2m_stringToUri(path, strlen(path), &uri) == 0)
    {
        ulfius_set_empty_body_response(resp, 404);
        return U_CALLBACK_CONTINUE;
    }

    /*
     * IMPORTANT! This is where server-error section starts and any error must
     * go through the cleanup section. See comment above.
     */
    const int err = U_CALLBACK_ERROR;

    // Search for existing registrations to prevent duplicates
    for (targetP = client->observationList; targetP != NULL; targetP = targetP->next)
    {
        if (targetP->uri.objectId == uri.objectId
         && targetP->uri.flag == uri.flag
         && targetP->uri.instanceId == uri.instanceId
         && targetP->uri.resourceId == uri.resourceId)
        {
            async_context = targetP->userData;
            break;
        }
    }

    if (async_context == NULL)
    {
        /* Create response callback context and async-response cookie */
        async_context = malloc(sizeof(rest_async_context_t));
        if (async_context == NULL)
        {
            goto exit;
        }

        async_context->rest = rest;
        async_context->cookie = rest_async_cookie_new();
        if (async_context->cookie == NULL)
        {
            goto exit;
        }

        res = lwm2m_observe(
                rest->lwm2m, client->internalID, &uri,
                rest_observe_cb, async_context
        );
        if (res != 0)
        {
            goto exit;
        }

        rest->observeList = REST_LIST_ADD(rest->observeList, async_context->cookie);
    }

    jresponse = json_object();
    json_object_set_new(jresponse, "async-response-id", json_string(async_context->cookie->id));
    ulfius_set_json_body_response(resp, 202, jresponse);

    return U_CALLBACK_CONTINUE;

exit:
    if (err == U_CALLBACK_ERROR)
    {
        if (async_context != NULL)
        {
            if (async_context->cookie != NULL)
            {
                free(async_context->cookie);
            }
            free(async_context);
        }
    }

    return err;
}

