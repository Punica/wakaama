
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <linux/random.h>

#include "restserver.h"


int rest_getrandom(void *buf, size_t buflen)
{
    FILE *f;
    size_t len;
   
    f = fopen("/dev/urandom", "r");
    if (f == NULL)
    {
        return -1;
    }

    len = fread(buf, 1, buflen, f);
    fclose(f);
    return len;
}

rest_async_cookie_t * rest_async_cookie_create(rest_context_t *rest)
{
    rest_async_cookie_t *cookie;
    uint32_t ts;
    uint16_t r[6];

    cookie = malloc(sizeof(rest_async_cookie_t));
    if (cookie == NULL)
    {
        return NULL;
    }
    memset(cookie, 0, sizeof(rest_async_cookie_t));

    ts = time(NULL);
    if (rest_getrandom(r, sizeof(r)) != sizeof(r))
    {
        return NULL;
    }

    snprintf(cookie->id, sizeof(cookie->id), "%u#%02x%02x-%02x-%02x-%02x-%02x",
            ts, r[0], r[1], r[2], r[3], r[4], r[5]);

    rest->pendingResponseList = REST_LIST_ADD(rest->pendingResponseList, cookie);

    return cookie;
}

void rest_async_cookie_destroy(rest_context_t *rest, rest_async_cookie_t *cookie)
{
    if (cookie->payload != NULL)
    {
        free((void *)cookie->payload);
    }

    free(cookie);
}

int rest_async_cookie_complete(rest_context_t *rest, rest_async_cookie_t *cookie,
                               int status, const char *payload)
{
    rest->pendingResponseList = REST_LIST_RM(rest->pendingResponseList, cookie);

    cookie->status = status;
    cookie->payload = payload;

    rest->completedResponseList = REST_LIST_ADD(rest->completedResponseList, cookie);
}

static int coap_to_http_status(int status)
{
    // This is not logically correct, only visually
    return ((status >> 5) & 0x7) * 100 +  (status & 0x1F);
}

static void rest_async_cb(uint16_t clientID, lwm2m_uri_t *uriP, int status, lwm2m_media_type_t format,
                          uint8_t *data, int dataLength, void *context)
{
    rest_async_context_t *ctx = (rest_async_context_t *)context;
    char *payload;

    fprintf(stdout, "[ASYNC-RESPONSE] id=%s status=%d\n", ctx->cookie->id, coap_to_http_status(status));

    payload = malloc(dataLength+1);
    assert(payload != NULL); // fail-fast or implement a way to indicate internal server error
    // TODO: base64 encode the payload
    memcpy(payload, data, dataLength);
    payload[dataLength] = '\0';

    rest_async_cookie_complete(ctx->rest, ctx->cookie, coap_to_http_status(status), payload);

    // Free rest_async_context_t which was allocated in rest_resources_read_cb
    free(context);
}

int rest_resources_read_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    rest_context_t *rest = (rest_context_t *)context;
    int err = U_CALLBACK_CONTINUE;
    const char *name;
    lwm2m_client_t *client;
    char path[100];
    size_t len;
    lwm2m_uri_t uri;
    json_t *jresponse;
    rest_async_context_t *async_context;

    fprintf(stdout, "[READ-REQUEST] %s\n", req->http_url);

    /* Find requested client */
    name = u_map_get(req->map_url, "name");
    client = rest_endpoints_find_client(rest->lwm2m->clientList, name);
    if (client == NULL)
    {
        ulfius_set_string_body_response(resp, 404, "");
        return U_CALLBACK_CONTINUE;
    }

    /* Reconstruct and validate client path */
    len = snprintf(path, sizeof(path), "/endpoints/%s/", name);

    if (req->http_url == NULL || strlen(req->http_url) >= sizeof(path) || len >= sizeof(path))
    {
        fprintf(stderr, "%s(): invalid http request (%s)!\n", __func__, req->http_url);
        return U_CALLBACK_ERROR;
    }

    // this is probaly redundant if there's only one matching ulfius filter
    if (strncmp(path, req->http_url, len) != 0)
    {
        return U_CALLBACK_CONTINUE;
    }

    /* Extract and convert resource path */
    strcpy(path, &req->http_url[len-1]);

    if (lwm2m_stringToUri(path, strlen(path), &uri) == 0)
    {
       return U_CALLBACK_CONTINUE;
    }

    /* Create response callback context and async-response cookie */
    async_context = malloc(sizeof(rest_async_context_t));
    if (async_context == NULL)
    {
        err = U_CALLBACK_ERROR;
        goto exit;
    }

    async_context->rest = rest;
    async_context->cookie = rest_async_cookie_create(rest);
    if (async_context->cookie == NULL)
    {
        err = U_CALLBACK_ERROR;
        goto exit;
    }

    if (lwm2m_dm_read(rest->lwm2m, client->internalID, &uri, rest_async_cb, async_context) != 0)
    {
        err = U_CALLBACK_CONTINUE;
        goto exit;
    }

    jresponse = json_object();
    json_object_set_new(jresponse, "async-response-id", json_string(async_context->cookie->id));
    ulfius_set_json_body_response(resp, 200, jresponse);

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

