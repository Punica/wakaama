
#include <assert.h>
#include <b64/cencode.h>
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

rest_async_cookie_t * rest_async_cookie_new(void)
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

    snprintf(cookie->id, sizeof(cookie->id), "%u#%04x%04x-%04x-%04x-%04x-%04x",
            ts, r[0], r[1], r[2], r[3], r[4], r[5]);

    return cookie;
}

rest_async_cookie_t * rest_async_cookie_clone(const rest_async_cookie_t * cookie)
{
    rest_async_cookie_t *clone;

    clone = rest_async_cookie_new();
    if (clone == NULL)
    {
        return NULL;
    }

    memcpy(clone->id, cookie->id, sizeof(clone->id));

    // XXX: should the payload be cloned?

    return clone;
}

void rest_async_cookie_destroy(rest_context_t *rest, rest_async_cookie_t *cookie)
{
    if (cookie->payload != NULL)
    {
        free((void *)cookie->payload);
    }

    free(cookie);
}

const char * base64_encode(const uint8_t *data, size_t length)
{
    char *buffer, *out;
    size_t lenb64 = ((length + 2) / 3) * 4 + 1; // +1 for null-terminator
    base64_encodestate state;

    buffer = malloc(lenb64);
    if (buffer == NULL)
    {
        return NULL;
    }

    base64_init_encodestate(&state);
    out = buffer;
    out += base64_encode_block(data, length, out, &state);
    out += base64_encode_blockend(out, &state);
    out[-1] = '\0'; // replace '\n' with null-terminator

    assert((out - buffer) <= lenb64);

    return buffer;
}

int rest_async_cookie_set(rest_async_cookie_t *cookie, int status,
                          const uint8_t *payload, size_t length)
{
    if (cookie->payload != NULL)
    {
        free((void *)cookie->payload);
        cookie->payload = NULL;
    }

    cookie->payload = base64_encode(payload, length);
    if (cookie->payload == NULL)
    {
        return -1;
    }

    cookie->status = status;

    return 0;
}

int coap_to_http_status(int status)
{
    switch (status)
    {
    case COAP_204_CHANGED:
    case COAP_205_CONTENT:
        return HTTP_200_OK;

    case COAP_404_NOT_FOUND:
        return HTTP_404_NOT_FOUND;

    default:
        return -(((status >> 5) & 0x7) * 100 +  (status & 0x1F));
    }
}

static int http_to_coap_format(const char *type)
{
    if (type == NULL)
        return -1;

    if (strcmp(type, "application/vnd.oma.lwm2m+tlv") == 0)
        return LWM2M_CONTENT_TLV;

    if (strcmp(type, "application/vnd.oma.lwm2m+json") == 0)
        return LWM2M_CONTENT_JSON;

    if (strcmp(type, "application/octet-stream") == 0)
        return LWM2M_CONTENT_OPAQUE;

    return -1;
}

static void rest_async_cb(uint16_t clientID, lwm2m_uri_t *uriP, int status, lwm2m_media_type_t format,
                          uint8_t *data, int dataLength, void *context)
{
    rest_async_context_t *ctx = (rest_async_context_t *)context;
    const char *payload;
    int err;

    fprintf(stdout, "[ASYNC-RESPONSE] id=%s status=%d\n", ctx->cookie->id, coap_to_http_status(status));

    ctx->rest->pendingResponseList = REST_LIST_RM(ctx->rest->pendingResponseList, ctx->cookie);

    err = rest_async_cookie_set(ctx->cookie, coap_to_http_status(status), data, dataLength);
    assert(err == 0);

    ctx->rest->completedResponseList = REST_LIST_ADD(ctx->rest->completedResponseList, ctx->cookie);

    // Free rest_async_context_t which was allocated in rest_resources_read_cb
    free(context);
}

int rest_resources_rwe_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    rest_context_t *rest = (rest_context_t *)context;
    enum {
        RES_ACTION_UNDEFINED,
        RES_ACTION_READ,
        RES_ACTION_WRITE,
        RES_ACTION_EXEC,
    } action = RES_ACTION_UNDEFINED;
    const char *name;
    lwm2m_client_t *client;
    char path[100];
    size_t len;
    lwm2m_uri_t uri;
    json_t *jresponse;
    rest_async_context_t *async_context = NULL;
    lwm2m_media_type_t format;
    uint8_t *payload = NULL;
    int size, length;
    int res;

    /*
     * IMPORTANT!!! Error handling is split into two parts:
     * First, validate client request and, in case of an error, fail fast and
     * return any related 4xx code.
     * Second, once the request is validated, start allocating neccessary
     * resources and, in case of an error, jump (goto) to cleanup section at
     * the end of the function.
     */

    if (strcmp(req->http_verb, "GET") == 0)
    {
        fprintf(stdout, "[READ-REQUEST] %s\n", req->http_url);
        action = RES_ACTION_READ;
    }
    else if (strcmp(req->http_verb, "PUT") == 0)
    {
        fprintf(stdout, "[WRITE-REQUEST] %s\n", req->http_url);
        action = RES_ACTION_WRITE;
    }
    else if (strcmp(req->http_verb, "POST") == 0)
    {
        fprintf(stdout, "[EXEC-REQUEST] %s\n", req->http_url);
        action = RES_ACTION_EXEC;
    }
    else
    {
        ulfius_set_empty_body_response(resp, 405);
        return U_CALLBACK_CONTINUE;
    }

    if ((action == RES_ACTION_WRITE) || (action == RES_ACTION_EXEC))
    {
        format = http_to_coap_format(u_map_get_case(req->map_header, "Content-Type"));
        if (format == -1)
        {
            ulfius_set_empty_body_response(resp, 415);
            return U_CALLBACK_CONTINUE;
        }
    }

    /* Find requested client */
    name = u_map_get(req->map_url, "name");
    client = rest_endpoints_find_client(rest->lwm2m->clientList, name);
    if (client == NULL)
    {
        ulfius_set_empty_body_response(resp, 410);
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

    switch (action)
    {
    case RES_ACTION_READ:
        res = lwm2m_dm_read(
                rest->lwm2m, client->internalID, &uri,
                rest_async_cb, async_context
        );
        if (res != 0)
        {
            goto exit;
        }
        break;

    case RES_ACTION_WRITE:
    case RES_ACTION_EXEC:
#if 1
        payload = malloc(req->binary_body_length);
        if (payload == NULL)
        {
            goto exit;
        }
        length = req->binary_body_length;
        memcpy(payload, req->binary_body, length);
#else
        // XXX: should content format be converted to TLV?
        format = LWM2M_CONTENT_JSON;
        size = lwm2m_data_parse(&uri, req->binary_body, req->binary_body_length, format, &data);
        if (size < 1 || data == NULL)
        {
            goto exit;
        }

        format = LWM2M_CONTENT_TLV;
        length = lwm2m_data_serialize(&uri, size, data, &format, &payload);
        if (length < 1 || payload == NULL || format != LWM2M_CONTENT_TLV)
        {
            goto exit;
        }
#endif
        if (action == RES_ACTION_WRITE)
        {
            res = lwm2m_dm_write(
                    rest->lwm2m, client->internalID, &uri,
                    format, payload, length,
                    rest_async_cb, async_context
            );
        }
        else if (action == RES_ACTION_EXEC)
        {
            res = lwm2m_dm_execute(
                    rest->lwm2m, client->internalID, &uri,
                    format, payload, length,
                    rest_async_cb, async_context
            );
        }
        else
        {
            assert(false); // fail-fast on unhandled action
        }

        if (res != 0)
        {
            goto exit;
        }
        break;

    default:
        assert(false); // if this happens, there's an error in the logic
        break;
    }
    rest->pendingResponseList = REST_LIST_ADD(rest->pendingResponseList, async_context->cookie);

    jresponse = json_object();
    json_object_set_new(jresponse, "async-response-id", json_string(async_context->cookie->id));
    ulfius_set_json_body_response(resp, 202, jresponse);
    json_decref(jresponse);

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

        if (payload != NULL)
        {
            free(payload);
        }
    }

    return err;
}

