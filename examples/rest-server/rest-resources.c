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

#include <assert.h>
#include <b64/cencode.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <linux/random.h>

#include "restserver.h"


typedef struct
{
    rest_context_t *rest;
    rest_async_response_t *response;
} rest_async_context_t;

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
    int err;

    fprintf(stdout, "[ASYNC-RESPONSE] id=%s status=%d\n", ctx->response->id, coap_to_http_status(status));

    rest_list_remove(ctx->rest->pendingResponseList, ctx->response);

    err = rest_async_response_set(ctx->response, coap_to_http_status(status), data, dataLength);
    assert(err == 0);

    rest_notify_async_response(ctx->rest, ctx->response);

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
    int length;
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
        return U_CALLBACK_COMPLETE;
    }

    if ((action == RES_ACTION_WRITE) || (action == RES_ACTION_EXEC))
    {
        format = http_to_coap_format(u_map_get_case(req->map_header, "Content-Type"));
        if (format == -1)
        {
            ulfius_set_empty_body_response(resp, 415);
            return U_CALLBACK_COMPLETE;
        }
    }

    /* Find requested client */
    name = u_map_get(req->map_url, "name");
    rest_lock(rest);
    client = rest_endpoints_find_client(rest->lwm2m->clientList, name);
    rest_unlock(rest);
    if (client == NULL)
    {
        ulfius_set_empty_body_response(resp, 410);
        return U_CALLBACK_COMPLETE;
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
        return U_CALLBACK_COMPLETE;
    }

    /* Extract and convert resource path */
    strcpy(path, &req->http_url[len-1]);

    if (lwm2m_stringToUri(path, strlen(path), &uri) == 0)
    {
        ulfius_set_empty_body_response(resp, 404);
        return U_CALLBACK_COMPLETE;
    }

    /*
     * IMPORTANT! This is where server-error section starts and any error must
     * go through the cleanup section. See comment above.
     */
    const int err = U_CALLBACK_ERROR;

    rest_lock(rest);

    // Duplicated check just in case client was removed while rest was unlocked
    client = rest_endpoints_find_client(rest->lwm2m->clientList, name);
    if (client == NULL)
    {
        goto exit;
    }

    /* Create response callback context and async response */
    async_context = malloc(sizeof(rest_async_context_t));
    if (async_context == NULL)
    {
        goto exit;
    }

    async_context->rest = rest;
    async_context->response = rest_async_response_new();
    if (async_context->response == NULL)
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
    rest_list_add(rest->pendingResponseList, async_context->response);

    jresponse = json_object();
    json_object_set_new(jresponse, "async-response-id", json_string(async_context->response->id));
    ulfius_set_json_body_response(resp, 202, jresponse);
    json_decref(jresponse);

    rest_unlock(rest);

    return U_CALLBACK_COMPLETE;

exit:
    if (err == U_CALLBACK_ERROR)
    {
        if (async_context != NULL)
        {
            if (async_context->response != NULL)
            {
                free(async_context->response);
            }
            free(async_context);
        }

        if (payload != NULL)
        {
            free(payload);
        }
    }

    rest_unlock(rest);

    return err;
}

