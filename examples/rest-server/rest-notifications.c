
#include "restserver.h"


json_t * rest_async_to_json(rest_async_cookie_t *async)
{
    json_t *jasync = json_object();

    json_object_set_new(jasync, "id", json_string(async->id));
    json_object_set_new(jasync, "status", json_integer(async->status));
    json_object_set_new(jasync, "payload", json_string(async->payload));

    return jasync;
}

bool valid_callback_url(const char *url)
{
    // TODO: implement
    return true;
}

bool validate_callback(json_t *jcallback)
{
    json_t *url, *headers;
    const char *key;
    json_t *value;

    if (jcallback == NULL)
    {
        return false;
    }

    // Must be an object with "url" and "headers"
    if (!json_is_object(jcallback) || json_object_size(jcallback) != 2)
    {
        return false;
    }

    // "url" must be a string with valid url
    url = json_object_get(jcallback, "url");
    if (!json_is_string(url) || !valid_callback_url(json_string_value(url)))
    {
        return false;
    }

    // "header" must be an object...
    headers = json_object_get(jcallback, "headers");
    if (!json_is_object(headers))
    {
        return false;
    }

    // ... which contains string key-value pairs
    json_object_foreach(headers, key, value)
    {
        // TODO: validate key and value strings
        if (!json_is_string(value))
        {
            return false;
        }
    }

    return true;
}

int rest_notifications_put_callback_cb(const ulfius_req_t *req, ulfius_resp_t *resp,
        void *context)
{
    rest_context_t *rest = (rest_context_t *)context;
    const char *ct;
    json_t *jcallback;

    ct = u_map_get_case(req->map_header, "Content-Type");
    if (ct == NULL || strcmp(ct, "application/json") != 0)
    {
        ulfius_set_empty_body_response(resp, 415);
        return U_CALLBACK_CONTINUE;
    }

    jcallback = json_loadb(req->binary_body, req->binary_body_length, 0, NULL);
    if (!validate_callback(jcallback))
    {
        ulfius_set_empty_body_response(resp, 400);
        return U_CALLBACK_CONTINUE;
    }

    fprintf(stdout, "[SET-CALLBACK] url=%s\n", json_string_value(json_object_get(jcallback, "url")));

    if (rest->callback != NULL)
    {
        json_decref(rest->callback);
        rest->callback = NULL;
    }

    rest->callback = jcallback;

    return U_CALLBACK_CONTINUE;
}

int rest_notifications_pull_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    rest_context_t *rest = (rest_context_t *)context;
    json_t *jbody = json_object();
    rest_async_cookie_t *async;

    if (rest->completedResponseList != NULL)
    {
        json_t *jasync = json_array();

        REST_LIST_FOREACH(rest->completedResponseList, async)
        {
            json_array_append_new(jasync, rest_async_to_json(async));
        }

        json_object_set_new(jbody, "async-responses", jasync);


        while (rest->completedResponseList != NULL)
        {
            async = rest->completedResponseList;
            rest->completedResponseList = REST_LIST_RM(rest->completedResponseList, async);
            rest_async_cookie_destroy(rest, async);
        }
    }

    ulfius_set_json_body_response(resp, 200, jbody);

    return U_CALLBACK_CONTINUE;
}

