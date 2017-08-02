
#include "restserver.h"


static json_t * async_to_json(rest_async_cookie_t *async)
{
    json_t *jasync = json_object();

    json_object_set_new(jasync, "id", json_string(async->id));
    json_object_set_new(jasync, "status", json_integer(async->status));
    json_object_set_new(jasync, "payload", json_string(async->payload));

    return jasync;
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
            json_array_append_new(jasync, async_to_json(async));
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

