
#include <string.h>

#include "restserver.h"


void rest_notify_registration(rest_context_t *rest, rest_notif_registration_t *reg)
{
    rest->registrationList = REST_LIST_ADD(rest->registrationList, reg);
}

void rest_notify_update(rest_context_t *rest, rest_notif_update_t *update)
{
    rest->updateList = REST_LIST_ADD(rest->updateList, update);
}

void rest_notify_deregistration(rest_context_t *rest, rest_notif_deregistration_t *dereg)
{
    rest->deregistrationList = REST_LIST_ADD(rest->deregistrationList, dereg);
}

void rest_notify_timeout(rest_context_t *rest, rest_notif_timeout_t *timeout)
{
    rest->timeoutList = REST_LIST_ADD(rest->timeoutList, timeout);
}

void rest_notify_async_response(rest_context_t *rest, rest_notif_async_response_t *resp)
{
    rest->asyncResponseList = REST_LIST_ADD(rest->asyncResponseList, resp);
}

json_t * rest_async_response_to_json(rest_async_response_t *async)
{
    json_t *jasync = json_object();

    json_object_set_new(jasync, "id", json_string(async->id));
    json_object_set_new(jasync, "status", json_integer(async->status));
    json_object_set_new(jasync, "payload", json_string(async->payload));

    return jasync;
}

int rest_step(rest_context_t *rest, struct timeval *tv)
{
    ulfius_req_t request;
    ulfius_resp_t response;
    rest_async_response_t *async;
    json_t *jbody;
    json_t *jasync;
    int res;

    if (rest->asyncResponseList != NULL && rest->callback != NULL)
    {
        const char *url = json_string_value(json_object_get(rest->callback, "url"));
        
        fprintf(stdout, "[CALLBACK] Sending to %s\n", url);

        jbody = json_object();
        jasync = json_array();
        REST_LIST_FOREACH(rest->asyncResponseList, async)
        {
            json_array_append(jasync, rest_async_response_to_json(async));
        }
        json_object_set_new(jbody, "async-responses", jasync);


        ulfius_init_request(&request);
        request.http_verb = strdup("PUT");
        request.http_url = strdup(url);
        request.timeout = 20;
        // TODO: add headers

        ulfius_set_json_body_request(&request, jbody);
        json_decref(jbody);

        ulfius_init_response(&response);
        res = ulfius_send_http_request(&request, &response);
        if (res == U_OK) 
        {
            // Cleanup responses only when succesfully sent
            while (rest->asyncResponseList != NULL)
            {
                async = rest->asyncResponseList;
                rest->asyncResponseList = REST_LIST_RM(rest->asyncResponseList, async);
                rest_async_response_delete(async);
            }
        }

        ulfius_clean_request(&request);
        ulfius_clean_response(&response);
    }

    return 0;
}

