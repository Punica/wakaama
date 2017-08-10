
#include <string.h>

#include "restserver.h"


void rest_add_async_response(rest_context_t *rest, rest_async_cookie_t *cookie)
{
    rest->completedResponseList = REST_LIST_ADD(rest->completedResponseList, cookie);
}

int rest_step(rest_context_t *rest, struct timeval *tv)
{
    ulfius_req_t request;
    ulfius_resp_t response;
    rest_async_cookie_t *async;
    json_t *jbody;
    json_t *jasync;
    int res;

    if (rest->completedResponseList != NULL && rest->callback != NULL)
    {
        const char *url = json_string_value(json_object_get(rest->callback, "url"));
        
        fprintf(stdout, "[CALLBACK] Sending to %s\n", url);

        jbody = json_object();
        jasync = json_array();
        REST_LIST_FOREACH(rest->completedResponseList, async)
        {
            json_array_append(jasync, rest_async_to_json(async)); 
        }
        json_object_set_new(jbody, "async-responses", jasync);


        ulfius_init_request(&request);
        request.http_verb = strdup("PUT");
        request.http_url = strdup(url);
        request.timeout = 20;
        // TODO: add headers

        ulfius_set_json_body_request(&request, jbody);

        ulfius_init_response(&response);
        res = ulfius_send_http_request(&request, &response);
        if (res == U_OK) 
        {
            // Cleanup responses only when succesfully sent
            while (rest->completedResponseList != NULL)
            {
                async = rest->completedResponseList;
                rest->completedResponseList = REST_LIST_RM(rest->completedResponseList, async);
                rest_async_cookie_destroy(rest, async);
            }
        }

        ulfius_clean_request(&request);
        ulfius_clean_response(&response);
    }

    return 0;
}

