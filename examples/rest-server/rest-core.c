
#include "restserver.h"

#include <string.h>


int rest_step(rest_context_t *rest, struct timeval *tv)
{
    ulfius_req_t request;
    ulfius_resp_t response;
    json_t *jbody;
    int res;

    if (rest->asyncResponseList != NULL && rest->callback != NULL)
    {
        const char *url = json_string_value(json_object_get(rest->callback, "url"));
        
        fprintf(stdout, "[CALLBACK] Sending to %s\n", url);

        jbody = rest_notifications_json(rest);

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
            rest_notifications_clear(rest);
        }

        ulfius_clean_request(&request);
        ulfius_clean_response(&response);
    }

    return 0;
}

