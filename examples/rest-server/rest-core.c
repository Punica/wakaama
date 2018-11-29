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
#include <string.h>

#include "logging.h"
#include "restserver.h"

void rest_init(rest_context_t *rest)
{
    memset(rest, 0, sizeof(rest_context_t));

    rest->registrationList = rest_list_new();
    rest->updateList = rest_list_new();
    rest->deregistrationList = rest_list_new();
    rest->timeoutList = rest_list_new();
    rest->asyncResponseList = rest_list_new();
    rest->pendingResponseList = rest_list_new();
    rest->observeList = rest_list_new();

    assert(pthread_mutex_init(&rest->mutex, NULL) == 0);
}

void rest_cleanup(rest_context_t *rest)
{
    if (rest->callback)
    {
        json_decref(rest->callback);
        rest->callback = NULL;
    }

    rest_notifications_clear(rest);
    rest_list_delete(rest->registrationList);
    rest_list_delete(rest->updateList);
    rest_list_delete(rest->deregistrationList);
    rest_list_delete(rest->timeoutList);
    rest_list_delete(rest->asyncResponseList);
    rest_list_delete(rest->pendingResponseList);
    rest_list_delete(rest->observeList);

    assert(pthread_mutex_destroy(&rest->mutex) == 0);
}

int rest_step(rest_context_t *rest, struct timeval *tv)
{
    ulfius_req_t request;
    ulfius_resp_t response;
    json_t *jbody;
    json_t *jheaders;
    json_t *value;
    const char *header;
    struct _u_map headers;
    int res;

    if ((rest->registrationList->head != NULL
         || rest->updateList->head != NULL
         || rest->deregistrationList->head != NULL
         || rest->asyncResponseList->head != NULL)
        && rest->callback != NULL)
    {
        const char *url = json_string_value(json_object_get(rest->callback, "url"));
        jheaders = json_object_get(rest->callback, "headers");
        u_map_init(&headers);
        json_object_foreach(jheaders, header, value)
        {
            u_map_put(&headers, header, json_string_value(value));
        }

        log_message(LOG_LEVEL_INFO, "[CALLBACK] Sending to %s\n", url);

        jbody = rest_notifications_json(rest);

        ulfius_init_request(&request);
        request.http_verb = strdup("PUT");
        request.http_url = strdup(url);
        request.timeout = 20;
        u_map_copy_into(request.map_header, &headers);

        ulfius_set_json_body_request(&request, jbody);
        json_decref(jbody);

        ulfius_init_response(&response);
        res = ulfius_send_http_request(&request, &response);
        if (res == U_OK)
        {
            rest_notifications_clear(rest);
        }

        u_map_clean(&headers);
        ulfius_clean_request(&request);
        ulfius_clean_response(&response);
    }

    return 0;
}

void rest_lock(rest_context_t *rest)
{
    assert(pthread_mutex_lock(&rest->mutex) == 0);
}

void rest_unlock(rest_context_t *rest)
{
    assert(pthread_mutex_unlock(&rest->mutex) == 0);
}

