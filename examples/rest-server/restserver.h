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

#ifndef RESTSERVER_H
#define RESTSERVER_H

#include <liblwm2m.h>
#include <ulfius.h>

#include "http_codes.h"
#include "rest-core-types.h"
#include "rest-utils.h"


typedef struct _u_request ulfius_req_t;
typedef struct _u_response ulfius_resp_t;

typedef struct
{
    pthread_mutex_t mutex;

    lwm2m_context_t *lwm2m;

    // rest-core
    json_t *callback;

    // rest-notifications
    rest_list_t *registrationList;
    rest_list_t *updateList;
    rest_list_t *deregistrationList;
    rest_list_t *timeoutList;
    rest_list_t *asyncResponseList;

    // rest-resources
    rest_list_t *pendingResponseList;

    // rest-subsciptions
    rest_list_t *observeList;
} rest_context_t;

lwm2m_client_t * rest_endpoints_find_client(lwm2m_client_t *list, const char *name);

int rest_endpoints_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_endpoints_name_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_resources_rwe_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);


void rest_notify_registration(rest_context_t *rest, rest_notif_registration_t *reg);
void rest_notify_update(rest_context_t *rest, rest_notif_update_t *update);
void rest_notify_deregistration(rest_context_t *rest, rest_notif_deregistration_t *dereg);
void rest_notify_timeout(rest_context_t *rest, rest_notif_timeout_t *timeout);
void rest_notify_async_response(rest_context_t *rest, rest_notif_async_response_t *resp);

json_t * rest_notifications_json(rest_context_t *rest);

void rest_notifications_clear(rest_context_t *rest);

int rest_notifications_get_callback_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);
int rest_notifications_put_callback_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_notifications_pull_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_subscriptions_put_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);
int rest_subscriptions_delete_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

void rest_init(rest_context_t *rest);
void rest_cleanup(rest_context_t *rest);
int rest_step(rest_context_t *rest, struct timeval *tv);

void rest_lock(rest_context_t *rest);
void rest_unlock(rest_context_t *rest);

#endif // RESTSERVER_H

