
#ifndef RESTSERVER_H
#define RESTSERVER_H

#include <liblwm2m.h>
#include <ulfius.h>

#include "http_codes.h"
#include "rest-core-types.h"


typedef struct _u_request ulfius_req_t;
typedef struct _u_response ulfius_resp_t;

typedef struct
{
    lwm2m_context_t *lwm2m;

    // rest-core
    json_t *callback;

    // rest-notifications
    rest_notif_registration_t   *registrationList;
    rest_notif_update_t         *updateList;
    rest_notif_deregistration_t *deregistrationList;
    rest_notif_timeout_t        *timeoutList;
    rest_notif_async_response_t *asyncResponseList;

    // rest-resources
    rest_async_response_t *pendingResponseList;

    // rest-subsciptions
    rest_async_response_t *observeList;
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

int rest_notifications_put_callback_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_notifications_pull_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_subscriptions_put_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_step(rest_context_t *rest, struct timeval *tv);

#endif // RESTSERVER_H

