
#ifndef RESTSERVER_H
#define RESTSERVER_H

#include <liblwm2m.h>
#include <ulfius.h>


typedef struct _u_request ulfius_req_t;
typedef struct _u_response ulfius_resp_t;

typedef struct
{
    void *next;
} rest_list_t;

typedef struct
{
    rest_list_t list;
    char id[40];
    int status;
    const char *payload;
} rest_async_cookie_t;

typedef struct
{
    lwm2m_context_t *lwm2m;
    rest_async_cookie_t *pendingResponseList;
    rest_async_cookie_t *completedResponseList;
    json_t *callback;
} rest_context_t;

typedef struct
{
    rest_context_t *rest;
    rest_async_cookie_t *cookie;
} rest_async_context_t;

rest_list_t * rest_list_add(rest_list_t *head, rest_list_t *node);

rest_list_t * rest_list_remove(rest_list_t *head, rest_list_t *node);

#define REST_LIST_ADD(H, N) (typeof(H))rest_list_add((rest_list_t *)(H), (rest_list_t *)(N))
#define REST_LIST_RM(H, N) (typeof(H))rest_list_remove((rest_list_t *)(H), (rest_list_t *)(N))
#define REST_LIST_FOREACH(H, I) for ((I)=(H); (I) != NULL; (I)=((rest_list_t *)(I))->next)


lwm2m_client_t * rest_endpoints_find_client(lwm2m_client_t *list, const char *name);

int rest_endpoints_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_endpoints_name_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_resources_rwe_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);


json_t * rest_async_to_json(rest_async_cookie_t *async);

int rest_notifications_put_callback_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_notifications_pull_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_step(rest_context_t *rest, struct timeval *tv);

#endif // RESTSERVER_H

