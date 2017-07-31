
#ifndef RESTSERVER_H
#define RESTSERVER_H

#include <liblwm2m.h>
#include <ulfius.h>


typedef struct _u_request ulfius_req_t;
typedef struct _u_response ulfius_resp_t;

typedef struct
{
    lwm2m_context_t *lwm2m;
} rest_context_t;

int rest_endpoints_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_endpoints_name_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

#endif // RESTSERVER_H

