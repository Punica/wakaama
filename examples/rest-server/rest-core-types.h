
#ifndef REST_CORE_TYPES_H
#define REST_CORE_TYPES_H

#include <stdint.h>
#include <stdlib.h>

#include "rest-list.h"


typedef struct
{
    rest_list_t list;
    char id[40];
    int status;
    const char *payload;
} rest_notif_async_response_t;

typedef rest_notif_async_response_t rest_async_response_t;

typedef struct
{
    rest_list_t list;
    const char *name;
} rest_notif_registration_t;

typedef struct
{
    rest_list_t list;
    const char *name;
} rest_notif_update_t;

typedef struct
{
    rest_list_t list;
    const char *name;
} rest_notif_deregistration_t;

typedef struct
{
    rest_list_t list;
    const char *name;
} rest_notif_timeout_t;


rest_async_response_t * rest_async_response_new(void);

rest_async_response_t * rest_async_response_clone(const rest_async_response_t *resp);

void rest_async_response_delete(rest_async_response_t *response);

int rest_async_response_set(rest_async_response_t *resp, int status, const uint8_t *payload, size_t length);

#endif // REST_CORE_TYPES_H

