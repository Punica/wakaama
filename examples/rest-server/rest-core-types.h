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

#ifndef REST_CORE_TYPES_H
#define REST_CORE_TYPES_H

#include <stdint.h>
#include <stdlib.h>

#include "rest-list.h"


typedef struct
{
    rest_list_t list;
    time_t timestamp;
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


rest_async_response_t *rest_async_response_new(void);

rest_async_response_t *rest_async_response_clone(const rest_async_response_t *resp);

void rest_async_response_delete(rest_async_response_t *response);

int rest_async_response_set(rest_async_response_t *resp, int status,
                            const uint8_t *payload, size_t length);


rest_notif_registration_t *rest_notif_registration_new(void);

void rest_notif_registration_delete(rest_notif_registration_t *registration);

int rest_notif_registration_set(rest_notif_registration_t *registration, const char *name);


rest_notif_update_t *rest_notif_update_new(void);

void rest_notif_update_delete(rest_notif_update_t *update);

int rest_notif_update_set(rest_notif_update_t *update, const char *name);


rest_notif_deregistration_t *rest_notif_deregistration_new(void);

void rest_notif_deregistration_delete(rest_notif_deregistration_t *deregistration);

int rest_notif_deregistration_set(rest_notif_deregistration_t *deregistration, const char *name);

#endif // REST_CORE_TYPES_H

