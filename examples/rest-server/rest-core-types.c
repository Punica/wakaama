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

#include "rest-core-types.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <liblwm2m.h>


static const char *base64_table =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t rest_get_random(void *buf, size_t buflen)
{
    FILE *f;
    size_t len;

    f = fopen("/dev/urandom", "r");
    if (f == NULL)
    {
        return 0;
    }

    len = fread(buf, 1, buflen, f);
    fclose(f);
    return len;
}

rest_async_response_t *rest_async_response_new(void)
{
    rest_async_response_t *response;
    uint32_t ts;
    uint16_t r[6];

    response = malloc(sizeof(rest_async_response_t));
    if (response == NULL)
    {
        return NULL;
    }
    memset(response, 0, sizeof(rest_async_response_t));

    ts = time(NULL);
    if (rest_get_random(r, sizeof(r)) != sizeof(r))
    {
        return NULL;
    }

    snprintf(response->id, sizeof(response->id), "%u#%04x%04x-%04x-%04x-%04x-%04x",
             ts, r[0], r[1], r[2], r[3], r[4], r[5]);

    return response;
}

rest_async_response_t *rest_async_response_clone(const rest_async_response_t *response)
{
    rest_async_response_t *clone;

    clone = rest_async_response_new();
    if (clone == NULL)
    {
        return NULL;
    }

    memcpy(clone->id, response->id, sizeof(clone->id));

    // XXX: should the payload be cloned?

    return clone;
}

void rest_async_response_delete(rest_async_response_t *response)
{
    if (response->payload != NULL)
    {
        free((void *)response->payload);
    }

    free(response);
}

const char *base64_encode(const uint8_t *data, size_t length)
{
    size_t buffer_length = ((length + 2) / 3) * 4 + 1; // +1 for null-terminator
    char *buffer;
    static uint8_t previous_byte;
    int data_index = 0,
        buffer_index = 0;

    buffer = malloc(buffer_length);
    if (buffer == NULL)
    {
        return NULL;
    }

    for (data_index = 0; data_index < length; data_index++)
    {
        switch (data_index % 3)
        {
        case 2:
            buffer[buffer_index++] = base64_table[
                                         ((previous_byte & 0x0f) << 2) + ((data[data_index] & 0xc0) >> 6)
                                     ];
            buffer[buffer_index++] = base64_table[data[data_index] & 0x3f];
            break;
        case 1:
            buffer[buffer_index++] = base64_table[
                                         ((previous_byte & 0x03) << 4) + ((data[data_index] & 0xf0) >> 4)
                                     ];
            break;
        case 0:
            buffer[buffer_index++] = base64_table[(data[data_index] & 0xfc) >> 2];
            break;
        }
        previous_byte = data[data_index];
    }

    if ((data_index % 3) == 2)
    {
        buffer[buffer_index++] = base64_table[(previous_byte & 0x0f) << 2];
        buffer[buffer_index++] = '=';
    }
    else if ((data_index % 3) == 1)
    {
        buffer[buffer_index++] = base64_table[(previous_byte & 0x03) << 4];
        buffer[buffer_index++] = '=';
        buffer[buffer_index++] = '=';
    }

    buffer[buffer_index++] = '\0';

    assert(buffer_index == buffer_length);

    return buffer;
}

int rest_async_response_set(rest_async_response_t *response, int status,
                            const uint8_t *payload, size_t length)
{
    response->timestamp = lwm2m_getmillis();
    response->status = status;

    if (response->payload != NULL)
    {
        free((void *)response->payload);
        response->payload = NULL;
    }

    response->payload = base64_encode(payload, length);
    if (response->payload == NULL)
    {
        return -1;
    }

    return 0;
}

rest_notif_registration_t *rest_notif_registration_new(void)
{
    rest_notif_registration_t *registration;

    registration = malloc(sizeof(rest_notif_registration_t));
    if (registration == NULL)
    {
        return NULL;
    }

    memset(registration, 0, sizeof(rest_notif_registration_t));

    return registration;
}

void rest_notif_registration_delete(rest_notif_registration_t *registration)
{
    if (registration->name)
    {
        free((void *)registration->name);
        registration->name = NULL;
    }

    free(registration);
}

int rest_notif_registration_set(rest_notif_registration_t *registration, const char *name)
{
    if (registration->name)
    {
        free((void *)registration->name);
        registration->name = NULL;
    }

    if (name != NULL)
    {
        registration->name = strdup(name);
        if (registration->name == NULL)
        {
            return -1;
        }
    }

    return 0;
}

rest_notif_update_t *rest_notif_update_new(void)
{
    rest_notif_update_t *update;

    update = malloc(sizeof(rest_notif_update_t));
    if (update == NULL)
    {
        return NULL;
    }

    memset(update, 0, sizeof(rest_notif_update_t));

    return update;
}

void rest_notif_update_delete(rest_notif_update_t *update)
{
    if (update->name)
    {
        free((void *)update->name);
        update->name = NULL;
    }

    free(update);
}

int rest_notif_update_set(rest_notif_update_t *update, const char *name)
{
    if (update->name)
    {
        free((void *)update->name);
        update->name = NULL;
    }

    if (name != NULL)
    {
        update->name = strdup(name);
        if (update->name == NULL)
        {
            return -1;
        }
    }

    return 0;
}

rest_notif_deregistration_t *rest_notif_deregistration_new(void)
{
    rest_notif_deregistration_t *deregistration;

    deregistration = malloc(sizeof(rest_notif_deregistration_t));
    if (deregistration == NULL)
    {
        return NULL;
    }

    memset(deregistration, 0, sizeof(rest_notif_deregistration_t));

    return deregistration;
}

void rest_notif_deregistration_delete(rest_notif_deregistration_t *deregistration)
{
    if (deregistration->name)
    {
        free((void *)deregistration->name);
        deregistration->name = NULL;
    }

    free(deregistration);
}

int rest_notif_deregistration_set(rest_notif_deregistration_t *deregistration, const char *name)
{
    if (deregistration->name)
    {
        free((void *)deregistration->name);
        deregistration->name = NULL;
    }

    if (name != NULL)
    {
        deregistration->name = strdup(name);
        if (deregistration->name == NULL)
        {
            return -1;
        }
    }

    return 0;
}

