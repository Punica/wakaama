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

#include <b64/cencode.h>


int rest_getrandom(void *buf, size_t buflen)
{
    FILE *f;
    size_t len;

    f = fopen("/dev/urandom", "r");
    if (f == NULL)
    {
        return -1;
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
    if (rest_getrandom(r, sizeof(r)) != sizeof(r))
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
    char *buffer, *out;
    size_t lenb64 = ((length + 2) / 3) * 4 + 1; // +1 for null-terminator
    base64_encodestate state;

    buffer = malloc(lenb64);
    if (buffer == NULL)
    {
        return NULL;
    }

    base64_init_encodestate(&state);
    out = buffer;
    out += base64_encode_block((const char *)data, length, out, &state);
    out += base64_encode_blockend(out, &state);
    out[-1] = '\0'; // replace '\n' with null-terminator

    assert((out - buffer) <= lenb64);

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

