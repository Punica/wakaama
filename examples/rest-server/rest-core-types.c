
#include "rest-core-types.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

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

rest_async_response_t * rest_async_response_new(void)
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

rest_async_response_t * rest_async_response_clone(const rest_async_response_t * response)
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

const char * base64_encode(const uint8_t *data, size_t length)
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
    out += base64_encode_block(data, length, out, &state);
    out += base64_encode_blockend(out, &state);
    out[-1] = '\0'; // replace '\n' with null-terminator

    assert((out - buffer) <= lenb64);

    return buffer;
}

int rest_async_response_set(rest_async_response_t *response, int status,
                          const uint8_t *payload, size_t length)
{
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

