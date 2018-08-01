/*
 * MIT License
 *
 * Copyright (c) 2018 8devices
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

#ifndef SECURITY_H
#define SECURITY_H

#include <jwt.h>
#include <ulfius.h>
#include <stdint.h>
#include <stdbool.h>

#include "rest-list.h"

enum
{
    J_MAX_LENGTH_SECRET_KEY = 1024,
    J_MAX_LENGTH_METHOD = 8,
    J_MAX_LENGTH_URL = 2048,
    J_MAX_LENGTH_USER_NAME = 1024,
    J_MAX_LENGTH_USER_SECRET = 1024,
};

typedef enum
{
    J_OK,
    J_ERROR,
    J_ERROR_INTERNAL,
    J_ERROR_INVALID_REQUEST,
    J_ERROR_INVALID_TOKEN,
    J_ERROR_EXPIRED_TOKEN,
    J_ERROR_INSUFFICIENT_SCOPE
} jwt_error_t;

typedef struct
{
    char *name;
    char *secret;
    json_t *j_scope_list;
} user_t;

typedef struct
{
    bool initialised;
    jwt_alg_t algorithm;
    unsigned char *secret_key;
    size_t secret_key_length;
    rest_list_t *users_list;
    json_int_t expiration_time;
} jwt_settings_t;

typedef struct
{
    char *private_key;
    char *certificate;
    char *private_key_file;
    char *certificate_file;
    jwt_settings_t jwt;
} http_security_settings_t;

int security_load(http_security_settings_t *settings);
int security_unload(http_security_settings_t *settings);

void jwt_init(jwt_settings_t *settings);
void jwt_cleanup(jwt_settings_t *settings);

user_t *security_user_new();
int security_user_set(user_t *user, const char *name, const char *secret, json_t *scope);
void security_user_delete(user_t *user);

int security_user_check_scope(user_t *user, char *required_scope);

#endif // SECURITY_H
