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

#include <string.h>
#include <stdio.h>
#include <malloc.h>
#include <jansson.h>
#include <regex.h>

#include "security.h"
#include "logging.h"

static char *read_file(const char *filename)
{
    char *buffer = NULL;
    long length;
    FILE *f = fopen(filename, "rb");
    if (filename != NULL)
    {

        if (f)
        {
            fseek(f, 0, SEEK_END);
            length = ftell(f);
            fseek(f, 0, SEEK_SET);
            buffer = malloc(length + 1);
            if (buffer)
            {
                fread(buffer, 1, length, f);
                buffer[length] = '\0';
            }
            fclose(f);
        }
        return buffer;
    }
    else
    {
        return NULL;
    }
}

int security_load(http_security_settings_t *settings)
{
    if (settings->private_key == NULL || settings->certificate == NULL)
    {
        log_message(LOG_LEVEL_ERROR, "Not enough security files provided\n");
        return 1;
    }

    settings->private_key_file = read_file(settings->private_key);
    settings->certificate_file = read_file(settings->certificate);

    if (settings->private_key_file == NULL || settings->certificate_file == NULL)
    {
        log_message(LOG_LEVEL_ERROR, "Failed to read security files\n");
        return 1;
    }
    log_message(LOG_LEVEL_TRACE, "Successfully loaded security configuration\n");

    return 0;
}

user_t *security_user_new(void)
{
    user_t *user;

    user = calloc(1, sizeof(user_t));
    if (user == NULL)
    {
        log_message(LOG_LEVEL_FATAL, "[JWT] Failed to allocate user memory");
    }

    return user;
}

void security_user_delete(user_t *user)
{
    if (user->name)
    {
        memset(user->name, 0, strnlen(user->name, J_MAX_LENGTH_USER_NAME));
    }

    if (user->secret)
    {
        memset(user->secret, 0, strnlen(user->secret, J_MAX_LENGTH_USER_SECRET));
    }

    if (user->j_scope_list)
    {
        json_decref(user->j_scope_list);
        user->j_scope_list = NULL;
    }

    free(user);
}

int security_user_set(user_t *user, const char *name, const char *secret, json_t *scope)
{
    user->name = strdup(name);
    user->secret = strdup(secret);
    user->j_scope_list = json_deep_copy(scope);

    return 0;
}

int security_unload(http_security_settings_t *settings)
{
    memset(settings->private_key, 0, strlen(settings->private_key));
    memset(settings->certificate, 0, strlen(settings->certificate));
    memset(settings->private_key_file, 0, strlen(settings->private_key_file));
    memset(settings->certificate_file, 0, strlen(settings->certificate_file));

    log_message(LOG_LEVEL_TRACE, "Successfully unloaded security");
    return 0;
}

void jwt_init(jwt_settings_t *settings)
{
    settings->initialised = true;
}

void jwt_cleanup(jwt_settings_t *settings)
{
    rest_list_entry_t *entry;

    if (settings->secret_key != NULL)
    {
        free(settings->secret_key);
    }

    for (entry = settings->users_list->head; entry != NULL; entry = entry->next)
    {
        security_user_delete((user_t *) entry->data);
    }

    rest_list_delete(settings->users_list);
    settings->initialised = false;
}

int security_user_check_scope(user_t *user, char *required_scope)
{
    size_t index;
    json_t *j_scope_pattern;
    const char *scope_pattern;
    regex_t regex;

    json_array_foreach(user->j_scope_list, index, j_scope_pattern)
    {
        scope_pattern = json_string_value(j_scope_pattern);

        regcomp(&regex, scope_pattern, REG_EXTENDED);

        if (regexec(&regex, required_scope, 0, NULL, 0) == 0)
        {
            return 0;
        }
    }

    return 1;
}
