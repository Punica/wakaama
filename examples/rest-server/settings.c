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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rest-list.h"
#include "settings.h"
#include "version.h"
#include "security.h"

const char *argp_program_version = RESTSERVER_FULL_VERSION;

static char doc[] = "Restserver - interface to LwM2M server and all clients connected to it";

static struct argp_option options[] =
{
    {"log",   'l', "LOGGING_LEVEL", 0, "Specify logging level (0-5)" },
    {"config",   'c', "FILE", 0, "Specify parameters configuration file" },
    {"private_key",   'k', "PRIVATE_KEY", 0, "Specify TLS security private key file" },
    {"certificate",   'C', "CERTIFICATE", 0, "Specify TLS security certificate file" },
    { 0 }
};

static void set_coap_settings(json_t *j_section, coap_settings_t *settings)
{
    const char *key;
    const char *section_name = "coap";
    json_t *j_value;

    json_object_foreach(j_section, key, j_value)
    {
        if (strcasecmp(key, "port") == 0)
        {
            settings->port = (uint16_t) json_integer_value(j_value);
        }
        else
        {
            fprintf(stdout, "Unrecognised configuration file key: %s.%s\n",
                    section_name, key);
        }
    }
}

static int set_user_settings(json_t *user_settings, rest_list_t *users_list)
{
    user_t *user, *user_entry;
    rest_list_entry_t *entry;
    json_t *j_name, *j_secret, *j_scope, *j_scope_value;
    const char *user_name, *user_secret;
    char *scope_value;
    size_t user_name_length, user_secret_length, scope_length, scope_index;

    j_name = json_object_get(user_settings, "name");
    j_secret = json_object_get(user_settings, "secret");
    j_scope = json_object_get(user_settings, "scope");

    if (!json_is_string(j_name) || strlen(json_string_value(j_name)) < 1)
    {
        fprintf(stdout, "User configured without name.\n");
        return 1;
    }

    user_name = json_string_value(j_name);
    user_name_length = strnlen(user_name, J_MAX_LENGTH_USER_NAME);
    if (user_name_length == 0 || user_name_length == J_MAX_LENGTH_USER_NAME)
    {
        fprintf(stdout, "User name length is invalid\n");
        return 1;
    }

    for (entry = users_list->head; entry != NULL; entry = entry->next)
    {
        user_entry = entry->data;

        if (strncmp(user_entry->name, user_name, J_MAX_LENGTH_USER_NAME) == 0)
        {
            fprintf(stdout, "Found duplicate \"%s\" user name in config\n", user_name);
            return 1;
        }
    }

    if (!json_is_string(j_secret))
    {
        fprintf(stdout, "User \"%s\" configured without valid secret key.\n", user_name);
        return 1;
    }

    user_secret = json_string_value(j_secret);
    user_secret_length = strnlen(user_secret, J_MAX_LENGTH_USER_SECRET);
    if (user_secret_length == J_MAX_LENGTH_USER_NAME)
    {
        fprintf(stdout, "User secret length is invalid\n");
        return 1;
    }

    if (!json_is_array(j_scope))
    {
        fprintf(stdout, "User \"%s\" configured without valid scope. Setting default scope.\n", user_name);
        j_scope = json_array();
    }

    json_array_foreach(j_scope, scope_index, j_scope_value)
    {
        if (!json_is_string(j_scope_value))
        {
            fprintf(stdout, "User %s scope list configuration contains invalid type value\n", user_name);
            return 1;
        }

        scope_value = (char *) json_string_value(j_scope_value);
        scope_length = strnlen(scope_value, J_MAX_LENGTH_METHOD + 1 + J_MAX_LENGTH_URL);
        if (scope_length == 0 || scope_length == J_MAX_LENGTH_METHOD + 1 + J_MAX_LENGTH_URL)
        {
            fprintf(stdout, "User %s scope list configuration contains invalid length value\n", user_name);
            return 1;
        }
    }

    user = security_user_new();

    security_user_set(user, user_name, user_secret, j_scope);

    rest_list_add(users_list, user);

    return 0;
}

static void set_jwt_settings(json_t *j_section, jwt_settings_t *settings)
{
    size_t user_index, value_length;
    const char *key, *string_value;
    const char *section_name = "http.security.jwt";
    json_t *j_value, *j_user_settings;
    jwt_init(settings);

    json_object_foreach(j_section, key, j_value)
    {
        if (strcasecmp(key, "algorithm") == 0)
        {
            settings->algorithm = jwt_str_alg(json_string_value(j_value));
        }
        else if (strcasecmp(key, "expiration_time") == 0)
        {
            if (json_is_integer(j_value))
            {
                settings->expiration_time = json_integer_value(j_value);
            }
            else
            {
                fprintf(stdout, "Token %s must be an integer\n", key);
            }
        }
        else if (strcasecmp(key, "secret_key") == 0)
        {
            printf("DEBUG Before segfault!\n");
            if (!json_is_string(j_value))
            {
                fprintf(stdout, "Token %s must be a string\n", key);
                continue;
            }

            string_value = json_string_value(j_value);
            value_length = strnlen(string_value, J_MAX_LENGTH_SECRET_KEY);
            if (value_length == 0 || value_length == J_MAX_LENGTH_SECRET_KEY)
            {
                fprintf(stdout, "Token %s length is invalid\n", key);
                continue;
            }

            if (settings->secret_key != NULL)
            {
                free(settings->secret_key);
            }

            settings->secret_key_length = value_length;
            settings->secret_key = (unsigned char *) malloc(settings->secret_key_length * sizeof(
                                                                unsigned char));
            if (settings->secret_key == NULL)
            {
                fprintf(stderr, "Failed to allocate %s!\n", key);
                settings->secret_key_length = 0;
                continue;
            }
            memcpy(settings->secret_key, string_value, value_length);
        }
        else if (strcasecmp(key, "users") == 0)
        {
            if (json_is_array(j_value))
            {
                json_array_foreach(j_value, user_index, j_user_settings)
                {
                    if (json_is_object(j_user_settings))
                    {
                        set_user_settings(j_user_settings, settings->users_list);
                    }
                    else
                    {
                        fprintf(stdout, "User settings must be stored in an object\n");
                    }
                }
            }
            else
            {
                fprintf(stdout, "Users settings must be stored in objects list\n");
            }
        }
        else
        {
            fprintf(stdout, "Unrecognised configuration file key: %s.%s\n",
                    section_name, key);
        }
    }
}

static void set_http_security_settings(json_t *j_section, http_security_settings_t *settings)
{
    const char *key;
    const char *section_name = "http.security";
    json_t *j_value;

    json_object_foreach(j_section, key, j_value)
    {
        if (strcasecmp(key, "private_key") == 0)
        {
            settings->private_key = (char *) json_string_value(j_value);
        }
        else if (strcasecmp(key, "certificate") == 0)
        {
            settings->certificate = (char *) json_string_value(j_value);
        }
        else if (strcasecmp(key, "jwt") == 0)
        {
            set_jwt_settings(j_value, &settings->jwt);
        }
        else
        {
            fprintf(stdout, "Unrecognised configuration file key: %s.%s\n",
                    section_name, key);
        }
    }
}

static void set_http_settings(json_t *j_section, http_settings_t *settings)
{
    const char *key, *section_name = "http";
    json_t *j_value;

    json_object_foreach(j_section, key, j_value)
    {
        if (strcasecmp(key, "port") == 0)
        {
            settings->port = (uint16_t) json_integer_value(j_value);
        }
        else if (strcasecmp(key, "security") == 0)
        {
            set_http_security_settings(j_value, &settings->security);
        }
        else
        {
            fprintf(stdout, "Unrecognised configuration file key: %s.%s\n",
                    section_name, key);
        }
    }
}

static void set_logging_settings(json_t *j_section, logging_settings_t *settings)
{
    const char *key;
    const char *section_name = "logging";
    json_t *j_value;

    json_object_foreach(j_section, key, j_value)
    {
        if (strcasecmp(key, "level") == 0)
        {
            settings->level = (logging_level_t) json_integer_value(j_value);
        }
        else if (strcasecmp(key, "timestamp") == 0)
        {
            if (json_is_boolean(j_value))
            {
                settings->timestamp = json_is_true(j_value) ? true : false;
            }
            else
            {
                fprintf(stdout, "%s.%s must be set to a boolean value!\n",
                        section_name, key);
            }
        }
        else if (strcasecmp(key, "human_readable_timestamp") == 0)
        {
            if (json_is_boolean(j_value))
            {
                settings->human_readable_timestamp = json_is_true(j_value) ? true : false;
            }
            else
            {
                fprintf(stdout, "%s.%s must be set to a boolean value!\n",
                        section_name, key);
            }
        }
        else
        {
            fprintf(stdout, "Unrecognised configuration file key: %s.%s\n",
                    section_name, key);
        }
    }
}

int read_config(char *config_name, settings_t *settings)
{
    json_error_t error;
    const char *section;
    json_t *j_value;

    json_t *settings_json = json_object();

    settings_json = json_load_file(config_name, 0, &error);

    if (settings_json == NULL)
    {
        fprintf(stderr, "%s:%d:%d error:%s \n",
                config_name, error.line, error.column, error.text);
        return 1;
    }

    json_object_foreach(settings_json, section, j_value)
    {
        if (strcasecmp(section, "coap") == 0)
        {
            set_coap_settings(j_value, &settings->coap);
        }
        else if (strcasecmp(section, "http") == 0)
        {
            set_http_settings(j_value, &settings->http);
        }
        else if (strcasecmp(section, "logging") == 0)
        {
            set_logging_settings(j_value, &settings->logging);
        }
        else
        {
            fprintf(stdout, "Unrecognised configuration file section: %s\n", section);
        }
    }

    return 0;
}

error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    settings_t *settings = state->input;

    switch (key)
    {
    case 'l':
        settings->logging.level = atoi(arg);
        break;

    case 'c':
        if (read_config(arg, settings) != 0)
        {
            argp_usage(state);
            return 1;
        }
        break;

    case 'C':
        settings->http.security.certificate = arg;
        break;

    case 'k':
        settings->http.security.private_key = arg;
        break;


    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = { options, parse_opt, 0, doc };

int settings_init(int argc, char *argv[], settings_t *settings)
{
    return argp_parse(&argp, argc, argv, 0, 0, settings);
}
