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

#include "settings.h"
#include "version.h"

const char *argp_program_version = RESTSERVER_FULL_VERSION;

static char doc[] = "Restserver - interface to LwM2M server and all clients connected to it";

static struct argp_option options[] =
{
    {"log",   'l', "LOGGING_LEVEL", 0, "Specify logging level (0-5)" },
    {"config",   'c', "FILE", 0, "Specify parameters configuration file" },
    { 0 }
};

static void set_coap_settings(json_t *section, coap_settings_t *settings)
{
    const char *key;
    const char *section_name = "coap";
    json_t *value;

    json_object_foreach(section, key, value)
    {
        if (strcmp(key, "port") == 0)
        {
            settings->port = (uint16_t) json_integer_value(value);
        }
        else
        {
            fprintf(stdout, "Unrecognised configuration file key: %s.%s\n",
                    section_name, key);
        }
    }
}

static void set_http_settings(json_t *section, http_settings_t *settings)
{
    const char *key;
    const char *section_name = "http";
    json_t *value;

    json_object_foreach(section, key, value)
    {
        if (strcmp(key, "port") == 0)
        {
            settings->port = (uint16_t) json_integer_value(value);
        }
        else
        {
            fprintf(stdout, "Unrecognised configuration file key: %s.%s\n",
                    section_name, key);
        }
    }
}

static void set_logging_settings(json_t *section, logging_settings_t *settings)
{
    const char *key;
    const char *section_name = "logging";
    json_t *value;

    json_object_foreach(section, key, value)
    {
        if (strcmp(key, "level") == 0)
        {
            settings->level = (logging_level_t) json_integer_value(value);
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
    json_t *value;

    json_t *settings_json = json_object();

    settings_json = json_load_file(config_name, 0, &error);

    if (settings_json == NULL)
    {
        fprintf(stderr, "%s:%d:%d error:%s \n",
                config_name, error.line, error.column, error.text);
        return 1;
    }

    json_object_foreach(settings_json, section, value)
    {
        if (strcmp(section, "coap") == 0)
        {
            set_coap_settings(value, &settings->coap);
        }
        else if (strcmp(section, "http") == 0)
        {
            set_http_settings(value, &settings->http);
        }
        else if (strcmp(section, "logging") == 0)
        {
            set_logging_settings(value, &settings->logging);
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
            return 1;
        }
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
