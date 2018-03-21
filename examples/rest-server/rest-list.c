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

#include "rest-list.h"

#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>


rest_list_t * rest_list_new(void)
{
    rest_list_t *list = malloc(sizeof(rest_list_t));

    if (list == NULL)
    {
        return NULL;
    }

    memset(list, 0, sizeof(rest_list_t));

    pthread_mutex_init(&list->mutex, NULL);
    list->head = NULL;

    return list;
}

void rest_list_delete(rest_list_t *list)
{
    rest_list_entry_t *entry;

    pthread_mutex_lock(&list->mutex);

    while (list->head != NULL)
    {
        entry = list->head;
        list->head = entry->next;
        entry->next = NULL;
        free(entry);
    }

    pthread_mutex_unlock(&list->mutex);

    pthread_mutex_destroy(&list->mutex);

    free(list);
}

void rest_list_add(rest_list_t *list, void *data)
{
    rest_list_entry_t *entry;

    pthread_mutex_lock(&list->mutex);

    entry = malloc(sizeof(rest_list_entry_t));
    assert(entry != NULL);

    entry->next = list->head;
    entry->data = data;
    list->head = entry;

    pthread_mutex_unlock(&list->mutex);
}

void rest_list_remove(rest_list_t *list, void *data)
{
    pthread_mutex_lock(&list->mutex);

    rest_list_entry_t *entry, *previous;

    for (entry = list->head; entry != NULL; entry = entry->next)
    {
        if (entry->data == data)
        {
            if (entry == list->head)
            {
                list->head = entry->next;
                entry->next = NULL;
                free(entry);
            }
            else
            {
                previous->next = entry->next;
                entry->next = NULL;
                free(entry);
            }

            pthread_mutex_unlock(&list->mutex);
            return;
        }

        previous = entry;
    }

    assert(false);
}

