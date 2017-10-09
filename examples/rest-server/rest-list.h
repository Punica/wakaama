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

#ifndef REST_LIST_H
#define REST_LIST_H

#include <pthread.h>


typedef struct rest_list_entry_t
{
    struct rest_list_entry_t *next;
    void *data;
} rest_list_entry_t;

typedef struct
{
    pthread_mutex_t mutex;
    rest_list_entry_t *head;
} rest_list_t;

/**
 * This function creates new list resource.
 *
 * @return Pointer to a new list instance or NULL on error
 *
 */
rest_list_t * rest_list_new(void);

/**
 * This functions deletes list resource.
 *
 * @param[in]  list  Pointer to the list which will be delted
 *
 */
void rest_list_delete(rest_list_t *list);

/**
 * Adds data entry to the list.
 *
 * @param[in]  list  Pointer to the list
 * @param[in]  data  Data entry to be added
 */
void rest_list_add(rest_list_t *list, void *data);

/**
 * Removes data entry from the list. The data MUST be present in the list,
 * otherwise an assertion error occurs. If there are multiple data entries,
 * then only one of them is removed.
 *
 * @param[in]  list  Pointer to the list
 * @param[in]  data  Data entry to be removed
 */
void rest_list_remove(rest_list_t *list, void *data);

#endif // REST_LIST_H
