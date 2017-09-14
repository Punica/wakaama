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


rest_list_t * rest_list_add(rest_list_t *head, rest_list_t *node)
{
    assert(node->next == NULL);

    if (NULL == head)
    {
        return node;
    }

    node->next = head;
    return node;
}

rest_list_t * rest_list_remove(rest_list_t *head, rest_list_t *node)
{
    rest_list_t *target;

    if (head == node)
    {
        target = node->next;
        node->next = NULL;
        return target;
    }

    REST_LIST_FOREACH(head, target)
    {
        if (target->next == node)
        {
            target->next = node->next;
            node->next = NULL;
            return head;
        }
    }

    assert(false);
}

