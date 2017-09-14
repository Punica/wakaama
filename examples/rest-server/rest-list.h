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

typedef struct
{
    void *next;
} rest_list_t;

rest_list_t * rest_list_add(rest_list_t *head, rest_list_t *node);

rest_list_t * rest_list_remove(rest_list_t *head, rest_list_t *node);

#define REST_LIST_ADD(H, N) (typeof(H))rest_list_add((rest_list_t *)(H), (rest_list_t *)(N))

#define REST_LIST_RM(H, N) (typeof(H))rest_list_remove((rest_list_t *)(H), (rest_list_t *)(N))

#define REST_LIST_FOREACH(H, I) for ((I)=(H); (I) != NULL; (I)=((rest_list_t *)(I))->next)

#endif // REST_LIST_H
