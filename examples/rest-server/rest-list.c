
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

