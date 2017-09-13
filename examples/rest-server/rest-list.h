
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
