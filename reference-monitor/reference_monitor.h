#include <linux/spinlock.h>

#define ON 0
#define OFF 1
#define REC_ON 2
#define REC_OFF 3

struct reference_monitor {
    int state;
    char *passwd;
    struct protected_resource *protected_resource_list_head;
    spinlock_t lock;
}reference_monitor;

struct protected_resource{
    char *path;
    struct protected_resource *next;
} protected_resource;