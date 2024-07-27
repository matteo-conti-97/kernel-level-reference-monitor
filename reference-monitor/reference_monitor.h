#include <linux/spinlock.h>
#include <linux/string.h>

//States of the reference monitor
#define ON 0
#define OFF 1
#define REC_ON 2
#define REC_OFF 3


#define PASSWD_LEN 128
#define HASH_LEN 32

//Error codes
#define SUCCESS 0
#define GENERIC_ERR -1 
#define OP_NOT_PERMITTED_ERR -2
#define PASSWD_MISMATCH_ERR -3
#define RES_NOT_PROTECTED_ERR -4
#define INVALID_STATE_ERR -5


typedef struct reference_monitor {
    int state;
    char *hash_passwd;
    struct protected_resource *protected_resource_list_head;
    spinlock_t lock;
}reference_monitor;

typedef struct protected_resource{
    char *path;
    struct protected_resource *next;
} protected_resource;

protected_resource *create_protected_resource(char *res_path){
    //Allocate memory for the new protected resource
        protected_resource *new_protected_resource = kmalloc(sizeof(protected_resource), GFP_KERNEL);
        if (new_protected_resource == NULL) return NULL;

        //Copy the path of the new protected resource
        new_protected_resource->path = kmalloc(strlen(res_path) + 1, GFP_KERNEL);
        if (new_protected_resource->path == NULL)
        {
                kfree(new_protected_resource);
                return NULL;
        }
        strcpy(new_protected_resource->path, res_path);

        return new_protected_resource;
}

// Function to insert a node at the beginning of the list
void add_new_protected_resource(reference_monitor *ref_mon, protected_resource *new_protected_resource) {
    new_protected_resource->next = ref_mon->protected_resource_list_head;
    ref_mon->protected_resource_list_head = new_protected_resource;
}

// Function to remove a node from the list
int remove_protected_resource(reference_monitor *ref_mon, char *res_path) {
    protected_resource *curr = ref_mon->protected_resource_list_head;
    protected_resource *prev = NULL;

    while (curr != NULL) {
        if (strcmp(curr->path, res_path) == 0) {
            // If the node to be removed is the head node
            if (prev == NULL) 
                ref_mon->protected_resource_list_head = curr->next;
            // If the node to be removed is not the head node
            else 
                prev->next = curr->next;

            kfree(curr->path);
            kfree(curr);
            return 0;
        }
        prev = curr;
        curr = curr->next;
    }

    //If the node to be removed is not found
    return -1;
}