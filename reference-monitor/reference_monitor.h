#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/rculist.h>

#define PASSWD_LEN 128
#define HASH_LEN 32
#define MAX_FILENAME_LEN 512

typedef struct reference_monitor {
    int state;
    char *hash_passwd;
    struct protected_resource __rcu *protected_resource_list_head; // Updated for RCU
    spinlock_t lock;
} reference_monitor;

typedef struct protected_resource {
    char *path;
    struct protected_resource __rcu *next; // Updated for RCU
} protected_resource;

protected_resource *create_protected_resource(char *res_path);
void add_new_protected_resource(reference_monitor *ref_mon, protected_resource *new_protected_resource);
int remove_protected_resource(reference_monitor *ref_mon, char *res_path);
void print_protected_resources(reference_monitor *ref_mon);
bool check_protected_resource(reference_monitor *ref_mon, const char *res_path);

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
void add_new_protected_resource(reference_monitor *rm, protected_resource *new_resource) {
    protected_resource *old_head;

    //Insert the new protected resource at the beginning of the list
    spin_lock(&rm->lock);
    old_head = rcu_dereference(rm->protected_resource_list_head);
    new_resource->next = old_head;
    rcu_assign_pointer(rm->protected_resource_list_head, new_resource);
    spin_unlock(&rm->lock);
}

// Function to remove a node from the list
int remove_protected_resource(reference_monitor *rm, char *target) {
    protected_resource *prev = NULL;
    protected_resource *curr;
    spin_lock(&rm->lock);

    rcu_read_lock();
    curr = rcu_dereference(rm->protected_resource_list_head);
    while (curr != NULL) {
        if (strcmp(curr->path, target) == 0) {
            if (prev) {
                rcu_assign_pointer(prev->next, curr->next);
            } else {
                rcu_assign_pointer(rm->protected_resource_list_head, curr->next);
            }
            spin_unlock(&rm->lock);
            synchronize_rcu(); // Wait for ongoing RCU readers to finish
           
            // Free the node after RCU grace period
            kfree(curr);
            return 0;
        }
        prev = curr;
        curr = rcu_dereference(curr->next);
    }
    spin_unlock(&rm->lock);
    rcu_read_unlock();
    return -1;

}

void print_protected_resources(reference_monitor *rm) {
    protected_resource *cur;

    rcu_read_lock();
    cur = rcu_dereference(rm->protected_resource_list_head);
    while (cur != NULL) {
        printk("Protected resource: %s\n", cur->path);
        cur = rcu_dereference(cur->next);
    }
    rcu_read_unlock();
}

// Function to check if a resource is protected
bool check_protected_resource(reference_monitor *rm, const char *res_path) {
    protected_resource *curr;
    int prefix_len;

    rcu_read_lock();
    curr = rcu_dereference(rm->protected_resource_list_head);
    while (curr != NULL) {

        prefix_len = strlen(curr->path);
        //If the resource is found in the list
        if (strncmp(res_path, curr->path, prefix_len) == 0) {
            rcu_read_unlock();
            return true;
        }

        curr = rcu_dereference(curr->next);
    }
    rcu_read_unlock();
    return false;

}