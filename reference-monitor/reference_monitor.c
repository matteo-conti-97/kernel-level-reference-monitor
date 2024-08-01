/*
Blocking Queuing Service (BQS)
This homework deals with the implementation of a Linux kernel subsystem dealing with thread management.
The subsystem should implement a blocking FIFO-queuing service. It is based on two system calls:
1) int goto_sleep(void) used to make a thread sleep at the tail of the queue.
2) int awake(void) used to awake the thread currently standing at the head of the queue.
Threads could also be awaken in non-FIFO order because of Posix signals.
*/

#define EXPORT_SYMTAB
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/apic.h>
#include <asm/io.h>
#include <linux/device.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/kprobes.h>
#include "lib/include/scth.h"
#include "reference_monitor.h"
#include "states.h"
#include "error_codes.h"
#include "../utils/utils.h"
#include "probes.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Matteo Conti <matteo.conti.97@students.uniroma2.eu>");

#define MODNAME "REFERENCE_MONITOR"


unsigned long syscall_table_addr = 0x0;
module_param(syscall_table_addr, ulong, 0660);

char passwd[PASSWD_LEN];
module_param_string(passwd, passwd, PASSWD_LEN, 0);

reference_monitor ref_mon;

unsigned long the_ni_syscall;

unsigned long new_sys_call_array[] = {0x0, 0x1, 0x2, 0x3}; // please set to sys_vtpmo at startup
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array) / sizeof(unsigned long))
// #define HACKED_ENTRIES 2
int restore[HACKED_ENTRIES] = {[0 ...(HACKED_ENTRIES - 1)] - 1};

#define AUDIT if (1)

//SYSTEM CALLS

// Change reference monitor state
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(2, _switch_state, int, state, char *, passwd)
{
#else
asmlinkage long sys_switch_state(int state, char *passwd)
{
#endif
        char *hash_passwd;
        int prev_state;
        printk("%s: switch_state syscall called\n", MODNAME);

        //Check effective user id to be root
        if (!uid_eq(current_euid(), GLOBAL_ROOT_UID))
        {
                printk("%s: [ERROR] only user root can change the reference monitor configuration\n", MODNAME);
                return OP_NOT_PERMITTED_ERR;
        }

        // Check password hash
        hash_passwd = kmalloc(HASH_LEN, GFP_KERNEL);
        if (hash_passwd == NULL)
        {
                printk("%s: could not allocate memory for password\n", MODNAME);
                return -ENOMEM;
        }

        if (compute_sha256(passwd, strlen(passwd), hash_passwd) < 0)
        {
                printk("%s: could not compute sha256 of given password\n", MODNAME);
                return GENERIC_ERR;
        }

        if (!compare_hashes(hash_passwd, ref_mon.hash_passwd, HASH_LEN))
        {
                printk("%s: [ERROR] given password does not match\n", MODNAME);
                return PASSWD_MISMATCH_ERR;
        }

        //Switch state
        switch(state)
        {
                case REC_ON:
                        printk("%s: setting reference monitor state to REC-ON\n", MODNAME);
                        spin_lock(&ref_mon.lock);
                        prev_state = ref_mon.state;
                        ref_mon.state = REC_ON;
                        spin_unlock(&ref_mon.lock);

                        if((prev_state == OFF)||(prev_state == REC_OFF))
                        {
                                //TODO Enable kprobes
                        }
                        break;
                case ON:
                        printk("%s: setting reference monitor state to ON\n", MODNAME);
                        spin_lock(&ref_mon.lock);
                        prev_state = ref_mon.state;
                        ref_mon.state = ON;
                        spin_unlock(&ref_mon.lock);

                        if((prev_state == OFF)||(prev_state == REC_OFF))
                        {
                                //TODO Enable kprobes
                        }
                        break;
                case REC_OFF:
                        printk("%s: setting reference monitor state to REC-OFF\n", MODNAME);
                        spin_lock(&ref_mon.lock);
                        prev_state = ref_mon.state;
                        ref_mon.state = REC_OFF;
                        spin_unlock(&ref_mon.lock);

                        if((prev_state == ON)||(prev_state == REC_ON))
                        {
                                //TODO Disable kprobes
                        }
                        break;
                case OFF:
                        printk("%s: setting reference monitor state to OFF\n", MODNAME);
                        spin_lock(&ref_mon.lock);
                        prev_state = ref_mon.state;
                        ref_mon.state = OFF;
                        spin_unlock(&ref_mon.lock);

                        if((prev_state == ON)||(prev_state == REC_ON))
                        {
                                //TODO Disable kprobes
                        }
                        break;
                default:
                        printk("%s: [ERROR] invalid state given\n", MODNAME);
                        return INVALID_STATE_ERR;
        }

        return SUCCESS;
}

// Add the path of a new protected resource by the reference monitor
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(2, _add_protected_res, char *, res_path, char *, passwd)
{
#else
asmlinkage long sys_add_protected_res(char *res_path, char *passwd)
{
#endif
        char *hash_passwd;
        protected_resource *new_protected_resource;
        printk("%s: add_protected_res syscall called\n", MODNAME);

        //Check effective user id to be root
        if (!uid_eq(current_euid(), GLOBAL_ROOT_UID))
        {
                printk("%s: [ERROR] only user root can change the reference monitor configuration\n", MODNAME);
                return OP_NOT_PERMITTED_ERR;
        }
        
        // Check password hash
        hash_passwd = kmalloc(HASH_LEN, GFP_KERNEL);
        if (hash_passwd == NULL)
        {
                printk("%s: [ERROR] could not allocate memory for password\n", MODNAME);
                return -ENOMEM;
        }

        if (compute_sha256(passwd, strlen(passwd), hash_passwd) < 0)
        {
                printk("%s: [ERROR] could not compute sha256 of given password\n", MODNAME);
                return GENERIC_ERR;
        }

        if (!compare_hashes(hash_passwd, ref_mon.hash_passwd, HASH_LEN))
        {
                printk("%s: [ERROR] given password does not match\n", MODNAME);
                return PASSWD_MISMATCH_ERR;
        }

         //Check if reference monitor is in reconfiguration mode
        if ((ref_mon.state != REC_ON) && (ref_mon.state != REC_OFF))
        {
                printk("%s: [ERROR] reference monitor is not in reconfiguration mode\n", MODNAME);
                return OP_NOT_PERMITTED_ERR;
        }

        //Create the new protected resource
        new_protected_resource = create_protected_resource(res_path);
        if(new_protected_resource == NULL)
        {
                printk("%s: [ERROR] could not create new protected resource\n", MODNAME);
                return GENERIC_ERR;
        }

        //Lock the reference monitor 
        spin_lock(&ref_mon.lock);

        //Add the new protected resource to the list
        add_new_protected_resource(&ref_mon, new_protected_resource);

        //Unlock the reference monitor
        spin_unlock(&ref_mon.lock);

        return SUCCESS;
}

// Remove the path of a protected resource by the reference monitor
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(2, _rm_protected_res, char *, res_path, char *, passwd)
{
#else
asmlinkage long sys_rm_protected_res(char *res_path, char *passwd)
{
#endif
        int i = 0;
        char *hash_passwd;
        printk("%s: rm_protected_res syscall called\n", MODNAME);

        //Check effective user id to be root
        if (!uid_eq(current_euid(), GLOBAL_ROOT_UID))
        {
                printk("%s: [ERROR] only user root can change the reference monitor configuration\n", MODNAME);
                return OP_NOT_PERMITTED_ERR;
        }

        // Check password hash
        hash_passwd = kmalloc(HASH_LEN, GFP_KERNEL);
        if (hash_passwd == NULL)
        {
                printk("%s: [ERROR] could not allocate memory for password\n", MODNAME);
                return -ENOMEM;
        }

        if (compute_sha256(passwd, strlen(passwd), hash_passwd) < 0)
        {
                printk("%s: [ERROR] could not compute sha256 of given password\n", MODNAME);
                return GENERIC_ERR;
        }

        if (!compare_hashes(hash_passwd, ref_mon.hash_passwd, HASH_LEN))
        {
                printk("%s: [ERROR] given password does not match\n", MODNAME);
                return PASSWD_MISMATCH_ERR;
        }

        //Check if reference monitor is in reconfiguration mode
        if ((ref_mon.state != REC_ON) && (ref_mon.state != REC_OFF))
        {
                printk("%s: [ERROR] reference monitor is not in reconfiguration mode\n", MODNAME);
                return OP_NOT_PERMITTED_ERR;
        }

        //Lock the reference monitor 
        spin_lock(&ref_mon.lock);

        while(remove_protected_resource(&ref_mon, res_path) >= 0) i++;

        if(i == 0){
                printk("%s: [ERROR] resource not protected\n", MODNAME);
                spin_unlock(&ref_mon.lock);
                return RES_NOT_PROTECTED_ERR;
        }
        printk("%s: removed protected resource %d times\n", MODNAME, i);
        
        //Unlock the reference monitor
        spin_unlock(&ref_mon.lock);

        return SUCCESS;
}

// Get the path of all the protected resources by the reference monitor
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(2, _get_protected_res_list, char **, buff, int *, buff_size)
{
#else
asmlinkage long sys_get_protected_res_list(char **buff, int * buff_size)
{
#endif
    
        return SUCCESS;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
long sys_switch_state = (unsigned long)__x64_sys_switch_state;
long sys_add_protected_res = (unsigned long)__x64_sys_add_protected_res;
long sys_rm_protected_res = (unsigned long)__x64_sys_rm_protected_res;
long sys_get_protected_res_list = (unsigned long)__x64_sys_get_protected_res_list;
#else
#endif


//KERNEL PROBES

struct kretprobe kprobe_array[(KPROBES_SIZE/2)+1][2];

char *symbol_names[(KPROBES_SIZE/2)+1][2] = {
    {"__x64_sys_open", "sys_open"},
    {"__x64_sys_truncate", "sys_truncate"},
    {"__x64_sys_rename", "sys_rename"},
    {"__x64_sys_mkdir", "sys_mkdir"},
    {"__x64_sys_mknod", "sys_mknod"},
    {"__x64_sys_rmdir", "sys_rmdir"},
    {"__x64_sys_creat", "sys_creat"},
    {"__x64_sys_link", "sys_link"},
    {"__x64_sys_unlink", "sys_unlink"},
    {"__x64_sys_symlink", "sys_symlink"},
    {"__x64_sys_renameat", "sys_renameat"},
    {"__x64_sys_unlinkat", "sys_unlinkat"},
    {"__x64_sys_linkat", "sys_linkat"},
    {"__x64_sys_symlinkat", "sys_symlinkat"},
    {"__x64_sys_mkdirat", "sys_mkdirat"},
    {"__x64_sys_mknodat", "sys_mknodat"},
    {"__x64_sys_openat", "sys_openat"},
    {"__x64_sys_renameat2", "sys_renameat2"},
    {"__x64_sys_openat2", NULL}
};


typedef void (*func_ptr)(struct kretprobe_instance *prob_inst, struct pt_regs *regs);

func_ptr func_array[(KPROBES_SIZE/2)+1] = {
    (func_ptr)sys_open_handler,
    (func_ptr)sys_truncate_handler,
    (func_ptr)sys_rename_handler,
    (func_ptr)sys_mkdir_handler,
    (func_ptr)sys_mknod_handler,
    (func_ptr)sys_rmdir_handler,
    (func_ptr)sys_creat_handler,
    (func_ptr)sys_link_handler,
    (func_ptr)sys_unlink_handler,
    (func_ptr)sys_symlink_handler,
    (func_ptr)sys_renameat_handler,
    (func_ptr)sys_unlinkat_handler,
    (func_ptr)sys_linkat_handler,
    (func_ptr)sys_symlinkat_handler,
    (func_ptr)sys_mkdirat_handler,
    (func_ptr)sys_mknodat_handler,
    (func_ptr)sys_openat_handler,
    (func_ptr)sys_renameat2_handler,
    (func_ptr)sys_openat2_handler
}; 

//PROBES HANDLERS

int sys_open_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs){
        char *path_name;

        struct file *file = (struct file *)regs->di;
        struct path path = file->f_path;
        struct dentry *dentry = path.dentry;
        int open_flags = file->f_flags;

        // Check flags
        if (open_flags & O_WRONLY || open_flags & O_RDWR || open_flags & O_CREAT || open_flags & O_APPEND || open_flags & O_TRUNC){
                path_name = get_path_name(dentry);
                if (check_protected_resource(&ref_mon, path_name) == 1){
                        printk("%s Blocked access to resource %s", MODNAME, path_name);
                        return 0;
                }
        }

        return 1;
}

int sys_truncate_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs){
        return 0;
}

int sys_rename_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs){
return 0;
}

int sys_mkdir_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs){
return 0;
}

int sys_mknod_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs){
return 0;
}

int sys_rmdir_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs){
return 0;
}

int sys_creat_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs){
        return 0;
}

int sys_link_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs){
        return 0;
}

int sys_unlink_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs){
        return 0;
}

int sys_symlink_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs){
        return 0;
}

int sys_renameat_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs){
        return 0;
}

int sys_unlinkat_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs){
        return 0;
}

int sys_linkat_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs){
        return 0;
}

int sys_symlinkat_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs){
        return 0;
}

int sys_mkdirat_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs){
        return 0;
}

int sys_mknodat_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs){
        return 0;
}

int sys_openat_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs){
        return 0;
}

int sys_renameat2_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs){
        return 0;
}

int sys_openat2_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs){
        return 0;
}

//PROBES SETUP AND REGISTRATION

void setup_probe(struct kretprobe *probe, char *symbol, kretprobe_handler_t entry_handler, kretprobe_handler_t ret_handler)
{
    probe->kp.symbol_name = symbol;
    probe->kp.flags = KPROBE_FLAG_DISABLED; //Disabled by default
    probe->handler = (kretprobe_handler_t)ret_handler;
    probe->entry_handler = entry_handler;
    probe->maxactive = -1; // unlimited instances cause it's stateless
}

int kretprobe_init(){
    int ret = 0 , i, j;
    //Setup and register probes
    for(i=0;i<(KPROBES_SIZE/2)+1;i+=2)
    {
        for (j=0;j<2;j++){
            if(symbol_names[i][j] != NULL)
                setup_probe(&kprobe_array[i][j], symbol_names[i][j], NULL, NULL);
                ret = register_kretprobe(&kprobe_array[i][j]);
                if (ret < 0)
                {
                    printk("[ERROR] Kretprobe registration failed\n");
                    return ret;
                }
        }
    }
    
    printk("[INFO] Kretprobes correctly installed\n");

    return ret;
}

void kretprobe_clean(){
        int i, j;
        for(i=0;i<(KPROBES_SIZE/2)+1;i+=2)
        {
                for (j=0;j<2;j++){
                        if(symbol_names[i][j] != NULL)
                                unregister_kretprobe(&kprobe_array[i][j]);
                }       
        }

        printk("[INFO] Kretprobes correctly removed\n");

        kfree(kprobe_array);
}


int init_module(void)
{

        int i;
        int ret;

        printk("%s: initializing reference monitor state\n", MODNAME);

        // setup password
        ref_mon.hash_passwd = kmalloc(HASH_LEN, GFP_KERNEL);
        if (ref_mon.hash_passwd == NULL)
        {
                printk("%s: could not allocate memory for password\n", MODNAME);
                return -ENOMEM;
        }

        if (compute_sha256(passwd, strlen(passwd), ref_mon.hash_passwd) < 0)
        {
                printk("%s: could not compute sha256 of password\n", MODNAME);
                return GENERIC_ERR;
        }

        // delete password
        memset(passwd, 0, PASSWD_LEN);

        // setup state
        ref_mon.state = REC_ON;

        // setup protected resources list
        ref_mon.protected_resource_list_head = NULL;

        // setup lock
        spin_lock_init(&ref_mon.lock);

        if (syscall_table_addr == 0x0)
        {
                printk("%s: cannot manage sys_call_table address set to 0x0\n", MODNAME);
                return GENERIC_ERR;
        }

        AUDIT
        {
                printk("%s: received sys_call_table address %px\n", MODNAME, (void *)syscall_table_addr);
                printk("%s: initializing - hacked entries %d\n", MODNAME, HACKED_ENTRIES);
        }

        new_sys_call_array[0] = (unsigned long)sys_switch_state;
        new_sys_call_array[1] = (unsigned long)sys_add_protected_res;
        new_sys_call_array[2] = (unsigned long)sys_rm_protected_res;
        new_sys_call_array[3] = (unsigned long)sys_get_protected_res_list;

        ret = get_entries(restore, HACKED_ENTRIES, (unsigned long *)syscall_table_addr, &the_ni_syscall);

        if (ret != HACKED_ENTRIES)
        {
                printk("%s: could not hack %d entries (just %d)\n", MODNAME, HACKED_ENTRIES, ret);
                return GENERIC_ERR;
        }

        unprotect_memory();

        for (i = 0; i < HACKED_ENTRIES; i++)
        {
                ((unsigned long *)syscall_table_addr)[restore[i]] = (unsigned long)new_sys_call_array[i];
        }

        protect_memory();

        printk("%s: all new system-calls correctly installed on sys-call table\n", MODNAME);

        printk("%s: reference monitor correctly initialized\n", MODNAME);

        return SUCCESS;
}

void cleanup_module(void)
{

        int i;

        printk("%s: shutting down\n", MODNAME);

        unprotect_memory();
        for (i = 0; i < HACKED_ENTRIES; i++)
        {
                ((unsigned long *)syscall_table_addr)[restore[i]] = the_ni_syscall;
        }
        protect_memory();
        printk("%s: sys-call table restored to its original content\n", MODNAME);
}
