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
MODULE_DESCRIPTION("This module implements a reference monitor which offers a set of system calls to manage protected resources and a set of kernel probes to block write operations on protected resources");

#define MODNAME "REFERENCE_MONITOR"

unsigned long syscall_table_addr = 0x0;
module_param(syscall_table_addr, ulong, 0660);

char passwd[PASSWD_LEN];
module_param_string(passwd, passwd, PASSWD_LEN, 0);

reference_monitor ref_mon;

unsigned long the_ni_syscall;

unsigned long new_sys_call_array[] = {0x0, 0x1, 0x2}; // please set to sys_vtpmo at startup
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array) / sizeof(unsigned long))
// #define HACKED_ENTRIES 2
int restore[HACKED_ENTRIES] = {[0 ...(HACKED_ENTRIES - 1)] - 1};

#define AUDIT if (1)

// SYSTEM CALLS

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
        printk("%s: [INFO] switch_state syscall called\n", MODNAME);

        // Check effective user id to be root
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

        // Switch state
        switch (state)
        {
        case REC_ON:
                printk("%s: [INFO] setting reference monitor state to REC-ON\n", MODNAME);
                spin_lock(&ref_mon.lock);
                prev_state = ref_mon.state;
                ref_mon.state = REC_ON;
                spin_unlock(&ref_mon.lock);

                // If switching from OFF to ON
                if ((prev_state == OFF) || (prev_state == REC_OFF))
                        enable_probes();

                break;
        case ON:
                printk("%s: [INFO] setting reference monitor state to ON\n", MODNAME);
                spin_lock(&ref_mon.lock);
                prev_state = ref_mon.state;
                ref_mon.state = ON;
                spin_unlock(&ref_mon.lock);

                // If switching from OFF to ON
                if ((prev_state == OFF) || (prev_state == REC_OFF))
                        enable_probes();

                break;
        case REC_OFF:
                printk("%s: [INFO] setting reference monitor state to REC-OFF\n", MODNAME);
                spin_lock(&ref_mon.lock);
                prev_state = ref_mon.state;
                ref_mon.state = REC_OFF;
                spin_unlock(&ref_mon.lock);

                // If switching from ON to OFF
                if ((prev_state == ON) || (prev_state == REC_ON))
                        disable_probes();
                break;
        case OFF:
                printk("%s: [INFO] setting reference monitor state to OFF\n", MODNAME);
                spin_lock(&ref_mon.lock);
                prev_state = ref_mon.state;
                ref_mon.state = OFF;
                spin_unlock(&ref_mon.lock);

                // If switching from ON to OFF
                if ((prev_state == ON) || (prev_state == REC_ON))
                        disable_probes();
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
        printk("%s: [INFO] add_protected_res syscall called\n", MODNAME);

        // Check effective user id to be root
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

        // Check if reference monitor is in reconfiguration mode
        if ((ref_mon.state != REC_ON) && (ref_mon.state != REC_OFF))
        {
                printk("%s: [ERROR] reference monitor is not in reconfiguration mode\n", MODNAME);
                return OP_NOT_PERMITTED_ERR;
        }

        // Create the new protected resource
        new_protected_resource = create_protected_resource(res_path);
        if (new_protected_resource == NULL)
        {
                printk("%s: [ERROR] could not create new protected resource\n", MODNAME);
                return GENERIC_ERR;
        }

        // Add the new protected resource to the list
        add_new_protected_resource(&ref_mon, new_protected_resource);
        print_protected_resources(&ref_mon);

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
        printk("%s: [INFO] rm_protected_res syscall called\n", MODNAME);

        // Check effective user id to be root
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

        // Check if reference monitor is in reconfiguration mode
        if ((ref_mon.state != REC_ON) && (ref_mon.state != REC_OFF))
        {
                printk("%s: [ERROR] reference monitor is not in reconfiguration mode\n", MODNAME);
                return OP_NOT_PERMITTED_ERR;
        }

        // Lock the reference monitor

        while (remove_protected_resource(&ref_mon, res_path) >= 0)
                i++;

        if (i == 0)
        {
                printk("%s: [ERROR] resource not protected\n", MODNAME);
                return RES_NOT_PROTECTED_ERR;
        }
        printk("%s: [INFO] removed protected resource %d times\n", MODNAME, i);
        print_protected_resources(&ref_mon);

        return SUCCESS;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
long sys_switch_state = (unsigned long)__x64_sys_switch_state;
long sys_add_protected_res = (unsigned long)__x64_sys_add_protected_res;
long sys_rm_protected_res = (unsigned long)__x64_sys_rm_protected_res;
#else
#endif

// KERNEL PROBES

struct kretprobe kprobe_array[KPROBES_SIZE];

char *symbol_names[KPROBES_SIZE] = {
    "vfs_open",
    "security_path_truncate",
    "security_path_rename",
    "security_inode_mkdir",
    "security_path_mknod",
    "security_inode_rmdir",
    "security_inode_create",
    "security_inode_link",
    "security_inode_unlink",
    "security_inode_symlink"};

typedef int (*kretprobe_handler_t)(struct kretprobe_instance *prob_inst, struct pt_regs *regs);

kretprobe_handler_t handler_array[KPROBES_SIZE] = {
    (kretprobe_handler_t)vfs_open_handler,
    (kretprobe_handler_t)security_path_truncate_handler,
    (kretprobe_handler_t)security_path_rename_handler,
    (kretprobe_handler_t)security_inode_mkdir_handler,
    (kretprobe_handler_t)security_path_mknod_handler,
    (kretprobe_handler_t)security_inode_rmdir_handler,
    (kretprobe_handler_t)security_inode_create_handler,
    (kretprobe_handler_t)security_inode_link_handler,
    (kretprobe_handler_t)security_inode_unlink_handler,
    (kretprobe_handler_t)security_inode_symlink_handler};

// PROBES HANDLERS
/* Note Registers Used for Passing Arguments:
rdi: First argument
rsi: Second argument
rdx: Third argument
rcx: Fourth argument
rax: Used for returning the result of the system call*/

int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
        regs->ax = -EACCES;
        return 0;
}

int vfs_open_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs)
{
        struct path *path;
        struct dentry *dentry;
        struct file *file;
        char *buff;
        const char *pathname;
        int flags;

        // Get open parameters
        path = (struct path *)regs->di;
        file = (struct file *)regs->si;
        flags = file->f_flags;
        dentry = path->dentry;

        // Get the file path
        buff = (char *)kmalloc(GFP_KERNEL, MAX_FILENAME_LEN);
        if (!buff) {
                printk("%s: [ERROR] could not allocate memory for buffer\n", MODNAME);
                return 0;
        }
        pathname = dentry_path_raw(dentry, buff, MAX_FILENAME_LEN);
        if (IS_ERR(pathname)) {
                printk("%s: [ERROR] could not get path from dentry\n", MODNAME);
                kfree(buff);
                return 0;
        }

        // Check the flags
        if (flags & O_WRONLY || flags & O_RDWR || flags & O_CREAT || flags & O_APPEND || flags & O_TRUNC)
        {
                // Check if file is protected
                if (check_protected_resource(&ref_mon, pathname))
                {
                        printk("%s: [ERROR] Blocked open access to protected resource %s\n", MODNAME, pathname);
                        return 0;
                }
        }
        return 1;
}

int security_path_truncate_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs)
{
        struct path *path;
        struct dentry *dentry;
        char *buff;
        const char *pathname;

        // Get truncate parameters
        path = (struct path *)regs->di;
        dentry = path->dentry;
        

        // Get the file path
        buff = (char *)kmalloc(GFP_KERNEL, MAX_FILENAME_LEN);
        if (!buff) {
                printk("%s: [ERROR] could not allocate memory for buffer\n", MODNAME);
                return 0;
        }
        pathname = dentry_path_raw(dentry, buff, MAX_FILENAME_LEN);
        if (IS_ERR(pathname)) {
                printk("%s: [ERROR] could not get path from dentry\n", MODNAME);
                kfree(buff);
                return 0;
        }

 
        // Check if file is protected
        if (check_protected_resource(&ref_mon, pathname))
        {
                printk("%s: [ERROR] Blocked truncate access to protected resource %s\n", MODNAME, pathname);
                return 0;
        }
        
        return 1;
}

int security_path_rename_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs)
{
        struct dentry *dentry;
        char *buff;
        const char *old_pathname;
        const char *new_pathname;

        // Get the old path
        dentry = (struct dentry *)regs->si;
        
        buff = (char *)kmalloc(GFP_KERNEL, MAX_FILENAME_LEN);
        if (!buff) {
                printk("%s: [ERROR] could not allocate memory for buffer\n", MODNAME);
                return 0;
        }
        old_pathname = dentry_path_raw(dentry, buff, MAX_FILENAME_LEN);
        if (IS_ERR(old_pathname)) {
                printk("%s: [ERROR] could not get path from dentry\n", MODNAME);
                kfree(buff);
                return 0;
        }

        
        // Get the new path
        dentry = (struct dentry *)regs->cx;
        
        buff = (char *)kmalloc(GFP_KERNEL, MAX_FILENAME_LEN);
        if (!buff) {
                printk("%s: [ERROR] could not allocate memory for buffer\n", MODNAME);
                return 0;
        }
        new_pathname = dentry_path_raw(dentry, buff, MAX_FILENAME_LEN);
        if (IS_ERR(new_pathname)) {
                printk("%s: [ERROR] could not get path from dentry\n", MODNAME);
                kfree(buff);
                return 0;
        }

 
        // Check if old res is protected
        if (check_protected_resource(&ref_mon, old_pathname))
        {
                printk("%s: [ERROR] Blocked rename access to protected resource %s\n", MODNAME, old_pathname);
                return 0;
        }

        // Check if new res is protected
        if (check_protected_resource(&ref_mon, new_pathname))
        {
                printk("%s: [ERROR] Blocked rename access to protected resource %s\n", MODNAME, new_pathname);
                return 0;
        }
        
        return 1;
}

int security_inode_mkdir_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs)
{
        struct dentry *dentry;
        char *buff;
        const char *pathname;

        dentry = (struct dentry *)regs->si;
        

        // Get the dir path
        buff = (char *)kmalloc(GFP_KERNEL, MAX_FILENAME_LEN);
        if (!buff) {
                printk("%s: [ERROR] could not allocate memory for buffer\n", MODNAME);
                return 0;
        }
        pathname = dentry_path_raw(dentry, buff, MAX_FILENAME_LEN);
        if (IS_ERR(pathname)) {
                printk("%s: [ERROR] could not get path from dentry\n", MODNAME);
                kfree(buff);
                return 0;
        }

        // Check if file is protected
        if (check_protected_resource(&ref_mon, pathname))
        {
                printk("%s: [ERROR] Blocked mkdir access to protected resource %s\n", MODNAME, pathname);
                return 0;
        }
        
        return 1;
}

int security_path_mknod_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs)
{
        struct dentry *dentry;
        char *buff;
        const char *pathname;

        dentry = (struct dentry *)regs->si;
        

        // Get the dir path
        buff = (char *)kmalloc(GFP_KERNEL, MAX_FILENAME_LEN);
        if (!buff) {
                printk("%s: [ERROR] could not allocate memory for buffer\n", MODNAME);
                return 0;
        }
        pathname = dentry_path_raw(dentry, buff, MAX_FILENAME_LEN);
        if (IS_ERR(pathname)) {
                printk("%s: [ERROR] could not get path from dentry\n", MODNAME);
                kfree(buff);
                return 0;
        }

        // Check if file is protected
        if (check_protected_resource(&ref_mon, pathname))
        {
                printk("%s: [ERROR] Blocked mknod access to protected resource %s\n", MODNAME, pathname);
                return 0;
        }
        
        return 1;
}

int security_inode_rmdir_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs)
{
        struct dentry *dentry;
        char *buff;
        const char *pathname;

        dentry = (struct dentry *)regs->si;
        

        // Get the dir path
        buff = (char *)kmalloc(GFP_KERNEL, MAX_FILENAME_LEN);
        if (!buff) {
                printk("%s: [ERROR] could not allocate memory for buffer\n", MODNAME);
                return 0;
        }
        pathname = dentry_path_raw(dentry, buff, MAX_FILENAME_LEN);
        if (IS_ERR(pathname)) {
                printk("%s: [ERROR] could not get path from dentry\n", MODNAME);
                kfree(buff);
                return 0;
        }

        // Check if file is protected
        if (check_protected_resource(&ref_mon, pathname))
        {
                printk("%s: [ERROR] Blocked rmdir access to protected resource %s\n", MODNAME, pathname);
                return 0;
        }
        
        return 1;
}

int security_inode_create_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs)
{
        struct dentry *dentry;
        char *buff;
        const char *pathname;

        dentry = (struct dentry *)regs->si;
        

        // Get the dir path
        buff = (char *)kmalloc(GFP_KERNEL, MAX_FILENAME_LEN);
        if (!buff) {
                printk("%s: [ERROR] could not allocate memory for buffer\n", MODNAME);
                return 0;
        }
        pathname = dentry_path_raw(dentry, buff, MAX_FILENAME_LEN);
        if (IS_ERR(pathname)) {
                printk("%s: [ERROR] could not get path from dentry\n", MODNAME);
                kfree(buff);
                return 0;
        }

        // Check if file is protected
        if (check_protected_resource(&ref_mon, pathname))
        {
                printk("%s: [ERROR] Blocked create access to protected resource %s\n", MODNAME, pathname);
                return 0;
        }
        
        return 1;
}

int security_inode_link_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs)
{
        struct dentry *dentry;
        char *buff;
        const char *old_pathname;
        const char *new_pathname;

        // Get the old path
        dentry = (struct dentry *)regs->di;
        
        buff = (char *)kmalloc(GFP_KERNEL, MAX_FILENAME_LEN);
        if (!buff) {
                printk("%s: [ERROR] could not allocate memory for buffer\n", MODNAME);
                return 0;
        }
        
        old_pathname = dentry_path_raw(dentry, buff, MAX_FILENAME_LEN);
        if (IS_ERR(old_pathname)) {
                printk("%s: [ERROR] could not get path from dentry\n", MODNAME);
                kfree(buff);
                return 0;
        }

       // Get the new path
        dentry = (struct dentry *)regs->dx;
        
        buff = (char *)kmalloc(GFP_KERNEL, MAX_FILENAME_LEN);
        if (!buff) {
                printk("%s: [ERROR] could not allocate memory for buffer\n", MODNAME);
                return 0;
        }
        
        new_pathname = dentry_path_raw(dentry, buff, MAX_FILENAME_LEN);
        if (IS_ERR(new_pathname)) {
                printk("%s: [ERROR] could not get path from dentry\n", MODNAME);
                kfree(buff);
                return 0;
        }

        // Check if old path is protected
        if (check_protected_resource(&ref_mon, old_pathname))
        {
                printk("%s: [ERROR] Blocked link access to protected resource %s\n", MODNAME, old_pathname);
                return 0;
        }

        // Check if new path is protected
        if (check_protected_resource(&ref_mon, new_pathname))
        {
                printk("%s: [ERROR] Blocked link access to protected resource %s\n", MODNAME, new_pathname);
                return 0;
        }

        
        return 1;
}

int security_inode_unlink_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs)
{
        struct dentry *dentry;
        char *buff;
        const char *pathname;

        dentry = (struct dentry *)regs->si;
        

        // Get the dir path
        buff = (char *)kmalloc(GFP_KERNEL, MAX_FILENAME_LEN);
        if (!buff) {
                printk("%s: [ERROR] could not allocate memory for buffer\n", MODNAME);
                return 0;
        }
        pathname = dentry_path_raw(dentry, buff, MAX_FILENAME_LEN);
        if (IS_ERR(pathname)) {
                printk("%s: [ERROR] could not get path from dentry\n", MODNAME);
                kfree(buff);
                return 0;
        }

        // Check if file is protected
        if (check_protected_resource(&ref_mon, pathname))
        {
                printk("%s: [ERROR] Blocked unlink access to protected resource %s\n", MODNAME, pathname);
                return 0;
        }
        
        return 1;
}

int security_inode_symlink_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs)
{
        struct dentry *dentry;
        char *buff;
        const char *old_pathname;
        const char *new_pathname;

        // Get the old path
        
        old_pathname = (const char *)regs->dx;


       // Get the new path
        dentry = (struct dentry *)regs->si;
        
        buff = (char *)kmalloc(GFP_KERNEL, MAX_FILENAME_LEN);
        if (!buff) {
                printk("%s: [ERROR] could not allocate memory for buffer\n", MODNAME);
                return 0;
        }
        
        new_pathname = dentry_path_raw(dentry, buff, MAX_FILENAME_LEN);
        if (IS_ERR(new_pathname)) {
                printk("%s: [ERROR] could not get path from dentry\n", MODNAME);
                kfree(buff);
                return 0;
        }

        // Check if old path is protected
        if (check_protected_resource(&ref_mon, old_pathname))
        {
                printk("%s: [ERROR] Blocked symlink access to protected resource %s\n", MODNAME, old_pathname);
                return 0;
        }

        // Check if new path is protected
        if (check_protected_resource(&ref_mon, new_pathname))
        {
                printk("%s: [ERROR] Blocked symlink access to protected resource %s\n", MODNAME, new_pathname);
                return 0;
        }

        
        return 1;
}


// PROBES SETUP AND REGISTRATION
void setup_probe(struct kretprobe *probe, char *symbol, kretprobe_handler_t entry_handler, kretprobe_handler_t ret_handler)
{
        printk("%s: [INFO] Setting up probe for symbol %s\n", MODNAME, symbol);
        probe->kp.symbol_name = symbol;
        probe->handler = (kretprobe_handler_t)ret_handler;
        probe->entry_handler = entry_handler;
        probe->maxactive = -1; // unlimited instances cause it's stateless
}

int register_probes()
{
        int ret = 0, i;
        // Setup and register probes
        for (i = 0; i < KPROBES_SIZE; i++)
        {

                setup_probe(&kprobe_array[i], symbol_names[i], handler_array[i], ret_handler);
                ret = register_kretprobe(&kprobe_array[i]);
                if ((ret != 0) && (ret != -EBUSY))
                {
                        printk("%s: [ERROR] Kretprobe registration for symbol %s failed with %d\n", MODNAME, symbol_names[i], ret);
                        return ret;
                }
        }

        printk("%s: [INFO] Kretprobes correctly installed\n", MODNAME);

        return ret;
}

void unregister_probes()
{
        int i;
        for (i = 0; i < KPROBES_SIZE; i++)
        {

                unregister_kretprobe(&kprobe_array[i]);
        }

        printk("%s: [INFO] Kretprobes correctly removed\n", MODNAME);

        kfree(kprobe_array);
}

int enable_probes()
{
        int ret = 0, i;
        // Setup and register probes
        for (i = 0; i < KPROBES_SIZE; i++)
        {

                setup_probe(&kprobe_array[i], symbol_names[i], NULL, NULL);
                ret = enable_kretprobe(&kprobe_array[i]);
                if (ret < 0)
                {
                        printk("%s: [ERROR] Kretprobe enable for symbol %s  failed\n", MODNAME, symbol_names[i]);
                        return ret;
                }
        }

        printk("%s: [INFO] Kretprobes correctly enabled\n", MODNAME);

        return ret;
}

void disable_probes()
{
        int i;
        for (i = 0; i < KPROBES_SIZE; i++)
        {

                disable_kretprobe(&kprobe_array[i]);
        }

        printk("%s: [INFO] Kretprobes correctly removed\n", MODNAME);

        kfree(kprobe_array);
}

int init_module(void)
{

        int i;
        int ret;

        printk("%s: [INFO] initializing reference monitor state\n", MODNAME);

        // setup password
        ref_mon.hash_passwd = kmalloc(HASH_LEN, GFP_KERNEL);
        if (ref_mon.hash_passwd == NULL)
        {
                printk("%s: [ERROR] could not allocate memory for password\n", MODNAME);
                return -ENOMEM;
        }

        if (compute_sha256(passwd, strlen(passwd), ref_mon.hash_passwd) < 0)
        {
                printk("%s: [ERROR] could not compute sha256 of password\n", MODNAME);
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

        printk("%s: [INFO] Initializing probes\n", MODNAME);
        register_probes();

        if (syscall_table_addr == 0x0)
        {
                printk("%s: [ERROR] cannot manage sys_call_table address set to 0x0\n", MODNAME);
                unregister_probes();
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

        ret = get_entries(restore, HACKED_ENTRIES, (unsigned long *)syscall_table_addr, &the_ni_syscall);

        if (ret != HACKED_ENTRIES)
        {
                printk("%s: [ERROR] could not hack %d entries (just %d)\n", MODNAME, HACKED_ENTRIES, ret);
                unregister_probes();
                return GENERIC_ERR;
        }

        unprotect_memory();

        for (i = 0; i < HACKED_ENTRIES; i++)
        {
                ((unsigned long *)syscall_table_addr)[restore[i]] = (unsigned long)new_sys_call_array[i];
        }

        protect_memory();

        printk("%s: [INFO] all new system-calls correctly installed on sys-call table\n", MODNAME);

        printk("%s: [INFO] reference monitor correctly initialized\n", MODNAME);

        return SUCCESS;
}

void cleanup_module(void)
{

        int i;

        printk("%s: [INFO] shutting down\n", MODNAME);

        unprotect_memory();
        for (i = 0; i < HACKED_ENTRIES; i++)
        {
                ((unsigned long *)syscall_table_addr)[restore[i]] = the_ni_syscall;
        }
        protect_memory();
        printk("%s: [INFO] sys-call table restored to its original content\n", MODNAME);
        unregister_probes();
}