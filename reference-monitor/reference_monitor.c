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
#include "deferred_log.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Matteo Conti <matteo.conti.97@students.uniroma2.eu>");
MODULE_DESCRIPTION("This module implements a reference monitor which offers a set of system calls to manage protected resources and a set of kernel probes to block write operations on protected resources");

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

// SYSTEM CALLS

// Change reference monitor state
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(2, _switch_state, int, state, char __user *, passwd)
{
#else
asmlinkage long sys_switch_state(int state, char __user *passwd)
{
#endif
        char *hash_passwd;
        char *kpasswd;
        int prev_state;
        printk("%s: [INFO] switch_state syscall called\n", MODNAME);

        // Check effective user id to be root
        if (!uid_eq(current_euid(), GLOBAL_ROOT_UID))
        {
                printk("%s: [ERROR] only user root can change the reference monitor configuration\n", MODNAME);
                return OP_NOT_PERMITTED_ERR;
        }

        //Copy password from user space
        kpasswd = kmalloc(PASSWD_LEN, GFP_KERNEL);
        if (kpasswd == NULL)
        {
                printk("%s: [ERROR] could not allocate memory for password\n", MODNAME);
                return -ENOMEM;
        }

        if(copy_from_user(kpasswd, passwd, PASSWD_LEN))
        {
                printk("%s: [ERROR] failed to copy password from userspace\n", MODNAME);
                kfree(kpasswd);
                return -EFAULT;
        }

        // Check password hash
        hash_passwd = kmalloc(HASH_HEX_SIZE, GFP_KERNEL);
        if (hash_passwd == NULL)
        {
                printk("%s: [ERROR] could not allocate memory for password\n", MODNAME);
                return -ENOMEM;
        }

        if (compute_sha256(kpasswd, strlen(kpasswd), hash_passwd) < 0)
        {
                printk("%s: [ERROR] could not compute sha256 of given password\n", MODNAME);
                return GENERIC_ERR;
        }

        spin_lock(&ref_mon.lock);

        if (!compare_hashes(hash_passwd, ref_mon.hash_passwd, HASH_HEX_SIZE))
        {
                printk("%s: [ERROR] given password does not match\n", MODNAME);
                spin_unlock(&ref_mon.lock);
                return PASSWD_MISMATCH_ERR;
        }

        spin_unlock(&ref_mon.lock);

        kfree(kpasswd);
        kfree(hash_passwd);

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
                        printk("%s: Enabling probes\n", MODNAME);
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
                        printk("%s: Enabling probes\n", MODNAME);
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
                        printk("%s: Disabling probes\n", MODNAME);
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
                        printk("%s: Disabling probes\n", MODNAME);
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
__SYSCALL_DEFINEx(2, _add_protected_res, char __user *, res_path, char __user *, passwd)
{
#else
asmlinkage long sys_add_protected_res(char __user *res_path, char __user *passwd)
{
#endif
        char *hash_passwd;
        char *kpasswd;
        char *kres_path;
        int res;
        protected_resource *new_protected_resource;
        printk("%s: [INFO] add_protected_res syscall called\n", MODNAME);

        // Check effective user id to be root
        if (!uid_eq(current_euid(), GLOBAL_ROOT_UID))
        {
                printk("%s: [ERROR] only user root can change the reference monitor configuration\n", MODNAME);
                return OP_NOT_PERMITTED_ERR;
        }

        //Copy password from user space
        kpasswd = kmalloc(PASSWD_LEN, GFP_KERNEL);
        if (kpasswd == NULL)
        {
                printk("%s: [ERROR] could not allocate memory for password\n", MODNAME);
                return -ENOMEM;
        }

        if(copy_from_user(kpasswd, passwd, PASSWD_LEN))
        {
                printk("%s: [ERROR] failed to copy password from userspace\n", MODNAME);
                kfree(kpasswd);
                return -EFAULT;
        }

        // Check password hash
        hash_passwd = kmalloc(HASH_HEX_SIZE, GFP_KERNEL);
        if (hash_passwd == NULL)
        {
                printk("%s: [ERROR] could not allocate memory for password\n", MODNAME);
                kfree(kpasswd);
                return -ENOMEM;
        }

        if (compute_sha256(kpasswd, strlen(kpasswd), hash_passwd) < 0)
        {
                printk("%s: [ERROR] could not compute sha256 of given password\n", MODNAME);
                kfree(kpasswd);
                kfree(hash_passwd);
                return GENERIC_ERR;
        }

        spin_lock(&ref_mon.lock);

        if (!compare_hashes(hash_passwd, ref_mon.hash_passwd, HASH_HEX_SIZE))
        {
                printk("%s: [ERROR] given password does not match\n", MODNAME);
                spin_unlock(&ref_mon.lock);

                kfree(kpasswd);
                kfree(hash_passwd);

                return PASSWD_MISMATCH_ERR;
        }


        // Check if reference monitor is in reconfiguration mode
        if ((ref_mon.state != REC_ON) && (ref_mon.state != REC_OFF))
        {
                printk("%s: [ERROR] reference monitor is not in reconfiguration mode\n", MODNAME);
                spin_unlock(&ref_mon.lock);
                
                kfree(kpasswd);
                kfree(hash_passwd);
                
                return OP_NOT_PERMITTED_ERR;
        }

        spin_unlock(&ref_mon.lock);

        kfree(kpasswd);
        kfree(hash_passwd);

        // Copy resource path from user space
        kres_path = kmalloc(MAX_FILENAME_LEN, GFP_KERNEL);
        if (kres_path == NULL)
        {
                printk("%s: [ERROR] could not allocate memory for resource path\n", MODNAME);
                return -ENOMEM;
        }

        if(copy_from_user(kres_path, res_path, MAX_FILENAME_LEN))
        {
                printk("%s: [ERROR] failed to copy res path from userspace\n", MODNAME);
                kfree(kres_path);
                return -EFAULT;
        }

        // Create the new protected resource
        new_protected_resource = create_protected_resource(kres_path);
        if (new_protected_resource == NULL)
        {
                printk("%s: [ERROR] could not create new protected resource\n", MODNAME);
                kfree(kres_path);
                return GENERIC_ERR;
        }

        kfree(kres_path);

        // Add the new protected resource to the list
        res = add_new_protected_resource(&ref_mon, new_protected_resource);
        if(res == RES_ALREADY_PROTECTED_ERR){
                printk("%s: [ERROR] resource already protected\n", MODNAME);
                kfree(new_protected_resource);
                return RES_ALREADY_PROTECTED_ERR;
        }

        //TODO Only for debug purposes, remove in production
        print_protected_resources(&ref_mon);
        
        return SUCCESS;
}

// Remove the path of a protected resource by the reference monitor
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(2, _rm_protected_res, char __user *, res_path, char __user *, passwd)
{
#else
asmlinkage long sys_rm_protected_res(char __user *res_path, char __user *passwd)
{
#endif
        int res;
        char *kres_path;
        char *kpasswd;
        char *hash_passwd;
        printk("%s: [INFO] rm_protected_res syscall called\n", MODNAME);

        // Check effective user id to be root
        if (!uid_eq(current_euid(), GLOBAL_ROOT_UID))
        {
                printk("%s: [ERROR] only user root can change the reference monitor configuration\n", MODNAME);
                return OP_NOT_PERMITTED_ERR;
        }

        //Copy password from user space
        kpasswd = kmalloc(PASSWD_LEN, GFP_KERNEL);
        if (kpasswd == NULL)
        {
                printk("%s: [ERROR] could not allocate memory for password\n", MODNAME);
                return -ENOMEM;
        }

        if(copy_from_user(kpasswd, passwd, PASSWD_LEN))
        {
                printk("%s: [ERROR] failed to copy password from userspace\n", MODNAME);
                kfree(kpasswd);
                return -EFAULT;
        }

        // Check password hash
        hash_passwd = kmalloc(HASH_HEX_SIZE, GFP_KERNEL);
        if (hash_passwd == NULL)
        {
                printk("%s: [ERROR] could not allocate memory for password\n", MODNAME);
                kfree(kpasswd);
                return -ENOMEM;
        }

        if (compute_sha256(kpasswd, strlen(kpasswd), hash_passwd) < 0)
        {
                printk("%s: [ERROR] could not compute sha256 of given password\n", MODNAME);           
                kfree(kpasswd);
                kfree(hash_passwd);
                return GENERIC_ERR;
        }

        spin_lock(&ref_mon.lock);

        if (!compare_hashes(hash_passwd, ref_mon.hash_passwd, HASH_HEX_SIZE))
        {
                printk("%s: [ERROR] given password does not match\n", MODNAME);
                spin_unlock(&ref_mon.lock);     
                kfree(kpasswd);
                kfree(hash_passwd);
                return PASSWD_MISMATCH_ERR;
        }


        // Check if reference monitor is in reconfiguration mode
        if ((ref_mon.state != REC_ON) && (ref_mon.state != REC_OFF))
        {
                printk("%s: [ERROR] reference monitor is not in reconfiguration mode\n", MODNAME);
                spin_unlock(&ref_mon.lock);
                kfree(kpasswd);
                kfree(hash_passwd);
                return OP_NOT_PERMITTED_ERR;
        }

        spin_unlock(&ref_mon.lock);

        kfree(kpasswd);
        kfree(hash_passwd);

        // Copy resource path from user space
        kres_path = kmalloc(MAX_FILENAME_LEN, GFP_KERNEL);
        if (kres_path == NULL)
        {
                printk("%s: [ERROR] could not allocate memory for resource path\n", MODNAME);
                return -ENOMEM;
        }

        if(copy_from_user(kres_path, res_path, MAX_FILENAME_LEN))
        {
                printk("%s: [ERROR] failed to copy res path from userspace\n", MODNAME);
                kfree(kres_path);
                return -EFAULT;
        }

        res = remove_protected_resource(&ref_mon, kres_path);
        if(res == RES_NOT_PROTECTED_ERR){
                printk("%s: [ERROR] resource not protected\n", MODNAME);
                kfree(kres_path);
                return RES_NOT_PROTECTED_ERR;
        }

        //TODO Only for debug purposes, remove in production
        print_protected_resources(&ref_mon);

        kfree(kres_path);

        return SUCCESS;
}

// Change reference monitor password
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(2, _change_passwd, char __user *, new_passwd, char __user *, old_passwd)
{
#else
asmlinkage long sys_change_passwd(char __user *new_passwd, char __user *old_passwd)
{
#endif
        char *hash_passwd;
        char *knew_passwd;
        char *kold_passwd;
        printk("%s: [INFO] change_passwd syscall called\n", MODNAME);

        // Check effective user id to be root
        if (!uid_eq(current_euid(), GLOBAL_ROOT_UID))
        {
                printk("%s: [ERROR] only user root can change the reference monitor password\n", MODNAME);
                return OP_NOT_PERMITTED_ERR;
        }

        //Copy password from user space
        knew_passwd = kmalloc(PASSWD_LEN, GFP_KERNEL);
        if (knew_passwd == NULL)
        {
                printk("%s: [ERROR] could not allocate memory for new password\n", MODNAME);
                return -ENOMEM;
        }

        if(copy_from_user(knew_passwd, new_passwd, PASSWD_LEN))
        {
                printk("%s: [ERROR] failed to copy new password from userspace\n", MODNAME);
                kfree(knew_passwd);
                return -EFAULT;
        }

        kold_passwd = kmalloc(PASSWD_LEN, GFP_KERNEL);
        if (kold_passwd == NULL)
        {
                printk("%s: [ERROR] could not allocate memory for old password\n", MODNAME);
                kfree(knew_passwd);
                return -ENOMEM;
        }

        if(copy_from_user(kold_passwd, old_passwd, PASSWD_LEN))
        {
                printk("%s: [ERROR] failed to copy old password from userspace\n", MODNAME);
                kfree(knew_passwd);
                kfree(kold_passwd);
                return -EFAULT;
        }

        // Check password hash
        hash_passwd = kmalloc(HASH_HEX_SIZE, GFP_KERNEL);
        if (hash_passwd == NULL)
        {
                printk("%s: [ERROR] could not allocate memory for password hash\n", MODNAME);
                kfree(knew_passwd);
                kfree(kold_passwd);
                return -ENOMEM;
        }

        if (compute_sha256(kold_passwd, strlen(kold_passwd), hash_passwd) < 0)
        {
                printk("%s: [ERROR] could not compute sha256 of given password\n", MODNAME);
                kfree(knew_passwd);
                kfree(kold_passwd);
                kfree(hash_passwd);
                return GENERIC_ERR;
        }

        spin_lock(&ref_mon.lock);

        if (!compare_hashes(hash_passwd, ref_mon.hash_passwd, HASH_HEX_SIZE))
        {
                printk("%s: [ERROR] given password does not match\n", MODNAME);
                spin_unlock(&ref_mon.lock);
                kfree(knew_passwd);
                kfree(kold_passwd);
                kfree(hash_passwd);
                return PASSWD_MISMATCH_ERR;
        }

        

        // Check if reference monitor is in reconfiguration mode
        if ((ref_mon.state != REC_ON) && (ref_mon.state != REC_OFF))
        {
                printk("%s: [ERROR] reference monitor is not in reconfiguration mode\n", MODNAME);
                spin_unlock(&ref_mon.lock);
                kfree(knew_passwd);
                kfree(kold_passwd);
                kfree(hash_passwd);
                return OP_NOT_PERMITTED_ERR;
        }

        //Compute and store new password hash
        if (compute_sha256(knew_passwd, strlen(knew_passwd), ref_mon.hash_passwd) < 0)
        {
                printk("%s: [ERROR] could not compute sha256 of password\n", MODNAME);
                spin_unlock(&ref_mon.lock);
                kfree(knew_passwd);
                kfree(kold_passwd);
                kfree(hash_passwd);
                return GENERIC_ERR;
        }

        spin_unlock(&ref_mon.lock);

        kfree(knew_passwd);
        kfree(kold_passwd);
        kfree(hash_passwd);

        return SUCCESS;
}



#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
long sys_switch_state = (unsigned long)__x64_sys_switch_state;
long sys_add_protected_res = (unsigned long)__x64_sys_add_protected_res;
long sys_rm_protected_res = (unsigned long)__x64_sys_rm_protected_res;
long sys_change_passwd = (unsigned long)__x64_sys_change_passwd;
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

//TODO MODIFICARE GLI HANDLER IN MODO CHE LA ROBA CHE MODIFICA IL CONTENUTO DIRECTORY PASSI SOLO IL PREFIX E NON TUTTO IL PATH E LA ROBA CHE MODIFICA FILE PASSI TUTTO
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
                if (rcu_check_protected_resource(&ref_mon, pathname))
                {
                        printk("%s: [ERROR] Blocked open access to protected resource %s\n", MODNAME, pathname);
                        setup_deferred_work();
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
        if (rcu_check_protected_resource(&ref_mon, pathname))
        {
                printk("%s: [ERROR] Blocked truncate access to protected resource %s\n", MODNAME, pathname);
                setup_deferred_work();
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
        if (rcu_check_protected_resource(&ref_mon, old_pathname))
        {
                printk("%s: [ERROR] Blocked rename access to protected resource %s\n", MODNAME, old_pathname);
                setup_deferred_work();
                return 0;
        }

        // Check if new res is protected for overwriting
        if (rcu_check_protected_resource(&ref_mon, new_pathname))
        {
                printk("%s: [ERROR] Blocked rename access to protected resource %s\n", MODNAME, new_pathname);
                setup_deferred_work();
                return 0;
        }

        //Check if old res is in a protected directory
        get_prefix(old_pathname);
        if (rcu_check_protected_resource(&ref_mon, old_pathname))
        {
                printk("%s: [ERROR] Blocked rename access to protected resource %s\n", MODNAME, old_pathname);
                setup_deferred_work();
                return 0;
        }

        // Check if new res is in a protected directory
        get_prefix(new_pathname);
        if (rcu_check_protected_resource(&ref_mon, new_pathname))
        {
                printk("%s: [ERROR] Blocked rename access to protected resource %s\n", MODNAME, new_pathname);
                setup_deferred_work();
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

        // Check if is in a protected directory
        get_prefix(pathname);
        if (rcu_check_protected_resource(&ref_mon, pathname))
        {
                printk("%s: [ERROR] Blocked mkdir access to protected resource %s\n", MODNAME, pathname);
                setup_deferred_work();
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

        // Check if is in a protected directory
        get_prefix(pathname);
        if (rcu_check_protected_resource(&ref_mon, pathname))
        {
                printk("%s: [ERROR] Blocked mknod access to protected resource %s\n", MODNAME, pathname);
                setup_deferred_work();
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

        // Check if directory is protected
        if (rcu_check_protected_resource(&ref_mon, pathname))
        {
                printk("%s: [ERROR] Blocked rmdir access to protected resource %s\n", MODNAME, pathname);
                setup_deferred_work();
                return 0;
        }

        // Check if directory is in a protected directory
        get_prefix(pathname);
        if (rcu_check_protected_resource(&ref_mon, pathname))
        {
                printk("%s: [ERROR] Blocked rmdir access to protected resource %s\n", MODNAME, pathname);
                setup_deferred_work();
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

        // Check if attempting to overwrite protected file
        if (rcu_check_protected_resource(&ref_mon, pathname))
        {
                printk("%s: [ERROR] Blocked create access to protected resource %s\n", MODNAME, pathname);
                setup_deferred_work();
                return 0;
        }

        // Check if attempting to create file in a protected directory
        get_prefix(pathname);
        if (rcu_check_protected_resource(&ref_mon, pathname))
        {
                printk("%s: [ERROR] Blocked create access to protected resource %s\n", MODNAME, pathname);
                setup_deferred_work();
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
        if (rcu_check_protected_resource(&ref_mon, old_pathname))
        {
                printk("%s: [ERROR] Blocked link access to protected resource %s\n", MODNAME, old_pathname);
                setup_deferred_work();
                return 0;
        }

        // Check if new path is protected
        if (rcu_check_protected_resource(&ref_mon, new_pathname))
        {
                printk("%s: [ERROR] Blocked link access to protected resource %s\n", MODNAME, new_pathname);
                setup_deferred_work();
                return 0;
        }

        //check if new path is in a protected directory
        get_prefix(new_pathname);
        if (rcu_check_protected_resource(&ref_mon, new_pathname))
        {
                printk("%s: [ERROR] Blocked link access to protected resource %s\n", MODNAME, new_pathname);
                setup_deferred_work();
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
        if (rcu_check_protected_resource(&ref_mon, pathname))
        {
                printk("%s: [ERROR] Blocked unlink access to protected resource %s\n", MODNAME, pathname);
                setup_deferred_work();
                return 0;
        }

        // Check if file is in a protected directory
        get_prefix(pathname);
        if (rcu_check_protected_resource(&ref_mon, pathname))
        {
                printk("%s: [ERROR] Blocked unlink access to protected resource %s\n", MODNAME, pathname);
                setup_deferred_work();
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
        char *old_full_pathname;
        char *buf;
        struct path path;

        // Get the old path
        
        old_pathname = (const char *)regs->dx;
        // Resolve the relative path to a struct path
        if (kern_path(old_pathname, LOOKUP_FOLLOW, &path)) {
            printk("%s: [ERROR] could not resolve old path\n", MODNAME);
            return 0;
        }

        // Allocate buffer for the absolute path
        buf = kmalloc(GFP_KERNEL, MAX_FILENAME_LEN);
        if (!buf) {
            printk("%s: [ERROR] Failed to allocate memory.\n", MODNAME);
            return 0;
        }

        // Get the absolute path from the struct path
        old_full_pathname = dentry_path_raw(path.dentry, buf, MAX_FILENAME_LEN);
        if (IS_ERR(old_full_pathname)) {
            printk("%s: [ERROR] Failed to get the absolute path.\n", MODNAME);
            kfree(buf);
            return 0;
        }


       // Get the new path
        dentry = (struct dentry *)regs->si;
        
        buff = (char *)kmalloc(GFP_KERNEL, MAX_FILENAME_LEN);
        if (!buff) {
                printk("%s: [ERROR] could not allocate memory for buffer\n", MODNAME);
                kfree(buf);
                return 0;
        }
        
        new_pathname = dentry_path_raw(dentry, buff, MAX_FILENAME_LEN);
        if (IS_ERR(new_pathname)) {
                printk("%s: [ERROR] could not get path from dentry\n", MODNAME);
                kfree(buff);
                kfree(buf);
                return 0;
        }
        printk("OLD PATH NAME: %s\n", old_pathname);
        printk("OLD FULLPATH NAME: %s\n", old_full_pathname);
        printk("NEW PATH NAME: %s\n", new_pathname);

        // Check if old path is protected
        if (rcu_check_protected_resource(&ref_mon, old_full_pathname))
        {
                printk("%s: [ERROR] Blocked symlink access to protected resource %s\n", MODNAME, old_full_pathname);
                setup_deferred_work();
                kfree(buff);
                kfree(buf);
                return 0;
        }

        // Check if new path is protected
        if (rcu_check_protected_resource(&ref_mon, new_pathname))
        {
                printk("%s: [ERROR] Blocked symlink access to protected resource %s\n", MODNAME, new_pathname);
                setup_deferred_work();
                kfree(buff);
                kfree(buf);
                return 0;
        }

        //check if new path is in a protected directory
        get_prefix(new_pathname);
        if (rcu_check_protected_resource(&ref_mon, new_pathname))
        {
                printk("%s: [ERROR] Blocked symlink access to protected resource %s\n", MODNAME, new_pathname);
                setup_deferred_work();
                kfree(buff);
                kfree(buf);
                return 0;
        }

        kfree(buff);
        kfree(buf);
        
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

                //setup_probe(&kprobe_array[i], symbol_names[i], NULL, NULL);
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

}

//DEFERRED LOGGING

//Collect the data to be logged
void setup_deferred_work(void){
        struct dentry *exe_dentry;
        struct mm_struct *mm;
        int tid, tgid, uid, euid;
        char *exe_path;
        packed_work *task;
        char *buff;

        printk("%s: [INFO] setting up deferred work\n", MODNAME);


        tid = current->pid;
        tgid = task_tgid_vnr(current);
        uid = current_uid().val;
        euid = current_euid().val;

        //Get the path of the executable who attempted the operation
        mm = current->mm;
        exe_dentry = mm->exe_file->f_path.dentry;

        buff = (char *)kmalloc(GFP_KERNEL, MAX_FILENAME_LEN);
        if (!buff) {
                printk("%s: [ERROR] could not allocate memory for buffer\n", MODNAME);
                return;
        }

        exe_path = dentry_path_raw(exe_dentry, buff, MAX_FILENAME_LEN);
        if (IS_ERR(exe_path)) {
                printk("%s: [ERROR] could not get path from dentry\n", MODNAME);
                kfree(buff);
                return;
        }

        // Schedule hash computation and writing on file in deferred work 
        task = kmalloc(sizeof(packed_work), GFP_KERNEL);
        if (task == NULL)
        {
                printk("%s: [ERROR] tasklet allocation failure\n", MODNAME);
                return;
        }

        task->buffer = task;

        task->tid = tid;
        task->tgid = tgid;
        task->uid = uid;
        task->euid = euid;
        task->exe_path = exe_path;

        // Init and schedule the deferred work
        __INIT_WORK(&(task->work), (void *)deferred_log, (unsigned long)(&(task->work)));
        schedule_work(&task->work);
        printk("%s: [INFO] deferred work scheduled\n", MODNAME);
}

//Compute the hash of the exe who attempted the operation and write the data on a file
void deferred_log(unsigned long data){
        char log_row[512];
        struct file *log_file;
        struct file *exe_file;
        long ret;
        loff_t pos=0; 
        int tid, tgid, uid, euid;
        char *exe_path;
        char *exe_content;
        int exe_size;
        char exe_hash[HASH_HEX_SIZE];
        packed_work *task;

        printk("%s: [INFO] executing deferred work\n", MODNAME);

        task = container_of((void *)data, packed_work, work);

        tid = task->tid;
        tgid = task->tgid;
        uid = task->uid;
        euid = task->euid;
        exe_path = task->exe_path;

        //Hash computation
        //Open the exe file
        exe_file = filp_open(exe_path, O_RDONLY, 0);
        if (IS_ERR(exe_file)) {
                printk("%s [ERROR] Can't open exe file", MODNAME);
                strcpy(exe_hash, "N/A");
                goto build_log_row;
        }
        
        //Get the size of the exe file
        exe_size = vfs_llseek(exe_file, 0, SEEK_END);
        if (exe_size < 0) {
                printk("%s [ERROR] Can't seek exe file", MODNAME);
                strcpy(exe_hash, "N/A");
                goto build_log_row;
        }

        //Read the content of the exe file
        vfs_llseek(exe_file, 0, SEEK_SET);
        exe_content = kmalloc(exe_size + 1, GFP_KERNEL);
        if (!exe_content) {
                printk("%s [ERROR] Can't allocate memory for exe content", MODNAME);
                strcpy(exe_hash, "N/A");
                goto build_log_row;
        }

        ret = kernel_read(exe_file, exe_content, exe_size, &pos); 
        if (ret != exe_size) {
                printk("%s [ERROR] Can't read exe file", MODNAME);
                strcpy(exe_hash, "N/A");
                goto build_log_row;
        } else{
                exe_content[ret] = '\0';
        }

        //Compute the hash of the exe file
        if (compute_sha256(exe_content, ret, exe_hash) < 0)
        {
                printk("%s: [ERROR] could not compute sha256 of exe content\n", MODNAME);
                strcpy(exe_hash, "N/A");
                goto build_log_row;
        }

        //Build the log row
build_log_row:
        snprintf(log_row, 512, "%d, %d, %d, %d, %s, %s\n", tid, tgid, uid, euid, exe_path, exe_hash);

        printk("%s: [INFO] log row: %s\n", MODNAME, log_row);

        //Write the log row on the log file
        log_file = filp_open(LOG_PATH, O_WRONLY, 0644); 
        if (IS_ERR(log_file))
        {
                printk("%s [ERROR] Error in opening log file", MODNAME);
                filp_close(exe_file, NULL);
                kfree(exe_content);
                kfree(task);
                
        }

        ret = kernel_write(log_file, log_row, strlen(log_row), &log_file->f_pos);
        if (ret < 0)
        {
                printk("%s [ERROR] Error in writing on log file", MODNAME);
        }

        filp_close(exe_file, NULL);
        filp_close(log_file, NULL);
        kfree(exe_content);
        kfree(task);
}

// MODULE INIT AND CLEANUP
int init_module(void)
{

        int i;
        int ret;

        printk("%s: [INFO] initializing reference monitor state\n", MODNAME);

        // setup password
        ref_mon.hash_passwd = kmalloc(HASH_HEX_SIZE, GFP_KERNEL);
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

        printk("%s: [INFO] PASSWORD HASH %s", MODNAME, ref_mon.hash_passwd);

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


        printk("%s: received sys_call_table address %px\n", MODNAME, (void *)syscall_table_addr);
        printk("%s: initializing - hacked entries %d\n", MODNAME, HACKED_ENTRIES);
        

        new_sys_call_array[0] = (unsigned long)sys_switch_state;
        new_sys_call_array[1] = (unsigned long)sys_add_protected_res;
        new_sys_call_array[2] = (unsigned long)sys_rm_protected_res;
        new_sys_call_array[3] = (unsigned long)sys_change_passwd;

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