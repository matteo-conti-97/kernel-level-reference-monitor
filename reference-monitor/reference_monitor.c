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
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include "lib/include/scth.h"
#include "reference_monitor.h"
#include "../utils/utils.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Matteo Conti <matteo.conti.97@students.uniroma2.eu>");

#define MODNAME "REFERENCE_MONITOR"

unsigned long syscall_table_addr = 0x0;
module_param(syscall_table_addr, ulong, 0660);

char passwd[PASSWD_LEN];
module_param_string(passwd, passwd, PASSWD_LEN, 0);

unsigned long the_ni_syscall;

unsigned long new_sys_call_array[] = {0x0, 0x1, 0x2, 0x3}; // please set to sys_vtpmo at startup
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array) / sizeof(unsigned long))
// #define HACKED_ENTRIES 2
int restore[HACKED_ENTRIES] = {[0 ...(HACKED_ENTRIES - 1)] - 1};

#define AUDIT if (1)

// Change reference monitor state
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(2, _switch_state, int, state, char *, passwd)
{
#else
asmlinkage long sys_switch_state(int state, char *passwd)
{
#endif
        char *hash_passwd;
        printk("%s: switch_state syscall called\n", MODNAME);

        //Check effective user id to be root
        if (!uid_eq(current_euid(), GLOBAL_ROOT_UID))
        {
                printk("%s: [ERROR] only user root can change the reference monitor configuration\n", MODNAME);
                return -1;
        }

        // Check password hash
        hash_passwd = kmalloc(HASH_LEN, GFP_KERNEL);
        if (hash_passwd == NULL)
        {
                printk("%s: could not allocate memory for password\n", MODNAME);
                return -1;
        }

        if (compute_sha256(passwd, strlen(passwd), hash_passwd) < 0)
        {
                printk("%s: could not compute sha256 of given password\n", MODNAME);
                return -1;
        }

        if (!compare_hashes(hash_passwd, reference_monitor.hash_passwd, HASH_LEN))
        {
                printk("%s: [ERROR] given password does not match\n", MODNAME);
                return -1;
        }

        //Lock the reference monitor and change the state
        spin_lock(&reference_monitor.lock);
        switch(state)
        {
                case REC_ON:
                        printk("%s: setting reference monitor state to REC-ON\n", MODNAME);
                        reference_monitor.state = REC_ON;
                        //TODO Enable kprobes
                        break;
                case ON:
                        printk("%s: setting reference monitor state to ON\n", MODNAME);
                        reference_monitor.state = ON;
                        //TODO Enable kprobes
                        break;
                case REC_OFF:
                        printk("%s: setting reference monitor state to REC-OFF\n", MODNAME);
                        reference_monitor.state = REC_OFF;
                        //TODO Disable kprobes
                        break;
                case OFF:
                        printk("%s: setting reference monitor state to OFF\n", MODNAME);
                        reference_monitor.state = OFF;
                        //TODO Disable kprobes
                        break;
                default:
                        printk("%s: [ERROR] invalid state given\n", MODNAME);
                        spin_unlock(&reference_monitor.lock);
                        return -1;
        }
        spin_unlock(&reference_monitor.lock);

        return 0;
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
        printk("%s: add_protected_res syscall called\n", MODNAME);

        //Check effective user id to be root
        if (!uid_eq(current_euid(), GLOBAL_ROOT_UID))
        {
                printk("%s: [ERROR] only user root can change the reference monitor configuration\n", MODNAME);
                return -1;
        }

        // Check password hash
        hash_passwd = kmalloc(HASH_LEN, GFP_KERNEL);
        if (hash_passwd == NULL)
        {
                printk("%s: could not allocate memory for password\n", MODNAME);
                return -1;
        }

        if (compute_sha256(passwd, strlen(passwd), hash_passwd) < 0)
        {
                printk("%s: could not compute sha256 of given password\n", MODNAME);
                return -1;
        }

        if (!compare_hashes(hash_passwd, reference_monitor.hash_passwd, HASH_LEN))
        {
                printk("%s: [ERROR] given password does not match\n", MODNAME);
                return -1;
        }

        return 0;
}

// Remove the path of a protected resource by the reference monitor
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(2, _rm_protected_res, char *, res_path, char *, passwd)
{
#else
asmlinkage long sys_rm_protected_res(char *res_path, char *passwd)
{
#endif
        char *hash_passwd;
        printk("%s: rm_protected_res syscall called\n", MODNAME);

        //Check effective user id to be root
        if (!uid_eq(current_euid(), GLOBAL_ROOT_UID))
        {
                printk("%s: [ERROR] only user root can change the reference monitor configuration\n", MODNAME);
                return -1;
        }

        // Check password hash
        hash_passwd = kmalloc(HASH_LEN, GFP_KERNEL);
        if (hash_passwd == NULL)
        {
                printk("%s: could not allocate memory for password\n", MODNAME);
                return -1;
        }

        if (compute_sha256(passwd, strlen(passwd), hash_passwd) < 0)
        {
                printk("%s: could not compute sha256 of given password\n", MODNAME);
                return -1;
        }

        if (!compare_hashes(hash_passwd, reference_monitor.hash_passwd, HASH_LEN))
        {
                printk("%s: [ERROR] given password does not match\n", MODNAME);
                return -1;
        }

        return 0;
}

// Get the path of all the protected resources by the reference monitor
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(1, _get_protected_res_list, char **, buff)
{
#else
asmlinkage long sys_get_protected_res_list(char **buff)
{
#endif
        printk("%s: get_protected_res_list syscall called\n", MODNAME);
        return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
long sys_switch_state = (unsigned long)__x64_sys_switch_state;
long sys_add_protected_res = (unsigned long)__x64_sys_add_protected_res;
long sys_rm_protected_res = (unsigned long)__x64_sys_rm_protected_res;
long sys_get_protected_res_list = (unsigned long)__x64_sys_get_protected_res_list;
#else
#endif

int init_module(void)
{

        int i;
        int ret;

        printk("%s: initializing reference monitor state\n", MODNAME);

        // setup password
        reference_monitor.hash_passwd = kmalloc(HASH_LEN, GFP_KERNEL);
        if (reference_monitor.hash_passwd == NULL)
        {
                printk("%s: could not allocate memory for password\n", MODNAME);
                return -1;
        }

        if (compute_sha256(passwd, strlen(passwd), reference_monitor.hash_passwd) < 0)
        {
                printk("%s: could not compute sha256 of password\n", MODNAME);
                return -1;
        }

        // delete password
        memset(passwd, 0, PASSWD_LEN);

        // setup state
        reference_monitor.state = OFF;

        // setup protected resources list
        reference_monitor.protected_resource_list_head = NULL;

        // setup lock
        spin_lock_init(&reference_monitor.lock);

        if (syscall_table_addr == 0x0)
        {
                printk("%s: cannot manage sys_call_table address set to 0x0\n", MODNAME);
                return -1;
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
                return -1;
        }

        unprotect_memory();

        for (i = 0; i < HACKED_ENTRIES; i++)
        {
                ((unsigned long *)syscall_table_addr)[restore[i]] = (unsigned long)new_sys_call_array[i];
        }

        protect_memory();

        printk("%s: all new system-calls correctly installed on sys-call table\n", MODNAME);

        printk("%s: reference monitor correctly initialized\n", MODNAME);

        return 0;
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
