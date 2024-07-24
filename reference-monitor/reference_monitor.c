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




MODULE_LICENSE("GPL");
MODULE_AUTHOR("Matteo Conti <matteo.conti.97@students.uniroma2.eu>");

#define MODNAME "REFERENCE_MONITOR"

unsigned long syscall_table_addr = 0x0;
module_param(syscall_table_addr, ulong, 0660);


unsigned long the_ni_syscall;

unsigned long new_sys_call_array[] = {0x0, 0x1, 0x2, 0x3};//please set to sys_vtpmo at startup
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array)/sizeof(unsigned long))
//#define HACKED_ENTRIES 2
int restore[HACKED_ENTRIES] = {[0 ... (HACKED_ENTRIES-1)] -1};

#define AUDIT if(1)


//Change reference monitor state
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _switch_state, int, state, char *, passwd){
#else
asmlinkage long sys_switch_state(int state, char *passwd){
#endif

        
	return 0;
	
}

//Add the path of a new protected resource by the reference monitor
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _add_protected_res, char *, res_path, char *, passwd){
#else
asmlinkage long sys_add_protected_res(char * res_path, char *passwd){
#endif

        
	return 0;
	
}

//Remove the path of a protected resource by the reference monitor
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _rm_protected_res, char *, res_path, char *, passwd){
#else
asmlinkage long sys_rm_protected_res(char * res_path, char *passwd){
#endif

        
	return 0;
	
}

//Get the path of all the protected resources by the reference monitor
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1, _get_protected_res_list, char **, buff){
#else
asmlinkage long sys_get_protected_res_list(char ** buff){
#endif

        
	return 0;
	
}



#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
long sys_switch_state = (unsigned long) __x64_sys_switch_state;       
#else
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
long sys_add_protected_res = (unsigned long) __x64_sys_add_protected_res;       
#else
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
long sys_rm_protected_res = (unsigned long) __x64_sys_rm_protected_res;       
#else
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
long sys_get_protected_res_list = (unsigned long) __x64_sys_get_protected_res_list;       
#else
#endif


int init_module(void) {

        int i;
        int ret;

        if (syscall_table_addr == 0x0){
           printk("%s: cannot manage sys_call_table address set to 0x0\n",MODNAME);
           return -1;
        }

	AUDIT{
	   printk("%s: printk-example received sys_call_table address %px\n",MODNAME,(void*)syscall_table_addr);
     	   printk("%s: initializing - hacked entries %d\n",MODNAME,HACKED_ENTRIES);
	}

	new_sys_call_array[0] = (unsigned long)sys_switch_state;
        new_sys_call_array[1] = (unsigned long)sys_add_protected_res;
        new_sys_call_array[2] = (unsigned long)sys_rm_protected_res;
        new_sys_call_array[3] = (unsigned long)sys_get_protected_res_list;

        ret = get_entries(restore,HACKED_ENTRIES,(unsigned long*)syscall_table_addr,&the_ni_syscall);

        if (ret != HACKED_ENTRIES){
                printk("%s: could not hack %d entries (just %d)\n",MODNAME,HACKED_ENTRIES,ret); 
                return -1;      
        }

	unprotect_memory();

        for(i=0;i<HACKED_ENTRIES;i++){
                ((unsigned long *)syscall_table_addr)[restore[i]] = (unsigned long)new_sys_call_array[i];
        }

	protect_memory();

        printk("%s: all new system-calls correctly installed on sys-call table\n",MODNAME);

        return 0;

}

void cleanup_module(void) {

        int i;
                
        printk("%s: shutting down\n",MODNAME);

	unprotect_memory();
        for(i=0;i<HACKED_ENTRIES;i++){
                ((unsigned long *)syscall_table_addr)[restore[i]] = the_ni_syscall;
        }
	protect_memory();
        printk("%s: sys-call table restored to its original content\n",MODNAME);
        
}
