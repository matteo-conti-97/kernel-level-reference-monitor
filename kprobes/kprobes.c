#include <linux/device.h>
#include <linux/kprobes.h>
#include <linux/errno.h>
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

#define KPROBES_SIZE 37

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

int sys_open_handler();
int sys_truncate_handler();
int sys_rename_handler();
int sys_mkdir_handler();
int sys_mknod_handler();
int sys_rmdir_handler();
int sys_creat_handler();
int sys_link_handler();
int sys_unlink_handler();
int sys_symlink_handler();
int sys_renameat_handler();
int sys_unlinkat_handler();
int sys_linkat_handler();
int sys_symlinkat_handler();
int sys_mkdirat_handler();
int sys_mknodat_handler();
int sys_openat_handler();
int sys_renameat2_handler();
int sys_openat2_handler();

typedef void (*func_ptr)();

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


void setup_probe(struct kretprobe *probe, char *symbol, kretprobe_handler_t entry_handler, kretprobe_handler_t ret_handler)
{
    probe->kp.symbol_name = symbol;
    probe->kp.flags = KPROBE_FLAG_DISABLED; //Disabled by default
    probe->handler = (kretprobe_handler_t)ret_handler;
    probe->entry_handler = entry_handler;
    probe->maxactive = -1; // unlimited instances cause it's stateless
}

int kretprobe_init()
{
    int ret;
    //Setup and register probes
    for(int i=0;i<(KPROBES_SIZE/2)+1;i+=2)
    {
        for (int j=0;j<2;j++){
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
    

    return 0;
}

void kretprobe_clean()
{
    for(int i=0;i<(KPROBES_SIZE/2)+1;i+=2)
    {
        for (int j=0;j<2;j++){
            if(symbol_names[i][j] != NULL)
                unregister_kretprobe(&kprobe_array[i][j]);
        }
    }

    printk("[INFO] Kretprobes correctly removed\n");
    
    kfree(kprobe_array);
}