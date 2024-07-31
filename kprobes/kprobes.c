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

struct kretprobe x64_sys_open, sys_open;
struct kretprobe x64_sys_truncate, sys_truncate;
struct kretprobe x64_sys_rename, sys_rename;
struct kretprobe x64_sys_mkdir, sys_mkdir;
struct kretprobe x64_sys_mknod, sys_mknod;
struct kretprobe x64_sys_rmdir, sys_rmdir;
struct kretprobe x64_sys_creat, sys_creat;
struct kretprobe x64_sys_link, sys_link;
struct kretprobe x64_sys_unlink, sys_unlink;
struct kretprobe x64_sys_symlink, sys_symlink;
struct kretprobe x64_sys_renameat, sys_renameat;
struct kretprobe x64_sys_unlinkat, sys_unlinkat;
struct kretprobe x64_sys_linkat, sys_linkat;
struct kretprobe x64_sys_symlinkat, sys_symlinkat;
struct kretprobe x64_sys_mkdirat, sys_mkdirat;
struct kretprobe x64_sys_mknodat, sys_mknodat;
struct kretprobe x64_sys_openat, sys_openat;
struct kretprobe x64_sys_renameat2, sys_renameat2;
struct kretprobe x64_sys_openat2;

// kretprobes array
kprobe_array[KPROBES_SIZE];

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
    //Init probe TODO SET REAL ENTRY AND RET HANDLERS
    set_kretprobe(&x64_sys_open, "__x64_sys_open", NULL, NULL);
    set_kretprobe(&sys_open, "sys_open", NULL, NULL);
    set_kretprobe(&x64_sys_truncate, "__x64_sys_truncate", NULL, NULL);
    set_kretprobe(&sys_truncate, "sys_truncate", NULL, NULL);
    set_kretprobe(&x64_sys_rename, "__x64_sys_rename", NULL, NULL);
    set_kretprobe(&sys_rename, "sys_rename", NULL, NULL);
    set_kretprobe(&x64_sys_mkdir, "__x64_sys_mkdir", NULL, NULL);
    set_kretprobe(&sys_mkdir, "sys_mkdir", NULL, NULL);
    set_kretprobe(&x64_sys_mknod, "__x64_sys_mknod", NULL, NULL);
    set_kretprobe(&sys_mknod, "sys_mknod", NULL, NULL);
    set_kretprobe(&x64_sys_rmdir, "__x64_sys_rmdir", NULL, NULL);
    set_kretprobe(&sys_rmdir, "sys_rmdir", NULL, NULL);
    set_kretprobe(&x64_sys_creat, "__x64_sys_creat", NULL, NULL);
    set_kretprobe(&sys_creat, "sys_creat", NULL, NULL);
    set_kretprobe(&x64_sys_link, "__x64_sys_link", NULL, NULL);
    set_kretprobe(&sys_link, "sys_link", NULL, NULL);
    set_kretprobe(&x64_sys_unlink, "__x64_sys_unlink", NULL, NULL);
    set_kretprobe(&sys_unlink, "sys_unlink", NULL, NULL);
    set_kretprobe(&x64_sys_symlink, "__x64_sys_symlink", NULL, NULL);
    set_kretprobe(&sys_symlink, "sys_symlink", NULL, NULL);
    set_kretprobe(&x64_sys_renameat, "__x64_sys_renameat", NULL, NULL);
    set_kretprobe(&sys_renameat, "sys_renameat", NULL, NULL);
    set_kretprobe(&x64_sys_unlinkat, "__x64_sys_unlinkat", NULL, NULL);
    set_kretprobe(&sys_unlinkat, "sys_unlinkat", NULL, NULL);
    set_kretprobe(&x64_sys_linkat, "__x64_sys_linkat", NULL, NULL);
    set_kretprobe(&sys_linkat, "sys_linkat", NULL, NULL);
    set_kretprobe(&x64_sys_symlinkat, "__x64_sys_symlinkat", NULL, NULL);
    set_kretprobe(&sys_symlinkat, "sys_symlinkat", NULL, NULL);
    set_kretprobe(&x64_sys_mkdirat, "__x64_sys_mkdirat", NULL, NULL);
    set_kretprobe(&sys_mkdirat, "sys_mkdirat", NULL, NULL);
    set_kretprobe(&x64_sys_mknodat, "__x64_sys_mknodat", NULL, NULL);
    set_kretprobe(&sys_mknodat, "sys_mknodat", NULL, NULL);
    set_kretprobe(&x64_sys_openat, "__x64_sys_openat", NULL, NULL);
    set_kretprobe(&sys_openat, "sys_openat", NULL, NULL);
    set_kretprobe(&x64_sys_renameat2, "__x64_sys_renameat2", NULL, NULL);
    set_kretprobe(&sys_renameat2, "sys_renameat2", NULL, NULL);
    set_kretprobe(&x64_sys_openat2, "__x64_sys_openat2", NULL, NULL);

    

    kprobe_array[0] = &x64_sys_open;
    kprobe_array[1] = &sys_open;
    kprobe_array[2] = &x64_sys_truncate;
    kprobe_array[3] = &sys_truncate;
    kprobe_array[4] = &x64_sys_rename;
    kprobe_array[5] = &sys_rename;
    kprobe_array[6] = &x64_sys_mkdir;
    kprobe_array[7] = &sys_mkdir;
    kprobe_array[8] = &x64_sys_mknod;
    kprobe_array[9] = &sys_mknod;
    kprobe_array[10] = &x64_sys_rmdir;
    kprobe_array[11] = &sys_rmdir;
    kprobe_array[12] = &x64_sys_creat;
    kprobe_array[13] = &sys_creat;
    kprobe_array[14] = &x64_sys_link;
    kprobe_array[15] = &sys_link;
    kprobe_array[16] = &x64_sys_unlink;
    kprobe_array[17] = &sys_unlink;
    kprobe_array[18] = &x64_sys_symlink;
    kprobe_array[19] = &sys_symlink;
    kprobe_array[20] = &x64_sys_renameat;
    kprobe_array[21] = &sys_renameat;
    kprobe_array[22] = &x64_sys_unlinkat;
    kprobe_array[23] = &sys_unlinkat;
    kprobe_array[24] = &x64_sys_linkat;
    kprobe_array[25] = &sys_linkat;
    kprobe_array[26] = &x64_sys_symlinkat;
    kprobe_array[27] = &sys_symlinkat;
    kprobe_array[28] = &x64_sys_mkdirat;
    kprobe_array[29] = &sys_mkdirat;
    kprobe_array[30] = &x64_sys_mknodat;
    kprobe_array[31] = &sys_mknodat;
    kprobe_array[32] = &x64_sys_openat;
    kprobe_array[33] = &sys_openat;
    kprobe_array[34] = &x64_sys_renameat2;
    kprobe_array[35] = &sys_renameat2;
    kprobe_array[36] = &x64_sys_openat2;


    ret = register_kretprobes(kprobe_array, KPROBES_SIZE);
    if (ret != 0)
    {
        printk("[ERROR] Kretprobes registration failed, returned %d\n", ret);
        return ret;
    }
    
    printk("[INFO] Kretprobes correctly installed\n");
    

    return 0;
}

void kretprobe_clean()
{
    unregister_kretprobes(kprobe_array, KPROBES_SIZE);

    printk("[INFO] Kretprobes correctly removed\n");
    
    kfree(kprobe_array);
}