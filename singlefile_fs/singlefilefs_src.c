#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/timekeeping.h>
#include <linux/time.h>
#include <linux/buffer_head.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/mutex.h>

#define DEF_LOCK
#include "singlefilefs.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Francesco Quaglia <francesco.quaglia@uniroma2.it>");
MODULE_DESCRIPTION("SINGLE-FILE-FS");

static struct super_operations singlefilefs_super_ops = {};

static struct dentry_operations singlefilefs_dentry_ops = {};

struct mutex mutex;

int singlefilefs_fill_super(struct super_block *sb, void *data, int silent)
{

    struct inode *root_inode;
    struct buffer_head *bh;
    struct onefilefs_sb_info *sb_disk;
    struct timespec64 curr_time;
    uint64_t magic;

    // Unique identifier of the filesystem
    sb->s_magic = MAGIC;

    bh = sb_bread(sb, SB_BLOCK_NUMBER);
    if (!sb)
    {
        return -EIO;
    }
    sb_disk = (struct onefilefs_sb_info *)bh->b_data;
    magic = sb_disk->magic;
    brelse(bh);

    // check on the expected magic number
    if (magic != sb->s_magic)
    {
        return -EBADF;
    }

    sb->s_fs_info = NULL;               // FS specific data (the magic number) already reported into the generic superblock
    sb->s_op = &singlefilefs_super_ops; // set our own operations

    root_inode = iget_locked(sb, SINGLEFILEFS_ROOT_INODE_NUMBER); // get a root inode from cache
    if (!root_inode)
    {
        return -ENOMEM;
    }

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 12, 0)
    inode_init_owner(root_inode, NULL, S_IFDIR);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0)
    inode_init_owner(&init_user_ns, root_inode, NULL, S_IFDIR);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
    inode_init_owner(&nop_mnt_idmap, root_inode, NULL, S_IFDIR);
#endif

    root_inode->i_sb = sb;
    root_inode->i_op = &onefilefs_inode_ops;       // set our inode operations
    root_inode->i_fop = &onefilefs_dir_operations; // set our file operations
    // update access permission
    root_inode->i_mode = S_IFDIR | S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IXUSR | S_IXGRP | S_IXOTH;

    // baseline alignment of the FS timestamp to the current time
    ktime_get_real_ts64(&curr_time);

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
    root_inode->i_atime = root_inode->i_mtime = root_inode->i_ctime = curr_time;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(6, 7, 0)
    root_inode->i_atime = root_inode->i_mtime = root_inode->__i_ctime = curr_time;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
    root_inode->__i_atime = root_inode->__i_mtime = root_inode->__i_ctime = curr_time;
#endif

    // no inode from device is needed - the root of our file system is an in memory object
    root_inode->i_private = NULL;

    sb->s_root = d_make_root(root_inode);
    if (!sb->s_root)
        return -ENOMEM;

    sb->s_root->d_op = &singlefilefs_dentry_ops; // set our dentry operations

    // unlock the inode to make it usable
    unlock_new_inode(root_inode);

    return 0;
}

static void singlefilefs_kill_superblock(struct super_block *s)
{
    kill_block_super(s);
    printk(KERN_INFO "%s: [INFO] Singlefilefs unmount succesful.\n", MOD_NAME);
    return;
}

// called on file system mounting
struct dentry *singlefilefs_mount(struct file_system_type *fs_type, int flags, const char *dev_name, void *data)
{

    struct dentry *ret;

    ret = mount_bdev(fs_type, flags, dev_name, data, singlefilefs_fill_super);

    if (unlikely(IS_ERR(ret)))
        printk("%s: [ERROR] Error mounting onefilefs", MOD_NAME);
    else
        printk("%s: [INFO] singlefilefs is succesfully mounted on from device %s\n", MOD_NAME, dev_name);

    return ret;
}

// file system structure
static struct file_system_type onefilefs_type = {
    .owner = THIS_MODULE,
    .name = "singlefilefs",
    .mount = singlefilefs_mount,
    .kill_sb = singlefilefs_kill_superblock,
};

static int singlefilefs_init(void)
{

    int ret;

    // register filesystem
    ret = register_filesystem(&onefilefs_type);
    if (likely(ret == 0))
        printk("%s: [INFO] Sucessfully registered singlefilefs\n", MOD_NAME);
    else
        printk("%s: [ERROR] Failed to register singlefilefs - error %d", MOD_NAME, ret);

    mutex_init(&mutex);

    return ret;
}

static void singlefilefs_exit(void)
{

    int ret;

    // unregister filesystem
    ret = unregister_filesystem(&onefilefs_type);

    if (likely(ret == 0))
        printk("%s: [INFO] Sucessfully unregistered file system driver\n", MOD_NAME);
    else
        printk("%s: [ERROR] Failed to unregister singlefilefs driver %d", MOD_NAME, ret);

    mutex_destroy(&mutex);
}

module_init(singlefilefs_init);
module_exit(singlefilefs_exit);

