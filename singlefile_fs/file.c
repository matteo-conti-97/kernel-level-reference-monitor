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
#include <linux/uio.h>
#include <linux/mutex.h>

#include "singlefilefs.h"

ssize_t onefilefs_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{

    struct buffer_head *bh = NULL;
    struct inode *the_inode = filp->f_inode;
    uint64_t file_size = the_inode->i_size;
    int ret;
    loff_t offset;
    int block_to_read; // index of the block to be read from device

    printk("%s: [INFO] Read operation called with len %ld - and offset %lld (the current file size is %lld)", MOD_NAME, len, *off, file_size);

    //this operation is not synchronized 
    //*off can be changed concurrently 
    //add synchronization if you need it for any reason
    
    //mutex_lock(&mutex);

    // check that *off is within boundaries
    if (*off >= file_size)
    {
        //mutex_unlock(&mutex);
        return 0;
    }
    else if (*off + len > file_size)
        len = file_size - *off;

    // determine the block level offset for the operation
    offset = *off % DEFAULT_BLOCK_SIZE;
    // just read stuff in a single block - residuals will be managed at the applicatin level
    if (offset + len > DEFAULT_BLOCK_SIZE)
        len = DEFAULT_BLOCK_SIZE - offset;

    // compute the actual index of the the block to be read from device
    block_to_read = *off / DEFAULT_BLOCK_SIZE + 2; // the value 2 accounts for superblock and file-inode on device

    printk("%s: [INFO] Read operation must access block %d of the device", MOD_NAME, block_to_read);

    bh = (struct buffer_head *)sb_bread(filp->f_path.dentry->d_inode->i_sb, block_to_read);
    if (!bh)
    {
        //mutex_unlock(&mutex);
        return -EIO;
    }

    ret = copy_to_user(buf, bh->b_data + offset, len);
    *off += (len - ret);
    brelse(bh);

    //mutex_unlock(&mutex);
    return len - ret;
}

ssize_t onefilefs_write(struct kiocb *iocb, struct iov_iter *from)
{

    loff_t block_offset, offset;
    int block_to_write;
    struct buffer_head *bh = NULL;
    size_t copied_bytes;
    size_t payload;
    struct file *file;
    struct inode *the_inode;
    uint64_t file_size;
    char *data;

    //mutex_lock(&mutex);

    file = iocb->ki_filp;
    the_inode = file->f_inode;
    offset = file->f_pos;
    file_size = i_size_read(the_inode); //TODO Piuttosto che fare la cosa della master copy non posso scr4ivere sempre a file_size?

    // byte size of the payload
    payload = from->count;

    data = kmalloc(payload, GFP_KERNEL);
    if (!data)
    {
        printk("%s: [ERROR] Error in kmalloc allocation\n", MOD_NAME);
        //mutex_unlock(&mutex);
        return 0;
    }

    copied_bytes = _copy_from_iter((void *)data, payload, from);
    if (copied_bytes != payload)
    {
        printk("%s: [ERROR] Failed to copy %ld bytes from iov_iter\n", MOD_NAME, payload);
        //mutex_unlock(&mutex);
        return 0;
    }

    offset = file_size;

    // Append only
    block_offset = offset % DEFAULT_BLOCK_SIZE;
    block_to_write = offset / DEFAULT_BLOCK_SIZE + 2; // + superblock + inode

    if (DEFAULT_BLOCK_SIZE - block_offset < payload)
    {
        block_to_write++;
        offset += (DEFAULT_BLOCK_SIZE - block_offset);
        block_offset = 0;
    }

    bh = sb_bread(file->f_path.dentry->d_inode->i_sb, block_to_write);
    if (!bh)
    {
        //mutex_unlock(&mutex);
        return -EIO;
    }

    memcpy(bh->b_data + block_offset, data, payload);

    mark_buffer_dirty(bh);

    if (offset + payload > file_size)
        i_size_write(the_inode, offset + payload);

    brelse(bh);

    offset += payload;

    kfree(data);
    //mutex_unlock(&mutex);

    return payload;
}

int onefilefs_open(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "%s: [INFO] Open operation called for file.\n", MOD_NAME);

    // Single instance
    mutex_lock(&mutex);

    printk(KERN_INFO "%s: [INFO] Successfully opened file.\n", MOD_NAME);

    return 0; // Success
}


int onefilefs_close(struct inode *inode, struct file *file) {

    printk("%s: [INFO] Close operation called for file.\n",MOD_NAME);

   mutex_unlock(&mutex);

   printk("%s: [INFO] File closed\n",MOD_NAME);

   return 0;

}

struct dentry *onefilefs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags)
{

    struct onefilefs_inode *FS_specific_inode;
    struct super_block *sb = parent_inode->i_sb;
    struct buffer_head *bh = NULL;
    struct inode *the_inode = NULL;

    printk("%s: running the lookup inode-function for name %s", MOD_NAME, child_dentry->d_name.name);

    if (!strcmp(child_dentry->d_name.name, UNIQUE_FILE_NAME))
    {

        // get a locked inode from the cache
        the_inode = iget_locked(sb, 1);
        if (!the_inode)
            return ERR_PTR(-ENOMEM);

        // already cached inode - simply return successfully
        if (!(the_inode->i_state & I_NEW))
        {
            return child_dentry;
        }

        // this work is done if the inode was not already cached
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 12, 0)
        inode_init_owner(the_inode, NULL, S_IFDIR);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0)
        inode_init_owner(&init_user_ns, the_inode, NULL, S_IFDIR);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
        inode_init_owner(&nop_mnt_idmap, the_inode, NULL, S_IFDIR);
#endif
        the_inode->i_mode = S_IFREG | S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IXUSR | S_IXGRP | S_IXOTH;
        the_inode->i_fop = &onefilefs_file_operations;
        the_inode->i_op = &onefilefs_inode_ops;

        // just one link for this file
        set_nlink(the_inode, 1);

        // now we retrieve the file size via the FS specific inode, putting it into the generic inode
        bh = (struct buffer_head *)sb_bread(sb, SINGLEFILEFS_INODES_BLOCK_NUMBER);
        if (!bh)
        {
            iput(the_inode);
            return ERR_PTR(-EIO);
        }
        FS_specific_inode = (struct onefilefs_inode *)bh->b_data;
        the_inode->i_size = FS_specific_inode->file_size;
        brelse(bh);

        d_add(child_dentry, the_inode);
        dget(child_dentry);

        // unlock the inode to make it usable
        unlock_new_inode(the_inode);

        return child_dentry;
    }

    return NULL;
}

// look up goes in the inode operations
const struct inode_operations onefilefs_inode_ops = {
    .lookup = onefilefs_lookup,
};

const struct file_operations onefilefs_file_operations = {
    .owner = THIS_MODULE,
    .read = onefilefs_read,
    .write_iter = onefilefs_write,
    .open = onefilefs_open,
    .release = onefilefs_close,
};
