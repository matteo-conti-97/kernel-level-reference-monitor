#include <linux/crypto.h>
#include <crypto/hash.h>
#include "utils.h"
#include <linux/string.h>
#include <linux/device.h>
#include <linux/fs.h>

bool compare_hashes(const char *hash1, const char *hash2, size_t length) {
    return memcmp(hash1, hash2, length) == 0;
}

int compute_sha256(const char *data, long data_size, char *output) {
    struct crypto_shash *tfm;
    struct shash_desc *shash;
    int ret, i;
    char hash[HASH_DIGEST_SIZE];

    // Allocate a transformation object
    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        return -1;
    }

    // Allocate the hash descriptor
    shash = kmalloc(sizeof(*shash) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!shash) {
        crypto_free_shash(tfm);
        return -1;
    }

    shash->tfm = tfm;

    // Initialize the hash computation
    ret = crypto_shash_init(shash);
    if (ret) {
        kfree(shash);
        crypto_free_shash(tfm);
        return ret;
    }

    // Update with data
    ret = crypto_shash_update(shash, data, data_size);
    if (ret) {
        kfree(shash);
        crypto_free_shash(tfm);
        return ret;
    }

    // Finalize the hash computation
    ret = crypto_shash_final(shash, hash);

    //Convert to hex
    for (i = 0; i < HASH_DIGEST_SIZE; i++) {
        sprintf(output + i * 2, "%02x", (unsigned char)hash[i]);
    }
    output[HASH_HEX_SIZE] = '\0';

    // Clean up
    kfree(shash);
    crypto_free_shash(tfm);
    return ret;
}

char *get_path_name(struct dentry *dentry){
    char *buff;
    char *path;
    char *res;

    // Allocate memory for the buffer
    buff = kmalloc(MAX_PATH_SIZE, GFP_KERNEL);
    if (!buff) {
        pr_err("Failed to allocate memory for path buffer\n");
        return NULL;
    }

    // Get the path
    path = dentry_path_raw(dentry, buff, MAX_PATH_SIZE);
    if (IS_ERR(path)) {
        pr_err("Error getting dentry path\n");
        kfree(buff);
        return NULL;
    }

    // Allocate memory for the result to return
    res= kmalloc(strlen(path) + 1, GFP_KERNEL);
    res= strcpy(res, path);

    // Free the buffer
    kfree(buff);
    kfree(path);

    return res;
}

void get_prefix(const char *path) {
    // Find the last occurrence of '/'
    char *last_slash = strrchr(path, '/');
    if (last_slash != NULL) {
        // Null terminate the string at the last '/'
        *last_slash = '\0';
    }
}
