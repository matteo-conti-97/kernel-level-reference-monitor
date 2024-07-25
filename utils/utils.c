#include <linux/crypto.h>
#include <crypto/hash.h>
#include "utils.h"
#include <linux/string.h> // For memcmp

bool compare_hashes(const char *hash1, const char *hash2, size_t length) {
    return memcmp(hash1, hash2, length) == 0;
}

int compute_sha256(const char *data, size_t data_len, char *output) {
    struct crypto_shash *tfm;
    struct shash_desc *shash;
    int ret;

    // Allocate a transformation object
    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("crypto_alloc_shash failed\n");
        return PTR_ERR(tfm);
    }

    // Allocate the hash descriptor
    shash = kmalloc(sizeof(*shash) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!shash) {
        pr_err("kmalloc failed\n");
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    shash->tfm = tfm;

    // Initialize the hash computation
    ret = crypto_shash_init(shash);
    if (ret) {
        pr_err("crypto_shash_init failed\n");
        kfree(shash);
        crypto_free_shash(tfm);
        return ret;
    }

    // Update with data
    ret = crypto_shash_update(shash, data, data_len);
    if (ret) {
        pr_err("crypto_shash_update failed\n");
        kfree(shash);
        crypto_free_shash(tfm);
        return ret;
    }

    // Finalize the hash computation
    ret = crypto_shash_final(shash, output);
    if (ret) {
        pr_err("crypto_shash_final failed\n");
    }

    // Clean up
    kfree(shash);
    crypto_free_shash(tfm);
    return ret;
}