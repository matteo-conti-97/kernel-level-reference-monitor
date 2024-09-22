#include <linux/device.h>

#define MAX_PATH_SIZE 1024
#define HASH_DIGEST_SIZE 32
#define HASH_HEX_SIZE 2*HASH_DIGEST_SIZE+1

int compute_sha256(const char *data, long data_size, char *output);
bool compare_hashes(const char *hash1, const char *hash2, size_t length);
char *get_path_name(struct dentry *dentry);
void get_prefix(const char *path);