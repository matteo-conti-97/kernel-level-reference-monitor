#include <linux/device.h>

int compute_sha256(const char *data, size_t data_len, char *output);
bool compare_hashes(const char *hash1, const char *hash2, size_t length);
char *get_path_name(struct dentry *dentry);