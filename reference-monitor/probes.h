#define KPROBES_SIZE 37

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