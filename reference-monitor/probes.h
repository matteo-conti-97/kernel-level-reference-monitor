#define KPROBES_SIZE 10

int vfs_open_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int vfs_truncate_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int vfs_rename_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int vfs_mkdir_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int vfs_mknod_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int vfs_rmdir_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int vfs_create_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int vfs_link_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int vfs_unlink_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int vfs_symlink_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);

int ret_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);

int enable_probes(void);
void disable_probes(void);
int register_probes(void);
void unregister_probes(void);