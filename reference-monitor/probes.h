#define KPROBES_SIZE 37

int sys_open_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int sys_truncate_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int sys_rename_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int sys_mkdir_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int sys_mknod_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int sys_rmdir_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int sys_creat_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int sys_link_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int sys_unlink_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int sys_symlink_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int sys_renameat_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int sys_unlinkat_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int sys_linkat_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int sys_symlinkat_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int sys_mkdirat_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int sys_mknodat_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int sys_openat_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int sys_renameat2_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);
int sys_openat2_handler(struct kretprobe_instance *prob_inst, struct pt_regs *regs);