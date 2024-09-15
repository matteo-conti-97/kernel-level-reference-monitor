#define LOG_PATH "/opt/mount/rm_log"

/*Using work queues becaus the deferred work have to use kernel_read which is blocking so we can't use tasklets, 
another option is use vfs_read with busy waiting but it's not as good as work queues*/
typedef struct _packed_work{
        void* buffer;
        int tid;
        int tgid;
        int uid;
        int euid;
        char *exe_path;
        struct work_struct work;
} packed_work;

void setup_deferred_work(void);
void deferred_log(unsigned long data);