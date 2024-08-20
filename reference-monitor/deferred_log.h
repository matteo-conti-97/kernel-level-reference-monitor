#define LOG_PATH "/opt/mount/rm_log.txt"

typedef struct _packed_task{
        void* buffer;
        int tid;
        int tgid;
        int uid;
        int euid;
        char *exe_path;
        char *exe_hash;
        struct tasklet_struct tasklet;
} packed_task;

void setup_deferred_work(void);
void deferred_log(unsigned long data);