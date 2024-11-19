#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct openat_args);
} start SEC(".maps");

#define NAME_MAX 255
//const char *fname = "/etc/passwd";

const char target_path[] = "/host-etc/crontab";


struct openat_args {
    int flags;
    uintptr_t fname_ptr;
    char fname[NAME_MAX];
};


SEC("tp/syscalls/sys_enter_openat")
int enter_openat(struct trace_event_raw_sys_enter* ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct openat_args arg ={};
    arg.flags = (int)ctx->args[2];
//    arg.fname_ptr = (const char *)ctx->args[1];
    arg.fname_ptr = ctx->args[1];
    bpf_map_update_elem(&start, &id, &arg, BPF_ANY);


    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int exit_openat(struct trace_event_raw_sys_exit* ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct openat_args *arg = bpf_map_lookup_elem(&start, &id);
    if (!arg) {
        return 0;
    }

    // Read filename on syscall exit
    bpf_probe_read_user(&arg->fname, sizeof(arg->fname), (void *)arg->fname_ptr);


   int i = 0;
    while (arg->fname[i] != '\0' && target_path[i] != '\0') {
        if (arg->fname[i] != target_path[i]) {
            return 0;  // Strings do not match
        }
        i++;
    }

    // If both strings are identical and null-terminated at the same position
    if (arg->fname[i] == '\0' && target_path[i] == '\0') {
        bpf_printk("Access detected to: %s flags: %d\n",arg->fname,arg->flags);
    }

/**
    if (bpf_strncmp(arg->fname, target_path, sizeof(target_path) -1) == 0) {
        bpf_printk("Hello!\n");
        return 0;
    }
**/
//    bpf_printk("openat: filename: %s flags: %d\n",arg->fname,arg->flags);
//     bpf_printk("%s",arg->fname);
//     bpf_printk("%s",arg->fname); 
     bpf_map_delete_elem(&start, &id);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
