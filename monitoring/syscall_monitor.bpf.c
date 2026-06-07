#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "syscall_monitor.h"
#include "utils.h"


char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct monitor_config);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct syscall_args);
} args_map SEC(".maps");

struct syscall_args {
    __u64 time;
    __u64 args[6];
};

struct newdir_data {
    umode_t        i_mode;
    kuid_t        i_uid;
    kgid_t        i_gid;
    unsigned long    i_ino;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct newdir_data);
} mkdir_map SEC(".maps");

struct mkdir_dentry_data {
    struct dentry *dentry;
    int depth;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, struct mkdir_dentry_data);
} mkdir_dentry SEC(".maps");

struct chmod_ctx {
    struct path *path;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, struct chmod_ctx);
} chmod_map SEC(".maps");

struct chmod_data {
    u32    i_mode;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct chmod_data);
} chmod_data_map SEC(".maps");

struct fput_data {
    unsigned ino;
    unsigned dev;
    __u64 time;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct fput_data);
} fput_data_map SEC(".maps");

struct ima_ctx {
    struct integrity_iint_cache *iint_cache;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct ima_ctx);
} ima_ctx_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct ima_data);
} ima_data_map SEC(".maps");

struct evm_ctx {
    struct evm_digest *digest_ptr;
    __u8 type;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct evm_ctx);
} evm_ctx_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct ima_data);
} evm_data_map SEC(".maps");

struct chown_ctx {
    struct path *path;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, struct chown_ctx);
} chown_map SEC(".maps");

struct chown_data {
    u32    i_mode;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct chown_data);
} chown_data_map SEC(".maps");

struct execve_data {
    char   pathname[PATH_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct execve_data);
} execve_map SEC(".maps");


// static __always_inline int
// bpf_memcmp(const void *a, const void *b, size_t len) {
//     const unsigned char *pa = (const unsigned char *)a;
//     const unsigned char *pb = (const unsigned char *)b;
//     for (size_t i = 0; i < len; i++) {
//         if (pa[i] != pb[i])
//             return (int)pa[i] - (int)pb[i];
//     }
//     return 0;
// }

static __always_inline int should_monitor(void)
{
    u32 key = 0;
    struct monitor_config *cfg = bpf_map_lookup_elem(&config_map, &key);

    if (!cfg || !cfg->enabled) {
        return 0;
    }
    if (!cfg->filter_tst) {
        return 1;
    }

    u32 comm[4] = {0};
    bpf_get_current_comm(&comm, sizeof comm);
    char prefix[4] = "tst_";
    return *(u32 *)prefix == comm[0]; // comm starts with "tst_"
}

//TODO: maybe we should track calculation hash instead set hash

// SEC("kprobe/__vfs_setxattr_noperm")
// int BPF_KPROBE(handle_vfs_setxattr_noperm)
// {
//     if (!should_monitor()) {
//         return 0;
//     }    

//     char name_buf[32];
//     const char *name_ptr = (const char *)PT_REGS_PARM3(ctx);
//     bpf_probe_read_kernel_str(name_buf, sizeof(name_buf), name_ptr);
//     if (bpf_memcmp(name_buf, XATTR_NAME_IMA, sizeof(XATTR_NAME_IMA)) != 0)
//         return 0;
//     u64 id = bpf_get_current_pid_tgid();

//     struct ima_data data = {};
//     data.size = (__u64) PT_REGS_PARM5(ctx);
//     const void *value_ptr = (const void *) PT_REGS_PARM4(ctx);
//     bpf_probe_read_kernel(&data.value, sizeof(data.value), value_ptr);
    
//     bpf_map_update_elem(&ima_data_map, &id, &data, BPF_ANY);
//     bpf_printk("kprobe/__vfs_setxattr_noperm: %llu", id);

//     return 0;
// }


SEC("kprobe/evm_calc_hmac_or_hash")
int BPF_KPROBE(handle_evm_calc_hmac_or_hash)
{
    if (!should_monitor()) {
        return 0;
    }
    bpf_printk("evm_calc_hmac_or_hash!");

    u64 id = bpf_get_current_pid_tgid();

    struct evm_ctx ctx_data = {
        .digest_ptr = (struct evm_digest *)ctx->r9,
        .type = PT_REGS_PARM5(ctx),
    };
    bpf_map_update_elem(&evm_ctx_map, &id, &ctx_data, BPF_ANY);

    return 0;
}

SEC("kretprobe/evm_calc_hmac_or_hash")
int BPF_KRETPROBE(handle_evm_calc_hmac_or_hash_ret) {
    if (!should_monitor()) {
        return 0;
    }
    bpf_printk("evm_calc_hmac_or_hash_ret!");

    u64 id = bpf_get_current_pid_tgid();

    struct evm_ctx *ictx;
    if (!(ictx = bpf_map_lookup_elem(&evm_ctx_map, &id))) {
        bpf_printk("evm_calc_hmac_or_hash_ret: no evm_ctx found");
        return 0;
    }

    long ret = PT_REGS_RC(ctx);
    if (ret < 0) {
        goto CLEANUP;
    }

    struct evm_digest *evm_digest_ptr = ictx->digest_ptr;
    struct ima_digest_data hdr = BPF_CORE_READ(evm_digest_ptr, hdr);
    
    struct ima_data data = {};
    data.size = BPF_CORE_READ(&hdr, length);
    //const void *value_ptr = (const void *)BPF_CORE_READ(ima_hash, digest);

    __u32 offset = offsetof(struct evm_digest, digest);
    const void *value_ptr = (const void *)((__u64)evm_digest_ptr + offset);
    
    if (data.size > HASH_MAX_DIGESTSIZE) {
        bpf_printk("evm_calc_hmac_or_hash_ret: digest size (%llu) "
            "is more that the maximum one (%d)", data.size, HASH_MAX_DIGESTSIZE);
        goto CLEANUP;
    }
    bpf_probe_read_kernel(&data.value[1], (__u32)data.size, value_ptr);
    data.value[0] = ictx->type;
    data.size += 1;

    // char hex_str[128] = {}; 
    // int pos = 0;
    // for (int i = 0; i < data.size && pos < sizeof(hex_str)-3; i++) {
    //     unsigned char byte = data.value[i];
    //     hex_str[pos++] = "0123456789abcdef"[byte >> 4];
    //     hex_str[pos++] = "0123456789abcdef"[byte & 0x0F];
    // }
    // hex_str[pos] = '\0';
    // bpf_printk("EVM HMAC (%d): %s\n", data.size, hex_str);

    bpf_map_update_elem(&evm_data_map, &id, &data, BPF_ANY);

CLEANUP:
    bpf_map_delete_elem(&evm_ctx_map, &id);
    return 0;
}

static __always_inline
struct syscall_event *
read_main_args()
{
    if (!should_monitor()) {
        return 0;
    }

    struct syscall_event *e = bpf_ringbuf_reserve(&events, sizeof *e, 0);
    if (!e) {
        bpf_printk("ringbuffer overflow");
        return 0;
    }

    e->ts = bpf_ktime_get_ns();

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid & ((1uLL << 32) - 1);
    e->tgid = pid_tgid >> 32;

    u64 uid_gid = bpf_get_current_uid_gid();
    e->euid = uid_gid & ((1uLL << 32) - 1);
    e->egid = uid_gid >> 32;

    bpf_get_current_comm(&e->comm, sizeof e->comm);

    return e;
}


SEC("kprobe/__fput")
int BPF_KPROBE(handle___fput)
{
    if (!should_monitor()) {
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();

    struct file *f = (struct file *)PT_REGS_PARM1(ctx);
    if (!f) {
        return 0;
    }
    struct fput_data data = {};
    const struct inode *i = bpf_file_inode(f);
    if (i == NULL) {
        return 0;
    }
    umode_t mode = BPF_CORE_READ(i, i_mode);
    if (!S_ISREG(mode)) {
        return 0;
    }
    data.ino = BPF_CORE_READ(i, i_ino);
    struct super_block *sb = BPF_CORE_READ(i, i_sb);
    data.dev = BPF_CORE_READ(sb, s_dev);
    data.time = bpf_ktime_get_ns();
    bpf_map_update_elem(&fput_data_map, &id, &data, BPF_ANY);

    return 0;
}

SEC("kretprobe/__fput")
int BPF_KRETPROBE(handle___fput_ret) {

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct fput_data *data;
    if (!(data = bpf_map_lookup_elem(&fput_data_map, &pid_tgid))) {
        bpf_printk("__fput without saved data");
        return 0;
    }
    struct syscall_event *e;
    if (!(e = read_main_args())) {
        return 0;
    }
    bpf_printk("__fput_ret!");
    e->type = FPUT_EVENT;
    e->fput.ino = data->ino;
    e->fput.dev = data->dev;
    bpf_map_delete_elem(&fput_data_map, &pid_tgid);
    e->event_start_time = data->time;
    e->fput.ima_hash.size = 0;
    e->fput.ima_hash.value[0] = 0;
    e->fput.evm_hash.size = 0;
    e->fput.evm_hash.value[0] = 0;

    struct ima_data *ima_data;
    if (!(ima_data = bpf_map_lookup_elem(&ima_data_map, &pid_tgid))) {
        bpf_printk("fput without saved ima data");
        goto END;
    }

    __builtin_memcpy(&e->fput.ima_hash, ima_data, sizeof(e->fput.ima_hash));

    bpf_map_delete_elem(&ima_data_map, &pid_tgid);

    struct ima_data *evm_data;
    if (!(evm_data = bpf_map_lookup_elem(&evm_data_map, &pid_tgid))) {
        bpf_printk("fput without saved evm data");
        goto END;
    }

    __builtin_memcpy(&e->fput.evm_hash, evm_data, sizeof(e->fput.evm_hash));

    bpf_map_delete_elem(&evm_data_map, &pid_tgid);
END:
    bpf_ringbuf_submit(e, 0);
    return 0;
}


SEC("kprobe/ima_update_xattr")
int BPF_KPROBE(handle_ima_update_xattr)
{
    if (!should_monitor()) {
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();

    struct ima_ctx data = {};
    data.iint_cache = (struct integrity_iint_cache *)PT_REGS_PARM1(ctx);

    bpf_map_update_elem(&ima_ctx_map, &id, &data, BPF_ANY);

    return 0;
}

SEC("kretprobe/ima_update_xattr")
int BPF_KRETPROBE(handle_ima_update_xattr_ret) {
    if (!should_monitor()) {
        return 0;
    }
    bpf_printk("ima_update_xattr_ret!");

    u64 id = bpf_get_current_pid_tgid();

    struct ima_ctx *ictx;
    if (!(ictx = bpf_map_lookup_elem(&ima_ctx_map, &id))) {
        bpf_printk("ima_update_xattr_ret: no ima_ctx found");
        return 0;
    }

    long ret = PT_REGS_RC(ctx);
    if (ret < 0) {
        goto CLEANUP;
    }

    struct integrity_iint_cache *iint_cache = ictx->iint_cache;
    struct ima_digest_data *ima_hash = BPF_CORE_READ(iint_cache, ima_hash);
    
    struct ima_data data = {};
    data.size = BPF_CORE_READ(ima_hash, length);
    //const void *value_ptr = (const void *)BPF_CORE_READ(ima_hash, digest);

    __u32 offset = offsetof(struct ima_digest_data, digest);
    __u32 offset_xattr = offsetof(struct ima_digest_data, xattr);

    const void *value_ptr = (const void *)((__u64)ima_hash + offset);
    const void *data_ptr = (const void *)((__u64)ima_hash + offset_xattr);
    
    if (data.size > HASH_MAX_DIGESTSIZE) {
        bpf_printk("ima_collesct_measurement_ret: digest size (%llu) "
            "is more that the maximum one (%d)", data.size, HASH_MAX_DIGESTSIZE);
        goto CLEANUP;
    }
    bpf_probe_read_kernel(&data.value[2], (__u32)data.size, value_ptr);
    bpf_probe_read_kernel(&data.value, 2, data_ptr);
    data.size += 2;
    // char hex_str[128] = {}; 
    // int pos = 0;
    // for (int i = 0; i < data.size && pos < sizeof(hex_str)-3; i++) {
    //     unsigned char byte = data.value[i];
    //     hex_str[pos++] = "0123456789abcdef"[byte >> 4];
    //     hex_str[pos++] = "0123456789abcdef"[byte & 0x0F];
    // }
    // hex_str[pos] = '\0';
    // bpf_printk("IMA (%d): %s\n", data.size, hex_str);


    bpf_map_update_elem(&ima_data_map, &id, &data, BPF_ANY);

CLEANUP:
    bpf_map_delete_elem(&ima_ctx_map, &id);
    return 0;
}

SEC("kprobe/chmod_common")
int BPF_KPROBE(handle_chmod_common)
{
    if (!should_monitor()) {
        return 0;
    }    

    u64 id = bpf_get_current_pid_tgid();

    struct chmod_ctx data = {};
    data.path = (struct path *)PT_REGS_PARM1(ctx);
    bpf_map_update_elem(&chmod_map, &id, &data, BPF_ANY);
    bpf_printk("kprobe/chmod_common: %llu", id);

    return 0;
}

SEC("kretprobe/chmod_common")
int BPF_KRETPROBE(handle_chmod_common_ret)
{
    if (!should_monitor()) {
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();

    struct chmod_ctx *cctx;
    if (!(cctx = bpf_map_lookup_elem(&chmod_map, &id))) {
        bpf_printk("chmod_common: no chmod_ctx found");
        return 0;
    }

    long ret = PT_REGS_RC(ctx);
    if (ret < 0) {
        goto CLEANUP;
    }

    struct path *path = cctx->path;
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);

    if (!inode) {
        bpf_printk("chmod_common: dentry without d_inode");
        goto CLEANUP;
    }

    struct chmod_data data = {};
    data.i_mode = BPF_CORE_READ(inode, i_mode);
    bpf_map_update_elem(&chmod_data_map, &id, &data, BPF_ANY);

CLEANUP:
    bpf_map_delete_elem(&chmod_map, &id);
    return 0;
}

SEC("kprobe/chown_common")
int BPF_KPROBE(handle_chown_common)
{
    if (!should_monitor()) {
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();

    struct chown_ctx data = {};
    data.path = (struct path *)PT_REGS_PARM1(ctx);

    bpf_map_update_elem(&chown_map, &id, &data, BPF_ANY);

    return 0;
}

SEC("kretprobe/chown_common")
int BPF_KRETPROBE(handle_chown_common_ret)
{
    if (!should_monitor()) {
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();

    struct chmod_ctx *cctx;
    if (!(cctx = bpf_map_lookup_elem(&chown_map, &id))) {
        bpf_printk("chown_common: no chown_ctx found");
        return 0;
    }

    long ret = PT_REGS_RC(ctx);
    if (ret < 0) {
        goto CLEANUP;
    }

    struct path *path = cctx->path;
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);

    if (!inode) {
        bpf_printk("chown_common: dentry without d_inode");
        goto CLEANUP;
    }

    struct chown_data data = {};
    data.i_mode = BPF_CORE_READ(inode, i_mode);
    bpf_map_update_elem(&chown_data_map, &id, &data, BPF_ANY);

CLEANUP:
    bpf_map_delete_elem(&chown_map, &id);
    return 0;
}

static __always_inline
int
save_syscall_args(struct trace_event_raw_sys_enter *ctx)
{
    if (!should_monitor()) {
        return 0;
    }

    u32 key = 0;

    struct syscall_args args = {};
    BPF_CORE_READ_INTO(&args.args, ctx, args);
    args.time = bpf_ktime_get_ns();

    long ret;
    if ((ret = bpf_map_update_elem(&args_map, &key, &args, BPF_ANY)) < 0) {
        bpf_printk("update elem returns %ld", ret);
    }

    return 1;
}

static __always_inline
struct syscall_event *
read_syscall_args(struct trace_event_raw_sys_exit *ctx)
{
    if (!should_monitor()) {
        return 0;
    }

    u32 key = 0;

    struct syscall_args *args;
    if (!(args = bpf_map_lookup_elem(&args_map, &key))) {
        bpf_printk("lookup failed");
        return 0;
    }
    bpf_map_delete_elem(&args_map, &key);

    struct syscall_event *e = read_main_args();
    if (!e) {
        return 0;
    }

    e->type = SYSCALL_EVENT;
    
    e->syscall.syscall_nr = ctx->id;
    __builtin_memcpy(e->syscall.args, args->args, sizeof e->syscall.args);

    e->syscall.ret = ctx->ret;
    e->event_start_time = args->time;

    return e;
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_enter_open(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_open")
int trace_exit_open(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->syscall.open.pathname, (const char *)e->syscall.args[0]);
    e->syscall.open.flags = e->syscall.args[1];
    e->syscall.open.mode = e->syscall.args[2];

    if (e->syscall.ret < 0) {
        goto END;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct file *file = bpf_get_task_file(task, e->syscall.ret);
    const struct inode *i = bpf_file_inode(file);

    e->syscall.open.uid = BPF_CORE_READ(i, i_uid).val;
    e->syscall.open.gid = BPF_CORE_READ(i, i_gid).val;
    e->syscall.open.ino = BPF_CORE_READ(i, i_ino);
    e->syscall.open.perms = BPF_CORE_READ(i, i_mode);

END:
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    e->syscall.openat.dfd = e->syscall.args[0];
    bpf_get_path(e->syscall.openat.pathname, (const char *)e->syscall.args[1]);
    e->syscall.openat.flags = e->syscall.args[2];
    e->syscall.openat.mode = e->syscall.args[3];

    if (e->syscall.ret < 0) {
        goto END;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct file *file = bpf_get_task_file(task, e->syscall.ret);
    const struct inode *i = bpf_file_inode(file);

    e->syscall.openat.uid = BPF_CORE_READ(i, i_uid).val;
    e->syscall.openat.gid = BPF_CORE_READ(i, i_gid).val;
    e->syscall.openat.ino = BPF_CORE_READ(i, i_ino);
    e->syscall.openat.perms = BPF_CORE_READ(i, i_mode);

END:
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_creat")
int trace_enter_creat(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_creat")
int trace_exit_creat(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->syscall.creat.pathname, (const char *)e->syscall.args[0]);
    e->syscall.creat.mode = e->syscall.args[1];

    if (e->syscall.ret < 0) {
        goto END;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct file *file = bpf_get_task_file(task, e->syscall.ret);
    const struct inode *i = bpf_file_inode(file);

    e->syscall.creat.uid = BPF_CORE_READ(i, i_uid).val;
    e->syscall.creat.gid = BPF_CORE_READ(i, i_gid).val;
    e->syscall.creat.ino = BPF_CORE_READ(i, i_ino);
    e->syscall.creat.perms = BPF_CORE_READ(i, i_mode);

END:
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdir")
int trace_enter_mkdir(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("kprobe/vfs_mkdir")
int BPF_KPROBE(handle_vfs_mkdir,
               struct user_namespace *mnt_userns,
               struct inode *dir,
               struct dentry *dentry,
               umode_t mode)
{
    if (!should_monitor()) {
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();

    struct mkdir_dentry_data *first_dentry;
    if (!(first_dentry = bpf_map_lookup_elem(&mkdir_dentry, &id))) {
        struct mkdir_dentry_data data = {};
        data.dentry = dentry;
        data.depth = 0;
        bpf_map_update_elem(&mkdir_dentry, &id, &data, BPF_ANY);
    } else {
        ++ first_dentry->depth;
        bpf_map_update_elem(&mkdir_dentry, &id, first_dentry, BPF_ANY);
    }

    return 0;
}

SEC("kretprobe/vfs_mkdir")
int BPF_KRETPROBE(handle_vfs_mkdir_ret)
{
    if (!should_monitor()) {
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();
    struct mkdir_dentry_data *dentryp = bpf_map_lookup_elem(&mkdir_dentry, &id);
    if (!dentryp) {
        bpf_printk("kretprobe/vfs_mkdir: no dentry for %lu", id);
        return 0;
    } else if (dentryp->depth > 0) {
        -- dentryp->depth;
        bpf_map_update_elem(&mkdir_dentry, &id, dentryp, BPF_ANY);
        return 0;
    }
    bpf_map_delete_elem(&mkdir_dentry, &id);

    struct dentry *dentry = dentryp->dentry;
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode) {
        bpf_printk("kretprobe/vfs_mkdir: no inode");
        return 0;
    }

    struct newdir_data data = {};
    data.i_uid = BPF_CORE_READ(inode, i_uid);
    data.i_gid = BPF_CORE_READ(inode, i_gid);
    data.i_ino = BPF_CORE_READ(inode, i_ino);
    data.i_mode = BPF_CORE_READ(inode, i_mode);

    bpf_map_update_elem(&mkdir_map, &id, &data, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mkdir")
int trace_exit_mkdir(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->syscall.mkdir.pathname, (char *)e->syscall.args[0]);
    e->syscall.mkdir.mode = e->syscall.args[1];

    if (e->syscall.ret != 0) {
        goto END;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct newdir_data *data;
    if (!(data = bpf_map_lookup_elem(&mkdir_map, &pid_tgid))) {
        bpf_printk("Mkdir without saved data");
        goto END;
    }

    e->syscall.mkdir.uid   = data->i_uid.val;
    e->syscall.mkdir.gid   = data->i_gid.val;
    e->syscall.mkdir.ino   = data->i_ino;
    e->syscall.mkdir.perms = data->i_mode;

    bpf_map_delete_elem(&mkdir_map, &pid_tgid);

END:
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdirat")
int trace_enter_mkdirat(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_mkdirat")
int trace_exit_mkdirat(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    e->syscall.mkdirat.dfd = e->syscall.args[0];
    bpf_get_path(e->syscall.mkdirat.pathname, (char *)e->syscall.args[1]);
    e->syscall.mkdirat.mode = e->syscall.args[2];

    if (e->syscall.ret != 0) {
        goto END;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct newdir_data *data;
    if (!(data = bpf_map_lookup_elem(&mkdir_map, &pid_tgid))) {
        bpf_printk("Mkdirat without saved data");
        goto END;
    }

    e->syscall.mkdirat.uid   = data->i_uid.val;
    e->syscall.mkdirat.gid   = data->i_gid.val;
    e->syscall.mkdirat.ino   = data->i_ino;
    e->syscall.mkdirat.perms = data->i_mode;

    bpf_map_delete_elem(&mkdir_map, &pid_tgid);

END:
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chdir")
int trace_enter_chdir(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_chdir")
int trace_exit_chdir(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->syscall.chdir.dir, (const char *)e->syscall.args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchdir")
int trace_enter_fchdir(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_fchdir")
int trace_exit_fchdir(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    e->syscall.fchdir.fd = e->syscall.args[0];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chmod")
int trace_enter_chmod(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_chmod")
int trace_exit_chmod(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->syscall.chmod.pathname, (char *)e->syscall.args[0]);
    e->syscall.chmod.mode = e->syscall.args[1];

    if (e->syscall.ret < 0) {
        goto END;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct chmod_data *data;
    if (!(data = bpf_map_lookup_elem(&chmod_data_map, &pid_tgid))) {
        bpf_printk("chmod without saved data");
        goto END;
    }

    e->syscall.chmod.perms = data->i_mode;

    bpf_map_delete_elem(&chmod_data_map, &pid_tgid);

    struct ima_data *evm_data;
    if (!(evm_data = bpf_map_lookup_elem(&evm_data_map, &pid_tgid))) {
        bpf_printk("chmod without saved evm data");
        goto END;
    }

    __builtin_memcpy(&e->syscall.chmod.evm_hash, evm_data, sizeof(e->syscall.chmod.evm_hash));

    bpf_map_delete_elem(&evm_data_map, &pid_tgid);

    bpf_printk("chmod close");

END:
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmod")
int trace_enter_fchmod(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_fchmod")
int trace_exit_fchmod(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    e->syscall.fchmod.fd = e->syscall.args[0];
    e->syscall.fchmod.mode = e->syscall.args[1];

    if (e->syscall.ret < 0) {
        goto END;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct chmod_data *data;
    if (!(data = bpf_map_lookup_elem(&chmod_data_map, &pid_tgid))) {
        bpf_printk("chmod without saved data");
        goto END;
    }

    e->syscall.fchmod.perms = data->i_mode;
    bpf_map_delete_elem(&chmod_data_map, &pid_tgid);

        struct ima_data *evm_data;
    if (!(evm_data = bpf_map_lookup_elem(&evm_data_map, &pid_tgid))) {
        bpf_printk("chmod without saved evm data");
        goto END;
    }

    __builtin_memcpy(&e->syscall.fchmod.evm_hash, evm_data, sizeof(e->syscall.fchmod.evm_hash));

    bpf_map_delete_elem(&evm_data_map, &pid_tgid);

END:
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chown")
int trace_enter_chown(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_chown")
int trace_exit_chown(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->syscall.chown.pathname, (char *)e->syscall.args[0]);
    e->syscall.chown.owner = e->syscall.args[1];
    e->syscall.chown.group = e->syscall.args[2];

    if (e->syscall.ret < 0) {
        goto END;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct chown_data *data;
    if (!(data = bpf_map_lookup_elem(&chown_data_map, &pid_tgid))) {
        bpf_printk("chown without saved data");
        goto END;
    }

    e->syscall.chown.perms = data->i_mode;

    bpf_map_delete_elem(&chown_data_map, &pid_tgid);

    struct ima_data *evm_data;
    if (!(evm_data = bpf_map_lookup_elem(&evm_data_map, &pid_tgid))) {
        bpf_printk("chown without saved evm data");
        goto END;
    }

    __builtin_memcpy(&e->syscall.chown.evm_hash, evm_data, sizeof(e->syscall.chown.evm_hash));

    bpf_map_delete_elem(&evm_data_map, &pid_tgid);

END:
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchown")
int trace_enter_fchown(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_fchown")
int trace_exit_fchown(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    e->syscall.fchown.fd = e->syscall.args[0];
    e->syscall.fchown.owner = e->syscall.args[1];
    e->syscall.fchown.group = e->syscall.args[2];

    if (e->syscall.ret < 0) {
        goto END;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct chown_data *data;
    if (!(data = bpf_map_lookup_elem(&chown_data_map, &pid_tgid))) {
        bpf_printk("chown without saved data");
        goto END;
    }

    e->syscall.fchown.perms = data->i_mode;
    bpf_map_delete_elem(&chown_data_map, &pid_tgid);

    struct ima_data *evm_data;
    if (!(evm_data = bpf_map_lookup_elem(&evm_data_map, &pid_tgid))) {
        bpf_printk("chown without saved evm data");
        goto END;
    }

    __builtin_memcpy(&e->syscall.fchown.evm_hash, evm_data, sizeof(e->syscall.fchown.evm_hash));

    bpf_map_delete_elem(&evm_data_map, &pid_tgid);

END:
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_enter_close(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_args close_args = {};
    BPF_CORE_READ_INTO(&close_args.args, ctx, args);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct file *file = bpf_get_task_file(task, close_args.args[0]);
    const struct inode *i = bpf_file_inode(file);

    struct fput_data data = {};
    data.ino = BPF_CORE_READ(i, i_ino);
    struct super_block *sb = BPF_CORE_READ(i, i_sb);
    data.dev = BPF_CORE_READ(sb, s_dev);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&fput_data_map, &pid_tgid, &data, BPF_ANY);
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_close")
int trace_exit_close(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct fput_data *data;
    if (!(data = bpf_map_lookup_elem(&fput_data_map, &pid_tgid))) {
        bpf_printk("close without saved data");
        goto END;
    } else {
        e->syscall.close.ino = data->ino;
        e->syscall.close.dev = data->dev;
        bpf_map_delete_elem(&fput_data_map, &pid_tgid);
    }
END:
    e->syscall.close.fd = e->syscall.args[0];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_umask")
int trace_enter_umask(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_umask")
int trace_exit_umask(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    e->syscall.umask.mask = e->syscall.args[0];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_enter_unlink(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_unlink")
int trace_exit_unlink(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->syscall.unlink.pathname, (char *)e->syscall.args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rmdir")
int trace_enter_rmdir(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_rmdir")
int trace_exit_rmdir(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->syscall.rmdir.pathname, (char *)e->syscall.args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getdents")
int trace_enter_getdents(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_getdents")
int trace_exit_getdents(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    e->syscall.getdents.fd = e->syscall.args[0];
    // e->getdents.dirent = e->args[1];
    // e->getdents.count = e->args[2];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_link")
int trace_enter_link(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_link")
int trace_exit_link(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->syscall.link.oldname, (char *)e->syscall.args[0]);
    bpf_get_path(e->syscall.link.newname, (char *)e->syscall.args[1]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_symlink")
int trace_enter_symlink(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_symlink")
int trace_exit_symlink(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->syscall.symlink.oldname, (char *)e->syscall.args[0]);
    bpf_get_path(e->syscall.symlink.newname, (char *)e->syscall.args[1]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getxattr")
int trace_enter_getxattr(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_getxattr")
int trace_exit_getxattr(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->syscall.getxattr.pathname, (char *)e->syscall.args[0]);
    bpf_get_xattr_name(e->syscall.getxattr.name, (char *)e->syscall.args[1]);
    e->syscall.getxattr.addr = (void *)e->syscall.args[2];
    e->syscall.getxattr.size = e->syscall.args[3];
    bpf_get_xattr_value(e->syscall.getxattr.value, e->syscall.getxattr.size, e->syscall.getxattr.addr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setxattr")
int trace_enter_setxattr(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_setxattr")
int trace_exit_setxattr(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->syscall.setxattr.pathname, (char *)e->syscall.args[0]);
    bpf_get_xattr_name(e->syscall.setxattr.name, (char *)e->syscall.args[1]);
    e->syscall.setxattr.size = e->syscall.args[3];
    e->syscall.setxattr.flags = e->syscall.args[4];
    bpf_get_xattr_value(e->syscall.setxattr.value, e->syscall.setxattr.size, (uint8_t *)e->syscall.args[2]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_execve")
int trace_exit_execve(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    if (e->syscall.ret < 0) {
        bpf_get_path(e->syscall.execve.pathname, (char *)e->syscall.args[0]);
    } else {
        // get pathname from map
        u64 pid_tgid = bpf_get_current_pid_tgid();
        struct execve_data *data;
        if (!(data = bpf_map_lookup_elem(&execve_map, &pid_tgid))) {
            bpf_printk("execve without saved data");
        } else {
            __builtin_memcpy(e->syscall.execve.pathname, data->pathname, sizeof data->pathname);
            bpf_map_delete_elem(&execve_map, &pid_tgid);
        }
    }
    //e->execve.argv = e->args[1];
    //e->execve.envp = e->args[2];
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->syscall.execve.umask = BPF_CORE_READ(task, fs, umask);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int trace_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    if (!should_monitor()) {
        return 0;
    }

    u32 loc = ctx->__data_loc_filename;

    u32 offset = loc & 0xffff;
    char *filename = (char *)ctx + offset;
    struct execve_data data = {};
    bpf_probe_read_kernel_str(data.pathname, sizeof data.pathname, filename);

    u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&execve_map, &id, &data, BPF_ANY);

    return 0;
}
 
SEC("tracepoint/syscalls/sys_enter_exit")
int trace_enter_exit(struct trace_event_raw_sys_enter *ctx)
{
    if (!should_monitor()) {
        return 0;
    }

    struct syscall_event *e;
    if (!(e = read_main_args())) {
        return 0;
    }

    e->event_start_time = e->ts;

    e->syscall.syscall_nr = ctx->id;
    struct syscall_args args = {};
    BPF_CORE_READ_INTO(&args.args, ctx, args);
    __builtin_memcpy(e->syscall.args, &args.args, sizeof e->syscall.args);

    e->syscall.ret = 0;
    e->syscall.exit.error_code = e->syscall.args[0];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit_group")
int trace_enter_exit_group(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event *e;
    if (!(e = read_main_args())) {
        return 0;
    }

    e->syscall.syscall_nr = ctx->id;
    e->event_start_time = e->ts;
    struct syscall_args args = {};
    BPF_CORE_READ_INTO(&args.args, ctx, args);
    __builtin_memcpy(e->syscall.args, &args.args, sizeof e->syscall.args);

    e->syscall.ret = 0;
    e->syscall.exit_group.error_code = e->syscall.args[0];

    bpf_ringbuf_submit(e, 0);
    return 0;
}
