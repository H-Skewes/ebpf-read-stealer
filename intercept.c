#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_DATA_SIZE 256

// defines event data
struct event_t {
    u32 pid;
    u32 uid;
    s64 bytes_read;
    char data[MAX_DATA_SIZE];
    char comm[16];
};


BPF_PERF_OUTPUT(intercepted_data);
BPF_HASH(read_buf_map, u32, u64);


// hooks to read
TRACEPOINT_PROBE(syscalls, sys_enter_read)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 buf_ptr = (u64)args->buf;
    read_buf_map.update(&pid, &buf_ptr);
    return 0;
}


# copies data from read onto perf ring
TRACEPOINT_PROBE(syscalls, sys_exit_read)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    s64 bytes_read = args->ret;

    if (bytes_read <= 0) {
        read_buf_map.delete(&pid);
        return 0;
    }

    u64 *buf_ptr = read_buf_map.lookup(&pid);
    if (!buf_ptr) {
        return 0;
    }

    struct event_t e = {};
    e.pid = pid;
    e.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e.bytes_read = bytes_read;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    s64 capture_size = bytes_read < MAX_DATA_SIZE ? bytes_read : MAX_DATA_SIZE;
    bpf_probe_read_user(e.data, capture_size, (void *)(long)*buf_ptr);

    intercepted_data.perf_submit(args, &e, sizeof(e));
    read_buf_map.delete(&pid);
    return 0;
}