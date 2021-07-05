from bcc import BPF

tmp = """
drwxr-xr-x   2 root root 0 Jul  3 10:00 sys_enter_fsopen/
drwxr-xr-x   2 root root 0 Jul  3 10:00 sys_enter_mq_open/
drwxr-xr-x   2 root root 0 Jul  3 10:00 sys_enter_open/
drwxr-xr-x   2 root root 0 Jul  3 10:00 sys_enter_openat/
drwxr-xr-x   2 root root 0 Jul  3 10:00 sys_enter_open_by_handle_at/
drwxr-xr-x   2 root root 0 Jul  3 10:00 sys_enter_open_tree/
drwxr-xr-x   2 root root 0 Jul  3 10:00 sys_enter_perf_event_open/
drwxr-xr-x   2 root root 0 Jul  3 10:00 sys_enter_pidfd_open/
drwxr-xr-x   2 root root 0 Jul  3 10:00 sys_exit_fsopen/
drwxr-xr-x   2 root root 0 Jul  3 10:00 sys_exit_mq_open/
drwxr-xr-x   2 root root 0 Jul  3 10:00 sys_exit_open/
drwxr-xr-x   2 root root 0 Jul  3 10:00 sys_exit_openat/
drwxr-xr-x   2 root root 0 Jul  3 10:00 sys_exit_open_by_handle_at/
drwxr-xr-x   2 root root 0 Jul  3 10:00 sys_exit_open_tree/
drwxr-xr-x   2 root root 0 Jul  3 10:00 sys_exit_perf_event_open/
drwxr-xr-x   2 root root 0 Jul  3 10:00 sys_exit_pidfd_open/
"""

bpf_source = """
int on_sys_enter_open(void *ctx) {
  char comm[16];
  bpf_get_current_comm(&comm, sizeof(comm));

  bpf_trace_printk("sys_enter_open: %s\\n", comm);
  return 0;
}

int on_sys_enter_openat(void *ctx) {
  char comm[16];
  bpf_get_current_comm(&comm, sizeof(comm));

  bpf_trace_printk("sys_enter_openat: %s\\n", comm);
  return 0;
}
"""

bpf = BPF(text = bpf_source)
bpf.attach_tracepoint(tp = "syscalls:sys_enter_open", fn_name = "on_sys_enter_open")
bpf.attach_tracepoint(tp = "syscalls:sys_enter_openat", fn_name = "on_sys_enter_openat")
bpf.trace_print()
