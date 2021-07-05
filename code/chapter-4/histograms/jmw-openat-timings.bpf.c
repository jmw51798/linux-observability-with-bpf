#include <uapi/linux/ptrace.h>

BPF_HASH(pid_timestamps, u64, u64); // PID --> timestamp
BPF_HISTOGRAM(syscall_timings);     // duration in ns from beginning of sys_enter_* to sys_exit_*
BPF_HISTOGRAM(enter_probe_timings); // execution time in ns from beginning of on_sys_enter_* to the end of on_sys_enter_*
BPF_HISTOGRAM(exit_probe_timings);  // execution time in ns from beginning of on_sys_exit_* to the end of on_sys_exit_*

int on_sys_enter_openat(void *ctx) {
  u64 start_time_ns = bpf_ktime_get_ns();

  u64 pid = bpf_get_current_pid_tgid();
  pid_timestamps.update(&pid, &start_time_ns);

  //char comm[16];
  //bpf_get_current_comm(&comm, sizeof(comm));
  //bpf_trace_printk("sys_enter_openat: %d %s\\n", pid, comm);

  //counts[OPENAT]pid_map.update(&pid, &start_time_ns);

  u64 probe_duration_ns = bpf_ktime_get_ns() - start_time_ns;
  enter_probe_timings.increment(bpf_log2l(probe_duration_ns));

  return 0;
}

int on_sys_exit_openat(void *ctx) {
  u64 probe_start_time_ns = bpf_ktime_get_ns();

  u64 pid = bpf_get_current_pid_tgid();
  u64 *syscall_start_time_ns;
  syscall_start_time_ns = pid_timestamps.lookup(&pid);
  if (syscall_start_time_ns == 0)
    return 0;
  pid_timestamps.delete(&pid);
  u64 syscall_duration_ns = bpf_ktime_get_ns() - *syscall_start_time_ns;
  syscall_timings.increment(bpf_log2l(syscall_duration_ns));

  //char comm[16];
  //bpf_get_current_comm(&comm, sizeof(comm));
  //bpf_trace_printk("sys_exit_openat: %d %s\\n", pid, comm);

  //counts[OPENAT]pid_map.update(&pid, &probe_start_time_ns);

  u64 probe_duration_ns = bpf_ktime_get_ns() - probe_start_time_ns;
  exit_probe_timings.increment(bpf_log2l(probe_duration_ns));

  return 0;
}
