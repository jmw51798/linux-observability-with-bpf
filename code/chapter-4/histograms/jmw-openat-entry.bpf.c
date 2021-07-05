#if __BCC__

#include "bpf_load.h"
#include <stdio.h>

BPF_HISTOGRAM(enter_probe_timings); // execution time in ns from beginning of on_sys_enter_* to the end of on_sys_enter_*

#else

#include <linux/version.h>
#include <linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

BPF_TABLE("histogram", int, u64, enter_probe_timings, 64)

#endif

int on_sys_enter_openat(void *ctx) {
  u64 start_time_ns = bpf_ktime_get_ns();

  bpf_trace_printk("JMW\n");

  u64 probe_duration_ns = bpf_ktime_get_ns() - start_time_ns;
  enter_probe_timings.increment(bpf_log2l(probe_duration_ns));

  return 0;
}

