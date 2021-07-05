from bcc import BPF

bpf_source = """
int trace_sys_enter_clock_gettime(void *ctx) {
  char comm[16];
  bpf_get_current_comm(&comm, sizeof(comm));

  //bpf_trace_printk("sys_enter_clock_gettime: %s\\n", comm);
  bpf_trace_printk("JMW\\n");
  return 0;
}
"""

bpf = BPF(text = bpf_source)
bpf.attach_tracepoint(tp = "syscalls:sys_enter_clock_gettime", fn_name = "trace_sys_enter_clock_gettime")
bpf.trace_print()
