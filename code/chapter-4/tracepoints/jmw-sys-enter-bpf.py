from bcc import BPF

bpf_source = """
int trace_sys_enter_bpf(void *ctx) {
  char comm[16];
  bpf_get_current_comm(&comm, sizeof(comm));

  bpf_trace_printk("sys_enter_bpf: %s", comm);
  return 0;
}
"""

bpf = BPF(text = bpf_source)
bpf.attach_tracepoint(tp = "syscalls:sys_enter_bpf", fn_name = "trace_sys_enter_bpf")
bpf.trace_print()
