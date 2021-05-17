from bcc import BPF

bpf_source = """
int trace_bpf_prog_load(void *ctx) {
  char comm[16];
  bpf_get_current_comm(&comm, sizeof(comm));

  bpf_trace_printk("%s is loading a BPF program", comm);
  return 0;
}
"""

bpf = BPF(text = bpf_source)
bpf.attach_tracepoint(tp = "bpf:bpf_prog_load", fn_name = "trace_bpf_prog_load")
bpf.trace_print()

# JMW this doesn't work for me on linuxvm:
#
# % sudo python3 example.py
# open(/sys/kernel/debug/tracing/events/bpf/bpf_prog_load/id): No such file or directory
# Traceback (most recent call last):
#   File "example.py", line 14, in <module>
#     bpf.attach_tracepoint(tp = "bpf:bpf_prog_load", fn_name = "trace_bpf_prog_load")
#   File "/usr/lib/python3/dist-packages/bcc/__init__.py", line 826, in attach_tracepoint
#     raise Exception("Failed to attach BPF program %s to tracepoint %s" %
# Exception: Failed to attach BPF program b'trace_bpf_prog_load' to tracepoint b'bpf:bpf_prog_load'
