from bcc import BPF

bpf_source = """
int trace_bpf_prog_load(void *ctx) {
  char comm[16];
  bpf_get_current_comm(&comm, sizeof(comm));

  bpf_trace_printk("%s is loading a BPF program\\n", comm);
  return 0;
}
"""

bpf = BPF(text = bpf_source)

# JMW this doesn't work for me on linuxvm: (/sys/kernel/debug/tracing/events/bpf doesn't exist)
# bpf.attach_tracepoint(tp = "bpf:bpf_prog_load", fn_name = "trace_bpf_prog_load")
#
# % sudo python3 example.py
# open(/sys/kernel/debug/tracing/events/bpf/bpf_prog_load/id): No such file or directory
# Traceback (most recent call last):
#   File "example.py", line 14, in <module>
#     bpf.attach_tracepoint(tp = "bpf:bpf_prog_load", fn_name = "trace_bpf_prog_load")
#   File "/usr/lib/python3/dist-packages/bcc/__init__.py", line 826, in attach_tracepoint
#     raise Exception("Failed to attach BPF program %s to tracepoint %s" %
# Exception: Failed to attach BPF program b'trace_bpf_prog_load' to tracepoint b'bpf:bpf_prog_load'
#
# root@linuxvm:/sys/kernel/debug/tracing# find . -name *bpf*
# ./events/bpf_test_run
# ./events/bpf_test_run/bpf_test_finish
# ./events/syscalls/sys_enter_bpf
# ./events/syscalls/sys_exit_bpf

bpf.attach_tracepoint(tp = "syscalls:sys_enter_bpf", fn_name = "trace_bpf_prog_load")

bpf.trace_print()

