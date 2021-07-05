import sys
import signal
from time import sleep

from bcc import BPF

def signal_ignore(signal, frame):
    print()

with open ("./jmw-openat-timings.bpf.c", "r") as bpf_source_file:
    bpf_source = bpf_source_file.read()
# print (bpf_source)

bpf = BPF(text = bpf_source)
bpf.attach_tracepoint(tp = "syscalls:sys_enter_openat", fn_name = "on_sys_enter_openat")
bpf.attach_tracepoint(tp = "syscalls:sys_exit_openat", fn_name = "on_sys_exit_openat")

try:
    sleep(300)
except KeyboardInterrupt:
    signal.signal(signal.SIGINT, signal_ignore)

bpf["syscall_timings"].print_log2_hist("syscall_timings (nsecs)")
print ()
bpf["enter_probe_timings"].print_log2_hist("enter_probe_timings (nsecs)")
print ()
bpf["exit_probe_timings"].print_log2_hist("exit_probe_timings (nsecs)")
