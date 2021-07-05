#!/usr/bin/python3
import sys
import signal
from time import sleep
from bcc import BPF, USDT

def signal_ignore(signal, frame):
    print()

bpf_source = """
#include <uapi/linux/ptrace.h>

const int kMaxElements = 10;
BPF_HASH(pidToTSC, u64, u64, kMaxElements);
BPF_HASH(pidToNS, u64, u64, kMaxElements);
BPF_HISTOGRAM(histogram);

void trace_enter(struct pt_regs *ctx) {
  u64 pid = bpf_get_current_pid_tgid();
  u64 ts=0;
  bpf_usdt_readarg(1, ctx, &ts);
  u64 startNS = bpf_ktime_get_ns();
  int rc = pidToNS.update(&pid, &startNS);
  if (rc) {
    bpf_trace_printk("ENTRY: PID: %d: pidToNS.update() FAILED rc = %d\\n", pid, rc); //JMW errno?
    return;
  }
  rc = pidToTSC.update(&pid, &ts);
  if (rc) {
    bpf_trace_printk("ENTRY: PID: %d: pidToTSC.update() FAILED rc = %d\\n", pid, rc); //JMW errno?
    pidToNS.delete(&pid);
    return;
  }
  //bpf_trace_printk("ENTRY: PID: %d, TS: %lu\\n", pid, ts);
}

void trace_exit(struct pt_regs *ctx) {
  u64 pid = bpf_get_current_pid_tgid();
  u64 *startNS = pidToNS.lookup(&pid);
  u64 *startTSC = pidToTSC.lookup(&pid);
  if (startNS && startTSC) {
    u64 endNS = bpf_ktime_get_ns();
    u64 endTSC = 0;
    bpf_usdt_readarg(1, ctx, &endTSC);
    u64 durationNS = endNS - *startNS;
    bpf_trace_printk("EXIT: PID: %d, duration(ticks): %lu, duration(ns): %lu\\n", pid, endTSC - *startTSC, durationNS);

    histogram.increment(bpf_log2l(durationNS));

    pidToNS.delete(&pid);
    pidToTSC.delete(&pid);
  } else {
    bpf_trace_printk("EXIT: PID: %d NOT FOUND in map\\n", pid); //JMW errno?
  }
}
"""

usdt = USDT(path = "./jmw-usdt")
usdt.enable_probe(probe = "main-enter", fn_name = "trace_enter")
usdt.enable_probe(probe = "main-exit", fn_name = "trace_exit")
# JMW https://stackoverflow.com/questions/62641551/getting-bpf-programs-working-with-usdt-probes-dtrace-in-linux
# JMW doesn't workbpf = BPF(text = bpf_source, usdt = usdt)
bpf = BPF(text = bpf_source, usdt_contexts = [usdt])
#bpf.trace_print()
try:
    sleep(300)
except KeyboardInterrupt:
    signal.signal(signal.SIGINT, signal_ignore)

bpf["histogram"].print_log2_hist("nsecs")
