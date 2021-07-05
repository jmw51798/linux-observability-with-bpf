#!/usr/bin/python3

import sys
import signal
from time import sleep

from bcc import BPF

def signal_ignore(signal, frame):
    print()

with open ("./jmw-openat-timings.bpf.c", "r") as bpf_source_file:
    bpf_source = bpf_source_file.read()
# print (bpf_source)

#bpf = BPF(text = bpf_source)
# JMW from https://bolinfest.github.io/opensnoop-native/ 
from bcc import DEBUG_SOURCE
bpf = BPF(text = bpf_source, debug=DEBUG_SOURCE)
import sys; sys.exit(0)
