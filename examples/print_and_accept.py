#!/usr/bin/env python
from netfilterqueue import NetfilterQueue

def print_and_accept(pkt):
    print(pkt)
    hw = pkt.get_hw()
    if hw:
        print(":".join("{:02x}".format(ord(c)) for c in hw[0:6]))
    pkt.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')

nfqueue.unbind()
