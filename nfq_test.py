#!/usr/bin/env python3

import threading

from time import perf_counter_ns
from ipaddress import IPv4Address

from new_packet import set_user_callback, NetfilterQueue

TEST_FORWARD = 0

def print_and_accept(pkt, pkt_mark):
    print('+'*30)

    start = perf_counter_ns()

#    print(pkt_mark)

    hw_info = pkt.get_hw()

#    print(hw_info)

#    print(hw_info[2].hex())

#    print('-'*30)

#    data = pkt.get_raw_packet()

#    print(data[0], (data[0] & 15) * 4)

#    print('-'*30)

    ip_header = pkt.get_ip_header()

#    print(ip_header)
#    print(ip_header[6], IPv4Address(ip_header[8]), IPv4Address(ip_header[9]))

#    print('-'*30)

    proto_header = pkt.get_proto_header()

#    print(pkt.get_proto_header())

#    print('-'*30)

    payload = pkt.get_payload()
#    print(pkt.get_payload())

#    t, s, d = pkt.get_ip_header()

#    print(array('i', pkt.get_ip_header()))
#    print(pkt, pkt.get_timestamp())

#    print(f'[IN] {pkt.get_inint()} {pkt.get_inint(name=True)}')
#    print(f'[OUT] {pkt.get_outint()} {pkt.get_outint(name=True)}')

#    pkt.update_mark(69)

#    print(f'[MARK] {pkt.get_initial_mark()} {pkt.get_modified_mark()} ')

#    print(pkt.payload_test)

    total = perf_counter_ns() - start

    pkt.accept()

    print(f'GRABBED IN: {total} ns')

    print('='*30)

def q_one(pkt):
    print('+'*30)

    print('[Q1/rcvd]')
#    print(f'[IN] {pkt.get_inint()} {pkt.get_inint(name=True)}')
#    print(f'[OUT] {pkt.get_outint()} {pkt.get_outint(name=True)}')

#    pkt.update_mark(69)

#    print(f'[MARK] {pkt.get_initial_mark()} {pkt.get_modified_mark()}')

#    pkt.forward(2)
#    print('[Q1/forward] > 2')

    print('-'*30)

def q_two(pkt):
    print('+'*30)

    print('[Q2/rcvd]')
    print(f'[IN] {pkt.get_inint()} {pkt.get_inint(name=True)}')
    print(f'[OUT] {pkt.get_outint()} {pkt.get_outint(name=True)}')

    pkt.update_mark(70)

    print(f'[MARK] {pkt.get_initial_mark()} {pkt.get_modified_mark()}')

    pkt.accept()

    print('[Q2/accept]')

    print('-'*30)

def queue(callback, queue_num):
    set_user_callback(print_and_accept)

    nfqueue = NetfilterQueue()
    nfqueue.bind(queue_num)

    print(f'[START] QUEUE-{queue_num}')

    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print('')

    finally:
        nfqueue.unbind()

if __name__ == '__main__':

    if (TEST_FORWARD):
        threading.Thread(target=queue, args=(q_one, 1)).start()
        threading.Thread(target=queue, args=(q_two, 2)).start()

    else:
        queue(print_and_accept, 1)
