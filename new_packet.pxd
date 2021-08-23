cdef extern from "sys/types.h":
    ctypedef unsigned char u_int8_t
    ctypedef unsigned short int u_int16_t
    ctypedef unsigned int u_int32_t

cdef extern from "<errno.h>":
    int errno

# cython define
cdef extern from "netinet/ip.h":
    struct iphdr:
        u_int8_t tos
        u_int16_t tot_len
        u_int16_t id
        u_int16_t frag_off
        u_int8_t ttl
        u_int8_t protocol
        u_int16_t check
        u_int32_t saddr
        u_int32_t daddr

# cython define
cdef extern from "netinet/tcp.h":
    struct tcphdr:
        u_int16_t	th_sport
        u_int16_t	th_dport
        u_int32_t	th_seq
        u_int32_t	th_ack

        u_int8_t th_x2:4
        u_int8_t th_off:4

        u_int8_t th_flags

        u_int16_t th_win
        u_int16_t th_sum
        u_int16_t th_urp

# cython define
cdef extern from "netinet/udp.h":
    struct udphdr:
        u_int16_t uh_sport
        u_int16_t uh_dport
        u_int16_t uh_ulen
        u_int16_t uh_sum

cdef struct icmphdr:
    u_int8_t type

# from netinet/in.h:
cdef enum:
    IPPROTO_IP = 0        # Dummy protocol for TCP.
    IPPROTO_ICMP = 1      # Internet Control Message Protocol.
    IPPROTO_TCP = 6       # Transmission Control Protocol.
    IPPROTO_UDP = 17      # User Datagram Protocol.


cdef class CPacket:
    cdef nfq_q_handle *_qh
    cdef nfq_data *_nfa
    cdef nfqnl_msg_packet_hdr *_hdr
    cdef nfqnl_msg_packet_hw *_hw

    cdef u_int16_t __queue_num
    cdef bint threaded

    cdef bint _verdict_is_set
    cdef u_int32_t _mark

    # Packet details:
    cdef Py_ssize_t payload_len
    cdef readonly unsigned char *payload
    cdef timeval timestamp
    cdef u_int8_t hw_addr[8]

    cdef netfilter(nfq_q_handle * qh, nfgenmsg * nfmsg, nfq_data * nfa, void * data)
    cdef void verdict(self, u_int32_t verdict)
    cdef def parse(self) nogil
