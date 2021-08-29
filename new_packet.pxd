cdef extern from "sys/types.h":
    ctypedef unsigned char u_int8_t
    ctypedef unsigned short int u_int16_t
    ctypedef unsigned int u_int32_t

cdef extern from "<errno.h>":
    int errno

# dummy defines from asm-generic/errno.h:
cdef enum:
    EAGAIN = 11           # Try again
    EWOULDBLOCK = EAGAIN
    ENOBUFS = 105         # No buffer space available

# cython define
cdef struct iphdr:
        u_int8_t  ver_ihl
        u_int8_t  tos
        u_int16_t tot_len
        u_int16_t id
        u_int16_t frag_off
        u_int8_t  ttl
        u_int8_t  protocol
        u_int16_t check
        u_int32_t saddr
        u_int32_t daddr

# cython define
cdef struct tcphdr:
    u_int16_t th_sport
    u_int16_t th_dport
    u_int32_t th_seq
    u_int32_t th_ack

    u_int8_t  th_off

    u_int8_t  th_flags
    u_int16_t th_win
    u_int16_t th_sum
    u_int16_t th_urp

# cython define
cdef struct udphdr:
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

cdef extern from "Python.h":
    object PyBytes_FromStringAndSize(char *s, Py_ssize_t len)

cdef extern from "sys/time.h":
    ctypedef long time_t
    struct timeval:
        time_t tv_sec
        time_t tv_usec

    struct timezone:
        pass

cdef extern from "netinet/in.h":
    u_int32_t ntohl (u_int32_t __netlong) nogil
    u_int16_t ntohs (u_int16_t __netshort) nogil
    u_int32_t htonl (u_int32_t __hostlong) nogil
    u_int16_t htons (u_int16_t __hostshort) nogil

cdef extern from "libnfnetlink/linux_nfnetlink.h":
    struct nfgenmsg:
        u_int8_t nfgen_family
        u_int8_t version
        u_int16_t res_id

cdef extern from "libnfnetlink/libnfnetlink.h":
    struct nfnl_handle:
        pass

    unsigned int nfnl_rcvbufsiz(nfnl_handle *h, unsigned int size)

cdef extern from "libnetfilter_queue/linux_nfnetlink_queue.h":
    enum nfqnl_config_mode:
        NFQNL_COPY_NONE
        NFQNL_COPY_META
        NFQNL_COPY_PACKET

    struct nfqnl_msg_packet_hdr:
        u_int32_t packet_id
        u_int16_t hw_protocol
        u_int8_t hook

cdef extern from "libnetfilter_queue/libnetfilter_queue.h":
    struct nfq_handle:
        pass

    struct nfq_q_handle:
        pass

    struct nfq_data:
        pass

    struct nfqnl_msg_packet_hw:
        u_int8_t hw_addr[8]

    nfq_handle *nfq_open()
    int nfq_close(nfq_handle *h)
    int nfq_bind_pf(nfq_handle *h, u_int16_t pf)
    int nfq_unbind_pf(nfq_handle *h, u_int16_t pf)
    ctypedef int *nfq_callback(nfq_q_handle *gh, nfgenmsg *nfmsg, nfq_data *nfad, void *data)
    nfq_q_handle *nfq_create_queue(nfq_handle *h, u_int16_t num, nfq_callback *cb, void *data)
    int nfq_destroy_queue(nfq_q_handle *qh)
    int nfq_handle_packet(nfq_handle *h, char *buf, int len)
    int nfq_set_mode(nfq_q_handle *qh, u_int8_t mode, unsigned int len)
    q_set_queue_maxlen(nfq_q_handle *qh, u_int32_t queuelen)
    int nfq_set_verdict(nfq_q_handle *qh, u_int32_t id, u_int32_t verdict, u_int32_t data_len, unsigned char *buf) nogil
    int nfq_set_verdict2(nfq_q_handle *qh, u_int32_t id, u_int32_t verdict, u_int32_t mark,
        u_int32_t datalen, unsigned char *buf) nogil

    int nfq_set_queue_maxlen(nfq_q_handle *qh, u_int32_t queuelen)
    int nfq_fd(nfq_handle *h)
    nfqnl_msg_packet_hdr *nfq_get_msg_packet_hdr(nfq_data *nfad) nogil
    int nfq_get_payload(nfq_data *nfad, unsigned char **data) nogil
    int nfq_get_timestamp(nfq_data *nfad, timeval *tv) nogil
    nfqnl_msg_packet_hw *nfq_get_packet_hw(nfq_data *nfad)
    int nfq_get_nfmark (nfq_data *nfad) nogil
    u_int8_t nfq_get_indev(nfq_data *nfad)
    u_int8_t nfq_get_outdev(nfq_data *nfad)
    nfnl_handle *nfq_nfnlh(nfq_handle *h)

# Dummy defines from linux/socket.h:
cdef enum: #  Protocol families, same as address families.
    PF_INET = 2
    PF_INET6 = 10

cdef extern from "sys/socket.h":
    ssize_t recv(int __fd, void *__buf, size_t __n, int __flags) nogil
    int MSG_DONTWAIT

# Dummy defines from linux/netfilter.h
cdef enum:
    NF_DROP
    NF_ACCEPT
    NF_STOLEN
    NF_QUEUE
    NF_REPEAT
    NF_STOP
    NF_MAX_VERDICT = NF_STOP


cdef class CPacket:
    cdef nfq_q_handle *_qh
    cdef nfq_data *_nfa
    cdef nfqnl_msg_packet_hdr *_hdr
    cdef nfqnl_msg_packet_hw *_hw

    cdef u_int32_t id

    # protocol headers
    cdef iphdr *ip_header
    cdef tcphdr *tcp_header
    cdef udphdr *udp_header
    cdef icmphdr *icmp_header

    cdef u_int8_t cmbhdr_len

    cdef bint _verdict_is_set
    cdef u_int32_t _mark

    # Packet details:
    cdef Py_ssize_t data_len
    cdef readonly unsigned char *data
    cdef readonly unsigned char *payload
    cdef timeval timestamp

    cdef u_int32_t parse(self, nfq_q_handle *qh, nfq_data *nfa) nogil
    cdef void _parse(self) nogil
    cdef void verdict(self, u_int32_t verdict)
    cdef double get_timestamp(self)
    cpdef update_mark(self, u_int32_t mark)
    cpdef accept(self)
    cpdef drop(self)
    cpdef forward(self, u_int16_t queue_num)
    cpdef repeat(self)

cdef class NetfilterQueue:
    cdef nfq_handle *h # Handle to NFQueue library
    cdef nfq_q_handle *qh # A handle to the queue
    cdef u_int16_t af # Address family
    cdef packet_copy_size # Amount of packet metadata + data copied to buffer