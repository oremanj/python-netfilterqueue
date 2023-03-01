cdef extern from "<sys/types.h>":
    ctypedef unsigned char u_int8_t
    ctypedef unsigned short int u_int16_t
    ctypedef unsigned int u_int32_t

cdef extern from "<unistd.h>":
    int dup2(int oldfd, int newfd)

cdef extern from "<errno.h>":
    int errno

# dummy defines from asm-generic/errno.h:
cdef enum:
    EINTR = 4
    EAGAIN = 11           # Try again
    EWOULDBLOCK = EAGAIN
    ENOBUFS = 105         # No buffer space available

cdef extern from "<netinet/ip.h>":
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

# Dummy defines from netinet/in.h:
cdef enum:
    IPPROTO_IP = 0        # Dummy protocol for TCP.
    IPPROTO_HOPOPTS = 0   # IPv6 Hop-by-Hop options.
    IPPROTO_ICMP = 1      # Internet Control Message Protocol.
    IPPROTO_IGMP = 2      # Internet Group Management Protocol. */
    IPPROTO_IPIP = 4      # IPIP tunnels (older KA9Q tunnels use 94).
    IPPROTO_TCP = 6       # Transmission Control Protocol.
    IPPROTO_EGP = 8       # Exterior Gateway Protocol.
    IPPROTO_PUP = 12      # PUP protocol.
    IPPROTO_UDP = 17      # User Datagram Protocol.
    IPPROTO_IDP = 22      # XNS IDP protocol.
    IPPROTO_TP = 29       # SO Transport Protocol Class 4.
    IPPROTO_IPV6 = 41     # IPv6 header.
    IPPROTO_ROUTING = 43  # IPv6 routing header.
    IPPROTO_FRAGMENT = 44 # IPv6 fragmentation header.
    IPPROTO_RSVP = 46     # Reservation Protocol.
    IPPROTO_GRE = 47      # General Routing Encapsulation.
    IPPROTO_ESP = 50      # encapsulating security payload.
    IPPROTO_AH = 51       # authentication header.
    IPPROTO_ICMPV6 = 58   # ICMPv6.
    IPPROTO_NONE = 59     # IPv6 no next header.
    IPPROTO_DSTOPTS = 60  # IPv6 destination options.
    IPPROTO_MTP = 92      # Multicast Transport Protocol.
    IPPROTO_ENCAP = 98    # Encapsulation Header.
    IPPROTO_PIM = 103     # Protocol Independent Multicast.
    IPPROTO_COMP = 108    # Compression Header Protocol.
    IPPROTO_SCTP = 132    # Stream Control Transmission Protocol.
    IPPROTO_RAW = 255     # Raw IP packets.
    IPPROTO_MAX

cdef extern from "Python.h":
    object PyBytes_FromStringAndSize(char *s, Py_ssize_t len)
    object PyString_FromStringAndSize(char *s, Py_ssize_t len)

cdef extern from "<sys/time.h>":
    ctypedef long time_t
    struct timeval:
        time_t tv_sec
        time_t tv_usec
    struct timezone:
        pass

cdef extern from "<netinet/in.h>":
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
    nfnl_handle *nfnl_open()
    void nfnl_close(nfnl_handle *h)
    int nfnl_fd(nfnl_handle *h)
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
    nfq_handle *nfq_open_nfnl(nfnl_handle *h)
    int nfq_close(nfq_handle *h)

    int nfq_bind_pf(nfq_handle *h, u_int16_t pf)
    int nfq_unbind_pf(nfq_handle *h, u_int16_t pf)
    ctypedef int *nfq_callback(nfq_q_handle *gh, nfgenmsg *nfmsg,
                       nfq_data *nfad, void *data)
    nfq_q_handle *nfq_create_queue(nfq_handle *h,
                                    u_int16_t num,
                                    nfq_callback *cb,
                                    void *data)

    # Any function that parses Netlink replies might invoke the user
    # callback and thus might need to propagate a Python exception.
    # This includes nfq_handle_packet but is not limited to that --
    # other functions might send a query, read until they get the reply,
    # and find a packet notification before the reply which they then
    # must deal with.
    int nfq_destroy_queue(nfq_q_handle *qh) except? -1
    int nfq_handle_packet(nfq_handle *h, char *buf, int len) except? -1
    int nfq_set_mode(nfq_q_handle *qh, u_int8_t mode, unsigned int len) except? -1
    int nfq_set_queue_maxlen(nfq_q_handle *qh, u_int32_t queuelen) except? -1

    int nfq_set_verdict(nfq_q_handle *qh,
                          u_int32_t id,
                          u_int32_t verdict,
                          u_int32_t data_len,
                          unsigned char *buf) nogil

    int nfq_set_verdict2(nfq_q_handle *qh,
                            u_int32_t id,
                            u_int32_t verdict,
                            u_int32_t mark,
                            u_int32_t datalen,
                            unsigned char *buf) nogil

    int nfq_fd(nfq_handle *h)
    nfqnl_msg_packet_hdr *nfq_get_msg_packet_hdr(nfq_data *nfad)
    int nfq_get_payload(nfq_data *nfad, unsigned char **data)
    int nfq_get_timestamp(nfq_data *nfad, timeval *tv)
    nfqnl_msg_packet_hw *nfq_get_packet_hw(nfq_data *nfad)
    int nfq_get_nfmark(nfq_data *nfad)
    u_int32_t nfq_get_indev(nfq_data *nfad)
    u_int32_t nfq_get_outdev(nfq_data *nfad)
    u_int32_t nfq_get_physindev(nfq_data *nfad)
    u_int32_t nfq_get_physoutdev(nfq_data *nfad)
    nfnl_handle *nfq_nfnlh(nfq_handle *h)

# Dummy defines from linux/socket.h:
cdef enum: #  Protocol families, same as address families.
    PF_INET = 2
    PF_INET6 = 10
    PF_NETLINK = 16

cdef extern from "<sys/socket.h>":
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

cdef class NetfilterQueue:
    cdef object __weakref__
    cdef object user_callback # User callback
    cdef nfq_handle *h # Handle to NFQueue library
    cdef nfq_q_handle *qh # A handle to the queue

cdef class Packet:
    cdef NetfilterQueue _queue
    cdef bint _verdict_is_set # True if verdict has been issued, false otherwise
    cdef bint _mark_is_set # True if a mark has been given, false otherwise
    cdef bint _hwaddr_is_set
    cdef bint _timestamp_is_set
    cdef u_int32_t _given_mark # Mark given to packet
    cdef bytes _given_payload # New payload of packet, or null
    cdef bytes _owned_payload

    # From NFQ packet header:
    cdef readonly u_int32_t id
    cdef readonly u_int16_t hw_protocol
    cdef readonly u_int8_t hook
    cdef readonly u_int32_t mark

    # Packet details:
    cdef Py_ssize_t payload_len
    cdef unsigned char *payload
    cdef timeval timestamp
    cdef u_int8_t hw_addr[8]
    cdef readonly u_int32_t indev
    cdef readonly u_int32_t physindev
    cdef readonly u_int32_t outdev
    cdef readonly u_int32_t physoutdev

    cdef set_nfq_data(self, NetfilterQueue queue, nfq_data *nfa)
    cdef drop_refs(self)
    cdef int verdict(self, u_int8_t verdict) except -1
    cpdef Py_ssize_t get_payload_len(self)
    cpdef double get_timestamp(self)
    cpdef bytes get_payload(self)
    cpdef set_payload(self, bytes payload)
    cpdef set_mark(self, u_int32_t mark)
    cpdef get_mark(self)
    cpdef retain(self)
    cpdef accept(self)
    cpdef drop(self)
    cpdef repeat(self)
