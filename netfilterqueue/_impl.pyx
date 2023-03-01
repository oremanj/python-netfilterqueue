"""
Bind to a Linux netfilter queue. Send packets to a user-specified callback
function.

Copyright: (c) 2011, Kerkhoff Technologies Inc.
License: MIT; see LICENSE.txt
"""

# Constants for module users
COPY_NONE = 0
COPY_META = 1
COPY_PACKET = 2

# Packet copying defaults
DEF DEFAULT_MAX_QUEUELEN = 1024
DEF MaxPacketSize = 0xFFFF
DEF BufferSize = 4096
DEF MetadataSize = 80
DEF MaxCopySize = BufferSize - MetadataSize
# Experimentally determined overhead
DEF SockOverhead = 760+20
DEF SockCopySize = MaxCopySize + SockOverhead
# Socket queue should hold max number of packets of copysize bytes
DEF SockRcvSize = DEFAULT_MAX_QUEUELEN * SockCopySize // 2

from cpython.exc cimport PyErr_CheckSignals

cdef extern from "Python.h":
    ctypedef struct PyTypeObject:
        const char* tp_name

# A negative return value from this callback will stop processing and
# make nfq_handle_packet return -1, so we use that as the error flag.
cdef int global_callback(nfq_q_handle *qh, nfgenmsg *nfmsg,
                         nfq_data *nfa, void *data) except -1 with gil:
    """Create a Packet and pass it to appropriate callback."""
    cdef NetfilterQueue nfqueue = <NetfilterQueue>data
    cdef object user_callback = <object>nfqueue.user_callback
    if user_callback is None:
        # Queue is being unbound; we can't send a verdict at this point
        # so just ignore the packet. The kernel will drop it once we
        # unbind.
        return 1
    packet = Packet()
    packet.set_nfq_data(nfqueue, nfa)
    try:
        user_callback(packet)
    finally:
        packet.drop_refs()
    return 1

cdef class Packet:
    """A packet received from NetfilterQueue."""
    def __cinit__(self):
        self._verdict_is_set = False
        self._mark_is_set = False
        self._given_payload = None

    def __str__(self):
        cdef unsigned char *payload = NULL
        if self._owned_payload:
            payload = self._owned_payload
        elif self.payload != NULL:
            payload = self.payload
        else:
            return "%d byte packet, contents unretained" % (self.payload_len,)

        cdef iphdr *hdr = <iphdr*>payload
        protocol = PROTOCOLS.get(hdr.protocol, "Unknown protocol")
        return "%s packet, %s bytes" % (protocol, self.payload_len)

    cdef set_nfq_data(self, NetfilterQueue queue, nfq_data *nfa):
        """
        Assign a packet from NFQ to this object. Parse the header and load
        local values.
        """
        cdef nfqnl_msg_packet_hw *hw
        cdef nfqnl_msg_packet_hdr *hdr

        hdr = nfq_get_msg_packet_hdr(nfa)
        self._queue = queue
        self.id = ntohl(hdr.packet_id)
        self.hw_protocol = ntohs(hdr.hw_protocol)
        self.hook = hdr.hook

        hw = nfq_get_packet_hw(nfa)
        if hw == NULL:
            # nfq_get_packet_hw doesn't work on OUTPUT and PREROUTING chains
            self._hwaddr_is_set = False
        else:
            self.hw_addr = hw.hw_addr
            self._hwaddr_is_set = True

        self.payload_len = nfq_get_payload(nfa, &self.payload)
        if self.payload_len < 0:
            # Probably using a mode that doesn't provide the payload
            self.payload = NULL
            self.payload_len = 0

        nfq_get_timestamp(nfa, &self.timestamp)
        self.mark = nfq_get_nfmark(nfa)
        self.indev = nfq_get_indev(nfa)
        self.outdev = nfq_get_outdev(nfa)
        self.physindev = nfq_get_physindev(nfa)
        self.physoutdev = nfq_get_physoutdev(nfa)

    cdef drop_refs(self):
        """
        Called at the end of the user_callback, when the storage passed to
        set_nfq_data() is about to be reused.
        """
        self.payload = NULL

    cdef int verdict(self, u_int8_t verdict) except -1:
        """Call appropriate set_verdict... function on packet."""
        if self._verdict_is_set:
            raise RuntimeError("Verdict already given for this packet")
        if self._queue.qh == NULL:
            raise RuntimeError("Parent queue has already been unbound")

        cdef u_int32_t modified_payload_len = 0
        cdef unsigned char *modified_payload = NULL
        if self._given_payload:
            modified_payload_len = len(self._given_payload)
            modified_payload = self._given_payload
        if self._mark_is_set:
            nfq_set_verdict2(
                self._queue.qh,
                self.id,
                verdict,
                self._given_mark,
                modified_payload_len,
                modified_payload)
        else:
            nfq_set_verdict(
                self._queue.qh,
                self.id,
                verdict,
                modified_payload_len,
                modified_payload)

        self._verdict_is_set = True

    def get_hw(self):
        """Return the packet's source MAC address as a Python bytestring, or
        None if it's not available.
        """
        if not self._hwaddr_is_set:
            return None
        cdef object py_string
        py_string = PyBytes_FromStringAndSize(<char*>self.hw_addr, 8)
        return py_string

    cpdef bytes get_payload(self):
        """Return payload as Python string."""
        if self._given_payload:
            return self._given_payload
        elif self._owned_payload:
            return self._owned_payload
        elif self.payload != NULL:
            return self.payload[:self.payload_len]
        elif self.payload_len == 0:
            raise RuntimeError(
                "Packet has no payload -- perhaps you're using COPY_META mode?"
            )
        else:
            raise RuntimeError(
                "Payload data is no longer available. You must call "
                "retain() within the user_callback in order to copy "
                "the payload if you need to expect it after your "
                "callback has returned."
            )

    cpdef Py_ssize_t get_payload_len(self):
        return self.payload_len

    cpdef double get_timestamp(self):
        return self.timestamp.tv_sec + (self.timestamp.tv_usec/1000000.0)

    cpdef set_payload(self, bytes payload):
        """Set the new payload of this packet."""
        self._given_payload = payload

    cpdef set_mark(self, u_int32_t mark):
        self._given_mark = mark
        self._mark_is_set = True

    cpdef get_mark(self):
        if self._mark_is_set:
            return self._given_mark
        return self.mark

    cpdef retain(self):
        self._owned_payload = self.get_payload()

    cpdef accept(self):
        """Accept the packet."""
        self.verdict(NF_ACCEPT)

    cpdef drop(self):
        """Drop the packet."""
        self.verdict(NF_DROP)

    cpdef repeat(self):
        """Repeat the packet."""
        self.verdict(NF_REPEAT)


cdef class NetfilterQueue:
    """Handle a single numbered queue."""
    def __cinit__(self, *, u_int16_t af = PF_INET, int sockfd = -1):
        cdef nfnl_handle *nlh = NULL
        try:
            if sockfd >= 0:
                # This is a hack to use the given Netlink socket instead
                # of the one allocated by nfq_open(). Intended use case:
                # the given socket was opened in a different network
                # namespace, and you want to monitor traffic in that
                # namespace from this process running outside of it.
                # Call socket(AF_NETLINK, SOCK_RAW, /*NETLINK_NETFILTER*/ 12)
                # in the other namespace and pass that fd here (via Unix
                # domain socket or similar).
                nlh = nfnl_open()
                if nlh == NULL:
                    raise OSError(errno, "Failed to open nfnetlink handle")

                # At this point nfnl_get_fd(nlh) is a new netlink socket
                # and has been bound to an automatically chosen port id.
                # This dup2 will close it, freeing up that address.
                if dup2(sockfd, nfnl_fd(nlh)) < 0:
                    raise OSError(errno, "dup2 failed")

                # Opening the netfilterqueue subsystem will rebind
                # the socket, using the same portid from the old socket,
                # which is hopefully now free. An alternative approach,
                # theoretically more robust against concurrent binds,
                # would be to autobind the new socket and write the chosen
                # address to nlh->local. nlh is an opaque type so this
                # would need to be done using memcpy (local starts
                # 4 bytes into the structure); let's avoid that unless
                # we really need it.
                self.h = nfq_open_nfnl(nlh)
            else:
                self.h = nfq_open()
            if self.h == NULL:
                raise OSError(errno, "Failed to open NFQueue.")
        except:
            if nlh != NULL:
                nfnl_close(nlh)
            raise

        nfq_unbind_pf(self.h, af) # This does NOT kick out previous queues
        if nfq_bind_pf(self.h, af) < 0:
            raise OSError("Failed to bind family %s. Are you root?" % af)

    def __del__(self):
        # unbind() can result in invocations of global_callback, so we
        # must do it in __del__ (when this is still a valid
        # NetfilterQueue object) rather than __dealloc__
        self.unbind()

    def __dealloc__(self):
        # Don't call nfq_unbind_pf unless you want to disconnect any other
        # processes using this libnetfilter_queue on this protocol family!
        if self.h != NULL:
            nfq_close(self.h)

    def bind(self, int queue_num, object user_callback,
                u_int32_t max_len=DEFAULT_MAX_QUEUELEN,
                u_int8_t mode=NFQNL_COPY_PACKET,
                u_int32_t range=MaxPacketSize,
                u_int32_t sock_len=SockRcvSize):
        """Create and bind to a new queue."""
        if self.qh != NULL:
            raise RuntimeError("A queue is already bound; use unbind() first")

        cdef unsigned int newsiz
        self.user_callback = user_callback
        self.qh = nfq_create_queue(self.h, queue_num,
                                   <nfq_callback*>global_callback, <void*>self)
        if self.qh == NULL:
            raise OSError("Failed to create queue %s." % queue_num)

        if range > MaxCopySize:
            range = MaxCopySize
        if nfq_set_mode(self.qh, mode, range) < 0:
            self.unbind()
            raise OSError("Failed to set packet copy mode.")

        nfq_set_queue_maxlen(self.qh, max_len)

        newsiz = nfnl_rcvbufsiz(nfq_nfnlh(self.h), sock_len)
        if newsiz != sock_len * 2:
            try:
                import warnings

                warnings.warn(
                    "Socket rcvbuf limit is now %d, requested %d." % (newsiz, sock_len),
                    category=RuntimeWarning,
                )
            except:  # if warnings are being treated as errors
                self.unbind()
                raise

    def unbind(self):
        """Destroy the queue."""
        self.user_callback = None
        if self.qh != NULL:
            nfq_destroy_queue(self.qh)
        self.qh = NULL
        # See warning about nfq_unbind_pf in __dealloc__ above.

    def get_fd(self):
        """Get the file descriptor of the queue handler."""
        return nfq_fd(self.h)

    def run(self, block=True):
        """Accept packets using recv."""
        cdef int fd = self.get_fd()
        cdef char buf[BufferSize]
        cdef int rv
        cdef int recv_flags
        recv_flags = 0 if block else MSG_DONTWAIT

        while True:
            with nogil:
                rv = recv(fd, buf, sizeof(buf), recv_flags)
            if rv < 0:
                if errno == EAGAIN:
                    break
                if errno == ENOBUFS:
                    # Kernel is letting us know we dropped a packet
                    continue
                if errno == EINTR:
                    PyErr_CheckSignals()
                    continue
                raise OSError(errno, "recv failed")
            nfq_handle_packet(self.h, buf, rv)

    def run_socket(self, s):
        """Accept packets using socket.recv so that, for example, gevent can monkeypatch it."""
        import socket

        while True:
            try:
                buf = s.recv(BufferSize)
            except socket.error as e:
                err = e.args[0]
                if err == ENOBUFS:
                    continue
                elif err == EAGAIN or err == EWOULDBLOCK:
                    # This should only happen with a non-blocking socket, and the
                    # app should call run_socket again when more data is available.
                    break
                else:
                    # This is bad. Let the caller handle it.
                    raise e
            else:
                nfq_handle_packet(self.h, buf, len(buf))

cdef void _fix_names():
    # Avoid ._impl showing up in reprs. This doesn't work on PyPy; there we would
    # need to modify the name before PyType_Ready(), but I can't find any way to
    # write Cython code that would execute at that time.
    cdef PyTypeObject* tp = <PyTypeObject*>Packet
    tp.tp_name = "netfilterqueue.Packet"
    tp = <PyTypeObject*>NetfilterQueue
    tp.tp_name = "netfilterqueue.NetfilterQueue"

_fix_names()

PROTOCOLS = {
    0: "HOPOPT",
    1: "ICMP",
    2: "IGMP",
    3: "GGP",
    4: "IP",
    5: "ST",
    6: "TCP",
    7: "CBT",
    8: "EGP",
    9: "IGP",
    10: "BBN-RCC-MON",
    11: "NVP-II",
    12: "PUP",
    13: "ARGUS",
    14: "EMCON",
    15: "XNET",
    16: "CHAOS",
    17: "UDP",
    18: "MUX",
    19: "DCN-MEAS",
    20: "HMP",
    21: "PRM",
    22: "XNS-IDP",
    23: "TRUNK-1",
    24: "TRUNK-2",
    25: "LEAF-1",
    26: "LEAF-2",
    27: "RDP",
    28: "IRTP",
    29: "ISO-TP4",
    30: "NETBLT",
    31: "MFE-NSP",
    32: "MERIT-INP",
    33: "DCCP",
    34: "3PC",
    35: "IDPR",
    36: "XTP",
    37: "DDP",
    38: "IDPR-CMTP",
    39: "TP++",
    40: "IL",
    41: "IPv6",
    42: "SDRP",
    43: "IPv6-Route",
    44: "IPv6-Frag",
    45: "IDRP",
    46: "RSVP",
    47: "GRE",
    48: "DSR",
    49: "BNA",
    50: "ESP",
    51: "AH",
    52: "I-NLSP",
    53: "SWIPE",
    54: "NARP",
    55: "MOBILE",
    56: "TLSP",
    57: "SKIP",
    58: "IPv6-ICMP",
    59: "IPv6-NoNxt",
    60: "IPv6-Opts",
    61: "any host internal protocol",
    62: "CFTP",
    63: "any local network",
    64: "SAT-EXPAK",
    65: "KRYPTOLAN",
    66: "RVD",
    67: "IPPC",
    68: "any distributed file system",
    69: "SAT-MON",
    70: "VISA",
    71: "IPCV",
    72: "CPNX",
    73: "CPHB",
    74: "WSN",
    75: "PVP",
    76: "BR-SAT-MON",
    77: "SUN-ND",
    78: "WB-MON",
    79: "WB-EXPAK",
    80: "ISO-IP",
    81: "VMTP",
    82: "SECURE-VMTP",
    83: "VINES",
    84: "TTP",
    85: "NSFNET-IGP",
    86: "DGP",
    87: "TCF",
    88: "EIGRP",
    89: "OSPFIGP",
    90: "Sprite-RPC",
    91: "LARP",
    92: "MTP",
    93: "AX.25",
    94: "IPIP",
    95: "MICP",
    96: "SCC-SP",
    97: "ETHERIP",
    98: "ENCAP",
    99: "any private encryption scheme",
    100: "GMTP",
    101: "IFMP",
    102: "PNNI",
    103: "PIM",
    104: "ARIS",
    105: "SCPS",
    106: "QNX",
    107: "A/N",
    108: "IPComp",
    109: "SNP",
    110: "Compaq-Peer",
    111: "IPX-in-IP",
    112: "VRRP",
    113: "PGM",
    114: "any 0-hop protocol",
    115: "L2TP",
    116: "DDX",
    117: "IATP",
    118: "STP",
    119: "SRP",
    120: "UTI",
    121: "SMP",
    122: "SM",
    123: "PTP",
    124: "ISIS",
    125: "FIRE",
    126: "CRTP",
    127: "CRUDP",
    128: "SSCOPMCE",
    129: "IPLT",
    130: "SPS",
    131: "PIPE",
    132: "SCTP",
    133: "FC",
    134: "RSVP-E2E-IGNORE",
    135: "Mobility",
    136: "UDPLite",
    137: "MPLS-in-IP",
    138: "manet",
    139: "HIP",
    140: "Shim6",
    255: "Reserved",
}
