#!/usr/bin/env python3

'''
Bind to a Linux netfilter queue. Send packets to a user-specified callback
function.

Copyright: (c) 2011, Kerkhoff Technologies Inc.
License: MIT; see SOURCE-LICENSE.txt
'''

'''
Expanded features + general refactor to be used with DNXFIREWALL.
 - DOWRIGHT @ Wright Network Solutions, LLC.
'''

import socket

# Constants for module users
cdef int COPY_NONE = 0
cdef int COPY_META = 1
cdef int COPY_PACKET = 2

cdef u_int16_t DEFAULT_MAX_QUEUELEN = 1024
cdef u_int16_t MaxPacketSize = 0xFFFF

# buffer size - metadata size
cdef u_int16_t MaxCopySize = 4096 - 80

# Socket queue should hold max number of packets of copy size bytes
# formula: DEF_MAX_QUEUELEN * (MaxCopySize+SockOverhead) / 2
cdef u_int32_t SockRcvSize = 1024 * 4796 // 2

cdef int global_callback(nfq_q_handle * qh, nfgenmsg * nfmsg, nfq_data * nfa, void * data) with gil:
    '''Create a Packet and pass it to appropriate callback.'''

    cdef NetfilterQueue nfqueue = < NetfilterQueue > data
    cdef object user_callback = < object > nfqueue.user_callback

    packet = Packet()
    packet.set_nfq_data(qh, nfa)

    user_callback(packet)

    return 1

cdef class Packet:
    '''A packet received from NetfilterQueue.'''

    def __cinit__(self):
        self._verdict_is_set = False
        self._mark = 0
        self._given_payload = None

    def __str__(self):
        cdef ip_header * hdr = < ip_header * > self.payload
        protocol = PROTOCOLS.get(hdr.protocol, "Unknown protocol")

        return "%s packet, %s bytes" % (protocol, self.payload_len)

    cdef set_nfq_data(self, nfq_q_handle * qh, nfq_data * nfa):
        '''Assign a packet from NFQ to this object. Parse the header and load local values.'''

        self._qh = qh
        self._nfa = nfa
        self._hdr = nfq_get_msg_packet_hdr(nfa)

        self.id = ntohl(self._hdr.packet_id)
        self.hw_protocol = ntohs(self._hdr.hw_protocol)
        self.hook = self._hdr.hook

        self.payload_len = nfq_get_payload(self._nfa, &self.payload)
        if self.payload_len < 0:
            raise OSError("Failed to get payload of packet.")

        self._payload

        # timestamp gets assigned via pointer/struct -> time_val: (t_sec, t_usec).
        nfq_get_timestamp(self._nfa, &self.timestamp)

        cdef u_int32_t mark = nfq_get_nfmark(nfa)

    cdef void verdict(self, u_int32_t verdict):
        '''Call appropriate set_verdict... function on packet.'''

        if self._verdict_is_set:
            raise RuntimeWarning("Verdict already given for this packet.")

        cdef u_int32_t modified_payload_len = 0
        cdef unsigned char * modified_payload = NULL

        # rewriting payload data/len
        if self._given_payload:
            modified_payload_len = len(self._given_payload)
            modified_payload = self._given_payload

        if self._modified_mark:
            nfq_set_verdict2(
                self._qh, self.id, verdict, self._modified_mark, modified_payload_len, modified_payload
            )

        else:
            nfq_set_verdict(
                self._qh, self.id, verdict, modified_payload_len, modified_payload
            )

        self._verdict_is_set = True

    cpdef get_inint(self, bint name=False):
        '''Returns index of inbound interface of packet. If the packet sourced from localhost or the input
        interface is not known, 0 will be returned.
        
        if name=True, socket.if_indextoname() will be returned.
        '''

        cdef object in_interface_name

        in_interface = nfq_get_indev(self._nfa)
        if not name:
            return in_interface

        try:
            in_interface_name = socket.if_indextoname(in_interface)
        except OSError:
            in_interface_name = 'unknown'

        return in_interface_name

    # NOTE: keeping these funtions separate instead of making an argument option to adjust which interface to return.
    # this will keep it explicit for which interface is returning to minimize chance of confusion/bugs.
    cpdef get_outint(self, bint name=False):
        '''Returns index of outbound interface of packet. If the packet is destined for localhost or the output
        interface is not yet known, 0 will be returned.
        
        if name=True, socket.if_indextoname() will be returned.
        '''

        cdef object out_interface_name

        out_interface = nfq_get_outdev(self._nfa)
        if not name:
            return out_interface

        try:
            out_interface_name = socket.if_indextoname(out_interface)
        except OSError:
            out_interface_name = 'unknown'

        return out_interface_name

    def get_mark(self):
        '''Return mark set at first receipt of packet.'''

        return self._mark

    cpdef update_mark(self, u_int32_t mark):
        '''Modifies the running mark of the packet. This will not override the initial mark received, but any
        subsequent update will override the previous.'''

        self._modified_mark = mark

    def get_hw(self):
        '''Return the source mac address of the packet.'''

        cdef object mac_addr

        self._hw = nfq_get_packet_hw(self._nfa)
        if self._hw == NULL:
            # nfq_get_packet_hw doesn't work on OUTPUT and PREROUTING chains
            # NOTE: making this a quick fail scenario since this would likely cause problems later in the packet
            # parsing process and forcing error handling will ensure it is dealt with [properly].
            raise OSError('MAC address not available in OUTPUT and PREROUTING chains')

        # NOTE: can this not just be directly referenced below?
        self.hw_addr = self._hw.hw_addr

        mac_addr = PyBytes_FromStringAndSize( < char * > self.hw_addr, 8)

        return mac_addr

    def get_payload(self):
        '''Return payload as Python string.'''

        cdef object payload

        payload = self.payload[:self.payload_len]

        return payload

    cpdef set_payload(self, bytes payload):
        '''Set the new payload of this packet.'''

        self._given_payload = payload

    cpdef Py_ssize_t get_payload_len(self):

        return self.payload_len

    cpdef double get_timestamp(self):

        return self.timestamp.tv_sec + (self.timestamp.tv_usec / 1000000.0)

    cpdef accept(self):
        '''Accept the packet.'''

        self.verdict(NF_ACCEPT)

    cpdef drop(self):
        '''Drop the packet.'''

        self.verdict(NF_DROP)

    cpdef forward(self, u_int16_t queue_num):
        '''Send the packet to a different queue.'''

        cdef u_int32_t forward_to_queue

        forward_to_queue = queue_num << 16 | NF_QUEUE

        self.verdict(forward_to_queue)

    cpdef repeat(self):
        '''Repeat the packet.'''

        self.verdict(NF_REPEAT)


cdef class NetfilterQueue:
    '''Handle a single numbered queue.'''

    def __cinit__(self, *args, **kwargs):
        self.af = kwargs.get('af', PF_INET)

        self.h = nfq_open()
        if self.h == NULL:
            raise OSError('Failed to open NFQueue.')

        # This does NOT kick out previous running queues
        nfq_unbind_pf(self.h, self.af)

        if nfq_bind_pf(self.h, self.af) < 0:
            raise OSError('Failed to bind family %s. Are you root?' % self.af)

    def __dealloc__(self):
        if self.qh != NULL:
            nfq_destroy_queue(self.qh)

        # Don't call nfq_unbind_pf unless you want to disconnect any other
        # processes using this libnetfilter_queue on this protocol family!
        nfq_close(self.h)

    def bind(self, int queue_num, object user_callback, u_int16_t max_len=DEFAULT_MAX_QUEUELEN,
            u_int8_t mode=NFQNL_COPY_PACKET, u_int16_t range=MaxPacketSize, u_int32_t sock_len=SockRcvSize):
        '''Create and bind to a new queue.'''

        cdef unsigned int newsiz

        self.user_callback = user_callback
        self.qh = nfq_create_queue(self.h, queue_num, < nfq_callback * > global_callback, < void * > self)
        if self.qh == NULL:
            raise OSError(f'Failed to create queue {queue_num}')

        if range > MaxCopySize:
            range = MaxCopySize

        if nfq_set_mode(self.qh, mode, range) < 0:
            raise OSError("Failed to set packet copy mode.")

        nfq_set_queue_maxlen(self.qh, max_len)

        newsiz = nfnl_rcvbufsiz(nfq_nfnlh(self.h), sock_len)
        if newsiz != sock_len * 2:
            raise RuntimeWarning("Socket rcvbuf limit is now %d, requested %d." % (newsiz, sock_len))

    def unbind(self):
        '''Destroy the queue.'''

        if self.qh != NULL:
            nfq_destroy_queue(self.qh)

        self.qh = NULL
        # See warning about nfq _unbind_pf in __dealloc__ above.

    def get_fd(self):
        '''Get the file descriptor of the queue handler.'''

        return nfq_fd(self.h)

    def run(self, bint block=True):
        '''Accept packets using recv.'''

        cdef int fd = self.get_fd()
        cdef char buf[4096]
        cdef int rv
        cdef int recv_flags

        recv_flags = 0

        while True:
            with nogil:
                rv = recv(fd, buf, sizeof(buf), recv_flags)

            print(rv)

            if (rv >= 0):
                nfq_handle_packet(self.h, buf, rv)

            else:
                if errno != ENOBUFS:
                    break

    def run_socket(self, s):
        '''Accept packets using socket.recv so that, for example, gevent can monkeypatch it.'''

        while True:
            try:
                buf = s.recv(4096)
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
                rv = len(buf)
                if rv >= 0:
                    nfq_handle_packet(self.h, buf, rv)
                else:
                    break

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
