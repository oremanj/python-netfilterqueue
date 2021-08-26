#!/usr/bin/env python3

import socket

from libc.stdio cimport printf

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

cdef object user_callback
def set_user_callback(ref):
    '''Set required reference which will be called after packet data is parsed into C structs.'''
    global user_callback

    user_callback = ref

cdef int nf_callback(nfq_q_handle *qh, nfgenmsg *nfmsg, nfq_data *nfa, void *data) with gil:

    cdef u_int32_t mark

    packet = CPacket()
    with nogil:
        mark = packet.parse(qh, nfa)

    user_callback(packet, mark)

    return 1


cdef class CPacket:

    def __cinit__(self):
        self._verdict_is_set = False
        self._mark = 0

    # NOTE: this will be callback target for nfqueue
    cdef u_int32_t parse(self, nfq_q_handle *qh, nfq_data *nfa) nogil:

        self._qh = qh
        self._nfa = nfa

        self._hdr = nfq_get_msg_packet_hdr(nfa)
        self.id = ntohl(self._hdr.packet_id)
        # NOTE: these are not needed at this moment.
        # self.hw_protocol = ntohs(hdr.hw_protocol)
        # self.hook = hdr.hook

        self.data_len = nfq_get_payload(self._nfa, &self.data)
        # TODO: figure this out. cant use no gil if its here.
        # if self.payload_len < 0:
        #     raise OSError("Failed to get payload of packet.")

        # timestamp gets assigned via pointer/struct -> time_val: (t_sec, t_usec).
        nfq_get_timestamp(self._nfa, &self.timestamp)

        self._mark = nfq_get_nfmark(nfa)

        # splitting packet by tcp/ip layers
        self._parse()

        return self._mark

        # if (self.continue_condition):
        #     self._before_exit()

    cdef void _parse(self) nogil:

        self.ip_header = <iphdr*>self.data

        cdef u_int8_t hdr_shift = 4
        cdef u_int8_t hdr_multiplier = 4
        cdef u_int8_t hdr_xand = 15
        cdef u_int8_t iphdr_len

        iphdr_len = self.ip_header.ver_ihl & hdr_xand
        iphdr_len = iphdr_len * hdr_multiplier

        # NOTE: tshoot print
        printf('ip header length=%f\n', <double>iphdr_len)

        cdef u_int8_t tcphdr_len
        cdef u_int8_t udphdr_len  = 8
        cdef u_int8_t icmphdr_len = 4

        cdef void *data = &self.data[iphdr_len]
        cdef ptrdiff_t hdrptr = <u_int32_t*>data - <u_int32_t*>self.data

        if (self.ip_header.protocol == IPPROTO_TCP):

            self.tcp_header = <tcphdr*>&hdrptr

            tcphdr_len = self.tcp_header.th_off >> hdr_shift
            tcphdr_len = tcphdr_len & hdr_xand
            tcphdr_len = tcphdr_len * hdr_multiplier

            # NOTE: tshoot print
            printf('TCP HEADER LEN=%f\n', <double>tcphdr_len)

            self.cmbhdr_len = iphdr_len + tcphdr_len

        elif (self.ip_header.protocol == IPPROTO_UDP):

            self.udp_header = <udphdr*>&hdrptr

            self.cmbhdr_len = iphdr_len + udphdr_len

        elif (self.ip_header.protocol == IPPROTO_ICMP):

            self.icmp_header = <icmphdr*>&hdrptr

            self.cmbhdr_len = iphdr_len + icmphdr_len

    cdef void verdict(self, u_int32_t verdict):
        '''Call appropriate set_verdict function on packet.'''

        # TODO: figure out what to do about this. maybe just printf instead?
        if self._verdict_is_set:
            raise RuntimeWarning('Verdict already given for this packet.')

        if self._mark:
            nfq_set_verdict2(
                self._qh, self.id, verdict, self._mark, self.data_len, self.data
            )

        else:
            nfq_set_verdict(
                self._qh, self.id, verdict, self.data_len, self.data
            )

        self._verdict_is_set = True

    cdef double get_timestamp(self):

        return self.timestamp.tv_sec + (self.timestamp.tv_usec / 1000000.0)

    cdef u_int8_t get_inint(self, bint name=False):
        '''Returns index of inbound interface of packet. If the packet sourced from localhost or the input
        interface is not known, 0 will be returned.
        '''
        # if name=True, socket.if_indextoname() will be returned.
        # '''

        # cdef object in_interface_name

        cdef u_int8_t in_interface

        in_interface = nfq_get_indev(self._nfa)

        return in_interface

        # try:
        #     in_interface_name = socket.if_indextoname(in_interface)
        # except OSError:
        #     in_interface_name = 'unknown'

        # return in_interface_name

    # NOTE: keeping these funtions separate instead of making an argument option to adjust which interface to return.
    # this will keep it explicit for which interface is returning to minimize chance of confusion/bugs.
    cdef u_int8_t get_outint(self, bint name=False):
        '''Returns index of outbound interface of packet. If the packet is destined for localhost or the output
        interface is not yet known, 0 will be returned.
        '''
        # if name=True, socket.if_indextoname() will be returned.
        # '''

        # cdef object out_interface_name

        cdef u_int8_t out_interface

        out_interface = nfq_get_outdev(self._nfa)

        return out_interface

        # try:
        #     out_interface_name = socket.if_indextoname(out_interface)
        # except OSError:
        #     out_interface_name = 'unknown'

        # return out_interface_name

    cpdef update_mark(self, u_int32_t mark):
        '''Modifies the running mark of the packet.'''

        self._mark = mark

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

    def get_hw(self):
        '''Return hardware information of the packet.

            hw_info = (
                self.get_inint(), self.get_outint(), mac_addr, self.get_timestamp()
            )
        '''

        cdef object mac_addr
        cdef tuple hw_info

        self._hw = nfq_get_packet_hw(self._nfa)
        if self._hw == NULL:
            # nfq_get_packet_hw doesn't work on OUTPUT and PREROUTING chains
            # NOTE: making this a quick fail scenario since this would likely cause problems later in the packet
            # parsing process and forcing error handling will ensure it is dealt with [properly].
            raise OSError('MAC address not available in OUTPUT and PREROUTING chains')

        # NOTE: can this not just be directly referenced below?
        # self.hw_addr = self._hw.hw_addr

        mac_addr = PyBytes_FromStringAndSize(<char*>self._hw.hw_addr, 8)

        hw_info = (
            self.get_inint(),
            self.get_outint(),
            mac_addr,
            self.get_timestamp(),
        )

        return hw_info

    def get_raw_packet(self):
        '''Return layer 3-7 of packet data.'''

        return self.data[:self.data_len]

    def get_ip_header(self):
        '''Return layer3 of packet data as a tuple converted directly from C struct.'''

        cdef tuple ip_header

        ip_header = (
            self.ip_header.ver_ihl,
            self.ip_header.tos,
            ntohs(self.ip_header.tot_len),
            ntohs(self.ip_header.id),
            ntohs(self.ip_header.frag_off),
            self.ip_header.ttl,
            self.ip_header.protocol,
            ntohs(self.ip_header.check),
            ntohl(self.ip_header.saddr),
            ntohl(self.ip_header.daddr),
        )

        return ip_header

    def get_proto_header(self):
        '''Return layer4 of packet data as a tuple converted directly from C struct.'''

        cdef tuple proto_header

        if (self.ip_header.protocol == IPPROTO_TCP):

            proto_header = (
                ntohs(self.tcp_header.th_sport),
                ntohs(self.tcp_header.th_dport),
                ntohl(self.tcp_header.th_seq),
                ntohl(self.tcp_header.th_ack),

                self.tcp_header.th_off,

                self.tcp_header.th_flags,
                ntohs(self.tcp_header.th_win),
                ntohs(self.tcp_header.th_sum),
                ntohs(self.tcp_header.th_urp),
            )

        elif (self.ip_header.protocol == IPPROTO_UDP):

            proto_header = (
                ntohs(self.udp_header.uh_sport),
                ntohs(self.udp_header.uh_dport),
                ntohs(self.udp_header.uh_ulen),
                ntohs(self.udp_header.uh_sum),
            )

        elif (self.ip_header.protocol == IPPROTO_ICMP):

            proto_header = (
                self.icmp_header.type,
            )

        else:
            proto_header = ()

        return proto_header

    def get_payload(self):
        '''Return payload (>layer4) as Python bytes.'''

        cdef object payload

        payload = self.data[<Py_ssize_t>self.cmbhdr_len:self.data_len]

        return payload


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

    def bind(self, int queue_num, u_int16_t max_len=DEFAULT_MAX_QUEUELEN,
            u_int8_t mode=NFQNL_COPY_PACKET, u_int16_t range=MaxPacketSize, u_int32_t sock_len=SockRcvSize):
        '''Create and bind to a new queue.'''

        cdef unsigned int newsiz

        self.qh = nfq_create_queue(self.h, queue_num, <nfq_callback*>nf_callback, <void*>self)
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

            if (rv >= 0):
                nfq_handle_packet(self.h, buf, rv)

            else:
                if errno != ENOBUFS:
                    break
