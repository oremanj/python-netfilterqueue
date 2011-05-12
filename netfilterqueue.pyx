## cython: profile=True
import socket

# Constants for module users
COPY_NONE = 1
COPY_META = 2
COPY_PACKET = 3

# Packet copying defaults
DEF MaxPacketSize = 0xFFFF
DEF BufferSize = 4096
DEF MetadataSize = 80
DEF MaxCopySize = BufferSize - MetadataSize

cdef int global_callback(nfq_q_handle *qh, nfgenmsg *nfmsg, 
                         nfq_data *nfa, void *data) with gil:
    """
    Create an NFPacket and pass it to appropriate Python/Cython callback.
    
    Working in a Python or Cython callback, rather than directly in this 
    callback, results in a ~7% performance hit.
    """
#    cdef nfqnl_msg_packet_hdr *_hdr = nfq_get_msg_packet_hdr(nfa)
#    cdef u_int32_t id = ntohl(_hdr.packet_id)
#    nfq_set_verdict(
#        qh,
#        id,
#        NF_ACCEPT,
#        0, # TODO: adapt to use self._given_payload
#        NULL # TODO: adapt to use self._given_payload
#    )
    packet = NFPacket()
    packet.set_nfq_data(qh, nfa)
    (<NFQueue>data).handle(packet)
    return 1

cdef class NFPacket:
    """A packet received from NFQueue."""
    def __cinit__(self):
        self._verdict_is_set = False
        self._mark_is_set = False
        self._given_payload = NULL
    
    def __str__(self):
        cdef iphdr *hdr = <iphdr*>self.payload
        protocol = "Unknown protocol"
        for name in filter(lambda x: x.startswith("IPPROTO"), dir(socket)):
          if getattr(socket, name) == hdr.protocol:
            protocol = name[8:]
        return "%s packet, %s bytes" % (protocol, self.payload_len)
    
    cdef set_nfq_data(self, nfq_q_handle *qh, nfq_data *nfa):
        """
        Assign a packet from NFQ to this object. Parse the header and load 
        local values.
        """
        self._qh = qh
        self._nfa = nfa
        self._hdr = nfq_get_msg_packet_hdr(nfa)
        
        self.id = ntohl(self._hdr.packet_id)
        self.hw_protocol = ntohs(self._hdr.hw_protocol)
        self.hook = self._hdr.hook
        
        self.payload_len = nfq_get_payload(self._nfa, &self.payload)
        if self.payload_len < 0:
            raise OSError("Failed to get payload of packet.")
        
        nfq_get_timestamp(self._nfa, &self.timestamp)

    cdef void verdict(self, u_int8_t verdict):
        """Call appropriate set_verdict... function on packet."""
        #if self._verdict_is_set:
        #    raise RuntimeWarning("Verdict already given for this packet.")

        if self._mark_is_set:
            nfq_set_verdict_mark( # TODO: make this use nfq_set_verdict2 if available on system
                self._qh,
                self.id,
                verdict,
                htonl(self._given_mark),
                0, # TODO: adapt to use self._given_payload
                NULL # TODO: adapt to use self._given_payload
            )
        else:
            nfq_set_verdict(
                self._qh,
                self.id,
                verdict,
                0, # TODO: adapt to use self._given_payload
                NULL # TODO: adapt to use self._given_payload
            )

        #self._verdict_is_set = True
    
    def get_payload(self):
        cdef object py_string = PyString_FromStringAndSize(self.payload, self.payload_len)
        return py_string
    
    cpdef Py_ssize_t get_payload_len(self):
        return self.payload_len
    
    cpdef double get_timestamp(self):
        return self.timestamp.tv_sec + (self.timestamp.tv_usec/1000000.0)
    
    # TODO: implement this
    #cpdef set_payload(self, unsigned char *payload):
    #    """Set the new payload of this packet."""
    #    self._given_payload = payload
        
    cpdef set_mark(self, u_int32_t mark):
        self._given_mark = mark
        self._mark_is_set = True
    
    cpdef accept(self):
        """Accept the packet."""
        self.verdict(NF_ACCEPT)
        
    cpdef drop(self):
        """Drop the packet."""
        self.verdict(NF_DROP)

cdef class NFQueue:
    """Handle a single numbered queue."""
    def __cinit__(self, *args, **kwargs):
        if "af" in kwargs:
            self.af = kwargs["af"]
        else:
            self.af = socket.AF_INET

        self.h = nfq_open()
        if self.h == NULL:
            raise OSError("Failed to open NFQueue.")
        nfq_unbind_pf(self.h, self.af) # This does NOT kick out previous 
            # running queues
        if nfq_bind_pf(self.h, self.af) < 0:
            raise OSError("Failed to bind family %s." % self.af)
    
    def __dealloc__(self):
        if self.qh != NULL:
            nfq_destroy_queue(self.qh)
        # Don't call nfq_unbind_pf unless you want to disconnect any other 
        # processes using this libnetfilter_queue on this protocol family!
        nfq_close(self.h)

    def bind(self, object handler, int queue_num, u_int32_t maxlen, u_int8_t mode=NFQNL_COPY_PACKET, u_int32_t range=MaxPacketSize):
        """Create a new queue with the given callback function."""
        self.qh = nfq_create_queue(self.h, queue_num, <nfq_callback*>global_callback, <void*>handler)
        if self.qh == NULL:
            raise OSError("Failed to create queue %s." % queue_num)
        
        if range > MaxCopySize:
            range = MaxCopySize
        if nfq_set_mode(self.qh, mode, range) < 0:
            raise OSError("Failed to set packet copy mode.")
        
        nfq_set_queue_maxlen(self.qh, maxlen)
    
    def unbind(self):
        """Destroy the queue."""
        if self.qh != NULL:
            nfq_destroy_queue(self.qh)
        # See warning about nfq_unbind_pf in __dealloc__ above.
        
    def run(self):
        """Begin accepting packets."""
        cdef int fd = nfq_fd(self.h)
        cdef char buf[BufferSize]
        cdef int rv
        with nogil:
            rv = recv(fd, buf, sizeof(buf), 0)
        while rv >= 0:
            nfq_handle_packet(self.h, buf, rv)
            with nogil:
                rv = recv(fd, buf, sizeof(buf), 0)

    def handle(self, NFPacket packet):
        """Handle a single packet. User-defined classes should override this."""
        packet.accept()
