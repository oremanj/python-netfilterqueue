==============
NetfilterQueue
==============

NetfilterQueue provides access to packets matched by an iptables rule in
Linux. Packets so matched can be accepted, dropped, altered, or given a mark.

Libnetfilter_queue (the netfilter library, not this module) is part of the
`Netfilter project <http://netfilter.org/projects/libnetfilter_queue/>`_.

Example
=======

The following script prints a short description of each packet before accepting
it. ::

    from netfilterqueue import NetfilterQueue
    
    def print_and_accept(pkt):
        print(pkt)
        pkt.accept()
    
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, print_and_accept)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print('')
    
    nfqueue.unbind()

You can also make your own socket so that it can be used with gevent, for example. ::

    from netfilterqueue import NetfilterQueue
    import socket

    def print_and_accept(pkt):
        print(pkt)
        pkt.accept()

    nfqueue = NetfilterQueue()
    nfqueue.bind(1, print_and_accept)
    s = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        nfqueue.run_socket(s)
    except KeyboardInterrupt:
        print('')

    s.close()
    nfqueue.unbind()

To send packets destined for your LAN to the script, type something like::

    iptables -I INPUT -d 192.168.0.0/24 -j NFQUEUE --queue-num 1

Installation
============

NetfilterQueue is a C extention module that links against libnetfilter_queue. 
Before installing, ensure you have:

1. A C compiler

2. Python development files

3. Libnetfilter_queue development files and associated dependencies

On Debian or Ubuntu, install these files with::

    apt-get install build-essential python-dev libnetfilter-queue-dev

From PyPI
---------

To install from PyPI by pip::

    pip install NetfilterQueue

From source
-----------

To install from source::

    git clone git@github.com:kti/python-netfilterqueue.git
    cd python-netfilterqueue
    python setup.py install

If Cython is installed, Distutils will use it to regenerate the .c source from the .pyx. It will then compile the .c into a .so.

API
===

``NetfilterQueue.COPY_NONE``

``NetfilterQueue.COPY_META``

``NetfilterQueue.COPY_PACKET``
    These constants specify how much of the packet should be given to the
    script- nothing, metadata, or the whole packet.

NetfilterQueue objects
----------------------

A NetfilterQueue object represents a single queue. Configure your queue with
a call to ``bind``, then start receiving packets with a call to ``run``.

``QueueHandler.bind(queue_num, callback[, max_len[, mode[, range, [sock_len]]]])``
    Create and bind to the queue. ``queue_num`` must match the number in your
    iptables rule. ``callback`` is a function or method that takes one
    argument, a Packet object (see below). ``max_len`` sets the largest number
    of packets that can be in the queue; new packets are dropped if the size of
    the queue reaches this number. ``mode`` determines how much of the packet
    data is provided to your script. Use the constants above. ``range`` defines
    how many bytes of the packet you want to get. For example, if you only want
    the source and destination IPs of a IPv4 packet, ``range`` could be 20.
    ``sock_len`` sets the receive socket buffer size.

``QueueHandler.unbind()``
    Remove the queue. Packets matched by your iptables rule will be dropped.

``QueueHandler.get_fd()``
    Get the file descriptor of the queue handler.

``QueueHandler.run([block])``
    Send packets to your callback. By default, this method blocks. Set
    block=False to let your thread continue. You can get the file descriptor
    of the socket with the ``get_fd`` method.

``QueueHandler.run_socket(socket)``
    Send packets to your callback, but use the supplied socket instead of
    recv, so that, for example, gevent can monkeypatch it. You can make a
    socket with ``socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)``
    and optionally make it non-blocking with ``socket.setblocking(False)``.

Packet objects
--------------

Objects of this type are passed to your callback.

``Packet.get_payload()``
    Return the packet's payload as a string (Python 2) or bytes (Python 3).

``Packet.set_payload(payload)``
    Set the packet payload. ``payload`` is a bytes.

``Packet.get_payload_len()``
    Return the size of the payload.

``Packet.set_mark(mark)``
    Give the packet a kernel mark. ``mark`` is a 32-bit number.

``Packet.get_mark()``
    Get the mark already on the packet.

``Packet.get_hw()``
    Return the hardware address as a Python string.

``Packet.accept()``
    Accept the packet.

``Packet.drop()``
    Drop the packet.
   
``Packet.repeat()``
    Iterate the same cycle once more.
 
Callback objects
----------------

Your callback can be function or a method and must accept one argument, a
Packet object. You must call either Packet.accept() or Packet.drop() before
returning.

``callback(packet)`` or ``callback(self, packet)``
    Handle a single packet from the queue. You must call either
    ``packet.accept()`` or ``packet.drop()``.

Usage
=====

To send packets to the queue::

    iptables -I <table or chain> <match specification> -j NFQUEUE --queue-num <queue number>
    
For example::

    iptables -I INPUT -d 192.168.0.0/24 -j NFQUEUE --queue-num 1
    
The only special part of the rule is the target. Rules can have any match and 
can be added to any table or chain.

Valid queue numbers are integers from 0 to 65,535 inclusive.

To view libnetfilter_queue stats, refer to /proc/net/netfilter/nfnetlink_queue::

    cat /proc/net/netfilter/nfnetlink_queue
    1  31621     0 2  4016     0     0        2  1

The fields are:

1. Queue ID

2. Bound process ID

3. Number of currently queued packets

4. Copy mode

5. Copy size

6. Number of packets dropped due to reaching max queue size

7. Number of packets dropped due to netlink socket failure

8. Total number of packets sent to queue

9. Something for libnetfilter_queue's internal use

Limitations
===========

* Compiled with a 4096-byte buffer for packets, so it probably won't work on
  loopback or Ethernet with jumbo packets. If this is a problem, either lower
  MTU on your loopback, disable jumbo packets, or get Cython,
  change ``DEF BufferSize = 4096`` in ``netfilterqueue.pyx``, and rebuild.
* Full libnetfilter_queue API is not yet implemented:

    * Omits methods for getting information about the interface a packet has
      arrived on or is leaving on
    * Probably other stuff is omitted too
    
Source
======

https://github.com/kti/python-netfilterqueue

License
=======

Copyright (c) 2011, Kerkhoff Technologies, Inc.

`MIT licensed <https://github.com/kti/python-netfilterqueue/blob/master/LICENSE.txt>`_

