.. image:: https://img.shields.io/pypi/v/netfilterqueue.svg
   :target: https://pypi.org/project/netfilterqueue
   :alt: Latest PyPI version

.. image:: https://github.com/oremanj/python-netfilterqueue/actions/workflows/ci.yml/badge.svg?branch=master
   :target: https://github.com/oremanj/python-netfilterqueue/actions?query=branch%3Amaster
   :alt: Automated test status

==============
NetfilterQueue
==============

NetfilterQueue provides access to packets matched by an iptables rule in
Linux. Packets so matched can be accepted, dropped, altered, reordered,
or given a mark.

libnetfilter_queue (the netfilter library, not this module) is part of the
`Netfilter project <http://netfilter.org/projects/libnetfilter_queue/>`_.

The current version of NetfilterQueue requires Python 3.6 or later.
The last version with support for Python 2.7 was 0.9.0.

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

    pip install cython
    git clone https://github.com/oremanj/python-netfilterqueue
    cd python-netfilterqueue
    pip install .

API
===

``NetfilterQueue.COPY_NONE``, ``NetfilterQueue.COPY_META``, ``NetfilterQueue.COPY_PACKET``
    These constants specify how much of the packet should be given to the
    script: nothing, metadata, or the whole packet.

NetfilterQueue objects
----------------------

A NetfilterQueue object represents a single queue. Configure your queue with
a call to ``bind``, then start receiving packets with a call to ``run``.

``NetfilterQueue.bind(queue_num, callback, max_len=1024, mode=COPY_PACKET, range=65535, sock_len=...)``
    Create and bind to the queue. ``queue_num`` uniquely identifies this
    queue for the kernel. It must match the ``--queue-num`` in your iptables
    rule, but there is no ordering requirement: it's fine to either ``bind()``
    first or set up the iptables rule first.
    ``callback`` is a function or method that takes one
    argument, a Packet object (see below). ``max_len`` sets the largest number
    of packets that can be in the queue; new packets are dropped if the size of
    the queue reaches this number. ``mode`` determines how much of the packet
    data is provided to your script. Use the constants above. ``range`` defines
    how many bytes of the packet you want to get. For example, if you only want
    the source and destination IPs of a IPv4 packet, ``range`` could be 20.
    ``sock_len`` sets the receive socket buffer size.

``NetfilterQueue.unbind()``
    Remove the queue. Packets matched by your iptables rule will be dropped.

``NetfilterQueue.get_fd()``
    Get the file descriptor of the socket used to receive queued
    packets and send verdicts. If you're using an async event loop,
    you can poll this FD for readability and call ``run(False)`` every
    time data appears on it.

``NetfilterQueue.run(block=True)``
    Send packets to your callback. By default, this method blocks, running
    until an exception is raised (such as by Ctrl+C). Set
    ``block=False`` to process the pending messages without waiting for more;
    in conjunction with the ``get_fd`` method, you can use this to integrate
    with async event loops.

``NetfilterQueue.run_socket(socket)``
    Send packets to your callback, but use the supplied socket instead of
    recv, so that, for example, gevent can monkeypatch it. You can make a
    socket with ``socket.fromfd(nfqueue.get_fd(), socket.AF_NETLINK, socket.SOCK_RAW)``
    and optionally make it non-blocking with ``socket.setblocking(False)``.

Packet objects
--------------

Objects of this type are passed to your callback.

``Packet.get_payload()``
    Return the packet's payload as a bytes object. The returned value
    starts with the IP header. You must call ``retain()`` if you want
    to be able to ``get_payload()`` after your callback has returned.
    If you have already called ``set_payload()``, then ``get_payload()``
    returns what you passed to ``set_payload()``.

``Packet.set_payload(payload)``
    Set the packet payload. Call this before ``accept()`` if you want to
    change the contents of the packet before allowing it to be released.
    Don't forget to update the transport-layer checksum (or clear it,
    if you're using UDP), or else the recipient is likely to drop the
    packet. If you're changing the length of the packet, you'll also need
    to update the IP length, IP header checksum, and probably some
    transport-level fields (such as UDP length for UDP).

``Packet.get_payload_len()``
    Return the size of the payload.

``Packet.set_mark(mark)``
    Give the packet a kernel mark, which can be used in future iptables
    rules. ``mark`` is a 32-bit number.

``Packet.get_mark()``
    Get the mark on the packet (either the one you set using
    ``set_mark()``, or the one it arrived with if you haven't called
    ``set_mark()``).

``Packet.get_hw()``
    Return the source hardware address of the packet as a Python
    bytestring, or ``None`` if the source hardware address was not
    captured (packets captured by the ``OUTPUT`` or ``PREROUTING``
    hooks). For example, on Ethernet the result will be a six-byte
    MAC address. The destination hardware address is not available
    because it is determined in the kernel only after packet filtering
    is complete.

``Packet.get_timestamp()``
    Return the time at which this packet was received by the kernel,
    as a floating-point Unix timestamp with microsecond precision
    (comparable to the result of ``time.time()``, for example).
    Packets captured by the ``OUTPUT`` or ``POSTROUTING`` hooks
    do not have a timestamp, and ``get_timestamp()`` will return 0.0
    for them.

``Packet.id``
    The identifier assigned to this packet by the kernel. Typically
    the first packet received by your queue starts at 1 and later ones
    count up from there.

``Packet.hw_protocol``
    The link-layer protocol for this packet. For example, IPv4 packets
    on Ethernet would have this set to the EtherType for IPv4, which is
    ``0x0800``.

``Packet.mark``
    The mark that had been assigned to this packet when it was enqueued.
    Unlike the result of ``get_mark()``, this does not change if you call
    ``set_mark()``.

``Packet.hook``
    The netfilter hook (iptables chain, roughly) that diverted this packet
    into our queue. Values 0 through 4 correspond to PREROUTING, INPUT,
    FORWARD, OUTPUT, and POSTROUTING respectively.

``Packet.retain()``
    Allocate a copy of the packet payload for use after the callback
    has returned. ``get_payload()`` will raise an exception at that
    point if you didn't call ``retain()``.

``Packet.accept()``
    Accept the packet. You can reorder packets by accepting them
    in a different order than the order in which they were passed
    to your callback.

``Packet.drop()``
    Drop the packet.

``Packet.repeat()``
    Restart processing of this packet from the beginning of its
    Netfilter hook (iptables chain, roughly). Any changes made
    using ``set_payload()`` or ``set_mark()`` are preserved; in the
    absence of such changes, the packet will probably come right
    back to the same queue.

Callback objects
----------------

Your callback can be any one-argument callable and will be invoked with
a ``Packet`` object as argument. You must call ``retain()`` within the
callback if you want to be able to ``get_payload()`` after the callback
has returned. You can hang onto ``Packet`` objects and resolve them later,
but note that packets continue to count against the queue size limit
until they've been given a verdict (accept, drop, or repeat). Also, the
kernel stores the enqueued packets in a linked list, so keeping lots of packets
outstanding is likely to adversely impact performance.

Monitoring a different network namespace
----------------------------------------

If you are using Linux network namespaces (``man 7
network_namespaces``) in some kind of containerization system, all of
the Netfilter queue state is kept per-namespace; queue 1 in namespace
X is not the same as queue 1 in namespace Y. NetfilterQueue will
ordinarily pass you the traffic for the network namespace you're a
part of. If you want to monitor a different one, you can do so with a
bit of trickery and cooperation from a process in that
namespace; this section describes how.

You'll need to arrange for a process in the network namespace you want
to monitor to call ``socket(AF_NETLINK, SOCK_RAW, 12)`` and pass you
the resulting file descriptor using something like
``socket.send_fds()`` over a Unix domain socket. (12 is
``NETLINK_NETFILTER``, a constant which is not exposed by the Python
``socket`` module.)  Once you've received that file descriptor in your
process, you can create a NetfilterQueue object using the special
constructor ``NetfilterQueue(sockfd=N)`` where N is the file
descriptor you received. Because the socket was originally created
in the other network namespace, the kernel treats it as part of that
namespace, and you can use it to access that namespace even though it's
not the namespace you're in yourself.

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

* We use a fixed-size 4096-byte buffer for packets, so you are likely
  to see truncation on loopback and on Ethernet with jumbo packets.
  If this is a problem, either lower the MTU on your loopback, disable
  jumbo packets, or get Cython, change ``DEF BufferSize = 4096`` in
  ``netfilterqueue.pyx``, and rebuild.

* Not all information available from libnetfilter_queue is exposed:
  missing pieces include packet input/output network interface names,
  checksum offload flags, UID/GID and security context data
  associated with the packet (if any).

* Not all information available from the kernel is even processed by
  libnetfilter_queue: missing pieces include additional link-layer
  header data for some packets (including VLAN tags), connection-tracking
  state, and incoming packet length (if truncated for queueing).

* We do not expose the libnetfilter_queue interface for changing queue flags.
  Most of these pertain to other features we don't support (listed above),
  but there's one that could set the queue to accept (rather than dropping)
  packets received when it's full.

Source
======

https://github.com/oremanj/python-netfilterqueue

Authorship
==========

python-netfilterqueue was originally written by Matthew Fox of
Kerkhoff Technologies, Inc. Since 2022 it has been maintained by
Joshua Oreman of Hudson River Trading LLC. Both authors wish to
thank their employers for their support of open source.

License
=======

Copyright (c) 2011, Kerkhoff Technologies, Inc, and contributors.

`MIT licensed <https://github.com/kti/python-netfilterqueue/blob/master/LICENSE.txt>`_

