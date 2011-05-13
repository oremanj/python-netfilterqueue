==============
NetfilterQueue
==============

NetfilterQueue provides access to packets matched by an iptables rule in
Linux. Packets so matched can be accepted, dropped, altered, or given a mark.

Libnetfilter_queue (the netfilter library, not this module) is part of the `Netfilter project <http://netfilter.org/projects/libnetfilter_queue/>`_.

Example
=======

The following script prints a short description of each packet before accepting it::

    from netfilterqueue import NetfilterQueue
    
    class PacketPrinter(NetfilterQueue):
        def handle(self, packet):
            print packet
            packet.accept()
    
    p = PacketPrinter()
    p.bind(1)
    p.run()

To send packets destined for your LAN to the script, type something like::

    iptables -I INPUT -d 192.168.0.0/24 -j NFQUEUE --queue-num 1

Installation
============

NetfilterQueue is a C extention module that links against libnetfilter_queue. Before installing, ensure you have:

1. A C compiler

2. Python development files

3. Libnetfilter_queue development files and associated dependencies

On Debian or Ubuntu, these files are install with::

    sudo apt-get install build-essential python-dev libnetfilter-queue-dev

From PyPI
---------

To install from PyPI by pip::

    pip install NetfilterQueue

From source
-----------

To install from source::

    wget http://pypi.python.org/packages/source/N/NetfilterQueue/NetfilterQueue-0.1.tar.gz
    tar -xvzf NetfilterQueue-0.1.tar.gz
    cd NetfilterQueue-0.1
    python setup.py install

Setup will use Cython if it is installed, regenerating the .c source from the .pyx before compiling the .so.

API
===

Coming soon...

Usage
=====

To route packets to the queue::

    iptables -I <table or chain> <match specification> -j NFQUEUE --queue-num <queue number>
    
For example::

    iptables -I INPUT -d 192.168.0.0/24 -j NFQUEUE --queue-num 1
    
The only special part of the rule is the target. Rules can have any match and 
can be added to any table or chain.

Valid queue numbers are integers from 0 to 65,536 inclusive.

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

9. Libnetfilter_queue internal use


Limitations
===========

TODO: fix this up

* compiled to max 2048-byte packets, so won't work on LO?
* full API not implemented: omits set_payload(), interface methods, and what else?