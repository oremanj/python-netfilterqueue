==============
NetfilterQueue
==============

NetfilterQueue provides access to packets matched by an iptables rule in
Linux. Packets so matched can be accepted, dropped, altered, or given a mark.

Libnetfilter_queue (the netfilter library, not this module) is part of the `Netfilter project <http://netfilter.org/projects/libnetfilter_queue/>`_.

Example
=======

Coming soon...

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

Usage
=====

Coming soon...

Now route packets to the queue::

    # iptables -I INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 1
    
The only special part of the rule is the target. Rules can have any match and 
can be added to any table or chain.

Valid queue numbers are integers from 0 to 65,536 inclusive.

Limitations
===========

TODO: fix this up

* compiled to max 2048-byte packets, so won't work on LO?
* full API not implemented: omits set_payload(), interface methods, and what else?