import gc
import struct
import os
import pytest
import signal
import socket
import sys
import time
import trio
import trio.testing
import weakref

from netfilterqueue import NetfilterQueue, COPY_META


async def test_comms_without_queue(harness):
    await harness.send(2, b"hello", b"world")
    await harness.expect(2, b"hello", b"world")
    await harness.send(1, b"it works?")
    await harness.expect(1, b"it works?")


async def test_queue_dropping(harness):
    async def drop(packets, msg):
        async for packet in packets:
            if packet.get_payload()[28:] == msg:
                packet.drop()
            else:
                packet.accept()

    async with trio.open_nursery() as nursery:
        async with harness.capture_packets_to(2) as p2, harness.capture_packets_to(
            1
        ) as p1:
            nursery.start_soon(drop, p2, b"two")
            nursery.start_soon(drop, p1, b"one")

            await harness.send(2, b"one", b"two", b"three")
            await harness.send(1, b"one", b"two", b"three")
            await harness.expect(2, b"one", b"three")
            await harness.expect(1, b"two", b"three")

        # Once we stop capturing, everything gets through again:
        await harness.send(2, b"one", b"two", b"three")
        await harness.send(1, b"one", b"two", b"three")
        await harness.expect(2, b"one", b"two", b"three")
        await harness.expect(1, b"one", b"two", b"three")


async def test_rewrite_reorder(harness):
    async def munge(packets):
        def set_udp_payload(p, msg):
            data = bytearray(p.get_payload())
            old_len = len(data) - 28
            if len(msg) != old_len:
                data[2:4] = struct.pack(">H", len(msg) + 28)
                data[24:26] = struct.pack(">H", len(msg) + 8)
                # Recompute checksum too
                data[10:12] = b"\x00\x00"
                words = struct.unpack(">10H", data[:20])
                cksum = sum(words)
                while cksum >> 16:
                    cksum = (cksum & 0xFFFF) + (cksum >> 16)
                data[10:12] = struct.pack(">H", cksum ^ 0xFFFF)
            # Clear UDP checksum and set payload
            data[28:] = msg
            data[26:28] = b"\x00\x00"
            p.set_payload(bytes(data))

        async for packet in packets:
            payload = packet.get_payload()[28:]
            if payload == b"one":
                set_udp_payload(packet, b"numero uno")
                assert b"numero uno" == packet.get_payload()[28:]
                packet.accept()
            elif payload == b"two":
                two = packet
            elif payload == b"three":
                set_udp_payload(two, b"TWO")
                packet.accept()
                two.accept()
            else:
                packet.accept()

    async with trio.open_nursery() as nursery:
        async with harness.capture_packets_to(2) as p2:
            nursery.start_soon(munge, p2)
            await harness.send(2, b"one", b"two", b"three", b"four")
            await harness.expect(2, b"numero uno", b"three", b"TWO", b"four")


async def test_mark_repeat(harness):
    counter = 0
    timestamps = []

    def cb(chan, pkt):
        nonlocal counter
        with pytest.raises(RuntimeError, match="Packet has no payload"):
            pkt.get_payload()
        assert pkt.get_mark() == counter
        timestamps.append(pkt.get_timestamp())
        if counter < 5:
            counter += 1
            pkt.set_mark(counter)
            pkt.repeat()
            assert pkt.get_mark() == counter
        else:
            pkt.accept()

    async with harness.capture_packets_to(2, cb, mode=COPY_META):
        t0 = time.time()
        await harness.send(2, b"testing")
        await harness.expect(2, b"testing")
        t1 = time.time()
    assert counter == 5
    # All iterations of the packet have the same timestamps
    assert all(t == timestamps[0] for t in timestamps[1:])
    assert t0 < timestamps[0] < t1


async def test_hwaddr(harness):
    hwaddrs = []

    def cb(pkt):
        hwaddrs.append((pkt.get_hw(), pkt.hook, pkt.get_payload()[28:]))
        pkt.accept()

    queue_num, nfq = harness.bind_queue(cb)
    try:
        async with trio.open_nursery() as nursery:

            @nursery.start_soon
            async def listen_for_packets():
                while True:
                    await trio.lowlevel.wait_readable(nfq.get_fd())
                    nfq.run(block=False)

            async with harness.enqueue_packets_to(2, queue_num, forwarded=True):
                await harness.send(2, b"one", b"two")
                await harness.expect(2, b"one", b"two")
            async with harness.enqueue_packets_to(2, queue_num, forwarded=False):
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    for payload in (b"three", b"four"):
                        sock.sendto(payload, harness.dest_addr[2])
                with trio.fail_after(1):
                    while len(hwaddrs) < 4:
                        await trio.sleep(0.1)
            nursery.cancel_scope.cancel()
    finally:
        nfq.unbind()

    # Forwarded packets capture a hwaddr, but OUTPUT don't
    FORWARD = 2
    OUTPUT = 3
    mac1 = hwaddrs[0][0]
    assert mac1 is not None
    assert hwaddrs == [
        (mac1, FORWARD, b"one"),
        (mac1, FORWARD, b"two"),
        (None, OUTPUT, b"three"),
        (None, OUTPUT, b"four"),
    ]


async def test_errors(harness):
    with pytest.warns(RuntimeWarning, match="rcvbuf limit is") as record:
        async with harness.capture_packets_to(2, sock_len=2 ** 30):
            pass
    assert record[0].filename.endswith("conftest.py")

    async with harness.capture_packets_to(2, queue_num=0):
        with pytest.raises(OSError, match="Failed to create queue"):
            async with harness.capture_packets_to(2, queue_num=0):
                pass

    _, nfq = harness.bind_queue(lambda: None, queue_num=1)
    with pytest.raises(RuntimeError, match="A queue is already bound"):
        nfq.bind(2, lambda p: None)

    # Test unbinding via __del__
    nfq = weakref.ref(nfq)
    for _ in range(4):
        gc.collect()
        if nfq() is None:
            break
    else:
        raise RuntimeError("Couldn't trigger garbage collection of NFQ")


async def test_unretained(harness):
    def cb(chan, pkt):
        # Can access payload within callback
        assert pkt.get_payload()[-3:] in (b"one", b"two")
        chan.send_nowait(pkt)

    # Capture packets without retaining -> can't access payload after cb returns
    async with harness.capture_packets_to(2, cb) as chan:
        await harness.send(2, b"one", b"two")
        accept = True
        async for p in chan:
            with pytest.raises(
                RuntimeError, match="Payload data is no longer available"
            ):
                p.get_payload()
            # Can still issue verdicts though
            if accept:
                p.accept()
                accept = False
            else:
                break

    with pytest.raises(RuntimeError, match="Parent queue has already been unbound"):
        p.drop()
    await harness.expect(2, b"one")


async def test_cb_exception(harness):
    pkt = None

    def cb(channel, p):
        nonlocal pkt
        pkt = p
        raise ValueError("test")

    # Error raised within run():
    with pytest.raises(ValueError, match="test"):
        async with harness.capture_packets_to(2, cb):
            await harness.send(2, b"boom")
            with trio.fail_after(1):
                try:
                    await trio.sleep_forever()
                finally:
                    # At this point the error has been raised (since we were
                    # cancelled) but the queue is still open. We shouldn't
                    # be able to access the payload, since we didn't retain(),
                    # but verdicts should otherwise work.
                    with pytest.raises(RuntimeError, match="Payload data is no longer"):
                        pkt.get_payload()
                    pkt.accept()

    await harness.expect(2, b"boom")

    with pytest.raises(RuntimeError, match="Verdict already given for this packet"):
        pkt.drop()


@pytest.mark.skipif(
    sys.implementation.name == "pypy",
    reason="pypy does not support PyErr_CheckSignals",
)
def test_signal():
    nfq = NetfilterQueue()
    nfq.bind(1, lambda p: None, sock_len=131072)

    def raise_alarm(sig, frame):
        raise KeyboardInterrupt("brrrrrring!")

    old_handler = signal.signal(signal.SIGALRM, raise_alarm)
    old_timer = signal.setitimer(signal.ITIMER_REAL, 0.5, 0)
    try:
        with pytest.raises(KeyboardInterrupt, match="brrrrrring!") as exc_info:
            nfq.run()
        assert any("NetfilterQueue.run" in line.name for line in exc_info.traceback)
    finally:
        nfq.unbind()
        signal.setitimer(signal.ITIMER_REAL, *old_timer)
        signal.signal(signal.SIGALRM, old_handler)


async def test_external_fd(harness):
    child_prog = """
import os, sys, unshare
from netfilterqueue import NetfilterQueue
unshare.unshare(unshare.CLONE_NEWNET)
nfq = NetfilterQueue(sockfd=int(sys.argv[1]))
def cb(pkt):
    pkt.accept()
    sys.exit(pkt.get_payload()[28:].decode("ascii"))
nfq.bind(1, cb, sock_len=131072)
os.write(1, b"ok\\n")
try:
    nfq.run()
finally:
    nfq.unbind()
"""
    async with trio.open_nursery() as nursery:

        async def monitor_in_child(task_status):
            with trio.fail_after(5):
                r, w = os.pipe()
                # 12 is NETLINK_NETFILTER family
                nlsock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12)

                @nursery.start_soon
                async def wait_started():
                    await trio.lowlevel.wait_readable(r)
                    assert b"ok\n" == os.read(r, 16)
                    nlsock.close()
                    os.close(w)
                    os.close(r)
                    task_status.started()

                result = await trio.run_process(
                    [sys.executable, "-c", child_prog, str(nlsock.fileno())],
                    stdout=w,
                    capture_stderr=True,
                    check=False,
                    pass_fds=(nlsock.fileno(),),
                )
            assert result.stderr == b"this is a test\n"

        await nursery.start(monitor_in_child)
        async with harness.enqueue_packets_to(2, queue_num=1):
            await harness.send(2, b"this is a test")
            await harness.expect(2, b"this is a test")

    with pytest.raises(OSError, match="dup2 failed"):
        NetfilterQueue(sockfd=1000)

    with pytest.raises(OSError, match="Failed to open NFQueue"):
        with open("/dev/null") as fp:
            NetfilterQueue(sockfd=fp.fileno())
