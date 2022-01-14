import math
import os
import pytest
import socket
import subprocess
import sys
import trio
import unshare  # type: ignore
import netfilterqueue
from functools import partial
from typing import Any, AsyncIterator, Callable, Dict, Optional, Tuple
from async_generator import asynccontextmanager
from pytest_trio.enable_trio_mode import *  # type: ignore


# We'll create three network namespaces, representing a router (which
# has interfaces on ROUTER_IP[1, 2]) and two hosts connected to it
# (PEER_IP[1, 2] respectively). The router (in the parent pytest
# process) will configure netfilterqueue iptables rules and use them
# to intercept and modify traffic between the two hosts (each of which
# is implemented in a subprocess).
#
# The 'peer' subprocesses communicate with each other over UDP, and
# with the router parent over a UNIX domain SOCK_SEQPACKET socketpair.
# Each packet sent from the parent to one peer over the UNIX domain
# socket will be forwarded to the other peer over UDP. Each packet
# received over UDP by either of the peers will be forwarded to its
# parent.

ROUTER_IP = {1: "172.16.101.1", 2: "172.16.102.1"}
PEER_IP = {1: "172.16.101.2", 2: "172.16.102.2"}


def enter_netns() -> None:
    # Create new namespaces of the other types we need
    unshare.unshare(unshare.CLONE_NEWNS | unshare.CLONE_NEWNET)

    # Mount /sys so network tools work
    subprocess.run("/bin/mount -t sysfs sys /sys".split(), check=True)

    # Bind-mount /run so iptables can get its lock
    subprocess.run("/bin/mount -t tmpfs tmpfs /run".split(), check=True)

    # Set up loopback interface
    subprocess.run("/sbin/ip link set lo up".split(), check=True)


@pytest.hookimpl(tryfirst=True)  # type: ignore
def pytest_runtestloop() -> None:
    if os.getuid() != 0:
        # Create a new user namespace for the whole test session
        outer = {"uid": os.getuid(), "gid": os.getgid()}
        unshare.unshare(unshare.CLONE_NEWUSER)
        with open("/proc/self/setgroups", "wb") as fp:
            # This is required since we're unprivileged outside the namespace
            fp.write(b"deny")
        for idtype in ("uid", "gid"):
            with open(f"/proc/self/{idtype}_map", "wb") as fp:
                fp.write(b"0 %d 1" % (outer[idtype],))
        assert os.getuid() == os.getgid() == 0

    # Create a new network namespace for this pytest process
    enter_netns()
    with open("/proc/sys/net/ipv4/ip_forward", "wb") as fp:
        fp.write(b"1\n")


async def peer_main(idx: int, parent_fd: int) -> None:
    parent = trio.socket.fromfd(parent_fd, socket.AF_UNIX, socket.SOCK_SEQPACKET)

    # Tell parent we've set up our netns, wait for it to confirm it's
    # created our veth interface
    await parent.send(b"ok")
    assert b"ok" == await parent.recv(4096)

    my_ip = PEER_IP[idx]
    router_ip = ROUTER_IP[idx]
    peer_ip = PEER_IP[3 - idx]

    for cmd in (
        f"ip link set veth0 up",
        f"ip addr add {my_ip}/24 dev veth0",
        f"ip route add default via {router_ip} dev veth0",
    ):
        await trio.run_process(cmd.split(), capture_stdout=True, capture_stderr=True)

    peer = trio.socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    await peer.bind((my_ip, 0))

    # Tell the parent our port and get our peer's port
    await parent.send(b"%d" % peer.getsockname()[1])
    peer_port = int(await parent.recv(4096))
    await peer.connect((peer_ip, peer_port))

    # Enter the message-forwarding loop
    async def proxy_one_way(
        src: trio.socket.SocketType, dest: trio.socket.SocketType
    ) -> None:
        while src.fileno() >= 0:
            try:
                msg = await src.recv(4096)
            except trio.ClosedResourceError:
                return
            if not msg:
                dest.close()
                return
            try:
                await dest.send(msg)
            except BrokenPipeError:
                return

    async with trio.open_nursery() as nursery:
        nursery.start_soon(proxy_one_way, parent, peer)
        nursery.start_soon(proxy_one_way, peer, parent)


def _default_capture_cb(
    target: "trio.MemorySendChannel[netfilterqueue.Packet]",
    packet: netfilterqueue.Packet,
) -> None:
    packet.retain()
    target.send_nowait(packet)


class Harness:
    def __init__(self) -> None:
        self._received: Dict[int, trio.MemoryReceiveChannel[bytes]] = {}
        self._conn: Dict[int, trio.socket.SocketType] = {}
        self.dest_addr: Dict[int, Tuple[str, int]] = {}
        self.failed = False

    async def _run_peer(self, idx: int, *, task_status: Any) -> None:
        their_ip = PEER_IP[idx]
        my_ip = ROUTER_IP[idx]
        conn, child_conn = trio.socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with conn:
            try:
                process = await trio.open_process(
                    [sys.executable, __file__, str(idx), str(child_conn.fileno())],
                    stdin=subprocess.DEVNULL,
                    pass_fds=[child_conn.fileno()],
                    preexec_fn=enter_netns,
                )
            finally:
                child_conn.close()
            assert b"ok" == await conn.recv(4096)
            for cmd in (
                f"ip link add veth{idx} type veth peer netns {process.pid} name veth0",
                f"ip link set veth{idx} up",
                f"ip addr add {my_ip}/24 dev veth{idx}",
            ):
                await trio.run_process(cmd.split())

            try:
                await conn.send(b"ok")
                self._conn[idx] = conn
                task_status.started()
                retval = await process.wait()
            except BaseException:
                process.kill()
                with trio.CancelScope(shield=True):
                    await process.wait()
                raise
            else:
                if retval != 0:
                    raise RuntimeError(
                        "peer subprocess exited with code {}".format(retval)
                    )
            finally:
                # On some kernels the veth device is removed when the subprocess exits
                # and its netns goes away. check=False to suppress that error.
                await trio.run_process(f"ip link delete veth{idx}".split(), check=False)

    async def _manage_peer(self, idx: int, *, task_status: Any) -> None:
        async with trio.open_nursery() as nursery:
            await nursery.start(self._run_peer, idx)
            packets_w, packets_r = trio.open_memory_channel[bytes](math.inf)
            self._received[idx] = packets_r
            task_status.started()
            async with packets_w:
                while True:
                    msg = await self._conn[idx].recv(4096)
                    if not msg:
                        break
                    await packets_w.send(msg)

    @asynccontextmanager
    async def run(self) -> AsyncIterator[None]:
        async with trio.open_nursery() as nursery:
            async with trio.open_nursery() as start_nursery:
                start_nursery.start_soon(nursery.start, self._manage_peer, 1)
                start_nursery.start_soon(nursery.start, self._manage_peer, 2)
            # Tell each peer about the other one's port
            for idx in (1, 2):
                self.dest_addr[idx] = (
                    PEER_IP[idx],
                    int(await self._received[idx].receive()),
                )
                await self._conn[3 - idx].send(b"%d" % self.dest_addr[idx][1])
            yield
            self._conn[1].shutdown(socket.SHUT_WR)
            self._conn[2].shutdown(socket.SHUT_WR)

        if not self.failed:
            for idx in (1, 2):
                async for remainder in self._received[idx]:
                    raise AssertionError(
                        f"Peer {idx} received unexepcted packet {remainder!r}"
                    )

    def bind_queue(
        self,
        cb: Callable[[netfilterqueue.Packet], None],
        *,
        queue_num: int = -1,
        **options: int,
    ) -> Tuple[int, netfilterqueue.NetfilterQueue]:
        nfq = netfilterqueue.NetfilterQueue()
        # Use a smaller socket buffer to avoid a warning in CI
        options.setdefault("sock_len", 131072)
        if queue_num >= 0:
            nfq.bind(queue_num, cb, **options)
        else:
            for queue_num in range(16):
                try:
                    nfq.bind(queue_num, cb, **options)
                    break
                except Exception as ex:
                    last_error = ex
            else:
                raise RuntimeError(
                    "Couldn't bind any netfilter queue number between 0-15"
                ) from last_error
        return queue_num, nfq

    @asynccontextmanager
    async def enqueue_packets_to(
        self, idx: int, queue_num: int, *, forwarded: bool = True
    ) -> AsyncIterator[None]:
        if forwarded:
            chain = "FORWARD"
        else:
            chain = "OUTPUT"

        rule = f"{chain} -d {PEER_IP[idx]} -j NFQUEUE --queue-num {queue_num}"
        await trio.run_process(f"/sbin/iptables -A {rule}".split())
        try:
            yield
        finally:
            await trio.run_process(f"/sbin/iptables -D {rule}".split())

    @asynccontextmanager
    async def capture_packets_to(
        self,
        idx: int,
        cb: Callable[
            ["trio.MemorySendChannel[netfilterqueue.Packet]", netfilterqueue.Packet],
            None,
        ] = _default_capture_cb,
        **options: int,
    ) -> AsyncIterator["trio.MemoryReceiveChannel[netfilterqueue.Packet]"]:

        packets_w, packets_r = trio.open_memory_channel[netfilterqueue.Packet](math.inf)
        queue_num, nfq = self.bind_queue(partial(cb, packets_w), **options)
        try:
            async with self.enqueue_packets_to(idx, queue_num):
                async with packets_w, trio.open_nursery() as nursery:

                    @nursery.start_soon
                    async def listen_for_packets() -> None:
                        while True:
                            await trio.lowlevel.wait_readable(nfq.get_fd())
                            nfq.run(block=False)

                    yield packets_r
                    nursery.cancel_scope.cancel()
        finally:
            nfq.unbind()

    async def expect(self, idx: int, *packets: bytes) -> None:
        for expected in packets:
            with trio.move_on_after(5) as scope:
                received = await self._received[idx].receive()
            if scope.cancelled_caught:
                self.failed = True
                raise AssertionError(
                    f"Timeout waiting for peer {idx} to receive {expected!r}"
                )
            if received != expected:
                self.failed = True
                raise AssertionError(
                    f"Expected peer {idx} to receive {expected!r} but it "
                    f"received {received!r}"
                )

    async def send(self, idx: int, *packets: bytes) -> None:
        for packet in packets:
            await self._conn[3 - idx].send(packet)


@pytest.fixture
async def harness() -> AsyncIterator[Harness]:
    h = Harness()
    async with h.run():
        yield h


if __name__ == "__main__":
    trio.run(peer_main, int(sys.argv[1]), int(sys.argv[2]))
