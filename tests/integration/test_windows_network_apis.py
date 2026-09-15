"""Integration tests for socket collection and process ↔ network correlation.

The spawned child opens only loopback sockets: a TCP listener, a TCP connection to that
listener, and a UDP socket. No external network access is used.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from collections.abc import Iterator
from datetime import timedelta

import pytest

pytestmark = pytest.mark.integration

if sys.platform == "win32":
    from winsentinel.collectors.network_collector import NetworkCollector
    from winsentinel.collectors.process_collector import ProcessCollector
    from winsentinel.core.models import AddressScope, Attribution, ConnectionState, Direction
    from winsentinel.correlation.process_network import (
        connection_chain,
        correlate,
        lookup_from_processes,
    )

PYTHON = getattr(sys, "_base_executable", sys.executable)
CHILD = """
import socket, sys, time
srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen()
cli = socket.create_connection(srv.getsockname()); acc, _ = srv.accept()
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.bind(("127.0.0.1", 0))
print(srv.getsockname()[1], cli.getsockname()[1], udp.getsockname()[1], flush=True)
time.sleep(60)
"""


@pytest.fixture
def socket_child() -> Iterator[tuple[subprocess.Popen[str], int, int, int]]:
    proc = subprocess.Popen(
        [PYTHON, "-c", CHILD], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
    )
    try:
        assert proc.stdout is not None
        listen_port, client_port, udp_port = (int(x) for x in proc.stdout.readline().split())
        yield proc, listen_port, client_port, udp_port
    finally:
        proc.kill()
        proc.wait(timeout=10)


def test_child_sockets_are_collected_with_direction_and_timestamp(
    socket_child: tuple[subprocess.Popen[str], int, int, int],
) -> None:
    proc, listen_port, client_port, udp_port = socket_child
    sockets = [c for c in NetworkCollector().collect().connections if c.pid == proc.pid]
    by_role = {(c.local_port, c.remote_port, c.protocol.value): c for c in sockets}
    listener = by_role[(listen_port, None, "TCP")]
    outbound = by_role[(client_port, listen_port, "TCP")]
    inbound = by_role[(listen_port, client_port, "TCP")]
    udp = by_role[(udp_port, None, "UDP")]

    assert listener.state is ConnectionState.LISTEN and listener.direction is Direction.LISTENING
    assert (
        outbound.state is ConnectionState.ESTABLISHED and outbound.direction is Direction.OUTBOUND
    )
    assert inbound.direction is Direction.INBOUND
    assert udp.direction is Direction.BOUND
    assert outbound.remote_scope is AddressScope.LOOPBACK
    for sock in (listener, outbound, inbound, udp):
        assert sock.created_at is not None
        assert abs(time.time() - sock.created_at.timestamp()) < 30


def test_child_sockets_are_attributed_to_child_process_instance(
    socket_child: tuple[subprocess.Popen[str], int, int, int],
) -> None:
    proc, listen_port, _, _ = socket_child
    processes = ProcessCollector().collect().processes
    child = next(p for p in processes if p.pid == proc.pid)
    items = correlate(NetworkCollector().collect().connections, lookup_from_processes(processes))
    mine = [i for i in items if i.pid == proc.pid]
    assert mine
    assert all(i.attribution is Attribution.ATTRIBUTED for i in mine)
    assert all(i.process_key == child.process_key for i in mine)

    # Kernel timestamps agree: every socket was created after its owning process.
    assert child.create_time is not None
    for item in mine:
        assert item.connection.created_at is not None
        assert item.connection.created_at >= child.create_time - timedelta(seconds=1)

    outbound = next(i for i in mine if i.connection.remote_port == listen_port)
    chain = connection_chain(outbound, processes)
    assert chain.process is not None and chain.process.pid == proc.pid
    assert chain.ancestors and chain.ancestors[0].pid == os.getpid()
