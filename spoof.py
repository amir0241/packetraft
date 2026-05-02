#!/usr/bin/env python3
"""
Spoof Tunnel with TUN interface support (Linux only).

Three modes (--mode tun | portfwd | direct):

── TUN mode (default) ────────────────────────────────────────────────────────
Architecture:
  Client <--> TUN(iran1)
              Iran1 reads raw IP pkts from TUN
              Iran1 --RawSocket(src=SPOOF_IP)--------------> Foreign sniffer
                                                              Foreign writes to TUN(foreign)
                                                              Foreign reads reply from TUN(foreign)
              Iran2 sniffer <--RawSocket(src=Iran1_IP)------ Foreign
              Iran2 --framed TCP-------------------------->  Iran1 relay listener
              Iran1 writes raw IP pkt to TUN(iran1)
  Client <--> TUN(iran1)

Roles:
  iran1   - TUN interface. Reads IP packets, sends spoofed raw TCP to foreign.
            Relay listener receives framed TCP from iran2, writes back to TUN.
  iran2   - No TUN. Sniffs spoofed packets (src=iran1_ip) from foreign,
            forwards as framed TCP to iran1 relay port.
  foreign - TUN interface. Sniffs from iran1 (src=spoof_src_ip), writes to TUN.
            Reads replies from TUN, sends spoofed raw TCP (src=iran1_ip) to iran2.

Usage (TUN mode):
  sudo python tunnel.py iran1 --mode tun \
      --tun-cidr 10.8.0.1/24 \
      --relay-port 9002 \
      --spoof-src-ip 10.0.0.99 --spoof-src-port 7000 \
      --foreign-ip 5.6.7.8 --foreign-port 9001

  sudo python tunnel.py iran2 \
      --listen-port 9000 \
      --iran1-ip 9.10.11.12 --iran1-port 9002

  sudo python tunnel.py foreign --mode tun \
      --tun-cidr 10.8.0.2/24 \
      --listen-port 9001 \
      --spoof-src-ip 10.0.0.99 \
      --iran1-ip 9.10.11.12 \
      --iran2-ip 1.2.3.4 --iran2-port 9000

── Port-forward mode ─────────────────────────────────────────────────────────
  iran1 listens for plain TCP clients on --pf-listen-port.
  Each client connection is multiplexed over the spoofed-raw channel
  (same iran2 relay path) to foreign, which connects to --pf-target-ip:--pf-target-port
  and pipes data in both directions.  No TUN or IP forwarding needed.

  Port-forward framing (inside each relay frame):
    [4B session-id][1B type][payload]
    type: 0x01=data  0x02=connect  0x03=close

Usage (portfwd mode):
  sudo python tunnel.py iran1 --mode portfwd \
      --relay-port 9002 \
      --spoof-src-ip 10.0.0.99 --spoof-src-port 7000 \
      --foreign-ip 5.6.7.8 --foreign-port 9001 \
      --pf-listen-port 1080

  sudo python tunnel.py iran2 \
      --listen-port 9000 \
      --iran1-ip 9.10.11.12 --iran1-port 9002

  sudo python tunnel.py foreign --mode portfwd \
      --listen-port 9001 \
      --spoof-src-ip 10.0.0.99 \
      --iran1-ip 9.10.11.12 \
      --iran2-ip 1.2.3.4 --iran2-port 9000 \
      --pf-target-ip 127.0.0.1 --pf-target-port 443

── Direct mode (NO relay server / iran2) ────────────────────────────────────
  Eliminates the iran2 relay entirely.  iran1 sniffs reply packets from foreign
  directly; foreign sends spoofed raw TCP straight back to iran1.
  Use this when you only have two servers (iran1 + foreign) and no middle relay.

  Both iran1 and foreign must agree on the same --reply-src-ip (the spoofed
  source IP that foreign puts on its return packets so iran1 can filter them).

Architecture (direct / direct-portfwd):
  Client <--> TUN(iran1)  [or TCP client on pf-listen-port]
              Iran1 --RawSocket(src=SPOOF_IP)--------------> Foreign sniffer
                                                              Foreign writes to TUN / mux
              Iran1 sniffer <--RawSocket(src=REPLY_SRC_IP)-- Foreign
              Iran1 writes raw IP pkt to TUN  [or mux.on_frame]
  Client <--> TUN(iran1)  [or TCP client]

Usage (direct TUN mode – two servers only):
  sudo python tunnel.py iran1 --mode direct \
      --tun-cidr 10.8.0.1/24 \
      --spoof-src-ip 10.0.0.99 --spoof-src-port 7000 \
      --foreign-ip 5.6.7.8 --foreign-port 9001 \
      --listen-port 9002 \
      --reply-src-ip 10.0.0.88

  sudo python tunnel.py foreign --mode direct \
      --tun-cidr 10.8.0.2/24 \
      --listen-port 9001 \
      --spoof-src-ip 10.0.0.99 \
      --iran1-ip 9.10.11.12 \
      --iran1-sniff-port 9002 \
      --reply-src-ip 10.0.0.88

Usage (direct port-forward mode – two servers only):
  sudo python tunnel.py iran1 --mode direct-portfwd \
      --spoof-src-ip 10.0.0.99 --spoof-src-port 7000 \
      --foreign-ip 5.6.7.8 --foreign-port 9001 \
      --listen-port 9002 \
      --reply-src-ip 10.0.0.88 \
      --pf-listen-port 1080

  sudo python tunnel.py foreign --mode direct-portfwd \
      --listen-port 9001 \
      --spoof-src-ip 10.0.0.99 \
      --iran1-ip 9.10.11.12 \
      --iran1-sniff-port 9002 \
      --reply-src-ip 10.0.0.88 \
      --pf-target-ip 127.0.0.1 --pf-target-port 443

Notes:
  - Requires root and Linux (raw sockets; TUN only in tun/direct modes).
  - On the foreign server enable IP forwarding (tun/direct modes only):
      echo 1 > /proc/sys/net/ipv4/ip_forward
  - pip install scapy
"""

import argparse
import array   as _array
import fcntl
import os
import queue  as _queue
import struct
import subprocess
import sys
import socket
import threading
import time as _time

# TUN MTU – conservative value: leaves headroom for outer IP(20)+TCP(20) headers
# AND any path overhead (PPPoE +8, some ISP encaps) so the 1500-byte Ethernet
# frame is never exceeded and fragmentation never occurs.
# 1400 = 1500 - 20(IP) - 20(TCP) - 60(headroom)
MTU = 1400
# 4-byte big-endian length prefix used on the TCP relay stream (iran2 -> iran1)
_FRAME = struct.Struct("!I")

# Linux-specific socket constants (graceful fallback on older kernels)
_SO_BUSY_POLL     = getattr(socket, "SO_BUSY_POLL",  46)  # µs busy-poll
_TCP_QUICKACK     = getattr(socket, "TCP_QUICKACK",  12)  # suppress delayed ACKs
_TCP_KEEPIDLE     = getattr(socket, "TCP_KEEPIDLE",   4)  # idle secs before keepalive
_TCP_KEEPINTVL    = getattr(socket, "TCP_KEEPINTVL",  5)  # interval between probes
_TCP_KEEPCNT       = getattr(socket, "TCP_KEEPCNT",        6)  # probe count before drop
_TCP_NOTSENT_LOWAT = getattr(socket, "TCP_NOTSENT_LOWAT", 25)  # max unsent bytes in sndbuf
_SO_ATTACH_FILTER  = 26                                         # SO_ATTACH_FILTER (always 26)
_IS_LE            = sys.byteorder == "little"             # checksum endianness
_HAS_SENDMSG      = hasattr(socket.socket, "sendmsg")     # Linux: avoid header+data copy


def _set_thread_realtime(priority: int = 50) -> None:
    """Elevate the calling thread to SCHED_FIFO real-time scheduling (Linux, root only).
    Eliminates scheduler jitter on hot I/O loops. Silently ignored on failure.
    Uses os.sched_setscheduler (stdlib, no ctypes) with pid=0 → current thread."""
    try:
        os.sched_setscheduler(0, os.SCHED_FIFO, os.sched_param(priority))
    except (AttributeError, OSError, PermissionError):
        pass


def _pin_thread(core: int) -> None:
    """Pin the calling thread to a specific CPU core.
    Prevents the scheduler from migrating hot loops between cores, which
    would flush L1/L2 caches and add ~50–200 µs jitter per migration."""
    try:
        n = os.cpu_count() or 1
        os.sched_setaffinity(0, {core % n})
    except (AttributeError, OSError):
        pass


# ---------------------------------------------------------------------------
# TUN interface (Linux only)
# ---------------------------------------------------------------------------

_TUNSETIFF = 0x400454CA
_IFF_TUN   = 0x0001
_IFF_NO_PI = 0x1000   # do NOT prepend packet-info header


class TunInterface:
    def __init__(self, name="tun0"):
        self.name = name
        self._fd = None
        self._rbuf = bytearray(65535)   # max possible IP packet; prevents silent truncation
        self._write_lock = threading.Lock()  # TUN writes must be serialised across threads

    def open(self):
        self._fd = open("/dev/net/tun", "r+b", buffering=0)
        ifr = struct.pack("16sH", self.name.encode(), _IFF_TUN | _IFF_NO_PI)
        fcntl.ioctl(self._fd, _TUNSETIFF, ifr)
        return self

    def configure(self, cidr):
        """Assign IP address and bring the interface up."""
        subprocess.run(["ip", "addr", "add", cidr, "dev", self.name], check=True)
        subprocess.run(["ip", "link", "set", "dev", self.name, "mtu", str(MTU)], check=True)
        subprocess.run(["ip", "link", "set", "dev", self.name, "txqueuelen", "10000"], check=True)
        subprocess.run(["ip", "link", "set", "dev", self.name, "up"], check=True)
        # Clamp TCP MSS on packets forwarded through this TUN to MTU-40.
        # Without this, remote servers negotiate MSS=1460 (based on their eth0 MTU=1500)
        # and send 1480-byte IP packets with DF=1.  The kernel cannot fragment them
        # to fit the TUN MTU=1400, silently drops them, and the inner TCP connection
        # stalls after the initial burst – the root cause of video-stream freeze.
        _mss = MTU - 40  # 1360: IP(20) + TCP(20) headers subtracted
        for direction in ("-i", "-o"):
            subprocess.run(
                ["iptables", "-t", "mangle", "-C", "FORWARD",
                 "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                 direction, self.name, "-j", "TCPMSS", "--set-mss", str(_mss)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            r = subprocess.run(
                ["iptables", "-t", "mangle", "-C", "FORWARD",
                 "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                 direction, self.name, "-j", "TCPMSS", "--set-mss", str(_mss)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            if r.returncode != 0:  # rule doesn't exist yet – add it
                subprocess.run(
                    ["iptables", "-t", "mangle", "-A", "FORWARD",
                     "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                     direction, self.name, "-j", "TCPMSS", "--set-mss", str(_mss)],
                    check=False
                )
        print("[tun] {} configured with {} mtu={} mss-clamp={}".format(
            self.name, cidr, MTU, _mss))

    def read(self):
        """Block until one IP packet is available, return it."""
        n = self._fd.readinto(self._rbuf)  # zero-copy into pre-allocated buffer
        return bytes(self._rbuf[:n])

    def write(self, data):
        with self._write_lock:
            self._fd.write(data)

    def close(self):
        if self._fd:
            self._fd.close()
            self._fd = None


# ---------------------------------------------------------------------------
# Framed TCP helpers  (length-prefix so we can reassemble the stream)
# ---------------------------------------------------------------------------

def _recv_exact(sock, n):
    buf = bytearray(n)
    view = memoryview(buf)
    pos = 0
    while pos < n:
        got = sock.recv_into(view[pos:], n - pos)
        if not got:
            return None
        pos += got
    return bytes(buf)


def send_framed(sock, data: bytes) -> None:
    hdr = _FRAME.pack(len(data))
    if _HAS_SENDMSG:
        sock.sendmsg([hdr, data])  # single syscall, no Python-level copy
    else:
        sock.sendall(hdr + data)


def recv_framed(sock):
    hdr = _recv_exact(sock, _FRAME.size)
    if hdr is None:
        return None
    length = _FRAME.unpack(hdr)[0]
    return _recv_exact(sock, length)


# ---------------------------------------------------------------------------
# Raw-socket sender + BPF filter helpers
# ---------------------------------------------------------------------------

# Pre-compiled struct formats
_IP_HDR_S  = struct.Struct("!BBHHHBBH4s4s")
_TCP_HDR_S = struct.Struct("!HHIIBBHHH")
_PSEUDO_S  = struct.Struct("!4s4sBBH")
_TCP_OFF   = 0x50   # data-offset field: 5 × 4-byte words


def _ip_checksum(data: bytes) -> int:
    """
    One's-complement checksum.
    Uses the stdlib `array` module for a tight C-level sum (~2× faster than
    struct.unpack for payloads > 64 bytes; critical for per-packet TCP checksum).
    """
    if len(data) & 1:
        data = data + b"\x00"
    a = _array.array("H", data)
    if _IS_LE:
        a.byteswap()          # convert pairs to big-endian so sum is in network order
    s = sum(a)
    s = (s >> 16) + (s & 0xFFFF)   # fold carries (two explicit folds = no loop)
    s += (s >> 16)
    return ~s & 0xFFFF


# ---------------------------------------------------------------------------
# Kernel BPF filter – SO_ATTACH_FILTER (zero Python overhead per packet)
# ---------------------------------------------------------------------------

def _attach_bpf(sock: socket.socket, src_ip: str, dst_port: int) -> bool:
    """
    Attach a cBPF program that passes only: IPv4 + TCP + src==src_ip + dport==dst_port.
    Non-matching frames are discarded inside the kernel – Python never sees them.
    Returns True on success; silently falls back to Python-level filtering on failure.
    """
    import ctypes  # imported locally – only needed here

    class _BpfInsn(ctypes.Structure):
        _fields_ = [("code", ctypes.c_uint16),
                    ("jt",   ctypes.c_uint8),
                    ("jf",   ctypes.c_uint8),
                    ("k",    ctypes.c_uint32)]

    class _BpfProg(ctypes.Structure):
        _fields_ = [("len",    ctypes.c_uint16),
                    ("filter", ctypes.POINTER(_BpfInsn))]

    src_int = struct.unpack("!I", socket.inet_aton(src_ip))[0]
    # fmt: (code, jt, jf, k).  Jump offsets skip N instructions *after* current one.
    raw = [
        (0x28,  0,  0, 12),          # ldh  [12]           ; ethertype
        (0x15,  0,  8, 0x0800),      # jeq  #0x800  +0 +8  ; not IPv4  → FAIL
        (0x30,  0,  0, 23),          # ldb  [23]           ; IP proto
        (0x15,  0,  6, 6),           # jeq  #6      +0 +6  ; not TCP   → FAIL
        (0x20,  0,  0, 26),          # ld   [26]           ; src IP
        (0x15,  0,  4, src_int),     # jeq  #src    +0 +4  ; wrong src → FAIL
        (0xb1,  0,  0, 14),          # ldxb 4*([14]&0xf)   ; X = IP hdr len
        (0x48,  0,  0, 16),          # ldh  [x+16]         ; TCP dst port
        (0x15,  0,  1, dst_port),    # jeq  #port   +0 +1  ; wrong port → FAIL
        (0x06,  0,  0, 0xFFFF),      # ret  #PASS
        (0x06,  0,  0, 0),           # ret  #FAIL
    ]
    try:
        arr  = (_BpfInsn * len(raw))(*[_BpfInsn(*i) for i in raw])
        prog = _BpfProg(len(raw), arr)
        blob = bytes(ctypes.string_at(ctypes.addressof(prog), ctypes.sizeof(prog)))
        sock.setsockopt(socket.SOL_SOCKET, _SO_ATTACH_FILTER, blob)
        return True
    except OSError as exc:
        print("[bpf] SO_ATTACH_FILTER failed ({}) – falling back to Python filter".format(exc))
        return False


class RawTCPBuilder:
    """
    Pre-caches binary src/dst for zero-lookup-per-packet assembly.
    Embeds DSCP EF (TOS=0xB8) and DF bit (0x4000) directly in the IP header
    so they actually take effect on SOCK_RAW/IP_HDRINCL sockets.
    """
    __slots__ = ("_src_b", "_dst_b", "_sp", "_dp")

    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int):
        self._src_b = socket.inet_aton(src_ip)
        self._dst_b = socket.inet_aton(dst_ip)
        self._sp    = src_port
        self._dp    = dst_port

    def build(self, payload: bytes, seq: int, flags: int = 0x18) -> bytes:
        src_b, dst_b, sp, dp = self._src_b, self._dst_b, self._sp, self._dp
        plen  = len(payload)
        seq32 = seq & 0xFFFFFFFF

        tcp0  = _TCP_HDR_S.pack(sp, dp, seq32, 0, _TCP_OFF, flags, 65535, 0, 0)
        chk   = _ip_checksum(
            _PSEUDO_S.pack(src_b, dst_b, 0, socket.IPPROTO_TCP, 20 + plen)
            + tcp0 + payload)
        tcp   = _TCP_HDR_S.pack(sp, dp, seq32, 0, _TCP_OFF, flags, 65535, chk, 0)

        ip_len = 40 + plen
        ip0   = _IP_HDR_S.pack(0x45, 0xB8, ip_len, 0, 0x4000, 64, socket.IPPROTO_TCP, 0,    src_b, dst_b)
        ip    = _IP_HDR_S.pack(0x45, 0xB8, ip_len, 0, 0x4000, 64, socket.IPPROTO_TCP, _ip_checksum(ip0), src_b, dst_b)

        return ip + tcp + payload


class DirectSender:
    """
    Zero-queue raw-socket sender.

    Sends packets in the CALLING thread – no queue, no thread-wakeup latency,
    no out-of-order risk (queued multi-worker senders can reorder packets, forcing
    TCP retransmits at the application layer).

    sendto() on a non-full kernel buffer returns in < 1 µs; the 16 MB SO_SNDBUF
    absorbs any burst so it effectively never blocks.
    """
    __slots__ = ("_builder", "_dst", "_sock")

    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int):
        self._builder = RawTCPBuilder(src_ip, dst_ip, src_port, dst_port)
        self._dst     = dst_ip
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP,  socket.IP_HDRINCL,  1)
        sock.setsockopt(socket.SOL_SOCKET,  socket.SO_SNDBUF,   16 * 1024 * 1024)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY, 6)  # kernel qdisc EF
        except OSError:
            pass
        try:
            sock.setsockopt(socket.SOL_SOCKET, _SO_BUSY_POLL, 50)      # µs busy-poll
        except OSError:
            pass
        self._sock = sock

    def send(self, payload: bytes, seq: int, flags: int = 0x18) -> None:
        try:
            self._sock.sendto(self._builder.build(payload, seq, flags), (self._dst, 0))
        except OSError:
            pass

    def close(self) -> None:
        self._sock.close()


# ---------------------------------------------------------------------------
# Buffered relay-stream reader  (replaces recv_framed – fewer syscalls per frame)
# ---------------------------------------------------------------------------

_FR_BUFSIZE = 2 * 1024 * 1024   # 2 MB read-ahead buffer


class FrameReader:
    """
    Length-prefixed frame reader with 512 KB read-ahead.

    Under load, multiple frames arrive in a single TCP segment.  By reading
    large chunks, we reduce recv() syscalls by ~10× compared to calling
    recv_framed() (which makes 2 syscalls per frame).
    """
    __slots__ = ("_sock", "_buf", "_view", "_pos", "_end")

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._buf  = bytearray(_FR_BUFSIZE)
        self._view = memoryview(self._buf)
        self._pos  = 0
        self._end  = 0

    def read(self) -> "bytes | None":
        if not self._ensure(_FRAME.size):
            return None
        length = _FRAME.unpack_from(self._buf, self._pos)[0]
        self._pos += _FRAME.size
        if not self._ensure(length):
            return None
        out = bytes(self._view[self._pos:self._pos + length])
        self._pos += length
        return out

    def _ensure(self, n: int) -> bool:
        while self._end - self._pos < n:
            avail = self._end - self._pos
            if self._pos > 0 and (self._pos > _FR_BUFSIZE // 2 or self._end == _FR_BUFSIZE):
                self._buf[:avail] = self._view[self._pos:self._end]
                self._pos = 0
                self._end = avail
            got = self._sock.recv_into(self._view[self._end:])
            if not got:
                return False
            self._end += got
        return True


# ---------------------------------------------------------------------------
# Fast AF_PACKET sniffer  (replaces Scapy AsyncSniffer – much lower latency)
# ---------------------------------------------------------------------------

def _af_packet_sniffer(filter_src_ip: str, filter_dst_port: int,
                        callback, stop_event: threading.Event):
    """
    Raw AF_PACKET sniffer – bypasses libpcap/Scapy Python overhead entirely.
    Calls callback(payload: bytes) for each matching TCP packet that has a payload.
    """
    ETH_P_IP = 0x0800
    src_b = socket.inet_aton(filter_src_ip)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024 * 1024)
    try:
        s.setsockopt(socket.SOL_SOCKET, _SO_BUSY_POLL, 50)
    except OSError:
        pass
    # Kernel BPF filter: non-matching frames never reach Python
    _attach_bpf(s, filter_src_ip, filter_dst_port)
    s.settimeout(0.1)   # 100 ms timeout → faster stop_event response
    _buf  = bytearray(65536)   # pre-allocated receive buffer (no per-packet alloc)
    _view = memoryview(_buf)
    try:
        while not stop_event.is_set():
            try:
                n = s.recv_into(_view)   # zero-copy into pre-allocated buffer
            except socket.timeout:
                continue
            except OSError:
                break
            # Ethernet header = 14 bytes; need at least Ethernet + IP + TCP
            if n < 34:
                continue
            ip_start = 14
            ip_b0 = _buf[ip_start]
            if (ip_b0 >> 4) != 4:                                     # IPv4 only
                continue
            if _buf[ip_start + 9] != 6:                               # TCP only
                continue
            if _buf[ip_start + 12:ip_start + 16] != src_b:           # src IP filter
                continue
            ihl = (ip_b0 & 0x0F) << 2
            tcp_start = ip_start + ihl
            if n < tcp_start + 20:
                continue
            dst_port_val = (_buf[tcp_start + 2] << 8) | _buf[tcp_start + 3]
            if dst_port_val != filter_dst_port:                       # dst port filter
                continue
            tcp_doff      = (_buf[tcp_start + 12] >> 4) << 2
            payload_start = tcp_start + tcp_doff
            if payload_start < n:
                callback(bytes(_view[payload_start:n]))
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Role: iran1
# ---------------------------------------------------------------------------

def run_iran1(args):
    """
    1. Create TUN, assign tun_cidr.
    2. Read IP packets from TUN -> send to foreign as raw spoofed TCP (src=spoof_src_ip).
    3. Relay listener: accept framed TCP from iran2 -> write raw IP packets to TUN.
    """
    tun_name       = args.tun_name
    tun_cidr       = args.tun_cidr
    relay_port     = args.relay_port
    spoof_src_ips  = args.spoof_src_ip   # list of one or more IPs
    spoof_src_port = args.spoof_src_port
    foreign_ip     = args.foreign_ip
    foreign_port   = args.foreign_port

    tun = TunInterface(tun_name).open()
    tun.configure(tun_cidr)

    seq_counter = 10000

    # --- Relay listener (iran2 connects here to deliver replies) ---
    relay_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    relay_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    relay_server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32 * 1024 * 1024)
    relay_server.bind(("0.0.0.0", relay_port))
    relay_server.listen(64)
    print("[iran1] Relay listener on port {}".format(relay_port))

    def handle_relay(conn, addr):
        _set_thread_realtime(55)
        _pin_thread(2)   # dedicate core 2 to relay I/O
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY,  1)
        conn.setsockopt(socket.SOL_SOCKET,  socket.SO_RCVBUF,   32 * 1024 * 1024)
        conn.setsockopt(socket.SOL_SOCKET,  socket.SO_SNDBUF,   32 * 1024 * 1024)
        conn.setsockopt(socket.SOL_SOCKET,  socket.SO_KEEPALIVE, 1)
        try:
            conn.setsockopt(socket.IPPROTO_TCP, _TCP_QUICKACK,        1)
            conn.setsockopt(socket.IPPROTO_TCP, _TCP_KEEPIDLE,        5)
            conn.setsockopt(socket.IPPROTO_TCP, _TCP_KEEPINTVL,       2)
            conn.setsockopt(socket.IPPROTO_TCP, _TCP_KEEPCNT,         3)
            conn.setsockopt(socket.IPPROTO_IP,  socket.IP_TOS,        0xB8)  # DSCP EF on relay
            conn.setsockopt(socket.SOL_SOCKET,  _SO_BUSY_POLL,        50)    # µs busy-poll
            conn.setsockopt(socket.SOL_SOCKET,  socket.SO_PRIORITY,   6)
        except OSError:
            pass
        print("[iran1] Relay connected: {}".format(addr))
        reader = FrameReader(conn)
        try:
            while True:
                pkt = reader.read()
                if pkt is None:
                    break
                if pkt:   # empty frames are keepalive no-ops from iran2
                    tun.write(pkt)
        except OSError:
            pass
        finally:
            conn.close()
            print("[iran1] Relay disconnected: {}".format(addr))

    def relay_acceptor():
        while True:
            try:
                conn, addr = relay_server.accept()
                threading.Thread(target=handle_relay, args=(conn, addr), daemon=True).start()
            except OSError:
                break

    threading.Thread(target=relay_acceptor, daemon=True).start()

    # --- TUN reader: forward packets to foreign ---
    senders = [
        DirectSender(src_ip=ip, dst_ip=foreign_ip,
                     src_port=spoof_src_port, dst_port=foreign_port)
        for ip in spoof_src_ips
    ]
    # Each sender has its own seq counter to avoid gaps per TCP flow
    _seq_counters = [10000] * len(senders)
    _n_senders = len(senders)

    def _pick_sender(pkt: bytes) -> int:
        """Flow-based sender selection: hash inner dst IP so all packets of
        one TCP flow always leave from the same src IP.  Round-robin across
        flows would cause out-of-order delivery → TCP congestion collapse."""
        if _n_senders == 1:
            return 0
        if len(pkt) >= 20:
            # dst IP is at bytes 16-19 of the inner IP header
            return (pkt[16] << 24 | pkt[17] << 16 | pkt[18] << 8 | pkt[19]) % _n_senders
        return 0

    print("[iran1] TUN -> foreign {}:{} (spoof src(s)={} port={})".format(
        foreign_ip, foreign_port, spoof_src_ips, spoof_src_port))
    try:
        while True:
            pkt = tun.read()
            if not pkt:
                break
            idx = _pick_sender(pkt)
            cur_seq = _seq_counters[idx]
            _seq_counters[idx] += len(pkt)
            senders[idx].send(payload=pkt, seq=cur_seq)
    except KeyboardInterrupt:
        print("[iran1] Shutting down.")
    finally:
        for _s in senders:
            _s.close()
        tun.close()
        relay_server.close()


# ---------------------------------------------------------------------------
# Role: iran2
# ---------------------------------------------------------------------------

def run_iran2(args):
    """
    Sniff spoofed packets from foreign (src=iran1_ip, dst_port=listen_port).
    Forward each payload as a framed TCP message to iran1 relay port.
    """
    iran1_ip    = args.iran1_ip     # foreign spoofs src as this IP
    iran1_port  = args.iran1_port   # relay port on iran1
    listen_port = args.listen_port

    relay_sock = None
    relay_lock = threading.Lock()
    # 512 slots × ~1400 B = ~700 KB max buffering.  A large queue (e.g. 131072)
    # causes bufferbloat: video data fills it, new connections (Telegram photo,
    # Instagram fetch) wait seconds before their first packet is relayed.
    _relay_q: _queue.Queue = _queue.Queue(maxsize=512)

    def get_relay():
        nonlocal relay_sock
        with relay_lock:
            if relay_sock is not None:
                return relay_sock
        # Connect OUTSIDE the lock so reset_relay() is never blocked by a slow connect
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)               # 5 s connect timeout – prevents indefinite freeze
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY,  1)
            s.setsockopt(socket.SOL_SOCKET,  socket.SO_SNDBUF,   32 * 1024 * 1024)
            s.setsockopt(socket.SOL_SOCKET,  socket.SO_RCVBUF,   32 * 1024 * 1024)
            s.setsockopt(socket.SOL_SOCKET,  socket.SO_KEEPALIVE, 1)
            try:
                s.setsockopt(socket.IPPROTO_TCP, _TCP_QUICKACK,       1)
                s.setsockopt(socket.IPPROTO_TCP, _TCP_KEEPIDLE,       5)
                s.setsockopt(socket.IPPROTO_TCP, _TCP_KEEPINTVL,      2)
                s.setsockopt(socket.IPPROTO_TCP, _TCP_KEEPCNT,        3)
                s.setsockopt(socket.IPPROTO_TCP, _TCP_NOTSENT_LOWAT,  4096)  # cap unsent buffer → lower relay latency
                s.setsockopt(socket.IPPROTO_IP,  socket.IP_TOS,       0xB8)  # DSCP EF
                s.setsockopt(socket.SOL_SOCKET,  _SO_BUSY_POLL,       50)
                s.setsockopt(socket.SOL_SOCKET,  socket.SO_PRIORITY,  6)
            except OSError:
                pass
            s.connect((iran1_ip, iran1_port))
            s.settimeout(None)              # back to blocking I/O after connect
        except OSError as e:
            print("[iran2] Cannot connect to iran1: {}".format(e))
            try:
                s.close()
            except Exception:
                pass
            return None
        with relay_lock:
            if relay_sock is None:
                relay_sock = s
                print("[iran2] Relay connected to iran1 {}:{}".format(iran1_ip, iran1_port))
                return relay_sock
            else:
                s.close()   # another thread connected first; discard duplicate
                return relay_sock

    def reset_relay():
        nonlocal relay_sock
        with relay_lock:
            if relay_sock:
                try:
                    relay_sock.close()
                except OSError:
                    pass
            relay_sock = None

    def relay_sender():
        """Dedicated thread: drains _relay_q and forwards framed packets to iran1.
        Retries indefinitely on connection failure – no packet is silently dropped."""
        _set_thread_realtime(60)
        _pin_thread(0)   # highest-priority work owns core 0
        _backoff = 0.05  # starts at 50 ms, doubles on each failure up to 2 s
        _connected = False
        while True:
            payload = _relay_q.get()
            if payload is None:
                break
            while True:           # keep trying until this specific packet is sent
                s = get_relay()
                if s is None:
                    _connected = False
                    _time.sleep(_backoff)
                    _backoff = min(_backoff * 2, 2.0)   # exponential back-off
                    continue
                if not _connected:
                    # Flush packets that accumulated in the queue while relay was
                    # down.  They are stale – inner TCP will retransmit.  Sending
                    # a burst of old data over the freshly-established connection
                    # would trigger TCP slow-start and delay new traffic.
                    _drained = 0
                    while True:
                        try:
                            _relay_q.get_nowait()
                            _drained += 1
                        except _queue.Empty:
                            break
                    if _drained:
                        print("[iran2] Flushed {} stale packets after reconnect".format(_drained))
                    _connected = True
                    _backoff = 0.05
                    break   # discard current stale payload; outer loop gets fresh one
                try:
                    send_framed(s, payload)
                    _backoff = 0.05   # reset on successful send
                    break           # success – move to next packet
                except OSError:
                    _connected = False
                    reset_relay()   # connection died, reconnect on next iteration

    threading.Thread(target=relay_sender, daemon=True).start()

    def _heartbeat_thread():
        """Send a zero-length keepalive frame every 15 s when the relay is up.
        Prevents stateful ISP/NAT firewalls from silently dropping idle TCP connections,
        which is the primary cause of surprise reconnects during video streams."""
        while True:
            _time.sleep(15)
            with relay_lock:
                s = relay_sock
            if s is not None:
                try:
                    send_framed(s, b"")
                except OSError:
                    reset_relay()

    threading.Thread(target=_heartbeat_thread, daemon=True).start()

    def handle_pkt(payload: bytes):
        # Drop-oldest eviction: when the queue is full, remove the oldest stale
        # packet and insert the new one.  This gives new connections (Telegram
        # downloads, Instagram fetch start) a path through even under heavy
        # streaming load, instead of blocking the sniffer thread.
        while True:
            try:
                _relay_q.put_nowait(payload)
                return
            except _queue.Full:
                try:
                    _relay_q.get_nowait()   # evict oldest packet to make room
                except _queue.Empty:
                    pass

    _sniffer_stop = threading.Event()

    def _sniffer_thread():
        _set_thread_realtime(55)
        _pin_thread(1)   # sniffer on core 1, relay_sender on core 0
        _af_packet_sniffer(iran1_ip, listen_port, handle_pkt, _sniffer_stop)

    threading.Thread(target=_sniffer_thread, daemon=True).start()
    print("[iran2] Sniffer: port={}, expected src={}".format(listen_port, iran1_ip))
    print("[iran2] Relaying to iran1 {}:{}".format(iran1_ip, iran1_port))

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("[iran2] Shutting down.")
    finally:
        _sniffer_stop.set()
        _relay_q.put(None)
        reset_relay()


# ---------------------------------------------------------------------------
# Role: foreign
# ---------------------------------------------------------------------------

def run_foreign(args):
    """
    1. Create TUN, assign tun_cidr.
    2. Sniff incoming packets (src=spoof_src_ip) -> write raw IP packet to TUN.
    3. TUN reader: read reply IP packets -> send spoofed raw TCP (src=iran1_ip) to iran2.
    """
    tun_name     = args.tun_name
    tun_cidr     = args.tun_cidr
    listen_port  = args.listen_port
    spoof_src_ips = args.spoof_src_ip   # list of IPs iran1 spoofed as (filter)
    iran1_ip      = args.iran1_ip       # spoofed src in replies toward iran2
    iran2_ip     = args.iran2_ip       # destination of spoofed reply
    iran2_port   = args.iran2_port

    tun = TunInterface(tun_name).open()
    tun.configure(tun_cidr)

    seq_counter = 20000

    # --- TUN reader: send replies back to iran2 (spoofed) ---
    sender = DirectSender(
        src_ip=iran1_ip, dst_ip=iran2_ip,
        src_port=listen_port, dst_port=iran2_port,
    )

    def tun_reader():
        _set_thread_realtime(60)
        _pin_thread(0)   # TUN send loop owns core 0
        nonlocal seq_counter
        while True:
            pkt = tun.read()
            if not pkt:
                break
            cur_seq = seq_counter
            seq_counter += len(pkt)
            sender.send(payload=pkt, seq=cur_seq)

    threading.Thread(target=tun_reader, daemon=True).start()

    # --- Sniffer: receive raw IP packets from iran1 ---
    def handle_incoming(payload: bytes):
        tun.write(payload)

    _sniffer_stop = threading.Event()

    def _make_sniffer(ip):
        def _sniffer_thread():
            _set_thread_realtime(55)
            _pin_thread(1)   # sniffer on core 1, tun_reader on core 0
            _af_packet_sniffer(ip, listen_port, handle_incoming, _sniffer_stop)
        return _sniffer_thread

    for _spoof_ip in spoof_src_ips:
        threading.Thread(target=_make_sniffer(_spoof_ip), daemon=True).start()
        print("[foreign] Sniffer: port={}, expected src={}".format(listen_port, _spoof_ip))
    print("[foreign] Replies: src={} -> {}:{}".format(iran1_ip, iran2_ip, iran2_port))

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("[foreign] Shutting down.")
    finally:
        _sniffer_stop.set()
        sender.close()
        tun.close()


# ---------------------------------------------------------------------------
# Port-forward session multiplexer
# ---------------------------------------------------------------------------

# Frame layout inside each relay payload: [4B session-id big-endian][1B type][data]
_PF_HDR      = struct.Struct("!IB")   # session_id, msg_type
_PF_DATA     = 0x01
_PF_CONNECT  = 0x02
_PF_CLOSE    = 0x03


def _pf_encode(session_id: int, msg_type: int, data: bytes = b"") -> bytes:
    return _PF_HDR.pack(session_id, msg_type) + data


def _pf_decode(frame: bytes):
    """Returns (session_id, msg_type, data) or None on malformed frame."""
    if len(frame) < _PF_HDR.size:
        return None
    sid, mtype = _PF_HDR.unpack_from(frame)
    return sid, mtype, frame[_PF_HDR.size:]


class _PFMuxIran1:
    """
    Multiplexer living on iran1 in portfwd mode.
    Listens for plain TCP clients; tunnels each session over the spoofed channel.
    """

    def __init__(self, listen_port: int, send_fn):
        self._listen_port = listen_port
        self._send        = send_fn          # send_fn(bytes) → puts frame into tunnel
        self._sessions    = {}               # sid -> client socket
        self._lock        = threading.Lock()
        self._next_sid    = 1

    def on_frame(self, frame: bytes) -> None:
        """Called from relay thread when a frame arrives from foreign."""
        decoded = _pf_decode(frame)
        if decoded is None:
            return
        sid, mtype, data = decoded
        with self._lock:
            sock = self._sessions.get(sid)
        if sock is None:
            return
        if mtype == _PF_DATA and data:
            try:
                sock.sendall(data)
            except OSError:
                self._close_session(sid)
        elif mtype == _PF_CLOSE:
            self._close_session(sid)

    def _close_session(self, sid: int) -> None:
        with self._lock:
            sock = self._sessions.pop(sid, None)
        if sock:
            try:
                sock.close()
            except OSError:
                pass

    def close_all_sessions(self) -> None:
        """Close every active session immediately.

        Must be called when the relay connection (iran2→iran1) drops so that
        clients receive a prompt RST/FIN instead of hanging until their own
        keep-alive fires.  _client_reader finally-blocks will try to send a
        _PF_CLOSE frame, which is harmless even if the relay is gone."""
        with self._lock:
            sids = list(self._sessions.keys())
        for sid in sids:
            self._close_session(sid)

    def accept_client(self, conn: socket.socket, addr) -> None:
        """Spawn a thread to handle one client connection."""
        with self._lock:
            sid = self._next_sid
            self._next_sid += 1
            self._sessions[sid] = conn
        # Notify foreign to open remote connection
        self._send(_pf_encode(sid, _PF_CONNECT))
        threading.Thread(target=self._client_reader, args=(sid, conn), daemon=True).start()

    def _client_reader(self, sid: int, conn: socket.socket) -> None:
        try:
            while True:
                data = conn.recv(MTU)
                if not data:
                    break
                self._send(_pf_encode(sid, _PF_DATA, data))
        except OSError:
            pass
        finally:
            self._send(_pf_encode(sid, _PF_CLOSE))
            self._close_session(sid)

    def serve(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self._listen_port))
        srv.listen(256)
        print("[iran1/pf] Listening for clients on port {}".format(self._listen_port))
        try:
            while True:
                conn, addr = srv.accept()
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                conn.setsockopt(socket.SOL_SOCKET,  socket.SO_KEEPALIVE, 1)
                try:
                    conn.setsockopt(socket.IPPROTO_TCP, _TCP_KEEPIDLE,   10)
                    conn.setsockopt(socket.IPPROTO_TCP, _TCP_KEEPINTVL,   3)
                    conn.setsockopt(socket.IPPROTO_TCP, _TCP_KEEPCNT,     3)
                    conn.setsockopt(socket.SOL_SOCKET,  socket.SO_RCVBUF, 4 * 1024 * 1024)
                    conn.setsockopt(socket.SOL_SOCKET,  socket.SO_SNDBUF, 4 * 1024 * 1024)
                except OSError:
                    pass
                self.accept_client(conn, addr)
        except OSError:
            pass
        finally:
            srv.close()


class _PFMuxForeign:
    """
    Multiplexer living on foreign in portfwd mode.
    Receives sessions from iran1; connects each to the local target.
    """

    def __init__(self, target_ip: str, target_port: int, send_fn):
        self._target_ip   = target_ip
        self._target_port = target_port
        self._send        = send_fn
        self._sessions    = {}     # sid -> target socket
        self._lock        = threading.Lock()

    def on_frame(self, frame: bytes) -> None:
        """Called from sniffer thread for every frame received from iran1."""
        decoded = _pf_decode(frame)
        if decoded is None:
            return
        sid, mtype, data = decoded
        if mtype == _PF_CONNECT:
            self._open_session(sid)
        elif mtype == _PF_DATA and data:
            with self._lock:
                sock = self._sessions.get(sid)
            if sock:
                try:
                    sock.sendall(data)
                except OSError:
                    self._close_session(sid)
        elif mtype == _PF_CLOSE:
            self._close_session(sid)

    def _open_session(self, sid: int) -> None:
        """Spawn a thread so connecting to the target never blocks the relay/sniffer thread.
        Blocking here would freeze delivery of _PF_DATA frames for ALL other sessions."""
        threading.Thread(target=self._connect_session, args=(sid,), daemon=True).start()

    def _connect_session(self, sid: int) -> None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY,  1)
            s.setsockopt(socket.SOL_SOCKET,  socket.SO_KEEPALIVE, 1)
            s.setsockopt(socket.SOL_SOCKET,  socket.SO_RCVBUF, 4 * 1024 * 1024)
            s.setsockopt(socket.SOL_SOCKET,  socket.SO_SNDBUF, 4 * 1024 * 1024)
            try:
                s.setsockopt(socket.IPPROTO_TCP, _TCP_KEEPIDLE,  10)
                s.setsockopt(socket.IPPROTO_TCP, _TCP_KEEPINTVL,  3)
                s.setsockopt(socket.IPPROTO_TCP, _TCP_KEEPCNT,    3)
            except OSError:
                pass
            s.settimeout(10.0)   # 10 s connect timeout – avoids indefinite thread leaks
            s.connect((self._target_ip, self._target_port))
            s.settimeout(None)
        except OSError:
            self._send(_pf_encode(sid, _PF_CLOSE))
            return
        with self._lock:
            self._sessions[sid] = s
        threading.Thread(target=self._target_reader, args=(sid, s), daemon=True).start()

    def _close_session(self, sid: int) -> None:
        with self._lock:
            sock = self._sessions.pop(sid, None)
        if sock:
            try:
                sock.close()
            except OSError:
                pass

    def _target_reader(self, sid: int, sock: socket.socket) -> None:
        try:
            while True:
                data = sock.recv(MTU)
                if not data:
                    break
                self._send(_pf_encode(sid, _PF_DATA, data))
        except OSError:
            pass
        finally:
            self._send(_pf_encode(sid, _PF_CLOSE))
            self._close_session(sid)


# ---------------------------------------------------------------------------
# iran1 – portfwd mode
# ---------------------------------------------------------------------------

def run_iran1_portfwd(args):
    """
    Port-forward entry point on iran1.
    Accepts plain TCP clients; multiplexes sessions over the spoofed-raw channel.
    No TUN needed.
    """
    relay_port     = args.relay_port
    spoof_src_ips  = args.spoof_src_ip
    spoof_src_port = args.spoof_src_port
    foreign_ip     = args.foreign_ip
    foreign_port   = args.foreign_port
    pf_listen_port = args.pf_listen_port

    senders = [
        DirectSender(src_ip=ip, dst_ip=foreign_ip,
                     src_port=spoof_src_port, dst_port=foreign_port)
        for ip in spoof_src_ips
    ]
    _seq_counters = [10000] * len(senders)
    _n_senders    = len(senders)
    _sid_lock     = threading.Lock()

    def _send_to_foreign(payload: bytes) -> None:
        # Simple round-robin across senders (sessions are already balanced at open time)
        idx = 0
        if _n_senders > 1:
            # hash first byte of payload (session-id high byte) for consistency
            idx = payload[0] % _n_senders
        with _sid_lock:
            cur = _seq_counters[idx]
            _seq_counters[idx] += len(payload)
        senders[idx].send(payload=payload, seq=cur)

    mux = _PFMuxIran1(listen_port=pf_listen_port, send_fn=_send_to_foreign)

    # Relay listener: accepts framed messages from iran2, delivers to mux
    relay_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    relay_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    relay_server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32 * 1024 * 1024)
    relay_server.bind(("0.0.0.0", relay_port))
    relay_server.listen(64)
    print("[iran1/pf] Relay listener on port {}".format(relay_port))

    def handle_relay(conn, addr):
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        conn.setsockopt(socket.SOL_SOCKET,  socket.SO_RCVBUF,  32 * 1024 * 1024)
        conn.setsockopt(socket.SOL_SOCKET,  socket.SO_SNDBUF,  32 * 1024 * 1024)
        conn.setsockopt(socket.SOL_SOCKET,  socket.SO_KEEPALIVE, 1)
        try:
            conn.setsockopt(socket.IPPROTO_TCP, _TCP_QUICKACK,        1)
            conn.setsockopt(socket.IPPROTO_TCP, _TCP_KEEPIDLE,        5)
            conn.setsockopt(socket.IPPROTO_TCP, _TCP_KEEPINTVL,       2)
            conn.setsockopt(socket.IPPROTO_TCP, _TCP_KEEPCNT,         3)
            conn.setsockopt(socket.IPPROTO_TCP, _TCP_NOTSENT_LOWAT, 4096)
            conn.setsockopt(socket.SOL_SOCKET,  _SO_BUSY_POLL,       50)
            conn.setsockopt(socket.SOL_SOCKET,  socket.SO_PRIORITY,   6)
            conn.setsockopt(socket.IPPROTO_IP,  socket.IP_TOS,      0xB8)
        except OSError:
            pass
        reader = FrameReader(conn)
        try:
            while True:
                frame = reader.read()
                if frame is None:
                    break
                if frame:   # empty frames are keepalive no-ops from iran2
                    mux.on_frame(frame)
        except OSError:
            pass
        finally:
            conn.close()
            # When the relay drops, all in-flight sessions lose their return path.
            # Close them immediately so clients get RST/FIN instead of hanging.
            mux.close_all_sessions()

    def relay_acceptor():
        while True:
            try:
                conn, addr = relay_server.accept()
                threading.Thread(target=handle_relay, args=(conn, addr), daemon=True).start()
            except OSError:
                break

    threading.Thread(target=relay_acceptor, daemon=True).start()

    try:
        mux.serve()   # blocks; spawns client threads internally
    except KeyboardInterrupt:
        print("[iran1/pf] Shutting down.")
    finally:
        for _s in senders:
            _s.close()
        relay_server.close()


# ---------------------------------------------------------------------------
# foreign – portfwd mode
# ---------------------------------------------------------------------------

def run_foreign_portfwd(args):
    """
    Port-forward exit node on foreign.
    Sniffs incoming frames from iran1, connects to pf-target, pipes data back.
    No TUN needed.
    """
    listen_port   = args.listen_port
    spoof_src_ips = args.spoof_src_ip
    iran1_ip      = args.iran1_ip
    iran2_ip      = args.iran2_ip
    iran2_port    = args.iran2_port
    target_ip     = args.pf_target_ip
    target_port   = args.pf_target_port

    seq_counter = 20000
    seq_lock    = threading.Lock()

    sender = DirectSender(
        src_ip=iran1_ip, dst_ip=iran2_ip,
        src_port=listen_port, dst_port=iran2_port,
    )

    def _send_to_iran2(payload: bytes) -> None:
        nonlocal seq_counter
        with seq_lock:
            cur = seq_counter
            seq_counter += len(payload)
        sender.send(payload=payload, seq=cur)

    mux = _PFMuxForeign(target_ip=target_ip, target_port=target_port,
                        send_fn=_send_to_iran2)

    def handle_incoming(payload: bytes) -> None:
        mux.on_frame(payload)

    _sniffer_stop = threading.Event()

    def _make_sniffer(ip):
        def _t():
            _set_thread_realtime(55)
            _pin_thread(1)
            while not _sniffer_stop.is_set():
                _af_packet_sniffer(ip, listen_port, handle_incoming, _sniffer_stop)
                if _sniffer_stop.is_set():
                    break
                print("[foreign/pf] Sniffer({}) exited unexpectedly, restarting...".format(ip))
                _time.sleep(1.0)
        return _t

    for _spoof_ip in spoof_src_ips:
        threading.Thread(target=_make_sniffer(_spoof_ip), daemon=True).start()
        print("[foreign/pf] Sniffer: port={}, expected src={}".format(listen_port, _spoof_ip))
    print("[foreign/pf] Forwarding sessions to {}:{}".format(target_ip, target_port))
    print("[foreign/pf] Replies spoofed src={} -> {}:{}".format(iran1_ip, iran2_ip, iran2_port))

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("[foreign/pf] Shutting down.")
    finally:
        _sniffer_stop.set()
        sender.close()


# ---------------------------------------------------------------------------
# Role: iran1 – direct mode (TUN, no relay server)
# ---------------------------------------------------------------------------

def run_iran1_direct(args):
    """
    Direct TUN mode – no iran2 relay server.
    1. Create TUN, assign tun_cidr.
    2. Read IP packets from TUN -> send to foreign as raw spoofed TCP.
    3. Sniff reply packets from foreign (src=reply_src_ip, dst_port=listen_port)
       -> write raw IP packets back to TUN.
    """
    tun_name       = args.tun_name
    tun_cidr       = args.tun_cidr
    listen_port    = args.listen_port
    reply_src_ip   = args.reply_src_ip
    spoof_src_ips  = args.spoof_src_ip
    spoof_src_port = args.spoof_src_port
    foreign_ip     = args.foreign_ip
    foreign_port   = args.foreign_port

    tun = TunInterface(tun_name).open()
    tun.configure(tun_cidr)

    senders = [
        DirectSender(src_ip=ip, dst_ip=foreign_ip,
                     src_port=spoof_src_port, dst_port=foreign_port)
        for ip in spoof_src_ips
    ]
    _seq_counters = [10000] * len(senders)
    _n_senders    = len(senders)

    def _pick_sender(pkt: bytes) -> int:
        if _n_senders == 1:
            return 0
        if len(pkt) >= 20:
            return (pkt[16] << 24 | pkt[17] << 16 | pkt[18] << 8 | pkt[19]) % _n_senders
        return 0

    # Sniffer: receive reply packets directly from foreign
    _sniffer_stop = threading.Event()

    def handle_incoming(payload: bytes):
        if payload:
            tun.write(payload)

    def _sniffer_thread():
        _set_thread_realtime(55)
        _pin_thread(1)
        _af_packet_sniffer(reply_src_ip, listen_port, handle_incoming, _sniffer_stop)

    threading.Thread(target=_sniffer_thread, daemon=True).start()
    print("[iran1/direct] Sniffer: port={}, reply-src={}".format(listen_port, reply_src_ip))
    print("[iran1/direct] TUN -> foreign {}:{} (spoof src(s)={} port={})".format(
        foreign_ip, foreign_port, spoof_src_ips, spoof_src_port))

    try:
        while True:
            pkt = tun.read()
            if not pkt:
                break
            idx = _pick_sender(pkt)
            cur_seq = _seq_counters[idx]
            _seq_counters[idx] += len(pkt)
            senders[idx].send(payload=pkt, seq=cur_seq)
    except KeyboardInterrupt:
        print("[iran1/direct] Shutting down.")
    finally:
        _sniffer_stop.set()
        for _s in senders:
            _s.close()
        tun.close()


# ---------------------------------------------------------------------------
# Role: foreign – direct mode (TUN, no relay server)
# ---------------------------------------------------------------------------

def run_foreign_direct(args):
    """
    Direct TUN mode – no iran2 relay server.
    1. Create TUN, assign tun_cidr.
    2. Sniff incoming packets (src=spoof_src_ip) -> write raw IP packet to TUN.
    3. TUN reader: read reply IP packets -> send spoofed raw TCP (src=reply_src_ip)
       directly to iran1 (no iran2).
    """
    tun_name         = args.tun_name
    tun_cidr         = args.tun_cidr
    listen_port      = args.listen_port
    spoof_src_ips    = args.spoof_src_ip
    iran1_ip         = args.iran1_ip
    iran1_sniff_port = args.iran1_sniff_port
    reply_src_ip     = args.reply_src_ip

    tun = TunInterface(tun_name).open()
    tun.configure(tun_cidr)

    seq_counter = 20000

    sender = DirectSender(
        src_ip=reply_src_ip, dst_ip=iran1_ip,
        src_port=listen_port, dst_port=iran1_sniff_port,
    )

    def tun_reader():
        _set_thread_realtime(60)
        _pin_thread(0)
        nonlocal seq_counter
        while True:
            pkt = tun.read()
            if not pkt:
                break
            cur_seq = seq_counter
            seq_counter += len(pkt)
            sender.send(payload=pkt, seq=cur_seq)

    threading.Thread(target=tun_reader, daemon=True).start()

    def handle_incoming(payload: bytes):
        tun.write(payload)

    _sniffer_stop = threading.Event()

    def _make_sniffer(ip):
        def _sniffer_thread():
            _set_thread_realtime(55)
            _pin_thread(1)
            _af_packet_sniffer(ip, listen_port, handle_incoming, _sniffer_stop)
        return _sniffer_thread

    for _spoof_ip in spoof_src_ips:
        threading.Thread(target=_make_sniffer(_spoof_ip), daemon=True).start()
        print("[foreign/direct] Sniffer: port={}, expected src={}".format(listen_port, _spoof_ip))
    print("[foreign/direct] Replies: src={} -> {}:{}".format(reply_src_ip, iran1_ip, iran1_sniff_port))

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("[foreign/direct] Shutting down.")
    finally:
        _sniffer_stop.set()
        sender.close()
        tun.close()


# ---------------------------------------------------------------------------
# iran1 – direct portfwd mode (no relay server)
# ---------------------------------------------------------------------------

def run_iran1_direct_portfwd(args):
    """
    Direct port-forward mode – no iran2 relay server.
    Accepts plain TCP clients; multiplexes sessions over the spoofed-raw channel.
    Sniffs reply frames from foreign directly (no TCP relay listener needed).
    """
    listen_port    = args.listen_port
    reply_src_ip   = args.reply_src_ip
    spoof_src_ips  = args.spoof_src_ip
    spoof_src_port = args.spoof_src_port
    foreign_ip     = args.foreign_ip
    foreign_port   = args.foreign_port
    pf_listen_port = args.pf_listen_port

    senders = [
        DirectSender(src_ip=ip, dst_ip=foreign_ip,
                     src_port=spoof_src_port, dst_port=foreign_port)
        for ip in spoof_src_ips
    ]
    _seq_counters = [10000] * len(senders)
    _n_senders    = len(senders)
    _sid_lock     = threading.Lock()

    def _send_to_foreign(payload: bytes) -> None:
        idx = 0
        if _n_senders > 1:
            idx = payload[0] % _n_senders
        with _sid_lock:
            cur = _seq_counters[idx]
            _seq_counters[idx] += len(payload)
        senders[idx].send(payload=payload, seq=cur)

    mux = _PFMuxIran1(listen_port=pf_listen_port, send_fn=_send_to_foreign)

    # Sniffer: receive framed replies directly from foreign
    _sniffer_stop = threading.Event()

    def handle_incoming(payload: bytes) -> None:
        if payload:
            mux.on_frame(payload)

    def _sniffer_thread():
        """Auto-restarting sniffer wrapper.
        If _af_packet_sniffer exits due to an OSError (e.g. interface reset),
        close all active sessions immediately so clients get RST/FIN rather
        than hanging indefinitely, then restart the sniffer after a short delay."""
        _set_thread_realtime(55)
        _pin_thread(1)
        while not _sniffer_stop.is_set():
            _af_packet_sniffer(reply_src_ip, listen_port, handle_incoming, _sniffer_stop)
            if _sniffer_stop.is_set():
                break
            # Unexpected exit – clean up hanging sessions before restarting
            print("[iran1/direct-pf] Sniffer exited unexpectedly, closing sessions and restarting...")
            mux.close_all_sessions()
            _time.sleep(1.0)

    threading.Thread(target=_sniffer_thread, daemon=True).start()
    print("[iran1/direct-pf] Sniffer: port={}, reply-src={}".format(listen_port, reply_src_ip))

    try:
        mux.serve()
    except KeyboardInterrupt:
        print("[iran1/direct-pf] Shutting down.")
    finally:
        _sniffer_stop.set()
        mux.close_all_sessions()
        for _s in senders:
            _s.close()


# ---------------------------------------------------------------------------
# foreign – direct portfwd mode (no relay server)
# ---------------------------------------------------------------------------

def run_foreign_direct_portfwd(args):
    """
    Direct port-forward exit node – no iran2 relay server.
    Sniffs incoming frames from iran1, connects to pf-target, sends replies
    directly back to iran1 via spoofed raw TCP.
    """
    listen_port      = args.listen_port
    spoof_src_ips    = args.spoof_src_ip
    iran1_ip         = args.iran1_ip
    iran1_sniff_port = args.iran1_sniff_port
    reply_src_ip     = args.reply_src_ip
    target_ip        = args.pf_target_ip
    target_port      = args.pf_target_port

    seq_counter = 20000
    seq_lock    = threading.Lock()

    sender = DirectSender(
        src_ip=reply_src_ip, dst_ip=iran1_ip,
        src_port=listen_port, dst_port=iran1_sniff_port,
    )

    def _send_to_iran1(payload: bytes) -> None:
        nonlocal seq_counter
        with seq_lock:
            cur = seq_counter
            seq_counter += len(payload)
        sender.send(payload=payload, seq=cur)

    mux = _PFMuxForeign(target_ip=target_ip, target_port=target_port,
                        send_fn=_send_to_iran1)

    def handle_incoming(payload: bytes) -> None:
        mux.on_frame(payload)

    _sniffer_stop = threading.Event()

    def _make_sniffer(ip):
        def _t():
            """Auto-restarting sniffer wrapper for each spoofed source IP."""
            _set_thread_realtime(55)
            _pin_thread(1)
            while not _sniffer_stop.is_set():
                _af_packet_sniffer(ip, listen_port, handle_incoming, _sniffer_stop)
                if _sniffer_stop.is_set():
                    break
                print("[foreign/direct-pf] Sniffer({}) exited unexpectedly, restarting...".format(ip))
                _time.sleep(1.0)
        return _t

    for _spoof_ip in spoof_src_ips:
        threading.Thread(target=_make_sniffer(_spoof_ip), daemon=True).start()
        print("[foreign/direct-pf] Sniffer: port={}, expected src={}".format(listen_port, _spoof_ip))
    print("[foreign/direct-pf] Forwarding sessions to {}:{}".format(target_ip, target_port))
    print("[foreign/direct-pf] Replies: src={} -> {}:{}".format(reply_src_ip, iran1_ip, iran1_sniff_port))

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("[foreign/direct-pf] Shutting down.")
    finally:
        _sniffer_stop.set()
        sender.close()


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        description="Spoof TUN Tunnel",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="role", required=True)

    # iran1
    p1 = sub.add_parser("iran1", help="Entry point with TUN interface")
    p1.add_argument("--mode",           default="tun",
                    choices=["tun", "portfwd", "direct", "direct-portfwd"],
                    help="Tunnel mode: tun (default), portfwd, direct (no iran2, TUN), "
                         "direct-portfwd (no iran2, port-forward)")
    p1.add_argument("--tun-name",       default="tun0",
                    help="TUN device name (default: tun0) [tun/direct modes only]")
    p1.add_argument("--tun-cidr",
                    help="TUN address, e.g. 10.8.0.1/24 [tun/direct modes only]")
    p1.add_argument("--relay-port",     type=int,
                    help="Port to accept framed relay connections from iran2 [tun/portfwd modes]")
    p1.add_argument("--listen-port",    type=int,
                    help="Port to sniff on for reply packets from foreign [direct modes]")
    p1.add_argument("--reply-src-ip",
                    help="IP foreign spoofs as src in replies – must match on both sides [direct modes]")
    p1.add_argument("--spoof-src-ip",   required=True, nargs='+',
                    help="Spoofed source IP(s) used when sending to foreign (multiple = round-robin)")
    p1.add_argument("--spoof-src-port", type=int, required=True,
                    help="Spoofed source port used when sending to foreign")
    p1.add_argument("--foreign-ip",     required=True,  help="Foreign server IP")
    p1.add_argument("--foreign-port",   type=int, required=True, help="Foreign server port")
    p1.add_argument("--pf-listen-port", type=int, default=1080,
                    help="Local TCP port to accept clients on [portfwd/direct-portfwd modes, default: 1080]")

    # iran2
    p2 = sub.add_parser("iran2", help="Middle relay (no TUN needed)")
    p2.add_argument("--listen-port", type=int, required=True,
                    help="Port to sniff for spoofed packets from foreign")
    p2.add_argument("--iran1-ip",    required=True,
                    help="Iran1 IP (foreign spoofs src as this; also relay destination)")
    p2.add_argument("--iran1-port",  type=int, required=True,
                    help="Relay port on iran1")

    # foreign
    p3 = sub.add_parser("foreign", help="Exit node with TUN interface")
    p3.add_argument("--mode",         default="tun",
                    choices=["tun", "portfwd", "direct", "direct-portfwd"],
                    help="Tunnel mode: tun (default), portfwd, direct (no iran2, TUN), "
                         "direct-portfwd (no iran2, port-forward)")
    p3.add_argument("--tun-name",     default="tun0",
                    help="TUN device name (default: tun0) [tun/direct modes only]")
    p3.add_argument("--tun-cidr",
                    help="TUN address, e.g. 10.8.0.2/24 [tun/direct modes only]")
    p3.add_argument("--listen-port",  type=int, required=True,
                    help="Port to sniff for incoming packets from iran1")
    p3.add_argument("--spoof-src-ip", required=True, nargs='+',
                    help="Spoofed source IP(s) iran1 used (to filter incoming; one sniffer per IP)")
    p3.add_argument("--iran1-ip",     required=True,
                    help="Iran1 IP (used as spoofed source in replies / relay destination)")
    p3.add_argument("--iran2-ip",     default=None,  help="Iran2 IP (reply destination) [tun/portfwd modes]")
    p3.add_argument("--iran2-port",   type=int, default=None,
                    help="Port on iran2 for spoofed reply [tun/portfwd modes]")
    p3.add_argument("--iran1-sniff-port", type=int, default=None,
                    help="Port on iran1 to target for direct replies [direct modes]")
    p3.add_argument("--reply-src-ip", default=None,
                    help="IP foreign spoofs as src in replies – must match iran1's value [direct modes]")
    p3.add_argument("--pf-target-ip",   default="127.0.0.1",
                    help="Target host to forward to [portfwd/direct-portfwd modes, default: 127.0.0.1]")
    p3.add_argument("--pf-target-port", type=int, default=443,
                    help="Target port to forward to [portfwd/direct-portfwd modes, default: 443]")

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _apply_sysctl() -> None:
    """Auto-apply kernel network tuning at startup (requires root + sysctl binary)."""
    settings = [
        ("net.core.rmem_max",                "134217728"),
        ("net.core.wmem_max",                "134217728"),
        ("net.core.netdev_max_backlog",       "250000"),
        ("net.core.busy_read",               "50"),     # system-wide NIC busy-poll (µs)
        ("net.core.busy_poll",               "50"),
        ("net.ipv4.tcp_rmem",               "4096 87380 134217728"),
        ("net.ipv4.tcp_wmem",               "4096 65536 134217728"),
        ("net.ipv4.tcp_congestion_control",  "bbr"),
        ("net.ipv4.tcp_low_latency",         "1"),
        ("net.ipv4.tcp_autocorking",         "0"),     # disable coalescing small writes
        ("net.ipv4.tcp_fastopen",            "3"),
        ("net.ipv4.tcp_timestamps",          "0"),
        ("net.ipv4.tcp_sack",               "1"),
        ("net.ipv4.tcp_no_metrics_save",     "1"),     # don't cache stale RTT between conns
        ("net.ipv4.conf.all.rp_filter",      "0"),     # allow spoofed-src packets to pass
        ("net.ipv4.conf.default.rp_filter",  "0"),
    ]
    ok = []
    for k, v in settings:
        try:
            subprocess.run(["sysctl", "-w", "{}={}".format(k, v)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           check=True)
            ok.append(k)
        except Exception:
            pass
    print("[sysctl] Applied {} / {} settings.".format(len(ok), len(settings)))


if __name__ == "__main__":
    if os.name == "nt":
        print("[ERROR] TUN interfaces require Linux. Not supported on Windows.")
        sys.exit(1)
    if os.geteuid() != 0:
        print("[WARNING] TUN + raw sockets require root. Run with sudo.")
    else:
        try:
            os.nice(-20)   # maximum nice priority
        except OSError:
            pass
        _set_thread_realtime(70)   # SCHED_FIFO for the main I/O thread
        _pin_thread(0)             # anchor main thread to core 0
        _apply_sysctl()

    args = build_parser().parse_args()

    # Validate mode-specific required args
    if args.role in ("iran1", "foreign"):
        if args.mode in ("tun", "direct") and not args.tun_cidr:
            build_parser().error("--tun-cidr is required in tun/direct mode")
        if args.mode in ("tun", "portfwd"):
            if args.role == "iran1" and not args.relay_port:
                build_parser().error("--relay-port is required in tun/portfwd mode")
            if args.role == "foreign":
                if not args.iran2_ip or not args.iran2_port:
                    build_parser().error("--iran2-ip and --iran2-port are required in tun/portfwd mode")
        if args.mode in ("direct", "direct-portfwd"):
            if args.role == "iran1":
                if not args.listen_port:
                    build_parser().error("--listen-port is required in direct mode")
                if not args.reply_src_ip:
                    build_parser().error("--reply-src-ip is required in direct mode")
            if args.role == "foreign":
                if not args.iran1_sniff_port:
                    build_parser().error("--iran1-sniff-port is required in direct mode")
                if not args.reply_src_ip:
                    build_parser().error("--reply-src-ip is required in direct mode")
        if args.role == "iran1" and args.mode == "portfwd" and not args.pf_listen_port:
            build_parser().error("--pf-listen-port is required in portfwd mode")
        if args.role == "foreign" and args.mode in ("portfwd", "direct-portfwd"):
            if not args.pf_target_ip or not args.pf_target_port:
                build_parser().error("--pf-target-ip and --pf-target-port are required in portfwd mode")

    _dispatch = {
        ("iran1",   "tun"):            run_iran1,
        ("iran1",   "portfwd"):        run_iran1_portfwd,
        ("iran1",   "direct"):         run_iran1_direct,
        ("iran1",   "direct-portfwd"): run_iran1_direct_portfwd,
        ("iran2",   None):             run_iran2,
        ("foreign", "tun"):            run_foreign,
        ("foreign", "portfwd"):        run_foreign_portfwd,
        ("foreign", "direct"):         run_foreign_direct,
        ("foreign", "direct-portfwd"): run_foreign_direct_portfwd,
    }
    mode = getattr(args, "mode", None)
    fn   = _dispatch.get((args.role, mode)) or _dispatch.get((args.role, None))
    fn(args)
