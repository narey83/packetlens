#!/usr/bin/env python3

"""
Packetlens - defensive DDoS forensics for packet captures

Single-pass, streaming forensic analyzer that flags indicators of:

  - TCP floods         (SYN / ACK / RST / FIN)
  - UDP floods
  - ICMP floods
  - IP fragmentation floods
  - DNS query floods
  - Reflection / amplification abuse across ~19 known reflector services
    (NTP, DNS, SSDP, memcached, CLDAP, SNMP, chargen, QOTD, mDNS, ...)

What makes it "advanced" compared to a naive average-rate check:

  * Streams the capture with PcapReader instead of loading it all into RAM,
    so multi-GB captures are fine.
  * Detects PEAK bursts using time-windowed buckets, not just the whole-capture
    average. A 30-second capture with a 2-second 900k-pps burst is obvious to a
    peak detector and invisible to an average.
  * Analyzes the SOURCE distribution per victim: unique source count,
    distributed-vs-single-source, and a spoofing/randomization heuristic.
  * Machine-readable JSON output and meaningful exit codes for automation.

Packetlens is a heuristic analysis tool, not a production/inline DDoS detector.

Requires:
    pip install scapy

Usage:
    python3 ddos_analyzer.py capture.pcap
    python3 ddos_analyzer.py capture.pcap --json > findings.json
    python3 ddos_analyzer.py capture.pcap --window 0.5 --syn-pps 2000 --top 20
"""

import argparse
import json
import math
import hashlib
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from typing import Optional

from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
from scapy.layers.dns import DNS


# ---------------------------------------------------------------------------
# Detection thresholds (all overridable from the command line)
# ---------------------------------------------------------------------------

@dataclass
class Thresholds:
    # Peak packets-per-second, measured over a sliding time window, that a
    # single victim must exceed before a flood is reported.
    syn_pps: float = 500.0
    ack_pps: float = 2000.0
    rst_pps: float = 1000.0
    fin_pps: float = 1000.0
    udp_pps: float = 1000.0
    icmp_pps: float = 500.0
    frag_pps: float = 500.0
    dns_query_pps: float = 500.0

    # Reflection/amplification: peak responses-per-second toward a victim.
    reflect_pps: float = 200.0

    # Optional guard: require this proportion of a category's traffic to hit
    # one destination before reporting. Default 0.0 = report but do not gate,
    # so simultaneous multi-vector attacks are not hidden by each other. The
    # per-victim peak thresholds already ensure there is a single target.
    concentration: float = 0.0

    # A victim seen with at least this many distinct sources is "distributed".
    # Generic volumetric floods only fire on the signature path when the target
    # is distributed -- benign one-directional traffic to a host (a download,
    # a media stream) comes from one or a few sources, real floods from many.
    distributed_sources: int = 25
    # Reflection needs at least this many distinct reflectors on the signature
    # path (a benign NTP/DNS client only hears from a handful of servers).
    min_reflectors: int = 5

    # Time window (seconds) over which peak rates are measured.
    window: float = 1.0

    # --- Signature (rate-independent) detection ---
    # Many real captures are anonymized, filtered, one-way samples: the whole
    # file is the attack, aimed at one victim, but only at sample rates. These
    # let the detectors fire on the attack *fingerprint* even when the volume
    # never approaches the pps thresholds above (rate then only escalates
    # severity). Set signatures=False to disable and use pure rate detection.
    signatures: bool = True
    # Minimum packets of a signature toward one victim to consider it.
    min_sig_packets: int = 20
    # A destination receiving at least this share of all IP packets is treated
    # as the attack target. Kept high because benign two-way traffic splits
    # ~50/50 between endpoints, while these one-way attack samples are ~100%.
    target_share: float = 0.8
    # A signature must be at least this share of the target's inbound traffic
    # to fire (keeps stray control packets from tripping a detector).
    sig_victim_share: float = 0.2

    def validate(self) -> "Thresholds":
        """Reject values that would make rate calculations nonsensical."""
        rates = (
            "syn_pps", "ack_pps", "rst_pps", "fin_pps", "udp_pps",
            "icmp_pps", "frag_pps", "dns_query_pps", "reflect_pps",
        )
        for name in rates:
            value = getattr(self, name)
            if not math.isfinite(value) or value < 0:
                raise ValueError(f"{name} must be a finite number >= 0")
        if not math.isfinite(self.window) or self.window <= 0:
            raise ValueError("window must be a finite number > 0")
        for name in ("concentration", "target_share", "sig_victim_share"):
            value = getattr(self, name)
            if not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError(f"{name} must be between 0 and 1")
        for name in ("distributed_sources", "min_reflectors",
                     "min_sig_packets"):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be at least 1")
        return self


# Known reflector/amplifier services keyed by UDP *source* port. A high volume
# of packets arriving *from* one of these ports toward a single victim is the
# signature of a reflection/amplification attack (the victim's address was
# spoofed as the request source). The note is the widely-cited amplification
# factor for context; the tool reports the observed average response size.
REFLECTORS = {
    17:    ("QOTD", "~140x"),
    19:    ("Chargen", "~359x"),
    53:    ("DNS", "~28-54x"),
    69:    ("TFTP", "~60x"),
    111:   ("Portmap/RPC", "~7-28x"),
    123:   ("NTP", "~557x"),
    137:   ("NetBIOS", "~3.8x"),
    161:   ("SNMPv2", "~6.3x"),
    389:   ("CLDAP", "~56-70x"),
    500:   ("ISAKMP/IKE", ""),
    520:   ("RIPv1", "~131x"),
    626:   ("serialnumberd", "~"),
    1900:  ("SSDP", "~30x"),
    3283:  ("Apple ARD", "~35x"),
    3702:  ("WS-Discovery", "~15x"),
    4500:  ("ISAKMP/NAT-T", ""),
    5060:  ("SIP", "~"),
    5353:  ("mDNS", "~10x"),
    5683:  ("CoAP", "~35x"),
    10001: ("Ubiquiti (UBNT)", "~30x"),
    11211: ("memcached", "up to 51000x"),
    27015: ("Steam/Source", "~5x"),
    30718: ("Lantronix", "~30x"),
    37810: ("DVR/IoT (DVRIP)", "~"),
    47808: ("BACnet", "~24x"),
}

# Reverse map: reflector service name -> UDP source port (for FlowSpec rules).
REFLECTOR_PORT = {name: port for port, (name, _amp) in REFLECTORS.items()}


# Short, non-authoritative mitigation hints shown alongside each finding.
MITIGATIONS = {
    "TCP SYN Flood":
        "Enable SYN cookies, rate-limit half-open connections, deploy an "
        "upstream scrubbing/SYN-proxy.",
    "TCP ACK Flood":
        "Drop out-of-state ACKs at a stateful firewall; use upstream scrubbing "
        "since ACK floods bypass SYN cookies.",
    "TCP RST Flood":
        "Filter spoofed RSTs upstream; verify sequence numbers with a stateful "
        "device.",
    "TCP FIN Flood":
        "Drop out-of-state FINs at a stateful firewall / scrubbing center.",
    "UDP Flood":
        "Rate-limit UDP per source/destination; block unused UDP ports at the "
        "edge; engage upstream scrubbing.",
    "ICMP Flood":
        "Rate-limit or block ICMP echo at the edge; enable upstream scrubbing.",
    "IP Fragmentation Flood":
        "Rate-limit fragments; drop fragments to services that never fragment; "
        "reassemble upstream.",
    "DNS Query Flood":
        "Enable response rate limiting (RRL), anycast the resolver, cache "
        "aggressively, and filter garbage QNAMEs.",
    "Reflection / Amplification":
        "Block or rate-limit the reflector's source port at the edge; deploy "
        "BCP38 anti-spoofing upstream; use scrubbing.",
    "TCP SYN-ACK Reflection":
        "Drop unsolicited SYN-ACKs (no matching outbound SYN) at a stateful "
        "firewall; use upstream scrubbing; deploy BCP38 anti-spoofing.",
    "Crafted Packets (sport = dport)":
        "Drop packets where source port equals destination port (LAND-style); "
        "enable anti-spoofing (BCP38/uRPF) upstream.",
    "Malformed Packets (UDP port 0)":
        "Drop UDP to/from port 0 at the edge; these are always malformed / "
        "crafted and safe to filter.",
    "Non-standard IP Protocol":
        "Filter unexpected IP protocol numbers at the edge; allow only the "
        "protocols your services actually use.",
}

# Ordered response playbooks. These complement the one-line hint above: first
# contain the immediate impact, then harden the service and upstream edge.
# They are deliberately operational but vendor-neutral; an analyst must still
# review scope and collateral risk before applying a control.
MITIGATION_TECHNIQUES = {
    "TCP SYN Flood": [
        "Enable SYN cookies and reduce the SYN-RECEIVED timeout/backlog pressure.",
        "Use a stateful SYN proxy at the load balancer, firewall, or scrubbing edge.",
        "Rate-limit new connections per source and protect known service ports only.",
        "Ask the transit provider to filter or scrub before the access link saturates.",
    ],
    "TCP ACK Flood": [
        "Drop out-of-state ACK packets with a stateful firewall or ACL pipeline.",
        "Rate-limit anomalous ACK-only traffic toward the affected service.",
        "Use upstream scrubbing when packet rate threatens edge or firewall capacity.",
        "Do not deploy a blanket stateless ACK drop; it disrupts established sessions.",
    ],
    "TCP RST Flood": [
        "Require valid connection state and sequence windows before accepting resets.",
        "Rate-limit invalid or out-of-state RST packets at the nearest capable edge.",
        "Apply BCP38/uRPF anti-spoofing where source validation is operationally safe.",
        "Escalate to upstream scrubbing if local stateful devices are overloaded.",
    ],
    "TCP FIN Flood": [
        "Drop FIN packets that do not belong to an established connection.",
        "Rate-limit abnormal FIN rates per source and destination service.",
        "Tune connection aging cautiously to release state without harming clients.",
        "Move filtering upstream if the attack saturates the local circuit.",
    ],
    "UDP Flood": [
        "Block UDP destination ports that the victim does not intentionally serve.",
        "Rate-limit the affected UDP service by destination and, where useful, source.",
        "Use anycast, load distribution, or upstream scrubbing for required UDP services.",
        "Apply source validation and provider ACLs as close to spoofed traffic as possible.",
    ],
    "ICMP Flood": [
        "Police ICMP by type and code instead of blocking all control traffic blindly.",
        "Prioritize essential ICMP such as Packet Too Big and unreachable messages.",
        "Rate-limit echo requests at the edge and protect control-plane processing.",
        "Use upstream filtering when the inbound link is the constrained resource.",
    ],
    "IP Fragmentation Flood": [
        "Drop fragments for services and protocols that never legitimately require them.",
        "Rate-limit fragments and cap reassembly queues, memory, and timeout values.",
        "Normalize or reassemble suspicious fragments on a protected upstream device.",
        "Preserve required IPv6 fragmentation and Path MTU behavior when writing policy.",
    ],
    "DNS Query Flood": [
        "Enable DNS Response Rate Limiting and per-client query controls.",
        "Cache aggressively and use anycast or multiple authoritative nodes.",
        "Filter invalid query shapes and abusive QNAME patterns at a DNS-aware layer.",
        "Keep recursion access-controlled and separate recursive from authoritative roles.",
    ],
    "Reflection / Amplification": [
        "Filter or police responses from the identified reflector source port to the victim.",
        "Engage upstream scrubbing before amplified traffic fills the access circuit.",
        "Deploy BCP38/uRPF source validation to prevent spoofed requests in your networks.",
        "Disable exposed amplification services or configure them for authenticated clients.",
    ],
    "TCP SYN-ACK Reflection": [
        "Drop unsolicited SYN-ACKs that have no corresponding outbound SYN state.",
        "Rate-limit SYN-ACK traffic toward the victim at the provider or scrubbing edge.",
        "Use BCP38/uRPF to reduce the spoofed SYN requests that trigger reflection.",
        "Avoid filtering valid SYN-ACKs for client workloads sharing the protected address.",
    ],
    "Crafted Packets (sport = dport)": [
        "Drop equal source/destination-port packets when no legitimate application needs them.",
        "Constrain the ACL to the victim, protocol, and observed fixed port where possible.",
        "Enable BCP38/uRPF source validation to reduce spoofed crafted traffic.",
        "Log sampled matches and verify that the signature persists before broadening policy.",
    ],
    "Malformed Packets (UDP port 0)": [
        "Drop UDP packets whose source or destination port is zero at the edge.",
        "Use a victim-scoped FlowSpec port match if upstream enforcement is required.",
        "Rate-limit logging so malformed-packet floods cannot exhaust telemetry systems.",
        "Check internal sources for broken software or compromise before blocking them broadly.",
    ],
    "Non-standard IP Protocol": [
        "Identify the observed IP protocol number before creating a filtering rule.",
        "Allow-list only the IP protocols intentionally used by the protected service.",
        "Filter the specific unexpected protocol toward the victim at the upstream edge.",
        "Confirm legitimate GRE, ESP, AH, and tunnelling requirements before enforcement.",
    ],
}

# Base severity for a signature match before any rate-based escalation.
BASE_SEVERITY = {
    "Reflection / Amplification": "HIGH",
    "TCP SYN-ACK Reflection": "HIGH",
    "TCP SYN Flood": "MEDIUM",
    "TCP ACK Flood": "MEDIUM",
    "TCP RST Flood": "MEDIUM",
    "TCP FIN Flood": "MEDIUM",
    "UDP Flood": "MEDIUM",
    "ICMP Flood": "MEDIUM",
    "IP Fragmentation Flood": "MEDIUM",
    "DNS Query Flood": "MEDIUM",
    "Crafted Packets (sport = dport)": "MEDIUM",
    "Malformed Packets (UDP port 0)": "MEDIUM",
    "Non-standard IP Protocol": "MEDIUM",
}

RESET = "\033[0m"
SEVERITY_COLORS = {
    "CRITICAL": "\033[1;37;41m",  # white on red
    "HIGH":     "\033[1;31m",     # bold red
    "MEDIUM":   "\033[1;33m",     # bold yellow
    "LOW":      "\033[36m",       # cyan
}

# Cap on the per-victim source set to bound memory on heavily spoofed captures.
SOURCE_TRACK_CAP = 200_000


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def rate(count: int, duration: float) -> float:
    return count / duration if duration > 0 else 0.0


def percentage(part: int, total: int) -> float:
    return (part / total) * 100 if total else 0.0


def severity_for_rate(observed: float, threshold: float) -> str:
    ratio = observed / threshold if threshold else 0.0
    if ratio >= 10:
        return "CRITICAL"
    if ratio >= 5:
        return "HIGH"
    if ratio >= 2:
        return "MEDIUM"
    return "LOW"


SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:,.1f} {unit}"
        n /= 1024
    return f"{n:,.1f} TB"


# ---------------------------------------------------------------------------
# Per-category, per-victim accumulator
# ---------------------------------------------------------------------------

class CategoryTracker:
    """Accumulates traffic of one category (e.g. SYN packets) keyed by victim.

    Tracks packet counts, byte counts, per-window buckets (for peak-rate
    detection), and a bounded set of distinct sources (for distribution and
    spoofing analysis).
    """

    def __init__(self):
        self.count = Counter()                     # victim -> packets
        self.bytes = Counter()                     # victim -> bytes
        self.buckets = defaultdict(Counter)        # victim -> {bucket: packets}
        self.sources = defaultdict(set)            # victim -> {src, ...}
        self.sources_capped = set()                # victims whose set overflowed
        self.dports = defaultdict(Counter)         # victim -> {dst port: packets}
        self.sizes = defaultdict(Counter)          # victim -> {packet bytes: packets}
        self.icmp_types = defaultdict(Counter)     # victim -> {type: packets}
        self.protocols = defaultdict(Counter)      # victim -> {IP proto: packets}

    def add(self, victim: str, bucket: int, size: int, src: str,
            dport: int = None, icmp_type: int = None,
            protocol: int = None) -> None:
        self.count[victim] += 1
        self.bytes[victim] += size
        self.buckets[victim][bucket] += 1
        self.sizes[victim][size] += 1

        srcs = self.sources[victim]
        if len(srcs) < SOURCE_TRACK_CAP:
            srcs.add(src)
        else:
            self.sources_capped.add(victim)

        if dport is not None:
            self.dports[victim][dport] += 1
        if icmp_type is not None:
            self.icmp_types[victim][icmp_type] += 1
        if protocol is not None:
            self.protocols[victim][protocol] += 1

    def total(self) -> int:
        return sum(self.count.values())

    def top_dport(self, victim: str, dominance: float = 0.6):
        """Most common destination port for a victim, but only if it clearly
        dominates (so a FlowSpec rule can safely narrow to it). Else None."""
        ports = self.dports.get(victim)
        if not ports:
            return None
        port, hits = ports.most_common(1)[0]
        total = sum(ports.values())
        return port if total and hits / total >= dominance else None

    @staticmethod
    def dominant(counter: Counter, dominance: float = 0.6):
        """Return the leading value only when it safely represents the flow."""
        if not counter:
            return None
        value, hits = counter.most_common(1)[0]
        total = sum(counter.values())
        return value if total and hits / total >= dominance else None

    def size_floor(self, victim: str, coverage: float = 0.9):
        """Lower packet-size bound retaining at least ``coverage`` of packets."""
        sizes = self.sizes.get(victim)
        if not sizes:
            return None
        total = sum(sizes.values())
        discard = total * (1 - coverage)
        seen = 0
        for size, count in sorted(sizes.items()):
            if seen + count > discard:
                return size
            seen += count
        return min(sizes)

    def peak(self, victim: str, window: float) -> tuple:
        """Return (peak_pps, bucket_index) for the busiest window."""
        buckets = self.buckets.get(victim)
        if not buckets:
            return 0.0, 0
        idx, peak_count = max(buckets.items(), key=lambda kv: kv[1])
        return peak_count / window, idx

    def unique_sources(self, victim: str) -> tuple:
        """Return (count, capped) distinct sources seen for this victim."""
        n = len(self.sources.get(victim, ()))
        return n, victim in self.sources_capped

    def source_spread(self, victim: str) -> int:
        """Distinct source networks (IPv4 /16, IPv6 /32) for this victim.

        A widely-spread source set is the signature of spoofing / a real
        botnet; benign one-directional traffic clusters in a few networks.
        Derived from the stored source set, so it costs nothing at ingest.
        """
        nets = set()
        for s in self.sources.get(victim, ()):
            if ":" in s:
                nets.add(":".join(s.split(":")[:2]))
            else:
                parts = s.split(".")
                nets.add(".".join(parts[:2]) if len(parts) >= 2 else s)
        return len(nets)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    attack: str
    severity: str
    victim: str
    peak_pps: float
    avg_pps: float
    total_packets: int
    unique_sources: int
    distributed: bool
    evidence: str
    mitigation: str
    mitigation_techniques: list = field(default_factory=list)
    method: str = "rate"          # "rate", "signature", or "rate+signature"
    confidence: str = "high"      # "high" or "medium"
    peak_offset_s: float = 0.0
    mbps: Optional[float] = None
    extra: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Adaptive-resolution timeline histogram
# ---------------------------------------------------------------------------

class TimelineHistogram:
    """Memory-bounded, adaptive-resolution packet-rate histogram for charting.

    The detection window (e.g. 1 s) is far too coarse to chart a sub-second
    capture: every packet lands in one bucket and the timeline is a single
    spike. This keeps up to ``max_buckets`` buckets at the finest bucket size
    that fits the capture. The size starts small and doubles -- merging existing
    buckets -- whenever the span would overflow, so a 0.8 s flood and a
    multi-hour capture both render a real curve while memory stays bounded.
    Buckets are anchored to the first packet seen; empty spans between bursts
    are preserved as zeros by the reader.
    """

    _PROTO_INDEX = {"TCP": 0, "UDP": 1, "ICMP": 2}

    def __init__(self, max_buckets: int = 1000, init_size: float = 0.001):
        self.size = init_size          # seconds per bucket (grows as needed)
        self.max_buckets = max_buckets
        self.first = None
        self.min_idx = None
        self.max_idx = None
        self.buckets = {}              # idx -> [tcp, udp, icmp, other, total]

    def add(self, ts: float, proto: str) -> None:
        if self.first is None:
            self.first = ts
        idx = int((ts - self.first) // self.size)
        bucket = self.buckets.get(idx)
        if bucket is None:
            bucket = [0, 0, 0, 0, 0]
            self.buckets[idx] = bucket
            self.min_idx = idx if self.min_idx is None else min(self.min_idx, idx)
            self.max_idx = idx if self.max_idx is None else max(self.max_idx, idx)
        bucket[self._PROTO_INDEX.get(proto, 3)] += 1
        bucket[4] += 1
        if self.max_idx - self.min_idx >= self.max_buckets:
            self._coarsen()

    def _coarsen(self) -> None:
        while self.max_idx - self.min_idx >= self.max_buckets:
            self.size *= 2
            merged = {}
            for idx, bucket in self.buckets.items():
                ni = idx // 2  # floors toward -inf; correct for doubling size
                target = merged.get(ni)
                if target is None:
                    merged[ni] = list(bucket)
                else:
                    for k in range(5):
                        target[k] += bucket[k]
            self.buckets = merged
            self.min_idx = min(merged)
            self.max_idx = max(merged)

    def rows(self, base: float, max_points: int) -> list:
        if not self.buckets:
            return []
        size = self.size

        def row(idx: int) -> dict:
            b = self.buckets.get(idx)
            t = round(max(base + idx * size, 0.0), 3)
            if not b:
                return {"t": t, "TCP": 0.0, "UDP": 0.0, "ICMP": 0.0,
                        "other": 0.0, "total": 0.0}
            return {"t": t, "TCP": b[0] / size, "UDP": b[1] / size,
                    "ICMP": b[2] / size, "other": b[3] / size,
                    "total": b[4] / size}

        lo, hi = self.min_idx, self.max_idx
        span = hi - lo + 1
        if span <= max_points:
            return [row(i) for i in range(lo, hi + 1)]

        # Already bounded to ~max_buckets, but keep the peak-preserving
        # downsampler as a guard for any max_points smaller than the span.
        occupied = sorted(self.buckets)
        sampled, pos = [], 0
        for g in range(max_points):
            start = lo + (g * span) // max_points
            end = lo + ((g + 1) * span) // max_points
            candidates = []
            while pos < len(occupied) and occupied[pos] < end:
                if occupied[pos] >= start:
                    candidates.append(occupied[pos])
                pos += 1
            idx = (max(candidates, key=lambda i: self.buckets[i][4])
                   if candidates else start)
            sampled.append(row(idx))
        return sampled


# ---------------------------------------------------------------------------
# Analyzer: one streaming pass over the capture
# ---------------------------------------------------------------------------

class Analyzer:
    def __init__(self, thresholds: Thresholds):
        self.t = thresholds.validate()
        self.window = thresholds.window

        self.total_packets = 0
        self.total_bytes = 0
        self.first_time: Optional[float] = None   # bucket anchor (first seen)
        self.min_time: Optional[float] = None      # earliest timestamp
        self.max_time: Optional[float] = None      # latest timestamp

        self.protocol_counts = Counter()
        self.dst_packets = Counter()
        self.dst_bytes = Counter()
        self.src_packets = Counter()
        self.udp_ports = Counter()
        # Adaptive-resolution timeline for charting and the peak-rate summary,
        # independent of the coarse detection window, so sub-second captures
        # show a real curve instead of a single spike.
        self.tl = TimelineHistogram()

        # Flood categories.
        self.syn = CategoryTracker()
        self.synack = CategoryTracker()
        self.ack = CategoryTracker()
        self.rst = CategoryTracker()
        self.fin = CategoryTracker()
        self.udp = CategoryTracker()
        self.icmp = CategoryTracker()
        self.frag = CategoryTracker()
        self.dns_query = CategoryTracker()

        # Crafted / malformed packet signatures.
        self.samesport = CategoryTracker()    # source port == destination port
        self.udp_port0 = CategoryTracker()    # UDP to/from port 0
        self.weird_proto = CategoryTracker()  # non TCP/UDP/ICMP IP protocols

        # Reflection: service name -> CategoryTracker.
        self.reflectors = defaultdict(CategoryTracker)

    # -- ingest -----------------------------------------------------------

    def _bucket(self, ts: float) -> int:
        return int((ts - self.first_time) / self.window)

    def abs_offset(self, idx: int) -> float:
        """Offset (seconds from capture start) of a bucket index, clamped >=0.

        Buckets are anchored to the first packet seen; captures merged out of
        order can therefore produce negative raw offsets. Translate back to the
        true minimum timestamp so reported offsets are always sensible.
        """
        offset = (self.first_time - self.min_time) + idx * self.window
        return max(offset, 0.0)

    def ingest(self, packet) -> None:
        ts = float(packet.time)
        size = len(packet)

        if self.first_time is None:
            self.first_time = ts
            self.min_time = ts
            self.max_time = ts
        else:
            if ts < self.min_time:
                self.min_time = ts
            if ts > self.max_time:
                self.max_time = ts

        self.total_packets += 1
        self.total_bytes += size

        bucket = self._bucket(ts)

        ip = packet.getlayer(IP) or packet.getlayer(IPv6)
        if ip is None:
            self.protocol_counts["non-IP"] += 1
            self.tl.add(ts, "other")
            return

        src, dst = ip.src, ip.dst
        self.src_packets[src] += 1
        self.dst_packets[dst] += 1
        self.dst_bytes[dst] += size

        # IPv4 fragmentation: MF flag set, or a non-zero fragment offset.
        is_fragment = False
        if packet.haslayer(IP):
            ipv4 = packet.getlayer(IP)
            if (int(ipv4.flags) & 0x1) or ipv4.frag != 0:
                is_fragment = True
        # IPv6 carries fragmentation in an extension header. Count even an
        # atomic fragment (offset=0, M=0): the header itself is the signature.
        if packet.haslayer(IPv6ExtHdrFragment):
            is_fragment = True
        if is_fragment:
            self.frag.add(dst, bucket, size, src)

        if packet.haslayer(TCP):
            self.protocol_counts["TCP"] += 1
            self.tl.add(ts, "TCP")
            tcp = packet.getlayer(TCP)
            flags = int(tcp.flags)
            syn, ack = flags & 0x02, flags & 0x10
            rst, fin, psh = flags & 0x04, flags & 0x01, flags & 0x08

            if tcp.sport == tcp.dport:
                self.samesport.add(dst, bucket, size, src)

            if syn and not ack:
                self.syn.add(dst, bucket, size, src, dport=tcp.dport)
            elif syn and ack:
                self.synack.add(dst, bucket, size, src, dport=tcp.dport)
            elif ack and not (syn or rst or fin or psh):
                # Bare ACK only. PSH-ACK carries data (normal traffic), so it
                # is excluded to avoid flagging legitimate transfers.
                self.ack.add(dst, bucket, size, src, dport=tcp.dport)
            if rst:
                self.rst.add(dst, bucket, size, src, dport=tcp.dport)
            if fin:
                self.fin.add(dst, bucket, size, src, dport=tcp.dport)

        elif packet.haslayer(UDP):
            self.protocol_counts["UDP"] += 1
            self.tl.add(ts, "UDP")
            udp = packet.getlayer(UDP)
            sport, dport = udp.sport, udp.dport
            self.udp_ports[dport] += 1

            if sport == dport:
                self.samesport.add(dst, bucket, size, src)

            # Classify each UDP packet into exactly one bucket so a single
            # attack vector is not reported twice (e.g. as both a reflection
            # and a generic UDP flood).
            if sport == 0 or dport == 0:
                # Port 0 is never valid: always crafted/malformed.
                self.udp_port0.add(dst, bucket, size, src)
            elif sport in REFLECTORS:
                # Reflection/amplification: response *from* a reflector port.
                name = REFLECTORS[sport][0]
                self.reflectors[name].add(dst, bucket, size, src)
            elif packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
                # DNS query flood: request headed *to* a resolver.
                self.dns_query.add(dst, bucket, size, src, dport=dport)
            else:
                # Generic UDP flood: anything not otherwise classified.
                self.udp.add(dst, bucket, size, src, dport=dport)

        elif packet.haslayer(ICMP):
            self.protocol_counts["ICMP"] += 1
            self.tl.add(ts, "ICMP")
            self.icmp.add(dst, bucket, size, src,
                          icmp_type=int(packet.getlayer(ICMP).type))
        else:
            # Any other IP payload protocol (ESP, GRE, or crafted/random
            # protocol numbers seen in some floods).
            self.protocol_counts["other-IP"] += 1
            self.tl.add(ts, "other")
            ipv4 = packet.getlayer(IP)
            # Non-first fragments of TCP/UDP/ICMP also land here (no L4 header
            # left to parse); those belong to the fragmentation detector, so
            # only flag genuinely uncommon IP protocol numbers as crafted.
            if (not is_fragment
                    and (ipv4 is None or int(ipv4.proto) not in (1, 6, 17))):
                proto = int(ipv4.proto) if ipv4 is not None else int(ip.nh)
                self.weird_proto.add(dst, bucket, size, src, protocol=proto)

    # -- derived stats ----------------------------------------------------

    @property
    def duration(self) -> float:
        if self.min_time is None or self.max_time is None:
            return 0.0
        return max(self.max_time - self.min_time, 0.000001)

    def peak_overall_pps(self) -> float:
        # Derive the peak from the same adaptive-resolution histogram the chart
        # uses, so the "peak rate" summary agrees with the timeline's tallest
        # point (and reveals true sub-second bursts instead of the 1s average).
        if not self.tl.buckets or self.tl.size <= 0:
            return 0.0
        return max(b[4] for b in self.tl.buckets.values()) / self.tl.size

    @property
    def timeline_bucket_s(self) -> float:
        return self.tl.size

    def timeline(self, max_points: int = 800) -> list:
        """Per-bucket pps time series, split by protocol, for charting.

        Resolution adapts to the capture length (see TimelineHistogram): a
        sub-second capture and a multi-hour one both return a real curve rather
        than a single spike, and empty spans between bursts are shown as zeros.
        Each value is packets-per-second over that bucket.
        """
        base = (self.first_time - self.min_time) if self.first_time else 0.0
        return self.tl.rows(base, max_points)

    # -- detection --------------------------------------------------------

    def _total_ip(self) -> int:
        return sum(self.dst_packets.values())

    def _escalate(self, base: str, peak_pps: float, threshold: float) -> str:
        """Raise a signature's base severity when the peak rate warrants it."""
        rank = max(SEVERITY_RANK[base],
                   SEVERITY_RANK[severity_for_rate(peak_pps, threshold)])
        return {v: k for k, v in SEVERITY_RANK.items()}[rank]

    def _gate(self, tracker, victim, count, threshold, require_vic_share=True,
              require_distributed=False, min_sources=None):
        """Decide whether a category fires for a victim, by rate and/or by
        signature. Returns (method, peak_pps, offset) or None.

        Rate:      peak pps over a window crosses the threshold.
        Signature: the victim is the dominant target of the capture and this
                   category is a meaningful part of its inbound traffic -- so an
                   attack fingerprint is caught even at low (sample) volume.

        ``require_distributed`` additionally demands many distinct sources on
        the signature path. This is what separates a distributed flood from
        heavy one-directional benign traffic (a download / stream from one or a
        few hosts): the latter is not distributed, so it does not fire.
        """
        tracker_total = tracker.total()
        if (self.t.concentration > 0 and tracker_total
                and count / tracker_total < self.t.concentration):
            return None

        peak_pps, idx = tracker.peak(victim, self.window)
        by_rate = peak_pps >= threshold

        by_sig = False
        if self.t.signatures and count >= self.t.min_sig_packets:
            total_ip = self._total_ip()
            victim_total = self.dst_packets.get(victim, 0)
            dst_share = victim_total / total_ip if total_ip else 0.0
            vic_share = count / victim_total if victim_total else 0.0
            by_sig = dst_share >= self.t.target_share and (
                not require_vic_share or vic_share >= self.t.sig_victim_share)
            if by_sig and require_distributed:
                uniq, _ = tracker.unique_sources(victim)
                floor = (min_sources if min_sources is not None
                         else self.t.distributed_sources)
                by_sig = uniq >= floor

        if not (by_rate or by_sig):
            return None
        method = ("rate+signature" if by_rate and by_sig
                  else "rate" if by_rate else "signature")
        return method, peak_pps, self.abs_offset(idx)

    def _mk(self, attack, victim, count, peak_pps, offset, uniq, capped,
            method, threshold, evidence, mbps=None, extra=None,
            confidence="high"):
        return Finding(
            attack=attack,
            severity=self._escalate(
                BASE_SEVERITY.get(attack, "LOW"), peak_pps, threshold),
            victim=victim,
            peak_pps=round(peak_pps, 1),
            avg_pps=round(rate(count, self.duration), 1),
            total_packets=count,
            unique_sources=uniq,
            distributed=uniq >= self.t.distributed_sources,
            evidence=evidence,
            mitigation=MITIGATIONS.get(attack, ""),
            mitigation_techniques=list(MITIGATION_TECHNIQUES.get(attack, ())),
            method=method,
            confidence=confidence,
            peak_offset_s=round(offset, 2),
            mbps=(round(mbps, 3) if mbps is not None else None),
            extra=extra or {},
        )

    def _detect_flood(self, attack, tracker, threshold,
                      require_distributed=True):
        findings = []
        for victim, count in tracker.count.items():
            gate = self._gate(tracker, victim, count, threshold,
                              require_distributed=require_distributed)
            if gate is None:
                continue
            method, peak_pps, offset = gate
            uniq, capped = tracker.unique_sources(victim)
            spread = tracker.source_spread(victim)
            victim_total = self.dst_packets.get(victim, 0) or 1
            share = count / victim_total

            # Confidence keys off distribution, not rate: a genuinely
            # distributed flood (many sources spread across many networks) is
            # high confidence, while a single/few-source flood -- even at high
            # rate -- is medium: it may be a single-source DoS or just heavy
            # legitimate one-directional traffic (a stream, backup, download).
            # Inherently-malicious signatures (require_distributed=False) stay
            # high regardless of how many sources they came from.
            if not require_distributed:
                confidence = "high"
            elif (uniq >= self.t.distributed_sources
                  and spread >= 2 * self.t.min_reflectors):
                confidence = "high"
            else:
                confidence = "medium"

            spoofish = ""
            if count and uniq / count > 0.5 and count > 200:
                spoofish = " (near-unique sources: spoofing/botnet likely)"
            offset_txt = f" (@ +{offset:,.1f}s)" if peak_pps else ""
            evidence = (
                f"{count:,} packets ({share * 100:.0f}% of the target's "
                f"inbound), peak {peak_pps:,.0f} pps{offset_txt}, "
                f"{uniq:,}{'+' if capped else ''} unique sources across "
                f"{spread:,} networks{spoofish}"
            )
            extra = {}
            dport = tracker.top_dport(victim)
            if dport is not None:
                extra["top_destination_port"] = dport
                evidence += f"; dominant destination port {dport}"
            icmp_type = tracker.dominant(tracker.icmp_types.get(victim))
            if icmp_type is not None:
                extra["icmp_type"] = icmp_type
                extra["icmp_type_counts"] = dict(
                    tracker.icmp_types[victim].most_common())
                evidence += f"; dominant ICMP type {icmp_type}"
            protocol = tracker.dominant(tracker.protocols.get(victim))
            if protocol is not None:
                extra["ip_protocol"] = protocol
            if tracker.protocols.get(victim):
                extra["ip_protocol_counts"] = dict(
                    tracker.protocols[victim].most_common())
                evidence += "; IP protocol(s) " + ", ".join(
                    f"{p} ({n:,})" for p, n in
                    tracker.protocols[victim].most_common(5))
            findings.append(self._mk(attack, victim, count, peak_pps, offset,
                                     uniq, capped, method, threshold, evidence,
                                     extra=extra, confidence=confidence))
        return findings

    def _detect_syn(self):
        findings = self._detect_flood("TCP SYN Flood", self.syn, self.t.syn_pps)
        for f in findings:
            synacks = self.synack.count.get(f.victim, 0)
            ratio = synacks / f.total_packets if f.total_packets else 0.0
            f.extra["synack_syn_ratio"] = round(ratio, 3)
            if ratio < 0.1:
                f.evidence += "; few/no completed handshakes (half-open)"
        return findings

    def _detect_synack_reflection(self):
        findings = []
        threshold = self.t.reflect_pps
        for victim, count in self.synack.count.items():
            uniq, capped = self.synack.unique_sources(victim)
            # Real TCP reflection sprays spoofed SYNs across many servers, so
            # the unsolicited SYN-ACKs come back from many distinct sources.
            if uniq < 10:
                continue
            gate = self._gate(self.synack, victim, count, threshold,
                              require_vic_share=False)
            if gate is None:
                continue
            method, peak_pps, offset = gate
            offset_txt = f" (@ +{offset:,.1f}s)" if peak_pps else ""
            evidence = (
                f"{count:,} unsolicited SYN-ACK packets (TCP reflection) from "
                f"{uniq:,}{'+' if capped else ''} servers, "
                f"peak {peak_pps:,.0f} pps{offset_txt}"
            )
            findings.append(self._mk("TCP SYN-ACK Reflection", victim, count,
                                     peak_pps, offset, uniq, capped, method,
                                     threshold, evidence))
        return findings

    def _detect_reflection(self):
        findings = []
        threshold = self.t.reflect_pps
        for name, tracker in self.reflectors.items():
            amp_note = next(
                (a for _, (n, a) in REFLECTORS.items() if n == name), "")
            amp_txt = (f" (typical amp {amp_note})"
                       if amp_note and amp_note != "~" else "")
            for victim, count in tracker.count.items():
                uniq, capped = tracker.unique_sources(victim)
                # A busy conversation with one DNS/NTP server is not evidence
                # of reflection, even if it crosses the rate threshold.
                if uniq < self.t.min_reflectors:
                    continue
                gate = self._gate(tracker, victim, count, threshold,
                                  require_vic_share=False,
                                  require_distributed=True,
                                  min_sources=self.t.min_reflectors)
                if gate is None:
                    continue
                method, peak_pps, offset = gate
                mbps = (tracker.bytes[victim] * 8) / self.duration / 1_000_000
                avg_size = tracker.bytes[victim] / count if count else 0
                size_floor = tracker.size_floor(victim)
                offset_txt = f" (@ +{offset:,.1f}s)" if peak_pps else ""
                evidence = (
                    f"{name} responses: {count:,} packets from "
                    f"{uniq:,}{'+' if capped else ''} reflectors, "
                    f"peak {peak_pps:,.0f} pps{offset_txt}, {mbps:,.2f} Mbps, "
                    f"avg response {avg_size:,.0f} B{amp_txt}"
                )
                f = self._mk(
                    "Reflection / Amplification", victim, count, peak_pps,
                    offset, uniq, capped, method, threshold, evidence,
                    mbps=mbps,
                    extra={"service": name,
                           "source_port": REFLECTOR_PORT.get(name),
                           "avg_response_bytes": round(avg_size),
                           "min_packet_bytes_90pct": size_floor,
                           "sources_capped": capped})
                if name == "memcached":
                    f.severity = "CRITICAL"
                findings.append(f)
        return findings

    def findings(self):
        gp = self.t.udp_pps  # generic pps threshold for signature-only classes
        results = []
        results += self._detect_syn()
        results += self._detect_flood("TCP ACK Flood", self.ack, self.t.ack_pps)
        results += self._detect_flood("TCP RST Flood", self.rst, self.t.rst_pps)
        results += self._detect_flood("TCP FIN Flood", self.fin, self.t.fin_pps)
        results += self._detect_synack_reflection()
        results += self._detect_flood("UDP Flood", self.udp, self.t.udp_pps)
        results += self._detect_flood("ICMP Flood", self.icmp, self.t.icmp_pps)
        results += self._detect_flood(
            "IP Fragmentation Flood", self.frag, self.t.frag_pps)
        results += self._detect_flood(
            "DNS Query Flood", self.dns_query, self.t.dns_query_pps)
        # Crafted / malformed signatures are inherently malicious: they do not
        # occur in benign traffic, so they need no distribution corroboration.
        results += self._detect_flood(
            "Crafted Packets (sport = dport)", self.samesport, gp,
            require_distributed=False)
        results += self._detect_flood(
            "Malformed Packets (UDP port 0)", self.udp_port0, gp,
            require_distributed=False)
        results += self._detect_flood(
            "Non-standard IP Protocol", self.weird_proto, gp,
            require_distributed=False)
        results += self._detect_reflection()

        # De-duplicate by (attack, victim, service), keeping the highest
        # severity. Reflection keeps one finding per abused service (source
        # port) so each gets its own FlowSpec rule.
        best = {}
        for f in results:
            key = (f.attack, f.victim, (f.extra or {}).get("service"))
            if (key not in best
                    or SEVERITY_RANK[f.severity] > SEVERITY_RANK[best[key].severity]):
                best[key] = f

        results = list(best.values())
        results.sort(
            key=lambda f: (SEVERITY_RANK[f.severity], f.peak_pps), reverse=True)
        return results


# ---------------------------------------------------------------------------
# Convenience: run a full analysis over a capture file
# ---------------------------------------------------------------------------

def analyze_file(path: str, thresholds: Optional[Thresholds] = None,
                 max_packets: int = 0) -> Analyzer:
    """Stream ``path`` through a fresh Analyzer and return it (findings via
    ``analyzer.findings()``). Shared by the CLI and the web app."""
    analyzer = Analyzer(thresholds or Thresholds())
    with PcapReader(path) as reader:
        for packet in reader:
            analyzer.ingest(packet)
            if max_packets and analyzer.total_packets >= max_packets:
                break
    return analyzer


# ---------------------------------------------------------------------------
# FlowSpec mitigation (BGP FlowSpec, RFC 8955)
#
# Turn a finding into a surgical BGP FlowSpec rule that blocks the attack
# traffic toward the victim. ExaBGP is the primary format (the announcing
# controller); a portable/Junos-style form is provided for reference. Rules
# default to `discard` (traffic-rate 0). Always review scope before advertising
# -- keep rules as narrow as the evidence allows to avoid collateral damage.
# ---------------------------------------------------------------------------

# IOS XE / IOS XR verification commands (shown once per report).
FLOWSPEC_VERIFY_CMDS = [
    "show bgp ipv4 flowspec summary        # session up, PfxRcd increments",
    "show bgp ipv4 flowspec detail         # NLRI + Extended Community action",
    "show flowspec summary                 # FlowSpec Manager installed a flow",
    "show flowspec ipv4 detail             # Matched/Dropped packet counters",
]


def _slug(text: str) -> str:
    out = "".join(c if c.isalnum() else "-" for c in text.lower())
    while "--" in out:
        out = out.replace("--", "-")
    return out.strip("-")


def flowspec_for_finding(finding, analyzer):
    """Build a FlowSpec mitigation for one finding.

    Returns a dict with a structured ``match``, an ``action``, rendered
    ``exabgp`` / ``portable`` config, a human ``summary`` and a ``note`` -- or,
    when FlowSpec cannot express the signature, a note-only dict (no config).
    """
    victim = finding.victim
    is_v6 = ":" in victim
    dst = f"{victim}/{'128' if is_v6 else '32'}"

    match = [("destination", dst)]
    action = "discard"
    note = ""
    a = finding.attack

    if a == "Reflection / Amplification":
        port = REFLECTOR_PORT.get((finding.extra or {}).get("service"))
        match.append(("protocol", "udp"))
        if port:
            match.append(("source-port", port))
        size_floor = (finding.extra or {}).get("min_packet_bytes_90pct")
        if size_floor is not None and size_floor >= 128:
            match.append(("packet-length", f">={size_floor}"))
        note = ("Drops reflected responses coming FROM the abused service "
                "source port toward the victim; review overlap with legitimate traffic.")
    elif a == "TCP SYN-ACK Reflection":
        match += [("protocol", "tcp"), ("tcp-flags", ["syn", "ack"])]
        note = "Drops unsolicited SYN-ACKs (TCP reflection) to the victim."
    elif a == "TCP SYN Flood":
        match += [("protocol", "tcp"), ("tcp-flags", ["syn"])]
        dport = analyzer.syn.top_dport(victim)
        if dport is not None:
            match.append(("destination-port", dport))
        note = ("Drops inbound SYNs matching the flood. Prefer SYN cookies / a "
                "SYN-proxy for the service; this also blocks new legitimate "
                "connections to the matched port -- consider rate-limit.")
    elif a == "TCP ACK Flood":
        return {
            "supported": False,
            "summary": "stateless ACK-flood discard",
            "note": ("A FlowSpec ACK match also catches legitimate established "
                     "TCP traffic. Use a stateful firewall to drop out-of-state "
                     "ACKs, or apply a reviewed upstream rate-limit instead."),
        }
    elif a == "TCP RST Flood":
        match += [("protocol", "tcp"), ("tcp-flags", ["rst"])]
        dport = (finding.extra or {}).get("top_destination_port")
        if dport is not None:
            match.append(("destination-port", dport))
    elif a == "TCP FIN Flood":
        match += [("protocol", "tcp"), ("tcp-flags", ["fin"])]
        dport = (finding.extra or {}).get("top_destination_port")
        if dport is not None:
            match.append(("destination-port", dport))
    elif a == "UDP Flood":
        match.append(("protocol", "udp"))
        dport = analyzer.udp.top_dport(victim)
        if dport is not None:
            match.append(("destination-port", dport))
        else:
            note = ("No single destination port dominates -- rule matches all "
                    "UDP to the victim. Narrow to a port if possible.")
    elif a == "DNS Query Flood":
        match += [("protocol", "udp"), ("destination-port", 53)]
        note = "Prefer DNS RRL; a blanket UDP/53 discard breaks legitimate DNS."
    elif a == "ICMP Flood":
        match.append(("protocol", "icmp"))
        icmp_type = (finding.extra or {}).get("icmp_type")
        if icmp_type is not None:
            match.append(("icmp-type", icmp_type))
    elif a == "IP Fragmentation Flood":
        match.append(("fragment", True))
        note = "Matches fragmented packets to the victim."
    elif a == "Malformed Packets (UDP port 0)":
        match += [("protocol", "udp"), ("port", 0)]
        note = "Matches UDP with source or destination port 0; always invalid."
    elif a == "Crafted Packets (sport = dport)":
        return {
            "supported": False,
            "summary": "source port == destination port",
            "note": ("FlowSpec cannot compare two fields (sport == dport). "
                     "Filter with an ACL / uRPF, or match the specific service "
                     "port if the attack uses a fixed one."),
        }
    elif a == "Non-standard IP Protocol":
        protocol = (finding.extra or {}).get("ip_protocol")
        if protocol is None:
            return {
                "supported": False,
                "summary": "multiple non-standard IP protocol numbers",
                "note": ("No protocol dominates this finding. Review the "
                         "reported protocol counts and create separate rules."),
            }
        match.append(("protocol", protocol))
        note = (f"Matches observed IP protocol {protocol}. Confirm it is not a "
                "required tunnel or security protocol before filtering.")
    else:
        match.append(("protocol", "ip"))

    service = (finding.extra or {}).get("service", "")
    name = _slug(f"{a}-{service}-{victim}")
    risk = _flowspec_risk(a, match)
    expiry = {"low": 60, "medium": 30, "high": 15}[risk["level"]]
    checklist = [
        "Review the victim, match scope, and collateral-risk rating.",
        "Run the vendor syntax or commit validation before activation.",
        "Advertise or install the rule through the approved change path.",
        "Verify route installation and matched/dropped packet counters.",
        f"Monitor service health and counters every 60 seconds for {expiry} minutes.",
        "Withdraw the rule at expiry unless an analyst explicitly renews it.",
    ]
    return {
        "supported": True,
        "name": name,
        "match": [[k, v] for k, v in match],
        "action": action,
        "summary": _flowspec_summary(match, action),
        "note": note,
        "risk": risk,
        "monitoring": {"check_every_seconds": 60,
                       "suggested_expiry_minutes": expiry},
        "response_checklist": checklist,
        "exabgp": _render_exabgp(name, match, action),
        "portable": _render_portable(name, match, action),
        "vendors": _flowspec_vendors(name, match, action),
    }


def _flowspec_risk(attack, match):
    fields = dict(match)
    if attack in ("TCP SYN Flood", "DNS Query Flood"):
        return {"level": "high", "reason":
                "Discarding this match can block legitimate access to the service."}
    if attack == "Reflection / Amplification" and "packet-length" in fields:
        return {"level": "low", "reason":
                "Victim, protocol, reflector source port, and observed size are scoped."}
    if attack in ("Malformed Packets (UDP port 0)",
                  "Non-standard IP Protocol"):
        return {"level": "low", "reason":
                "The rule targets an invalid or explicitly observed crafted field."}
    if ("destination-port" not in fields
            and attack in ("UDP Flood", "TCP RST Flood", "TCP FIN Flood")):
        return {"level": "high", "reason":
                "No destination port dominates, so the rule covers the full protocol."}
    return {"level": "medium", "reason":
            "The rule is victim-scoped but can still overlap legitimate traffic."}


def _flowspec_vendors(name, match, action):
    """Render reviewed IPv4 dialects; never silently omit a match component.

    Snippets define rules, not sessions or policy attachments. IOS XR permits
    an attached aggregate policy, so per-finding examples must not replace it.
    """
    fields = dict(match)
    junos_doc = "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/flow-edit-routing-options.html"
    xr_doc = "https://www.cisco.com/c/en/us/td/docs/iosxr/cisco8000/bgp/cumulative/command/reference/b-bgp-cr-cisco8000/m-bgp-flowspec-commands-8k.html"
    vendors = {
        "exabgp": {"label": "ExaBGP", "supported": True,
                   "config": _render_exabgp(name, match, action),
                   "note": "Insert into a configured neighbor with the matching FlowSpec address family. Review scope before advertising.",
                   "verify": ["exabgpcli neighbor", "exabgpcli route"],
                   "withdraw": _render_exabgp_withdraw(match),
                   "withdraw_note": "Text API withdrawal; send it through the same process/neighbor scope used to announce the route.",
                   "reference": "https://github.com/Exa-Networks/exabgp/wiki/Text-API-Reference"},
    }
    for key, label, reference in (("junos", "Juniper Junos", junos_doc),
                                   ("iosxr", "Cisco IOS XR", xr_doc)):
        vendors[key] = {"label": label, "supported": False, "config": "",
                        "note": "IPv6 vendor templates are not yet validated; no IPv4 commands are substituted.",
                        "verify": [], "withdraw": "",
                        "withdraw_note": "", "reference": reference}
    if ":" in fields["destination"]:
        return vendors

    # Stable short identifiers avoid platform name limits and service collisions.
    short = "ddos-" + hashlib.sha256(name.encode()).hexdigest()[:16]
    base = f"set routing-options flow route {short}"
    lines = []
    for key, value in match:
        if key == "tcp-flags":
            value = '"' + " & ".join(value) + '"'
        elif key == "fragment":
            value = "is-fragment"
        lines.append(f"{base} match {key} {value}")
    lines.append(f"{base} then {action}")
    vendors["junos"].update(
        supported=True, config="\n".join(lines),
        note="IPv4 static FlowSpec route; paste in configuration mode. BGP family inet flow, export policy and forwarding support must already be configured. Run commit check before committing.",
        verify=["show route table inetflow.0 extensive",
                "show configuration routing-options flow | display set"],
        withdraw=f"delete routing-options flow route {short}\ncommit check\ncommit",
        withdraw_note="Remove only this generated static flow route, validate, then commit through your normal change process.")

    flags = fields.get("tcp-flags", [])
    if len(flags) > 1:
        vendors["iosxr"]["note"] = (
            "The documented IOS XR 'any' flag matcher would broaden SYN+ACK "
            "to SYN OR ACK. No rule emitted; use a validated controller or stateful filtering.")
        return vendors
    # Source-or-destination port is an OR: two classes retain the destination
    # and protocol in each branch, instead of an incorrect match-all of ports.
    branches = ("source-port", "destination-port") if "port" in fields else (None,)
    lines, classes = [], []
    for branch in branches:
        cname = short + ("-src" if branch == "source-port" else "-dst" if branch else "")
        classes.append(cname)
        lines.append(f"class-map type traffic match-all {cname}")
        for key, value in match:
            if key == "destination":
                lines.append(f" match destination-address ipv4 {value.split('/')[0]} 255.255.255.255")
            elif key == "tcp-flags":
                mask = {"syn": "2", "rst": "4", "fin": "1"}[value[0]]
                lines.append(f" match tcp flag {mask} any")
            elif key == "fragment":
                lines.append(" match fragment type is-fragment")
            elif key == "icmp-type":
                lines.append(f" match ipv4 icmp-type {value}")
            elif key == "packet-length":
                minimum = str(value).removeprefix(">=")
                lines.append(f" match packet length [{minimum} - 65535]")
            else:
                lines.append(f" match {branch if key == 'port' else key} {value}")
        lines.append("end-class-map")
    lines.append(f"policy-map type pbr {short}")
    for cname in classes:
        lines.extend([f" class type traffic {cname}", "  drop", " !"])
    lines.append("end-policy-map")
    vendors["iosxr"].update(
        supported=True, config="\n".join(lines),
        note="IPv4 rule definitions for IOS XR platforms supporting these FlowSpec matches. Merge the classes into your existing FlowSpec PBR policy. Attach that aggregate policy under flowspec / address-family ipv4 using service-policy type pbr <policy-name>. These definitions alone do not activate filtering; BGP export and local installation are separate setup steps. Validate on your release and hardware.",
        verify=["show bgp ipv4 flowspec", "show flowspec ipv4 detail"],
        withdraw=(f"no policy-map type pbr {short}\n" + "\n".join(
            f"no class-map type traffic match-all {cname}" for cname in classes)),
        withdraw_note="Use these commands only if the generated standalone policy was installed. If its classes were merged into an aggregate policy, remove the matching class entries from that policy first.")
    return vendors


def _render_exabgp_withdraw(match):
    parts = []
    for key, value in match:
        if key == "tcp-flags":
            parts.append(f"{key} [ {' '.join(value)} ];")
        elif key == "fragment":
            parts.append("fragment [ is-fragment first-fragment ];")
        elif key in ("port", "source-port", "destination-port", "icmp-type"):
            parts.append(f"{key} ={value};")
        else:
            parts.append(f"{key} {value};")
    return "withdraw flow route { match { " + " ".join(parts) + " } }"


def _flowspec_summary(match, action):
    parts = []
    for k, v in match:
        if k == "tcp-flags":
            parts.append(f"tcp-flags {'+'.join(v)}")
        elif k == "fragment":
            parts.append("fragment")
        else:
            parts.append(f"{k} {v}")
    return " + ".join(parts) + f"  ->  {action}"


def _render_exabgp(name, match, action):
    lines = ["flow {", f"    route {name} {{", "        match {"]
    for k, v in match:
        if k in ("port", "source-port", "destination-port", "icmp-type"):
            lines.append(f"            {k} ={v};")
        elif k == "tcp-flags":
            lines.append(f"            tcp-flags [ {' '.join(v)} ];")
        elif k == "fragment":
            lines.append("            fragment [ is-fragment first-fragment ];")
        else:
            lines.append(f"            {k} {v};")
    lines += ["        }", "        then {", f"            {action};",
              "        }", "    }", "}"]
    return "\n".join(lines)


def _render_portable(name, match, action):
    """Junos-style routing-options flow route (verify against your platform)."""
    lines = [f"routes {{", f"    route {name} {{", "        match {"]
    for k, v in match:
        if k == "tcp-flags":
            lines.append(f'            tcp-flags "{"&".join(v)}";')
        elif k == "fragment":
            lines.append("            fragment is-fragment;")
        else:
            lines.append(f"            {k} {v};")
    lines += ["        }", f"        then {action};", "    }", "}"]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def colorize(severity: str, use_color: bool) -> str:
    if not use_color:
        return severity
    return f"{SEVERITY_COLORS.get(severity, '')}{severity}{RESET}"


def print_text_report(analyzer: Analyzer, findings, use_color: bool,
                      top: int = 10, flowspec_format: str = "exabgp") -> None:
    duration = analyzer.duration
    total_pps = rate(analyzer.total_packets, duration)
    peak_pps = analyzer.peak_overall_pps()
    bandwidth = (analyzer.total_bytes * 8) / duration / 1_000_000

    def rule(title):
        print()
        print("=" * 72)
        print(title)
        print("=" * 72)

    rule("PACKETLENS - CAPTURE SUMMARY")
    print(f"Packets:            {analyzer.total_packets:,}")
    print(f"Bytes:              {human_bytes(analyzer.total_bytes)}")
    print(f"Duration:           {duration:,.2f} s")
    print(f"Average rate:       {total_pps:,.1f} pps")
    _res = analyzer.timeline_bucket_s
    _res_txt = f"{_res * 1000:.0f} ms" if _res < 1 else f"{_res:g} s"
    print(f"Peak rate:          {peak_pps:,.1f} pps "
          f"(over {_res_txt} buckets)")
    print(f"Average bandwidth:  {bandwidth:,.2f} Mbps")
    print()
    print("Protocol counts:")
    total = analyzer.total_packets
    for proto, count in analyzer.protocol_counts.most_common():
        print(f"  {proto:<10} {count:>12,}  ({percentage(count, total):5.1f}%)")

    rule("TOP DESTINATIONS")
    dst_total = sum(analyzer.dst_packets.values())
    for dst, count in analyzer.dst_packets.most_common(top):
        print(f"{dst:<40} {count:>10,} pkts  "
              f"{rate(count, duration):>10,.1f} pps  "
              f"{percentage(count, dst_total):>6.2f}%")

    rule("TOP SOURCES")
    for src, count in analyzer.src_packets.most_common(top):
        print(f"{src:<40} {count:>10,} pkts  {rate(count, duration):>10,.1f} pps")

    if analyzer.udp_ports:
        rule("TOP UDP DESTINATION PORTS")
        for port, count in analyzer.udp_ports.most_common(top):
            svc = ""
            if port in REFLECTORS:
                svc = f"  <- {REFLECTORS[port][0]} reflector port"
            print(f"UDP/{port:<8} {count:>12,} pkts{svc}")

    rule("DDoS FINDINGS")
    if not findings:
        print("No traffic crossed the configured heuristic thresholds.")
    else:
        print(f"{len(findings)} finding(s), most severe first:")
        for f in findings:
            scope = "distributed" if f.distributed else "single/few-source"
            conf = "" if f.confidence == "high" else f", {f.confidence} confidence"
            svc = (f.extra or {}).get("service")
            port = (f.extra or {}).get("source_port")
            label = f.attack
            if svc:
                label += f" — {svc}" + (f" (UDP/{port})" if port else "")
            print()
            print(f"[{colorize(f.severity, use_color)}] {label}  "
                  f"({scope}, via {f.method}{conf})")
            print(f"  Victim:     {f.victim}")
            print(f"  Evidence:   {f.evidence}")
            if f.mbps is not None:
                print(f"  Volume:     {f.mbps:,.2f} Mbps")
            print(f"  Mitigation: {f.mitigation}")
            if f.mitigation_techniques:
                print("  Response playbook:")
                for technique in f.mitigation_techniques:
                    print(f"    - {technique}")

        # -- FlowSpec mitigation ---------------------------------------------
        rule("FLOWSPEC MITIGATION (BGP FlowSpec, RFC 8955)")
        print("Surgical rules to block the attack traffic. Review scope before")
        print("advertising, and withdraw once the attack subsides.\n")
        for f in findings:
            fs = flowspec_for_finding(f, analyzer)
            print(f"# {f.attack}  ->  {f.victim}")
            if not fs.get("supported"):
                print(f"  (not expressible in FlowSpec: {fs['summary']})")
                print(f"  {fs['note']}\n")
                continue
            print(f"  Match/Action: {fs['summary']}")
            if fs["note"]:
                print(f"  Note: {fs['note']}")
            print(f"  Collateral risk: {fs['risk']['level'].upper()} — "
                  f"{fs['risk']['reason']}")
            print("  Response checklist:")
            for step in fs["response_checklist"]:
                print(f"    - {step}")
            vendor = fs["vendors"][flowspec_format]
            print(f"  {vendor['label']}: {vendor['note']}")
            if not vendor["supported"]:
                continue
            for line in vendor["config"].splitlines():
                print(f"    {line}")
            for command in vendor["verify"]:
                print(f"    Verify: {command}")
            print(f"  Withdrawal: {vendor['withdraw_note']}")
            for line in vendor["withdraw"].splitlines():
                print(f"    {line}")
            print()
    print()


def build_json_report(analyzer: Analyzer, findings, top: int = 10) -> dict:
    duration = analyzer.duration
    dst_total = sum(analyzer.dst_packets.values())
    destinations = [
        {"ip": d, "packets": c, "pps": round(rate(c, duration), 1),
         "share": round(percentage(c, dst_total), 2)}
        for d, c in analyzer.dst_packets.most_common()
    ]
    sources = [
        {"ip": s, "packets": c, "pps": round(rate(c, duration), 1),
         "share": round(percentage(c, analyzer.total_packets), 2)}
        for s, c in analyzer.src_packets.most_common()
    ]
    return {
        "summary": {
            "packets": analyzer.total_packets,
            "bytes": analyzer.total_bytes,
            "duration_s": round(duration, 3),
            "avg_pps": round(rate(analyzer.total_packets, duration), 1),
            "peak_pps": round(analyzer.peak_overall_pps(), 1),
            "avg_mbps": round((analyzer.total_bytes * 8) / duration / 1_000_000, 3),
            "window_s": analyzer.window,
            "timeline_bucket_s": analyzer.timeline_bucket_s,
            "protocol_counts": dict(analyzer.protocol_counts),
            "top_destinations": [
                {"ip": d, "packets": c}
                for d, c in analyzer.dst_packets.most_common(top)
            ],
            "top_sources": [
                {"ip": s, "packets": c}
                for s, c in analyzer.src_packets.most_common(top)
            ],
        },
        "inventory": {
            "complete": True,
            "destinations": destinations,
            "sources": sources,
            "protocols": [
                {"protocol": p, "packets": c,
                 "pps": round(rate(c, duration), 1),
                 "share": round(percentage(c, analyzer.total_packets), 2)}
                for p, c in analyzer.protocol_counts.most_common()
            ],
            "udp_ports": [
                {"port": p, "packets": c,
                 "share": round(percentage(c, sum(analyzer.udp_ports.values())), 2),
                 "reflector": REFLECTORS[p][0] if p in REFLECTORS else None}
                for p, c in analyzer.udp_ports.most_common()
            ],
        },
        "findings": [
            {**asdict(f), "flowspec": flowspec_for_finding(f, analyzer)}
            for f in findings
        ],
        "flowspec_verify": FLOWSPEC_VERIFY_CMDS,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="packetlens",
        description="Packetlens: analyze a PCAP for common DDoS indicators (heuristic).")
    p.add_argument("pcap", help="PCAP/PCAPNG file to analyze")
    p.add_argument("--json", action="store_true",
                   help="emit machine-readable JSON instead of a text report")
    p.add_argument("--flowspec-format", choices=("exabgp", "junos", "iosxr"),
                   default="exabgp", help="FlowSpec dialect for text output (JSON includes all)")
    p.add_argument("--no-color", action="store_true",
                   help="disable ANSI color in the text report")
    p.add_argument("--top", type=int, default=10,
                   help="number of rows in top-N tables (default 10)")
    p.add_argument("--max-packets", type=int, default=0,
                   help="stop after N packets (0 = no limit)")

    g = p.add_argument_group("thresholds")
    g.add_argument("--window", type=float, default=1.0,
                   help="seconds per peak-rate window (default 1.0)")
    g.add_argument("--syn-pps", type=float)
    g.add_argument("--ack-pps", type=float)
    g.add_argument("--rst-pps", type=float)
    g.add_argument("--fin-pps", type=float)
    g.add_argument("--udp-pps", type=float)
    g.add_argument("--icmp-pps", type=float)
    g.add_argument("--frag-pps", type=float)
    g.add_argument("--dns-query-pps", type=float)
    g.add_argument("--reflect-pps", type=float)
    g.add_argument("--concentration", type=float,
                   help="fraction of a category's traffic to one victim (0-1)")
    g.add_argument("--distributed-sources", type=int,
                   help="unique sources to classify a victim as distributed")
    g.add_argument("--no-signatures", dest="signatures", action="store_false",
                   help="disable rate-independent signature detection "
                        "(use pure volumetric thresholds only)")
    g.add_argument("--target-share", type=float,
                   help="min share of all IP packets to one dst to treat it "
                        "as the attack target (signature mode, default 0.8)")
    p.set_defaults(signatures=True)
    return p.parse_args(argv)


def thresholds_from_args(args) -> Thresholds:
    t = Thresholds(window=args.window)
    for name in ("syn_pps", "ack_pps", "rst_pps", "fin_pps", "udp_pps",
                 "icmp_pps", "frag_pps", "dns_query_pps", "reflect_pps",
                 "concentration", "distributed_sources", "target_share"):
        value = getattr(args, name, None)
        if value is not None:
            setattr(t, name, value)
    t.signatures = getattr(args, "signatures", True)
    return t.validate()


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        thresholds = thresholds_from_args(args)
    except ValueError as exc:
        print(f"[-] Invalid threshold: {exc}", file=sys.stderr)
        return 3
    analyzer = Analyzer(thresholds)

    use_color = (not args.no_color) and (not args.json) and sys.stdout.isatty()

    if not args.json:
        print(f"[+] Reading {args.pcap} (streaming)...", file=sys.stderr)

    try:
        with PcapReader(args.pcap) as reader:
            for packet in reader:
                analyzer.ingest(packet)
                if args.max_packets and analyzer.total_packets >= args.max_packets:
                    break
                if (not args.json
                        and analyzer.total_packets % 500_000 == 0):
                    print(f"    ... {analyzer.total_packets:,} packets",
                          file=sys.stderr)
    except FileNotFoundError:
        print(f"[-] No such file: {args.pcap}", file=sys.stderr)
        return 3
    except Exception as exc:  # noqa: BLE001 - surface any scapy read error
        print(f"[-] Failed to read capture: {exc}", file=sys.stderr)
        return 3

    if analyzer.total_packets == 0:
        print("[-] Capture contains no packets.", file=sys.stderr)
        return 3

    findings = analyzer.findings()

    if args.json:
        print(json.dumps(build_json_report(analyzer, findings, args.top), indent=2))
    else:
        print_text_report(analyzer, findings, use_color, args.top, args.flowspec_format)

    # Exit code: 0 = clean, 1 = low/medium findings, 2 = high/critical findings.
    if not findings:
        return 0
    worst = max(SEVERITY_RANK[f.severity] for f in findings)
    return 2 if worst >= SEVERITY_RANK["HIGH"] else 1


if __name__ == "__main__":
    sys.exit(main())
