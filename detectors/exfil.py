"""Heuristic DNS-tunneling / exfiltration detector.

Adapted from the sibling dns-sinkhole project's ``ExfilDetector``, generalized
to feed off :class:`core.models.PacketRecord` DNS fields. Looks at three
orthogonal signals in a sliding time window per registered domain:

1. **Encoded label** - a very long subdomain label with high Shannon entropy
   (base32/base64/hex payload rather than a real hostname).
2. **Subdomain fan-out** - an unusual number of distinct subdomains under one
   registered domain.
3. **Payload flood** - a high query rate to one domain using payload-carrying
   qtypes (TXT/NULL/CNAME).

Any single signal is enough to flag a query; that keeps recall high while the
length/entropy thresholds keep ordinary CDN hashes and long-but-real hostnames
from tripping it.
"""

from __future__ import annotations

import math
import time
from collections import Counter, deque
from typing import Callable, Optional

from core.config import ExfilConfig
from core.models import Alert, PacketRecord


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    counts = Counter(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def split_domain(name: str) -> tuple[str, list[str]]:
    labels = name.rstrip(".").lower().split(".")
    if len(labels) <= 2:
        return ".".join(labels), []
    return ".".join(labels[-2:]), labels[:-2]


class ExfilDetector:
    def __init__(self, config: Optional[ExfilConfig] = None, clock: Callable[[], float] = time.time):
        self.cfg = config or ExfilConfig()
        self._clock = clock
        self._events: deque = deque()  # (ts, sld, subdomain, qtype)
        self._last_alert: dict[str, float] = {}

    def _prune(self, now: float) -> None:
        cutoff = now - self.cfg.window_seconds
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()

    def observe(self, pkt: PacketRecord, now: Optional[float] = None) -> Optional[Alert]:
        if pkt.proto != "DNS" or pkt.dns_qr == 1 or not pkt.dns_qname:
            return None
        now = now if now is not None else self._clock()

        sld, sub_labels = split_domain(pkt.dns_qname)
        subdomain = ".".join(sub_labels)
        self._prune(now)
        self._events.append((now, sld, subdomain, pkt.dns_qtype))

        longest_label = max(sub_labels, key=len) if sub_labels else ""
        entropy = shannon_entropy(longest_label)

        same = [e for e in self._events if e[1] == sld]
        query_rate = len(same)
        unique_subs = len({e[2] for e in same if e[2]})

        cfg = self.cfg
        reason, score = "", 0.0
        if len(longest_label) > cfg.max_label_length and entropy > cfg.entropy_threshold:
            reason, score = "encoded-label", entropy
        elif unique_subs > cfg.unique_subdomains:
            reason, score = "subdomain-fanout", float(unique_subs)
        elif query_rate > cfg.query_rate and pkt.dns_qtype in cfg.payload_qtypes:
            reason, score = "payload-flood", float(query_rate)
        else:
            return None

        last = self._last_alert.get(sld)
        if last is not None and now - last < self.cfg.cooldown:
            return None
        self._last_alert[sld] = now

        detail = f"{reason} for {sld} (score={score:.2f}, qtype={pkt.dns_qtype})"
        return Alert(kind="exfil", severity="high", src=pkt.src, dst=sld, detail=detail, ts=now, score=score)
