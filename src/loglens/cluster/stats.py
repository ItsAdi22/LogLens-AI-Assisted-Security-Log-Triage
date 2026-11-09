"""Statistical anomaly detectors for log event streams and clusters."""

import math
from collections import Counter, defaultdict
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from loglens.models import Cluster, Event


def detect_entity_bursts(
    events: Sequence[Event],
    *,
    entity_field: str = "ip",
    threshold_count: int = 20,
    window_seconds: float = 300.0,
) -> list[dict[str, Any]]:
    """Detect entities (IPs, users) that generate bursts exceeding threshold_count in window_seconds.

    Returns a list of burst records containing entity, count, start_time, and end_time.
    """
    if not events:
        return []

    # Filter events having the specified entity field and sort by timestamp
    entity_events: list[tuple[datetime, str]] = []
    for ev in events:
        val = ev.fields.get(entity_field)
        if val is not None:
            entity_events.append((ev.ts, str(val)))

    entity_events.sort(key=lambda x: x[0])

    bursts: list[dict[str, Any]] = []
    # Group by entity
    grouped: dict[str, list[datetime]] = defaultdict(list)
    for ts, entity in entity_events:
        grouped[entity].append(ts)

    for entity, timestamps in grouped.items():
        if len(timestamps) < threshold_count:
            continue

        # Two-pointer sliding window over timestamps
        left = 0
        max_in_window = 0
        window_start = timestamps[0]
        window_end = timestamps[-1]

        for right in range(len(timestamps)):
            while (timestamps[right] - timestamps[left]).total_seconds() > window_seconds:
                left += 1

            count_in_window = right - left + 1
            if count_in_window > max_in_window:
                max_in_window = count_in_window
                window_start = timestamps[left]
                window_end = timestamps[right]

        if max_in_window >= threshold_count:
            bursts.append(
                {
                    "entity_field": entity_field,
                    "entity": entity,
                    "burst_count": max_in_window,
                    "window_start": window_start,
                    "window_end": window_end,
                }
            )

    return sorted(bursts, key=lambda b: int(b["burst_count"]), reverse=True)


def detect_rare_templates(
    clusters: Sequence[Cluster],
    total_events: int,
    *,
    rarity_threshold: float = 0.02,
    min_total_events: int = 50,
) -> list[Cluster]:
    """Identify clusters whose frequency is unusually rare relative to total events.

    Only evaluates when total_events >= min_total_events.
    """
    if total_events < min_total_events:
        return []

    rare: list[Cluster] = []
    for cluster in clusters:
        freq = cluster.count / total_events
        if freq <= rarity_threshold:
            rare.append(cluster)

    return rare


def detect_rate_spikes(
    events: Sequence[Event],
    *,
    bucket_seconds: int = 60,
    z_threshold: float = 3.0,
) -> list[dict[str, Any]]:
    """Detect time buckets where event arrival rate z-score exceeds z_threshold.

    Returns buckets containing start_time, count, mean, stddev, and z_score.
    """
    if len(events) < 10:
        return []

    timestamps = sorted(ev.ts for ev in events)
    min_ts = timestamps[0].timestamp()

    # Bucket events into discrete time bins
    bins: Counter[int] = Counter()
    for ts in timestamps:
        bin_idx = int((ts.timestamp() - min_ts) // bucket_seconds)
        bins[bin_idx] += 1

    counts = list(bins.values())
    if len(counts) < 3:
        return []

    mean = sum(counts) / len(counts)
    variance = sum((c - mean) ** 2 for c in counts) / len(counts)
    stddev = math.sqrt(variance)

    if stddev == 0.0:
        return []

    spikes: list[dict[str, Any]] = []
    for bin_idx, count in bins.items():
        z = (count - mean) / stddev
        if z >= z_threshold:
            bucket_start = datetime.fromtimestamp(
                min_ts + bin_idx * bucket_seconds, tz=timestamps[0].tzinfo
            )
            spikes.append(
                {
                    "bucket_start": bucket_start,
                    "count": count,
                    "mean": round(mean, 2),
                    "stddev": round(stddev, 2),
                    "z_score": round(z, 2),
                }
            )

    return sorted(spikes, key=lambda s: float(s["z_score"]), reverse=True)
