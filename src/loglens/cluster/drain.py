"""Drain3 log template mining and event clustering."""

from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import datetime

from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

from loglens.models import Cluster, Event


class DrainClusterer:
    """Clusters normalized log events using the Drain3 algorithm."""

    def __init__(
        self,
        *,
        depth: int = 4,
        sim_th: float = 0.4,
        max_children: int = 100,
    ) -> None:
        """Initialize DrainClusterer with Drain3 configuration."""
        config = TemplateMinerConfig()
        config.drain_depth = depth
        config.drain_sim_th = sim_th
        config.drain_max_children = max_children
        config.profiling_enabled = False

        self.miner = TemplateMiner(config=config)

        # Internal tracking per cluster_id
        self._counts: Counter[int] = Counter()
        self._first_seen: dict[int, datetime] = {}
        self._last_seen: dict[int, datetime] = {}
        self._sample_messages: dict[int, list[str]] = defaultdict(list)
        self._templates: dict[int, str] = {}
        self._field_counters: dict[int, dict[str, Counter[str]]] = defaultdict(
            lambda: defaultdict(Counter)
        )

    def add_event(self, event: Event) -> int:
        """Feed a normalized Event into Drain3 and update cluster statistics.

        Returns the assigned cluster ID.
        """
        # Pass the message body to Drain3
        res = self.miner.add_log_message(event.message)
        cluster_id: int = int(res["cluster_id"])
        template: str = str(res["template_mined"])

        self._counts[cluster_id] += 1
        self._templates[cluster_id] = template

        if cluster_id not in self._first_seen or event.ts < self._first_seen[cluster_id]:
            self._first_seen[cluster_id] = event.ts

        if cluster_id not in self._last_seen or event.ts > self._last_seen[cluster_id]:
            self._last_seen[cluster_id] = event.ts

        # Keep up to 3 distinct sample messages
        samples = self._sample_messages[cluster_id]
        if len(samples) < 3 and event.message not in samples:
            samples.append(event.message)

        # Track top fields (ip, user, method, path, status, action)
        counters = self._field_counters[cluster_id]
        for field_name, field_val in event.fields.items():
            if field_val is not None:
                counters[field_name][str(field_val)] += 1

        return cluster_id

    def add_events(self, events: Iterable[Event]) -> None:
        """Batch add events to clusterer."""
        for ev in events:
            self.add_event(ev)

    def get_clusters(self, *, min_count: int = 1) -> list[Cluster]:
        """Convert accumulated state into a list of validated Cluster models."""
        clusters: list[Cluster] = []

        for cluster_id, count in self._counts.items():
            if count < min_count:
                continue

            top_fields: dict[str, list[tuple[str, int]]] = {}
            for field_name, counter in self._field_counters[cluster_id].items():
                # Store top 5 most common values for each field
                top_fields[field_name] = counter.most_common(5)

            clusters.append(
                Cluster(
                    id=f"cluster-{cluster_id}",
                    template=self._templates[cluster_id],
                    count=count,
                    first_seen=self._first_seen[cluster_id],
                    last_seen=self._last_seen[cluster_id],
                    top_fields=top_fields,
                    sample_messages=self._sample_messages[cluster_id],
                )
            )

        # Sort by total occurrence count descending
        clusters.sort(key=lambda c: c.count, reverse=True)
        return clusters
