"""Log clustering, statistical detection, and error classification package."""

from loglens.cluster.drain import DrainClusterer
from loglens.cluster.errors import (
    ClassifiedError,
    classify_cluster_error,
    extract_classified_errors,
)
from loglens.cluster.stats import (
    detect_entity_bursts,
    detect_rare_templates,
    detect_rate_spikes,
)

__all__ = [
    "ClassifiedError",
    "DrainClusterer",
    "classify_cluster_error",
    "detect_entity_bursts",
    "detect_rare_templates",
    "detect_rate_spikes",
    "extract_classified_errors",
]
