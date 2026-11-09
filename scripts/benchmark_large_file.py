"""Large-file performance and memory profiling benchmark script."""

from __future__ import annotations

import argparse
import sys
import time
import tracemalloc
from pathlib import Path

from rich.console import Console
from rich.table import Table

from loglens.cluster import DrainClusterer
from loglens.ingest import FileReader
from loglens.parsers import registry
from loglens.rules import RuleEngine, get_builtin_rules


def run_benchmark(file_path: Path, max_lines: int | None = None) -> dict[str, float]:
    """Profile parsing throughput, clustering, and peak memory on target file."""
    console = Console()
    console.print(f"[bold cyan]Benchmarking LogLens on:[/bold cyan] {file_path}")

    reader = FileReader(file_path)
    sample_lines: list[str] = []
    for _, line in reader.stream():
        sample_lines.append(line)
        if len(sample_lines) >= 50:
            break

    parser = registry.autodetect(sample_lines)
    console.print(f"Detected Parser: [bold green]{parser.name}[/bold green] ({parser.description})")

    clusterer = DrainClusterer()
    rules = get_builtin_rules()
    engine = RuleEngine(rules)

    tracemalloc.start()
    t0 = time.perf_counter()

    line_count = 0
    parsed_events = []

    for line_num, raw_line in reader.stream():
        line_count += 1
        ev = parser.parse_line(raw_line, line_num)
        if ev:
            parsed_events.append(ev)
            clusterer.add_event(ev)

        if max_lines and line_count >= max_lines:
            break

    t_ingest = time.perf_counter() - t0
    clusters = clusterer.get_clusters()

    t_rule_0 = time.perf_counter()
    findings = engine.evaluate(parsed_events, clusters)
    t_rules = time.perf_counter() - t_rule_0

    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    total_time = t_ingest + t_rules
    throughput = line_count / total_time if total_time > 0 else 0.0

    table = Table(title="Performance Benchmark Results", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="bold")
    table.add_column("Value", style="green")

    table.add_row("Total Lines Ingested", f"{line_count:,}")
    table.add_row("Parsed Events", f"{len(parsed_events):,}")
    table.add_row("Drain3 Clusters Mined", f"{len(clusters):,}")
    table.add_row("Security Findings", f"{len(findings):,}")
    table.add_row("Ingestion & Cluster Time", f"{t_ingest:.3f} s")
    table.add_row("Rule Evaluation Time", f"{t_rules:.3f} s")
    table.add_row("Total Elapsed Time", f"{total_time:.3f} s")
    table.add_row("Throughput", f"{throughput:,.1f} lines/sec")
    table.add_row("Peak Traced Memory", f"{peak_mem / (1024 * 1024):.2f} MB")
    table.add_row("Final Memory Allocation", f"{current_mem / (1024 * 1024):.2f} MB")

    console.print(table)

    return {
        "lines": float(line_count),
        "total_time": total_time,
        "throughput": throughput,
        "peak_mem_mb": peak_mem / (1024 * 1024),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="LogLens Large-File Performance Benchmark")
    parser.add_argument("file", type=Path, help="Target log file to benchmark")
    parser.add_argument("--max-lines", type=int, default=None, help="Optional line limit")
    args = parser.parse_args()

    if not args.file.exists():
        print(f"Error: file not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    run_benchmark(args.file, max_lines=args.max_lines)


if __name__ == "__main__":
    main()
