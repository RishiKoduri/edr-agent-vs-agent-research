from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from .detectors import BehavioralEDRDetector
from .models import ArchitectureMode, EndpointEvent, EventType


def read_osquery_jsonl(path: Path) -> list[dict[str, Any]]:
    """Read newline-delimited or shell-mode JSON osquery observations."""

    text = path.read_text()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = None
    if payload is not None:
        if isinstance(payload, dict):
            return [payload]
        if isinstance(payload, list) and all(isinstance(row, dict) for row in payload):
            return payload
        raise ValueError(f"{path} must contain JSON objects or a JSON array of objects")

    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid JSON on line {line_number} of {path}") from error
        if not isinstance(row, dict):
            raise ValueError(f"line {line_number} of {path} is not a JSON object")
        rows.append(row)
    return rows


def row_to_event(row: dict[str, Any], row_number: int) -> EndpointEvent:
    """Convert one osquery observation into the simulator event schema.

    Osquery often returns point-in-time tables rather than an EDR event stream.
    The adapter therefore accepts an explicit ``event_type`` when available and
    falls back to conservative field-based inference for exploratory use.
    """

    columns = row.get("columns")
    if isinstance(columns, dict):
        normalized = {**row, **columns}
    else:
        normalized = row

    event_type = infer_event_type(normalized)
    timestamp = as_float(
        normalized.get("timestamp", normalized.get("time", normalized.get("unix_time"))),
        float(row_number),
    )
    endpoint_id = string_value(
        normalized.get("endpoint_id", normalized.get("host_identifier", "osquery-host"))
    )
    user = string_value(normalized.get("user", normalized.get("username", "unknown")))
    role = string_value(normalized.get("role", "unknown"))
    tool = string_value(
        normalized.get(
            "tool",
            normalized.get("name", normalized.get("process_name", normalized.get("path", "unknown"))),
        )
    )
    target = string_value(
        normalized.get(
            "target",
            normalized.get(
                "remote_address",
                normalized.get("path", normalized.get("filename", "unknown")),
            ),
        )
    )
    metadata = {
        "source": "osquery",
        "osquery_query": normalized.get("query_name", normalized.get("name", "unknown")),
        "session_id": string_value(normalized.get("session_id", "osquery-session")),
        "adaptation_level": as_int(normalized.get("adaptation_level"), 0),
        "command_quality": string_value(normalized.get("command_quality", "normal")),
    }
    return EndpointEvent(
        timestamp=timestamp,
        endpoint_id=endpoint_id,
        user=user,
        role=role,
        event_type=event_type,
        tool=tool,
        target=target,
        metadata=metadata,
    )


def infer_event_type(row: dict[str, Any]) -> EventType:
    explicit = string_value(row.get("event_type", row.get("action", ""))).lower()
    if explicit:
        try:
            return EventType(explicit)
        except ValueError:
            pass

    query_name = string_value(row.get("query_name", row.get("name", ""))).lower()
    if any(token in query_name for token in ("process", "command")):
        return EventType.PROCESS_START
    if any(token in query_name for token in ("socket", "network", "connection")):
        return EventType.NETWORK_CONNECT
    if any(token in query_name for token in ("user", "login", "auth")):
        return EventType.AUTH
    if any(token in query_name for token in ("file", "hash", "directory")):
        return EventType.FILE_ACCESS
    return EventType.PROCESS_START


def score_osquery_sessions(
    rows: list[dict[str, Any]],
    *,
    architecture: ArchitectureMode = ArchitectureMode.CENTRALIZED,
    threshold: float = 4.0,
) -> list[dict[str, Any]]:
    sessions: dict[str, list[EndpointEvent]] = defaultdict(list)
    for row_number, row in enumerate(rows, start=1):
        event = row_to_event(row, row_number)
        sessions[event.metadata["session_id"]].append(event)

    detector = BehavioralEDRDetector(threshold=threshold, architecture=architecture)
    results: list[dict[str, Any]] = []
    for session_id, events in sorted(sessions.items()):
        result = detector.score(sorted(events, key=lambda event: event.timestamp))
        results.append(
            {
                "session_id": session_id,
                "architecture": architecture.value,
                "detected": result.suspicious,
                "score": result.score,
                "reasons": "; ".join(result.reasons),
                "event_count": len(events),
                "endpoint_hops": result.features.endpoint_hops,
                "goal_directedness": result.features.goal_directedness,
                "source": "osquery",
            }
        )
    return results


def write_results_csv(results: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "session_id",
        "architecture",
        "detected",
        "score",
        "reasons",
        "event_count",
        "endpoint_hops",
        "goal_directedness",
        "source",
    ]
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for result in results:
            writer.writerow(
                {
                    **result,
                    "score": f"{result['score']:.4f}",
                    "goal_directedness": f"{result['goal_directedness']:.4f}",
                }
            )


def write_synthetic_fixture(path: Path) -> None:
    """Create safe osquery-shaped data for a bridge smoke test."""

    from .generators import generate_session
    from .models import ActorProfile, TrafficClass

    sessions = [
        ("human-office", TrafficClass.BENIGN_ADMIN, ActorProfile.OFFICE_WORKER, 0),
        ("ai-adaptive", TrafficClass.AI_AGENT_ATTACKER, ActorProfile.ADAPTIVE_AI_AGENT, 4),
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as handle:
        for session_id, traffic_class, profile, adaptation_level in sessions:
            events = generate_session(
                traffic_class,
                seed=42 if traffic_class == TrafficClass.BENIGN_ADMIN else 43,
                length=32,
                adaptation_level=adaptation_level,
                actor_profile=profile,
            )
            for event in events:
                row = {
                    "event_type": event.event_type.value,
                    "timestamp": event.timestamp,
                    "host_identifier": event.endpoint_id,
                    "username": event.user,
                    "role": event.role,
                    "name": event.tool,
                    "target": event.target,
                    "command_quality": event.metadata.get("command_quality", "normal"),
                    "session_id": session_id,
                    "adaptation_level": adaptation_level,
                }
                handle.write(json.dumps(row) + "\n")


def string_value(value: Any) -> str:
    if value is None:
        return "unknown"
    return str(value)


def as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Score osquery-style endpoint observations")
    parser.add_argument("input", type=Path, help="newline-delimited JSON observations")
    parser.add_argument("--architecture", choices=[mode.value for mode in ArchitectureMode], default="centralized")
    parser.add_argument("--threshold", type=float, default=4.0)
    parser.add_argument("--output", type=Path, default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    rows = read_osquery_jsonl(args.input)
    results = score_osquery_sessions(
        rows,
        architecture=ArchitectureMode(args.architecture),
        threshold=args.threshold,
    )
    if args.output:
        write_results_csv(results, args.output)
    for result in results:
        print(
            f"{result['session_id']}: detected={result['detected']} "
            f"score={result['score']:.2f} events={result['event_count']} "
            f"reasons={result['reasons']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
