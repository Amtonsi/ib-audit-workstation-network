from __future__ import annotations

from math import cos, pi, sin
from typing import Any


SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

TOPOLOGY_PALETTE = {
    "local": ("#2563EB", "#93C5FD", "#FFFFFF"),
    "gateway": ("#DCFCE7", "#4ADE80", "#166534"),
    "service": ("#FFF7D6", "#F6C453", "#92400E"),
    "dns": ("#E6F9FE", "#38BDF8", "#075985"),
    "adapter": ("#F1F5F9", "#94A3B8", "#334155"),
    "loopback": ("#F1F5F9", "#94A3B8", "#334155"),
    "risk": ("#FFE4E6", "#FB7185", "#BE123C"),
    "external": ("#ECFEFF", "#2DD4BF", "#115E59"),
    "endpoint": ("#EFF6FF", "#93C5FD", "#1E3A8A"),
}

TOPOLOGY_ROLE_LABELS = {
    "local": "ЛОКАЛЬНЫЙ УЗЕЛ",
    "gateway": "ШЛЮЗ",
    "service": "СЕРВИС",
    "dns": "DNS",
    "adapter": "ИНТЕРФЕЙС",
    "loopback": "ЛОКАЛЬНАЯ ЦЕЛЬ",
    "risk": "РИСК",
    "external": "ВНЕШНИЙ УЗЕЛ",
    "endpoint": "УЗЕЛ",
}


def normalize_topology_severity(value: object) -> str:
    normalized = str(value or "INFO").strip().upper()
    aliases = {"WARNING": "MEDIUM", "WARN": "MEDIUM", "ERROR": "HIGH"}
    return aliases.get(normalized, normalized if normalized in SEVERITY_RANK else "INFO")


def short_topology_label(value: object, limit: int = 23) -> str:
    text = str(value or "-").strip()
    if text.startswith("service:"):
        text = text.rsplit(":", 1)[-1]
    return text if len(text) <= limit else f"{text[: limit - 1]}…"


def topology_vector_size(node_count: int) -> tuple[int, int]:
    satellites = max(0, int(node_count) - 1)
    ring_count = 0
    capacity = 8
    while satellites > 0:
        satellites -= capacity
        ring_count += 1
        capacity += 4
    extra_rings = max(0, ring_count - 2)
    return 900 + extra_rings * 220, 400 + extra_rings * 150


def build_topology_layout(
    graph: dict[str, object],
    *,
    width: float,
    height: float,
    include_all: bool,
) -> dict[str, Any]:
    all_nodes = [item for item in graph.get("nodes", []) if isinstance(item, dict)]
    all_edges = [item for item in graph.get("edges", []) if isinstance(item, dict)]
    if not all_nodes:
        return {
            "nodes": [],
            "edges": [],
            "positions": {},
            "center": "",
            "scale": 1.0,
            "hidden_count": 0,
        }

    known_ids = {str(node.get("id") or node.get("ip") or "") for node in all_nodes}
    center_id = str(graph.get("center") or "")
    if center_id not in known_ids:
        center_id = str(all_nodes[0].get("id") or all_nodes[0].get("ip") or "")

    def node_priority(node: dict[str, object]) -> tuple[int, int, int, int, str]:
        node_id = str(node.get("id") or node.get("ip") or "")
        return (
            1 if node_id == center_id else 0,
            SEVERITY_RANK[normalize_topology_severity(node.get("severity"))],
            int(node.get("degree") or node.get("neighbor_count") or 0),
            int(node.get("packets") or 0),
            node_id,
        )

    ordered_nodes = sorted(all_nodes, key=node_priority, reverse=True)
    if include_all:
        visible_nodes = ordered_nodes
    else:
        density_capacity = max(7, min(31, int(width / 105) * max(1, int(height / 90))))
        visible_nodes = ordered_nodes[:density_capacity]
        if center_id not in {str(node.get("id") or node.get("ip") or "") for node in visible_nodes}:
            visible_nodes[-1] = next(
                node for node in all_nodes if str(node.get("id") or node.get("ip") or "") == center_id
            )

    visible_ids = {str(node.get("id") or node.get("ip") or "") for node in visible_nodes}
    visible_edges = [
        edge
        for edge in all_edges
        if str(edge.get("source") or "") in visible_ids and str(edge.get("target") or "") in visible_ids
    ]

    scale = max(0.68, min(1.18, min(width / 760, height / 285)))
    if len(visible_nodes) > 18:
        scale *= 0.76
    elif len(visible_nodes) > 10:
        scale *= 0.87

    center_x = width * 0.46
    center_y = height * 0.53
    positions: dict[str, tuple[float, float]] = {center_id: (center_x, center_y)}
    satellites = [
        node for node in visible_nodes if str(node.get("id") or node.get("ip") or "") != center_id
    ]
    rings: list[list[dict[str, object]]] = []
    if include_all:
        offset = 0
        capacity = 8
        while offset < len(satellites):
            rings.append(satellites[offset : offset + capacity])
            offset += capacity
            capacity += 4
    else:
        first_ring_size = min(8, len(satellites))
        if first_ring_size:
            rings.append(satellites[:first_ring_size])
        if len(satellites) > first_ring_size:
            rings.append(satellites[first_ring_size:])

    for ring_index, ring in enumerate(rings):
        radius_x = min(width * (0.29 + ring_index * 0.16), width / 2 - 66 * scale)
        radius_y = min(height * (0.31 + ring_index * 0.13), height / 2 - 28 * scale)
        radius_x = max(radius_x, 120 * scale)
        radius_y = max(radius_y, 56 * scale)
        angle_offset = -pi / 2 + (pi / max(len(ring), 1) if ring_index else 0)
        for index, node in enumerate(ring):
            angle = angle_offset + 2 * pi * index / max(len(ring), 1)
            x = center_x + radius_x * cos(angle)
            y = center_y + radius_y * sin(angle)
            node_id = str(node.get("id") or node.get("ip") or "")
            positions[node_id] = (
                min(width - 82 * scale, max(82 * scale, x)),
                min(height - 34 * scale, max(42 * scale, y)),
            )

    return {
        "nodes": visible_nodes,
        "edges": visible_edges,
        "positions": positions,
        "center": center_id,
        "scale": scale,
        "hidden_count": max(0, len(all_nodes) - len(visible_nodes)),
    }
