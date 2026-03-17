"""Digital Twin network simulation engine using NetworkX DiGraph."""

import json
import logging
import random
from collections import deque

import networkx as nx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.network_topology import NetworkTopology

logger = logging.getLogger(__name__)


class DigitalTwinEngine:
    def __init__(self) -> None:
        self._graph = nx.DiGraph()
        self._topology_id: str | None = None

    async def load_from_db(self, db: AsyncSession) -> None:
        result = await db.execute(
            select(NetworkTopology).where(NetworkTopology.is_active.is_(True)).limit(1)
        )
        topo = result.scalar_one_or_none()
        if not topo:
            logger.info("No active network topology found")
            return

        self._topology_id = topo.id
        self._graph.clear()

        for node in topo.nodes or []:
            self._graph.add_node(
                node["id"],
                label=node.get("label", node["id"]),
                node_type=node.get("node_type", "server"),
                criticality=node.get("criticality", 5),
                ip_address=node.get("ip_address"),
                subnet=node.get("subnet"),
                is_internet_facing=node.get("is_internet_facing", False),
                **{k: v for k, v in node.items() if k not in (
                    "id", "label", "node_type", "criticality",
                    "ip_address", "subnet", "is_internet_facing"
                )},
            )

        for edge in topo.edges or []:
            self._graph.add_edge(
                edge["source"],
                edge["target"],
                edge_type=edge.get("edge_type", "network"),
                weight=edge.get("weight", 1.0),
                **{k: v for k, v in edge.items() if k not in (
                    "source", "target", "edge_type", "weight"
                )},
            )
        logger.info(
            "Loaded topology %s: %d nodes, %d edges",
            topo.name, self._graph.number_of_nodes(), self._graph.number_of_edges(),
        )

    def bfs_attack_paths(
        self, start_node_id: str, max_depth: int = 8
    ) -> list[list[str]]:
        if start_node_id not in self._graph:
            return []

        paths: list[list[str]] = []
        queue: deque[list[str]] = deque([[start_node_id]])

        while queue:
            path = queue.popleft()
            if len(path) > max_depth:
                continue
            if len(path) > 1:
                paths.append(path)
            current = path[-1]
            for neighbor in self._graph.successors(current):
                if neighbor not in path:
                    queue.append(path + [neighbor])

        return paths

    def dfs_attack_paths(
        self, start_node_id: str, max_depth: int = 6
    ) -> list[list[str]]:
        if start_node_id not in self._graph:
            return []

        paths: list[list[str]] = []

        def _dfs(current: str, path: list[str]) -> None:
            if len(paths) >= 50:
                return
            if len(path) > max_depth:
                return
            if len(path) > 1:
                paths.append(list(path))
            for neighbor in self._graph.successors(current):
                if neighbor not in path:
                    path.append(neighbor)
                    _dfs(neighbor, path)
                    path.pop()

        _dfs(start_node_id, [start_node_id])
        return paths

    def blast_radius(self, compromised_node_id: str) -> dict:
        if compromised_node_id not in self._graph:
            return {
                "reachable_nodes": [],
                "critical_assets_at_risk": [],
                "estimated_lateral_moves": 0,
                "path_count": 0,
                "risk_score": 0.0,
            }

        reachable = set(nx.descendants(self._graph, compromised_node_id))
        critical = [
            n for n in reachable
            if self._graph.nodes[n].get("criticality", 0) >= 7
        ]

        paths = self.bfs_attack_paths(compromised_node_id, max_depth=6)
        max_crit = max(
            (self._graph.nodes[n].get("criticality", 0) for n in reachable),
            default=0,
        )
        risk_score = min(10.0, (len(reachable) * 0.5 + max_crit) * (len(critical) + 1) / 5)

        affected_nodes = [
            {"id": n, "label": self._graph.nodes[n].get("label", n),
             "criticality": self._graph.nodes[n].get("criticality", 0),
             "ip_address": self._graph.nodes[n].get("ip_address")}
            for n in reachable
        ]

        return {
            "reachable_nodes": sorted(reachable),
            "affected_nodes": affected_nodes,
            "critical_assets_at_risk": sorted(critical),
            "estimated_lateral_moves": len(reachable),
            "path_count": len(paths),
            "risk_score": round(risk_score, 2),
        }

    def lateral_movement_simulation(self, start_node_id: str) -> dict:
        stages = [
            "Reconnaissance",
            "Credential Harvest",
            "Privilege Escalation",
            "Lateral Movement",
            "Data Exfiltration",
        ]

        if start_node_id not in self._graph:
            return {
                "stages": [
                    {"name": s, "affected_nodes": [], "probability": 0.0}
                    for s in stages
                ]
            }

        reachable = list(nx.descendants(self._graph, start_node_id))
        result_stages = []
        cumulative_prob = 0.95
        affected_so_far: list[str] = [start_node_id]

        for stage in stages:
            prob = round(cumulative_prob * random.uniform(0.7, 1.0), 3)
            new_nodes = reachable[: len(affected_so_far) + 2]
            affected_so_far = list(set(affected_so_far + new_nodes))
            result_stages.append({
                "name": stage,
                "affected_nodes": list(affected_so_far),
                "probability": prob,
            })
            cumulative_prob *= 0.85

        return {"stages": result_stages}

    async def add_node(self, node_data: dict, db: AsyncSession) -> dict:
        nid = node_data["id"]
        self._graph.add_node(nid, **{k: v for k, v in node_data.items() if k != "id"})
        await self._persist(db)
        return node_data

    async def remove_node(self, node_id: str, db: AsyncSession) -> None:
        if node_id in self._graph:
            self._graph.remove_node(node_id)
            await self._persist(db)

    async def add_edge(self, edge_data: dict, db: AsyncSession) -> dict:
        self._graph.add_edge(
            edge_data["source"],
            edge_data["target"],
            edge_type=edge_data.get("edge_type", "network"),
            weight=edge_data.get("weight", 1.0),
        )
        await self._persist(db)
        return edge_data

    async def remove_edge(self, source: str, target: str, db: AsyncSession) -> None:
        if self._graph.has_edge(source, target):
            self._graph.remove_edge(source, target)
            await self._persist(db)

    def get_topology(self) -> dict:
        nodes = []
        for nid, data in self._graph.nodes(data=True):
            nodes.append({"id": nid, **data})
        edges = []
        for src, tgt, data in self._graph.edges(data=True):
            edges.append({"source": src, "target": tgt, **data})
        return {"nodes": nodes, "edges": edges}

    async def _persist(self, db: AsyncSession) -> None:
        if not self._topology_id:
            return
        result = await db.execute(
            select(NetworkTopology).where(NetworkTopology.id == self._topology_id)
        )
        topo = result.scalar_one_or_none()
        if topo:
            t = self.get_topology()
            topo.nodes = t["nodes"]
            topo.edges = t["edges"]
            await db.flush()


digital_twin = DigitalTwinEngine()
