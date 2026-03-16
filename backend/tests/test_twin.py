"""Digital Twin engine tests with hardcoded 8-node graph."""

import pytest

from app.twin.engine import DigitalTwinEngine


@pytest.fixture
def twin():
    engine = DigitalTwinEngine()
    # Build an 8-node sample graph:
    #   internet -> firewall -> dmz -> app1 -> db (crit=9)
    #                        -> dmz -> app2 -> db
    #   firewall -> vpn -> admin (crit=8)
    nodes = [
        {"id": "internet", "label": "Internet", "node_type": "external", "criticality": 1},
        {"id": "firewall", "label": "Firewall", "node_type": "firewall", "criticality": 8},
        {"id": "dmz", "label": "DMZ", "node_type": "network", "criticality": 5},
        {"id": "app1", "label": "App Server 1", "node_type": "server", "criticality": 6},
        {"id": "app2", "label": "App Server 2", "node_type": "server", "criticality": 6},
        {"id": "db", "label": "Database", "node_type": "database", "criticality": 9},
        {"id": "vpn", "label": "VPN Gateway", "node_type": "network", "criticality": 7},
        {"id": "admin", "label": "Admin Workstation", "node_type": "endpoint", "criticality": 8},
    ]
    edges = [
        ("internet", "firewall"),
        ("firewall", "dmz"),
        ("firewall", "vpn"),
        ("dmz", "app1"),
        ("dmz", "app2"),
        ("app1", "db"),
        ("app2", "db"),
        ("vpn", "admin"),
    ]

    for node in nodes:
        engine._graph.add_node(
            node["id"],
            label=node["label"],
            node_type=node["node_type"],
            criticality=node["criticality"],
        )
    for src, tgt in edges:
        engine._graph.add_edge(src, tgt, edge_type="network", weight=1.0)

    return engine


def test_bfs_respects_max_depth(twin):
    paths = twin.bfs_attack_paths("internet", max_depth=2)
    for path in paths:
        assert len(path) <= 3  # max_depth=2 means max 3 nodes in path


def test_bfs_finds_paths(twin):
    paths = twin.bfs_attack_paths("internet", max_depth=8)
    assert len(paths) > 0
    # Should be able to reach db
    all_nodes = {n for p in paths for n in p}
    assert "db" in all_nodes


def test_dfs_returns_paths(twin):
    paths = twin.dfs_attack_paths("internet", max_depth=6)
    assert len(paths) > 0
    assert len(paths) <= 50


def test_blast_radius_identifies_critical_nodes(twin):
    result = twin.blast_radius("firewall")
    assert "db" in result["critical_assets_at_risk"]  # criticality=9
    assert "admin" in result["critical_assets_at_risk"]  # criticality=8
    assert result["risk_score"] > 0


def test_blast_radius_nonexistent_node(twin):
    result = twin.blast_radius("nonexistent")
    assert result["reachable_nodes"] == []
    assert result["risk_score"] == 0.0


def test_lateral_movement(twin):
    result = twin.lateral_movement_simulation("firewall")
    assert "stages" in result
    assert len(result["stages"]) == 5
    for stage in result["stages"]:
        assert "name" in stage
        assert "probability" in stage
        assert stage["probability"] > 0


def test_get_topology(twin):
    topo = twin.get_topology()
    assert len(topo["nodes"]) == 8
    assert len(topo["edges"]) == 8
