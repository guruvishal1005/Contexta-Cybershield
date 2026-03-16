from fastapi import APIRouter, Depends, Query, HTTPException, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.twin import digital_twin
from app.ledger import ledger
from app.schemas.twin import (
    TopologyOut,
    NodeOut,
    EdgeOut,
    NodeCreate,
    EdgeCreate,
    SimulateRequest,
    SimulationResultOut,
)

router = APIRouter()


@router.get("/topology", response_model=TopologyOut)
async def get_topology(db: AsyncSession = Depends(get_db)) -> TopologyOut:
    topo = digital_twin.get_topology()
    return TopologyOut(
        id=digital_twin._topology_id or "none",
        name="Active Topology",
        nodes=[NodeOut(**n) for n in topo["nodes"]],
        edges=[EdgeOut(**e) for e in topo["edges"]],
    )


@router.post("/simulate", response_model=SimulationResultOut)
async def simulate(
    data: SimulateRequest,
    db: AsyncSession = Depends(get_db),
) -> SimulationResultOut:
    sim_type = data.simulation_type
    node_id = data.compromised_node_id

    result: dict = {}
    if sim_type == "bfs":
        paths = digital_twin.bfs_attack_paths(node_id)
        result = {
            "simulation_type": "bfs",
            "compromised_node_id": node_id,
            "paths": paths,
            "path_count": len(paths),
            "reachable_nodes": sorted({n for p in paths for n in p}),
        }
    elif sim_type == "dfs":
        paths = digital_twin.dfs_attack_paths(node_id)
        result = {
            "simulation_type": "dfs",
            "compromised_node_id": node_id,
            "paths": paths,
            "path_count": len(paths),
            "reachable_nodes": sorted({n for p in paths for n in p}),
        }
    elif sim_type == "blast":
        blast = digital_twin.blast_radius(node_id)
        result = {"simulation_type": "blast", "compromised_node_id": node_id, **blast}
    elif sim_type == "lateral":
        lateral = digital_twin.lateral_movement_simulation(node_id)
        result = {
            "simulation_type": "lateral",
            "compromised_node_id": node_id,
            "kill_chain": lateral,
            "reachable_nodes": [
                n for s in lateral.get("stages", []) for n in s.get("affected_nodes", [])
            ],
        }
    else:
        raise HTTPException(400, f"Unknown simulation_type: {sim_type}")

    await ledger.append(
        "simulation_run", None,
        {"simulation_type": sim_type, "compromised_node_id": node_id}, db,
    )
    return SimulationResultOut(**result)


@router.post("/topology/nodes", response_model=NodeOut, status_code=201)
async def add_node(
    data: NodeCreate,
    db: AsyncSession = Depends(get_db),
) -> NodeOut:
    node_data = data.model_dump()
    await digital_twin.add_node(node_data, db)
    await ledger.append("topology_modified", None, {"action": "add_node", "node_id": data.id}, db)
    return NodeOut(**node_data)


@router.delete("/topology/nodes/{node_id}", status_code=204)
async def remove_node(
    node_id: str,
    db: AsyncSession = Depends(get_db),
) -> Response:
    await digital_twin.remove_node(node_id, db)
    await ledger.append("topology_modified", None, {"action": "remove_node", "node_id": node_id}, db)
    return Response(status_code=204)


@router.post("/topology/edges", response_model=EdgeOut, status_code=201)
async def add_edge(
    data: EdgeCreate,
    db: AsyncSession = Depends(get_db),
) -> EdgeOut:
    edge_data = data.model_dump()
    await digital_twin.add_edge(edge_data, db)
    return EdgeOut(**edge_data)


@router.delete("/topology/edges", status_code=204)
async def remove_edge(
    source_id: str = Query(...),
    target_id: str = Query(...),
    db: AsyncSession = Depends(get_db),
) -> Response:
    await digital_twin.remove_edge(source_id, target_id, db)
    return Response(status_code=204)
