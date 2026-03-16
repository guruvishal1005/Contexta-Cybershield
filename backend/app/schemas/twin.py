from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class _CamelBase(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )


class NodeOut(_CamelBase):
    id: str
    label: str
    node_type: str = ""
    criticality: int = 5
    ip_address: str | None = None
    subnet: str | None = None
    is_internet_facing: bool = False
    metadata: dict = {}


class EdgeOut(_CamelBase):
    source: str
    target: str
    edge_type: str = "network"
    weight: float = 1.0
    metadata: dict = {}


class TopologyOut(_CamelBase):
    id: str
    name: str
    description: str | None = None
    nodes: list[NodeOut] = []
    edges: list[EdgeOut] = []
    is_active: bool = True


class NodeCreate(_CamelBase):
    id: str
    label: str
    node_type: str = "server"
    criticality: int = 5
    ip_address: str | None = None
    subnet: str | None = None
    is_internet_facing: bool = False
    metadata: dict = {}


class EdgeCreate(_CamelBase):
    source: str
    target: str
    edge_type: str = "network"
    weight: float = 1.0
    metadata: dict = {}


class SimulateRequest(_CamelBase):
    compromised_node_id: str
    simulation_type: str = "blast"


class SimulationResultOut(_CamelBase):
    simulation_type: str
    compromised_node_id: str
    reachable_nodes: list[str] = []
    critical_assets_at_risk: list[str] = []
    estimated_lateral_moves: int = 0
    path_count: int = 0
    risk_score: float = 0.0
    paths: list[list[str]] = []
    kill_chain: dict | None = None
