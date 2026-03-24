"""Pydantic schemas for KubePath API requests and responses."""

from __future__ import annotations

from pydantic import BaseModel, Field
from typing import Any


# ── Request Schemas ────────────────────────────────────────────────

class IngestKubernetesRequest(BaseModel):
    """Request to ingest from a live Kubernetes cluster."""
    kubeconfig: str | None = Field(None, description="Path to kubeconfig file (uses default if omitted)")


class IngestAWSRequest(BaseModel):
    """Request to ingest from a live AWS account."""
    profile: str | None = Field(None, description="AWS profile name (uses default if omitted)")
    region: str = Field("us-east-1", description="AWS region")


class UploadConfigRequest(BaseModel):
    """Upload configuration data directly as JSON."""
    source_type: str = Field(..., description="Type of config: 'kubernetes' or 'aws'")
    data: dict[str, Any] = Field(..., description="Configuration data")


class PathQuery(BaseModel):
    """Query for finding paths between nodes."""
    source_uid: str = Field(..., description="Source node UID")
    target_uid: str = Field(..., description="Target node UID")
    max_hops: int = Field(10, ge=1, le=20, description="Maximum path hops")


# ── Response Schemas ───────────────────────────────────────────────

class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "healthy"
    version: str = "1.0.0"
    neo4j_connected: bool = False


class IngestResponse(BaseModel):
    """Ingestion result response."""
    success: bool
    source_type: str
    stats: dict[str, Any] = {}
    error: str | None = None


class GraphResponse(BaseModel):
    """Full graph data response (Cytoscape format)."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    total_nodes: int = 0
    total_edges: int = 0


class NodeDetailResponse(BaseModel):
    """Node detail with neighbors."""
    node: dict[str, Any] = {}
    neighbors: list[dict[str, Any]] = []


class AttackPathsResponse(BaseModel):
    """Attack paths response."""
    paths: list[dict[str, Any]] = []
    total_paths: int = 0


class ScoreResponse(BaseModel):
    """Overall risk score response."""
    score: float = 0.0
    grade: str = "N/A"
    risk_level: str = "INFO"
    factors: list[dict[str, Any]] = []
    summary: str = ""
    stats: dict[str, Any] = {}


class FindingsResponse(BaseModel):
    """Security findings response."""
    findings: list[dict[str, Any]] = []
    total_findings: int = 0


class StatsResponse(BaseModel):
    """Graph statistics response."""
    total_nodes: int = 0
    total_edges: int = 0
    node_types: dict[str, int] = {}
    risk_breakdown: dict[str, int] = {}


class ClearResponse(BaseModel):
    """Graph clear response."""
    success: bool
    deleted: int = 0


class RulesResponse(BaseModel):
    """Attack rules response."""
    rules: list[dict[str, Any]] = []
    total_rules: int = 0
