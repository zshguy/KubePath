"""FastAPI route definitions for KubePath."""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, UploadFile, File

from kubepath.api.schemas import (
    HealthResponse, IngestResponse, IngestKubernetesRequest, IngestAWSRequest,
    UploadConfigRequest, GraphResponse, NodeDetailResponse, AttackPathsResponse,
    PathQuery, ScoreResponse, FindingsResponse, StatsResponse, ClearResponse,
    RulesResponse,
)
from kubepath.database.neo4j_client import neo4j_client
from kubepath.ingestion.kubernetes import KubernetesIngestor
from kubepath.ingestion.aws import AWSIngestor
from kubepath.analysis.pathfinder import pathfinder
from kubepath.analysis.scoring import risk_scorer
from kubepath.analysis.rules import get_all_rules

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["KubePath API"])


# ── Health ─────────────────────────────────────────────────────────

@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    neo4j_ok = False
    try:
        stats = await neo4j_client.get_stats()
        neo4j_ok = True
    except Exception:
        pass
    return HealthResponse(status="healthy", version="1.0.0", neo4j_connected=neo4j_ok)


# ── Ingestion ──────────────────────────────────────────────────────

@router.post("/ingest/kubernetes", response_model=IngestResponse)
async def ingest_kubernetes(request: IngestKubernetesRequest | None = None):
    """Ingest from a live Kubernetes cluster."""
    try:
        ingestor = KubernetesIngestor()
        kwargs = {}
        if request and request.kubeconfig:
            kwargs["kubeconfig"] = request.kubeconfig
        stats = await ingestor.ingest(**kwargs)

        if "error" in stats:
            return IngestResponse(success=False, source_type="kubernetes", error=stats["error"])

        return IngestResponse(success=True, source_type="kubernetes", stats=stats)
    except Exception as e:
        logger.error("Kubernetes ingestion failed: %s", e, exc_info=True)
        return IngestResponse(success=False, source_type="kubernetes", error=str(e))


@router.post("/ingest/aws", response_model=IngestResponse)
async def ingest_aws(request: IngestAWSRequest | None = None):
    """Ingest from a live AWS account."""
    try:
        ingestor = AWSIngestor()
        kwargs = {}
        if request:
            if request.profile:
                kwargs["profile"] = request.profile
            kwargs["region"] = request.region
        stats = await ingestor.ingest(**kwargs)

        if "error" in stats:
            return IngestResponse(success=False, source_type="aws", error=stats["error"])

        return IngestResponse(success=True, source_type="aws", stats=stats)
    except Exception as e:
        logger.error("AWS ingestion failed: %s", e, exc_info=True)
        return IngestResponse(success=False, source_type="aws", error=str(e))


@router.post("/ingest/upload", response_model=IngestResponse)
async def ingest_upload(request: UploadConfigRequest):
    """Upload configuration data directly as JSON."""
    try:
        if request.source_type == "kubernetes":
            ingestor = KubernetesIngestor()
        elif request.source_type == "aws":
            ingestor = AWSIngestor()
        else:
            return IngestResponse(
                success=False, source_type=request.source_type,
                error=f"Unknown source type: {request.source_type}"
            )

        stats = await ingestor.ingest_from_data(request.data)
        return IngestResponse(success=True, source_type=request.source_type, stats=stats)
    except Exception as e:
        logger.error("Upload ingestion failed: %s", e, exc_info=True)
        return IngestResponse(success=False, source_type=request.source_type, error=str(e))


@router.post("/ingest/file", response_model=IngestResponse)
async def ingest_file(source_type: str, file: UploadFile = File(...)):
    """Upload a JSON config file."""
    try:
        content = await file.read()
        data = json.loads(content)

        if source_type == "kubernetes":
            ingestor = KubernetesIngestor()
        elif source_type == "aws":
            ingestor = AWSIngestor()
        else:
            return IngestResponse(
                success=False, source_type=source_type,
                error=f"Unknown source type: {source_type}"
            )

        stats = await ingestor.ingest_from_data(data)
        return IngestResponse(success=True, source_type=source_type, stats=stats)
    except json.JSONDecodeError:
        return IngestResponse(success=False, source_type=source_type, error="Invalid JSON file")
    except Exception as e:
        logger.error("File ingestion failed: %s", e, exc_info=True)
        return IngestResponse(success=False, source_type=source_type, error=str(e))


# ── Graph ──────────────────────────────────────────────────────────

@router.get("/graph", response_model=GraphResponse)
async def get_graph():
    """Get the full graph data for visualization."""
    try:
        graph = await neo4j_client.get_full_graph()
        return GraphResponse(
            nodes=graph["nodes"],
            edges=graph["edges"],
            total_nodes=len(graph["nodes"]),
            total_edges=len(graph["edges"]),
        )
    except Exception as e:
        logger.error("Failed to get graph: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/graph/node/{uid}", response_model=NodeDetailResponse)
async def get_node_detail(uid: str):
    """Get node details and neighbors."""
    try:
        result = await neo4j_client.get_node_neighbors(uid)
        if not result:
            raise HTTPException(status_code=404, detail="Node not found")
        return NodeDetailResponse(
            node=result.get("node", {}),
            neighbors=result.get("neighbors", []),
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get node: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ── Analysis ───────────────────────────────────────────────────────

@router.get("/analysis/paths", response_model=AttackPathsResponse)
async def get_attack_paths(max_hops: int = 8):
    """Find all attack paths to admin-level targets."""
    try:
        paths = await pathfinder.find_paths_to_admin(max_hops=max_hops)
        return AttackPathsResponse(paths=paths, total_paths=len(paths))
    except Exception as e:
        logger.error("Failed to find attack paths: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analysis/path", response_model=AttackPathsResponse)
async def find_path(query: PathQuery):
    """Find paths between two specific nodes."""
    try:
        paths = await pathfinder.find_path_between(
            query.source_uid, query.target_uid, query.max_hops
        )
        return AttackPathsResponse(paths=paths, total_paths=len(paths))
    except Exception as e:
        logger.error("Failed to find paths: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/analysis/critical")
async def get_critical_nodes():
    """Get critical chokepoint nodes."""
    try:
        nodes = await pathfinder.find_critical_nodes()
        return {"nodes": nodes, "total": len(nodes)}
    except Exception as e:
        logger.error("Failed to find critical nodes: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/analysis/entry-points")
async def get_entry_points():
    """Get externally accessible entry points."""
    try:
        entries = await pathfinder.find_external_entry_points()
        return {"entry_points": entries, "total": len(entries)}
    except Exception as e:
        logger.error("Failed to find entry points: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/analysis/score", response_model=ScoreResponse)
async def get_risk_score():
    """Get the overall risk score."""
    try:
        score = await risk_scorer.compute_overall_score()
        return ScoreResponse(**score)
    except Exception as e:
        logger.error("Failed to compute score: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/analysis/findings", response_model=FindingsResponse)
async def get_findings():
    """Get security findings."""
    try:
        findings = await risk_scorer.get_findings()
        return FindingsResponse(findings=findings, total_findings=len(findings))
    except Exception as e:
        logger.error("Failed to get findings: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/analysis/rules", response_model=RulesResponse)
async def get_attack_rules():
    """Get all known attack pattern rules."""
    rules = get_all_rules()
    return RulesResponse(rules=rules, total_rules=len(rules))


# ── Stats & Management ────────────────────────────────────────────

@router.get("/stats", response_model=StatsResponse)
async def get_stats():
    """Get graph statistics."""
    try:
        stats = await neo4j_client.get_stats()
        return StatsResponse(**stats)
    except Exception as e:
        logger.error("Failed to get stats: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/graph", response_model=ClearResponse)
async def clear_graph():
    """Clear the entire graph."""
    try:
        deleted = await neo4j_client.clear_graph()
        return ClearResponse(success=True, deleted=deleted)
    except Exception as e:
        logger.error("Failed to clear graph: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
