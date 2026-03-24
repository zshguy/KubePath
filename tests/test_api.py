"""Tests for KubePath API endpoints."""

import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, patch

from kubepath.main import app


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    """Create an async test client."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestHealthEndpoint:
    """Test the health endpoint."""

    @pytest.mark.anyio
    async def test_health(self, client):
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["version"] == "1.0.0"


class TestRulesEndpoint:
    """Test the rules endpoint (no Neo4j required)."""

    @pytest.mark.anyio
    async def test_get_rules(self, client):
        response = await client.get("/api/v1/analysis/rules")
        assert response.status_code == 200
        data = response.json()
        assert data["total_rules"] > 10
        assert len(data["rules"]) > 10

        # Verify rule structure
        rule = data["rules"][0]
        assert "rule_id" in rule
        assert "name" in rule
        assert "risk_level" in rule
        assert "category" in rule


class TestUploadEndpoint:
    """Test the upload endpoint."""

    @pytest.mark.anyio
    async def test_upload_invalid_source_type(self, client):
        response = await client.post("/api/v1/ingest/upload", json={
            "source_type": "invalid",
            "data": {},
        })
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "Unknown source type" in data["error"]


class TestFrontend:
    """Test that the frontend is served."""

    @pytest.mark.anyio
    async def test_frontend_index(self, client):
        response = await client.get("/")
        assert response.status_code == 200
        # Should return HTML
        assert "KubePath" in response.text
