"""KubePath configuration management."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

# Load .env file if it exists
_env_path = Path(__file__).resolve().parent.parent / ".env"
if _env_path.exists():
    load_dotenv(_env_path)


@dataclass(frozen=True)
class Neo4jConfig:
    """Neo4j connection configuration."""
    uri: str = field(default_factory=lambda: os.getenv("NEO4J_URI", "bolt://localhost:7687"))
    user: str = field(default_factory=lambda: os.getenv("NEO4J_USER", "neo4j"))
    password: str = field(default_factory=lambda: os.getenv("NEO4J_PASSWORD", "kubepath_secret"))
    database: str = field(default_factory=lambda: os.getenv("NEO4J_DATABASE", "neo4j"))
    max_connection_pool_size: int = 50


@dataclass(frozen=True)
class ServerConfig:
    """KubePath server configuration."""
    host: str = field(default_factory=lambda: os.getenv("KUBEPATH_HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: int(os.getenv("KUBEPATH_PORT", "8000")))


@dataclass(frozen=True)
class AppConfig:
    """Root application configuration."""
    neo4j: Neo4jConfig = field(default_factory=Neo4jConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    version: str = "1.0.0"
    app_name: str = "KubePath"
    frontend_dir: str = field(
        default_factory=lambda: str(Path(__file__).resolve().parent.parent / "frontend")
    )


# Singleton config instance
settings = AppConfig()
