"""Runtime configuration from environment variables (.env supported, never logged)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"


def _load_dotenv() -> None:
    env = REPO_ROOT / ".env"
    if not env.exists():
        return
    for line in env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


_load_dotenv()


def _bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None or v == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _list(name: str, default: str = "") -> list[str]:
    return [x.strip().lower() for x in os.environ.get(name, default).split(",") if x.strip()]


@dataclass(frozen=True)
class Settings:
    api_key: str = field(default_factory=lambda: os.environ.get("PHISHDNA_API_KEY", ""))
    db_path: Path = field(default_factory=lambda: (BACKEND_DIR / os.environ.get("PHISHDNA_DB_PATH", "phishdna.db")))
    model_dir: Path = field(default_factory=lambda: (REPO_ROOT / os.environ.get("PHISHDNA_MODEL_DIR", "models")))
    rate_limit_per_min: int = field(default_factory=lambda: int(os.environ.get("PHISHDNA_RATE_LIMIT_PER_MIN", "120")))
    max_email_bytes: int = field(default_factory=lambda: int(os.environ.get("PHISHDNA_MAX_EMAIL_BYTES", str(5 * 1024 * 1024))))
    max_batch_items: int = 50
    analysis_timeout_s: float = 20.0
    retain_raw: bool = field(default_factory=lambda: _bool("PHISHDNA_RETAIN_RAW", True))
    org_domains: list[str] = field(default_factory=lambda: _list("PHISHDNA_ORG_DOMAINS", "phishdna-demo.local"))
    trusted_authserv_ids: list[str] = field(default_factory=lambda: _list("PHISHDNA_TRUSTED_AUTHSERV_IDS"))
    enable_external_lookups: bool = field(default_factory=lambda: _bool("PHISHDNA_ENABLE_EXTERNAL_LOOKUPS", False))
    virustotal_api_key: str = field(default_factory=lambda: os.environ.get("VIRUSTOTAL_API_KEY", ""))
    cors_origins: list[str] = field(default_factory=lambda: _list(
        "PHISHDNA_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173"))
    fixtures_dir: Path = REPO_ROOT / "data" / "fixtures"
    reports_dir: Path = REPO_ROOT / "data" / "reports"


settings = Settings()

RULES_VERSION = "rules-1.0.0"
FUSION_VERSION = "fusion-1.0.0"
