"""Process-wide singletons (database, model, engine, benchmark runner)."""
from __future__ import annotations

from .analysis.model import TextModel
from .config import settings
from .db import Database
from .evaluation.benchmark import BenchmarkRunner
from .services.engine import Engine


class AppState:
    def __init__(self) -> None:
        self.db = Database(settings.db_path)
        self.model = TextModel(settings.model_dir)
        self.engine = Engine(self.db, self.model, settings)
        self.runner = BenchmarkRunner(self.engine, self.db)
        self.started_at: str = ""
        self.request_errors: int = 0

    def startup(self) -> None:
        from datetime import datetime, timezone
        self.db.init()
        self.model.load()
        self.started_at = datetime.now(timezone.utc).isoformat()
        # runs interrupted by a restart must not stay "running" forever
        self.db.execute("UPDATE evaluation_runs SET status='failed', error='interrupted by server restart' "
                        "WHERE status IN ('queued','running')")


state = AppState()
