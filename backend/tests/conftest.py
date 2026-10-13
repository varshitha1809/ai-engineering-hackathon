import os
import sys
import tempfile
from pathlib import Path

# Isolated database for the whole test session; must be set before backend modules are imported.
_TMP = Path(tempfile.mkdtemp(prefix="phishdna-test-"))
os.environ["PHISHDNA_DB_PATH"] = str(_TMP / "test.db")
os.environ.setdefault("PHISHDNA_RETAIN_RAW", "true")
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402

from backend.app.analysis.model import TextModel  # noqa: E402
from backend.app.config import settings  # noqa: E402
from backend.app.db import Database  # noqa: E402
from backend.app.services.engine import Engine  # noqa: E402


def eml(headers: dict, body: str = "", html: str | None = None, attachments=()) -> bytes:
    from email.message import EmailMessage
    m = EmailMessage()
    for k, v in headers.items():
        m[k] = v
    m.set_content(body or " ")
    if html:
        m.add_alternative(html, subtype="html")
    for name, ctype, data in attachments:
        a, b = ctype.split("/")
        m.add_attachment(data, maintype=a, subtype=b, filename=name)
    return m.as_bytes()


@pytest.fixture(scope="session")
def model():
    m = TextModel(settings.model_dir)
    m.load()
    return m


@pytest.fixture()
def engine(model, tmp_path):
    db = Database(tmp_path / "engine.db")
    db.init()
    return Engine(db, model, settings)


@pytest.fixture()
def analyze(engine):
    def run(raw, source="eml", **kw):
        if isinstance(raw, str):
            raw = raw.encode()
        return engine.analyze(raw, source, persist=False, correlate=False, **kw)
    return run


def cats(result) -> set[str]:
    return {f["category"] for f in result["findings"]}
