import pytest

from cvescout import sources


@pytest.fixture(autouse=True)
def no_network(monkeypatch, tmp_path):
    """Tests use fakes; a real request means a source call slipped past them. The disk cache goes to tmp_path."""

    def blocked(*a, **k):
        raise AssertionError("network access in a test")

    monkeypatch.setattr(sources.urllib.request, "urlopen", blocked)
    monkeypatch.setattr(sources, "_cache_dir", lambda: tmp_path / "cache")
