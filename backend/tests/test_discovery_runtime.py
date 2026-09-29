import threading
from unittest.mock import Mock

import pytest

from app.discovery import runner


def test_pool_rejects_other_factory_and_drains_accepted_work(monkeypatch):
    factory = Mock()
    started, release, closed = threading.Event(), threading.Event(), threading.Event()
    calls = []

    def execute(run_id, session_factory):
        calls.append((run_id, session_factory))
        started.set()
        assert release.wait(5)

    monkeypatch.setattr(runner, "execute_run", execute)
    runtime = runner.DiscoveryRuntime(factory)
    closer = threading.Thread(target=lambda: (runtime.close(), closed.set()))
    try:
        with pytest.raises(runner.DiscoveryUnavailable):
            runtime.submit(1, Mock())
        runtime.submit(1, factory)
        assert started.wait(5)
        closer.start()
        # An accepted worker is deliberately held open. Closing cannot return
        # before that worker's database-dependent work has finished.
        assert not closed.wait(0.05)
        release.set()
        assert closed.wait(5)
        assert calls == [(1, factory)]
        assert not runtime.owns(factory)
        with pytest.raises(runner.DiscoveryUnavailable):
            runtime.submit(2, factory)
    finally:
        release.set()
        if closer.ident is not None:
            closer.join(5)
        runtime.close()


def test_immediate_completion_and_new_lifespans_have_independent_pools(monkeypatch):
    factory = Mock()
    calls = []
    monkeypatch.setattr(runner, "execute_run", lambda run_id, owned: calls.append((run_id, owned)))
    for run_id in range(3):
        runtime = runner.DiscoveryRuntime(factory)
        runtime.submit(run_id, factory)
        runtime.close()
    assert calls == [(index, factory) for index in range(3)]
