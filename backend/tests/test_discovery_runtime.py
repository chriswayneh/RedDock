import threading
from unittest.mock import Mock

import pytest

from app.discovery import runner
from app.workflow_authorization import LOCAL_WORKFLOW_POLICY


def test_pool_rejects_other_factory_and_drains_accepted_work(monkeypatch):
    factory = Mock()
    started, release, closed = threading.Event(), threading.Event(), threading.Event()
    calls = []

    def execute(run_id, session_factory, receipt, policy):
        calls.append((run_id, session_factory, receipt, policy))
        started.set()
        assert release.wait(5)

    monkeypatch.setattr(runner, "execute_run", execute)
    runtime = runner.DiscoveryRuntime(factory, LOCAL_WORKFLOW_POLICY)
    closer = threading.Thread(target=lambda: (runtime.close(), closed.set()))
    try:
        with pytest.raises(runner.DiscoveryUnavailable):
            runtime.submit(1, Mock(), 19)
        runtime.submit(1, factory, 19)
        assert started.wait(5)
        closer.start()
        # An accepted worker is deliberately held open. Closing cannot return
        # before that worker's database-dependent work has finished.
        assert not closed.wait(0.05)
        release.set()
        assert closed.wait(5)
        assert calls == [(1, factory, 19, LOCAL_WORKFLOW_POLICY)]
        assert not runtime.owns(factory, "local")
        with pytest.raises(runner.DiscoveryUnavailable):
            runtime.submit(2, factory, 20)
    finally:
        release.set()
        if closer.ident is not None:
            closer.join(5)
        runtime.close()


def test_immediate_completion_and_new_lifespans_have_independent_pools(monkeypatch):
    factory = Mock()
    calls = []
    monkeypatch.setattr(runner, "execute_run", lambda run_id, owned, receipt, policy:
                        calls.append((run_id, owned, receipt, policy)))
    for run_id in range(3):
        runtime = runner.DiscoveryRuntime(factory, LOCAL_WORKFLOW_POLICY)
        assert not runtime.owns(factory, "server")
        runtime.submit(run_id, factory, run_id + 10)
        runtime.close()
    assert calls == [(index, factory, index + 10, LOCAL_WORKFLOW_POLICY) for index in range(3)]
