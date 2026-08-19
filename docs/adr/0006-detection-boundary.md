# ADR 0006: A detector concludes; it never reaches

**Status:** Accepted

Phase 2 introduces findings, and the risk it introduces with them is that a component allowed to interpret data starts wanting to go and get more of it. The detection boundary is therefore deliberately weaker than the discovery adapter boundary rather than parallel to it.

A discovery adapter may contact a target, after DockGuard allows it. A detector may not contact anything. It receives a frozen snapshot of one Dockyard's recorded assets, services and observations and returns value objects. It is given no database session, no socket, no subprocess, no target string and no operator-supplied option, so there is nothing for it to widen, execute or reach, and it needs no scope decision because it reaches nothing. This is enforced structurally: the detector modules are parsed in the test suite and refused if they import anything that could reach outside the process or touch the database.

Everything that could be got wrong belongs to the runner rather than the detector. The runner builds the snapshot, validates the output, computes identity, reconciles against what is already known, resolves what is no longer reproduced and writes evidence. A detector that returns something malformed is failed as a whole and its results are discarded, because a component that has demonstrated it is wrong about its own output is not one to half-believe, and a detector that failed resolves nothing — not running is not evidence that an issue went away.

Two invariants make a finding checkable rather than merely stated. A finding must cite at least one observation from the snapshot it was drawn from, and a finding with no evidence is refused rather than stored with a caveat. Identity is a SHA-256 fingerprint over the detector, the rule and the asset and service concerned, so the same issue stays one record across runs, restarts and processes; Python's randomized `hash()` would make every finding look new after a restart.

A finding is never deleted. One that a later successful run no longer reproduces is resolved and kept, because the record that it was once true is part of what an assessment is for.
