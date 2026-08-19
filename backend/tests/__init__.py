"""Test package.

This file makes `tests` a real package so that shared helpers import the same
way under any invocation. Without it `from tests.phase1 import Recorder`
resolves only when the working directory happens to be on `sys.path`, which is
true for `python -m pytest` and false for the bare `pytest` that CI runs.
"""
