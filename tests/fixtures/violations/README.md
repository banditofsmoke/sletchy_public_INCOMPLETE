# Deliberately-broken modules

Each file here violates one architectural rule on purpose, so
`tests/unit/test_import_layers.py` can prove the corresponding contract **fails**
rather than merely observing that the real code passes.

A contract that has never been seen to fail is a hypothesis. These fixtures are how
it becomes a test.

**Nothing here is importable by the package.** They live outside `src/`, are never
collected by pytest as tests, and are read as text by the analyser under test.
