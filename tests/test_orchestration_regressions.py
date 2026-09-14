"""Include lightweight coordinator checks in default discovery, without native VTD runs."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import test_all_vtd_ordering
import test_retained_arc_ordering


def load_tests(loader, tests, pattern):
    tests.addTests(loader.loadTestsFromModule(test_all_vtd_ordering))
    tests.addTests(loader.loadTestsFromModule(test_retained_arc_ordering))
    return tests
