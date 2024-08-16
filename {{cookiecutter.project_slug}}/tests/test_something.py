import os

import binaryninja
import pytest
from binaryninja import BinaryView

PROGRAM_DIRS = os.path.join(os.path.dirname(__file__), "bins")
program_under_analysis = os.path.join(PROGRAM_DIRS, "test")

if not os.path.exists(program_under_analysis):
    pytest.skip(f"Test program {program_under_analysis!r} not found")

bv: BinaryView = binaryninja.load(program_under_analysis)


def test_def_use_chain_build():
    # TODO: Implement the test
    output = True
    assert output is not None
