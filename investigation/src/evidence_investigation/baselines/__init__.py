"""M6 comparison methods sharing the M4 runtime and public action contract."""

from .direct import DirectBaseline
from .fixed import FixedWorkflowBaseline
from .react import ReActBaseline

__all__ = ["DirectBaseline", "FixedWorkflowBaseline", "ReActBaseline"]
