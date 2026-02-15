"""
Security Guardrails Framework
A comprehensive security automation framework
"""

__version__ = "1.0.0"

from . import contract
from . import secrets
from . import sast
from . import ai_detection
from . import dependencies
from . import iac
from . import provenance
from . import enforcement
from . import metrics

__all__ = [
    'contract',
    'secrets',
    'sast',
    'ai_detection',
    'dependencies',
    'iac',
    'provenance',
    'enforcement',
    'metrics',
]