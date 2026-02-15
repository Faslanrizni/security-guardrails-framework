"""
Secrets Guardrail Module
Detects and blocks hardcoded secrets
"""

from .scanner import SecretsScanner
from .freezer import RepoFreezer

__all__ = ['SecretsScanner', 'RepoFreezer']