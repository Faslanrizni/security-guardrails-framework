"""
IaC Guardrail Module
Scans Infrastructure as Code for security misconfigurations
"""

from .scanner import IaCScanner

__all__ = ['IaCScanner']