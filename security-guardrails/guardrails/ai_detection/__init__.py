"""
AI Detection Guardrail Module
Identifies AI-generated code for extra review
"""

from .detector import AICodeDetector

__all__ = ['AICodeDetector']