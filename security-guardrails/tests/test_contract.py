#!/usr/bin/env python3
"""
Test the security contract validator
"""

import os
import tempfile
import shutil
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from guardrails.contract.validator import SecurityContractValidator


def test_valid_contract():
    """Test that a valid contract passes"""
    # Create temp directory
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir)
        
        # Create security directory
        security_dir = repo_path / "security"
        security_dir.mkdir()
        
        # Create valid files
        (security_dir / "SECURITY.md").write_text("""
# Security Policy

## Supported Versions
Version 1.x supported

## Reporting a Vulnerability
Contact: security@example.com
        """)
        
        (security_dir / "threat-model.yaml").write_text("""
version: 1.0
metadata:
  name: "test"
  description: "test"
  criticality: "medium"
  last_reviewed: "2024-01-01"
assets:
  - id: "ASSET-001"
    name: "Test"
    type: "pii"
    sensitivity: "high"
    location: "db"
threats:
  - id: "THREAT-001"
    name: "Test"
    description: "test"
    stride_category: "Tampering"
    affected_components: ["api"]
    mitigations:
      - id: "MIT-001"
        name: "Fix"
        description: "test"
        status: "planned"
        owner: "team"
        due_date: "2024-02-01"
        """)
        
        (security_dir / "security-owners.yaml").write_text("""
version: 1.0
owners:
  security-team:
    team: "@org/security"
    paths: ["*"]
critical_paths:
  - path: "auth/"
    reason: "test"
    required_approvers: ["@org/security"]
        """)
        
        (security_dir / "allowed-tools.yaml").write_text("""
version: 1.0
required_tools:
  - name: "semgrep"
blocked_tools:
  - name: "bandit"
        """)
        
        # Validate
        validator = SecurityContractValidator(str(repo_path))
        assert validator.validate() == True
        print("✅ Valid contract test passed")


def test_missing_files():
    """Test that missing files are caught"""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir)
        
        # No security directory
        validator = SecurityContractValidator(str(repo_path))
        assert validator.validate() == False
        print("✅ Missing directory test passed")


if __name__ == "__main__":
    test_valid_contract()
    test_missing_files()
    print("\n🎉 All contract tests passed!")