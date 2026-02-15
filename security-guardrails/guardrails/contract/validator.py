#!/usr/bin/env python3
"""
Security Contract Validator
Ensures every repo has the required security files
"""

import os
import yaml
import sys
from pathlib import Path
from typing import List, Dict, Any
import argparse


class SecurityContractValidator:
    """
    Validates that repositories comply with the security contract.
    Checks for required files and validates their contents.
    """
    
    def __init__(self, repo_path: str = "."):
        self.repo_path = Path(repo_path)
        self.security_dir = self.repo_path / "security"
        self.violations = []
        
        # Required files and their validation rules
        self.required_files = {
            "SECURITY.md": self._validate_security_md,
            "threat-model.yaml": self._validate_threat_model,
            "security-owners.yaml": self._validate_owners,
            "allowed-tools.yaml": self._validate_tools,
        }
        
    def validate(self) -> bool:
        """
        Run all validations.
        
        Returns:
            True if all validations pass, False otherwise
        """
        print("\n🔐 Security Contract Validation")
        print("=" * 50)
        
        # Check if security directory exists
        if not self.security_dir.exists():
            self.violations.append({
                "type": "missing_directory",
                "path": "security/",
                "severity": "BLOCKING",
                "message": "Security directory not found"
            })
            self._report()
            return False
        
        # Validate each required file
        for filename, validator in self.required_files.items():
            file_path = self.security_dir / filename
            if not file_path.exists():
                self.violations.append({
                    "type": "missing_file",
                    "path": f"security/{filename}",
                    "severity": "BLOCKING",
                    "message": f"Required file missing: {filename}"
                })
            else:
                # Validate file contents
                validator(file_path)
        
        self._report()
        return len(self.violations) == 0
    
    def _validate_security_md(self, file_path: Path):
        """Validate SECURITY.md contains required sections"""
        content = file_path.read_text().lower()
        
        required_sections = [
            "reporting a vulnerability",
            "supported versions",
            "contact"
        ]
        
        missing = []
        for section in required_sections:
            if section not in content:
                missing.append(section)
        
        if missing:
            self.violations.append({
                "type": "invalid_content",
                "path": str(file_path),
                "severity": "WARNING",
                "message": f"Missing sections: {', '.join(missing)}"
            })
    
    def _validate_threat_model(self, file_path: Path):
        """Validate threat-model.yaml structure"""
        try:
            with open(file_path) as f:
                model = yaml.safe_load(f)
            
            # Check required top-level sections
            required_sections = ["assets", "threats", "metadata"]
            for section in required_sections:
                if section not in model:
                    self.violations.append({
                        "type": "invalid_threat_model",
                        "path": str(file_path),
                        "severity": "BLOCKING",
                        "message": f"Missing required section: {section}"
                    })
            
            # Validate assets have required fields
            if "assets" in model:
                for i, asset in enumerate(model["assets"]):
                    if "id" not in asset:
                        self.violations.append({
                            "type": "invalid_asset",
                            "path": str(file_path),
                            "severity": "WARNING",
                            "message": f"Asset at index {i} missing 'id'"
                        })
                    if "sensitivity" not in asset:
                        self.violations.append({
                            "type": "invalid_asset",
                            "path": str(file_path),
                            "severity": "WARNING",
                            "message": f"Asset {asset.get('id', i)} missing 'sensitivity'"
                        })
            
            # Validate threats have mitigations
            if "threats" in model:
                for i, threat in enumerate(model["threats"]):
                    if "mitigations" not in threat or not threat["mitigations"]:
                        self.violations.append({
                            "type": "missing_mitigation",
                            "path": str(file_path),
                            "severity": "WARNING",
                            "message": f"Threat {threat.get('id', i)} has no mitigations"
                        })
                        
        except yaml.YAMLError as e:
            self.violations.append({
                "type": "invalid_yaml",
                "path": str(file_path),
                "severity": "BLOCKING",
                "message": f"Invalid YAML: {str(e)}"
            })
    
    def _validate_owners(self, file_path: Path):
        """Validate security-owners.yaml"""
        try:
            with open(file_path) as f:
                owners = yaml.safe_load(f)
            
            # Check for critical paths
            if "critical_paths" not in owners:
                self.violations.append({
                    "type": "missing_critical_paths",
                    "path": str(file_path),
                    "severity": "WARNING",
                    "message": "No critical paths defined"
                })
            
            # Validate owners format
            if "owners" in owners:
                for owner_name, owner_config in owners["owners"].items():
                    if "team" not in owner_config:
                        self.violations.append({
                            "type": "invalid_owner",
                            "path": str(file_path),
                            "severity": "BLOCKING",
                            "message": f"Owner {owner_name} missing 'team' field"
                        })
                    
        except yaml.YAMLError as e:
            self.violations.append({
                "type": "invalid_yaml",
                "path": str(file_path),
                "severity": "BLOCKING",
                "message": f"Invalid YAML: {str(e)}"
            })
    
    def _validate_tools(self, file_path: Path):
        """Validate allowed-tools.yaml"""
        try:
            with open(file_path) as f:
                tools = yaml.safe_load(f)
            
            # Check for required tools
            if "required_tools" not in tools:
                self.violations.append({
                    "type": "missing_required_tools",
                    "path": str(file_path),
                    "severity": "WARNING",
                    "message": "No required tools defined"
                })
            
        except yaml.YAMLError as e:
            self.violations.append({
                "type": "invalid_yaml",
                "path": str(file_path),
                "severity": "BLOCKING",
                "message": f"Invalid YAML: {str(e)}"
            })
    
    def _report(self):
        """Print validation report"""
        if not self.violations:
            print("\n✅ All security contract checks passed!")
            return
        
        print(f"\n❌ Found {len(self.violations)} violations:")
        for v in self.violations:
            emoji = "🚫" if v["severity"] == "BLOCKING" else "⚠️"
            print(f"\n{emoji} {v['type']}")
            print(f"   Path: {v['path']}")
            print(f"   Message: {v['message']}")
        
        blocking = [v for v in self.violations if v["severity"] == "BLOCKING"]
        if blocking:
            print(f"\n🚨 {len(blocking)} BLOCKING violations found")
            print("Fix these before proceeding")


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(description="Validate security contract")
    parser.add_argument("--repo-path", default=".", help="Path to repository")
    args = parser.parse_args()
    
    validator = SecurityContractValidator(args.repo_path)
    if not validator.validate():
        sys.exit(1)


if __name__ == "__main__":
    main()