#!/usr/bin/env python3
"""
Secrets Scanner
Detects hardcoded secrets in code
"""

import os
import re
import sys
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional
import argparse


class SecretsScanner:
    """
    Scans for hardcoded secrets in code files
    """
    
    def __init__(self, repo_path: str = "."):
        self.repo_path = Path(repo_path)
        self.findings = []
        
        # Secret patterns (regex)
        self.patterns = {
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'aws_secret_key': r'[0-9a-zA-Z/+]{40}',
            'github_token': r'ghp_[0-9a-zA-Z]{36}',
            'github_old': r'github_token\s*[=:]\s*["\'][0-9a-zA-Z]{40}["\']',
            'private_key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            'api_key': r'api[_-]?key\s*[=:]\s*["\'][0-9a-zA-Z]{16,}["\']',
            'password': r'password\s*[=:]\s*["\'][^"\']{8,}["\']',
            'connection_string': r'(postgresql|mysql|mongodb)://[^/\s]+:[^/\s]+@',
            'slack_token': r'xox[baprs]-[0-9a-zA-Z]{10,}',
        }
        
        # Files to always check
        self.file_patterns = [
            '*.py', '*.js', '*.ts', '*.java', '*.go', '*.rb',
            '*.yml', '*.yaml', '*.json', '*.env', '*.conf',
            'Dockerfile', 'docker-compose.yml',
        ]
        
    def scan(self, files: Optional[List[str]] = None) -> List[Dict]:
        """
        Scan files for secrets
        """
        print("\n🔐 Scanning for secrets...")
        
        if files is None:
            files = self._get_all_files()
        
        if not files:
            print("No files to scan")
            return []
        
        # Scan each file
        for file_path in files:
            self._scan_file(file_path)
        
        # Report findings
        if self.findings:
            print(f"\n❌ Found {len(self.findings)} secrets:")
            for f in self.findings:
                print(f"  - {f['file']}:{f['line']} - {f['type']}")
        else:
            print("✅ No secrets detected")
        
        return self.findings
    
    def _get_all_files(self) -> List[str]:
        """Get all files in repo (not git-ignored)"""
        all_files = []
        
        for pattern in self.file_patterns:
            for file_path in self.repo_path.glob(f"**/{pattern}"):
                # Skip .git directory
                if '.git' in str(file_path):
                    continue
                all_files.append(str(file_path.relative_to(self.repo_path)))
        
        return all_files
    
    def _scan_file(self, file_path: str):
        """Scan a single file for secrets"""
        full_path = self.repo_path / file_path
        
        if not full_path.exists():
            return
        
        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for i, line in enumerate(lines, 1):
                for pattern_name, pattern in self.patterns.items():
                    if re.search(pattern, line):
                        # Check if it's likely a false positive
                        if not self._is_false_positive(line, pattern_name):
                            self.findings.append({
                                'file': file_path,
                                'line': i,
                                'type': pattern_name,
                                'match': line.strip()[:50] + '...',
                                'severity': 'BLOCKING'
                            })
        except Exception as e:
            print(f"  ⚠️ Error scanning {file_path}: {e}")
    
    def _is_false_positive(self, line: str, pattern_type: str) -> bool:
        """Check if finding is likely false positive"""
        line_lower = line.lower()
        
        # Common false positive patterns
        false_patterns = [
            'example', 'sample', 'test', 'mock', 'fake',
            'placeholder', 'your-key', 'your-token', 'xxxx',
            'dummy', 'not-a-real', 'for-demo'
        ]
        
        for pattern in false_patterns:
            if pattern in line_lower:
                return True
        
        # Check if it's in a test file path
        if 'test' in line_lower and pattern_type != 'private_key':
            return True
        
        return False
    
    def should_block(self) -> bool:
        """Check if findings should block"""
        return len(self.findings) > 0


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(description="Scan for secrets")
    parser.add_argument("--repo-path", default=".", help="Path to repository")
    parser.add_argument("--files", nargs="+", help="Specific files to scan")
    parser.add_argument("--block", action="store_true", help="Exit with error if secrets found")
    args = parser.parse_args()
    
    scanner = SecretsScanner(args.repo_path)
    findings = scanner.scan(args.files)
    
    if args.block and scanner.should_block():
        print("\n🚨 SECRETS DETECTED - BLOCKING")
        sys.exit(1)
    
    sys.exit(0)


if __name__ == "__main__":
    main()