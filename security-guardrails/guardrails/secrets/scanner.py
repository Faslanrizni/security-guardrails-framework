#!/usr/bin/env python3
"""
Secrets Scanner
Detects hardcoded secrets in code files
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
        
        # Files to completely skip (auto-generated, safe)
        self.skip_files = [
            'package-lock.json',
            'yarn.lock',
            'composer.lock',
            'Gemfile.lock',
            'poetry.lock',
            'pnpm-lock.yaml',
        ]
        
        # Secret patterns (regex) - made more specific
        self.patterns = {
            'aws_access_key': r'AKIA[0-9A-F]{16}(?![a-z0-9])',  # AWS keys are hex
            'aws_secret_key': r'(?<![a-zA-Z0-9+/])[0-9a-zA-Z/+]{40}(?![a-zA-Z0-9+/])',  # Word boundaries
            'github_token': r'ghp_[0-9a-zA-Z]{36}(?![a-zA-Z0-9])',
            'github_old': r'github_token\s*[=:]\s*["\'][0-9a-zA-Z]{40}["\']',
            'private_key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            'api_key': r'api[_-]?key\s*[=:]\s*["\'][0-9a-zA-Z]{32,}["\']',  # Increased min length
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
                
                # Skip auto-generated lock files
                if file_path.name in self.skip_files:
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
                    matches = re.finditer(pattern, line)
                    for match in matches:
                        matched_text = match.group(0)
                        
                        # Check if it's likely a false positive
                        if not self._is_false_positive(line, file_path, pattern_name, matched_text):
                            self.findings.append({
                                'file': file_path,
                                'line': i,
                                'type': pattern_name,
                                'match': matched_text[:30] + '...' if len(matched_text) > 30 else matched_text,
                                'severity': 'BLOCKING'
                            })
        except Exception as e:
            print(f"  ⚠️ Error scanning {file_path}: {e}")
    
    def _is_false_positive(self, line: str, file_path: str, pattern_type: str, matched_text: str) -> bool:
        """Check if finding is likely false positive"""
        
        # Ignore package-lock.json entirely (caught by skip_files, but double-check)
        if 'package-lock.json' in file_path:
            return True
            
        # Ignore integrity hashes in package files
        if 'integrity' in line.lower() or 'sha512' in line.lower() or 'sha256' in line.lower():
            # Check if it looks like a hash (long hex string)
            if re.match(r'^[a-f0-9]{40,}$', matched_text, re.IGNORECASE):
                return True
        
        line_lower = line.lower()
        matched_lower = matched_text.lower()
        
        # Common false positive patterns in code
        false_patterns = [
            'example', 'sample', 'test', 'mock', 'fake',
            'placeholder', 'your-key', 'your-token', 'xxxx',
            'dummy', 'not-a-real', 'for-demo', 'changeme',
            'testkey', 'testpassword', 'testtoken'
        ]
        
        for pattern in false_patterns:
            if pattern in line_lower or pattern in matched_lower:
                return True
        
        # Check if it's in a test file path
        if 'test' in file_path.lower() and pattern_type != 'private_key':
            return True
        
        # Check for version numbers or hashes that look like secrets
        if pattern_type == 'aws_secret_key':
            # AWS secret keys are base64-ish, not hex-only
            if re.match(r'^[a-f0-9]{40}$', matched_text, re.IGNORECASE):
                return True  # Looks like a git commit hash or SHA
        
        # Check for common false positives in specific file types
        if file_path.endswith('.js') or file_path.endswith('.ts'):
            # In JS/TS files, check if it's a variable name, not a value
            if '=' not in line and ':' not in line:
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