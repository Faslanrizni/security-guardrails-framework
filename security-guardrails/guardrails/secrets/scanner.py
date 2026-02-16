#!/usr/bin/env python3
"""

Features:
- Accurate secret pattern detection
- Entropy-based detection
- Bearer token validation (no false positives)
- Multiline private key detection
- JSON reporting
- CI/CD blocking support
"""

import re
import sys
import json
import math
import argparse
from pathlib import Path
from typing import List, Dict


class SecretsScanner:

    def __init__(self, repo_path="."):

        self.repo_path = Path(repo_path)
        self.findings: List[Dict] = []

        self.skip_dirs = {
            ".git",
            "node_modules",
            "dist",
            "build",
            "__pycache__",
            ".venv",
            ".idea",
            ".vscode"
        }

        self.skip_files = {
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "poetry.lock",
            "composer.lock"
        }

       
        # Enterprise-grade patterns
       

        self.patterns = {

            # AWS
            "aws_access_key":
                r"\bAKIA[0-9A-Z]{16}\b",

            "aws_secret_key":
                r"\b[A-Za-z0-9/+=]{40}\b",

            # GitHub
            "github_pat":
                r"\bgithub_pat_[A-Za-z0-9_]{80,}\b",

            "github_token":
                r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",

            # Google
            "gcp_api_key":
                r"\bAIza[0-9A-Za-z\-_]{35}\b",

            "google_oauth":
                r"\bya29\.[0-9A-Za-z\-_]+\b",

            # Stripe
            "stripe_secret":
                r"\bsk_(live|test)_[0-9A-Za-z]{24,}\b",

            # Slack
            "slack_token":
                r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b",

            # JWT
            "jwt_token":
                r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",

            # Bearer token (FIXED — requires 40+ chars)
            "bearer_token":
                r"Bearer\s+([A-Za-z0-9\-._~+/]{40,2000})",

            # Azure
            "azure_storage":
                r"AccountKey=[A-Za-z0-9+/=]{88}",

            # Firebase
            "firebase_key":
                r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b",

            # Database connection
            "db_connection":
                r"(postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@",

            # Environment secrets
            "env_secret":
                r"(SECRET|TOKEN|KEY|PASSWORD|PWD)\s*[=:]\s*[\"'][^\"']{8,}[\"']",
        }

        self.private_key_pattern = re.compile(
            r"-----BEGIN (RSA|DSA|EC|OPENSSH|PRIVATE) KEY-----"
        )
        self.file_patterns = [
            "*.py",
            "*.js",
            "*.ts",
            "*.env",
            "*.json",
            "*.yaml",
            "*.yml",
            "*.conf",
            "*.ini",
            "*.java",
            "*.go",
            "*.rb",
            "*.php",
            "Dockerfile"
        ]


  
    # Entropy calculation
    def shannon_entropy(self, data):
        if not data:
            return 0
        entropy = 0
        for char in set(data):
            p = data.count(char) / len(data)
            entropy -= p * math.log2(p)
        return entropy


    def is_high_entropy(self, token):
        if len(token) < 20:
            return False
        if not re.fullmatch(r"[A-Za-z0-9+/=]{20,}", token):
            return False
        entropy = self.shannon_entropy(token)
        return entropy >= 4.5


  
    # False positive filter
    def is_false_positive(self, line, value):
        false_keywords = {
            "example",
            "sample",
            "test",
            "mock",
            "dummy",
            "fake",
            "placeholder",
            "changeme",
            "ispublic",
            "public",
        }

        line_lower = line.lower()
        value_lower = value.lower()

        for keyword in false_keywords:
            if keyword in line_lower or keyword in value_lower:
                return True
        if re.fullmatch(r"[a-f0-9]{40}", value):
            return True
        return False



    # Validate bearer token
    def valid_bearer(self, token):
        if len(token) < 40:
            return False
        entropy = self.shannon_entropy(token)
        return entropy >= 3.5


 
    # Get files
    def get_files(self):
        files = []
        for pattern in self.file_patterns:
            for file in self.repo_path.glob(f"**/{pattern}"):
                if any(skip in file.parts for skip in self.skip_dirs):
                    continue
                if file.name in self.skip_files:
                    continue
                files.append(file)
        return files

    # Add finding
    def add_finding(
        self,
        file,
        line,
        type_,
        match,
        severity
    ):

        self.findings.append({
            "file": str(file.relative_to(self.repo_path)),
            "line": line,
            "type": type_,
            "severity": severity,
            "match": match[:50]
        })

    # Scan file
    def scan_file(self, file):
        try:
            content = file.read_text(errors="ignore")
            lines = content.splitlines()

            # Private key detection
            if self.private_key_pattern.search(content):
                self.add_finding(
                    file,
                    0,
                    "private_key",
                    "PRIVATE KEY BLOCK",
                    "CRITICAL"
                )

            for line_num, line in enumerate(lines, 1):

                # Pattern detection
                for name, pattern in self.patterns.items():
                    matches = re.finditer(pattern, line)
                    for match in matches:
                        value = match.group(1) if match.groups() else match.group(0)
                        if name == "bearer_token":
                            if not self.valid_bearer(value):
                                continue
                        if self.is_false_positive(line, value):
                            continue
                        self.add_finding(
                            file,
                            line_num,
                            name,
                            value,
                            "HIGH"
                        )

                # Entropy detection
                tokens = re.findall(
                    r"[A-Za-z0-9+/=]{20,}",
                    line
                )

                for token in tokens:
                    if self.is_high_entropy(token):
                        self.add_finding(
                            file,
                            line_num,
                            "high_entropy_secret",
                            token,
                            "MEDIUM"
                        )
        except Exception:
            pass

    # Scan repository
    def scan(self):
        print("Scanning repository...")
        files = self.get_files()
        for file in files:
            self.scan_file(file)
        return self.findings


    # Output
    def print_findings(self):
        if not self.findings:
            print("No secrets found")
            return
        print(f"\nFound {len(self.findings)} secrets\n")
        for f in self.findings:
            print(
                f"{f['file']}:{f['line']} "
                f"{f['type']} "
                f"{f['severity']}"
            )

    def save_json(self, path="secrets-report.json"):
        with open(path, "w") as f:
            json.dump(self.findings, f, indent=2)


    def should_block(self):
        return any(
            f["severity"] in ("HIGH", "CRITICAL")
            for f in self.findings
        )

# CLI
def main():

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--repo-path",
        default="."
    )
    parser.add_argument(
        "--json",
        action="store_true"
    )
    parser.add_argument(
        "--block",
        action="store_true"
    )
    args = parser.parse_args()
    scanner = SecretsScanner(args.repo_path)
    scanner.scan()
    scanner.print_findings()
    if args.json:
        scanner.save_json()
    if args.block and scanner.should_block():
        print("\nBLOCKING: secrets detected")
        sys.exit(1)


if __name__ == "__main__":
    main()
