#!/usr/bin/env python3
"""
SAST Runner
Runs static analysis and blocks on critical findings
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional
import argparse


class SASTRunner:
    """
    Runs SAST tools and enforces blocking rules
    """
    
    def __init__(self, repo_path: str = "."):
        self.repo_path = Path(repo_path)
        self.findings = []
        
        # Rules that always block
        self.blocking_rules = [
            'sql-injection',
            'command-injection',
            'ssrf',
            'insecure-deserialization',
            'path-traversal',
            'auth-bypass',
        ]
        
        # Severity levels that block
        self.blocking_severities = ['ERROR', 'WARNING']  # Adjust as needed
        
    def run_semgrep(self) -> List[Dict]:
        """Run semgrep scan"""
        print("🔍 Running Semgrep SAST...")
        
        # Check if semgrep is installed
        try:
            subprocess.run(['semgrep', '--version'], capture_output=True, check=True)
        except:
            print("  ⚠️ Semgrep not installed. Installing...")
            subprocess.run(['pip', 'install', 'semgrep'], check=True)
        
        # Semgrep rules to run
        rules = [
            'p/owasp-top-ten',
            'p/command-injection',
            'p/sql-injection',
            'p/jwt',
            'p/security-audit',
            'p/flask',
        ]
        
        try:
            # Run semgrep
            result = subprocess.run(
                ['semgrep', 'scan', '--config'] + rules +
                ['--json', '--quiet', '.'],
                cwd=self.repo_path,
                capture_output=True,
                text=True
            )
            
            if result.stdout:
                data = json.loads(result.stdout)
                
                for finding in data.get('results', []):
                    severity = finding.get('extra', {}).get('severity', 'INFO').upper()
                    check_id = finding.get('check_id', '')
                    
                    finding_data = {
                        'tool': 'semgrep',
                        'rule_id': check_id,
                        'rule_name': finding.get('extra', {}).get('message', 'Unknown'),
                        'file': finding.get('path'),
                        'line': finding.get('start', {}).get('line'),
                        'message': finding.get('extra', {}).get('message'),
                        'severity': severity,
                        'code': finding.get('extra', {}).get('lines'),
                        'fix': finding.get('extra', {}).get('fix'),
                    }
                    
                    # Check if this is a blocking finding
                    finding_data['blocks'] = self._is_blocking(check_id, severity)
                    
                    self.findings.append(finding_data)
                    
            print(f"  ✅ Semgrep found {len(self.findings)} potential issues")
                    
        except Exception as e:
            print(f"  ⚠️ Semgrep failed: {e}")
        
        return self.findings
    
    def _is_blocking(self, rule_id: str, severity: str) -> bool:
        """Determine if a finding should block the build"""
        
        # Block by severity
        if severity in self.blocking_severities:
            return True
        
        # Block by rule pattern
        for blocking_rule in self.blocking_rules:
            if blocking_rule in rule_id.lower():
                return True
        
        return False
    
    def generate_report(self) -> str:
        """Generate human-readable report"""
        if not self.findings:
            return "✅ No security vulnerabilities found!"
        
        report = []
        report.append("🔐 SAST SCAN RESULTS")
        report.append("=" * 60)
        
        # Group by severity
        blocking = [f for f in self.findings if f.get('blocks')]
        non_blocking = [f for f in self.findings if not f.get('blocks')]
        
        if blocking:
            report.append(f"\n❌ BLOCKING FINDINGS ({len(blocking)})")
            for f in blocking[:10]:  # Show first 10
                report.append(f"\n  📄 {f['file']}:{f['line']}")
                report.append(f"  🔴 {f['rule_name']}")
                report.append(f"  📝 {f['message']}")
                if f.get('fix'):
                    report.append(f"  💡 Fix: {f['fix']}")
            
            if len(blocking) > 10:
                report.append(f"\n  ... and {len(blocking) - 10} more blocking issues")
        
        if non_blocking:
            report.append(f"\n⚠️ WARNINGS ({len(non_blocking)})")
            for f in non_blocking[:5]:  # Show first 5
                report.append(f"  {f['file']}:{f['line']} - {f['rule_name']}")
            
            if len(non_blocking) > 5:
                report.append(f"  ... and {len(non_blocking) - 5} more warnings")
        
        return '\n'.join(report)
    
    def should_block(self) -> bool:
        """Check if findings should block the build"""
        return any(f.get('blocks') for f in self.findings)


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(description="Run SAST scans")
    parser.add_argument("--repo-path", default=".", help="Path to repository")
    parser.add_argument("--block", action="store_true", help="Block on critical findings")
    args = parser.parse_args()
    
    runner = SASTRunner(args.repo_path)
    
    # Run scans
    runner.run_semgrep()
    
    # Generate report
    print(runner.generate_report())
    
    # Block if needed
    if args.block and runner.should_block():
        print("\n🚨 BLOCKING FINDINGS DETECTED")
        sys.exit(1)
    
    sys.exit(0)


if __name__ == "__main__":
    main()