#!/usr/bin/env python3
"""
IaC Security Scanner
Checks Terraform, CloudFormation, Kubernetes for misconfigurations
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional
import argparse


class IaCScanner:
    """
    Scans Infrastructure as Code for security misconfigurations:
    - Public storage buckets
    - Open security groups
    - Wildcard IAM policies
    - Unencrypted data stores
    - Privileged containers
    """
    
    def __init__(self, repo_path: str = "."):
        self.repo_path = Path(repo_path)
        self.findings = []
        
        # Critical misconfigurations that always block
        self.blocking_misconfigs = [
            'public_storage',
            'open_security_group',
            'wildcard_iam',
            'unencrypted_storage',
            'privileged_container',
            'host_network',
            'public_ec2',
            'public_rds',
            'no_encryption',
            'world_readable'
        ]
        
    def scan_all(self) -> List[Dict]:
        """
        Run all IaC scans based on what files exist
        """
        print("\n☁️ Running IaC Security Scan...")
        
        # Check for Terraform files
        if list(self.repo_path.glob('**/*.tf')):
            self._scan_terraform()
        
        # Check for CloudFormation files
        if list(self.repo_path.glob('**/*.yaml')) or list(self.repo_path.glob('**/*.yml')):
            self._scan_cloudformation()
        
        # Check for Kubernetes files
        if list(self.repo_path.glob('**/*.yaml')):
            self._scan_kubernetes()
        
        # Always run Checkov (comprehensive scanner)
        self._scan_with_checkov()
        
        # Generate report
        self._print_report()
        
        return self.findings
    
    def _scan_with_checkov(self) -> None:
        """Run Checkov IaC scan"""
        print("  🔍 Running Checkov (comprehensive IaC scan)...")
        
        try:
            # Check if checkov is installed
            subprocess.run(['checkov', '--version'], capture_output=True, check=True)
        except:
            print("  ⚠️ Checkov not found. Installing...")
            subprocess.run(['pip', 'install', 'checkov'], check=False)
        
        try:
            # Run checkov
            result = subprocess.run(
                ['checkov', '-d', str(self.repo_path), '--compact', '--quiet', '--output', 'json'],
                capture_output=True,
                text=True
            )
            
            if result.stdout:
                data = json.loads(result.stdout)
                
                for failed_check in data.get('results', {}).get('failed_checks', []):
                    check_name = failed_check.get('check_name', '').lower()
                    check_id = failed_check.get('check_id', '')
                    
                    finding = {
                        'tool': 'checkov',
                        'check_id': check_id,
                        'check_name': failed_check.get('check_name'),
                        'file': failed_check.get('file'),
                        'line': failed_check.get('file_line_range', [0, 0])[0],
                        'resource': failed_check.get('resource'),
                        'severity': failed_check.get('severity', 'MEDIUM'),
                        'guideline': failed_check.get('guideline'),
                    }
                    
                    # Check if this is a blocking misconfiguration
                    finding['blocks'] = any(
                        block in finding['check_name'].lower() or block in check_id.lower()
                        for block in self.blocking_misconfigs
                    )
                    
                    self.findings.append(finding)
                    
        except Exception as e:
            print(f"  ⚠️ Checkov scan failed: {e}")
    
    def _scan_terraform(self) -> None:
        """Run tfsec for Terraform-specific issues"""
        print("  🔍 Running tfsec (Terraform security)...")
        
        try:
            # Check if tfsec is installed
            subprocess.run(['tfsec', '--version'], capture_output=True, check=True)
        except:
            print("  ⚠️ tfsec not found. Skipping Terraform-specific scan.")
            return
        
        try:
            result = subprocess.run(
                ['tfsec', '--format', 'json', '--quiet', '.'],
                cwd=self.repo_path,
                capture_output=True,
                text=True
            )
            
            if result.stdout:
                data = json.loads(result.stdout)
                
                for finding in data.get('results', []):
                    severity = finding.get('severity', 'MEDIUM').upper()
                    
                    self.findings.append({
                        'tool': 'tfsec',
                        'check_id': finding.get('rule_id'),
                        'check_name': finding.get('rule_description'),
                        'file': finding.get('location', {}).get('filename'),
                        'line': finding.get('location', {}).get('start_line'),
                        'severity': severity,
                        'blocks': severity in ['CRITICAL', 'HIGH']
                    })
                    
        except Exception as e:
            print(f"  ⚠️ tfsec failed: {e}")
    
    def _scan_cloudformation(self) -> None:
        """Scan CloudFormation templates"""
        print("  🔍 Scanning CloudFormation templates...")
        
        # cfn-lint and cfn-nag are good for CloudFormation
        try:
            # Try cfn-lint first
            result = subprocess.run(
                ['cfn-lint', '--format', 'json'] + list(self.repo_path.glob('**/*.yaml')),
                capture_output=True,
                text=True
            )
            
            if result.stdout:
                data = json.loads(result.stdout)
                
                for finding in data:
                    if finding.get('level') in ['WARNING', 'ERROR']:
                        self.findings.append({
                            'tool': 'cfn-lint',
                            'check_id': finding.get('rule'),
                            'message': finding.get('message'),
                            'file': finding.get('filename'),
                            'line': finding.get('location', {}).get('start', {}).get('line'),
                            'severity': finding.get('level'),
                            'blocks': finding.get('level') == 'ERROR'
                        })
                        
        except Exception as e:
            print(f"  ⚠️ CloudFormation scan failed: {e}")
    
    def _scan_kubernetes(self) -> None:
        """Scan Kubernetes manifests"""
        print("  🔍 Scanning Kubernetes manifests...")
        
        # Try kube-score
        try:
            result = subprocess.run(
                ['kube-score', 'score'] + list(self.repo_path.glob('**/*.yaml')),
                capture_output=True,
                text=True
            )
            
            if result.stdout:
                # Parse kube-score output (text-based)
                lines = result.stdout.split('\n')
                for line in lines:
                    if '[CRITICAL]' in line or '[ERROR]' in line:
                        self.findings.append({
                            'tool': 'kube-score',
                            'type': 'kubernetes',
                            'message': line.strip(),
                            'severity': 'CRITICAL',
                            'blocks': True
                        })
                        
        except Exception as e:
            print(f"  ⚠️ Kubernetes scan failed: {e}")
        
        # Try kubescape if available
        try:
            result = subprocess.run(
                ['kubescape', 'scan', '--format', 'json'] + list(self.repo_path.glob('**/*.yaml')),
                capture_output=True,
                text=True
            )
            
            if result.stdout:
                data = json.loads(result.stdout)
                
                for finding in data.get('results', []):
                    severity = finding.get('severity', '').upper()
                    self.findings.append({
                        'tool': 'kubescape',
                        'check_id': finding.get('id'),
                        'check_name': finding.get('name'),
                        'severity': severity,
                        'blocks': severity in ['CRITICAL', 'HIGH']
                    })
                    
        except Exception as e:
            print(f"  ⚠️ Kubescape scan failed: {e}")
    
    def _print_report(self) -> None:
        """Print scan report"""
        if not self.findings:
            print("\n✅ No IaC misconfigurations found!")
            return
        
        print(f"\n☁️ IAC SECURITY SCAN RESULTS")
        print("=" * 60)
        
        # Group by severity
        blocking = [f for f in self.findings if f.get('blocks')]
        warnings = [f for f in self.findings if not f.get('blocks')]
        
        if blocking:
            print(f"\n❌ BLOCKING MISCONFIGURATIONS ({len(blocking)})")
            for f in blocking[:10]:
                print(f"\n  📄 {f.get('file', 'unknown')}:{f.get('line', '')}")
                print(f"  🔴 {f.get('check_name', f.get('message', 'Unknown'))}")
                if f.get('guideline'):
                    print(f"  📖 Fix: {f['guideline']}")
            
            if len(blocking) > 10:
                print(f"\n  ... and {len(blocking) - 10} more blocking issues")
        
        if warnings:
            print(f"\n⚠️ WARNINGS ({len(warnings)})")
            for f in warnings[:5]:
                print(f"  {f.get('file', 'unknown')}: {f.get('check_name', f.get('message', 'Unknown'))[:100]}")
        
        # Summarize by resource type
        print(f"\n📊 Summary by Resource Type:")
        resource_counts = {}
        for f in self.findings:
            if f.get('resource'):
                resource_type = f['resource'].split('.')[0] if '.' in f['resource'] else f['resource']
                resource_counts[resource_type] = resource_counts.get(resource_type, 0) + 1
        
        for resource, count in sorted(resource_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  • {resource}: {count} issues")
    
    def should_block(self) -> bool:
        """Check if findings should block"""
        return any(f.get('blocks') for f in self.findings)


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(description="Scan IaC for misconfigurations")
    parser.add_argument("--repo-path", default=".", help="Path to repository")
    parser.add_argument("--block", action="store_true", help="Exit with error if issues found")
    args = parser.parse_args()
    
    scanner = IaCScanner(args.repo_path)
    scanner.scan_all()
    
    if args.block and scanner.should_block():
        print("\n🚨 BLOCKING IAC MISCONFIGURATIONS FOUND")
        sys.exit(1)
    
    sys.exit(0)


if __name__ == "__main__":
    main()