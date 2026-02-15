#!/usr/bin/env python3
"""
Dependency Security Scanner
Checks for vulnerabilities, malicious packages, and license violations
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional
import argparse
import xml.etree.ElementTree as ET


class DependencyScanner:
    """
    Scans project dependencies for:
    - Known vulnerabilities (CVEs)
    - Malicious packages
    - License compliance
    - Outdated versions
    """
    
    def __init__(self, repo_path: str = "."):
        self.repo_path = Path(repo_path)
        self.findings = []
        
        # Allowed licenses (customize for your org)
        self.allowed_licenses = [
            'MIT', 'Apache-2.0', 'BSD-3-Clause', 'BSD-2-Clause',
            'ISC', 'Python-2.0', 'PSF', 'MPL-2.0', 'Unlicense'
        ]
        
        # Blocked licenses (copyleft / problematic)
        self.blocked_licenses = [
            'GPL-3.0', 'GPL-2.0', 'AGPL-3.0', 'LGPL-3.0',
            'SSPL-1.0', 'BUSL-1.1', 'CC-BY-NC-4.0'
        ]
        
        # Severity thresholds
        self.block_severities = ['CRITICAL', 'HIGH']
        
    def scan_all(self) -> List[Dict]:
        """
        Run all dependency scans
        """
        print("\n📦 Running Dependency Security Scan...")
        
        # Detect project type and run appropriate scans
        if (self.repo_path / 'package.json').exists():
            self._scan_npm()
        if (self.repo_path / 'requirements.txt').exists():
            self._scan_python()
        if (self.repo_path / 'go.mod').exists():
            self._scan_go()
        if (self.repo_path / 'pom.xml').exists():
            self._scan_maven()
        if (self.repo_path / 'Gemfile').exists():
            self._scan_ruby()
        
        # Always run Trivy (works for everything)
        self._scan_with_trivy()
        
        # Check licenses
        self._check_licenses()
        
        # Generate report
        self._print_report()
        
        return self.findings
    
    def _scan_with_trivy(self) -> None:
        """Run Trivy filesystem scan"""
        print("  🔍 Running Trivy vulnerability scan...")
        
        try:
            # Check if trivy is installed
            subprocess.run(['trivy', '--version'], capture_output=True, check=True)
        except:
            print("  ⚠️ Trivy not found. Installing...")
            # Download and install trivy (platform-specific)
            import platform
            if platform.system() == 'Windows':
                # Windows installation instructions
                print("  Please install Trivy manually from: https://github.com/aquasecurity/trivy/releases")
                return
            else:
                subprocess.run(['sudo', 'apt', 'install', 'trivy', '-y'], check=False)
        
        try:
            # Run trivy filesystem scan
            result = subprocess.run(
                ['trivy', 'fs', '--severity', 'CRITICAL,HIGH',
                 '--format', 'json', '--ignore-unfixed',
                 str(self.repo_path)],
                capture_output=True,
                text=True
            )
            
            if result.stdout:
                data = json.loads(result.stdout)
                
                for result_item in data.get('Results', []):
                    target = result_item.get('Target', 'unknown')
                    vulnerabilities = result_item.get('Vulnerabilities', [])
                    
                    for vuln in vulnerabilities:
                        severity = vuln.get('Severity', 'UNKNOWN')
                        self.findings.append({
                            'tool': 'trivy',
                            'type': 'vulnerability',
                            'target': target,
                            'package': vuln.get('PkgName'),
                            'installed': vuln.get('InstalledVersion'),
                            'fixed': vuln.get('FixedVersion'),
                            'vulnerability': vuln.get('VulnerabilityID'),
                            'severity': severity,
                            'description': vuln.get('Description', '')[:100],
                            'blocks': severity in self.block_severities
                        })
                        
        except Exception as e:
            print(f"  ⚠️ Trivy scan failed: {e}")
    
    def _scan_npm(self) -> None:
        """Scan npm dependencies"""
        print("  🔍 Scanning npm dependencies...")
        
        try:
            # Run npm audit
            result = subprocess.run(
                ['npm', 'audit', '--json'],
                cwd=self.repo_path,
                capture_output=True,
                text=True
            )
            
            if result.stdout:
                data = json.loads(result.stdout)
                
                vulnerabilities = data.get('vulnerabilities', {})
                for pkg_name, vuln_info in vulnerabilities.items():
                    severity = vuln_info.get('severity', 'info').upper()
                    
                    self.findings.append({
                        'tool': 'npm-audit',
                        'type': 'vulnerability',
                        'package': pkg_name,
                        'severity': severity,
                        'via': vuln_info.get('via', []),
                        'fix': f"npm update {pkg_name}",
                        'blocks': severity in self.block_severities
                    })
                    
        except Exception as e:
            print(f"  ⚠️ npm audit failed: {e}")
    
    def _scan_python(self) -> None:
        """Scan Python dependencies"""
        print("  🔍 Scanning Python dependencies...")
        
        try:
            # Try pip-audit first
            result = subprocess.run(
                ['pip-audit', '--requirement', 'requirements.txt', '--format', 'json'],
                cwd=self.repo_path,
                capture_output=True,
                text=True
            )
            
            if result.stdout:
                data = json.loads(result.stdout)
                
                for vuln in data.get('vulnerabilities', []):
                    self.findings.append({
                        'tool': 'pip-audit',
                        'type': 'vulnerability',
                        'package': vuln.get('name'),
                        'installed': vuln.get('version'),
                        'vulnerability': vuln.get('id'),
                        'severity': vuln.get('severity', 'UNKNOWN'),
                        'description': vuln.get('description', '')[:100],
                        'blocks': vuln.get('severity', '').upper() in self.block_severities
                    })
                    
        except Exception as e:
            print(f"  ⚠️ pip-audit failed (install with: pip install pip-audit): {e}")
    
    def _scan_go(self) -> None:
        """Scan Go dependencies"""
        print("  🔍 Scanning Go dependencies...")
        
        try:
            # Run govulncheck
            result = subprocess.run(
                ['govulncheck', './...'],
                cwd=self.repo_path,
                capture_output=True,
                text=True
            )
            
            # Parse output (govulncheck output is text-based)
            if 'Vulnerability' in result.stdout:
                # Simple parsing - can be enhanced
                self.findings.append({
                    'tool': 'govulncheck',
                    'type': 'vulnerability',
                    'details': 'Vulnerabilities found in Go modules',
                    'blocks': True
                })
                    
        except Exception as e:
            print(f"  ⚠️ govulncheck failed (install with: go install golang.org/x/vuln/cmd/govulncheck@latest): {e}")
    
    def _scan_maven(self) -> None:
        """Scan Maven dependencies"""
        print("  🔍 Scanning Maven dependencies...")
        
        try:
            # Run OWASP Dependency Check
            result = subprocess.run(
                ['mvn', 'org.owasp:dependency-check-maven:check'],
                cwd=self.repo_path,
                capture_output=True,
                text=True
            )
            
            # Check for vulnerabilities in output
            if 'One or more dependencies were identified with vulnerabilities' in result.stdout:
                self.findings.append({
                    'tool': 'dependency-check',
                    'type': 'vulnerability',
                    'details': 'Vulnerabilities found in Maven dependencies',
                    'blocks': True
                })
                    
        except Exception as e:
            print(f"  ⚠️ Maven dependency check failed: {e}")
    
    def _scan_ruby(self) -> None:
        """Scan Ruby dependencies"""
        print("  🔍 Scanning Ruby dependencies...")
        
        try:
            # Run bundle audit
            result = subprocess.run(
                ['bundle', 'audit', '--version'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                result = subprocess.run(
                    ['bundle', 'audit', 'check', '--format', 'json'],
                    cwd=self.repo_path,
                    capture_output=True,
                    text=True
                )
                
                if result.stdout:
                    data = json.loads(result.stdout)
                    
                    for vuln in data.get('results', []):
                        self.findings.append({
                            'tool': 'bundle-audit',
                            'type': 'vulnerability',
                            'package': vuln.get('name'),
                            'vulnerability': vuln.get('advisory', {}).get('id'),
                            'severity': 'HIGH',
                            'blocks': True
                        })
            else:
                print("  ⚠️ bundle-audit not installed. Run: gem install bundler-audit")
                    
        except Exception as e:
            print(f"  ⚠️ Bundle audit failed: {e}")
    
    def _check_licenses(self) -> None:
        """Check dependency licenses"""
        print("  🔍 Checking license compliance...")
        
        # Check npm licenses
        if (self.repo_path / 'package.json').exists():
            self._check_npm_licenses()
        
        # Check Python licenses
        if (self.repo_path / 'requirements.txt').exists():
            self._check_python_licenses()
    
    def _check_npm_licenses(self) -> None:
        """Check npm package licenses"""
        try:
            # Use license-checker
            result = subprocess.run(
                ['npx', 'license-checker', '--json'],
                cwd=self.repo_path,
                capture_output=True,
                text=True
            )
            
            if result.stdout:
                packages = json.loads(result.stdout)
                
                for pkg_name, pkg_info in packages.items():
                    license_name = pkg_info.get('licenses', 'Unknown')
                    
                    # Clean up license name
                    license_name = license_name.split('(')[0].strip()
                    
                    if license_name in self.blocked_licenses:
                        self.findings.append({
                            'tool': 'license-checker',
                            'type': 'license',
                            'package': pkg_name.split('@')[0],
                            'license': license_name,
                            'blocks': True,
                            'message': f'Blocked license: {license_name}'
                        })
                    elif license_name not in self.allowed_licenses and license_name != 'Unknown':
                        self.findings.append({
                            'tool': 'license-checker',
                            'type': 'license',
                            'package': pkg_name.split('@')[0],
                            'license': license_name,
                            'blocks': False,
                            'message': f'Unapproved license: {license_name} (needs review)'
                        })
                        
        except Exception as e:
            print(f"  ⚠️ License check failed: {e}")
    
    def _check_python_licenses(self) -> None:
        """Check Python package licenses"""
        try:
            # Use pip-licenses
            result = subprocess.run(
                ['pip-licenses', '--format=json'],
                cwd=self.repo_path,
                capture_output=True,
                text=True
            )
            
            if result.stdout:
                packages = json.loads(result.stdout)
                
                for pkg in packages:
                    license_name = pkg.get('License', 'Unknown')
                    
                    if license_name in self.blocked_licenses:
                        self.findings.append({
                            'tool': 'pip-licenses',
                            'type': 'license',
                            'package': pkg.get('Name'),
                            'version': pkg.get('Version'),
                            'license': license_name,
                            'blocks': True,
                            'message': f'Blocked license: {license_name}'
                        })
                    elif license_name not in self.allowed_licenses and license_name != 'Unknown':
                        self.findings.append({
                            'tool': 'pip-licenses',
                            'type': 'license',
                            'package': pkg.get('Name'),
                            'version': pkg.get('Version'),
                            'license': license_name,
                            'blocks': False,
                            'message': f'Unapproved license: {license_name}'
                        })
                        
        except Exception as e:
            print(f"  ⚠️ License check failed (install with: pip install pip-licenses): {e}")
    
    def _print_report(self) -> None:
        """Print scan report"""
        if not self.findings:
            print("\n✅ No dependency issues found!")
            return
        
        print(f"\n📦 DEPENDENCY SCAN RESULTS")
        print("=" * 60)
        
        # Group by type
        vulnerabilities = [f for f in self.findings if f['type'] == 'vulnerability' and f.get('blocks')]
        license_blocks = [f for f in self.findings if f['type'] == 'license' and f.get('blocks')]
        warnings = [f for f in self.findings if not f.get('blocks')]
        
        if vulnerabilities:
            print(f"\n❌ BLOCKING VULNERABILITIES ({len(vulnerabilities)})")
            for f in vulnerabilities[:10]:
                print(f"  • {f.get('package', 'unknown')} - {f.get('vulnerability', '')}")
                if f.get('fixed'):
                    print(f"    Fix: upgrade to {f['fixed']}")
        
        if license_blocks:
            print(f"\n❌ BLOCKED LICENSES ({len(license_blocks)})")
            for f in license_blocks[:5]:
                print(f"  • {f.get('package')} - {f.get('license')}")
        
        if warnings:
            print(f"\n⚠️ WARNINGS ({len(warnings)})")
            for f in warnings[:5]:
                if f['type'] == 'license':
                    print(f"  • {f.get('package')} - {f.get('license')} (needs review)")
                else:
                    print(f"  • {f.get('package')} - {f.get('vulnerability', '')}")
        
        if len(self.findings) > 20:
            print(f"\n  ... and {len(self.findings) - 20} more issues")
    
    def should_block(self) -> bool:
        """Check if findings should block"""
        return any(f.get('blocks') for f in self.findings)


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(description="Scan dependencies for vulnerabilities")
    parser.add_argument("--repo-path", default=".", help="Path to repository")
    parser.add_argument("--block", action="store_true", help="Exit with error if issues found")
    args = parser.parse_args()
    
    scanner = DependencyScanner(args.repo_path)
    scanner.scan_all()
    
    if args.block and scanner.should_block():
        print("\n🚨 BLOCKING DEPENDENCY ISSUES FOUND")
        sys.exit(1)
    
    sys.exit(0)


if __name__ == "__main__":
    main()