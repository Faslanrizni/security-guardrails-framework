#!/usr/bin/env python3
"""
Allowed Dependencies Enforcer
Checks every new dependency against allowed-dependencies.yaml
Blocks build if unapproved package found

POLICY LOCATION: tools/security-guardrails/guardrails/dependencies/allowed-dependencies.yaml
"""

import os
import sys
import json
import yaml
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
import argparse
import fnmatch


class AllowedDependenciesEnforcer:
    """
    Enforces that only approved dependencies can be used.
    
    ENFORCEMENT FLOW:
    1. Detect new/changed dependencies in PR
    2. Check against allowed-dependencies.yaml (in tools directory)
    3. If not allowed →  Build fails
    4. Provide instructions for approval request
    """
    
    def __init__(self, repo_path: str = "."):
        self.repo_path = Path(repo_path).resolve()
        
        # Look for policy file in tools directory
        self.policy_file = self.repo_path / 'tools' / 'security-guardrails' / 'guardrails' / 'dependencies' / 'allowed-dependencies.yaml'
        
        self.violations = []
        self.ai_detected = False
        
        # Load policy
        self.policy = self._load_policy()
        
    def _load_policy(self) -> Dict:
        """Load the allowed dependencies policy from tools directory"""
        if not self.policy_file.exists():
            print(f" Policy file not found at: {self.policy_file}")
            print("   Expected location: tools/security-guardrails/guardrails/dependencies/allowed-dependencies.yaml")
            print("")
            print("   To fix this:")
            print("   1. Create the directory: mkdir -p tools/security-guardrails/guardrails/dependencies")
            print("   2. Create the policy file from template")
            sys.exit(1)
            
        try:
            with open(self.policy_file, 'r') as f:
                return yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f" Error parsing YAML policy file: {e}")
            sys.exit(1)
        except Exception as e:
            print(f" Error reading policy file: {e}")
            sys.exit(1)
    
    def enforce(self) -> bool:
        """
        Main enforcement method
        Returns True if all dependencies are allowed, False otherwise
        """
        print("\n ALLOWED DEPENDENCIES ENFORCER")
        print("=" * 60)
        print(f" Using policy file: {self.policy_file.relative_to(self.repo_path)}")
        
        # Step 1: Detect project language and dependencies
        deps = self._detect_dependencies()
        
        if not deps:
            print(" No dependencies found to check")
            return True
        
        print(f"\n Found {len(deps)} dependencies to check")
        
        
        
        # Step 3: Validate each dependency
        for dep in deps:
            self._validate_dependency(dep)
        
        # Step 4: Report results
        self._print_report()
        
        return len(self.violations) == 0
    
    def _detect_dependencies(self) -> List[Dict]:
        """Detect project dependencies from lock files"""
        dependencies = []
        
        # Check for Node.js
        if (self.repo_path / 'package.json').exists():
            deps = self._parse_npm_deps()
            for dep in deps:
                dep['language'] = 'js'
            dependencies.extend(deps)
        
        # Check for Go
        if (self.repo_path / 'go.mod').exists():
            deps = self._parse_go_deps()
            for dep in deps:
                dep['language'] = 'go'
            dependencies.extend(deps)
        
        # Check for Python
        if (self.repo_path / 'requirements.txt').exists():
            deps = self._parse_python_deps()
            for dep in deps:
                dep['language'] = 'python'
            dependencies.extend(deps)
        
        return dependencies
    
    def _parse_npm_deps(self) -> List[Dict]:
        """Parse npm dependencies from package.json and lock file"""
        deps = []
        
        try:
            with open(self.repo_path / 'package.json') as f:
                data = json.load(f)
                
            # Get all dependencies
            all_deps = {}
            all_deps.update(data.get('dependencies', {}))
            all_deps.update(data.get('devDependencies', {}))
            
            for name, version in all_deps.items():
                deps.append({
                    'name': name,
                    'version': version,
                    'source': 'package.json'
                })
                
            # Check lock file for more details
            lock_file = self.repo_path / 'package-lock.json'
            if lock_file.exists():
                with open(lock_file) as f:
                    lock_data = json.load(f)
                    
                # Add transitive dependencies from lock file
                packages = lock_data.get('packages', {})
                for pkg_path, pkg_info in packages.items():
                    if pkg_path and pkg_path != '':
                        name = pkg_path.split('node_modules/')[-1]
                        if name and name not in [d['name'] for d in deps]:
                            deps.append({
                                'name': name,
                                'version': pkg_info.get('version', 'unknown'),
                                'source': 'transitive'
                            })
                            
        except Exception as e:
            print(f"  Error parsing npm deps: {e}")
            
        return deps
    
    def _parse_go_deps(self) -> List[Dict]:
        """Parse Go dependencies from go.mod"""
        deps = []
        
        try:
            with open(self.repo_path / 'go.mod') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith(('module', 'go ', 'require (')):
                        # Parse go.mod line
                        parts = line.split()
                        if len(parts) >= 2:
                            name = parts[0]
                            version = parts[1]
                            deps.append({
                                'name': name,
                                'version': version,
                                'source': 'direct'
                            })
        except Exception as e:
            print(f"  Error parsing go.mod: {e}")
            
        return deps
    
    def _parse_python_deps(self) -> List[Dict]:
        """Parse Python dependencies from requirements.txt"""
        deps = []
        
        try:
            with open(self.repo_path / 'requirements.txt') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Parse requirement line
                        if '==' in line:
                            name, version = line.split('==', 1)
                        elif '>=' in line:
                            name, version = line.split('>=', 1)
                        else:
                            name = line
                            version = 'latest'
                        
                        deps.append({
                            'name': name.strip(),
                            'version': version.strip(),
                            'source': 'direct'
                        })
        except Exception as e:
            print(f"Error parsing requirements.txt: {e}")
            
        return deps
    
    
    def _validate_dependency(self, dep: Dict):
        """Check if a dependency is allowed"""
        language = dep.get('language')
        name = dep.get('name')
        
        if not language or not name:
            return
        
        # Get policy for this language
        lang_policy = self.policy.get(language, {})
        allowed = lang_policy.get('allowed', [])
        blocked = lang_policy.get('blocked', [])
        requires_review = lang_policy.get('requires_review', [])
        
        # Check AI-specific restrictions
        ai_policy = self.policy.get('ai_code', {}).get('dependency_restrictions', {})
        ai_strict_mode = ai_policy.get('strict_mode', False)
        ai_blocked_patterns = ai_policy.get('blocked_patterns', [])
        
        # Check if explicitly blocked
        for blocked_pattern in blocked:
            if fnmatch.fnmatch(name, blocked_pattern):
                self.violations.append({
                    'type': 'blocked',
                    'dependency': name,
                    'language': language,
                    'reason': f'Package is explicitly blocked',
                    'details': self._get_block_reason(name, language)
                })
                return
        
        # Check if allowed
        allowed_match = False
        for allowed_pattern in allowed:
            if fnmatch.fnmatch(name, allowed_pattern):
                allowed_match = True
                break
        
        if not allowed_match:
            # Not in allowed list - this is a violation
            violation = {
                'type': 'unapproved',
                'dependency': name,
                'language': language,
                'version': dep.get('version', 'unknown'),
                'source': dep.get('source', 'direct')
            }
            
            # Check if it requires review (especially for AI code)
            for review_pattern in requires_review:
                if fnmatch.fnmatch(name, review_pattern):
                    violation['requires_review'] = True
                    violation['reason'] = 'Package requires security review'
                    
                    # AI code with requires_review packages is extra strict
                    if self.ai_detected:
                        violation['ai_restriction'] = True
                        violation['reason'] += ' (AI-generated code - extra scrutiny required)'
                    break
            
            # Check AI blocked patterns
            if self.ai_detected and ai_strict_mode:
                for pattern in ai_blocked_patterns:
                    if fnmatch.fnmatch(name, pattern):
                        violation['ai_blocked'] = True
                        violation['reason'] = f'Package matches AI blocked pattern: {pattern}'
                        break
            
            self.violations.append(violation)
    
    def _get_block_reason(self, name: str, language: str) -> str:
        """Get reason why a package is blocked"""
        # This could be extended to pull from a database
        reasons = {
            'github.com/dgrijalva/jwt-go': 'Unmaintained - use github.com/golang-jwt/jwt instead',
            'request': 'Deprecated - use axios or node-fetch',
            'left-pad': 'Trivial package - use native String.padStart',
            'pycrypto': 'Unmaintained - use pycryptodome',
            'colors.js': 'Supply chain attack history',
            'event-stream': 'Known backdoor incident'
        }
        return reasons.get(name, 'Blocked by security policy')
    
    def _print_report(self):
        """Print violation report with approval instructions"""
        if not self.violations:
            print("\nALL DEPENDENCIES ARE APPROVED")
            return
        
        print("\nDEPENDENCY VIOLATIONS FOUND")
        print("=" * 60)
        
        # Group violations by type
        blocked = [v for v in self.violations if v['type'] == 'blocked']
        unapproved = [v for v in self.violations if v['type'] == 'unapproved']
        ai_blocked = [v for v in self.violations if v.get('ai_blocked')]
        
        # Blocked packages (explicitly forbidden)
        if blocked:
            print(f"\n BLOCKED PACKAGES ({len(blocked)})")
            print("   " + "-" * 40)
            for v in blocked:
                print(f"\n    {v['dependency']}")
                print(f"      Reason: {v['details']}")
        
        # AI-blocked packages
        if ai_blocked:
            print(f"\n AI-BLOCKED PACKAGES ({len(ai_blocked)})")
            print("   " + "-" * 40)
            for v in ai_blocked:
                print(f"\n   {v['dependency']}")
                print(f"      {v['reason']}")
        
        # Unapproved packages (not in allowed list)
        if unapproved:
            print(f"\n UNAPPROVED PACKAGES ({len(unapproved)})")
            print("   " + "-" * 40)
            
            for v in unapproved:
                print(f"\n    {v['dependency']} ({v['language']})")
                if v.get('requires_review'):
                    print(f"       {v['reason']}")
                else:
                    print(f"      Not in allowed dependencies list")
 
# MAIN ENTRY POINT

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Allowed Dependencies Guardrail Enforcer"
    )
    parser.add_argument(
        "--repo",
        default=".",
        help="Path to repository (default: current directory)"
    )

    args = parser.parse_args()

    enforcer = AllowedDependenciesEnforcer(repo_path=args.repo)
    success = enforcer.enforce()

    if not success:
        print("\nBUILD BLOCKED: Unapproved dependencies detected")
        sys.exit(1)
    else:
        print("\nGuardrail check passed")
        sys.exit(0)
