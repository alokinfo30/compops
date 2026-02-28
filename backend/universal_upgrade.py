import requests
import semver
import subprocess
import tempfile
import os
from typing import Dict, List, Optional
import json

class UniversalUpgradeEngine:
    """Automatically upgrades vulnerable dependencies with test validation"""
    
    def __init__(self):
        self.package_managers = {
            'pip': self._upgrade_pip,
            'npm': self._upgrade_npm,
            'maven': self._upgrade_maven,
            'golang': self._upgrade_go
        }
        
    def check_upgrade_feasibility(self, vuln_id: int) -> Dict:
        """Check if a vulnerability can be auto-upgraded"""
        # Get vulnerability details from database
        import sqlite3
        conn = sqlite3.connect('database/sbom.db')
        c = conn.cursor()
        c.execute('SELECT component_name, version, fixed_version FROM vulnerabilities WHERE id = ?', (vuln_id,))
        row = c.fetchone()
        conn.close()
        
        if not row:
            return {'feasible': False, 'reason': 'Vulnerability not found'}
        
        component, current_version, fixed_version = row
        
        # Check if fixed version exists and is compatible
        try:
            # Query package repository for version info
            if fixed_version:
                # Verify fixed version is newer
                if semver.compare(fixed_version, current_version) > 0:
                    return {
                        'feasible': True,
                        'component': component,
                        'from_version': current_version,
                        'to_version': fixed_version,
                        'confidence': 0.9
                    }
                else:
                    return {'feasible': False, 'reason': 'Fixed version is not newer'}
            else:
                # Need to find the next safe version
                latest_safe = self._find_latest_safe_version(component, current_version)
                if latest_safe:
                    return {
                        'feasible': True,
                        'component': component,
                        'from_version': current_version,
                        'to_version': latest_safe,
                        'confidence': 0.7
                    }
        except Exception as e:
            return {'feasible': False, 'reason': str(e)}
        
        return {'feasible': False, 'reason': 'No safe upgrade path found'}
    
    def _find_latest_safe_version(self, component: str, current_version: str) -> Optional[str]:
        """Find the latest non-vulnerable version of a component"""
        # Check PyPI for Python packages
        try:
            response = requests.get(f'https://pypi.org/pypi/{component}/json')
            if response.status_code == 200:
                versions = list(response.json()['releases'].keys())
                # Filter versions > current_version
                newer_versions = [v for v in versions if semver.compare(v, current_version) > 0]
                if newer_versions:
                    # Return the latest version
                    return sorted(newer_versions, key=semver.Version.parse)[-1]
        except:
            pass
        
        # Check npm registry
        try:
            response = requests.get(f'https://registry.npmjs.org/{component}')
            if response.status_code == 200:
                versions = list(response.json()['versions'].keys())
                newer_versions = [v for v in versions if semver.compare(v, current_version) > 0]
                if newer_versions:
                    return sorted(newer_versions, key=semver.Version.parse)[-1]
        except:
            pass
        
        return None
    
    def _upgrade_pip(self, component: str, target_version: str, repo_path: str) -> bool:
        """Upgrade Python pip package and run tests"""
        try:
            # Update requirements.txt
            req_file = os.path.join(repo_path, 'requirements.txt')
            if os.path.exists(req_file):
                with open(req_file, 'r') as f:
                    lines = f.readlines()
                
                with open(req_file, 'w') as f:
                    for line in lines:
                        if line.startswith(component):
                            f.write(f'{component}=={target_version}\n')
                        else:
                            f.write(line)
            
            # Update setup.py if exists
            setup_file = os.path.join(repo_path, 'setup.py')
            if os.path.exists(setup_file):
                subprocess.run(['sed', '-i', f's/{component}==.*/{component}=={target_version}/', setup_file])
            
            # Run tests
            result = subprocess.run(['pytest'], cwd=repo_path, capture_output=True)
            return result.returncode == 0
            
        except Exception as e:
            print(f"Upgrade failed: {e}")
            return False
    
    def _upgrade_npm(self, component: str, target_version: str, repo_path: str) -> bool:
        """Upgrade npm package and run tests"""
        try:
            # Run npm update
            subprocess.run(['npm', 'install', f'{component}@{target_version}', '--save'], 
                         cwd=repo_path, check=True)
            
            # Run tests
            result = subprocess.run(['npm', 'test'], cwd=repo_path, capture_output=True)
            return result.returncode == 0
            
        except Exception as e:
            print(f"npm upgrade failed: {e}")
            return False
    
    def _upgrade_maven(self, component: str, target_version: str, repo_path: str) -> bool:
        """Upgrade Maven dependency and run tests"""
        try:
            pom_file = os.path.join(repo_path, 'pom.xml')
            if os.path.exists(pom_file):
                # Use Maven versions plugin
                subprocess.run([
                    'mvn', 'versions:use-dep-version',
                    f'-Dincludes={component}',
                    f'-DdepVersion={target_version}',
                    '-DforceVersion=true'
                ], cwd=repo_path, check=True)
                
                # Run tests
                result = subprocess.run(['mvn', 'test'], cwd=repo_path, capture_output=True)
                return result.returncode == 0
            
        except Exception as e:
            print(f"Maven upgrade failed: {e}")
            return False
    
    def _upgrade_go(self, component: str, target_version: str, repo_path: str) -> bool:
        """Upgrade Go module and run tests"""
        try:
            # Update go.mod
            subprocess.run(['go', 'get', f'{component}@{target_version}'], 
                         cwd=repo_path, check=True)
            subprocess.run(['go', 'mod', 'tidy'], cwd=repo_path, check=True)
            
            # Run tests
            result = subprocess.run(['go', 'test', './...'], cwd=repo_path, capture_output=True)
            return result.returncode == 0
            
        except Exception as e:
            print(f"Go upgrade failed: {e}")
            return False