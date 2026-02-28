import requests
import json
from typing import Dict, Optional
import subprocess
import tempfile
import os

class ReachabilityAnalyzer:
    """Uses local LLM to analyze if vulnerabilities are actually reachable"""
    
    def __init__(self, use_ollama: bool = True):
        self.use_ollama = use_ollama
        self.ollama_url = "http://localhost:11434/api/generate"
        
        # For zero-cost, we'll use Ollama with a small model
        # Install: curl -fsSL https://ollama.com/install.sh | sh
        # Then: ollama pull codellama:7b
        
    def analyze(self, component: str, version: str, vuln_id: str, 
                code_context: Optional[str] = None) -> Dict:
        """Determine if a vulnerability is actually reachable in the code"""
        
        if not code_context:
            # If no code context, try to fetch it
            code_context = self._fetch_component_code(component, version)
        
        if self.use_ollama:
            return self._analyze_with_ollama(component, vuln_id, code_context)
        else:
            # Fallback to static analysis
            return self._analyze_static(component, vuln_id, code_context)
    
    def _analyze_with_ollama(self, component: str, vuln_id: str, 
                             code_context: str) -> Dict:
        """Use Ollama LLM for sophisticated reachability analysis"""
        
        prompt = f"""
        Analyze if vulnerability {vuln_id} in component {component} is reachable in this code.
        
        Vulnerability info: 
        {self._get_vuln_description(vuln_id)}
        
        Code context:
        {code_context[:3000]}  # Limit context size
        
        Answer with JSON:
        {{
            "is_reachable": true/false,
            "confidence": 0.0-1.0,
            "explanation": "detailed explanation",
            "exploit_path": "how an attacker could reach this",
            "call_chain": ["function1", "function2", "vulnerable_function"]
        }}
        """
        
        try:
            response = requests.post(self.ollama_url, json={
                "model": "codellama:7b",
                "prompt": prompt,
                "stream": False,
                "format": "json"
            })
            
            if response.status_code == 200:
                result = response.json()
                # Parse the JSON from the response
                try:
                    analysis = json.loads(result.get('response', '{}'))
                    return {
                        'is_reachable': analysis.get('is_reachable', False),
                        'confidence': analysis.get('confidence', 0.5),
                        'explanation': analysis.get('explanation', 'No explanation'),
                        'exploit_path': analysis.get('exploit_path', ''),
                        'call_chain': analysis.get('call_chain', [])
                    }
                except:
                    return {'is_reachable': None, 'confidence': 0, 
                           'error': 'Failed to parse LLM response'}
            
        except Exception as e:
            print(f"Ollama error: {e}")
            return self._analyze_static(component, vuln_id, code_context)
    
    def _analyze_static(self, component: str, vuln_id: str, code_context: str) -> Dict:
        """Fallback static analysis using regex and pattern matching"""
        
        # Simple heuristics for demo
        reachable = False
        confidence = 0.3
        
        # Check if the component is actually imported/used
        import_patterns = [
            f"import {component}",
            f"from {component} import",
            f"require\('{component}'\)",
            f"<dependency>.*{component}.*</dependency>"
        ]
        
        for pattern in import_patterns:
            if pattern in code_context:
                reachable = True
                confidence = 0.6
                break
        
        # Check for dangerous function calls (simplified)
        dangerous_functions = ['eval', 'exec', 'os.system', 'subprocess.call',
                              'pickle.loads', 'yaml.load']
        
        for func in dangerous_functions:
            if func in code_context:
                confidence = min(confidence + 0.2, 0.9)
        
        return {
            'is_reachable': reachable,
            'confidence': confidence,
            'explanation': 'Based on static analysis of imports and dangerous calls',
            'method': 'static_heuristics'
        }
    
    def _get_vuln_description(self, vuln_id: str) -> str:
        """Fetch vulnerability description from NVD"""
        try:
            response = requests.get(
                f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={vuln_id}'
            )
            if response.status_code == 200:
                data = response.json()
                vuln = data['vulnerabilities'][0]['cve']
                desc = vuln['descriptions'][0]['value']
                return desc[:500]  # Limit length
        except:
            pass
        
        return "No description available"
    
    def _fetch_component_code(self, component: str, version: str) -> str:
        """Attempt to fetch actual code of the component"""
        # In production, this would clone the repo or fetch from package manager
        # For demo, return sample code
        return f"""
        # Sample code for {component} v{version}
        import os
        import sys
        
        def process_input(data):
            # Potentially vulnerable function
            result = eval(data)  # Dangerous!
            return result
        
        def main():
            user_input = sys.argv[1]
            output = process_input(user_input)
            print(output)
        """