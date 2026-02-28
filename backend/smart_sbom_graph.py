import networkx as nx
import json
import sqlite3
from typing import Dict, List, Any
from cyclonedx.model.bom import Bom
from cyclonedx.parser import parse
import pickle
import os

class SmartSBOMGraph:
    """Graph-based SBOM database for complex queries"""
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.graph_file = 'database/graph_store.pickle'
        self._load_graph()
    
    def _load_graph(self):
        """Load existing graph from disk"""
        if os.path.exists(self.graph_file):
            with open(self.graph_file, 'rb') as f:
                self.graph = pickle.load(f)
    
    def _save_graph(self):
        """Save graph to disk"""
        with open(self.graph_file, 'wb') as f:
            pickle.dump(self.graph, f)
    
    def generate_sbom(self, project_id: int, repo_url: str) -> Dict:
        """Generate SBOM from repository and store in graph"""
        
        # For demo, create sample SBOM data
        # In production, use tools like cyclonedx-python or SPDX tools
        
        # Sample components
        components = [
            {'name': 'requests', 'version': '2.28.1', 'type': 'library', 
             'vulnerabilities': ['CVE-2023-1234']},
            {'name': 'flask', 'version': '2.3.0', 'type': 'framework',
             'vulnerabilities': []},
            {'name': 'sqlalchemy', 'version': '1.4.47', 'type': 'library',
             'vulnerabilities': ['CVE-2023-5678']},
            {'name': 'jinja2', 'version': '3.1.2', 'type': 'template',
             'vulnerabilities': []},
            {'name': 'werkzeug', 'version': '2.3.0', 'type': 'library',
             'vulnerabilities': ['CVE-2023-9012']}
        ]
        
        # Add nodes and edges
        self.graph.add_node(f'project_{project_id}', 
                           type='project', 
                           url=repo_url,
                           timestamp='2024-01-01')
        
        for comp in components:
            node_id = f"{comp['name']}_{comp['version']}"
            self.graph.add_node(node_id, 
                               type='component',
                               name=comp['name'],
                               version=comp['version'],
                               vulns=comp['vulnerabilities'])
            
            # Add dependency edge
            self.graph.add_edge(f'project_{project_id}', node_id, 
                               relationship='DEPENDS_ON')
            
            # Add vulnerability nodes and edges
            for vuln_id in comp['vulnerabilities']:
                vuln_node = f"vuln_{vuln_id}"
                if not self.graph.has_node(vuln_node):
                    self.graph.add_node(vuln_node,
                                       type='vulnerability',
                                       id=vuln_id,
                                       severity='HIGH' if vuln_id == 'CVE-2023-1234' else 'MEDIUM')
                
                self.graph.add_edge(node_id, vuln_node, relationship='AFFECTED_BY')
        
        self._save_graph()
        
        # Also store in SQLite
        conn = sqlite3.connect('database/sbom.db')
        c = conn.cursor()
        c.execute('INSERT INTO sbom_documents (project_id, format, content, created_at) VALUES (?, ?, ?, ?)',
                 (project_id, 'cyclonedx', json.dumps(components), '2024-01-01'))
        conn.commit()
        conn.close()
        
        return {'status': 'success', 'components': len(components)}
    
    def query_reachable_vulnerabilities(self, project_id: int, vulnerable_component: str) -> List[Dict]:
        """Query for vulnerabilities that are actually reachable"""
        
        # Find all paths from project to vulnerable component
        reachable_vulns = []
        
        for node in self.graph.nodes():
            if self.graph.nodes[node].get('type') == 'vulnerability':
                # Check if there's a path from this vulnerability to the project
                try:
                    # Find all components affected by this vuln
                    affected_components = [n for n in self.graph.predecessors(node)]
                    
                    for comp in affected_components:
                        # Check if this component is used by the project
                        if nx.has_path(self.graph, f'project_{project_id}', comp):
                            # Found reachable vulnerability
                            reachable_vulns.append({
                                'vulnerability': self.graph.nodes[node].get('id'),
                                'component': self.graph.nodes[comp].get('name'),
                                'version': self.graph.nodes[comp].get('version'),
                                'path': list(nx.shortest_path(self.graph, f'project_{project_id}', comp))
                            })
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue
        
        return reachable_vulns
    
    def get_graph_data(self, project_id: int) -> Dict:
        """Return graph in D3.js compatible format"""
        nodes = []
        links = []
        
        # Get subgraph for this project
        try:
            project_node = f'project_{project_id}'
            subgraph_nodes = set(nx.descendants(self.graph, project_node))
            subgraph_nodes.add(project_node)
            
            for node in subgraph_nodes:
                nodes.append({
                    'id': node,
                    'name': str(node),
                    'type': self.graph.nodes[node].get('type', 'unknown'),
                    'vulns': self.graph.nodes[node].get('vulns', [])
                })
            
            for u, v in self.graph.edges(subgraph_nodes):
                links.append({
                    'source': u,
                    'target': v,
                    'relationship': self.graph.edges[u, v].get('relationship', 'unknown')
                })
        except (nx.NodeNotFound, KeyError):
            pass
        
        return {'nodes': nodes, 'links': links}