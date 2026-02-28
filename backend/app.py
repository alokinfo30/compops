from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3
import json
from datetime import datetime
import os

# Import our custom modules
from universal_upgrade import UniversalUpgradeEngine
from smart_sbom_graph import SmartSBOMGraph
from reachability_ai import ReachabilityAnalyzer
from github_integration import GitHubAutomation

app = Flask(__name__, static_folder='../frontend', static_url_path='')
CORS(app)

# Initialize components
upgrade_engine = UniversalUpgradeEngine()
sbom_graph = SmartSBOMGraph()
reachability_ai = ReachabilityAnalyzer()
github_auto = GitHubAutomation()

# Database initialization
def init_db():
    conn = sqlite3.connect('database/sbom.db')
    c = conn.cursor()
    
    # Projects table
    c.execute('''CREATE TABLE IF NOT EXISTS projects
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT UNIQUE,
                  repo_url TEXT,
                  created_at TIMESTAMP)''')
    
    # Vulnerabilities table
    c.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities
                 (id TEXT PRIMARY KEY,
                  component_name TEXT,
                  version TEXT,
                  severity TEXT,
                  cvss_score REAL,
                  description TEXT,
                  fixed_version TEXT,
                  detected_at TIMESTAMP,
                  is_reachable BOOLEAN DEFAULT 0)''')
    
    # SBOM documents table
    c.execute('''CREATE TABLE IF NOT EXISTS sbom_documents
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  project_id INTEGER,
                  format TEXT,
                  content TEXT,
                  created_at TIMESTAMP,
                  FOREIGN KEY(project_id) REFERENCES projects(id))''')
    
    conn.commit()
    conn.close()

init_db()

# Serve frontend
@app.route('/')
def serve_index():
    return send_from_directory('../frontend', 'index.html')

@app.route('/<path:path>')
def serve_frontend(path):
    return send_from_directory('../frontend', path)

# API Endpoints
@app.route('/api/projects', methods=['GET', 'POST'])
def handle_projects():
    if request.method == 'GET':
        conn = sqlite3.connect('database/sbom.db')
        c = conn.cursor()
        c.execute('SELECT * FROM projects')
        projects = [{'id': row[0], 'name': row[1], 'repo_url': row[2]} 
                   for row in c.fetchall()]
        conn.close()
        return jsonify(projects)
    
    elif request.method == 'POST':
        data = request.json
        conn = sqlite3.connect('database/sbom.db')
        c = conn.cursor()
        c.execute('INSERT INTO projects (name, repo_url, created_at) VALUES (?, ?, ?)',
                 (data['name'], data['repo_url'], datetime.now()))
        conn.commit()
        project_id = c.lastrowid
        conn.close()
        
        # Trigger initial SBOM generation
        sbom_graph.generate_sbom(project_id, data['repo_url'])
        return jsonify({'id': project_id, 'status': 'created'})

@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    project_id = request.args.get('project_id')
    reachable_only = request.args.get('reachable_only', 'false').lower() == 'true'
    
    conn = sqlite3.connect('database/sbom.db')
    c = conn.cursor()
    
    query = 'SELECT * FROM vulnerabilities'
    params = []
    
    if project_id:
        query += ' WHERE project_id = ?'
        params.append(project_id)
    if reachable_only:
        query += ' AND is_reachable = 1' if 'WHERE' in query else ' WHERE is_reachable = 1'
    
    c.execute(query, params)
    vulns = [{
        'id': row[0],
        'component': row[1],
        'version': row[2],
        'severity': row[3],
        'cvss': row[4],
        'description': row[5],
        'fixed_version': row[6],
        'is_reachable': bool(row[8])
    } for row in c.fetchall()]
    
    conn.close()
    return jsonify(vulns)

@app.route('/api/sbom/graph/<int:project_id>', methods=['GET'])
def get_sbom_graph(project_id):
    """Return graph data for visualization"""
    graph_data = sbom_graph.get_graph_data(project_id)
    return jsonify(graph_data)

@app.route('/api/upgrade/check/<int:vuln_id>', methods=['POST'])
def check_upgrade(vuln_id):
    """Check if auto-upgrade is possible"""
    result = upgrade_engine.check_upgrade_feasibility(vuln_id)
    return jsonify(result)

@app.route('/api/upgrade/execute', methods=['POST'])
def execute_upgrade():
    """Execute auto-upgrade with PR creation"""
    data = request.json
    result = github_auto.create_upgrade_pr(
        vuln_id=data['vuln_id'],
        component=data['component'],
        from_version=data['from_version'],
        to_version=data['to_version']
    )
    return jsonify(result)

@app.route('/api/reachability/analyze', methods=['POST'])
def analyze_reachability():
    """AI-powered reachability analysis"""
    data = request.json
    result = reachability_ai.analyze(
        component=data['component'],
        version=data['version'],
        vuln_id=data['vuln_id'],
        code_context=data.get('code_context')
    )
    
    # Update database with result
    if result.get('is_reachable') is not None:
        conn = sqlite3.connect('database/sbom.db')
        c = conn.cursor()
        c.execute('UPDATE vulnerabilities SET is_reachable = ? WHERE id = ?',
                 (1 if result['is_reachable'] else 0, data['vuln_id']))
        conn.commit()
        conn.close()
    
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)