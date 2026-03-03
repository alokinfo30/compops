from flask import Flask, request, jsonify, send_file, abort
from flask_cors import CORS
import sqlite3
import json
from datetime import datetime
import os
import sys

# Add current directory to path for local imports
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Determine the base directory - works both locally and on Render
# On Render, the repo is cloned to /opt/render/project/src
base_dir = os.path.dirname(os.path.abspath(__file__))
frontend_dir = os.path.join(base_dir, '..', 'frontend')
frontend_dir = os.path.normpath(frontend_dir)

# Check multiple possible locations for frontend
possible_paths = [
    os.path.join(base_dir, 'frontend'),
    os.path.join(base_dir, '..', 'frontend'),
    os.path.join(os.path.dirname(base_dir), 'frontend'),
    '/opt/render/project/src/frontend',
]

frontend_path = None
for path in possible_paths:
    if os.path.exists(os.path.join(path, 'index.html')):
        frontend_path = path
        break

if frontend_path is None:
    # Fallback - use base_dir/frontend
    frontend_path = os.path.join(base_dir, 'frontend')

print(f"Frontend path: {frontend_path}", file=sys.stderr)
print(f"Base dir: {base_dir}", file=sys.stderr)

app = Flask(__name__)
CORS(app)

# Initialize components
from universal_upgrade import UniversalUpgradeEngine
from smart_sbom_graph import SmartSBOMGraph
from reachability_ai import ReachabilityAnalyzer
from github_integration import GitHubAutomation
from sbom_generator import SBOMGenerator
from vulnerability_scanner import VulnerabilityScanner

upgrade_engine = UniversalUpgradeEngine()
sbom_graph = SmartSBOMGraph()
reachability_ai = ReachabilityAnalyzer()
github_auto = GitHubAutomation()
sbom_generator = SBOMGenerator()
vuln_scanner = VulnerabilityScanner()

# Database initialization
def init_db():
    # Ensure database directory exists
    os.makedirs('database', exist_ok=True)
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
                  project_id INTEGER,
                  component_name TEXT,
                  version TEXT,
                  severity TEXT,
                  cvss_score REAL,
                  description TEXT,
                  fixed_version TEXT,
                  detected_at TIMESTAMP,
                  is_reachable BOOLEAN DEFAULT 0,
                  FOREIGN KEY(project_id) REFERENCES projects(id))''')
    
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

# Serve static assets
@app.route('/assets/<path:filename>')
def serve_assets(filename):
    asset_path = os.path.join(frontend_path, 'assets', filename)
    if os.path.exists(asset_path):
        return send_file(asset_path)
    # Try without assets prefix
    asset_path = os.path.join(frontend_path, filename)
    if os.path.exists(asset_path):
        return send_file(asset_path)
    return abort(404)

# Serve index.html for root and all frontend routes
@app.route('/')
def serve_index():
    index_path = os.path.join(frontend_path, 'index.html')
    if os.path.exists(index_path):
        return send_file(index_path)
    return abort(404)

@app.route('/<path:path>')
def serve_frontend(path):
    # Try as a file first
    file_path = os.path.join(frontend_path, path)
    if os.path.exists(file_path) and os.path.isfile(file_path):
        return send_file(file_path)
    
    # Fallback to index.html for SPA routing
    index_path = os.path.join(frontend_path, 'index.html')
    if os.path.exists(index_path):
        return send_file(index_path)
    
    return abort(404)

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
        'project_id': row[1],
        'component': row[2],
        'version': row[3],
        'severity': row[4],
        'cvss': row[5],
        'description': row[6],
        'fixed_version': row[7],
        'is_reachable': bool(row[9])
    } for row in c.fetchall()]
    
    conn.close()
    return jsonify(vulns)

@app.route('/api/sbom/graph/<int:project_id>', methods=['GET'])
def get_sbom_graph(project_id):
    """Return graph data for visualization"""
    graph_data = sbom_graph.get_graph_data(project_id)
    return jsonify(graph_data)

@app.route('/api/upgrade/check/<path:vuln_id>', methods=['GET'])
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

@app.route('/api/scan/vulnerabilities', methods=['POST'])
def scan_vulnerabilities():
    """Scan a project for vulnerabilities using OSV API"""
    data = request.json
    project_id = data.get('project_id')
    
    conn = sqlite3.connect('database/sbom.db')
    c = conn.cursor()
    c.execute('SELECT repo_url FROM projects WHERE id = ?', (project_id,))
    row = c.fetchone()
    conn.close()
    
    if not row:
        return jsonify({'success': False, 'error': 'Project not found'})
    
    repo_url = row[0]
    result = vuln_scanner.scan_project(project_id, repo_url)
    sbom_graph.generate_sbom(project_id, repo_url)
    
    return jsonify(result)

@app.route('/api/sbom/generate', methods=['POST'])
def generate_sbom():
    """Generate SBOM for a project"""
    data = request.json
    project_id = data.get('project_id')
    format = data.get('format', 'cyclonedx')
    
    conn = sqlite3.connect('database/sbom.db')
    c = conn.cursor()
    c.execute('SELECT repo_url FROM projects WHERE id = ?', (project_id,))
    row = c.fetchone()
    conn.close()
    
    if not row:
        return jsonify({'success': False, 'error': 'Project not found'})
    
    repo_url = row[0]
    result = sbom_generator.generate_sbom(project_id, repo_url, format)
    sbom_graph.generate_sbom(project_id, repo_url)
    
    return jsonify(result)

@app.route('/api/sbom/export/<int:project_id>', methods=['GET'])
def export_sbom(project_id):
    """Export SBOM in specified format"""
    format = request.args.get('format', 'cyclonedx')
    sbom = sbom_generator.get_sbom_export(project_id, format)
    
    if sbom:
        return jsonify(sbom)
    return jsonify({'success': False, 'error': 'SBOM not found'})

@app.route('/api/vulnerability/<vuln_id>', methods=['GET'])
def get_vulnerability_details(vuln_id):
    """Get detailed vulnerability information"""
    details = vuln_scanner.get_vulnerability_details(vuln_id)
    
    if details:
        return jsonify(details)
    return jsonify({'success': False, 'error': 'Vulnerability not found'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
