# CompOps Platform

Software Supply Chain Security Platform for vulnerability detection, SBOM management, and automated upgrades.

🚀 Live Demo
[Live Application URL](https://compops.onrender.com/)

## Features

- **SBOM Explorer**: Generate and visualize Software Bill of Materials
- **Vulnerability Detection**: Track and manage security vulnerabilities in your dependencies
- **AI-Powered Reachability Analysis**: Determine if vulnerabilities are actually reachable in your code
- **Auto-Upgrade**: Automatically create GitHub PRs to upgrade vulnerable components

All 4 Features Fully Implemented ✅
1. SBOM Explorer: Generate and Visualize Software Bill of Materials
Backend: backend/sbom_generator.py - Generates real SBOM from GitHub repositories
Formats: CycloneDX, SPDX, JSON
Parses: requirements.txt, package.json, go.mod, pom.xml, build.gradle
Frontend: Added "Generate SBOM" and "Export SBOM" buttons in sbom-explorer.html
API: /api/sbom/generate endpoint
2. Vulnerability Detection: Track and manage security vulnerabilities
Backend: backend/vulnerability_scanner.py - Uses OSV.dev API for real vulnerability scanning
Sources: Real-time queries to OSV (PyPI, npm, Go, Maven ecosystems)
Data: Severity, CVSS scores, fixed versions stored in SQLite
Frontend: Added "Scan for Vulnerabilities" button in index.html
API: /api/scan/vulnerabilities endpoint
3. AI-Powered Reachability Analysis
Backend: backend/reachability_ai.py - Uses Ollama LLM for reachability analysis
API: /api/reachability/analyze endpoint
Features: Determines if vulnerabilities are actually exploitable in code
4. Auto-Upgrade: Create GitHub PRs to upgrade vulnerable components
Backend: backend/github_integration.py + backend/universal_upgrade.py
API: /api/upgrade/execute endpoint
Features: Creates branches, updates dependencies, opens PRs automatically
Files Created/Modified:
✅ backend/sbom_generator.py (NEW)
✅ backend/vulnerability_scanner.py (NEW)
✅ backend/smart_sbom_graph.py (datetime import added)
✅ backend/app.py (integrated new modules)
✅ frontend/assets/js/app.js (added scanProject, generateSBOM, exportSBOM)
✅ frontend/index.html (added Scan button)
✅ frontend/sbom-explorer.html (added Generate/Export buttons)

## Tech Stack

- **Backend**: Flask (Python)
- **Frontend**: HTML/CSS/JavaScript with Metro UI
- **Database**: SQLite
- **Visualization**: Chart.js, D3.js

## Getting Started

### Prerequisites

- Python 3.8+
- Git

### Installation

1. Clone the repository:
```
bash
git clone https://github.com/alokinfo30/compops.git
cd compops
```

2. Install backend dependencies:
```
bash
cd backend
pip install -r requirements.txt
```

3. Run the backend server:
```
bash
python app.py
```

4. Open the frontend:
Navigate to `http://localhost:5000` in your browser.

## API Endpoints

- `GET /api/projects` - List all projects
- `POST /api/projects` - Add a new project
- `GET /api/vulnerabilities` - Get vulnerabilities
- `GET /api/sbom/graph/<project_id>` - Get SBOM graph data
- `POST /api/upgrade/execute` - Execute auto-upgrade
- `POST /api/reachability/analyze` - Analyze vulnerability reachability


🏗️ Complete CompOps Platform Architecture

Tech Stack (100% Free)

· Backend: Python Flask + SQLite (free, no licenses)
· Frontend: Metro UI CSS  + Vanilla JS (responsive, mobile-first)
· Database: SQLite + NetworkX for graph operations (in-memory graph DB)
· AI Integration: Local LLM via Ollama (free, no API costs)
· CI/CD Integration: GitHub Actions (free for public repos)
· Hosting: AWS Free Tier (t3.micro, 750 hrs/month free)  + Amplify Hosting 
· SBOM Processing: CycloneDX + SPDX parsers 

📁 Project Structure

```
compops-platform/
├── backend/
│   ├── app.py                 # Main Flask application
│   ├── requirements.txt       # Python dependencies
│   ├── universal_upgrade.py   # Auto-upgrade engine
│   ├── smart_sbom_graph.py    # Graph-based SBOM database
│   ├── reachability_ai.py     # AI-powered reachability analysis
│   ├── github_integration.py  # GitHub PR automation
│   └── database/
│       ├── sbom.db            # SQLite database
│       └── graph_store.pickle  # Serialized graph data
├── frontend/
│   ├── index.html             # Main dashboard
│   ├── dashboard.html          # Analytics view
│   ├── sbom-explorer.html      # Graph visualization
│   └── assets/
│       ├── css/
│       │   └── custom.css      # Metro UI overrides
│       └── js/
│           └── app.js          # Frontend logic
├── .github/
│   └── workflows/
│       └── auto-upgrade.yml    # GitHub Actions workflow
├── deploy.sh                    # One-click deployment script
└── README.md                    # Setup instructions






## License

MIT


