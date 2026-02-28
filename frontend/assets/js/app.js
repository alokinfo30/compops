// Main application JavaScript

const API_BASE = 'http://localhost:5000/api';

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    loadDashboardStats();
    loadVulnerabilities();
    setupEventListeners();
});

function setupEventListeners() {
    // Add project form
    const projectForm = document.getElementById('add-project-form');
    if (projectForm) {
        projectForm.addEventListener('submit', handleAddProject);
    }
    
    // Show reachable only toggle
    const reachableToggle = document.getElementById('show-reachable-only');
    if (reachableToggle) {
        reachableToggle.addEventListener('change', function() {
            loadVulnerabilities(this.checked);
        });
    }
}

async function handleAddProject(e) {
    e.preventDefault();
    
    const name = document.getElementById('project-name').value;
    const repoUrl = document.getElementById('repo-url').value;
    
    try {
        const response = await fetch(`${API_BASE}/projects`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ name, repo_url: repoUrl })
        });
        
        if (response.ok) {
            // Reset form
            document.getElementById('project-name').value = '';
            document.getElementById('repo-url').value = '';
            
            // Reload data
            loadDashboardStats();
            loadVulnerabilities();
            
            // Show success message
            Metro.notify.create('Project added successfully', 'Success', {
                cls: 'success',
                timeout: 3000
            });
        }
    } catch (error) {
        console.error('Error adding project:', error);
        Metro.notify.create('Failed to add project', 'Error', {
            cls: 'alert',
            timeout: 3000
        });
    }
}

async function loadDashboardStats() {
    try {
        const response = await fetch(`${API_BASE}/projects`);
        const projects = await response.json();
        
        document.getElementById('stats-projects').textContent = projects.length;
        
        // Get vulnerabilities count
        const vulnsResponse = await fetch(`${API_BASE}/vulnerabilities`);
        const vulns = await vulnsResponse.json();
        
        document.getElementById('stats-vulns').textContent = vulns.length;
        
        // Count reachable
        const reachable = vulns.filter(v => v.is_reachable).length;
        document.getElementById('stats-reachable').textContent = reachable;
        
        // Count components (unique from vulns)
        const components = new Set(vulns.map(v => v.component)).size;
        document.getElementById('stats-components').textContent = components;
        
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

async function loadVulnerabilities(reachableOnly = false) {
    try {
        let url = `${API_BASE}/vulnerabilities`;
        if (reachableOnly) {
            url += '?reachable_only=true';
        }
        
        const response = await fetch(url);
        const vulns = await response.json();
        
        renderVulnerabilitiesTable(vulns);
    } catch (error) {
        console.error('Error loading vulnerabilities:', error);
    }
}

function renderVulnerabilitiesTable(vulns) {
    const tbody = document.getElementById('vulns-tbody');
    if (!tbody) return;
    
    if (vulns.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center">No vulnerabilities found</td></tr>';
        return;
    }
    
    tbody.innerHTML = vulns.map(vuln => `
        <tr data-vuln-id="${vuln.id}">
            <td>${vuln.component}</td>
            <td>${vuln.version}</td>
            <td>${vuln.id}</td>
            <td>
                <span class="badge ${getSeverityClass(vuln.severity)}">
                    ${vuln.severity || 'UNKNOWN'}
                </span>
            </td>
            <td>${vuln.cvss || 'N/A'}</td>
            <td>
                <span class="badge ${vuln.is_reachable ? 'danger' : 'success'}">
                    ${vuln.is_reachable ? 'YES' : 'NO'}
                </span>
            </td>
            <td>
                <button onclick="analyzeReachability('${vuln.id}')" 
                        class="button small ${vuln.is_reachable ? 'warning' : 'secondary'}"
                        ${vuln.is_reachable ? 'disabled' : ''}>
                    <i class="fas fa-brain"></i> Analyze
                </button>
                <button onclick="checkUpgrade('${vuln.id}')" 
                        class="button small success">
                    <i class="fas fa-arrow-up"></i> Upgrade
                </button>
            </td>
        </tr>
    `).join('');
}

function getSeverityClass(severity) {
    const severityMap = {
        'CRITICAL': 'danger',
        'HIGH': 'danger',
        'MEDIUM': 'warning',
        'LOW': 'success'
    };
    return severityMap[severity?.toUpperCase()] || 'secondary';
}

async function analyzeReachability(vulnId) {
    const button = event.target.closest('button');
    const originalText = button.innerHTML;
    
    button.innerHTML = '<span class="loading"></span> Analyzing...';
    button.disabled = true;
    
    try {
        // Get component info from table row
        const row = document.querySelector(`tr[data-vuln-id="${vulnId}"]`);
        const component = row.cells[0].textContent;
        const version = row.cells[1].textContent;
        
        const response = await fetch(`${API_BASE}/reachability/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                vuln_id: vulnId,
                component: component,
                version: version
            })
        });
        
        const result = await response.json();
        
        if (result.is_reachable !== null) {
            Metro.notify.create(
                `Reachable: ${result.is_reachable ? 'YES' : 'NO'} (${Math.round(result.confidence * 100)}% confidence)`,
                'Analysis Complete',
                { cls: result.is_reachable ? 'alert' : 'success' }
            );
            
            // Reload table
            loadVulnerabilities();
        }
        
    } catch (error) {
        console.error('Error analyzing:', error);
        Metro.notify.create('Analysis failed', 'Error', { cls: 'alert' });
    } finally {
        button.innerHTML = originalText;
        button.disabled = false;
    }
}

async function checkUpgrade(vulnId) {
    try {
        const response = await fetch(`${API_BASE}/upgrade/check/${vulnId}`, {
            method: 'POST'
        });
        
        const result = await response.json();
        
        if (result.feasible) {
            // Show upgrade modal
            showUpgradeModal(vulnId, result);
        } else {
            Metro.notify.create(
                `Cannot auto-upgrade: ${result.reason}`,
                'Upgrade Check',
                { cls: 'warning' }
            );
        }
        
    } catch (error) {
        console.error('Error checking upgrade:', error);
        Metro.notify.create('Upgrade check failed', 'Error', { cls: 'alert' });
    }
}

function showUpgradeModal(vulnId, upgradeInfo) {
    const modal = document.getElementById('upgrade-modal');
    const details = document.getElementById('upgrade-details');
    
    details.innerHTML = `
        <div class="info-panel">
            <p><strong>Component:</strong> ${upgradeInfo.component}</p>
            <p><strong>Current Version:</strong> ${upgradeInfo.from_version}</p>
            <p><strong>Target Version:</strong> ${upgradeInfo.to_version}</p>
            <p><strong>Confidence:</strong> ${Math.round(upgradeInfo.confidence * 100)}%</p>
            <p class="text-small text-muted mt-2">
                This will create a pull request with the upgraded dependency and run tests.
            </p>
        </div>
    `;
    
    // Store vuln ID for the execute button
    document.getElementById('execute-upgrade').dataset.vulnId = vulnId;
    document.getElementById('execute-upgrade').dataset.upgradeInfo = JSON.stringify(upgradeInfo);
    
    Metro.getPlugin(modal, 'modal').open();
}

// Execute upgrade
document.getElementById('execute-upgrade')?.addEventListener('click', async function() {
    const vulnId = this.dataset.vulnId;
    const upgradeInfo = JSON.parse(this.dataset.upgradeInfo);
    
    this.innerHTML = '<span class="loading"></span> Creating PR...';
    this.disabled = true;
    
    try {
        const response = await fetch(`${API_BASE}/upgrade/execute`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                vuln_id: vulnId,
                component: upgradeInfo.component,
                from_version: upgradeInfo.from_version,
                to_version: upgradeInfo.to_version
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            Metro.notify.create(
                `PR created: <a href="${result.pr_url}" target="_blank">#${result.pr_number}</a>`,
                'Upgrade Initiated',
                { cls: 'success', timeout: 10000 }
            );
            
            // Close modal
            Metro.getPlugin(document.getElementById('upgrade-modal'), 'modal').close();
        } else {
            Metro.notify.create(`Failed: ${result.error}`, 'Error', { cls: 'alert' });
        }
        
    } catch (error) {
        console.error('Error executing upgrade:', error);
        Metro.notify.create('Upgrade failed', 'Error', { cls: 'alert' });
    } finally {
        this.innerHTML = '<i class="fas fa-rocket"></i> Create Upgrade PR';
        this.disabled = false;
    }
});

// Real-time updates - poll every 30 seconds
setInterval(() => {
    if (document.visibilityState === 'visible') {
        loadDashboardStats();
        const reachableOnly = document.getElementById('show-reachable-only')?.checked || false;
        loadVulnerabilities(reachableOnly);
    }
}, 30000);