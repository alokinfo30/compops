// Main application JavaScript

// Use relative API URL for both local and production
const API_BASE = '/api';

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
            showNotification('Project added successfully', 'success');
        } else {
            showNotification('Failed to add project', 'error');
        }
    } catch (error) {
        console.error('Error adding project:', error);
        showNotification('Failed to add project: ' + error.message, 'error');
    }
}

async function loadDashboardStats() {
    try {
        const response = await fetch(`${API_BASE}/projects`);
        const projects = await response.json();
        
        const projectsEl = document.getElementById('stats-projects');
        if (projectsEl) projectsEl.textContent = projects.length;
        
        // Get vulnerabilities count
        const vulnsResponse = await fetch(`${API_BASE}/vulnerabilities`);
        const vulns = await vulnsResponse.json();
        
        const vulnsEl = document.getElementById('stats-vulns');
        if (vulnsEl) vulnsEl.textContent = vulns.length;
        
        // Count reachable
        const reachable = vulns.filter(v => v.is_reachable).length;
        const reachableEl = document.getElementById('stats-reachable');
        if (reachableEl) reachableEl.textContent = reachable;
        
        // Count components (unique from vulns)
        const components = new Set(vulns.map(v => v.component)).size;
        const componentsEl = document.getElementById('stats-components');
        if (componentsEl) componentsEl.textContent = components;
        
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
    
    if (!vulns || vulns.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center">No vulnerabilities found</td></tr>';
        return;
    }
    
    tbody.innerHTML = vulns.map(vuln => `
        <tr data-vuln-id="${vuln.id}">
            <td>${vuln.component || 'N/A'}</td>
            <td>${vuln.version || 'N/A'}</td>
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
                        class="action-btn ${vuln.is_reachable ? 'warning' : 'primary'}"
                        ${vuln.is_reachable ? 'disabled title="Already analyzed as reachable"' : ''}>
                    <i class="fas fa-brain"></i>
                </button>
                <button onclick="checkUpgrade('${vuln.id}')" 
                        class="action-btn success"
                        title="Check for upgrade">
                    <i class="fas fa-arrow-up"></i>
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
    return severityMap[severity?.toUpperCase()] || 'info';
}

async function analyzeReachability(vulnId) {
    const button = event.target.closest('button');
    const originalHTML = button.innerHTML;
    
    button.innerHTML = '<span class="loading"></span>';
    button.disabled = true;
    
    try {
        // Get component info from table row
        const row = document.querySelector(`tr[data-vuln-id="${vulnId}"]`);
        if (!row) return;
        
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
            showNotification(
                `Reachable: ${result.is_reachable ? 'YES' : 'NO'} (${Math.round(result.confidence * 100)}% confidence)`,
                result.is_reachable ? 'warning' : 'success'
            );
            
            // Reload table
            loadVulnerabilities();
        }
        
    } catch (error) {
        console.error('Error analyzing:', error);
        showNotification('Analysis failed: ' + error.message, 'error');
    } finally {
        button.innerHTML = originalHTML;
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
            showNotification(
                `Cannot auto-upgrade: ${result.reason}`,
                'warning'
            );
        }
        
    } catch (error) {
        console.error('Error checking upgrade:', error);
        showNotification('Upgrade check failed: ' + error.message, 'error');
    }
}

function showUpgradeModal(vulnId, upgradeInfo) {
    const modal = document.getElementById('upgrade-modal');
    const details = document.getElementById('upgrade-details');
    
    if (!modal || !details) return;
    
    details.innerHTML = `
        <div class="info-panel">
            <p><strong>Component:</strong> ${upgradeInfo.component}</p>
            <p><strong>Current Version:</strong> ${upgradeInfo.from_version}</p>
            <p><strong>Target Version:</strong> ${upgradeInfo.to_version}</p>
            <p><strong>Confidence:</strong> ${Math.round(upgradeInfo.confidence * 100)}%</p>
            <p class="text-small mt-2" style="color: #666;">
                This will create a pull request with the upgraded dependency.
            </p>
        </div>
    `;
    
    // Store vuln ID for the execute button
    const executeBtn = document.getElementById('execute-upgrade');
    if (executeBtn) {
        executeBtn.dataset.vulnId = vulnId;
        executeBtn.dataset.upgradeInfo = JSON.stringify(upgradeInfo);
    }
    
    // Open modal
    modal.style.display = 'flex';
}

// Execute upgrade
const executeUpgradeBtn = document.getElementById('execute-upgrade');
if (executeUpgradeBtn) {
    executeUpgradeBtn.addEventListener('click', async function() {
        const vulnId = this.dataset.vulnId;
        const upgradeInfo = JSON.parse(this.dataset.upgradeInfo);
        
        this.innerHTML = '<span class="loading"></span>';
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
                showNotification(
                    `PR created successfully! PR #${result.pr_number}`,
                    'success'
                );
                
                // Close modal
                const modal = document.getElementById('upgrade-modal');
                if (modal) modal.style.display = 'none';
            } else {
                showNotification(`Failed: ${result.error}`, 'error');
            }
            
        } catch (error) {
            console.error('Error executing upgrade:', error);
            showNotification('Upgrade failed: ' + error.message, 'error');
        } finally {
            this.innerHTML = '<i class="fas fa-rocket"></i> Create Upgrade PR';
            this.disabled = false;
        }
    });
}

// Simple notification function
function showNotification(message, type) {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 20px;
        border-radius: 4px;
        color: white;
        font-weight: 500;
        z-index: 10000;
        animation: slideIn 0.3s ease;
        background: ${type === 'success' ? '#4caf50' : type === 'warning' ? '#ff9800' : '#f44336'};
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    `;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    // Remove after 3 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Add animation styles
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(style);

// Real-time updates - poll every 30 seconds
setInterval(() => {
    if (document.visibilityState === 'visible') {
        loadDashboardStats();
        const reachableOnly = document.getElementById('show-reachable-only')?.checked || false;
        loadVulnerabilities(reachableOnly);
    }
}, 30000);
