// Main application JavaScript

// Use relative API URL for both local and production
const API_BASE = '/api';

// Store upgrade info globally
let currentUpgradeInfo = null;
let currentVulnId = null;

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
    
    // Execute upgrade button
    const executeBtn = document.getElementById('execute-upgrade');
    if (executeBtn) {
        executeBtn.addEventListener('click', executeUpgrade);
    }
}

async function handleAddProject(e) {
    e.preventDefault();
    
    const nameInput = document.getElementById('project-name');
    const repoUrlInput = document.getElementById('repo-url');
    
    if (!nameInput || !repoUrlInput) return;
    
    const name = nameInput.value;
    const repoUrl = repoUrlInput.value;
    
    try {
        const response = await fetch(API_BASE + '/projects', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ name: name, repo_url: repoUrl })
        });
        
        if (response.ok) {
            // Reset form
            nameInput.value = '';
            repoUrlInput.value = '';
            
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
        // Get projects count
        const projectsResponse = await fetch(API_BASE + '/projects');
        const projects = projectsResponse.ok ? await projectsResponse.json() : [];
        
        const projectsEl = document.getElementById('stats-projects');
        if (projectsEl) projectsEl.textContent = projects.length;
        
        // Get vulnerabilities count
        const vulnsResponse = await fetch(API_BASE + '/vulnerabilities');
        const vulns = vulnsResponse.ok ? await vulnsResponse.json() : [];
        
        const vulnsEl = document.getElementById('stats-vulns');
        if (vulnsEl) vulnsEl.textContent = vulns.length;
        
        // Count reachable
        const reachable = vulns.filter(function(v) { return v.is_reachable; }).length;
        const reachableEl = document.getElementById('stats-reachable');
        if (reachableEl) reachableEl.textContent = reachable;
        
        // Count components (unique from vulns)
        const componentSet = new Set();
        vulns.forEach(function(v) { 
            if (v.component) componentSet.add(v.component); 
        });
        const componentsEl = document.getElementById('stats-components');
        if (componentsEl) componentsEl.textContent = componentSet.size;
        
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

async function loadVulnerabilities(reachableOnly) {
    reachableOnly = reachableOnly || false;
    
    try {
        var url = API_BASE + '/vulnerabilities';
        if (reachableOnly) {
            url += '?reachable_only=true';
        }
        
        const response = await fetch(url);
        const vulns = response.ok ? await response.json() : [];
        
        renderVulnerabilitiesTable(vulns);
    } catch (error) {
        console.error('Error loading vulnerabilities:', error);
        var tbody = document.getElementById('vulns-tbody');
        if (tbody) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center">Error loading vulnerabilities</td></tr>';
        }
    }
}

function escapeHtml(text) {
    if (!text) return '';
    var div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

function renderVulnerabilitiesTable(vulns) {
    var tbody = document.getElementById('vulns-tbody');
    if (!tbody) return;
    
    if (!vulns || vulns.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center">No vulnerabilities found</td></tr>';
        return;
    }
    
    var html = '';
    for (var i = 0; i < vulns.length; i++) {
        var vuln = vulns[i];
        var vulnId = vuln.id ? encodeURIComponent(vuln.id) : '';
        var component = escapeHtml(vuln.component);
        var version = escapeHtml(vuln.version);
        var severity = vuln.severity || 'UNKNOWN';
        var cvss = vuln.cvss || 'N/A';
        var isReachable = vuln.is_reachable ? 'YES' : 'NO';
        var severityClass = getSeverityClass(severity);
        var reachableClass = vuln.is_reachable ? 'danger' : 'success';
        
        html += '<tr data-vuln-id="' + vulnId + '" data-component="' + component + '" data-version="' + version + '">';
        html += '<td>' + component + '</td>';
        html += '<td>' + version + '</td>';
        html += '<td>' + escapeHtml(vuln.id) + '</td>';
        html += '<td><span class="badge ' + severityClass + '">' + severity + '</span></td>';
        html += '<td>' + cvss + '</td>';
        html += '<td><span class="badge ' + reachableClass + '">' + isReachable + '</span></td>';
        html += '<td>';
        
        if (!vuln.is_reachable) {
            html += '<button onclick="analyzeReachability(\'' + vulnId + '\')" class="action-btn primary" title="Analyze"><i class="fas fa-brain"></i></button>';
        } else {
            html += '<button class="action-btn warning" disabled title="Already analyzed"><i class="fas fa-brain"></i></button>';
        }
        
        html += '<button onclick="checkUpgrade(\'' + vulnId + '\')" class="action-btn success" title="Check for upgrade"><i class="fas fa-arrow-up"></i></button>';
        html += '</td></tr>';
    }
    
    tbody.innerHTML = html;
}

function getSeverityClass(severity) {
    if (!severity) return 'info';
    var upper = severity.toUpperCase();
    if (upper === 'CRITICAL' || upper === 'HIGH') return 'danger';
    if (upper === 'MEDIUM') return 'warning';
    if (upper === 'LOW') return 'success';
    return 'info';
}

function analyzeReachability(vulnId) {
    var button = event.target.closest('button');
    if (!button) return;
    
    var originalHTML = button.innerHTML;
    button.innerHTML = '<span class="loading"></span>';
    button.disabled = true;
    
    // Get component info from table row
    var row = document.querySelector('tr[data-vuln-id="' + vulnId + '"]');
    if (!row) {
        button.innerHTML = originalHTML;
        button.disabled = false;
        return;
    }
    
    var component = row.getAttribute('data-component');
    var version = row.getAttribute('data-version');
    
    fetch(API_BASE + '/reachability/analyze', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            vuln_id: decodeURIComponent(vulnId),
            component: component,
            version: version
        })
    })
    .then(function(response) { return response.json(); })
    .then(function(result) {
        if (result.is_reachable !== null && result.is_reachable !== undefined) {
            var confidence = result.confidence ? Math.round(result.confidence * 100) : 0;
            showNotification(
                'Reachable: ' + (result.is_reachable ? 'YES' : 'NO') + ' (' + confidence + '% confidence)',
                result.is_reachable ? 'warning' : 'success'
            );
            
            // Reload table
            loadVulnerabilities();
        }
    })
    .catch(function(error) {
        console.error('Error analyzing:', error);
        showNotification('Analysis failed: ' + error.message, 'error');
    })
    .finally(function() {
        button.innerHTML = originalHTML;
        button.disabled = false;
    });
}

function checkUpgrade(vulnId) {
    fetch(API_BASE + '/upgrade/check/' + encodeURIComponent(vulnId), {
        method: 'POST'
    })
    .then(function(response) { return response.json(); })
    .then(function(result) {
        if (result.feasible) {
            showUpgradeModal(decodeURIComponent(vulnId), result);
        } else {
            showNotification(
                'Cannot auto-upgrade: ' + (result.reason || 'Unknown reason'),
                'warning'
            );
        }
    })
    .catch(function(error) {
        console.error('Error checking upgrade:', error);
        showNotification('Upgrade check failed: ' + error.message, 'error');
    });
}

function showUpgradeModal(vulnId, upgradeInfo) {
    var modal = document.getElementById('upgrade-modal');
    var details = document.getElementById('upgrade-details');
    
    if (!modal || !details) return;
    
    // Store globally
    currentVulnId = vulnId;
    currentUpgradeInfo = upgradeInfo;
    
    details.innerHTML = '<div class="info-panel">' +
        '<p><strong>Component:</strong> ' + escapeHtml(upgradeInfo.component) + '</p>' +
        '<p><strong>Current Version:</strong> ' + escapeHtml(upgradeInfo.from_version) + '</p>' +
        '<p><strong>Target Version:</strong> ' + escapeHtml(upgradeInfo.to_version) + '</p>' +
        '<p><strong>Confidence:</strong> ' + Math.round((upgradeInfo.confidence || 0) * 100) + '%</p>' +
        '<p class="text-small mt-2" style="color: #666;">This will create a pull request with the upgraded dependency.</p>' +
        '</div>';
    
    // Open modal
    modal.style.display = 'flex';
}

function executeUpgrade() {
    var executeBtn = document.getElementById('execute-upgrade');
    if (!currentVulnId || !currentUpgradeInfo) {
        showNotification('No upgrade information available', 'error');
        return;
    }
    
    var originalHTML = executeBtn.innerHTML;
    executeBtn.innerHTML = '<span class="loading"></span>';
    executeBtn.disabled = true;
    
    fetch(API_BASE + '/upgrade/execute', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            vuln_id: currentVulnId,
            component: currentUpgradeInfo.component,
            from_version: currentUpgradeInfo.from_version,
            to_version: currentUpgradeInfo.to_version
        })
    })
    .then(function(response) { return response.json(); })
    .then(function(result) {
        if (result.success) {
            showNotification('PR created successfully! PR #' + result.pr_number, 'success');
            
            var modal = document.getElementById('upgrade-modal');
            if (modal) modal.style.display = 'none';
            
            currentVulnId = null;
            currentUpgradeInfo = null;
        } else {
            showNotification('Failed: ' + (result.error || 'Unknown error'), 'error');
        }
    })
    .catch(function(error) {
        console.error('Error executing upgrade:', error);
        showNotification('Upgrade failed: ' + error.message, 'error');
    })
    .finally(function() {
        executeBtn.innerHTML = originalHTML;
        executeBtn.disabled = false;
    });
}

// Simple notification function
function showNotification(message, type) {
    var notification = document.createElement('div');
    var bgColor = '#4caf50';
    if (type === 'warning') bgColor = '#ff9800';
    if (type === 'error') bgColor = '#f44336';
    
    notification.style.cssText = 
        'position: fixed; top: 20px; right: 20px; padding: 15px 20px; border-radius: 4px; ' +
        'color: white; font-weight: 500; z-index: 10000; animation: slideIn 0.3s ease; ' +
        'background: ' + bgColor + '; box-shadow: 0 4px 12px rgba(0,0,0,0.15);';
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    setTimeout(function() {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(function() { 
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }, 3000);
}

// Add animation styles
var style = document.createElement('style');
style.textContent = 
    '@keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }' +
    '@keyframes slideOut { from { transform: translateX(0); opacity: 1; } to { transform: translateX(100%); opacity: 0; } }';
document.head.appendChild(style);

// Real-time updates - poll every 30 seconds
setInterval(function() {
    if (document.visibilityState === 'visible') {
        loadDashboardStats();
        var reachableOnly = false;
        var toggle = document.getElementById('show-reachable-only');
        if (toggle) reachableOnly = toggle.checked;
        loadVulnerabilities(reachableOnly);
    }
}, 30000);
