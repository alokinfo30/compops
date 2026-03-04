// Main application JavaScript

// Use relative API URL for both local and production
var API_BASE = '/api';

// Store upgrade info globally
var currentUpgradeInfo = null;
var currentVulnId = null;

// Safe storage helper (handles Tracking Prevention)
var Storage = {
    get: function(key) {
        try {
            return localStorage.getItem(key);
        } catch (e) {
            return null;
        }
    },
    set: function(key, value) {
        try {
            localStorage.setItem(key, value);
        } catch (e) {
            // Storage blocked - ignore
        }
    }
};

// Initialize on page load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
} else {
    initApp();
}

function initApp() {
    loadDashboardStats();
    loadVulnerabilities();
    setupEventListeners();
}

function setupEventListeners() {
    // Add project form
    var projectForm = document.getElementById('add-project-form');
    if (projectForm) {
        projectForm.addEventListener('submit', handleAddProject);
    }
    
    // Show reachable only toggle
    var reachableToggle = document.getElementById('show-reachable-only');
    if (reachableToggle) {
        reachableToggle.addEventListener('change', function() {
            loadVulnerabilities(this.checked);
        });
    }
    
    // Execute upgrade button
    var executeBtn = document.getElementById('execute-upgrade');
    if (executeBtn) {
        executeBtn.addEventListener('click', executeUpgrade);
    }
}

function handleAddProject(e) {
    e.preventDefault();
    
    var nameInput = document.getElementById('project-name');
    var repoUrlInput = document.getElementById('repo-url');
    
    if (!nameInput || !repoUrlInput) return;
    
    var name = nameInput.value;
    var repoUrl = repoUrlInput.value;
    
    fetch(API_BASE + '/projects', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ name: name, repo_url: repoUrl })
    })
    .then(function(response) {
        if (response.ok) {
            nameInput.value = '';
            repoUrlInput.value = '';
            loadDashboardStats();
            loadVulnerabilities();
            showNotification('Project added successfully', 'success');
        } else {
            showNotification('Failed to add project', 'error');
        }
    })
    .catch(function(error) {
        console.error('Error adding project:', error);
        showNotification('Failed to add project: ' + error.message, 'error');
    });
}

function loadDashboardStats() {
    // Get projects count
    fetch(API_BASE + '/projects')
    .then(function(response) { return response.ok ? response.json() : []; })
    .then(function(projects) {
        var projectsEl = document.getElementById('stats-projects');
        if (projectsEl) projectsEl.textContent = projects.length;
        
        return fetch(API_BASE + '/vulnerabilities');
    })
    .then(function(response) { return response.ok ? response.json() : []; })
    .then(function(vulns) {
        var vulnsEl = document.getElementById('stats-vulns');
        if (vulnsEl) vulnsEl.textContent = vulns.length;
        
        var reachable = 0;
        for (var i = 0; i < vulns.length; i++) {
            if (vulns[i].is_reachable) reachable++;
        }
        var reachableEl = document.getElementById('stats-reachable');
        if (reachableEl) reachableEl.textContent = reachable;
        
        var componentSet = {};
        for (var j = 0; j < vulns.length; j++) {
            if (vulns[j].component) componentSet[vulns[j].component] = true;
        }
        var componentsEl = document.getElementById('stats-components');
        if (componentsEl) componentsEl.textContent = Object.keys(componentSet).length;
    })
    .catch(function(error) {
        console.error('Error loading stats:', error);
    });
}

function loadVulnerabilities(reachableOnly) {
    reachableOnly = reachableOnly || false;
    
    var url = API_BASE + '/vulnerabilities';
    if (reachableOnly) {
        url += '?reachable_only=true';
    }
    
    fetch(url)
    .then(function(response) { return response.ok ? response.json() : []; })
    .then(function(vulns) {
        renderVulnerabilitiesTable(vulns);
    })
    .catch(function(error) {
        console.error('Error loading vulnerabilities:', error);
        var tbody = document.getElementById('vulns-tbody');
        if (tbody) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center">Error loading vulnerabilities</td></tr>';
        }
    });
}

function escapeHtml(text) {
    if (!text) return '';
    var map = {
        '&': '&amp;',
        '<': '<',
        '>': '>',
        '"': '"',
        "'": '&#039;'
    };
    return String(text).replace(/[&<>"']/g, function(m) { return map[m]; });
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
        var displayId = escapeHtml(vuln.vuln_id || vuln.id);
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
        html += '<td>' + displayId + '</td>';
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
    var btn = event.target.closest('button');
    if (!btn) return;
    
    var originalHTML = btn.innerHTML;
    btn.innerHTML = '<span class="loading"></span>';
    btn.disabled = true;
    
    var row = document.querySelector('tr[data-vuln-id="' + vulnId + '"]');
    if (!row) {
        btn.innerHTML = originalHTML;
        btn.disabled = false;
        return;
    }
    
    var component = row.getAttribute('data-component');
    var version = row.getAttribute('data-version');
    
    fetch(API_BASE + '/reachability/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
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
            loadVulnerabilities();
        }
    })
    .catch(function(error) {
        console.error('Error analyzing:', error);
        showNotification('Analysis failed: ' + error.message, 'error');
    })
    .finally(function() {
        btn.innerHTML = originalHTML;
        btn.disabled = false;
    });
}

function checkUpgrade(vulnId) {
    // The vulnId is already URI-encoded from the onclick handler in renderVulnerabilitiesTable
    fetch(API_BASE + '/upgrade/check/' + vulnId, {
        method: 'GET'
    })
    .then(function(response) {
        if (!response.ok) {
            // If we get a non-JSON error response (like a 404 HTML page),
            // this will prevent a JSON parsing error and provide a better error message.
            return response.text().then(function(text) {
                throw new Error('Server returned ' + response.status + '. Response: ' + text.substring(0, 100));
            });
        }
        return response.json();
    })
    .then(function(result) {
        if (result.feasible) {
            showUpgradeModal(decodeURIComponent(vulnId), result);
        } else {
            showNotification('Cannot auto-upgrade: ' + (result.reason || 'Unknown reason'), 'warning');
        }
    })
    .catch(function(error) {
        console.error('Error checking upgrade:', error);
        showNotification('Upgrade check failed: ' + error.message, 'error');
    });
}

function showUpgradeModal(vulnId, upgradeInfo) {
    var modalEl = document.getElementById('upgrade-modal');
    var details = document.getElementById('upgrade-details');
    
    if (!modalEl || !details) return;
    
    currentVulnId = vulnId;
    currentUpgradeInfo = upgradeInfo;
    
    details.innerHTML = '<div class="info-panel">' +
        '<p><strong>Component:</strong> ' + escapeHtml(upgradeInfo.component) + '</p>' +
        '<p><strong>Current Version:</strong> ' + escapeHtml(upgradeInfo.from_version) + '</p>' +
        '<p><strong>Target Version:</strong> ' + escapeHtml(upgradeInfo.to_version) + '</p>' +
        '<p><strong>Confidence:</strong> ' + Math.round((upgradeInfo.confidence || 0) * 100) + '%</p>' +
        '<p class="text-small mt-2" style="color: #666;">This will create a pull request with the upgraded dependency.</p>' +
        '</div>';
    
    var modal = new bootstrap.Modal(modalEl);
    modal.show();
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
        headers: { 'Content-Type': 'application/json' },
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
            var modalEl = document.getElementById('upgrade-modal');
            var modal = bootstrap.Modal.getInstance(modalEl);
            if (modal) modal.hide();
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

function showNotification(message, type) {
    var bgColor = '#4caf50';
    if (type === 'warning') bgColor = '#ff9800';
    if (type === 'error') bgColor = '#f44336';
    
    var notification = document.createElement('div');
    notification.style.cssText = 
        'position: fixed; top: 20px; right: 20px; padding: 15px 20px; border-radius: 4px; ' +
        'color: white; font-weight: 500; z-index: 10000; animation: slideIn 0.3s ease; ' +
        'background: ' + bgColor + '; box-shadow: 0 4px 12px rgba(0,0,0,0.15); max-width: 300px;';
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    setTimeout(function() {
        notification.style.opacity = '0';
        notification.style.transition = 'opacity 0.3s ease';
        setTimeout(function() { 
            if (notification.parentNode) notification.parentNode.removeChild(notification);
        }, 300);
    }, 3000);
}

// Add animation styles
var style = document.createElement('style');
style.textContent = 
    '@keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }';
document.head.appendChild(style);

// Real-time updates - poll every 30 seconds
setInterval(function() {
    if (document.visibilityState === 'visible') {
        loadDashboardStats();
        var toggle = document.getElementById('show-reachable-only');
        loadVulnerabilities(toggle ? toggle.checked : false);
    }
}, 30000);

// Vulnerability Scanning
function scanProject(projectId) {
    fetch(API_BASE + '/scan/vulnerabilities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ project_id: projectId })
    })
    .then(function(response) { return response.json(); })
    .then(function(result) {
        if (result.success) {
            showNotification('Scanned ' + result.dependencies_scanned + ' dependencies, found ' + result.vulnerabilities_found + ' vulnerabilities', 'success');
            loadDashboardStats();
            loadVulnerabilities();
        } else {
            showNotification('Scan failed: ' + (result.error || 'Unknown error'), 'error');
        }
    })
    .catch(function(error) {
        console.error('Error scanning:', error);
        showNotification('Scan failed: ' + error.message, 'error');
    });
}

// SBOM Generation
function generateSBOM(projectId, format) {
    format = format || 'cyclonedx';
    
    fetch(API_BASE + '/sbom/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ project_id: projectId, format: format })
    })
    .then(function(response) { return response.json(); })
    .then(function(result) {
        if (result.status === 'success') {
            showNotification('SBOM generated with ' + result.components + ' components', 'success');
            if (typeof loadSBOMGraph === 'function') {
                loadSBOMGraph(projectId);
            }
        } else {
            showNotification('SBOM generation failed: ' + (result.error || 'Unknown error'), 'error');
        }
    })
    .catch(function(error) {
        console.error('Error generating SBOM:', error);
        showNotification('SBOM generation failed: ' + error.message, 'error');
    });
}

// SBOM Export
function exportSBOM(projectId, format) {
    format = format || 'cyclonedx';
    
    fetch(API_BASE + '/sbom/export/' + projectId + '?format=' + format)
    .then(function(response) { return response.json(); })
    .then(function(sbom) {
        if (sbom && !sbom.success) {
            var blob = new Blob([JSON.stringify(sbom, null, 2)], { type: 'application/json' });
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = 'sbom-' + projectId + '.' + (format === 'cyclonedx' ? 'json' : format);
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            showNotification('SBOM exported successfully', 'success');
        } else {
            showNotification('No SBOM found. Generate one first.', 'warning');
        }
    })
    .catch(function(error) {
        console.error('Error exporting SBOM:', error);
        showNotification('Export failed: ' + error.message, 'error');
    });
}

// Expose functions to global scope for inline event handlers
window.generateSBOM = generateSBOM;
window.exportSBOM = exportSBOM;
window.scanProject = scanProject;
window.analyzeReachability = analyzeReachability;
window.checkUpgrade = checkUpgrade;
