"""UI routes for the dashboard.

Serves the HTML interface for the dashboard using
embedded templates for simplicity.
"""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse


router = APIRouter(tags=["ui"])


# Embedded HTML template for the dashboard
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MASS Dashboard</title>
    <style>
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-tertiary: #334155;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --accent: #3b82f6;
            --success: #22c55e;
            --warning: #f59e0b;
            --error: #ef4444;
            --critical: #dc2626;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
        }

        header {
            background: var(--bg-secondary);
            padding: 1rem 2rem;
            border-bottom: 1px solid var(--bg-tertiary);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .logo {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--accent);
        }

        .logo span { color: var(--text-primary); }

        main {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: var(--bg-secondary);
            padding: 1.5rem;
            border-radius: 0.5rem;
            border: 1px solid var(--bg-tertiary);
        }

        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            color: var(--accent);
        }

        .stat-value.critical { color: var(--critical); }
        .stat-value.success { color: var(--success); }

        .stat-label {
            color: var(--text-secondary);
            font-size: 0.875rem;
            margin-top: 0.5rem;
        }

        .section {
            background: var(--bg-secondary);
            border-radius: 0.5rem;
            border: 1px solid var(--bg-tertiary);
            margin-bottom: 2rem;
        }

        .section-header {
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--bg-tertiary);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .section-title {
            font-size: 1.125rem;
            font-weight: 600;
        }

        .btn {
            background: var(--accent);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 0.375rem;
            cursor: pointer;
            font-size: 0.875rem;
            font-weight: 500;
        }

        .btn:hover { opacity: 0.9; }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th, td {
            padding: 1rem 1.5rem;
            text-align: left;
            border-bottom: 1px solid var(--bg-tertiary);
        }

        th {
            color: var(--text-secondary);
            font-weight: 500;
            font-size: 0.875rem;
            text-transform: uppercase;
        }

        .status {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 500;
        }

        .status.completed { background: rgba(34, 197, 94, 0.2); color: var(--success); }
        .status.running { background: rgba(59, 130, 246, 0.2); color: var(--accent); }
        .status.pending { background: rgba(148, 163, 184, 0.2); color: var(--text-secondary); }
        .status.failed { background: rgba(239, 68, 68, 0.2); color: var(--error); }

        .severity {
            display: inline-block;
            padding: 0.125rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .severity.critical { background: rgba(220, 38, 38, 0.2); color: var(--critical); }
        .severity.high { background: rgba(239, 68, 68, 0.2); color: var(--error); }
        .severity.medium { background: rgba(245, 158, 11, 0.2); color: var(--warning); }
        .severity.low { background: rgba(59, 130, 246, 0.2); color: var(--accent); }
        .severity.info { background: rgba(148, 163, 184, 0.2); color: var(--text-secondary); }

        .modal {
            display: none;
            position: fixed;
            inset: 0;
            background: rgba(0,0,0,0.5);
            z-index: 100;
            align-items: center;
            justify-content: center;
        }

        .modal.active { display: flex; }

        .modal-content {
            background: var(--bg-secondary);
            padding: 2rem;
            border-radius: 0.5rem;
            width: 100%;
            max-width: 500px;
            border: 1px solid var(--bg-tertiary);
        }

        .modal-title {
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
        }

        .form-group {
            margin-bottom: 1rem;
        }

        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            color: var(--text-secondary);
            font-size: 0.875rem;
        }

        .form-group input, .form-group select {
            width: 100%;
            padding: 0.75rem;
            background: var(--bg-tertiary);
            border: 1px solid var(--bg-tertiary);
            border-radius: 0.375rem;
            color: var(--text-primary);
            font-size: 0.875rem;
        }

        .form-actions {
            display: flex;
            gap: 1rem;
            margin-top: 1.5rem;
        }

        .btn-secondary {
            background: var(--bg-tertiary);
        }

        .empty-state {
            padding: 3rem;
            text-align: center;
            color: var(--text-secondary);
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .status.running::before {
            content: '';
            width: 8px;
            height: 8px;
            background: currentColor;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
    </style>
</head>
<body>
    <header>
        <div class="logo">MASS <span>Dashboard</span></div>
        <button class="btn" onclick="showNewScanModal()">New Scan</button>
    </header>

    <main>
        <div class="stats-grid" id="stats">
            <div class="stat-card">
                <div class="stat-value" id="totalScans">-</div>
                <div class="stat-label">Total Scans</div>
            </div>
            <div class="stat-card">
                <div class="stat-value success" id="activeScans">-</div>
                <div class="stat-label">Active Scans</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="totalFindings">-</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-value critical" id="criticalFindings">-</div>
                <div class="stat-label">Critical Findings</div>
            </div>
        </div>

        <div class="section">
            <div class="section-header">
                <h2 class="section-title">Recent Scans</h2>
                <button class="btn" onclick="loadScans()">Refresh</button>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Target</th>
                        <th>Profile</th>
                        <th>Status</th>
                        <th>Findings</th>
                        <th>Duration</th>
                        <th>Started</th>
                    </tr>
                </thead>
                <tbody id="scansTable">
                    <tr><td colspan="6" class="empty-state">Loading scans...</td></tr>
                </tbody>
            </table>
        </div>
    </main>

    <div class="modal" id="newScanModal">
        <div class="modal-content">
            <h3 class="modal-title">New Scan</h3>
            <form onsubmit="startScan(event)">
                <div class="form-group">
                    <label>Target Path</label>
                    <input type="text" id="scanTarget" placeholder="/path/to/deployment" required>
                </div>
                <div class="form-group">
                    <label>Scan Profile</label>
                    <select id="scanProfile">
                        <option value="quick">Quick</option>
                        <option value="standard" selected>Standard</option>
                        <option value="comprehensive">Comprehensive</option>
                    </select>
                </div>
                <div class="form-actions">
                    <button type="button" class="btn btn-secondary" onclick="hideNewScanModal()">Cancel</button>
                    <button type="submit" class="btn">Start Scan</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        const API = '/api';

        async function loadStats() {
            try {
                const res = await fetch(`${API}/stats`);
                const stats = await res.json();
                document.getElementById('totalScans').textContent = stats.total_scans;
                document.getElementById('activeScans').textContent = stats.active_scans;
                document.getElementById('totalFindings').textContent = stats.total_findings;
                document.getElementById('criticalFindings').textContent = stats.critical_findings;
            } catch (e) {
                console.error('Failed to load stats:', e);
            }
        }

        async function loadScans() {
            try {
                const res = await fetch(`${API}/scans?limit=20`);
                const scans = await res.json();
                const tbody = document.getElementById('scansTable');

                if (scans.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No scans yet</td></tr>';
                    return;
                }

                tbody.innerHTML = scans.map(scan => `
                    <tr onclick="viewScan('${scan.scan_id}')" style="cursor:pointer">
                        <td>${scan.target}</td>
                        <td>${scan.profile}</td>
                        <td><span class="status ${scan.status}">${scan.status}</span></td>
                        <td>
                            ${scan.critical_count > 0 ? `<span class="severity critical">${scan.critical_count}</span>` : ''}
                            ${scan.high_count > 0 ? `<span class="severity high">${scan.high_count}</span>` : ''}
                            ${scan.medium_count > 0 ? `<span class="severity medium">${scan.medium_count}</span>` : ''}
                            ${scan.findings_count === 0 ? '-' : ''}
                        </td>
                        <td>${scan.duration_seconds ? scan.duration_seconds.toFixed(1) + 's' : '-'}</td>
                        <td>${new Date(scan.started_at).toLocaleString()}</td>
                    </tr>
                `).join('');
            } catch (e) {
                console.error('Failed to load scans:', e);
            }
        }

        function showNewScanModal() {
            document.getElementById('newScanModal').classList.add('active');
        }

        function hideNewScanModal() {
            document.getElementById('newScanModal').classList.remove('active');
        }

        async function startScan(e) {
            e.preventDefault();
            const target = document.getElementById('scanTarget').value;
            const profile = document.getElementById('scanProfile').value;

            try {
                const res = await fetch(`${API}/scans`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target, profile})
                });

                if (!res.ok) {
                    const err = await res.json();
                    alert(err.detail || 'Failed to start scan');
                    return;
                }

                hideNewScanModal();
                loadScans();
                loadStats();
            } catch (e) {
                alert('Failed to start scan: ' + e.message);
            }
        }

        function viewScan(scanId) {
            // TODO: Navigate to scan detail view
            console.log('View scan:', scanId);
        }

        // Initial load
        loadStats();
        loadScans();

        // Refresh every 5 seconds
        setInterval(() => {
            loadStats();
            loadScans();
        }, 5000);
    </script>
</body>
</html>
"""


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    """Serve the dashboard home page."""
    return HTMLResponse(content=DASHBOARD_HTML)


@router.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_detail(request: Request, scan_id: str) -> HTMLResponse:
    """Serve the scan detail page."""
    # For now, redirect to main dashboard
    # In a full implementation, this would show scan details
    return HTMLResponse(content=DASHBOARD_HTML)
