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
            cursor: pointer;
        }

        .logo span { color: var(--text-primary); }

        .header-actions { display: flex; gap: 0.5rem; align-items: center; }

        .breadcrumb {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.875rem;
            color: var(--text-secondary);
            margin-bottom: 1rem;
        }

        .breadcrumb a {
            color: var(--accent);
            text-decoration: none;
            cursor: pointer;
        }

        .breadcrumb a:hover { text-decoration: underline; }

        .breadcrumb .separator { color: var(--bg-tertiary); }

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
            flex-wrap: wrap;
            gap: 0.75rem;
        }

        .section-title {
            font-size: 1.125rem;
            font-weight: 600;
        }

        .filters {
            display: flex;
            gap: 0.5rem;
            align-items: center;
        }

        .filters select {
            padding: 0.375rem 0.75rem;
            background: var(--bg-tertiary);
            border: 1px solid var(--bg-tertiary);
            border-radius: 0.375rem;
            color: var(--text-primary);
            font-size: 0.8rem;
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

        .btn-sm {
            padding: 0.25rem 0.75rem;
            font-size: 0.8rem;
        }

        .btn-ghost {
            background: transparent;
            color: var(--text-secondary);
            border: 1px solid var(--bg-tertiary);
        }

        .btn-ghost:hover { color: var(--text-primary); border-color: var(--text-secondary); }

        .export-dropdown a:hover { background: var(--bg-tertiary); }

        .export-toast {
            position: fixed; bottom: 2rem; right: 2rem; padding: 0.75rem 1.25rem;
            border-radius: 0.5rem; font-size: 0.85rem; z-index: 1000;
            animation: fadeInUp 0.3s ease;
        }
        .export-toast.success { background: var(--success); color: #fff; }
        .export-toast.error { background: var(--error); color: #fff; }
        .export-toast.loading { background: var(--accent); color: #fff; }
        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th, td {
            padding: 0.875rem 1.5rem;
            text-align: left;
            border-bottom: 1px solid var(--bg-tertiary);
        }

        th {
            color: var(--text-secondary);
            font-weight: 500;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        tr.clickable { cursor: pointer; }
        tr.clickable:hover { background: rgba(59, 130, 246, 0.05); }

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
        .status.open { background: rgba(59, 130, 246, 0.2); color: var(--accent); }
        .status.confirmed { background: rgba(239, 68, 68, 0.2); color: var(--error); }
        .status.false_positive { background: rgba(148, 163, 184, 0.2); color: var(--text-secondary); }
        .status.fixed { background: rgba(34, 197, 94, 0.2); color: var(--success); }
        .status.accepted { background: rgba(245, 158, 11, 0.2); color: var(--warning); }

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

        .category-badge {
            display: inline-block;
            padding: 0.125rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.7rem;
            background: rgba(148, 163, 184, 0.15);
            color: var(--text-secondary);
        }

        /* Modal styles */
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

        /* Slide-out detail panel */
        .detail-panel {
            position: fixed;
            top: 0;
            right: -600px;
            width: 600px;
            max-width: 90vw;
            height: 100vh;
            background: var(--bg-secondary);
            border-left: 1px solid var(--bg-tertiary);
            z-index: 200;
            transition: right 0.3s ease;
            overflow-y: auto;
            box-shadow: -4px 0 20px rgba(0,0,0,0.3);
        }

        .detail-panel.open { right: 0; }

        .detail-panel-overlay {
            display: none;
            position: fixed;
            inset: 0;
            background: rgba(0,0,0,0.3);
            z-index: 199;
        }

        .detail-panel-overlay.open { display: block; }

        .detail-header {
            position: sticky;
            top: 0;
            background: var(--bg-secondary);
            padding: 1.5rem;
            border-bottom: 1px solid var(--bg-tertiary);
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            z-index: 1;
        }

        .detail-close {
            background: none;
            border: none;
            color: var(--text-secondary);
            font-size: 1.5rem;
            cursor: pointer;
            padding: 0.25rem;
            line-height: 1;
        }

        .detail-close:hover { color: var(--text-primary); }

        .detail-body {
            padding: 1.5rem;
        }

        .detail-section {
            margin-bottom: 1.5rem;
        }

        .detail-section-title {
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
            margin-bottom: 0.75rem;
            font-weight: 600;
        }

        .detail-content {
            background: var(--bg-primary);
            padding: 1rem;
            border-radius: 0.375rem;
            font-size: 0.875rem;
            line-height: 1.6;
            white-space: pre-wrap;
            word-break: break-word;
        }

        .detail-meta {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 0.75rem;
        }

        .detail-meta-item {
            background: var(--bg-primary);
            padding: 0.75rem;
            border-radius: 0.375rem;
        }

        .detail-meta-label {
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
            margin-bottom: 0.25rem;
        }

        .detail-meta-value {
            font-size: 0.875rem;
            font-weight: 500;
        }

        .sortable {
            cursor: pointer;
            user-select: none;
        }
        .sortable:hover {
            color: var(--accent);
        }
        .sort-indicator::after {
            content: '';
            margin-left: 0.25rem;
        }
        .sort-indicator.asc::after {
            content: '\\25B2';
        }
        .sort-indicator.desc::after {
            content: '\\25BC';
        }

        .filters {
            display: flex;
            gap: 0.5rem;
            align-items: center;
            flex-wrap: wrap;
        }
        .filters select {
            background: var(--bg-primary);
            border: 1px solid var(--bg-tertiary);
            color: var(--text-primary);
            padding: 0.35rem 0.5rem;
            border-radius: 0.375rem;
            font-size: 0.85rem;
        }

        .evidence-item {
            background: var(--bg-primary);
            border-radius: 0.375rem;
            margin-bottom: 0.75rem;
            overflow: hidden;
        }

        .evidence-item-header {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 0.75rem;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .evidence-item-header.prompt {
            background: rgba(239, 68, 68, 0.15);
            color: var(--error);
        }

        .evidence-item-header.response {
            background: rgba(59, 130, 246, 0.15);
            color: var(--accent);
        }

        .evidence-item-header.detection {
            background: rgba(245, 158, 11, 0.15);
            color: var(--warning);
        }

        .evidence-item-header.code,
        .evidence-item-header.matched_content,
        .evidence-item-header.pattern_match,
        .evidence-item-header.secret_match {
            background: rgba(168, 85, 247, 0.15);
            color: #a855f7;
        }

        .evidence-item-header.code_context {
            background: rgba(59, 130, 246, 0.15);
            color: var(--accent);
        }

        .evidence-item-header.config,
        .evidence-item-header.file_analysis,
        .evidence-item-header.workflow_analysis {
            background: rgba(34, 197, 94, 0.15);
            color: var(--success);
        }

        .confidence-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
            padding: 0.2rem 0.6rem;
            border-radius: 0.25rem;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }

        .confidence-badge.predicted {
            background: rgba(148, 163, 184, 0.15);
            color: var(--text-secondary);
        }

        .confidence-badge.static_match {
            background: rgba(245, 158, 11, 0.15);
            color: var(--warning);
        }

        .confidence-badge.heuristic {
            background: rgba(59, 130, 246, 0.15);
            color: var(--accent);
        }

        .confidence-badge.confirmed {
            background: rgba(239, 68, 68, 0.15);
            color: var(--error);
        }

        .evidence-item-body {
            padding: 0.75rem;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.8rem;
            line-height: 1.5;
            white-space: pre-wrap;
            word-break: break-word;
            max-height: 300px;
            overflow-y: auto;
        }

        .evidence-item-meta {
            padding: 0.4rem 0.75rem;
            font-size: 0.7rem;
            color: var(--text-secondary);
            border-top: 1px solid rgba(255,255,255,0.05);
        }

        .compliance-badges {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
        }

        .compliance-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
            padding: 0.25rem 0.75rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            font-weight: 500;
            background: rgba(59, 130, 246, 0.15);
            color: var(--accent);
        }

        .compliance-badge.cwe { background: rgba(239, 68, 68, 0.15); color: var(--error); }
        .compliance-badge.owasp { background: rgba(245, 158, 11, 0.15); color: var(--warning); }
        .compliance-badge.mitre { background: rgba(168, 85, 247, 0.15); color: #a855f7; }

        /* Remediation steps */
        .remediation-steps {
            counter-reset: step;
            list-style: none;
            padding: 0;
            margin: 0;
        }

        .remediation-steps li {
            counter-increment: step;
            display: flex;
            align-items: flex-start;
            gap: 0.75rem;
            padding: 0.6rem 0;
            font-size: 0.85rem;
            line-height: 1.5;
            border-bottom: 1px solid rgba(255,255,255,0.04);
        }

        .remediation-steps li:last-child { border-bottom: none; }

        .remediation-steps li::before {
            content: counter(step);
            flex-shrink: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            width: 1.5rem;
            height: 1.5rem;
            border-radius: 50%;
            background: rgba(16, 185, 129, 0.15);
            color: var(--success);
            font-size: 0.7rem;
            font-weight: 700;
        }

        /* Effort badge */
        .effort-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
            padding: 0.2rem 0.6rem;
            border-radius: 0.25rem;
            font-size: 0.7rem;
            font-weight: 500;
            background: rgba(59, 130, 246, 0.15);
            color: var(--accent);
            margin-left: 0.5rem;
        }

        /* Guardrail tabs */
        .guardrail-tabs {
            display: flex;
            gap: 0;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            margin-bottom: 0;
        }

        .guardrail-tab {
            padding: 0.5rem 1rem;
            font-size: 0.75rem;
            font-weight: 500;
            color: var(--text-secondary);
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.2s;
            background: none;
            border-top: none;
            border-left: none;
            border-right: none;
        }

        .guardrail-tab:hover {
            color: var(--text-primary);
            background: rgba(255,255,255,0.03);
        }

        .guardrail-tab.active {
            color: var(--accent);
            border-bottom-color: var(--accent);
        }

        .guardrail-panel {
            display: none;
        }

        .guardrail-panel.active {
            display: block;
        }

        .guardrail-code {
            background: var(--bg-primary);
            padding: 1rem;
            border-radius: 0 0 0.375rem 0.375rem;
            font-family: 'SF Mono', 'Fira Code', monospace;
            font-size: 0.78rem;
            line-height: 1.6;
            white-space: pre-wrap;
            word-break: break-word;
            overflow-x: auto;
            max-height: 400px;
            overflow-y: auto;
            color: var(--text-primary);
        }

        .guardrail-title {
            font-size: 0.8rem;
            font-weight: 500;
            color: var(--text-primary);
            padding: 0.5rem 1rem;
            background: rgba(255,255,255,0.02);
        }

        /* Reference links */
        .reference-links {
            display: flex;
            flex-direction: column;
            gap: 0.4rem;
        }

        .reference-links a {
            color: var(--accent);
            text-decoration: none;
            font-size: 0.85rem;
            word-break: break-all;
        }

        .reference-links a:hover {
            text-decoration: underline;
        }

        /* Scan detail header */
        .scan-header {
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
        }

        .scan-header h2 {
            font-size: 1.25rem;
            font-weight: 600;
        }

        .scan-meta-bar {
            display: flex;
            gap: 1.5rem;
            flex-wrap: wrap;
            margin-bottom: 1.5rem;
            font-size: 0.875rem;
            color: var(--text-secondary);
        }

        .scan-meta-bar span { display: flex; align-items: center; gap: 0.375rem; }

        .findings-summary-bar {
            display: flex;
            gap: 0.75rem;
            flex-wrap: wrap;
            margin-bottom: 1.5rem;
        }

        .findings-count-chip {
            display: inline-flex;
            align-items: center;
            gap: 0.375rem;
            padding: 0.375rem 0.75rem;
            border-radius: 0.375rem;
            font-size: 0.8rem;
            font-weight: 600;
            background: var(--bg-secondary);
            border: 1px solid var(--bg-tertiary);
        }

        .findings-count-chip .dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }

        .findings-count-chip .dot.critical { background: var(--critical); }
        .findings-count-chip .dot.high { background: var(--error); }
        .findings-count-chip .dot.medium { background: var(--warning); }
        .findings-count-chip .dot.low { background: var(--accent); }
        .findings-count-chip .dot.info { background: var(--text-secondary); }

        /* View management */
        .view { display: none; }
        .view.active { display: block; }

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

        .scan-progress-bar {
            background: var(--bg-tertiary);
            border-radius: 4px;
            height: 8px;
            margin: 0.5rem 0;
            overflow: hidden;
            display: none;
        }
        .scan-progress-bar.active { display: block; }
        .scan-progress-bar .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--accent), #60a5fa);
            border-radius: 4px;
            transition: width 0.5s ease;
            width: 0%;
        }
        .scan-progress-text {
            font-size: 0.75rem;
            color: var(--text-secondary);
            display: none;
        }
        .scan-progress-text.active { display: block; }

        .loading-spinner {
            display: inline-block;
            width: 16px;
            height: 16px;
            border: 2px solid var(--bg-tertiary);
            border-top-color: var(--accent);
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        /* ---- Topology Graph ---- */
        .topo-container {
            background: var(--bg-secondary);
            border: 1px solid var(--bg-tertiary);
            border-radius: 0.5rem;
            position: relative;
            overflow: hidden;
            min-height: 500px;
        }

        .topo-toolbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--bg-tertiary);
            flex-wrap: wrap;
            gap: 0.5rem;
        }

        .topo-toolbar-group {
            display: flex;
            gap: 0.5rem;
            align-items: center;
        }

        .topo-env-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.375rem;
            padding: 0.25rem 0.75rem;
            border-radius: 0.375rem;
            font-size: 0.8rem;
            font-weight: 600;
            background: rgba(59, 130, 246, 0.15);
            color: var(--accent);
        }

        .topo-svg-wrap {
            width: 100%;
            height: 500px;
            cursor: grab;
        }

        .topo-svg-wrap:active { cursor: grabbing; }

        .topo-svg-wrap svg { width: 100%; height: 100%; }

        /* SVG node styles */
        .topo-node rect {
            rx: 8;
            ry: 8;
            stroke-width: 2;
            cursor: pointer;
            transition: filter 0.2s;
        }

        .topo-node:hover rect { filter: brightness(1.2); }

        .topo-node text {
            fill: #fff;
            font-family: 'Segoe UI', system-ui, sans-serif;
            font-size: 12px;
            text-anchor: middle;
            pointer-events: none;
        }

        .topo-node .node-type-label {
            fill: rgba(255,255,255,0.6);
            font-size: 10px;
        }

        .topo-edge path {
            fill: none;
            stroke-width: 1.5;
            stroke: var(--bg-tertiary);
        }

        .topo-edge text {
            fill: var(--text-secondary);
            font-size: 10px;
            font-family: 'Segoe UI', system-ui, sans-serif;
        }

        /* Node side panel */
        .topo-node-panel {
            position: absolute;
            top: 0;
            right: 0;
            width: 320px;
            height: 100%;
            background: var(--bg-primary);
            border-left: 1px solid var(--bg-tertiary);
            padding: 1.25rem;
            overflow-y: auto;
            transform: translateX(100%);
            transition: transform 0.25s ease;
            z-index: 10;
        }

        .topo-node-panel.open { transform: translateX(0); }

        .topo-node-panel h4 {
            font-size: 1rem;
            margin-bottom: 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .topo-node-panel .meta-grid {
            display: grid;
            grid-template-columns: auto 1fr;
            gap: 0.5rem 1rem;
            font-size: 0.85rem;
        }

        .topo-node-panel .meta-grid .label {
            color: var(--text-secondary);
            font-weight: 500;
        }

        .topo-legend {
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
            padding: 0.5rem 1rem;
            border-top: 1px solid var(--bg-tertiary);
            font-size: 0.75rem;
            color: var(--text-secondary);
        }

        .topo-legend-item {
            display: inline-flex;
            align-items: center;
            gap: 0.375rem;
        }

        .topo-legend-dot {
            width: 10px;
            height: 10px;
            border-radius: 3px;
        }

        /* ---- Navigation Links ---- */
        .nav-links {
            display: flex;
            gap: 0.25rem;
            align-items: center;
        }

        .nav-link {
            color: var(--text-secondary);
            text-decoration: none;
            font-size: 0.95rem;
            font-weight: 500;
            padding: 0.5rem 1rem;
            border-radius: 0.375rem;
            transition: all 0.2s;
            cursor: pointer;
        }

        .nav-link:hover {
            color: var(--text-primary);
            background: rgba(255,255,255,0.05);
        }

        .nav-link.active {
            color: var(--accent);
            background: rgba(59,130,246,0.1);
        }

        /* ---- Wizard Layout ---- */
        .wizard-progress {
            display: flex;
            justify-content: center;
            gap: 2rem;
            margin: 2rem 0;
            padding: 1.5rem;
            background: var(--bg-secondary);
            border-radius: 0.5rem;
            border: 1px solid var(--bg-tertiary);
        }

        .wizard-step {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 0.5rem;
            position: relative;
            opacity: 0.4;
            transition: opacity 0.2s;
        }

        .wizard-step.active,
        .wizard-step.completed {
            opacity: 1;
        }

        .wizard-step::after {
            content: '';
            position: absolute;
            top: 20px;
            left: calc(100% + 0.25rem);
            width: 1.5rem;
            height: 2px;
            background: var(--bg-tertiary);
        }

        .wizard-step:last-child::after { display: none; }

        .wizard-step.completed::after { background: var(--accent); }

        .step-number {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            font-size: 1rem;
        }

        .wizard-step.active .step-number {
            background: var(--accent);
            color: white;
        }

        .wizard-step.completed .step-number {
            background: var(--success);
            color: white;
        }

        .step-label {
            font-size: 0.85rem;
            color: var(--text-secondary);
            font-weight: 500;
        }

        .wizard-step.active .step-label { color: var(--accent); }

        .wizard-container {
            background: var(--bg-secondary);
            border-radius: 0.5rem;
            border: 1px solid var(--bg-tertiary);
            padding: 2rem;
            margin-bottom: 2rem;
        }

        .wizard-panel { display: none; }
        .wizard-panel.active { display: block; }

        .wizard-title {
            font-size: 1.4rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
        }

        /* ---- Target Type Selector ---- */
        .target-type-selector {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .target-type-card {
            position: relative;
            background: var(--bg-primary);
            border: 2px solid var(--bg-tertiary);
            border-radius: 0.5rem;
            padding: 1.25rem 0.75rem;
            text-align: center;
            cursor: pointer;
            transition: all 0.2s;
        }

        .target-type-card:hover {
            border-color: var(--accent);
            transform: translateY(-2px);
        }

        .target-type-card input[type="radio"] {
            position: absolute;
            opacity: 0;
            pointer-events: none;
        }

        .target-type-card:has(input:checked) {
            border-color: var(--accent);
            background: rgba(59,130,246,0.06);
        }

        .target-type-icon { font-size: 2rem; margin-bottom: 0.5rem; }
        .target-type-name { font-weight: 600; font-size: 0.9rem; margin-bottom: 0.25rem; }
        .target-type-desc { font-size: 0.7rem; color: var(--text-secondary); }

        .target-form-section { margin-top: 1.5rem; }

        /* ---- Discovery Summary ---- */
        .discovery-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }

        .recommendation-banner {
            display: flex;
            gap: 1rem;
            align-items: center;
            padding: 1rem 1.5rem;
            background: rgba(59,130,246,0.1);
            border-left: 4px solid var(--accent);
            border-radius: 0.5rem;
            margin-bottom: 1.5rem;
        }

        .recommendation-icon { font-size: 1.75rem; }
        .recommendation-title { font-size: 0.95rem; margin-bottom: 0.25rem; }
        .recommendation-reason { font-size: 0.85rem; color: var(--text-secondary); }

        .risk-indicators {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 0.5rem;
        }

        .risk-badge {
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 0.25rem;
            font-size: 0.7rem;
            font-weight: 500;
            background: rgba(239,68,68,0.15);
            color: var(--error);
        }

        .risk-badge.info {
            background: rgba(59,130,246,0.15);
            color: var(--accent);
        }

        /* ---- Component Type Grid ---- */
        .section { margin-bottom: 1.5rem; }

        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }

        .section-title { font-size: 1.1rem; font-weight: 600; }

        .component-type-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 0.75rem;
        }

        .component-type-checkbox {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.75rem 1rem;
            background: var(--bg-primary);
            border-radius: 0.375rem;
            cursor: pointer;
            transition: background 0.2s;
        }

        .component-type-checkbox:hover { background: rgba(59,130,246,0.05); }

        .component-type-checkbox input[type="checkbox"] {
            width: 18px;
            height: 18px;
            cursor: pointer;
            accent-color: var(--accent);
        }

        .component-type-info { flex: 1; }
        .component-type-label { font-weight: 500; font-size: 0.9rem; display: block; margin-bottom: 0.15rem; }
        .component-type-count { font-size: 0.75rem; color: var(--text-secondary); }

        /* ---- AI Frameworks List ---- */
        .frameworks-list {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-bottom: 1.5rem;
        }

        .framework-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 1rem;
            font-size: 0.8rem;
            font-weight: 500;
            background: rgba(139,92,246,0.15);
            color: #a78bfa;
        }

        /* ---- Mini Topology ---- */
        .mini-topo-container {
            background: var(--bg-primary);
            border-radius: 0.5rem;
            padding: 1rem;
            min-height: 250px;
        }

        #miniTopoSvg {
            width: 100%;
            height: 250px;
        }

        #miniTopoSvg .topo-node rect {
            rx: 6;
            ry: 6;
            cursor: pointer;
        }

        #miniTopoSvg .topo-node text {
            fill: white;
            font-size: 10px;
            text-anchor: middle;
            pointer-events: none;
        }

        #miniTopoSvg .topo-node .node-type-label {
            font-size: 8px;
            opacity: 0.8;
        }

        #miniTopoSvg .topo-edge path {
            stroke: #475569;
            stroke-width: 1.5;
            fill: none;
        }

        /* ---- Workflow Import ---- */
        .workflow-import-area { padding: 0.5rem 0; }

        /* ---- Profile Selector ---- */
        .profile-selector {
            display: flex;
            flex-direction: column;
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .profile-card {
            position: relative;
            background: var(--bg-primary);
            border: 2px solid var(--bg-tertiary);
            border-radius: 0.5rem;
            padding: 1.5rem;
            cursor: pointer;
            transition: all 0.2s;
        }

        .profile-card:hover { border-color: var(--accent); }

        .profile-card input[type="radio"] {
            position: absolute;
            opacity: 0;
            pointer-events: none;
        }

        .profile-card:has(input:checked) {
            border-color: var(--accent);
            background: rgba(59,130,246,0.06);
        }

        .profile-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }

        .profile-name { font-size: 1.2rem; font-weight: 600; }

        .profile-duration {
            font-size: 0.8rem;
            color: var(--text-secondary);
            background: var(--bg-tertiary);
            padding: 0.2rem 0.6rem;
            border-radius: 0.25rem;
        }

        .profile-desc {
            font-size: 0.85rem;
            color: var(--text-secondary);
            margin-bottom: 0.75rem;
        }

        .profile-analyzers {
            display: flex;
            flex-wrap: wrap;
            gap: 0.4rem;
        }

        .analyzer-badge {
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 0.25rem;
            font-size: 0.7rem;
            font-weight: 500;
        }

        .analyzer-badge.enabled {
            background: rgba(34,197,94,0.15);
            color: var(--success);
        }

        .analyzer-badge.disabled {
            background: rgba(148,163,184,0.1);
            color: var(--text-secondary);
            text-decoration: line-through;
        }

        /* ---- Analyzer Toggles ---- */
        .analyzer-toggles {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 0.75rem;
        }

        .analyzer-toggle {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.75rem 1rem;
            background: var(--bg-primary);
            border-radius: 0.375rem;
            cursor: pointer;
            transition: background 0.2s;
        }

        .analyzer-toggle:hover { background: rgba(59,130,246,0.05); }

        .analyzer-toggle input[type="checkbox"] {
            width: 18px;
            height: 18px;
            cursor: pointer;
            accent-color: var(--accent);
        }

        .toggle-name { font-weight: 500; font-size: 0.9rem; margin-bottom: 0.15rem; }
        .toggle-desc { font-size: 0.75rem; color: var(--text-secondary); }

        /* ---- Interrogation Settings ---- */
        .interrogation-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 1rem;
        }

        .checkbox-group {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .checkbox-group label {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.9rem;
            cursor: pointer;
        }

        .checkbox-group input[type="checkbox"] {
            cursor: pointer;
            accent-color: var(--accent);
        }

        /* ---- Review Sections ---- */
        .review-section {
            background: var(--bg-primary);
            padding: 1.25rem;
            border-radius: 0.5rem;
            margin-bottom: 1rem;
        }

        .review-section h3 {
            font-size: 1rem;
            font-weight: 600;
            margin-bottom: 0.75rem;
            color: var(--accent);
        }

        .review-item {
            display: flex;
            gap: 1rem;
            padding: 0.5rem 0;
            border-bottom: 1px solid var(--bg-tertiary);
        }

        .review-item:last-child { border-bottom: none; }

        .review-label {
            font-weight: 500;
            color: var(--text-secondary);
            min-width: 130px;
            font-size: 0.9rem;
        }

        .review-value {
            color: var(--text-primary);
            font-weight: 500;
            font-size: 0.9rem;
        }

        .review-badges {
            display: flex;
            flex-wrap: wrap;
            gap: 0.4rem;
        }

        .review-badges .badge {
            background: rgba(59,130,246,0.15);
            color: var(--accent);
            padding: 0.2rem 0.6rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            font-weight: 500;
        }

        .wizard-actions {
            display: flex;
            justify-content: space-between;
            margin-top: 2rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--bg-tertiary);
        }

        /* ---- Interrogation UI ---- */
        .int-cat-label {
            display: inline-flex;
            align-items: center;
            gap: 0.35rem;
            font-size: 0.85rem;
            color: var(--text-secondary);
            cursor: pointer;
            padding: 0.3rem 0.6rem;
            border-radius: 0.375rem;
            border: 1px solid var(--bg-tertiary);
            transition: all 0.15s;
        }
        .int-cat-label:has(input:checked) {
            border-color: var(--accent);
            color: var(--text-primary);
            background: rgba(59,130,246,0.1);
        }
        .int-cat-label input { display: none; }

        .int-transcript {
            max-height: 600px;
            overflow-y: auto;
            font-family: 'SF Mono', 'Fira Code', monospace;
            font-size: 0.82rem;
            line-height: 1.6;
        }
        .int-turn {
            padding: 0.75rem 1rem;
            margin-bottom: 0.5rem;
            border-radius: 0.5rem;
            border-left: 3px solid var(--bg-tertiary);
        }
        .int-turn.attacker {
            border-left-color: #ef4444;
            background: rgba(239,68,68,0.05);
        }
        .int-turn.target {
            border-left-color: #3b82f6;
            background: rgba(59,130,246,0.05);
        }
        .int-turn.evaluator {
            border-left-color: #f59e0b;
            background: rgba(245,158,11,0.05);
        }
        .int-turn.system {
            border-left-color: var(--text-secondary);
            background: rgba(255,255,255,0.02);
            font-style: italic;
        }
        .int-turn-header {
            font-size: 0.75rem;
            font-weight: 600;
            margin-bottom: 0.35rem;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }
        .int-turn.attacker .int-turn-header { color: #ef4444; }
        .int-turn.target .int-turn-header { color: #3b82f6; }
        .int-turn.evaluator .int-turn-header { color: #f59e0b; }
        .int-turn.system .int-turn-header { color: var(--text-secondary); }

        .int-job-card {
            padding: 0.75rem;
            border-radius: 0.5rem;
            border: 1px solid var(--bg-tertiary);
            margin-bottom: 0.5rem;
            cursor: pointer;
            transition: all 0.15s;
        }
        .int-job-card:hover { border-color: var(--accent); background: rgba(59,130,246,0.05); }
        .int-job-card .status-badge {
            font-size: 0.7rem;
            padding: 0.15rem 0.5rem;
            border-radius: 9999px;
        }
        .int-job-card .status-badge.completed { background: rgba(34,197,94,0.15); color: #22c55e; }
        .int-job-card .status-badge.running { background: rgba(59,130,246,0.15); color: #3b82f6; }
        .int-job-card .status-badge.pending { background: rgba(245,158,11,0.15); color: #f59e0b; }
        .int-job-card .status-badge.failed { background: rgba(239,68,68,0.15); color: #ef4444; }

        .form-input {
            width: 100%;
            padding: 0.5rem 0.75rem;
            background: var(--bg-primary);
            border: 1px solid var(--bg-tertiary);
            border-radius: 0.375rem;
            color: var(--text-primary);
            font-size: 0.85rem;
            font-family: inherit;
            box-sizing: border-box;
        }
        .form-input:focus {
            outline: none;
            border-color: var(--accent);
        }
        textarea.form-input { resize: vertical; }
        select.form-input { cursor: pointer; }
    </style>
</head>
<body>
    <header>
        <div class="logo" onclick="showDashboard()">MASS <span>Dashboard</span></div>
        <div class="nav-links">
            <a class="nav-link active" id="navDashboard" onclick="showDashboard()">Dashboard</a>
            <a class="nav-link" id="navScan" onclick="showScanConfig()">Scan</a>
            <a class="nav-link" id="navInterrogate" onclick="showInterrogation()">Interrogate</a>
        </div>
        <div class="header-actions">
            <input type="text" id="apiKeyInput" class="form-input" placeholder="Paste API Key"
                   style="width:220px;height:30px;font-size:0.8rem;padding:0 0.5rem"
                   onkeydown="if(event.key==='Enter')connectApiKey()" />
            <button class="btn" id="apiKeyBtn" onclick="connectApiKey()" style="height:30px;padding:0 0.75rem;font-size:0.8rem">Connect</button>
            <span id="apiKeyStatus" style="font-size:0.75rem;margin-left:0.25rem"></span>
            <button class="btn" onclick="showScanConfig()">New Scan</button>
        </div>
    </header>

    <main>
        <!-- Dashboard View -->
        <div id="dashboardView" class="view active">
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
                    <button class="btn btn-sm" onclick="loadScans()">Refresh</button>
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
        </div>

        <!-- Scan Detail View -->
        <div id="scanDetailView" class="view">
            <div class="breadcrumb">
                <a onclick="showDashboard()">Dashboard</a>
                <span class="separator">/</span>
                <span id="scanBreadcrumb">Scan</span>
            </div>

            <div class="scan-header">
                <h2 id="scanDetailTitle">Scan Details</h2>
                <span class="status" id="scanDetailStatus"></span>
                <div style="margin-left:auto;display:flex;gap:0.5rem;align-items:center;">
                    <button class="btn btn-sm btn-ghost" id="topoBtn" onclick="viewTopology()" style="display:none">Topology</button>
                    <div class="export-dropdown" style="position:relative;">
                        <button class="btn btn-sm" id="exportBtn" onclick="toggleExportMenu()" style="display:none">Export Report</button>
                        <div id="exportMenu" style="display:none;position:absolute;right:0;top:100%;margin-top:4px;background:var(--bg-secondary);border:1px solid var(--bg-tertiary);border-radius:0.5rem;padding:0.5rem 0;z-index:100;min-width:160px;box-shadow:0 4px 12px rgba(0,0,0,0.3);">
                            <a onclick="generateReport('json')" style="display:block;padding:0.5rem 1rem;color:var(--text-primary);cursor:pointer;font-size:0.85rem;text-decoration:none;">JSON Report</a>
                            <a onclick="generateReport('html')" style="display:block;padding:0.5rem 1rem;color:var(--text-primary);cursor:pointer;font-size:0.85rem;text-decoration:none;">HTML Report</a>
                            <a onclick="generateReport('sarif')" style="display:block;padding:0.5rem 1rem;color:var(--text-primary);cursor:pointer;font-size:0.85rem;text-decoration:none;">SARIF Report</a>
                        </div>
                    </div>
                </div>
            </div>

            <div class="scan-meta-bar" id="scanDetailMeta"></div>

            <div class="scan-progress-bar" id="scanProgressBar">
                <div class="progress-fill" id="scanProgressFill"></div>
            </div>
            <div class="scan-progress-text" id="scanProgressText"></div>

            <div class="findings-summary-bar" id="findingsSummaryBar"></div>

            <div class="section">
                <div class="section-header">
                    <h2 class="section-title">Findings</h2>
                    <div class="filters">
                        <input type="text" id="findingsSearch" placeholder="Search findings..." oninput="applyFindingsFilter()"
                            style="background:var(--bg-primary);border:1px solid var(--bg-tertiary);color:var(--text-primary);padding:0.35rem 0.75rem;border-radius:0.375rem;font-size:0.85rem;width:200px;">
                        <select id="filterSeverity" onchange="applyFindingsFilter()">
                            <option value="">All Severities</option>
                            <option value="critical">Critical</option>
                            <option value="high">High</option>
                            <option value="medium">Medium</option>
                            <option value="low">Low</option>
                            <option value="info">Info</option>
                        </select>
                        <select id="filterCategory" onchange="applyFindingsFilter()">
                            <option value="">All Categories</option>
                        </select>
                        <select id="filterComponent" onchange="applyFindingsFilter()">
                            <option value="">All Components</option>
                        </select>
                        <button class="btn btn-sm btn-ghost" onclick="clearFindingsFilters()">Clear</button>
                        <button class="btn btn-sm btn-ghost" onclick="loadScanFindings(currentScanId)">Refresh</button>
                    </div>
                </div>
                <div id="findingsCount" style="padding:0.25rem 0;font-size:0.8rem;color:var(--text-secondary);"></div>
                <table>
                    <thead>
                        <tr>
                            <th class="sortable" onclick="sortFindings('severity')">Severity <span id="sortSeverity" class="sort-indicator"></span></th>
                            <th class="sortable" onclick="sortFindings('title')">Title <span id="sortTitle" class="sort-indicator"></span></th>
                            <th class="sortable" onclick="sortFindings('category')">Category <span id="sortCategory" class="sort-indicator"></span></th>
                            <th class="sortable" onclick="sortFindings('component')">Component <span id="sortComponent" class="sort-indicator"></span></th>
                            <th>Location</th>
                        </tr>
                    </thead>
                    <tbody id="findingsTable">
                        <tr><td colspan="5" class="empty-state">Loading findings...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Topology View -->
        <div id="topologyView" class="view">
            <div class="breadcrumb">
                <a onclick="showDashboard()">Dashboard</a>
                <span class="separator">/</span>
                <a onclick="returnFromTopology()" id="topoBreadcrumbScan">Scan</a>
                <span class="separator">/</span>
                <span>Topology</span>
            </div>

            <div class="scan-header">
                <h2 id="topoTitle">Deployment Topology</h2>
            </div>

            <div class="topo-container" id="topoContainer">
                <div class="topo-toolbar">
                    <div class="topo-toolbar-group">
                        <span id="topoEnvBadge" class="topo-env-badge" style="display:none"></span>
                        <span id="topoNodeCount" style="font-size:0.8rem;color:var(--text-secondary)"></span>
                    </div>
                    <div class="topo-toolbar-group">
                        <button class="btn btn-sm btn-ghost" onclick="topoZoomIn()">Zoom +</button>
                        <button class="btn btn-sm btn-ghost" onclick="topoZoomOut()">Zoom -</button>
                        <button class="btn btn-sm btn-ghost" onclick="topoFitView()">Fit</button>
                    </div>
                </div>
                <div class="topo-svg-wrap" id="topoSvgWrap">
                    <svg id="topoSvg" xmlns="http://www.w3.org/2000/svg">
                        <defs>
                            <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">
                                <polygon points="0 0, 10 3.5, 0 7" fill="#475569" />
                            </marker>
                        </defs>
                        <g id="topoGroup"></g>
                    </svg>
                </div>
                <div class="topo-legend" id="topoLegend"></div>

                <!-- Node detail side panel -->
                <div class="topo-node-panel" id="topoNodePanel">
                    <h4>
                        <span id="topoNodePanelTitle">Node</span>
                        <button class="btn btn-sm btn-ghost" onclick="closeTopoNodePanel()">&times;</button>
                    </h4>
                    <div id="topoNodePanelBody" class="meta-grid"></div>
                </div>
            </div>
        </div>

        <!-- Scan Configuration View (Wizard) -->
        <div id="scanConfigView" class="view">
            <div class="breadcrumb">
                <a onclick="showDashboard()">Dashboard</a>
                <span class="separator">/</span>
                <span>New Scan</span>
            </div>

            <!-- Wizard Progress Indicator -->
            <div class="wizard-progress">
                <div class="wizard-step active" data-step="1">
                    <div class="step-number">1</div>
                    <div class="step-label">Target</div>
                </div>
                <div class="wizard-step" data-step="2">
                    <div class="step-number">2</div>
                    <div class="step-label">Discovery</div>
                </div>
                <div class="wizard-step" data-step="3">
                    <div class="step-number">3</div>
                    <div class="step-label">Configure</div>
                </div>
                <div class="wizard-step" data-step="4">
                    <div class="step-number">4</div>
                    <div class="step-label">Launch</div>
                </div>
            </div>

            <div class="wizard-container">
                <!-- Step 1: Target Selection -->
                <div class="wizard-panel active" id="scanStep1">
                    <h2 class="wizard-title">Select Scan Target</h2>

                    <div class="target-type-selector">
                        <label class="target-type-card">
                            <input type="radio" name="targetType" value="deployment" checked>
                            <div class="target-type-icon">&#128193;</div>
                            <div class="target-type-name">Deployment</div>
                            <div class="target-type-desc">Full directory scan</div>
                        </label>
                        <label class="target-type-card">
                            <input type="radio" name="targetType" value="model_endpoint">
                            <div class="target-type-icon">&#129302;</div>
                            <div class="target-type-name">Model Endpoint</div>
                            <div class="target-type-desc">Test live model API</div>
                        </label>
                        <label class="target-type-card">
                            <input type="radio" name="targetType" value="agent_endpoint">
                            <div class="target-type-icon">&#128279;</div>
                            <div class="target-type-name">Agent Endpoint</div>
                            <div class="target-type-desc">Agent-to-agent scan</div>
                        </label>
                        <label class="target-type-card">
                            <input type="radio" name="targetType" value="model_file">
                            <div class="target-type-icon">&#128451;</div>
                            <div class="target-type-name">Model File</div>
                            <div class="target-type-desc">GGUF, safetensors</div>
                        </label>
                        <label class="target-type-card">
                            <input type="radio" name="targetType" value="mcp_server">
                            <div class="target-type-icon">&#128268;</div>
                            <div class="target-type-name">MCP Server</div>
                            <div class="target-type-desc">MCP configuration</div>
                        </label>
                        <label class="target-type-card">
                            <input type="radio" name="targetType" value="skill_file">
                            <div class="target-type-icon">&#9889;</div>
                            <div class="target-type-name">Skill File</div>
                            <div class="target-type-desc">Python/JS AI logic</div>
                        </label>
                        <label class="target-type-card">
                            <input type="radio" name="targetType" value="instruction_file">
                            <div class="target-type-icon">&#128221;</div>
                            <div class="target-type-name">Instructions</div>
                            <div class="target-type-desc">System prompts</div>
                        </label>
                    </div>

                    <!-- File-based target form -->
                    <div id="targetFormPath" class="target-form-section">
                        <div class="form-group">
                            <label>Available Targets</label>
                            <select id="wizTargetSelect" onchange="handleTargetSelect(this.value)">
                                <option value="">Loading targets...</option>
                            </select>
                            <div id="targetSelectHint" style="font-size:0.75rem;color:var(--text-secondary);margin-top:0.25rem">
                                Targets are directories mounted into the Docker container
                            </div>
                        </div>
                        <div class="form-group">
                            <label>Target Path <span style="font-size:0.75rem;color:var(--text-secondary)">(or enter manually)</span></label>
                            <input type="text" id="wizTargetPath" placeholder="/app/targets/my-project or local path">
                        </div>
                        <div class="form-group">
                            <label>Scan Name (optional)</label>
                            <input type="text" id="wizTargetName" placeholder="My AI Deployment">
                        </div>
                        <div class="wizard-actions">
                            <div></div>
                            <div style="display:flex;gap:0.5rem">
                                <button class="btn btn-secondary" id="wizSkipDiscoveryBtn" onclick="skipDiscovery()" style="display:none">
                                    Skip Discovery
                                </button>
                                <button class="btn" onclick="runDiscovery()">
                                    <span class="loading-spinner" id="discoverySpinner" style="display:none"></span>
                                    Discover &amp; Continue
                                </button>
                            </div>
                        </div>
                    </div>

                    <!-- Model Endpoint form -->
                    <div id="targetFormModel" class="target-form-section" style="display:none">
                        <div class="form-group">
                            <label>Target Name</label>
                            <input type="text" id="wizModelName" placeholder="Production GPT-4 API">
                        </div>
                        <div class="form-group">
                            <label>Model Provider</label>
                            <select id="wizModelProvider">
                                <option value="">Select provider...</option>
                                <option value="openai">OpenAI</option>
                                <option value="anthropic">Anthropic (Claude)</option>
                                <option value="bedrock">AWS Bedrock</option>
                                <option value="azure_openai">Azure OpenAI</option>
                                <option value="gemini">Google Gemini</option>
                                <option value="grok">xAI Grok</option>
                                <option value="ollama">Ollama (Local)</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Model Name / ID</label>
                            <input type="text" id="wizModelId" placeholder="gpt-4o, claude-sonnet-4-20250514, etc.">
                        </div>
                        <div class="form-group">
                            <label>API Endpoint URL (optional)</label>
                            <input type="text" id="wizModelEndpoint" placeholder="https://api.openai.com/v1">
                        </div>
                        <div class="form-group">
                            <label>API Key</label>
                            <input type="password" id="wizModelApiKey" placeholder="sk-...">
                        </div>
                        <div class="form-group">
                            <label>System Prompt to Test (optional)</label>
                            <textarea id="wizModelSystemPrompt" rows="4" placeholder="You are a helpful assistant..."></textarea>
                        </div>
                        <div class="wizard-actions">
                            <div></div>
                            <button class="btn" onclick="goToStep(3)">Continue to Configuration</button>
                        </div>
                    </div>

                    <!-- Agent Endpoint form -->
                    <div id="targetFormAgent" class="target-form-section" style="display:none">
                        <div class="form-group">
                            <label>Target Name</label>
                            <input type="text" id="wizAgentName" placeholder="My Agent Service">
                        </div>
                        <div class="form-group">
                            <label>Agent URL</label>
                            <input type="text" id="wizAgentUrl" placeholder="https://my-agent.example.com/api">
                        </div>
                        <div class="form-group">
                            <label>Protocol</label>
                            <select id="wizAgentProtocol">
                                <option value="rest">REST</option>
                                <option value="grpc">gRPC</option>
                                <option value="mcp">MCP</option>
                                <option value="a2a">A2A (Agent-to-Agent)</option>
                                <option value="custom">Custom</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Authentication</label>
                            <select id="wizAgentAuthType" onchange="toggleAgentAuthToken()">
                                <option value="none">None</option>
                                <option value="bearer">Bearer Token</option>
                                <option value="api_key">API Key</option>
                                <option value="oauth2">OAuth2</option>
                            </select>
                        </div>
                        <div class="form-group" id="wizAgentTokenGroup" style="display:none">
                            <label>Auth Token / API Key</label>
                            <input type="password" id="wizAgentAuthToken" placeholder="Token or API key">
                        </div>
                        <div class="wizard-actions">
                            <div></div>
                            <button class="btn" onclick="goToStep(3)">Continue to Configuration</button>
                        </div>
                    </div>
                </div>

                <!-- Step 2: Discovery Results -->
                <div class="wizard-panel" id="scanStep2">
                    <h2 class="wizard-title">Discovery Results</h2>

                    <div class="discovery-summary">
                        <div class="stat-card">
                            <div class="stat-value" id="discTotalFiles">-</div>
                            <div class="stat-label">Total Files</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value" id="discComponents">-</div>
                            <div class="stat-label">Components</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value" id="discFrameworks">-</div>
                            <div class="stat-label">AI Frameworks</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value" id="discModelFiles">-</div>
                            <div class="stat-label">Model Files</div>
                        </div>
                    </div>

                    <!-- Recommendation -->
                    <div class="recommendation-banner" id="recBanner">
                        <div class="recommendation-icon">&#128161;</div>
                        <div>
                            <div class="recommendation-title">Recommended: <strong id="recProfile">Standard</strong></div>
                            <div class="recommendation-reason" id="recReason">Balanced scan for typical deployments</div>
                            <div class="risk-indicators" id="recRisks"></div>
                        </div>
                    </div>

                    <!-- Detected AI Frameworks -->
                    <div class="section" id="frameworksSection" style="display:none">
                        <div class="section-header">
                            <h3 class="section-title">Detected AI Frameworks</h3>
                        </div>
                        <div class="frameworks-list" id="frameworksList"></div>
                    </div>

                    <!-- Component Selection -->
                    <div class="section">
                        <div class="section-header">
                            <h3 class="section-title">Components to Scan</h3>
                            <div>
                                <button class="btn btn-sm btn-ghost" onclick="selectAllComponents()">All</button>
                                <button class="btn btn-sm btn-ghost" onclick="deselectAllComponents()">None</button>
                            </div>
                        </div>
                        <div class="component-type-grid" id="compTypeGrid"></div>
                    </div>

                    <!-- Mini Topology -->
                    <div class="section" id="miniTopoSection" style="display:none">
                        <div class="section-header">
                            <h3 class="section-title">Architecture Preview</h3>
                        </div>
                        <div class="mini-topo-container">
                            <svg id="miniTopoSvg" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 250">
                                <defs>
                                    <marker id="miniArrow" markerWidth="8" markerHeight="5" refX="8" refY="2.5" orient="auto">
                                        <polygon points="0 0, 8 2.5, 0 5" fill="#475569" />
                                    </marker>
                                </defs>
                                <g id="miniTopoGroup"></g>
                            </svg>
                        </div>
                    </div>

                    <!-- Workflow Import -->
                    <div class="section">
                        <div class="section-header">
                            <h3 class="section-title">Import Workflow (Optional)</h3>
                        </div>
                        <div class="workflow-import-area">
                            <div class="form-group" style="max-width:300px">
                                <select id="wizWorkflowSource" onchange="toggleWorkflowImport()">
                                    <option value="">None - skip</option>
                                    <option value="n8n">n8n workflow</option>
                                    <option value="make">Make scenario</option>
                                    <option value="generic">Generic JSON</option>
                                </select>
                            </div>
                            <div id="workflowImportArea" style="display:none">
                                <div class="form-group">
                                    <label>Paste workflow JSON</label>
                                    <textarea id="wizWorkflowJson" rows="5" placeholder='{"nodes": [...], "connections": [...]}'></textarea>
                                </div>
                                <button class="btn btn-sm" onclick="importWorkflow()">Import &amp; Preview</button>
                            </div>
                        </div>
                    </div>

                    <div class="wizard-actions">
                        <button class="btn btn-secondary" onclick="goToStep(1)">Back</button>
                        <button class="btn" onclick="goToStep(3)">Continue to Configuration</button>
                    </div>
                </div>

                <!-- Step 3: Scan Configuration -->
                <div class="wizard-panel" id="scanStep3">
                    <h2 class="wizard-title">Configure Scan</h2>

                    <div class="profile-selector">
                        <label class="profile-card">
                            <input type="radio" name="wizProfile" value="quick">
                            <div class="profile-header">
                                <div class="profile-name">Quick Scan</div>
                                <div class="profile-duration">~5-10 min</div>
                            </div>
                            <div class="profile-desc">Fast assessment focusing on high-risk issues. Skips infrastructure, MCP, and workflow analysis.</div>
                            <div class="profile-analyzers">
                                <span class="analyzer-badge enabled">Deployment</span>
                                <span class="analyzer-badge enabled">Secrets</span>
                                <span class="analyzer-badge enabled">Models</span>
                                <span class="analyzer-badge enabled">Context</span>
                                <span class="analyzer-badge enabled">Interrogation (limited)</span>
                                <span class="analyzer-badge disabled">Infrastructure</span>
                                <span class="analyzer-badge disabled">MCP</span>
                                <span class="analyzer-badge disabled">Attack Surface</span>
                                <span class="analyzer-badge disabled">Workflows</span>
                            </div>
                        </label>

                        <label class="profile-card">
                            <input type="radio" name="wizProfile" value="standard" checked>
                            <div class="profile-header">
                                <div class="profile-name">Standard Scan</div>
                                <div class="profile-duration">~15-20 min</div>
                            </div>
                            <div class="profile-desc">Balanced assessment with all static analyzers. No active model interrogation.</div>
                            <div class="profile-analyzers">
                                <span class="analyzer-badge enabled">Deployment</span>
                                <span class="analyzer-badge enabled">Secrets</span>
                                <span class="analyzer-badge enabled">Infrastructure</span>
                                <span class="analyzer-badge enabled">Models</span>
                                <span class="analyzer-badge enabled">Context</span>
                                <span class="analyzer-badge enabled">MCP</span>
                                <span class="analyzer-badge enabled">Attack Surface</span>
                                <span class="analyzer-badge enabled">Workflows</span>
                                <span class="analyzer-badge disabled">Model Interrogation</span>
                            </div>
                        </label>

                        <label class="profile-card">
                            <input type="radio" name="wizProfile" value="comprehensive">
                            <div class="profile-header">
                                <div class="profile-name">Comprehensive Scan</div>
                                <div class="profile-duration">~30-45 min</div>
                            </div>
                            <div class="profile-desc">Full assessment including active model interrogation with attack probes against live endpoints.</div>
                            <div class="profile-analyzers">
                                <span class="analyzer-badge enabled">All Static Analyzers</span>
                                <span class="analyzer-badge enabled">Model Interrogation (full suite)</span>
                            </div>
                        </label>

                        <label class="profile-card">
                            <input type="radio" name="wizProfile" value="custom">
                            <div class="profile-header">
                                <div class="profile-name">Custom</div>
                                <div class="profile-duration">varies</div>
                            </div>
                            <div class="profile-desc">Choose exactly which analyzers to run.</div>
                        </label>
                    </div>

                    <!-- Custom Analyzer Toggles -->
                    <div class="section" id="customAnalyzersSection" style="display:none">
                        <div class="section-header">
                            <h3 class="section-title">Analyzer Selection</h3>
                        </div>
                        <div class="analyzer-toggles">
                            <label class="analyzer-toggle">
                                <input type="checkbox" id="chkDeployment" checked>
                                <div><div class="toggle-name">Deployment Scanner</div><div class="toggle-desc">Discover components and structure</div></div>
                            </label>
                            <label class="analyzer-toggle">
                                <input type="checkbox" id="chkSecrets" checked>
                                <div><div class="toggle-name">Secret Detector</div><div class="toggle-desc">Find API keys, tokens, credentials</div></div>
                            </label>
                            <label class="analyzer-toggle">
                                <input type="checkbox" id="chkInfra" checked>
                                <div><div class="toggle-name">Infrastructure Scanner</div><div class="toggle-desc">Docker, K8s, cloud configs</div></div>
                            </label>
                            <label class="analyzer-toggle">
                                <input type="checkbox" id="chkModelFile" checked>
                                <div><div class="toggle-name">Model File Scanner</div><div class="toggle-desc">GGUF, safetensors analysis</div></div>
                            </label>
                            <label class="analyzer-toggle">
                                <input type="checkbox" id="chkContext" checked>
                                <div><div class="toggle-name">Context Analyzer</div><div class="toggle-desc">System prompts, instructions</div></div>
                            </label>
                            <label class="analyzer-toggle">
                                <input type="checkbox" id="chkMcp" checked>
                                <div><div class="toggle-name">MCP Analyzer</div><div class="toggle-desc">MCP server configurations</div></div>
                            </label>
                            <label class="analyzer-toggle">
                                <input type="checkbox" id="chkAttackSurface" checked>
                                <div><div class="toggle-name">Attack Surface Analyzer</div><div class="toggle-desc">External interfaces, endpoints</div></div>
                            </label>
                            <label class="analyzer-toggle">
                                <input type="checkbox" id="chkWorkflow" checked>
                                <div><div class="toggle-name">Workflow Analyzer</div><div class="toggle-desc">Agent workflows, orchestration</div></div>
                            </label>
                            <label class="analyzer-toggle">
                                <input type="checkbox" id="chkInterrogator">
                                <div><div class="toggle-name">Model Interrogator</div><div class="toggle-desc">Active testing with attack probes</div></div>
                            </label>
                        </div>
                    </div>

                    <!-- Model Interrogation Settings -->
                    <div class="section" id="interrogationSection" style="display:none">
                        <div class="section-header">
                            <h3 class="section-title">Model Interrogation Settings</h3>
                        </div>
                        <div class="interrogation-grid">
                            <div class="form-group">
                                <label>Probe Categories</label>
                                <div class="checkbox-group" id="probeCategories">
                                    <label><input type="checkbox" value="jailbreak" checked> Jailbreak Attempts</label>
                                    <label><input type="checkbox" value="prompt_injection" checked> Prompt Injection</label>
                                    <label><input type="checkbox" value="sensitive_info"> Sensitive Info Extraction</label>
                                    <label><input type="checkbox" value="role_confusion"> Role / Context Confusion</label>
                                    <label><input type="checkbox" value="instruction_override"> Instruction Override</label>
                                </div>
                            </div>
                            <div>
                                <div class="form-group">
                                    <label>Max Probes per Category</label>
                                    <input type="number" id="wizMaxProbes" value="10" min="1" max="50" style="max-width:120px">
                                </div>
                                <div class="form-group">
                                    <label>Concurrent Probes</label>
                                    <input type="number" id="wizConcurrentProbes" value="4" min="1" max="10" style="max-width:120px">
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="wizard-actions">
                        <button class="btn btn-secondary" onclick="wizGoBack()">Back</button>
                        <button class="btn" onclick="goToStep(4)">Review &amp; Launch</button>
                    </div>
                </div>

                <!-- Step 4: Review & Launch -->
                <div class="wizard-panel" id="scanStep4">
                    <h2 class="wizard-title">Review &amp; Launch</h2>

                    <div class="review-section">
                        <h3>Target</h3>
                        <div class="review-item">
                            <span class="review-label">Type</span>
                            <span class="review-value" id="revTargetType">-</span>
                        </div>
                        <div class="review-item">
                            <span class="review-label">Name</span>
                            <span class="review-value" id="revTargetName">-</span>
                        </div>
                        <div class="review-item">
                            <span class="review-label">Path / URL</span>
                            <span class="review-value" id="revTargetPath">-</span>
                        </div>
                    </div>

                    <div class="review-section" id="revDiscoverySection">
                        <h3>Discovery</h3>
                        <div class="review-item">
                            <span class="review-label">Files</span>
                            <span class="review-value" id="revFiles">-</span>
                        </div>
                        <div class="review-item">
                            <span class="review-label">Components</span>
                            <span class="review-value" id="revComponents">-</span>
                        </div>
                        <div class="review-item">
                            <span class="review-label">Selected Types</span>
                            <div class="review-badges" id="revSelectedTypes"></div>
                        </div>
                    </div>

                    <div class="review-section">
                        <h3>Configuration</h3>
                        <div class="review-item">
                            <span class="review-label">Profile</span>
                            <span class="review-value" id="revProfile">-</span>
                        </div>
                        <div class="review-item">
                            <span class="review-label">Analyzers</span>
                            <div class="review-badges" id="revAnalyzers"></div>
                        </div>
                        <div class="review-item" id="revInterrogationRow" style="display:none">
                            <span class="review-label">Interrogation</span>
                            <span class="review-value" id="revInterrogation">-</span>
                        </div>
                        <div class="review-item">
                            <span class="review-label">Est. Duration</span>
                            <span class="review-value" id="revDuration">-</span>
                        </div>
                    </div>

                    <div class="wizard-actions">
                        <button class="btn btn-secondary" onclick="goToStep(3)">Back</button>
                        <button class="btn" onclick="launchScan()" id="launchScanBtn">
                            <span class="loading-spinner" id="launchSpinner" style="display:none"></span>
                            Start Scan
                        </button>
                    </div>
                </div>
            </div>
        </div>
        <!-- Interrogation View -->
        <div id="interrogationView" class="view">
            <div class="page-header" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.5rem;">
                <div>
                    <h2 style="margin:0;font-size:1.3rem;">Model Interrogation</h2>
                    <p style="margin:0.25rem 0 0;color:var(--text-secondary);font-size:0.85rem;">
                        AI-driven adversarial testing — use one model to interrogate another
                    </p>
                </div>
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;">
                <!-- Left: Configuration -->
                <div class="card" style="padding:1.25rem;">
                    <h3 style="margin:0 0 1rem;font-size:1rem;">Configuration</h3>

                    <div style="margin-bottom:1rem;">
                        <label style="display:block;font-size:0.8rem;color:var(--text-secondary);margin-bottom:0.25rem;">Target Model (being tested)</label>
                        <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.5rem;">
                            <select id="intTargetProvider" class="form-input" onchange="onIntProviderChange('target')">
                                <option value="ollama">Ollama (Local)</option>
                                <option value="openai">OpenAI</option>
                                <option value="anthropic">Anthropic</option>
                                <option value="bedrock">AWS Bedrock</option>
                                <option value="azure_openai">Azure OpenAI</option>
                                <option value="gemini">Google Gemini</option>
                                <option value="grok">xAI Grok</option>
                            </select>
                            <input id="intTargetModel" class="form-input" placeholder="Model name" />
                        </div>
                        <input id="intTargetEndpoint" class="form-input" placeholder="Endpoint URL (optional)" style="margin-top:0.5rem;" />
                        <input id="intTargetApiKey" class="form-input" placeholder="API Key (not needed for Ollama)" type="password" style="margin-top:0.5rem;" />
                    </div>

                    <div style="margin-bottom:1rem;">
                        <label style="display:block;font-size:0.8rem;color:var(--text-secondary);margin-bottom:0.25rem;">Target System Prompt (what we're testing)</label>
                        <textarea id="intTargetSystemPrompt" class="form-input" rows="3" placeholder="Enter the system prompt configured on the target model..."></textarea>
                    </div>

                    <div style="margin-bottom:1rem;">
                        <label style="display:block;font-size:0.8rem;color:var(--text-secondary);margin-bottom:0.25rem;">Attacker Model (drives the interrogation)</label>
                        <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.5rem;">
                            <select id="intAttackerProvider" class="form-input" onchange="onIntProviderChange('attacker')">
                                <option value="ollama">Ollama (Local)</option>
                                <option value="openai">OpenAI</option>
                                <option value="anthropic">Anthropic</option>
                                <option value="bedrock">AWS Bedrock</option>
                                <option value="gemini">Google Gemini</option>
                            </select>
                            <input id="intAttackerModel" class="form-input" placeholder="Model name" />
                        </div>
                        <input id="intAttackerEndpoint" class="form-input" placeholder="Endpoint URL (optional)" style="margin-top:0.5rem;" />
                        <input id="intAttackerApiKey" class="form-input" placeholder="API Key" type="password" style="margin-top:0.5rem;" />
                    </div>

                    <div style="margin-bottom:1rem;">
                        <label style="display:block;font-size:0.8rem;color:var(--text-secondary);margin-bottom:0.25rem;">Attack Categories</label>
                        <div id="intCategories" style="display:flex;flex-wrap:wrap;gap:0.5rem;">
                            <label class="int-cat-label"><input type="checkbox" value="system_prompt_leakage" checked /> Prompt Extraction</label>
                            <label class="int-cat-label"><input type="checkbox" value="jailbreak" checked /> Jailbreak</label>
                            <label class="int-cat-label"><input type="checkbox" value="prompt_injection" /> Prompt Injection</label>
                            <label class="int-cat-label"><input type="checkbox" value="sensitive_info" /> Data Exfil</label>
                            <label class="int-cat-label"><input type="checkbox" value="excessive_agency" /> Tool Abuse</label>
                        </div>
                    </div>

                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.5rem;margin-bottom:1rem;">
                        <div>
                            <label style="display:block;font-size:0.8rem;color:var(--text-secondary);margin-bottom:0.25rem;">Max Turns</label>
                            <input id="intMaxTurns" class="form-input" type="number" value="8" min="2" max="20" />
                        </div>
                        <div>
                            <label style="display:block;font-size:0.8rem;color:var(--text-secondary);margin-bottom:0.25rem;">Strategies/Agent</label>
                            <input id="intMaxStrategies" class="form-input" type="number" value="2" min="0" max="10" />
                        </div>
                    </div>

                    <button class="btn btn-primary" onclick="startInterrogation()" id="intStartBtn" style="width:100%;">
                        <span class="loading-spinner" id="intSpinner" style="display:none"></span>
                        Start Interrogation
                    </button>
                </div>

                <!-- Right: Results -->
                <div>
                    <!-- Available Models -->
                    <div class="card" style="padding:1rem;margin-bottom:1rem;">
                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;">
                            <h3 style="margin:0;font-size:0.9rem;">Ollama Models</h3>
                            <button class="btn btn-sm" onclick="refreshOllamaModels()">Refresh</button>
                        </div>
                        <div id="ollamaModelList" style="font-size:0.85rem;color:var(--text-secondary);">
                            Loading...
                        </div>
                    </div>

                    <!-- Jobs List -->
                    <div class="card" style="padding:1rem;">
                        <h3 style="margin:0 0 0.75rem;font-size:0.9rem;">Interrogation Jobs</h3>
                        <div id="intJobsList" style="font-size:0.85rem;color:var(--text-secondary);">
                            No jobs yet
                        </div>
                    </div>
                </div>
            </div>

            <!-- Conversation Viewer (hidden until a job is selected) -->
            <div id="intConversationViewer" class="card" style="padding:1.25rem;margin-top:1.5rem;display:none;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;">
                    <h3 style="margin:0;font-size:1rem;" id="intConvTitle">Conversation Transcript</h3>
                    <button class="btn btn-sm" onclick="document.getElementById('intConversationViewer').style.display='none'">&times; Close</button>
                </div>
                <div id="intConvSummary" style="margin-bottom:1rem;"></div>
                <div id="intConvTranscript" class="int-transcript"></div>
            </div>
        </div>

    </main>

    <!-- Finding Detail Panel (slide-out) -->
    <div class="detail-panel-overlay" id="detailOverlay" onclick="closeDetailPanel()"></div>
    <div class="detail-panel" id="detailPanel">
        <div class="detail-header">
            <div>
                <span class="severity" id="detailSeverity"></span>
                <h3 id="detailTitle" style="margin-top: 0.5rem; font-size: 1.1rem;"></h3>
            </div>
            <button class="detail-close" onclick="closeDetailPanel()">&times;</button>
        </div>
        <div class="detail-body" id="detailBody">
            <!-- Populated dynamically -->
        </div>
    </div>

    <script>
        const API = '/api/v1/dashboard';
        const INT_API = '/api/v1/interrogation';
        const V1_API = '/api/v1';

        // Auth
        function getApiKey() {
            return localStorage.getItem('mass_api_key') || '';
        }
        function getAuthHeaders() {
            const key = getApiKey();
            if (!key) return {};
            return { 'X-API-Key': key };
        }
        async function connectApiKey() {
            const input = document.getElementById('apiKeyInput');
            const statusEl = document.getElementById('apiKeyStatus');
            const key = input.value.trim();
            if (!key) { statusEl.textContent = 'Enter a key'; statusEl.style.color = 'var(--warning)'; return; }
            localStorage.setItem('mass_api_key', key);
            statusEl.textContent = 'Testing...';
            statusEl.style.color = 'var(--text-secondary)';
            try {
                const res = await fetch(`${API}/stats`, {headers: {'X-API-Key': key}});
                if (res.ok) {
                    statusEl.textContent = 'Connected';
                    statusEl.style.color = 'var(--success)';
                    refreshDashboard();
                } else if (res.status === 401) {
                    statusEl.textContent = 'Invalid key';
                    statusEl.style.color = 'var(--error)';
                    localStorage.removeItem('mass_api_key');
                } else {
                    statusEl.textContent = 'Error ' + res.status;
                    statusEl.style.color = 'var(--warning)';
                }
            } catch (e) {
                statusEl.textContent = 'Network error';
                statusEl.style.color = 'var(--error)';
            }
        }
        function refreshDashboard() {
            loadStats();
            loadScans();
        }

        // Restore saved key on load
        (function() {
            const saved = getApiKey();
            if (saved) {
                const el = document.getElementById('apiKeyInput');
                if (el) el.value = saved;
                const statusEl = document.getElementById('apiKeyStatus');
                if (statusEl) { statusEl.textContent = 'Saved'; statusEl.style.color = 'var(--success)'; }
            } else {
                const statusEl = document.getElementById('apiKeyStatus');
                if (statusEl) { statusEl.textContent = 'No key set'; statusEl.style.color = 'var(--warning)'; }
            }
        })();

        // State
        let currentScanId = null;
        let currentScanData = null;
        let allFindings = [];
        let refreshInterval = null;

        // ---- Dashboard View ----

        function showDashboard() {
            document.getElementById('dashboardView').classList.add('active');
            document.getElementById('scanDetailView').classList.remove('active');
            document.getElementById('topologyView').classList.remove('active');
            document.getElementById('scanConfigView').classList.remove('active');
            document.getElementById('interrogationView').classList.remove('active');
            currentScanId = null;
            currentScanData = null;
            const topoBtn = document.getElementById('topoBtn');
            if (topoBtn) topoBtn.style.display = 'none';
            updateNavActive('navDashboard');
            startAutoRefresh();
        }

        async function loadStats() {
            try {
                const res = await fetch(`${API}/stats`, {headers: getAuthHeaders()});
                if (!res.ok) {
                    document.getElementById('totalScans').textContent = 'ERR ' + res.status;
                    return;
                }
                const stats = await res.json();
                document.getElementById('totalScans').textContent = stats.total_scans || 0;
                document.getElementById('activeScans').textContent = stats.active_scans || 0;
                document.getElementById('totalFindings').textContent = stats.total_findings || 0;
                document.getElementById('criticalFindings').textContent = stats.critical_findings || 0;
            } catch (e) {
                document.getElementById('totalScans').textContent = 'ERR';
                document.getElementById('scansTable').innerHTML = '<tr><td colspan="6" class="empty-state">API Error: ' + e.message + '</td></tr>';
                console.error('Failed to load stats:', e);
            }
        }

        async function loadScans() {
            try {
                const res = await fetch(`${API}/scans?limit=20`, {headers: getAuthHeaders()});
                if (!res.ok) {
                    document.getElementById('scansTable').innerHTML = '<tr><td colspan="6" class="empty-state">API Error: ' + res.status + ' ' + res.statusText + '</td></tr>';
                    return;
                }
                const scans = await res.json();
                const tbody = document.getElementById('scansTable');

                if (scans.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No scans yet. Click "New Scan" to start.</td></tr>';
                    return;
                }

                tbody.innerHTML = scans.map(scan => `
                    <tr class="clickable" onclick="viewScan('${scan.scan_id}')">
                        <td>${escapeHtml(scan.target)}</td>
                        <td>${escapeHtml(scan.profile)}</td>
                        <td><span class="status ${scan.status}">${scan.status}</span></td>
                        <td>
                            ${scan.critical_count > 0 ? `<span class="severity critical">${scan.critical_count}</span> ` : ''}
                            ${scan.high_count > 0 ? `<span class="severity high">${scan.high_count}</span> ` : ''}
                            ${scan.medium_count > 0 ? `<span class="severity medium">${scan.medium_count}</span> ` : ''}
                            ${scan.low_count > 0 ? `<span class="severity low">${scan.low_count}</span> ` : ''}
                            ${scan.findings_count === 0 ? '<span style="color:var(--text-secondary)">-</span>' : ''}
                        </td>
                        <td>${scan.duration_seconds ? scan.duration_seconds.toFixed(1) + 's' : '-'}</td>
                        <td>${scan.started_at ? new Date(scan.started_at).toLocaleString() : '-'}</td>
                    </tr>
                `).join('');
            } catch (e) {
                console.error('Failed to load scans:', e);
            }
        }

        // ---- Scan Detail View (D1) ----

        async function viewScan(scanId) {
            currentScanId = scanId;
            stopAutoRefresh();

            // Switch views
            document.getElementById('dashboardView').classList.remove('active');
            document.getElementById('scanConfigView').classList.remove('active');
            document.getElementById('interrogationView').classList.remove('active');
            document.getElementById('scanDetailView').classList.add('active');

            // Find scan data from the dashboard scans list
            try {
                const res = await fetch(`${API}/scans?limit=50`, {headers: getAuthHeaders()});
                const scans = await res.json();
                currentScanData = scans.find(s => s.scan_id === scanId);
            } catch (e) {
                console.error('Failed to fetch scan data:', e);
            }

            // Populate header
            if (currentScanData) {
                document.getElementById('scanBreadcrumb').textContent = currentScanData.target || scanId.slice(0, 8);
                document.getElementById('scanDetailTitle').textContent = currentScanData.target || 'Scan';
                const statusEl = document.getElementById('scanDetailStatus');
                statusEl.className = `status ${currentScanData.status}`;
                statusEl.textContent = currentScanData.status;

                // Meta bar
                const meta = [];
                if (currentScanData.profile) meta.push(`<span>Profile: <strong>${escapeHtml(currentScanData.profile)}</strong></span>`);
                if (currentScanData.started_at) meta.push(`<span>Started: ${new Date(currentScanData.started_at).toLocaleString()}</span>`);
                if (currentScanData.duration_seconds) meta.push(`<span>Duration: ${currentScanData.duration_seconds.toFixed(1)}s</span>`);
                meta.push(`<span>Total Findings: <strong>${currentScanData.findings_count}</strong></span>`);
                document.getElementById('scanDetailMeta').innerHTML = meta.join('');

                // Summary bar
                const chips = [];
                const counts = [
                    { key: 'critical', label: 'Critical', count: currentScanData.critical_count },
                    { key: 'high', label: 'High', count: currentScanData.high_count },
                    { key: 'medium', label: 'Medium', count: currentScanData.medium_count },
                    { key: 'low', label: 'Low', count: currentScanData.low_count },
                ];
                for (const c of counts) {
                    if (c.count > 0) {
                        chips.push(`<div class="findings-count-chip"><span class="dot ${c.key}"></span>${c.count} ${c.label}</div>`);
                    }
                }
                document.getElementById('findingsSummaryBar').innerHTML = chips.join('');
                updateProgressBarVisibility();
            } else {
                document.getElementById('scanBreadcrumb').textContent = scanId.slice(0, 8);
                document.getElementById('scanDetailTitle').textContent = 'Scan ' + scanId.slice(0, 8);
            }

            // Show export button if scan is completed
            const exportBtn = document.getElementById('exportBtn');
            if (currentScanData && currentScanData.status === 'completed') {
                exportBtn.style.display = '';
            } else {
                exportBtn.style.display = 'none';
            }

            // Load findings
            await loadScanFindings(scanId);

            // Check if topology data is available for this deployment
            checkTopologyAvailable();
        }

        // ---- Report Export (D1b) ----

        function toggleExportMenu() {
            const menu = document.getElementById('exportMenu');
            menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
        }

        // Close export menu when clicking outside
        document.addEventListener('click', function(e) {
            const dropdown = document.querySelector('.export-dropdown');
            if (dropdown && !dropdown.contains(e.target)) {
                document.getElementById('exportMenu').style.display = 'none';
            }
        });

        function showExportToast(message, type) {
            // Remove any existing toast
            const existing = document.querySelector('.export-toast');
            if (existing) existing.remove();

            const toast = document.createElement('div');
            toast.className = `export-toast ${type}`;
            toast.textContent = message;
            document.body.appendChild(toast);

            if (type !== 'loading') {
                setTimeout(() => toast.remove(), 4000);
            }
            return toast;
        }

        async function generateReport(format) {
            document.getElementById('exportMenu').style.display = 'none';

            if (!currentScanId) return;

            const toast = showExportToast(`Generating ${format.toUpperCase()} report...`, 'loading');

            try {
                // The reports API is at /api/v1/reports (not the dashboard prefix)
                const reportsApi = API.replace('/dashboard', '/reports');

                const res = await fetch(reportsApi, {
                    method: 'POST',
                    headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        scan_id: currentScanId,
                        format: format,
                        report_type: 'security',
                    }),
                });

                const report = await res.json();

                if (toast) toast.remove();

                if (report.status === 'completed') {
                    showExportToast(`${format.toUpperCase()} report ready - downloading...`, 'success');

                    // Download the file
                    const downloadUrl = `${reportsApi}/${report.id}/download`;
                    const dlRes = await fetch(downloadUrl, {headers: getAuthHeaders()});
                    const blob = await dlRes.blob();

                    // Trigger browser download
                    const a = document.createElement('a');
                    a.href = URL.createObjectURL(blob);
                    const ext = format === 'sarif' ? 'sarif' : format;
                    a.download = `mass_report_${currentScanId.slice(0,8)}.${ext}`;
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                    URL.revokeObjectURL(a.href);
                } else if (report.status === 'failed') {
                    showExportToast(`Report failed: ${report.error_message || 'Unknown error'}`, 'error');
                } else {
                    showExportToast(`Report status: ${report.status}`, 'loading');
                }
            } catch (e) {
                if (toast) toast.remove();
                showExportToast(`Export failed: ${e.message}`, 'error');
            }
        }

        // ---- Findings Table (D2) ----

        async function loadScanFindings(scanId) {
            const tbody = document.getElementById('findingsTable');
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state"><span class="loading-spinner"></span> Loading findings...</td></tr>';

            try {
                const res = await fetch(`${API}/scans/${scanId}/findings`, {headers: getAuthHeaders()});
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                allFindings = await res.json();

                // Populate category filter from actual data
                populateCategoryFilter(allFindings);

                // Render
                renderFindingsTable(allFindings);
            } catch (e) {
                tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Failed to load findings: ${escapeHtml(e.message)}</td></tr>`;
                console.error('Failed to load findings:', e);
            }
        }

        function populateCategoryFilter(findings) {
            const categories = [...new Set(findings.map(f => f.category))].sort();
            const select = document.getElementById('filterCategory');
            const currentValue = select.value;
            select.innerHTML = '<option value="">All Categories</option>' +
                categories.map(c => `<option value="${escapeHtml(c)}">${escapeHtml(formatCategory(c))}</option>`).join('');
            select.value = currentValue;

            // Also populate component filter
            const components = [...new Set(findings.map(f => f.component).filter(Boolean))].sort();
            const compSelect = document.getElementById('filterComponent');
            const compValue = compSelect.value;
            compSelect.innerHTML = '<option value="">All Components</option>' +
                components.map(c => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join('');
            compSelect.value = compValue;
        }

        let currentSort = { field: 'severity', dir: 'asc' };

        function sortFindings(field) {
            if (currentSort.field === field) {
                currentSort.dir = currentSort.dir === 'asc' ? 'desc' : 'asc';
            } else {
                currentSort.field = field;
                currentSort.dir = 'asc';
            }
            // Update sort indicators
            document.querySelectorAll('.sort-indicator').forEach(el => el.className = 'sort-indicator');
            const indicator = document.getElementById('sort' + field.charAt(0).toUpperCase() + field.slice(1));
            if (indicator) indicator.className = 'sort-indicator ' + currentSort.dir;
            applyFindingsFilter();
        }

        function clearFindingsFilters() {
            document.getElementById('findingsSearch').value = '';
            document.getElementById('filterSeverity').value = '';
            document.getElementById('filterCategory').value = '';
            document.getElementById('filterComponent').value = '';
            applyFindingsFilter();
        }

        function applyFindingsFilter() {
            const severity = document.getElementById('filterSeverity').value;
            const category = document.getElementById('filterCategory').value;
            const component = document.getElementById('filterComponent').value;
            const search = document.getElementById('findingsSearch').value.toLowerCase().trim();

            let filtered = allFindings;
            if (severity) filtered = filtered.filter(f => f.severity === severity);
            if (category) filtered = filtered.filter(f => f.category === category);
            if (component) filtered = filtered.filter(f => f.component === component);
            if (search) {
                filtered = filtered.filter(f =>
                    (f.title && f.title.toLowerCase().includes(search)) ||
                    (f.category && f.category.toLowerCase().includes(search)) ||
                    (f.component && f.component.toLowerCase().includes(search)) ||
                    (f.file_path && f.file_path.toLowerCase().includes(search))
                );
            }

            renderFindingsTable(filtered);
        }

        function renderFindingsTable(findings) {
            const tbody = document.getElementById('findingsTable');
            const countEl = document.getElementById('findingsCount');

            if (findings.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No findings match the current filters</td></tr>';
                countEl.textContent = `0 of ${allFindings.length} findings`;
                return;
            }

            countEl.textContent = findings.length === allFindings.length
                ? `${findings.length} findings`
                : `${findings.length} of ${allFindings.length} findings`;

            // Sort
            const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
            const dir = currentSort.dir === 'asc' ? 1 : -1;
            findings.sort((a, b) => {
                let av, bv;
                if (currentSort.field === 'severity') {
                    av = sevOrder[a.severity] ?? 5;
                    bv = sevOrder[b.severity] ?? 5;
                } else {
                    av = (a[currentSort.field] || '').toLowerCase();
                    bv = (b[currentSort.field] || '').toLowerCase();
                }
                if (av < bv) return -1 * dir;
                if (av > bv) return 1 * dir;
                return 0;
            });

            tbody.innerHTML = findings.map(f => `
                <tr class="clickable" onclick="viewFinding('${f.id}')">
                    <td><span class="severity ${f.severity}">${f.severity}</span></td>
                    <td>${escapeHtml(f.title)}</td>
                    <td><span class="category-badge">${escapeHtml(formatCategory(f.category))}</span></td>
                    <td>${escapeHtml(f.component)}</td>
                    <td>${f.file_path ? escapeHtml(f.file_path) + (f.line_number ? ':' + f.line_number : '') : '-'}</td>
                </tr>
            `).join('');
        }

        // ---- Finding Detail Panel (D3) ----

        async function viewFinding(findingId) {
            // Open panel immediately with loading state
            openDetailPanel();
            document.getElementById('detailTitle').textContent = 'Loading...';
            document.getElementById('detailSeverity').textContent = '';
            document.getElementById('detailSeverity').className = 'severity';
            document.getElementById('detailBody').innerHTML = '<div style="text-align:center;padding:2rem"><span class="loading-spinner"></span></div>';

            try {
                const res = await fetch(`${API}/findings/${findingId}`, {headers: getAuthHeaders()});
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                const finding = await res.json();

                // Header
                document.getElementById('detailTitle').textContent = finding.title;
                const sevEl = document.getElementById('detailSeverity');
                sevEl.className = `severity ${finding.severity}`;
                sevEl.textContent = finding.severity;

                // Build body
                let html = '';

                // Meta grid
                html += '<div class="detail-section"><div class="detail-section-title">Details</div>';
                html += '<div class="detail-meta">';
                html += metaItem('Status', `<span class="status ${finding.status}">${finding.status}</span>`);
                html += metaItem('Category', formatCategory(finding.category));
                html += metaItem('Component', finding.component);
                if (finding.file_path) html += metaItem('Location', finding.file_path + (finding.line_number ? ':' + finding.line_number : ''));
                if (finding.rule_id) html += metaItem('Rule', finding.rule_id);
                if (finding.confidence_level) {
                    const clLabels = {
                        'predicted': 'Predicted Risk (Unvalidated)',
                        'static_match': 'Static Pattern Match',
                        'heuristic': 'Heuristic Detection',
                        'confirmed': 'Confirmed Vulnerable',
                    };
                    const clLabel = clLabels[finding.confidence_level] || finding.confidence_level;
                    html += metaItem('Confidence', `<span class="confidence-badge ${finding.confidence_level}">${escapeHtml(clLabel)}</span>`);
                }
                if (finding.original_severity && finding.original_severity !== finding.severity) {
                    html += metaItem('If Confirmed', `<span class="severity ${finding.original_severity}">${finding.original_severity}</span>`);
                }
                html += '</div></div>';

                // Description (supports newlines and inline `code`)
                if (finding.description) {
                    html += '<div class="detail-section"><div class="detail-section-title">Description</div>';
                    const descHtml = escapeHtml(finding.description)
                        .replace(/`([^`]+)`/g, '<code style="background:var(--bg-primary);padding:0.1em 0.3em;border-radius:3px;font-size:0.85em">$1</code>')
                        .replace(/\\n/g, '<br>');
                    html += `<div class="detail-content">${descHtml}</div></div>`;
                }

                // Code snippet
                if (finding.code_snippet) {
                    html += '<div class="detail-section"><div class="detail-section-title">Code Snippet</div>';
                    html += `<div class="detail-content" style="font-family:monospace;font-size:0.8rem">${escapeHtml(finding.code_snippet)}</div></div>`;
                }

                // Evidence
                if (finding.evidence) {
                    html += '<div class="detail-section"><div class="detail-section-title">Evidence</div>';
                    html += renderEvidence(finding.evidence);
                    html += '</div>';
                }

                // Remediation
                const hasRemediation = finding.remediation || (finding.remediation_steps && finding.remediation_steps.length > 0);
                if (hasRemediation) {
                    const effortBadge = finding.estimated_effort
                        ? `<span class="effort-badge">&#9200; ${escapeHtml(finding.estimated_effort)}</span>`
                        : '';
                    html += `<div class="detail-section"><div class="detail-section-title">Remediation${effortBadge}</div>`;

                    // Summary text
                    if (finding.remediation) {
                        html += `<div class="detail-content" style="border-left: 3px solid var(--success); padding-left: 1rem; margin-bottom: 1rem;">${escapeHtml(finding.remediation)}</div>`;
                    }

                    // Numbered steps
                    if (finding.remediation_steps && finding.remediation_steps.length > 0) {
                        html += '<ol class="remediation-steps">';
                        finding.remediation_steps.forEach(step => {
                            html += `<li>${escapeHtml(step)}</li>`;
                        });
                        html += '</ol>';
                    }

                    html += '</div>';
                }

                // Guardrail examples
                if (finding.guardrail_examples && finding.guardrail_examples.length > 0) {
                    const guardrailId = 'guardrail_' + Date.now();
                    html += '<div class="detail-section"><div class="detail-section-title">&#128737; Guardrail / Protection Examples</div>';
                    html += `<div class="guardrail-tabs" id="${guardrailId}_tabs">`;
                    finding.guardrail_examples.forEach((ex, idx) => {
                        const activeClass = idx === 0 ? ' active' : '';
                        html += `<button class="guardrail-tab${activeClass}" onclick="switchGuardrailTab('${guardrailId}', ${idx})">${escapeHtml(ex.framework)}</button>`;
                    });
                    html += '</div>';
                    finding.guardrail_examples.forEach((ex, idx) => {
                        const activeClass = idx === 0 ? ' active' : '';
                        html += `<div class="guardrail-panel${activeClass}" id="${guardrailId}_panel_${idx}">`;
                        html += `<div class="guardrail-title">${escapeHtml(ex.title)}</div>`;
                        html += `<div class="guardrail-code">${escapeHtml(ex.code)}</div>`;
                        html += '</div>';
                    });
                    html += '</div>';
                }

                if (finding.code_fix_examples && finding.code_fix_examples.length > 0) {
                    const codeFixId = 'codefix_' + Date.now();
                    html += '<div class="detail-section"><div class="detail-section-title">&#128295; Code Fix Examples</div>';
                    html += `<div class="guardrail-tabs" id="${codeFixId}_tabs">`;
                    finding.code_fix_examples.forEach((ex, idx) => {
                        const activeClass = idx === 0 ? ' active' : '';
                        html += `<button class="guardrail-tab${activeClass}" onclick="switchGuardrailTab('${codeFixId}', ${idx})">${escapeHtml(ex.language)}</button>`;
                    });
                    html += '</div>';
                    finding.code_fix_examples.forEach((ex, idx) => {
                        const activeClass = idx === 0 ? ' active' : '';
                        html += `<div class="guardrail-panel${activeClass}" id="${codeFixId}_panel_${idx}">`;
                        html += `<div class="guardrail-title">${escapeHtml(ex.title)}</div>`;
                        if (ex.description) {
                            html += `<div style="padding:0.5rem 1rem;font-size:0.8rem;color:var(--text-secondary)">${escapeHtml(ex.description)}</div>`;
                        }
                        html += `<div class="guardrail-code">${escapeHtml(ex.code)}</div>`;
                        html += '</div>';
                    });
                    html += '</div>';
                }

                // Compliance mappings
                const badges = [];
                if (finding.cwe_id) badges.push(`<span class="compliance-badge cwe">CWE ${escapeHtml(finding.cwe_id)}</span>`);
                if (finding.owasp_category) badges.push(`<span class="compliance-badge owasp">OWASP ${escapeHtml(finding.owasp_category)}</span>`);
                if (finding.mitre_technique) badges.push(`<span class="compliance-badge mitre">MITRE ${escapeHtml(finding.mitre_technique)}</span>`);

                if (badges.length > 0) {
                    html += '<div class="detail-section"><div class="detail-section-title">Compliance Mappings</div>';
                    html += `<div class="compliance-badges">${badges.join('')}</div></div>`;
                }

                // References
                if (finding.references) {
                    html += '<div class="detail-section"><div class="detail-section-title">References</div>';
                    html += '<div class="reference-links">';
                    // Try to parse references as URLs (comma or newline separated)
                    const refs = finding.references.split(/[,\\n]+/).map(r => r.trim()).filter(r => r);
                    refs.forEach(ref => {
                        if (ref.startsWith('http://') || ref.startsWith('https://')) {
                            html += `<a href="${escapeHtml(ref)}" target="_blank" rel="noopener noreferrer">${escapeHtml(ref)}</a>`;
                        } else {
                            html += `<span style="font-size:0.85rem">${escapeHtml(ref)}</span>`;
                        }
                    });
                    html += '</div></div>';
                }

                document.getElementById('detailBody').innerHTML = html;

            } catch (e) {
                document.getElementById('detailBody').innerHTML = `<div class="empty-state">Failed to load finding: ${escapeHtml(e.message)}</div>`;
                console.error('Failed to load finding detail:', e);
            }
        }

        function switchGuardrailTab(groupId, idx) {
            // Deactivate all tabs and panels in this group
            const tabs = document.querySelectorAll(`#${groupId}_tabs .guardrail-tab`);
            tabs.forEach(t => t.classList.remove('active'));
            tabs[idx].classList.add('active');

            const panels = document.querySelectorAll(`[id^="${groupId}_panel_"]`);
            panels.forEach(p => p.classList.remove('active'));
            const target = document.getElementById(`${groupId}_panel_${idx}`);
            if (target) target.classList.add('active');
        }

        function renderEvidence(evidence) {
            // Parse evidence - could be JSON string or already an array
            let items = evidence;
            if (typeof evidence === 'string') {
                try {
                    items = JSON.parse(evidence);
                } catch (e) {
                    // Not valid JSON, show as preformatted text
                    return `<pre style="background:var(--bg-primary);padding:0.75rem;border-radius:0.375rem;font-size:0.8rem;white-space:pre-wrap;max-height:400px;overflow-y:auto;">${escapeHtml(evidence)}</pre>`;
                }
            }

            if (!Array.isArray(items)) {
                // Single object, wrap in array
                items = [items];
            }

            if (items.length === 0) return '<div style="color:var(--text-secondary)">No evidence recorded</div>';

            let html = '';
            const typeLabels = {
                'prompt': 'Prompt Sent',
                'response': 'Model Response',
                'detection': 'Detection Result',
                'code': 'Code',
                'code_context': 'Code Context',
                'config': 'Configuration',
                'matched_content': 'Matched Content',
                'pattern_match': 'Pattern Match',
                'secret_match': 'Secret Match',
                'file_analysis': 'File Analysis',
                'workflow_analysis': 'Workflow Analysis',
            };

            const typeIcons = {
                'prompt': '&#9654;',
                'response': '&#9664;',
                'detection': '&#9888;',
                'code': '&#128196;',
                'code_context': '&#128209;',
                'config': '&#9881;',
                'matched_content': '&#128270;',
                'pattern_match': '&#127919;',
                'secret_match': '&#128274;',
                'file_analysis': '&#128451;',
                'workflow_analysis': '&#128260;',
            };

            for (const item of items) {
                const evType = (item.type || 'detection').toLowerCase();
                const label = typeLabels[evType] || evType.replace(/_/g, ' ').replace(/\\b\\w/g, c => c.toUpperCase());
                const icon = typeIcons[evType] || '&#8226;';
                const cssClass = evType;

                html += `<div class="evidence-item">`;
                html += `<div class="evidence-item-header ${cssClass}">${icon} ${escapeHtml(label)}</div>`;
                html += `<div class="evidence-item-body">${escapeHtml(item.content || '')}</div>`;

                // Render metadata if present
                if (item.metadata && Object.keys(item.metadata).length > 0) {
                    const metaParts = [];
                    for (const [k, v] of Object.entries(item.metadata)) {
                        metaParts.push(`<strong>${escapeHtml(k)}:</strong> ${escapeHtml(String(v))}`);
                    }
                    html += `<div class="evidence-item-meta">${metaParts.join(' &middot; ')}</div>`;
                }

                html += `</div>`;
            }

            return html;
        }

        function metaItem(label, value) {
            return `<div class="detail-meta-item"><div class="detail-meta-label">${label}</div><div class="detail-meta-value">${value}</div></div>`;
        }

        function openDetailPanel() {
            document.getElementById('detailPanel').classList.add('open');
            document.getElementById('detailOverlay').classList.add('open');
        }

        function closeDetailPanel() {
            document.getElementById('detailPanel').classList.remove('open');
            document.getElementById('detailOverlay').classList.remove('open');
        }

        // ---- Scan Configuration Wizard ----

        let wizState = {
            currentStep: 1,
            targetType: 'deployment',
            targetPath: '',
            targetName: '',
            discoveryData: null,
            selectedComponentTypes: new Set(),
            selectedProfile: 'standard',
            workflowData: null,
        };

        function showScanConfig() {
            document.getElementById('dashboardView').classList.remove('active');
            document.getElementById('scanDetailView').classList.remove('active');
            document.getElementById('topologyView').classList.remove('active');
            document.getElementById('interrogationView').classList.remove('active');
            document.getElementById('scanConfigView').classList.add('active');
            stopAutoRefresh();
            updateNavActive('navScan');
            resetWizard();
            loadAvailableTargets();
        }

        function updateNavActive(id) {
            document.querySelectorAll('.nav-link').forEach(el => el.classList.remove('active'));
            const el = document.getElementById(id);
            if (el) el.classList.add('active');
        }

        function resetWizard() {
            wizState = {
                currentStep: 1,
                targetType: 'deployment',
                targetPath: '',
                targetName: '',
                discoveryData: null,
                selectedComponentTypes: new Set(),
                selectedProfile: 'standard',
                workflowData: null,
            };
            // Reset form inputs
            const pathEl = document.getElementById('wizTargetPath');
            if (pathEl) pathEl.value = '';
            const nameEl = document.getElementById('wizTargetName');
            if (nameEl) nameEl.value = '';
            const selectEl = document.getElementById('wizTargetSelect');
            if (selectEl) selectEl.value = '';
            // Reset radio
            const depRadio = document.querySelector('input[name="targetType"][value="deployment"]');
            if (depRadio) depRadio.checked = true;
            handleTargetTypeChange('deployment');
            // Reset profile
            const stdRadio = document.querySelector('input[name="wizProfile"][value="standard"]');
            if (stdRadio) stdRadio.checked = true;
            updateSkipButton();
            goToStep(1);
        }

        function goToStep(step) {
            document.querySelectorAll('.wizard-panel').forEach(p => p.classList.remove('active'));
            const panel = document.getElementById('scanStep' + step);
            if (panel) panel.classList.add('active');

            document.querySelectorAll('.wizard-step').forEach((el, idx) => {
                const n = idx + 1;
                el.classList.remove('active', 'completed');
                if (n < step) el.classList.add('completed');
                else if (n === step) el.classList.add('active');
            });

            wizState.currentStep = step;
            if (step === 4) populateReview();
        }

        function wizGoBack() {
            const t = wizState.targetType;
            if (t === 'model_endpoint' || t === 'agent_endpoint') {
                goToStep(1);
            } else {
                goToStep(wizState.discoveryData ? 2 : 1);
            }
        }

        // --- Step 1: Target type switching ---

        function handleTargetTypeChange(type) {
            wizState.targetType = type;
            document.getElementById('targetFormPath').style.display = 'none';
            document.getElementById('targetFormModel').style.display = 'none';
            document.getElementById('targetFormAgent').style.display = 'none';

            if (type === 'model_endpoint') {
                document.getElementById('targetFormModel').style.display = 'block';
            } else if (type === 'agent_endpoint') {
                document.getElementById('targetFormAgent').style.display = 'block';
            } else {
                document.getElementById('targetFormPath').style.display = 'block';
            }
            updateSkipButton();
        }

        // Listen for target type radio changes
        document.querySelectorAll('input[name="targetType"]').forEach(r => {
            r.addEventListener('change', e => handleTargetTypeChange(e.target.value));
        });

        // Profile change listener
        document.querySelectorAll('input[name="wizProfile"]').forEach(r => {
            r.addEventListener('change', e => handleProfileChange(e.target.value));
        });

        function toggleAgentAuthToken() {
            const authType = document.getElementById('wizAgentAuthType').value;
            document.getElementById('wizAgentTokenGroup').style.display =
                authType === 'none' ? 'none' : 'block';
        }

        function toggleWorkflowImport() {
            const src = document.getElementById('wizWorkflowSource').value;
            document.getElementById('workflowImportArea').style.display =
                src ? 'block' : 'none';
        }

        // --- Available targets ---

        let availableTargets = [];

        async function loadAvailableTargets() {
            const select = document.getElementById('wizTargetSelect');
            if (!select) return;
            select.innerHTML = '<option value="">Loading...</option>';
            try {
                const res = await fetch(`${V1_API}/discover/targets`, {headers: getAuthHeaders()});
                if (!res.ok) throw new Error('HTTP ' + res.status);
                availableTargets = await res.json();
                select.innerHTML = '<option value="">-- Select a mounted target --</option>';
                if (availableTargets.length === 0) {
                    select.innerHTML += '<option value="" disabled>No targets mounted</option>';
                } else {
                    for (const t of availableTargets) {
                        const badges = [];
                        if (t.has_models) badges.push('models');
                        if (t.has_code) badges.push('code');
                        const info = badges.length ? ' (' + badges.join(', ') + ')' : '';
                        select.innerHTML += '<option value="' + t.path + '">' +
                            t.name + ' - ' + t.file_count + ' files' + info + '</option>';
                    }
                }
                select.innerHTML += '<option value="__custom__">Enter path manually...</option>';
            } catch (e) {
                select.innerHTML = '<option value="">Failed to load targets</option>' +
                    '<option value="__custom__">Enter path manually...</option>';
            }
        }

        function handleTargetSelect(value) {
            const pathEl = document.getElementById('wizTargetPath');
            const nameEl = document.getElementById('wizTargetName');
            if (value === '__custom__' || value === '') {
                if (value === '__custom__' && pathEl) pathEl.focus();
                return;
            }
            if (pathEl) pathEl.value = value;
            // Auto-fill name from target name
            const target = availableTargets.find(t => t.path === value);
            if (target && nameEl && !nameEl.value) {
                nameEl.value = target.name;
            }
        }

        // --- Skip discovery for single-file targets ---

        function updateSkipButton() {
            const btn = document.getElementById('wizSkipDiscoveryBtn');
            if (!btn) return;
            const tt = wizState.targetType;
            const singleFileTypes = ['model_file', 'skill_file', 'instruction_file'];
            btn.style.display = singleFileTypes.includes(tt) ? 'inline-flex' : 'none';
        }

        function skipDiscovery() {
            const path = document.getElementById('wizTargetPath').value.trim();
            if (!path) {
                showWizToast('Please enter a target path', 'error');
                return;
            }
            wizState.targetPath = path;
            wizState.targetName = document.getElementById('wizTargetName').value.trim() ||
                path.split(/[\\/]/).filter(Boolean).pop() || 'Unnamed';
            goToStep(3);
        }

        // --- Step 1 -> 2: Discovery ---

        async function runDiscovery() {
            const path = document.getElementById('wizTargetPath').value.trim();
            if (!path) {
                showWizToast('Please enter a target path', 'error');
                return;
            }
            wizState.targetPath = path;
            wizState.targetName = document.getElementById('wizTargetName').value.trim() ||
                path.split(/[\\/]/).filter(Boolean).pop() || 'Unnamed';

            const spinner = document.getElementById('discoverySpinner');
            spinner.style.display = 'inline-block';

            try {
                const res = await fetch(`${V1_API}/discover`, {
                    method: 'POST',
                    headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                    body: JSON.stringify({ path: path, include_dependencies: true }),
                });

                if (!res.ok) {
                    const err = await res.json().catch(() => ({}));
                    throw new Error(err.detail || 'Discovery failed: HTTP ' + res.status);
                }

                const data = await res.json();
                wizState.discoveryData = data;

                // Pre-select all component types
                wizState.selectedComponentTypes = new Set(
                    Object.keys(data.components_by_type || {})
                );

                populateDiscoveryResults(data);
                goToStep(2);
            } catch (e) {
                showWizToast('Discovery failed: ' + e.message, 'error');
            } finally {
                spinner.style.display = 'none';
            }
        }

        function populateDiscoveryResults(data) {
            document.getElementById('discTotalFiles').textContent = data.total_files || 0;
            document.getElementById('discComponents').textContent = data.total_components || 0;
            document.getElementById('discFrameworks').textContent =
                (data.ai_frameworks || []).length;
            document.getElementById('discModelFiles').textContent =
                (data.model_files || []).length;

            // Recommendation
            const rec = data.recommendation || {};
            document.getElementById('recProfile').textContent =
                (rec.recommended_profile || 'standard').replace(/^\w/, l => l.toUpperCase());
            document.getElementById('recReason').textContent = rec.reason || '';

            // Risk indicators
            const risks = [];
            if (rec.has_secrets_risk) risks.push('<span class="risk-badge">Secrets Risk</span>');
            if (rec.has_models) risks.push('<span class="risk-badge info">Model Files</span>');
            if (rec.has_mcp) risks.push('<span class="risk-badge info">MCP Detected</span>');
            if (rec.has_workflows) risks.push('<span class="risk-badge info">Workflows</span>');
            if (rec.has_infrastructure) risks.push('<span class="risk-badge info">Infrastructure</span>');
            document.getElementById('recRisks').innerHTML = risks.join('');

            // Set recommended profile
            if (rec.recommended_profile) {
                wizState.selectedProfile = rec.recommended_profile;
                const radio = document.querySelector(
                    'input[name="wizProfile"][value="' + rec.recommended_profile + '"]'
                );
                if (radio) radio.checked = true;
            }

            // Frameworks
            const fws = data.ai_frameworks || [];
            if (fws.length > 0) {
                document.getElementById('frameworksSection').style.display = 'block';
                document.getElementById('frameworksList').innerHTML = fws.map(
                    f => '<span class="framework-badge">' + escapeHtml(f) + '</span>'
                ).join('');
            } else {
                document.getElementById('frameworksSection').style.display = 'none';
            }

            // Component types
            const typeLabels = {
                code: 'Code Files', config: 'Configuration', context: 'Context / Prompts',
                infrastructure: 'Infrastructure', knowledge: 'Knowledge Base',
            };
            const grid = document.getElementById('compTypeGrid');
            grid.innerHTML = Object.entries(data.components_by_type || {}).map(([t, c]) =>
                '<label class="component-type-checkbox">' +
                '<input type="checkbox" value="' + t + '" ' +
                (wizState.selectedComponentTypes.has(t) ? 'checked' : '') +
                ' onchange="toggleCompType(&#39;' + t + '&#39;)">' +
                '<div class="component-type-info">' +
                '<span class="component-type-label">' + escapeHtml(typeLabels[t] || t) + '</span>' +
                '<span class="component-type-count">' + c + ' files</span>' +
                '</div></label>'
            ).join('');

            // Mini topology
            renderMiniTopology(data);
        }

        function toggleCompType(type) {
            if (wizState.selectedComponentTypes.has(type)) {
                wizState.selectedComponentTypes.delete(type);
            } else {
                wizState.selectedComponentTypes.add(type);
            }
        }

        function selectAllComponents() {
            document.querySelectorAll('#compTypeGrid input[type="checkbox"]').forEach(cb => {
                cb.checked = true;
                wizState.selectedComponentTypes.add(cb.value);
            });
        }

        function deselectAllComponents() {
            document.querySelectorAll('#compTypeGrid input[type="checkbox"]').forEach(cb => {
                cb.checked = false;
                wizState.selectedComponentTypes.delete(cb.value);
            });
        }

        function renderMiniTopology(data) {
            const group = document.getElementById('miniTopoGroup');
            const comps = data.components || [];
            if (comps.length === 0) {
                document.getElementById('miniTopoSection').style.display = 'none';
                return;
            }

            document.getElementById('miniTopoSection').style.display = 'block';

            // Build simplified nodes from discovery: one per component type + framework
            const nodeMap = {};
            const edges = [];

            // Central AI agent node
            const agentId = 'agent_root';
            nodeMap[agentId] = { id: agentId, type: 'ai_agent', name: wizState.targetName || 'AI Agent' };

            // Add framework nodes
            const fws = data.ai_frameworks || [];
            fws.forEach((fw, i) => {
                const nid = 'fw_' + i;
                nodeMap[nid] = { id: nid, type: 'model_provider', name: fw };
                edges.push({ source: agentId, target: nid, label: 'uses' });
            });

            // Add component type summary nodes
            const typeNodeMap = {
                config: { type: 'cloud_service', name: 'Configuration' },
                context: { type: 'memory', name: 'Context / Prompts' },
                infrastructure: { type: 'cloud_service', name: 'Infrastructure' },
                knowledge: { type: 'database', name: 'Knowledge Base' },
            };
            Object.entries(data.components_by_type || {}).forEach(([t, count]) => {
                if (t === 'code' || count === 0) return;
                const info = typeNodeMap[t];
                if (!info) return;
                const nid = 'ctype_' + t;
                nodeMap[nid] = { id: nid, type: info.type, name: info.name + ' (' + count + ')' };
                edges.push({ source: agentId, target: nid, label: '' });
            });

            // Layout and render using same logic as main topology
            const nodes = Object.values(nodeMap);
            if (nodes.length <= 1) {
                group.innerHTML = '<text x="400" y="125" text-anchor="middle" fill="#94a3b8" font-size="13">No significant architecture detected</text>';
                return;
            }

            const layerMap = {};
            TOPO_LAYER_ORDER.forEach((t, i) => { layerMap[t] = i; });

            const layers = {};
            for (const node of nodes) {
                const layer = layerMap[node.type] !== undefined ? layerMap[node.type] : 5;
                if (!layers[layer]) layers[layer] = [];
                layers[layer].push(node);
            }

            const sortedLayers = Object.keys(layers).map(Number).sort((a, b) => a - b);
            const NW = 130, NH = 40, LGAP = 180, NGAP = 50, PAD = 40;
            const positions = {};
            let maxX = 0, maxY = 0;

            sortedLayers.forEach((li, col) => {
                const ln = layers[li];
                const x = PAD + col * LGAP;
                ln.forEach((node, row) => {
                    const y = PAD + row * (NH + NGAP);
                    positions[node.id] = { x, y, node };
                    maxX = Math.max(maxX, x + NW);
                    maxY = Math.max(maxY, y + NH);
                });
            });

            const svg = document.getElementById('miniTopoSvg');
            svg.setAttribute('viewBox', '0 0 ' + Math.max(maxX + PAD, 600) + ' ' + Math.max(maxY + PAD, 200));

            let html = '';

            // Edges
            for (const edge of edges) {
                const s = positions[edge.source], t = positions[edge.target];
                if (!s || !t) continue;
                const sx = s.x + NW, sy = s.y + NH / 2;
                const tx = t.x, ty = t.y + NH / 2;
                const dx = (tx - sx) / 2;
                html += '<path d="M' + sx + ',' + sy + ' C' + (sx + dx) + ',' + sy + ' ' + (tx - dx) + ',' + ty + ' ' + tx + ',' + ty + '" marker-end="url(#miniArrow)" stroke="#475569" stroke-width="1.5" fill="none" />';
            }

            // Nodes
            for (const id in positions) {
                const { x, y, node } = positions[id];
                const color = TOPO_NODE_COLORS[node.type] || '#64748b';
                const label = node.name.length > 18 ? node.name.slice(0, 16) + '...' : node.name;
                const typeLabel = TOPO_NODE_LABELS[node.type] || node.type;
                html += '<g class="topo-node" transform="translate(' + x + ',' + y + ')">';
                html += '<rect width="' + NW + '" height="' + NH + '" rx="6" ry="6" fill="' + color + '" opacity="0.85" />';
                html += '<text x="' + (NW/2) + '" y="15" class="node-type-label">' + escapeHtml(typeLabel) + '</text>';
                html += '<text x="' + (NW/2) + '" y="30" font-weight="600">' + escapeHtml(label) + '</text>';
                html += '</g>';
            }

            group.innerHTML = html;
        }

        async function importWorkflow() {
            const source = document.getElementById('wizWorkflowSource').value;
            const jsonStr = document.getElementById('wizWorkflowJson').value.trim();
            if (!jsonStr) {
                showWizToast('Paste workflow JSON first', 'error');
                return;
            }
            try {
                const parsed = JSON.parse(jsonStr);
                wizState.workflowData = { format: source, data: parsed };
                showWizToast('Workflow imported. It will be attached after scan creates the deployment.', 'success');
            } catch (e) {
                showWizToast('Invalid JSON: ' + e.message, 'error');
            }
        }

        // --- Step 3: Profile configuration ---

        function handleProfileChange(profile) {
            wizState.selectedProfile = profile;
            document.getElementById('customAnalyzersSection').style.display =
                profile === 'custom' ? 'block' : 'none';

            const showInterrogation = profile === 'comprehensive' || profile === 'quick';
            document.getElementById('interrogationSection').style.display =
                showInterrogation ? 'block' : 'none';
        }

        function getEnabledAnalyzers() {
            const profile = wizState.selectedProfile;
            const profiles = {
                quick: ['deployment_scanner', 'secret_detector', 'model_file_scanner', 'context_analyzer', 'model_interrogator'],
                standard: ['deployment_scanner', 'secret_detector', 'infrastructure_scanner', 'model_file_scanner', 'context_analyzer', 'mcp_analyzer', 'attack_surface_analyzer', 'workflow_analyzer'],
                comprehensive: ['deployment_scanner', 'secret_detector', 'infrastructure_scanner', 'model_file_scanner', 'context_analyzer', 'mcp_analyzer', 'attack_surface_analyzer', 'workflow_analyzer', 'model_interrogator'],
            };

            if (profile === 'custom') {
                const map = {
                    chkDeployment: 'deployment_scanner', chkSecrets: 'secret_detector',
                    chkInfra: 'infrastructure_scanner', chkModelFile: 'model_file_scanner',
                    chkContext: 'context_analyzer', chkMcp: 'mcp_analyzer',
                    chkAttackSurface: 'attack_surface_analyzer', chkWorkflow: 'workflow_analyzer',
                    chkInterrogator: 'model_interrogator',
                };
                return Object.entries(map)
                    .filter(([id]) => document.getElementById(id)?.checked)
                    .map(([, name]) => name);
            }

            return profiles[profile] || profiles.standard;
        }

        // --- Step 4: Review & Launch ---

        function populateReview() {
            const tt = wizState.targetType;
            document.getElementById('revTargetType').textContent =
                tt.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());

            // Name & path
            if (tt === 'model_endpoint') {
                document.getElementById('revTargetName').textContent =
                    document.getElementById('wizModelName').value || 'Model Endpoint';
                const prov = document.getElementById('wizModelProvider').value;
                const model = document.getElementById('wizModelId').value;
                document.getElementById('revTargetPath').textContent = prov + ' / ' + model;
            } else if (tt === 'agent_endpoint') {
                document.getElementById('revTargetName').textContent =
                    document.getElementById('wizAgentName').value || 'Agent Endpoint';
                document.getElementById('revTargetPath').textContent =
                    document.getElementById('wizAgentUrl').value || '-';
            } else {
                document.getElementById('revTargetName').textContent = wizState.targetName || '-';
                document.getElementById('revTargetPath').textContent = wizState.targetPath || '-';
            }

            // Discovery section
            if (wizState.discoveryData) {
                document.getElementById('revDiscoverySection').style.display = 'block';
                document.getElementById('revFiles').textContent = wizState.discoveryData.total_files || 0;
                document.getElementById('revComponents').textContent = wizState.discoveryData.total_components || 0;
                document.getElementById('revSelectedTypes').innerHTML =
                    Array.from(wizState.selectedComponentTypes).map(
                        t => '<span class="badge">' + escapeHtml(t) + '</span>'
                    ).join('');
            } else {
                document.getElementById('revDiscoverySection').style.display = 'none';
            }

            // Profile
            document.getElementById('revProfile').textContent =
                wizState.selectedProfile.replace(/^\w/, l => l.toUpperCase());

            // Analyzers
            const analyzers = getEnabledAnalyzers();
            document.getElementById('revAnalyzers').innerHTML = analyzers.map(
                a => '<span class="badge">' + escapeHtml(a.replace(/_/g, ' ')) + '</span>'
            ).join('');

            // Interrogation
            if (analyzers.includes('model_interrogator')) {
                const cats = Array.from(
                    document.querySelectorAll('#probeCategories input:checked')
                ).map(cb => cb.value);
                document.getElementById('revInterrogation').textContent =
                    cats.length + ' categories, max ' +
                    (document.getElementById('wizMaxProbes').value || 10) + ' probes each';
                document.getElementById('revInterrogationRow').style.display = 'flex';
            } else {
                document.getElementById('revInterrogationRow').style.display = 'none';
            }

            // Duration
            const durations = { quick: '5-10 min', standard: '15-20 min', comprehensive: '30-45 min', custom: '10-30 min' };
            document.getElementById('revDuration').textContent =
                durations[wizState.selectedProfile] || '15-20 min';
        }

        async function launchScan() {
            const btn = document.getElementById('launchScanBtn');
            const spinner = document.getElementById('launchSpinner');
            btn.disabled = true;
            spinner.style.display = 'inline-block';

            try {
                const payload = buildScanPayload();

                const res = await fetch(`${V1_API}/scan-targets`, {
                    method: 'POST',
                    headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                });

                if (!res.ok) {
                    const err = await res.json().catch(() => ({}));
                    throw new Error(err.detail || 'Failed to start scan: HTTP ' + res.status);
                }

                const result = await res.json();

                // If we have workflow data, import it to the deployment topology
                if (wizState.workflowData && result.deployment_id) {
                    try {
                        await fetch(`${V1_API}/deployments/` + result.deployment_id + '/topology/import', {
                            method: 'POST',
                            headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                            body: JSON.stringify(wizState.workflowData),
                        });
                    } catch (e) {
                        console.warn('Workflow import failed:', e);
                    }
                }

                showWizToast('Scan started! Redirecting to dashboard...', 'success');

                setTimeout(() => {
                    showDashboard();
                    loadScans();
                    loadStats();
                }, 1500);

            } catch (e) {
                showWizToast('Launch failed: ' + e.message, 'error');
                btn.disabled = false;
            } finally {
                spinner.style.display = 'none';
            }
        }

        function buildScanPayload() {
            const tt = wizState.targetType;
            const payload = {
                target_type: tt,
                profile: wizState.selectedProfile,
                auto_scan: true,
            };

            if (tt === 'model_endpoint') {
                payload.name = document.getElementById('wizModelName').value || 'Model Endpoint';
                payload.model_provider = document.getElementById('wizModelProvider').value;
                payload.model_name = document.getElementById('wizModelId').value;
                const ep = document.getElementById('wizModelEndpoint').value.trim();
                if (ep) payload.model_endpoint = ep;
                const key = document.getElementById('wizModelApiKey').value.trim();
                if (key) payload.model_api_key = key;
                const sp = document.getElementById('wizModelSystemPrompt').value.trim();
                if (sp) payload.system_prompt = sp;
            } else if (tt === 'agent_endpoint') {
                payload.name = document.getElementById('wizAgentName').value || 'Agent Endpoint';
                payload.agent_url = document.getElementById('wizAgentUrl').value;
                payload.agent_protocol = document.getElementById('wizAgentProtocol').value;
                const authType = document.getElementById('wizAgentAuthType').value;
                if (authType !== 'none') {
                    payload.agent_auth_type = authType;
                    payload.agent_auth_token = document.getElementById('wizAgentAuthToken').value;
                }
            } else {
                payload.name = wizState.targetName || 'Unnamed';
                payload.source_path = wizState.targetPath;

                // Selected component files
                if (wizState.discoveryData && wizState.selectedComponentTypes.size > 0) {
                    const files = (wizState.discoveryData.components || [])
                        .filter(c => wizState.selectedComponentTypes.has(c.component_type))
                        .map(c => c.file_path)
                        .filter(Boolean);
                    if (files.length > 0) payload.target_files = files;
                }
            }

            payload.tags = [tt, wizState.selectedProfile];
            return payload;
        }

        function showWizToast(message, type) {
            const existing = document.querySelector('.export-toast');
            if (existing) existing.remove();
            const toast = document.createElement('div');
            toast.className = 'export-toast ' + type;
            toast.textContent = message;
            document.body.appendChild(toast);
            if (type !== 'loading') setTimeout(() => toast.remove(), 4000);
            return toast;
        }

        // ---- Utility ----

        function escapeHtml(str) {
            if (!str) return '';
            const div = document.createElement('div');
            div.textContent = String(str);
            return div.innerHTML;
        }

        function formatCategory(cat) {
            if (!cat) return 'Unknown';
            return cat.replace(/_/g, ' ').replace(/\\b\\w/g, l => l.toUpperCase());
        }

        function startAutoRefresh() {
            stopAutoRefresh();
            refreshInterval = setInterval(() => {
                loadStats();
                loadScans();
            }, 5000);
        }

        function stopAutoRefresh() {
            if (refreshInterval) {
                clearInterval(refreshInterval);
                refreshInterval = null;
            }
        }

        // ---- WebSocket Real-time Updates ----

        let ws = null;
        let wsReconnectDelay = 1000;
        const WS_MAX_RECONNECT_DELAY = 30000;

        function connectWebSocket() {
            const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${location.host}/ws`;

            try {
                ws = new WebSocket(wsUrl);
            } catch (e) {
                console.debug('WebSocket not available');
                return;
            }

            ws.onopen = () => {
                console.debug('WebSocket connected');
                wsReconnectDelay = 1000;
            };

            ws.onmessage = (event) => {
                try {
                    const msg = JSON.parse(event.data);
                    handleWsMessage(msg);
                } catch (e) {
                    console.debug('Invalid WS message', e);
                }
            };

            ws.onclose = () => {
                console.debug('WebSocket disconnected, reconnecting...');
                setTimeout(connectWebSocket, wsReconnectDelay);
                wsReconnectDelay = Math.min(wsReconnectDelay * 2, WS_MAX_RECONNECT_DELAY);
            };

            ws.onerror = () => {
                ws.close();
            };
        }

        function handleWsMessage(msg) {
            if (msg.type === 'scan_update') {
                updateScanProgress(msg);
            } else if (msg.type === 'new_finding') {
                handleNewFinding(msg);
            } else if (msg.type === 'scan_complete') {
                handleScanComplete(msg);
            }
        }

        function updateScanProgress(msg) {
            // Update progress bar if we're viewing this scan
            if (currentScanData && currentScanData.id === msg.scan_id) {
                const progressBar = document.getElementById('scanProgressBar');
                const progressFill = document.getElementById('scanProgressFill');
                const progressText = document.getElementById('scanProgressText');
                if (progressBar && progressFill) {
                    progressBar.classList.add('active');
                    progressFill.style.width = msg.progress + '%';
                }
                if (progressText) {
                    progressText.classList.add('active');
                    const parts = [];
                    parts.push(Math.round(msg.progress) + '%');
                    if (msg.message) parts.push(msg.message);
                    if (msg.findings_count > 0) parts.push(msg.findings_count + ' findings');
                    progressText.textContent = parts.join(' · ');
                }
                // Update status badge
                const statusEl = document.getElementById('scanDetailStatus');
                if (statusEl) {
                    statusEl.className = 'status ' + msg.status;
                    statusEl.textContent = msg.status;
                }
            }
            // Also refresh the scan list to show updated status
            loadScans();
        }

        function handleNewFinding(msg) {
            if (currentScanData && currentScanData.id === msg.scan_id) {
                // Reload findings for the current scan
                loadScanFindings(msg.scan_id);
            }
            loadStats();
        }

        function handleScanComplete(msg) {
            if (currentScanData && currentScanData.id === msg.scan_id) {
                // Hide progress bar
                const progressBar = document.getElementById('scanProgressBar');
                const progressText = document.getElementById('scanProgressText');
                if (progressBar) progressBar.classList.remove('active');
                if (progressText) progressText.classList.remove('active');

                // Update status
                const statusEl = document.getElementById('scanDetailStatus');
                if (statusEl) {
                    statusEl.className = 'status ' + msg.status;
                    statusEl.textContent = msg.status;
                }
                // Reload full scan detail
                showScanDetail(msg.scan_id);
            }
            loadStats();
            loadScans();
        }

        // Show progress bar when viewing a running scan
        function updateProgressBarVisibility() {
            if (!currentScanData) return;
            const progressBar = document.getElementById('scanProgressBar');
            const progressFill = document.getElementById('scanProgressFill');
            const progressText = document.getElementById('scanProgressText');
            if (currentScanData.status === 'running') {
                if (progressBar) {
                    progressBar.classList.add('active');
                    if (progressFill) {
                        progressFill.style.width = (currentScanData.progress_percent || 0) + '%';
                    }
                }
                if (progressText) {
                    progressText.classList.add('active');
                    const parts = [];
                    parts.push(Math.round(currentScanData.progress_percent || 0) + '%');
                    if (currentScanData.current_phase) parts.push(currentScanData.current_phase);
                    progressText.textContent = parts.join(' · ');
                }
            } else {
                if (progressBar) progressBar.classList.remove('active');
                if (progressText) progressText.classList.remove('active');
            }
        }

        // ---- Topology Visualization ----

        const TOPO_NODE_COLORS = {
            ai_agent:       '#3b82f6',
            model_provider: '#8b5cf6',
            database:       '#22c55e',
            cloud_service:  '#f59e0b',
            mcp_server:     '#06b6d4',
            tool:           '#64748b',
            trigger:        '#f97316',
            api_service:    '#ec4899',
            memory:         '#14b8a6',
            vector_store:   '#10b981',
        };

        const TOPO_NODE_LABELS = {
            ai_agent:       'AI Agent',
            model_provider: 'Model',
            database:       'Database',
            cloud_service:  'Cloud Service',
            mcp_server:     'MCP Server',
            tool:           'Tool',
            trigger:        'Trigger',
            api_service:    'API Service',
            memory:         'Memory',
            vector_store:   'Vector Store',
        };

        // Layer order for left-to-right layout
        const TOPO_LAYER_ORDER = [
            'trigger',
            'ai_agent',
            'model_provider', 'mcp_server', 'cloud_service', 'api_service',
            'database', 'vector_store', 'memory', 'tool',
        ];

        let topoData = null;
        let topoEnv = null;
        let topoDeploymentId = null;
        let topoViewBox = { x: 0, y: 0, w: 1200, h: 600 };

        async function viewTopology() {
            if (!currentScanData) return;

            // We need deployment_id; look it up from scan
            try {
                const res = await fetch(`${V1_API}/scans/${currentScanId}`, {headers: getAuthHeaders()});
                if (!res.ok) return;
                const scanData = await res.json();
                topoDeploymentId = scanData.deployment_id;
            } catch (e) {
                console.error('Could not resolve deployment:', e);
                return;
            }

            if (!topoDeploymentId) return;

            // Fetch topology from dashboard endpoint
            try {
                const res = await fetch(`${API}/deployments/${topoDeploymentId}/topology`, {headers: getAuthHeaders()});
                if (!res.ok) throw new Error('HTTP ' + res.status);
                const data = await res.json();
                topoData = data.topology || { nodes: [], edges: [] };
                topoEnv = data.environment || {};
            } catch (e) {
                console.error('Failed to load topology:', e);
                topoData = { nodes: [], edges: [] };
                topoEnv = {};
            }

            // Switch view
            document.getElementById('dashboardView').classList.remove('active');
            document.getElementById('scanDetailView').classList.remove('active');
            document.getElementById('topologyView').classList.add('active');

            document.getElementById('topoBreadcrumbScan').textContent =
                currentScanData ? currentScanData.target : 'Scan';
            document.getElementById('topoTitle').textContent =
                (currentScanData ? currentScanData.target : 'Deployment') + ' \u2014 Topology';

            renderTopology();
        }

        function returnFromTopology() {
            document.getElementById('topologyView').classList.remove('active');
            if (currentScanId) {
                document.getElementById('scanDetailView').classList.add('active');
            } else {
                showDashboard();
            }
        }

        function renderTopology() {
            const nodes = topoData.nodes || [];
            const edges = topoData.edges || [];

            // Show env badge
            const badge = document.getElementById('topoEnvBadge');
            if (topoEnv.cloud_provider && topoEnv.cloud_provider !== 'unknown') {
                badge.textContent = topoEnv.cloud_provider.toUpperCase();
                badge.style.display = '';
            } else {
                badge.style.display = 'none';
            }

            document.getElementById('topoNodeCount').textContent =
                nodes.length + ' nodes, ' + edges.length + ' edges';

            if (nodes.length === 0) {
                document.getElementById('topoGroup').innerHTML =
                    '<text x="600" y="300" text-anchor="middle" fill="#94a3b8" font-size="14">' +
                    'No topology data. Run a scan to discover the deployment architecture.</text>';
                renderTopoLegend([]);
                return;
            }

            // Assign layers based on node type
            const layerMap = {};
            TOPO_LAYER_ORDER.forEach((t, i) => { layerMap[t] = i; });

            // Group nodes by layer
            const layers = {};
            for (const node of nodes) {
                const layer = layerMap[node.type] !== undefined ? layerMap[node.type] : 5;
                if (!layers[layer]) layers[layer] = [];
                layers[layer].push(node);
            }

            const sortedLayers = Object.keys(layers).map(Number).sort((a, b) => a - b);

            // Layout: assign x/y positions
            const NODE_W = 160;
            const NODE_H = 56;
            const LAYER_GAP = 220;
            const NODE_GAP = 80;
            const PAD = 60;

            const nodePositions = {};
            let maxX = 0;
            let maxY = 0;

            sortedLayers.forEach((layerIdx, col) => {
                const layerNodes = layers[layerIdx];
                const x = PAD + col * LAYER_GAP;
                const totalHeight = layerNodes.length * NODE_H + (layerNodes.length - 1) * NODE_GAP;
                const startY = PAD;

                layerNodes.forEach((node, row) => {
                    const y = startY + row * (NODE_H + NODE_GAP);
                    nodePositions[node.id] = { x, y, node };
                    maxX = Math.max(maxX, x + NODE_W);
                    maxY = Math.max(maxY, y + NODE_H);
                });
            });

            // Center vertically within the tallest column
            const svgH = maxY + PAD;
            const svgW = maxX + PAD;

            topoViewBox = { x: 0, y: 0, w: Math.max(svgW, 800), h: Math.max(svgH, 400) };
            const svg = document.getElementById('topoSvg');
            svg.setAttribute('viewBox', `${topoViewBox.x} ${topoViewBox.y} ${topoViewBox.w} ${topoViewBox.h}`);

            const g = document.getElementById('topoGroup');
            let svgContent = '';

            // Draw edges first (behind nodes)
            for (const edge of edges) {
                const src = nodePositions[edge.source];
                const tgt = nodePositions[edge.target];
                if (!src || !tgt) continue;

                const sx = src.x + NODE_W;
                const sy = src.y + NODE_H / 2;
                const tx = tgt.x;
                const ty = tgt.y + NODE_H / 2;

                // Curved path
                const dx = (tx - sx) / 2;
                const path = `M${sx},${sy} C${sx + dx},${sy} ${tx - dx},${ty} ${tx},${ty}`;
                const midX = (sx + tx) / 2;
                const midY = (sy + ty) / 2 - 10;

                svgContent += `<g class="topo-edge">`;
                svgContent += `<path d="${path}" marker-end="url(#arrowhead)" />`;
                if (edge.label) {
                    svgContent += `<text x="${midX}" y="${midY}" text-anchor="middle">${escapeHtml(edge.label)}</text>`;
                }
                svgContent += `</g>`;
            }

            // Draw nodes
            for (const id in nodePositions) {
                const { x, y, node } = nodePositions[id];
                const color = TOPO_NODE_COLORS[node.type] || '#64748b';
                const typeLabel = TOPO_NODE_LABELS[node.type] || node.type;
                const displayName = node.name.length > 20 ? node.name.slice(0, 18) + '\u2026' : node.name;

                svgContent += `<g class="topo-node" onclick="selectTopoNode('${escapeHtml(node.id)}')" transform="translate(${x},${y})">`;
                svgContent += `<rect width="${NODE_W}" height="${NODE_H}" fill="${color}" stroke="${color}" opacity="0.85" />`;
                svgContent += `<text x="${NODE_W/2}" y="22" class="node-type-label">${escapeHtml(typeLabel)}</text>`;
                svgContent += `<text x="${NODE_W/2}" y="40" font-weight="600">${escapeHtml(displayName)}</text>`;
                svgContent += `</g>`;
            }

            g.innerHTML = svgContent;

            // Legend
            const usedTypes = [...new Set(nodes.map(n => n.type))];
            renderTopoLegend(usedTypes);

            // Show topology button on scan detail if data exists
            const topoBtn = document.getElementById('topoBtn');
            if (topoBtn) topoBtn.style.display = '';
        }

        function renderTopoLegend(types) {
            const legend = document.getElementById('topoLegend');
            legend.innerHTML = types.map(t =>
                `<span class="topo-legend-item"><span class="topo-legend-dot" style="background:${TOPO_NODE_COLORS[t] || '#64748b'}"></span>${TOPO_NODE_LABELS[t] || t}</span>`
            ).join('');
        }

        function selectTopoNode(nodeId) {
            if (!topoData) return;
            const node = topoData.nodes.find(n => n.id === nodeId);
            if (!node) return;

            const panel = document.getElementById('topoNodePanel');
            document.getElementById('topoNodePanelTitle').textContent = node.name;

            let html = '';
            html += `<span class="label">Type</span><span>${escapeHtml(TOPO_NODE_LABELS[node.type] || node.type)}</span>`;
            if (node.provider) {
                html += `<span class="label">Provider</span><span>${escapeHtml(node.provider)}</span>`;
            }

            // Show metadata entries
            if (node.metadata) {
                for (const [k, v] of Object.entries(node.metadata)) {
                    if (v === null || v === undefined || v === '') continue;
                    const display = typeof v === 'object' ? JSON.stringify(v) : String(v);
                    html += `<span class="label">${escapeHtml(k.replace(/_/g, ' '))}</span><span>${escapeHtml(display)}</span>`;
                }
            }

            document.getElementById('topoNodePanelBody').innerHTML = html;
            panel.classList.add('open');
        }

        function closeTopoNodePanel() {
            document.getElementById('topoNodePanel').classList.remove('open');
        }

        // Pan/zoom
        function topoZoomIn() {
            topoViewBox.w *= 0.8;
            topoViewBox.h *= 0.8;
            applyTopoViewBox();
        }

        function topoZoomOut() {
            topoViewBox.w *= 1.25;
            topoViewBox.h *= 1.25;
            applyTopoViewBox();
        }

        function topoFitView() {
            // Reset to computed bounds
            renderTopology();
        }

        function applyTopoViewBox() {
            const svg = document.getElementById('topoSvg');
            svg.setAttribute('viewBox', `${topoViewBox.x} ${topoViewBox.y} ${topoViewBox.w} ${topoViewBox.h}`);
        }

        // Mouse-drag panning on SVG
        (function() {
            let dragging = false, startX = 0, startY = 0, startVBx = 0, startVBy = 0;
            const wrap = () => document.getElementById('topoSvgWrap');

            document.addEventListener('mousedown', function(e) {
                const w = wrap();
                if (!w || !w.contains(e.target)) return;
                if (e.target.closest('.topo-node')) return; // don't pan when clicking node
                dragging = true;
                startX = e.clientX;
                startY = e.clientY;
                startVBx = topoViewBox.x;
                startVBy = topoViewBox.y;
            });

            document.addEventListener('mousemove', function(e) {
                if (!dragging) return;
                const svg = document.getElementById('topoSvg');
                if (!svg) return;
                const rect = svg.getBoundingClientRect();
                const scaleX = topoViewBox.w / rect.width;
                const scaleY = topoViewBox.h / rect.height;
                topoViewBox.x = startVBx - (e.clientX - startX) * scaleX;
                topoViewBox.y = startVBy - (e.clientY - startY) * scaleY;
                applyTopoViewBox();
            });

            document.addEventListener('mouseup', function() { dragging = false; });
        })();

        // Check if topology exists when viewing a scan and show the button
        async function checkTopologyAvailable() {
            if (!currentScanId) return;
            try {
                const res = await fetch(`${V1_API}/scans/${currentScanId}`, {headers: getAuthHeaders()});
                if (!res.ok) return;
                const scanData = await res.json();
                if (!scanData.deployment_id) return;

                const topoRes = await fetch(`${API}/deployments/${scanData.deployment_id}/topology`, {headers: getAuthHeaders()});
                if (!topoRes.ok) return;
                const data = await topoRes.json();
                const topo = data.topology || {};

                const btn = document.getElementById('topoBtn');
                if (btn && topo.nodes && topo.nodes.length > 0) {
                    btn.style.display = '';
                }
            } catch (e) {
                // Silently ignore
            }
        }

        // ---- Interrogation ----

        let intPollingInterval = null;

        function showInterrogation() {
            document.getElementById('dashboardView').classList.remove('active');
            document.getElementById('scanDetailView').classList.remove('active');
            document.getElementById('topologyView').classList.remove('active');
            document.getElementById('scanConfigView').classList.remove('active');
            document.getElementById('interrogationView').classList.add('active');
            updateNavActive('navInterrogate');
            stopAutoRefresh();
            refreshOllamaModels();
            refreshIntJobs();
        }

        async function refreshOllamaModels() {
            const el = document.getElementById('ollamaModelList');
            try {
                const res = await fetch(`${INT_API}/models`, {headers: getAuthHeaders()});
                if (!res.ok) { el.textContent = 'Failed to load'; return; }
                const models = await res.json();
                if (models.length === 0) {
                    el.innerHTML = '<div style="color:var(--warning)">No models found. Run: <code>ollama pull llama3.1:8b</code></div>';
                    return;
                }
                el.innerHTML = models.map(m =>
                    '<div style="display:flex;justify-content:space-between;padding:0.3rem 0;border-bottom:1px solid var(--bg-tertiary)">' +
                    '<span style="color:var(--text-primary);cursor:pointer" onclick="selectOllamaModel(&#39;' + escapeHtml(m.name) + '&#39;)">' + escapeHtml(m.name) + ' <small style="color:var(--text-secondary)">(' + m.instance + ')</small></span>' +
                    '<span style="color:var(--text-secondary)">' + escapeHtml(m.size) + '</span>' +
                    '</div>'
                ).join('');
            } catch (e) {
                el.textContent = 'Ollama not available';
            }
        }

        function selectOllamaModel(name) {
            // Smart fill: if target is empty, fill target; else fill attacker
            const targetModel = document.getElementById('intTargetModel');
            const attackerModel = document.getElementById('intAttackerModel');
            if (!targetModel.value) {
                targetModel.value = name;
                document.getElementById('intTargetProvider').value = 'ollama';
            } else if (!attackerModel.value) {
                attackerModel.value = name;
                document.getElementById('intAttackerProvider').value = 'ollama';
            } else {
                attackerModel.value = name;
                document.getElementById('intAttackerProvider').value = 'ollama';
            }
        }

        function onIntProviderChange(role) {
            const prefix = role === 'target' ? 'intTarget' : 'intAttacker';
            const provider = document.getElementById(prefix + 'Provider').value;
            const modelInput = document.getElementById(prefix + 'Model');
            const endpointInput = document.getElementById(prefix + 'Endpoint');
            const apiKeyInput = document.getElementById(prefix + 'ApiKey');

            // Set defaults based on provider
            if (provider === 'ollama') {
                endpointInput.placeholder = 'http://ollama:11434 (auto)';
                apiKeyInput.placeholder = 'Not needed for Ollama';
                if (!modelInput.value) modelInput.placeholder = 'e.g., llama3.1:8b';
            } else if (provider === 'openai') {
                endpointInput.placeholder = 'https://api.openai.com/v1 (default)';
                apiKeyInput.placeholder = 'sk-...';
                if (!modelInput.value) modelInput.placeholder = 'e.g., gpt-4o-mini';
            } else if (provider === 'anthropic') {
                endpointInput.placeholder = 'https://api.anthropic.com (default)';
                apiKeyInput.placeholder = 'sk-ant-...';
                if (!modelInput.value) modelInput.placeholder = 'e.g., claude-sonnet-4-5-20250929';
            } else {
                endpointInput.placeholder = 'Endpoint URL';
                apiKeyInput.placeholder = 'API Key';
            }
        }

        async function startInterrogation() {
            const btn = document.getElementById('intStartBtn');
            const spinner = document.getElementById('intSpinner');
            btn.disabled = true;
            spinner.style.display = 'inline-block';

            const categories = [];
            document.querySelectorAll('#intCategories input:checked').forEach(cb => {
                categories.push(cb.value);
            });

            const payload = {
                name: 'Dashboard Interrogation',
                target: {
                    provider: document.getElementById('intTargetProvider').value,
                    model: document.getElementById('intTargetModel').value,
                    endpoint: document.getElementById('intTargetEndpoint').value || null,
                    api_key: document.getElementById('intTargetApiKey').value || null,
                },
                attacker: {
                    provider: document.getElementById('intAttackerProvider').value,
                    model: document.getElementById('intAttackerModel').value,
                    endpoint: document.getElementById('intAttackerEndpoint').value || null,
                    api_key: document.getElementById('intAttackerApiKey').value || null,
                },
                target_system_prompt: document.getElementById('intTargetSystemPrompt').value || null,
                categories: categories.length > 0 ? categories : null,
                max_turns: parseInt(document.getElementById('intMaxTurns').value) || 8,
                max_strategies_per_agent: parseInt(document.getElementById('intMaxStrategies').value) || 0,
            };

            if (!payload.target.model || !payload.attacker.model) {
                alert('Please specify both target and attacker model names');
                btn.disabled = false;
                spinner.style.display = 'none';
                return;
            }

            try {
                const res = await fetch(`${INT_API}/jobs`, {
                    method: 'POST',
                    headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                });
                if (!res.ok) {
                    const err = await res.json().catch(() => ({}));
                    alert('Failed: ' + (err.detail || res.statusText));
                    return;
                }
                const data = await res.json();
                showToast('Interrogation started: ' + data.job_id.slice(0, 8));
                startIntPolling();
                refreshIntJobs();
            } catch (e) {
                alert('Error: ' + e.message);
            } finally {
                btn.disabled = false;
                spinner.style.display = 'none';
            }
        }

        function startIntPolling() {
            if (intPollingInterval) clearInterval(intPollingInterval);
            intPollingInterval = setInterval(refreshIntJobs, 5000);
        }

        async function refreshIntJobs() {
            const el = document.getElementById('intJobsList');
            try {
                const res = await fetch(`${INT_API}/jobs`, {headers: getAuthHeaders()});
                if (!res.ok) return;
                const jobs = await res.json();
                if (jobs.length === 0) { el.textContent = 'No jobs yet'; return; }

                // Check if any are still running
                const hasRunning = jobs.some(j => j.status === 'running' || j.status === 'pending');
                if (!hasRunning && intPollingInterval) {
                    clearInterval(intPollingInterval);
                    intPollingInterval = null;
                }

                el.innerHTML = jobs.map(j =>
                    '<div class="int-job-card" onclick="viewIntJob(&#39;' + j.job_id + '&#39;)">' +
                    '<div style="display:flex;justify-content:space-between;align-items:center">' +
                    '<span style="font-weight:600;font-size:0.8rem">' + escapeHtml(j.job_id.slice(0,8)) + '</span>' +
                    '<span class="status-badge ' + j.status + '">' + j.status + '</span>' +
                    '</div>' +
                    '<div style="margin-top:0.35rem;color:var(--text-secondary);font-size:0.8rem">' +
                    escapeHtml(j.attacker_model) + ' &rarr; ' + escapeHtml(j.target_model) +
                    '</div>' +
                    '<div style="margin-top:0.2rem;font-size:0.75rem;color:var(--text-secondary)">' +
                    j.strategies_run + ' strategies, ' + j.successful_attacks + ' successful' +
                    (j.duration_seconds ? ' (' + j.duration_seconds.toFixed(1) + 's)' : '') +
                    '</div></div>'
                ).join('');
            } catch (e) {
                // ignore
            }
        }

        async function viewIntJob(jobId) {
            const viewer = document.getElementById('intConversationViewer');
            viewer.style.display = 'block';
            document.getElementById('intConvTitle').textContent = 'Loading...';
            document.getElementById('intConvSummary').innerHTML = '';
            document.getElementById('intConvTranscript').innerHTML = '';

            try {
                const res = await fetch(`${INT_API}/jobs/${jobId}`, {headers: getAuthHeaders()});
                if (!res.ok) { document.getElementById('intConvTitle').textContent = 'Error loading job'; return; }
                const job = await res.json();

                document.getElementById('intConvTitle').textContent =
                    'Interrogation: ' + escapeHtml(job.attacker_model) + ' vs ' + escapeHtml(job.target_model);

                // Summary
                let summaryHtml = '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;">';
                summaryHtml += '<div class="stat-card"><div class="stat-value">' + job.strategies_run + '</div><div class="stat-label">Strategies</div></div>';
                summaryHtml += '<div class="stat-card"><div class="stat-value" style="color:#ef4444">' + job.successful_attacks + '</div><div class="stat-label">Successful Attacks</div></div>';
                summaryHtml += '<div class="stat-card"><div class="stat-value" style="color:#22c55e">' + job.failed_attacks + '</div><div class="stat-label">Defended</div></div>';
                summaryHtml += '<div class="stat-card"><div class="stat-value">' + job.duration_seconds.toFixed(1) + 's</div><div class="stat-label">Duration</div></div>';
                summaryHtml += '</div>';

                // Findings summary
                if (job.findings && job.findings.length > 0) {
                    summaryHtml += '<div style="margin-top:1rem;"><h4 style="font-size:0.85rem;margin:0 0 0.5rem;">Findings</h4>';
                    job.findings.forEach(f => {
                        summaryHtml += '<div style="padding:0.5rem;border-radius:0.375rem;border:1px solid var(--bg-tertiary);margin-bottom:0.35rem;">' +
                            '<span class="severity ' + f.severity + '">' + f.severity + '</span> ' +
                            '<strong>' + escapeHtml(f.title) + '</strong>' +
                            '<div style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.2rem;">' +
                            escapeHtml(f.category) + ' | confidence: ' + (f.confidence * 100).toFixed(0) + '% | ' + f.total_turns + ' turns</div>' +
                            '</div>';
                    });
                    summaryHtml += '</div>';
                }
                document.getElementById('intConvSummary').innerHTML = summaryHtml;

                // Conversations
                let transcriptHtml = '';
                if (job.conversations && job.conversations.length > 0) {
                    job.conversations.forEach((conv, ci) => {
                        const statusIcon = conv.success ? '&#x2717;' : '&#x2713;';
                        const statusColor = conv.success ? '#ef4444' : '#22c55e';
                        transcriptHtml += '<div style="margin-top:' + (ci > 0 ? '1.5rem' : '0') + ';padding-bottom:0.75rem;border-bottom:1px solid var(--bg-tertiary)">';
                        transcriptHtml += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;">';
                        transcriptHtml += '<div><strong>' + escapeHtml(conv.category) + '</strong> / ' + escapeHtml(conv.strategy) + '</div>';
                        transcriptHtml += '<div style="color:' + statusColor + ';font-weight:600">' + statusIcon + ' ' + (conv.success ? 'BREACHED' : 'DEFENDED') +
                            ' (' + (conv.confidence * 100).toFixed(0) + '%)</div>';
                        transcriptHtml += '</div>';
                        if (conv.analysis) {
                            transcriptHtml += '<div style="font-size:0.8rem;color:var(--text-secondary);margin-bottom:0.5rem;font-style:italic">' + escapeHtml(conv.analysis) + '</div>';
                        }
                        conv.turns.forEach(t => {
                            transcriptHtml += '<div class="int-turn ' + t.role + '">';
                            transcriptHtml += '<div class="int-turn-header">' + escapeHtml(t.role) +
                                (t.model ? ' (' + escapeHtml(t.model) + ')' : '') +
                                ' — Turn ' + t.turn_number;
                            if (t.latency_ms > 0) transcriptHtml += ' (' + t.latency_ms.toFixed(0) + 'ms)';
                            transcriptHtml += '</div>';
                            transcriptHtml += '<div>' + escapeHtml(t.content).replace(/\\n/g, '<br>') + '</div>';
                            transcriptHtml += '</div>';
                        });
                        transcriptHtml += '</div>';
                    });
                }
                document.getElementById('intConvTranscript').innerHTML = transcriptHtml || '<div style="color:var(--text-secondary)">No conversations yet</div>';

                viewer.scrollIntoView({ behavior: 'smooth' });
            } catch (e) {
                document.getElementById('intConvTitle').textContent = 'Error: ' + e.message;
            }
        }

        // ---- Init ----

        if (getApiKey()) {
            loadStats();
            loadScans();
            startAutoRefresh();
        }
        connectWebSocket();

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                closeDetailPanel();
            }
        });
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
