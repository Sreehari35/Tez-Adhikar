"""
Clean, Modern Multi-Page UI for Tez Adhikar — Access Control & Audit Service.
Brand Palette based on Nagarkot Forwarders Pvt. Ltd. (https://nagarkot.co.in/):
- Primary Corporate Navy: #0B3056 / #002B49
- Secondary Logistics Ocean Blue: #00A3E0 / #0284C7
- Crisp Light Slate Background: #F8FAFC
- Elevated Pure White Cards: #FFFFFF with subtle border #E2E8F0
- High Contrast Slate Text: #0F172A, Muted: #475569, Dim: #64748B
- Embedded Logo: /logo.jpg

Architecture:
- Isolates all JavaScript as raw string constants (r'''<script>...</script>''') to eliminate Python f-string escaping bugs.
- Generates clean semantic HTML with zero external dependencies.
"""

import json
import sqlite3
from typing import Dict, Any, Optional, List

from app.db import get_grants_version

# --- Shared Base Styles (Plain string without f-string) ---
SHARED_CSS = """
    :root {
      --bg: #f8fafc;
      --card-bg: #ffffff;
      --card-hover: #f1f5f9;
      --border: #e2e8f0;
      --border-focus: #00a3e0;
      --text-main: #0f172a;
      --text-muted: #475569;
      --text-dim: #64748b;
      --primary: #0b3056;
      --primary-accent: #00a3e0;
      --primary-glow: rgba(0, 163, 224, 0.1);
      --success: #059669;
      --success-glow: rgba(5, 150, 105, 0.1);
      --danger: #dc2626;
      --danger-glow: rgba(220, 38, 38, 0.1);
      --warning: #d97706;
      --purple: #7c3aed;
      --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      --radius-sm: 6px;
      --radius-md: 10px;
      --radius-lg: 14px;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text-main);
      font-family: var(--font-sans);
      min-height: 100vh;
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
      display: flex;
      flex-direction: column;
    }

    code {
      font-family: var(--font-mono);
      font-size: 0.85em;
      background: #f1f5f9;
      color: var(--primary);
      padding: 0.15em 0.35em;
      border-radius: 4px;
      border: 1px solid #e2e8f0;
    }

    /* Top Navigation Header */
    .app-header {
      background: #ffffff;
      border-bottom: 1px solid var(--border);
      position: sticky;
      top: 0;
      z-index: 100;
      box-shadow: 0 2px 10px rgba(11, 48, 86, 0.05);
    }
    .header-inner {
      max-width: 1280px;
      margin: 0 auto;
      padding: 0.75rem 1.5rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
    }
    .brand-wrap {
      display: flex;
      align-items: center;
      gap: 0.85rem;
      text-decoration: none;
    }
    .brand-logo-img {
      height: 48px;
      width: auto;
      object-fit: contain;
      border-radius: 6px;
      box-shadow: 0 2px 6px rgba(0,0,0,0.06);
    }
    .brand-title {
      font-size: 1.22rem;
      font-weight: 800;
      color: #0b3056;
      letter-spacing: -0.01em;
      line-height: 1.15;
    }
    .brand-subtitle {
      font-size: 0.75rem;
      color: var(--text-muted);
      letter-spacing: 0.01em;
      font-weight: 500;
    }

    /* Navigation Links */
    .nav-links {
      display: flex;
      align-items: center;
      gap: 0.35rem;
      flex-wrap: wrap;
    }
    .nav-link {
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      padding: 0.5rem 0.85rem;
      font-size: 0.86rem;
      font-weight: 600;
      color: var(--text-muted);
      text-decoration: none;
      border-radius: var(--radius-sm);
      transition: all 0.2s;
    }
    .nav-link:hover {
      color: var(--primary);
      background: #f1f5f9;
    }
    .nav-link.active {
      color: var(--primary);
      background: rgba(0, 163, 224, 0.09);
      font-weight: 700;
      box-shadow: inset 0 -2px 0 var(--border-focus);
    }

    .header-badges {
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      padding: 0.25rem 0.65rem;
      border-radius: 9999px;
      font-size: 0.72rem;
      font-weight: 600;
      letter-spacing: 0.02em;
      border: 1px solid transparent;
      text-decoration: none;
    }
    .pill-live {
      background: #ecfdf5;
      color: #047857;
      border-color: #a7f3d0;
    }
    .pulse-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: #059669;
      box-shadow: 0 0 6px #059669;
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.4; transform: scale(0.85); }
    }

    /* Main Container */
    .main-wrap {
      max-width: 1280px;
      margin: 1.5rem auto 3rem auto;
      padding: 0 1.5rem;
      flex: 1;
      width: 100%;
    }

    /* Cards & Containers */
    .surface-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      padding: 1.75rem;
      margin-bottom: 1.5rem;
      box-shadow: 0 1px 4px rgba(0, 0, 0, 0.04);
    }
    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1.25rem;
      flex-wrap: wrap;
      gap: 0.75rem;
    }
    .card-title {
      font-size: 1.15rem;
      font-weight: 800;
      color: #0b3056;
      letter-spacing: -0.01em;
    }
    .card-desc {
      font-size: 0.82rem;
      color: var(--text-muted);
      margin-top: 0.2rem;
    }

    /* Metric Cards */
    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }
    .metric-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      padding: 1.1rem 1.25rem;
      position: relative;
      overflow: hidden;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04);
      transition: border-color 0.2s, transform 0.2s, box-shadow 0.2s;
      text-decoration: none;
      color: inherit;
      display: block;
    }
    .metric-card:hover {
      border-color: #00a3e0;
      transform: translateY(-1px);
      box-shadow: 0 4px 12px rgba(0, 163, 224, 0.08);
    }
    .metric-card::after {
      content: "";
      position: absolute;
      top: 0; left: 0; right: 0; height: 3px;
      background: linear-gradient(90deg, #0b3056, #00a3e0);
      opacity: 0.85;
    }
    .metric-label {
      font-size: 0.75rem;
      text-transform: uppercase;
      font-weight: 700;
      color: var(--text-muted);
      letter-spacing: 0.05em;
    }
    .metric-val {
      font-size: 1.85rem;
      font-weight: 800;
      color: #0b3056;
      margin: 0.3rem 0 0.1rem 0;
      letter-spacing: -0.02em;
    }
    .metric-meta {
      font-size: 0.75rem;
      color: var(--text-dim);
    }

    /* Feature Nav Cards */
    .features-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }
    .feature-nav-card {
      background: #ffffff;
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      padding: 1.25rem;
      text-decoration: none;
      color: inherit;
      transition: all 0.2s;
      display: flex;
      flex-direction: column;
      gap: 0.4rem;
    }
    .feature-nav-card:hover {
      border-color: var(--border-focus);
      background: #f0f9ff;
      transform: translateY(-2px);
      box-shadow: 0 4px 14px rgba(0, 163, 224, 0.1);
    }
    .feature-nav-title {
      font-size: 1rem;
      font-weight: 700;
      color: #0b3056;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .feature-nav-desc {
      font-size: 0.8rem;
      color: var(--text-muted);
      line-height: 1.4;
    }
    .feature-nav-cta {
      margin-top: 0.5rem;
      font-size: 0.78rem;
      font-weight: 700;
      color: var(--primary-accent);
      display: inline-flex;
      align-items: center;
      gap: 0.25rem;
    }

    /* Form Controls */
    .form-row {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1rem;
      margin-bottom: 1.25rem;
    }
    .field-group {
      display: flex;
      flex-direction: column;
      gap: 0.35rem;
    }
    .field-label {
      font-size: 0.78rem;
      font-weight: 700;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    .form-input, .form-select {
      background: #ffffff;
      border: 1px solid #cbd5e1;
      border-radius: var(--radius-sm);
      color: #0f172a;
      font-size: 0.9rem;
      padding: 0.65rem 0.85rem;
      outline: none;
      transition: border-color 0.2s, box-shadow 0.2s;
      width: 100%;
    }
    .form-input:focus, .form-select:focus {
      border-color: #00a3e0;
      box-shadow: 0 0 0 3px rgba(0, 163, 224, 0.15);
    }
    .action-btn {
      background: linear-gradient(135deg, #0b3056, #00a3e0);
      color: #fff;
      border: none;
      border-radius: var(--radius-sm);
      font-family: inherit;
      font-size: 0.88rem;
      font-weight: 700;
      padding: 0.65rem 1.4rem;
      cursor: pointer;
      transition: all 0.2s;
      box-shadow: 0 2px 8px rgba(11, 48, 86, 0.2);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.45rem;
      text-decoration: none;
    }
    .action-btn:hover {
      background: linear-gradient(135deg, #002b49, #0284c7);
      box-shadow: 0 4px 12px rgba(11, 48, 86, 0.3);
      transform: translateY(-1px);
    }
    .action-btn-secondary {
      background: #f1f5f9;
      color: #334155;
      border: 1px solid #cbd5e1;
      box-shadow: none;
    }
    .action-btn-secondary:hover {
      background: #e2e8f0;
      color: #0f172a;
      border-color: #94a3b8;
    }
    .action-btn-sm {
      padding: 0.35rem 0.75rem;
      font-size: 0.78rem;
    }

    /* Decision Result Box */
    .decision-panel {
      margin-top: 1.5rem;
      background: #f8fafc;
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      padding: 1.25rem;
      animation: fadeIn 0.3s ease;
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(6px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .decision-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
      padding-bottom: 0.85rem;
      border-bottom: 1px solid var(--border);
      margin-bottom: 0.85rem;
    }
    .badge-decision {
      font-size: 1.2rem;
      font-weight: 800;
      padding: 0.35rem 1.1rem;
      border-radius: var(--radius-sm);
      letter-spacing: 0.05em;
    }
    .badge-allow {
      background: #ecfdf5;
      color: #065f46;
      border: 1px solid #34d399;
    }
    .badge-deny {
      background: #fef2f2;
      color: #991b1b;
      border: 1px solid #f87171;
    }

    .receipt-code {
      background: #0f172a;
      border: 1px solid #1e293b;
      border-radius: var(--radius-sm);
      padding: 0.85rem;
      font-family: var(--font-mono);
      font-size: 0.8rem;
      color: #38bdf8;
      overflow-x: auto;
      max-height: 320px;
    }

    /* Tables */
    .data-table-wrap {
      overflow-x: auto;
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      background: #ffffff;
    }
    table.data-table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 0.85rem;
    }
    table.data-table th {
      background: #f8fafc;
      color: #475569;
      font-size: 0.74rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      padding: 0.85rem 1rem;
      border-bottom: 1px solid var(--border);
    }
    table.data-table td {
      padding: 0.85rem 1rem;
      border-bottom: 1px solid #f1f5f9;
      color: #1e293b;
      vertical-align: middle;
    }
    table.data-table tr:hover td {
      background: #f8fafc;
    }

    /* Stage Badges */
    .badge-stage {
      padding: 0.2rem 0.55rem;
      border-radius: 4px;
      font-size: 0.72rem;
      font-weight: 700;
      font-family: var(--font-mono);
      display: inline-block;
    }
    .stage-Confirmed { background: #e0f2fe; color: #0369a1; border: 1px solid #bae6fd; }
    .stage-Prepared  { background: #fef3c7; color: #b45309; border: 1px solid #fde68a; }
    .stage-Checked   { background: #f3e8ff; color: #7e22ce; border: 1px solid #e9d5ff; }
    .stage-Filed     { background: #d1fae5; color: #047857; border: 1px solid #a7f3d0; }
    .stage-Cancelled { background: #ffe4e6; color: #be123c; border: 1px solid #fecdd3; }
    .stage-Reopened  { background: #e0f2fe; color: #0284c7; border: 1px solid #bae6fd; }

    .badge-redacted {
      background: #fee2e2;
      color: #991b1b;
      padding: 0.15rem 0.4rem;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: 700;
      font-family: var(--font-mono);
    }

    /* Timeline & Audit Logs */
    .timeline {
      position: relative;
      padding-left: 2rem;
      margin-top: 1.5rem;
    }
    .timeline::before {
      content: "";
      position: absolute;
      top: 0; bottom: 0; left: 11px;
      width: 2px;
      background: #cbd5e1;
    }
    .timeline-item {
      position: relative;
      margin-bottom: 1.5rem;
    }
    .timeline-icon {
      position: absolute;
      left: -2rem;
      top: 2px;
      width: 24px;
      height: 24px;
      border-radius: 50%;
      background: #ffffff;
      border: 2px solid var(--border-focus);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 0.7rem;
      font-weight: bold;
    }
    .timeline-card {
      background: #ffffff;
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 1rem 1.25rem;
      box-shadow: 0 1px 3px rgba(0,0,0,0.03);
    }
    .timeline-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 0.5rem;
      margin-bottom: 0.5rem;
    }
    .timeline-title {
      font-weight: 700;
      color: #0b3056;
      font-size: 0.92rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .timeline-time {
      font-size: 0.75rem;
      color: var(--text-dim);
    }
    .timeline-desc {
      font-size: 0.84rem;
      color: #334155;
      margin-bottom: 0.5rem;
    }
    .timeline-meta {
      display: flex;
      gap: 0.75rem;
      align-items: center;
      font-size: 0.75rem;
      color: var(--text-dim);
      font-family: var(--font-mono);
      background: #f8fafc;
      padding: 0.4rem 0.6rem;
      border-radius: 4px;
      border: 1px solid #e2e8f0;
      flex-wrap: wrap;
    }

    /* Scenario Quick Buttons */
    .scenario-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 0.75rem;
      margin-bottom: 1.5rem;
    }
    .scenario-btn {
      background: #f8fafc;
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 0.75rem 1rem;
      text-align: left;
      cursor: pointer;
      transition: all 0.2s;
      font-family: inherit;
    }
    .scenario-btn:hover {
      border-color: #00a3e0;
      background: #f0f9ff;
      transform: translateY(-1px);
      box-shadow: 0 2px 8px rgba(0, 163, 224, 0.12);
    }
    .scenario-btn-title {
      font-size: 0.82rem;
      font-weight: 700;
      color: #0b3056;
      display: flex;
      align-items: center;
      gap: 0.4rem;
    }
    .scenario-btn-desc {
      font-size: 0.74rem;
      color: var(--text-muted);
      margin-top: 0.25rem;
    }

    /* Compare Grid */
    .compare-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1.25rem;
      margin-top: 1rem;
    }
    @media (max-width: 768px) {
      .compare-grid { grid-template-columns: 1fr; }
    }
    .compare-col {
      background: #f8fafc;
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      padding: 1.25rem;
    }

    /* Footer */
    footer {
      border-top: 1px solid var(--border);
      background: #ffffff;
      padding: 1.5rem 0;
      margin-top: auto;
      color: var(--text-dim);
      font-size: 0.82rem;
      text-align: center;
    }
"""

# Raw JavaScript helper (no f-string)
SHARED_JS = r"""
<script>
function showToast(msg, type) {
  let toast = document.getElementById('appToast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'appToast';
    toast.style.position = 'fixed';
    toast.style.bottom = '24px';
    toast.style.right = '24px';
    toast.style.padding = '12px 20px';
    toast.style.borderRadius = '8px';
    toast.style.fontFamily = 'inherit';
    toast.style.fontSize = '0.88rem';
    toast.style.fontWeight = '600';
    toast.style.boxShadow = '0 10px 25px rgba(11, 48, 86, 0.15)';
    toast.style.zIndex = '9999';
    toast.style.transition = 'all 0.3s ease';
    document.body.appendChild(toast);
  }
  
  if (type === 'success') {
    toast.style.background = '#065f46';
    toast.style.color = '#ffffff';
    toast.style.border = '1px solid #10b981';
  } else if (type === 'error') {
    toast.style.background = '#991b1b';
    toast.style.color = '#ffffff';
    toast.style.border = '1px solid #ef4444';
  } else {
    toast.style.background = '#0b3056';
    toast.style.color = '#ffffff';
    toast.style.border = '1px solid #00a3e0';
  }
  
  toast.textContent = msg;
  toast.style.display = 'block';
  toast.style.opacity = '1';
  
  setTimeout(function() {
    toast.style.opacity = '0';
    setTimeout(function() { toast.style.display = 'none'; }, 300);
  }, 3500);
}

// ---------------------------------------------------------------------------
// Auto-authentication: ensure a demo session token is always available so
// all interactive UI tabs work without manual login. Uses the AccessAdmin
// demo account (u_dev / NagarkotDemo@2026). The Shipments Explorer login
// form writes to the same sessionStorage keys, so a real sign-in takes
// precedence over the auto-login token silently.
// ---------------------------------------------------------------------------
function getAuthHeaders() {
  var token = sessionStorage.getItem('nagarkotSessionToken');
  if (token) {
    return { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' };
  }
  return { 'Content-Type': 'application/json' };
}

function getAuthHeadersNoContentType() {
  var token = sessionStorage.getItem('nagarkotSessionToken');
  if (token) {
    return { 'Authorization': 'Bearer ' + token };
  }
  return {};
}

window.nagarkotReady = (function nagarkotAutoLogin() {
  if (sessionStorage.getItem('nagarkotSessionToken')) {
    return Promise.resolve();
  }
  return fetch('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'asha', password: 'NagarkotDemo@2026' })
  }).then(function(r) {
    return r.json();
  }).then(function(d) {
    if (d && d.token) {
      sessionStorage.setItem('nagarkotSessionToken', d.token);
      sessionStorage.setItem('nagarkotSessionUser', d.user_id || 'u_asha');
    }
  }).catch(function() {
    // Auto-login failed silently; manual sign-in on Shipments page still works.
  });
})();
</script>
"""

# Raw JavaScript for Home Page
HOME_PAGE_JS = r"""
<script>
function applyScenario(actor, action, jobId, title) {
  document.getElementById('evalActor').value = actor;
  document.getElementById('evalAction').value = action;
  document.getElementById('evalJobId').value = jobId;
  showToast('Loaded ' + title, 'info');
  executeAuthorization();
}

function viewJobAuditFromSim() {
  const jid = document.getElementById('evalJobId').value.trim() || 'JOB_0001';
  window.location.href = '/logs?job=' + encodeURIComponent(jid);
}

async function executeAuthorization() {
  const actor_id = document.getElementById('evalActor').value;
  const action = document.getElementById('evalAction').value;
  const job_id = document.getElementById('evalJobId').value.trim();
  const panel = document.getElementById('evalResultPanel');
  const badge = document.getElementById('evalDecisionBadge');
  const codeText = document.getElementById('evalCodeText');
  const ruleText = document.getElementById('evalRuleText');
  const jsonBox = document.getElementById('evalReceiptJson');

  panel.style.display = 'block';
  badge.textContent = 'Evaluating...';
  badge.className = 'badge-decision';
  codeText.textContent = '';
  if (ruleText) ruleText.textContent = '';
  jsonBox.textContent = 'Contacting decision engine...';

  try {
    const resp = await fetch('/authorize', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ actor_id: actor_id, action: action, job_id: job_id, simulate: true })
    });
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.error || 'Unable to evaluate this authorization request (HTTP ' + resp.status + ').');
    }
    
    const isAllow = (data.decision === 'ALLOW');
    badge.textContent = data.decision;
    badge.className = 'badge-decision ' + (isAllow ? 'badge-allow' : 'badge-deny');
    codeText.textContent = 'Reason Code: ' + (data.code || 'UNKNOWN');
    if (ruleText) ruleText.textContent = data.rule || 'N/A';
    jsonBox.textContent = JSON.stringify(data, null, 2);
    
    showToast(data.decision + ': ' + (data.code || 'Evaluated'), isAllow ? 'success' : 'error');
  } catch (err) {
    badge.textContent = 'ERROR';
    badge.className = 'badge-decision badge-deny';
    codeText.textContent = err.message;
    jsonBox.textContent = String(err);
    showToast('Request failed: ' + err.message, 'error');
  }
}

window.addEventListener('DOMContentLoaded', function() {
  (window.nagarkotReady || Promise.resolve()).then(function() {
    executeAuthorization();
  });
});
</script>
"""

# Raw JavaScript for Shipments Page
SHIPMENTS_PAGE_JS = r"""
<script>
let explorerNextAfter = null;
let loadedJobsCache = [];

async function loadJobsExplorer(reset) {
  if (reset === undefined) reset = true;
  let url = '/jobs?limit=25';
  if (!reset && explorerNextAfter) {
    url += '&after=' + encodeURIComponent(explorerNextAfter);
  }

  const tbody = document.getElementById('explorerTableBody');
  const token = sessionStorage.getItem('nagarkotSessionToken');
  if (reset) {
    tbody.innerHTML = '<tr><td colspan="10" style="text-align:center; padding: 2rem; color: #64748b;">Loading shipments...</td></tr>';
  }

  try {
    const headers = token ? { 'Authorization': 'Bearer ' + token } : {};
    const resp = await fetch(url, { headers: headers });
    const data = await resp.json();
    if (resp.status === 401) {
      sessionStorage.removeItem('nagarkotSessionToken');
      sessionStorage.removeItem('nagarkotSessionUser');
      explorerNextAfter = null;
      loadedJobsCache = [];
      showExplorerLogin('Sign in to view shipments.');
      return;
    }
    if (!resp.ok) {
      throw new Error(data.error || 'Request failed with status ' + resp.status);
    }

    document.getElementById('explorerLoginPanel').hidden = true;
    document.getElementById('explorerSessionPanel').hidden = false;
    document.getElementById('explorerSessionUser').textContent =
      sessionStorage.getItem('nagarkotSessionUser') || 'Signed in';
    explorerNextAfter = data.next_after;
    loadedJobsCache = data.jobs || [];
    document.getElementById('explorerCountText').textContent = data.returned_count;
    document.getElementById('nextPageBtn').disabled = !explorerNextAfter;
    renderShipmentsTable(loadedJobsCache);
  } catch (err) {
    explorerNextAfter = null;
    loadedJobsCache = [];
    document.getElementById('explorerCountText').textContent = '—';
    document.getElementById('nextPageBtn').disabled = true;
    tbody.innerHTML = '<tr><td colspan="10" style="color:#b91c1c; padding:1rem;"></td></tr>';
    tbody.querySelector('td').textContent = 'Failed to load shipments: ' + err.message;
  }
}

function showExplorerLogin(message) {
  document.getElementById('explorerLoginPanel').hidden = false;
  document.getElementById('explorerSessionPanel').hidden = true;
  document.getElementById('explorerLoginMessage').textContent = message;
  document.getElementById('explorerCountText').textContent = '—';
  document.getElementById('explorerTableBody').innerHTML =
    '<tr><td colspan="10" style="text-align:center; padding:2rem; color:#64748b;">Sign in to view shipments.</td></tr>';
  document.getElementById('nextPageBtn').disabled = true;
}

async function signInToExplorer(event) {
  event.preventDefault();
  const form = document.getElementById('explorerLoginForm');
  const message = document.getElementById('explorerLoginMessage');
  const button = document.getElementById('explorerLoginButton');
  const username = document.getElementById('explorerUsername').value.trim();
  const password = document.getElementById('explorerPassword').value;
  button.disabled = true;
  message.textContent = 'Signing in...';

  try {
    const resp = await fetch('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username, password: password })
    });
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.error || 'Sign-in failed.');
    }

    sessionStorage.setItem('nagarkotSessionToken', data.token);
    sessionStorage.setItem('nagarkotSessionUser', data.user_id);
    document.getElementById('explorerPassword').value = '';
    explorerNextAfter = null;
    await loadJobsExplorer(true);
  } catch (err) {
    message.textContent = err.message;
  } finally {
    button.disabled = false;
  }
}

function signOutOfExplorer() {
  sessionStorage.removeItem('nagarkotSessionToken');
  sessionStorage.removeItem('nagarkotSessionUser');
  explorerNextAfter = null;
  loadedJobsCache = [];
  showExplorerLogin('Signed out. Sign in to view shipments.');
}

function renderShipmentsTable(jobs) {
  const tbody = document.getElementById('explorerTableBody');
  if (!jobs || jobs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="10" style="text-align:center; padding: 2rem; color: #64748b;">No shipments matched the current filter.</td></tr>';
    return;
  }

  let rowsHtml = '';
  for (let i = 0; i < jobs.length; i++) {
    const j = jobs[i];
    const isPrepRedacted = (j.prepared_by === '[REDACTED]');
    const isChkRedacted = (j.checked_by === '[REDACTED]');
    const isFilRedacted = (j.filed_by === '[REDACTED]');

    rowsHtml += '<tr>' +
      '<td><code>' + j.id + '</code></td>' +
      '<td>' + j.client_id + '</td>' +
      '<td>' + j.branch + '</td>' +
      '<td>' + j.direction + '</td>' +
      '<td>' + j.mode + '</td>' +
      '<td><span class="badge-stage stage-' + j.stage + '">' + j.stage + '</span></td>' +
      '<td>' + (isPrepRedacted ? '<span class="badge-redacted">[REDACTED]</span>' : (j.prepared_by || '-')) + '</td>' +
      '<td>' + (isChkRedacted ? '<span class="badge-redacted">[REDACTED]</span>' : (j.checked_by || '-')) + '</td>' +
      '<td>' + (isFilRedacted ? '<span class="badge-redacted">[REDACTED]</span>' : (j.filed_by || '-')) + '</td>' +
      '<td>' +
        '<a href="/logs?job=' + encodeURIComponent(j.id) + '" class="action-btn action-btn-secondary action-btn-sm" style="text-decoration:none;">' +
          '<span>&#x1F6E1;</span> Log' +
        '</a>' +
      '</td>' +
    '</tr>';
  }
  tbody.innerHTML = rowsHtml;
}

function filterLocalShipments() {
  const searchVal = document.getElementById('shipmentSearchInput').value.trim().toUpperCase();
  const stageVal = document.getElementById('stageFilterSelect').value;
  
  const filtered = loadedJobsCache.filter(function(j) {
    const matchSearch = (!searchVal || j.id.toUpperCase().includes(searchVal) || j.client_id.toUpperCase().includes(searchVal) || j.branch.toUpperCase().includes(searchVal));
    const matchStage = (stageVal === 'ALL' || j.stage === stageVal);
    return matchSearch && matchStage;
  });
  renderShipmentsTable(filtered);
}

function loadNextJobsPage() {
  loadJobsExplorer(false);
}

window.addEventListener('DOMContentLoaded', function() {
  document.getElementById('explorerLoginForm').addEventListener('submit', signInToExplorer);
  document.getElementById('explorerSignOutButton').addEventListener('click', signOutOfExplorer);
  (window.nagarkotReady || Promise.resolve()).then(function() {
    loadJobsExplorer(true);
  });
});
</script>
"""

# Raw JavaScript for Queue Page
QUEUE_PAGE_JS = r"""
<script>
async function loadWaitingQueue() {
  const user = document.getElementById('queueUserSelect').value;
  const tbody = document.getElementById('waitingTableBody');
  const countEl = document.getElementById('queueTotalCount');
  tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; padding: 2rem; color: #64748b;">Loading actionable jobs...</td></tr>';

  try {
    const resp = await fetch('/jobs/waiting?simulate=1&user=' + encodeURIComponent(user), {
      headers: getAuthHeadersNoContentType()
    });
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.error || 'Unable to load the waiting queue (HTTP ' + resp.status + ').');
    }
    const wc = (data.waiting_count !== undefined && data.waiting_count !== null) ? Number(data.waiting_count) : 0;
    countEl.textContent = (isNaN(wc) ? 0 : wc).toLocaleString() + ' shipments';

    if (!data.jobs || data.jobs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; padding: 2.5rem; color: #64748b;">No shipments currently require action for this user.</td></tr>';
      return;
    }

    let rowsHtml = '';
    for (let i = 0; i < data.jobs.length; i++) {
      const j = data.jobs[i];
      let act = 'prepare';
      if (j.stage === 'Prepared') act = 'check';
      if (j.stage === 'Checked') act = 'file';

      rowsHtml += '<tr>' +
        '<td><code>' + j.id + '</code></td>' +
        '<td>' + j.client_id + '</td>' +
        '<td>' + j.branch + '</td>' +
        '<td>' + j.direction + '</td>' +
        '<td>' + j.mode + '</td>' +
        '<td><span class="badge-stage stage-' + j.stage + '">' + j.stage + '</span></td>' +
        '<td>' + (j.prepared_by ? j.prepared_by : '<span style="color:#94a3b8;">-</span>') + '</td>' +
        '<td>' +
          '<button class="action-btn action-btn-sm" onclick="executeJobAction(\'' + j.id + '\', \'' + act + '\', \'' + user + '\')">' +
            act.toUpperCase() +
          '</button>' +
        '</td>' +
        '<td>' +
          '<a href="/logs?job=' + encodeURIComponent(j.id) + '" class="action-btn action-btn-secondary action-btn-sm">' +
            'View Log' +
          '</a>' +
        '</td>' +
      '</tr>';
    }
    tbody.innerHTML = rowsHtml;
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="9" style="color:#b91c1c; padding:1rem;">Failed to load queue: ' + err.message + '</td></tr>';
  }
}

async function executeJobAction(jobId, action, actorId) {
  try {
    const resp = await fetch('/jobs/' + jobId + '/action', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ action: action, actor_id: actorId })
    });
    const res = await resp.json();
    if (resp.ok) {
      showToast('Success! Job ' + jobId + ' advanced to ' + res.new_stage + ' & recorded in audit ledger!', 'success');
      loadWaitingQueue();
    } else {
      showToast('Action Denied: ' + (res.error || 'Unauthorized'), 'error');
    }
  } catch (err) {
    showToast('Error: ' + err.message, 'error');
  }
}

window.addEventListener('DOMContentLoaded', function() {
  (window.nagarkotReady || Promise.resolve()).then(function() {
    loadWaitingQueue();
  });
});
</script>
"""

# Raw JavaScript for Logs Page
LOGS_PAGE_JS = r"""
<script>
function pickJob(jid) {
  document.getElementById('logJobInput').value = jid;
  fetchJobAuditLog();
}

async function fetchJobAuditLog() {
  const jid = document.getElementById('logJobInput').value.trim();
  if (!jid) return;

  const timeline = document.getElementById('timelineContainer');
  const profileCard = document.getElementById('jobProfileCard');
  const countEl = document.getElementById('logEventCount');
  timeline.innerHTML = '<div style="color:#64748b; font-size:0.85rem; padding:1rem 0;">Retrieving history for ' + jid + '...</div>';

  try {
    const resp = await fetch('/audit/job/' + encodeURIComponent(jid) + '?simulate=1', {
      headers: getAuthHeadersNoContentType()
    });
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.error || 'Unable to retrieve this audit log (HTTP ' + resp.status + ').');
    }

    profileCard.style.display = 'block';
    document.getElementById('profJobId').textContent = data.job_id;

    if (data.job) {
      const j = data.job;
      const stageEl = document.getElementById('profStageBadge');
      stageEl.textContent = j.stage;
      stageEl.className = 'badge-stage stage-' + j.stage;
      document.getElementById('profMetaText').textContent = 'Client: ' + j.client_id + ' \u2022 Branch: ' + j.branch + ' \u2022 Direction: ' + j.direction + ' \u2022 Mode: ' + j.mode + ' \u2022 PreparedBy: ' + (j.prepared_by || '-') + ' \u2022 CheckedBy: ' + (j.checked_by || '-') + ' \u2022 FiledBy: ' + (j.filed_by || '-');

      const statusEl = document.getElementById('profStatusBadge');
      if (statusEl) {
        if (j.stage === 'Filed') {
          statusEl.innerHTML = '<span style="color:#059669; font-weight:700;">&#x2714; Filed (Finalized)</span>';
        } else {
          statusEl.innerHTML = '<span style="color:#0284c7; font-weight:600;">In Progress</span>';
        }
      }
    }

    const history = data.history || [];
    const incidents = data.security_incidents || [];
    countEl.textContent = history.length + ' logged events, ' + incidents.length + ' security incidents';

    if (history.length === 0 && incidents.length === 0) {
      timeline.innerHTML = '<div style="color:#64748b; font-size:0.88rem; padding:1.5rem 0;">No events currently recorded for this job.</div>';
      return;
    }

    let html = '';
    for (let i = 0; i < history.length; i++) {
      const ev = history[i];
      let details = {};
      try { details = JSON.parse(ev.details_json); } catch (e) { details = ev.details_json; }

      let badgeClass = 'badge-allow';
      let icon = '&#x2714;';
      let actionTitle = ev.event_type.toUpperCase();

      if (ev.event_type.includes('deny') || ev.event_type.includes('alert') || ev.event_type.includes('anomaly')) {
        badgeClass = 'badge-deny';
        icon = '&#x26A0;';
      }

      html += '<div class="timeline-item">' +
        '<div class="timeline-icon">' + icon + '</div>' +
        '<div class="timeline-card">' +
          '<div class="timeline-header">' +
            '<div class="timeline-title">' +
              '<span class="badge-decision ' + badgeClass + '" style="font-size:0.75rem; padding:0.2rem 0.6rem;">' + actionTitle + '</span>' +
              '<span>Actor: <code>' + ev.actor_id + '</code></span>' +
            '</div>' +
            '<div class="timeline-time">' + ev.timestamp + '</div>' +
          '</div>' +
          '<div class="timeline-desc">' + formatEventDescription(ev.event_type, details, ev.actor_id) + '</div>' +
          '<div class="timeline-meta">' +
            '<span><strong>Action:</strong> ' + ev.event_type + '</span>' +
            '<span><strong>Actor:</strong> ' + ev.actor_id + '</span>' +
            '<span><strong>Log Entry:</strong> #' + ev.seq + '</span>' +
          '</div>' +
        '</div>' +
      '</div>';
    }

    for (let k = 0; k < incidents.length; k++) {
      const inc = incidents[k];
      html += '<div class="timeline-item">' +
        '<div class="timeline-icon" style="border-color:#dc2626; color:#dc2626;">&#x2716;</div>' +
        '<div class="timeline-card" style="border-color:#fca5a5; background:#fff5f5;">' +
          '<div class="timeline-header">' +
            '<div class="timeline-title">' +
              '<span class="badge-decision badge-deny" style="font-size:0.75rem; padding:0.2rem 0.6rem;">INCIDENT / DENIAL</span>' +
              '<span>Actor: <code>' + inc.actor_id + '</code></span>' +
            '</div>' +
            '<div class="timeline-time">' + (new Date(inc.timestamp * 1000).toISOString()) + '</div>' +
          '</div>' +
          '<div class="timeline-desc" style="color:#991b1b; font-weight:600;">' + (inc.details ? inc.details.reason : 'Security access denied') + '</div>' +
        '</div>' +
      '</div>';
    }

    timeline.innerHTML = html;
  } catch (err) {
    timeline.innerHTML = '<div style="color:#b91c1c; padding:1rem 0;">Error fetching audit log: ' + err.message + '</div>';
  }
}

function formatEventDescription(eventType, details, actor) {
  if (eventType === 'job_created') {
    return 'Job created in Confirmed stage. Assigned client ' + (details.client_id || '') + ' across ' + (details.branch || '') + ' branch.';
  }
  if (eventType === 'job_prepare') {
    return 'Checklist and customs documentation prepared by ' + actor + '. Stage advanced from ' + (details.previous_stage || '') + ' to ' + (details.new_stage || '') + '.';
  }
  if (eventType === 'job_check') {
    return 'Customs declaration reviewed and compliance approved by ' + actor + '. Stage advanced to ' + (details.new_stage || '') + '.';
  }
  if (eventType === 'job_file') {
    return 'Shipment filed with Customs Authorities by ' + actor + '. Job is now finalized and immutable.';
  }
  if (eventType === 'access_allowed' || eventType === 'access_allow') {
    return 'Authorization evaluated for action "' + (details.action || '') + '" by ' + actor + '. Decision: ALLOWED (Rule: ' + (details.rule || '') + ').';
  }
  if (eventType === 'access_denied' || eventType === 'access_deny') {
    return 'Authorization evaluated for action "' + (details.action || '') + '" by ' + actor + '. Decision: DENIED (Reason: ' + (details.code || '') + ').';
  }
  if (eventType === 'alert') {
    return 'Security Alert: Unauthorized write attempt detected on immutable Filed shipment.';
  }
  return typeof details === 'object' ? JSON.stringify(details) : String(details);
}

async function executeQuickAccessTest() {
  const actor = document.getElementById('quickActorSelect').value;
  const action = document.getElementById('quickActionSelect').value;
  const jid = document.getElementById('logJobInput').value.trim();

  try {
    const resp = await fetch('/authorize', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ actor_id: actor, action: action, job_id: jid, simulate: true })
    });
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.error || 'Unable to evaluate this access test (HTTP ' + resp.status + ').');
    }
    showToast('Evaluated ' + action + ' for ' + actor + ': ' + data.decision, data.decision === 'ALLOW' ? 'success' : 'error');
    fetchJobAuditLog();
  } catch (err) {
    showToast('Error: ' + err.message, 'error');
  }
}

window.addEventListener('DOMContentLoaded', function() {
  const urlParams = new URLSearchParams(window.location.search);
  const jParam = urlParams.get('job');
  if (jParam) {
    document.getElementById('logJobInput').value = jParam;
  }
  (window.nagarkotReady || Promise.resolve()).then(function() {
    fetchJobAuditLog();
  });
});
</script>
"""

# Raw JavaScript for Staff Page
STAFF_PAGE_JS = r"""
<script>
async function executeExplain() {
  const user = document.getElementById('expUserA').value;
  const other = document.getElementById('expUserB').value;
  const action = document.getElementById('expAction').value;
  const job = document.getElementById('expJobId').value.trim();

  const panel = document.getElementById('expResultPanel');
  panel.style.display = 'block';
  document.getElementById('expSummaryBanner').textContent = 'Comparing decisions...';

  try {
    const url = '/explain?user=' + encodeURIComponent(user) +
                '&other=' + encodeURIComponent(other) +
                '&action=' + encodeURIComponent(action) +
                '&job=' + encodeURIComponent(job);
    const resp = await fetch(url + '&simulate=1', {
      headers: getAuthHeadersNoContentType()
    });
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.error || 'Unable to compare access decisions (HTTP ' + resp.status + ').');
    }

    document.getElementById('expSummaryBanner').textContent = data.comparison_summary || 'Comparison complete.';
    document.getElementById('expColTitleA').textContent = 'User A (' + user + ')';
    document.getElementById('expColTitleB').textContent = 'User B (' + other + ')';

    const bA = document.getElementById('expBadgeA');
    if (data.user_a) {
      bA.textContent = (data.user_a.decision || '?') + ' (' + (data.user_a.code || '?') + ')';
      bA.className = 'badge-decision ' + (data.user_a.decision === 'ALLOW' ? 'badge-allow' : 'badge-deny');
      document.getElementById('expCodeA').textContent = JSON.stringify(data.user_a, null, 2);
    }

    const bB = document.getElementById('expBadgeB');
    if (data.user_b) {
      bB.textContent = (data.user_b.decision || '?') + ' (' + (data.user_b.code || '?') + ')';
      bB.className = 'badge-decision ' + (data.user_b.decision === 'ALLOW' ? 'badge-allow' : 'badge-deny');
      document.getElementById('expCodeB').textContent = JSON.stringify(data.user_b, null, 2);
    }
    
    showToast('Comparison updated', 'info');
  } catch (err) {
    document.getElementById('expSummaryBanner').textContent = 'Error: ' + err.message;
    showToast('Explainer failed: ' + err.message, 'error');
  }
}

window.addEventListener('DOMContentLoaded', function() {
  (window.nagarkotReady || Promise.resolve()).then(function() {
    executeExplain();
  });
});
</script>
"""

def render_header(active_page: str, conn: sqlite3.Connection) -> str:
    policy_ver = get_grants_version(conn)

    def is_active(name: str) -> str:
        return " active" if active_page == name else ""

    return f"""
  <header class="app-header">
    <div class="header-inner">
      <a href="/" class="brand-wrap">
        <img src="/logo.jpg" alt="Tez Adhikar Logo" class="brand-logo-img">
        <div>
          <div class="brand-title">Tez Adhikar</div>
          <div class="brand-subtitle">Right Access. Right Authority. &bull; Nagarkot Forwarders</div>
        </div>
      </a>

      <!-- Primary Page Navigation -->
      <nav class="nav-links">
        <a href="/" class="nav-link{is_active('home')}">
          <span>&#x1F3E0;</span> Home
        </a>
        <a href="/shipments" class="nav-link{is_active('shipments')}">
          <span>&#x1F4E6;</span> Shipments
        </a>
        <a href="/waiting" class="nav-link{is_active('queue')}">
          <span>&#x1F4CB;</span> Work Queue
        </a>
        <a href="/logs" class="nav-link{is_active('logs')}">
          <span>&#x1F6E1;</span> Job Audit Logs
        </a>
        <a href="/staff" class="nav-link{is_active('staff')}">
          <span>&#x1F465;</span> Staff Access
        </a>
      </nav>

      <!-- System Health Pills -->
      <div class="header-badges">
        <div class="pill pill-live">
          <span class="pulse-dot"></span>
          <span>SQLite WAL Active</span>
        </div>
        <div class="pill" style="background: #ecfdf5; color: #047857; border-color: #a7f3d0;">
          <span>&#x2714; System Active</span>
        </div>
        <div class="pill" style="background: #f5f3ff; color: #6d28d9; border-color: #ddd6fe;">
          <span>Policy v{policy_ver}</span>
        </div>
      </div>
    </div>
  </header>
"""

def render_footer() -> str:
    return """
  <footer>
    <div style="max-width: 1280px; margin: 0 auto; padding: 0 1.5rem;">
      <strong>Tez Adhikar</strong> &bull; Access Control &amp; Audit Service &bull; <em>Right Access. Right Authority.</em> &bull; Nagarkot Forwarders Pvt. Ltd. (Customs Brokerage, 5 Branches)
    </div>
  </footer>
"""

# ==============================================================================
# PAGE 1: HOME
# ==============================================================================
def render_home_page(conn: sqlite3.Connection) -> str:
    job_cnt = conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
    user_cnt = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    grant_cnt = conn.execute("SELECT COUNT(*) FROM grants WHERE closed_at IS NULL").fetchone()[0]
    delegation_cnt = conn.execute("SELECT COUNT(*) FROM delegations WHERE status = 'active'").fetchone()[0]
    events_cnt = conn.execute("SELECT COUNT(*) FROM audit_ledger").fetchone()[0]

    header_html = render_header("home", conn)
    footer_html = render_footer()

    html_body = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Tez Adhikar — Access Control &amp; Audit Service</title>
  <style>{SHARED_CSS}</style>
</head>
<body>
  {header_html}

  <main class="main-wrap">
    <!-- Hero Banner with Official Product Info -->
    <div style="background: linear-gradient(135deg, rgba(11, 48, 86, 0.04), rgba(0, 163, 224, 0.08)); border: 1px solid #bae6fd; border-radius: var(--radius-md); padding: 1.5rem; margin-bottom: 2rem; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1.25rem;">
      <div>
        <div style="font-size: 1.25rem; font-weight: 800; color: #0b3056;">Tez Adhikar — Access Control &amp; Audit Service</div>
        <div style="font-size: 0.9rem; color: var(--text-muted); margin-top: 0.35rem; max-width: 820px; line-height: 1.5;">
          A centralized authorization service that ensures every user can perform only the actions permitted by their role, scope, and the shipment's current state.
        </div>
      </div>
      <div>
        <span style="display: inline-block; background: #0b3056; color: #ffffff; padding: 0.5rem 1.1rem; border-radius: 9999px; font-size: 0.85rem; font-weight: 700; letter-spacing: 0.02em; box-shadow: 0 2px 6px rgba(11, 48, 86, 0.25);">
          Right Access. Right Authority.
        </span>
      </div>
    </div>

    <!-- Live System Statistics -->
    <div class="metrics-grid">
      <a href="/shipments" class="metric-card">
        <div class="metric-label">Customs Shipments</div>
        <div class="metric-val">{job_cnt:,}</div>
        <div class="metric-meta">5 Branches &bull; 10 Clients &rarr;</div>
      </a>
      <a href="/staff" class="metric-card">
        <div class="metric-label">Staff &amp; Identities</div>
        <div class="metric-val">{user_cnt:,}</div>
        <div class="metric-meta">20 Baseline &bull; 500 Scaled &rarr;</div>
      </a>
      <a href="/staff" class="metric-card">
        <div class="metric-label">Bitemporal Grants</div>
        <div class="metric-val">{grant_cnt:,}</div>
        <div class="metric-meta">{delegation_cnt} active delegations &rarr;</div>
      </a>
      <a href="/logs" class="metric-card">
        <div class="metric-label">Audit Log Events</div>
        <div class="metric-val">{events_cnt:,}</div>
        <div class="metric-meta">Tracked lifecycle events &rarr;</div>
      </a>
    </div>

    <!-- Dedicated Application Feature Pages -->
    <div class="card-header" style="margin-bottom: 0.85rem;">
      <div>
        <div class="card-title">Explore Tez Adhikar Pages</div>
        <div class="card-desc">Navigate directly to dedicated modules for shipments, work queues, forensic logs, and staff access.</div>
      </div>
    </div>
    <div class="features-grid">
      <a href="/shipments" class="feature-nav-card">
        <div class="feature-nav-title"><span>&#x1F4E6;</span> Shipments Explorer</div>
        <div class="feature-nav-desc">Browse, filter, and inspect customs shipments across branches with ClientViewer redactions.</div>
        <div class="feature-nav-cta">Open Shipments Explorer &rarr;</div>
      </a>
      <a href="/waiting" class="feature-nav-card">
        <div class="feature-nav-title"><span>&#x1F4CB;</span> "Jobs Waiting for Me" Queue</div>
        <div class="feature-nav-desc">View actionable jobs matching any employee's role and advance stages with 1-click execution.</div>
        <div class="feature-nav-cta">Open Work Queue &rarr;</div>
      </a>
      <a href="/logs?job=JOB_0001" class="feature-nav-card">
        <div class="feature-nav-title"><span>&#x1F6E1;</span> Job Audit &amp; Lifecycle Log</div>
        <div class="feature-nav-desc">Inspect who created, accessed, modified, and all incidents for any individual shipment.</div>
        <div class="feature-nav-cta">Inspect Job Audit Trail &rarr;</div>
      </a>
      <a href="/staff" class="feature-nav-card">
        <div class="feature-nav-title"><span>&#x1F465;</span> Staff Directory &amp; Explainer</div>
        <div class="feature-nav-desc">Review plain-English access for all 20 staff and use the side-by-side "Why A Can &amp; B Can't" explainer.</div>
        <div class="feature-nav-cta">View Staff Access &rarr;</div>
      </a>
    </div>

    <!-- Interactive Decision Engine Simulator -->
    <div class="surface-card">
      <div class="card-header">
        <div>
          <div class="card-title">Real-Time Authorization Engine</div>
          <div class="card-desc">Evaluates requests in strict fail-closed order according to role, scope, and shipment state.</div>
        </div>
      </div>

      <!-- 1-Click Interactive Scenarios -->
      <div class="scenario-grid">
        <button class="scenario-btn" onclick="applyScenario('u_asha', 'check', 'JOB_0001', 'Scenario 1: Asha Checks C01 Mumbai job')">
          <div class="scenario-btn-title"><span>&#x2714;</span> Asha Checks C01 Mumbai</div>
          <div class="scenario-btn-desc">Asha holds Checker for C01 across all branches. Result: ALLOW.</div>
        </button>
        <button class="scenario-btn" onclick="applyScenario('u_ravi', 'check', 'JOB_0001', 'Scenario 2: Scope Mismatch — Ravi on Mumbai C01')">
          <div class="scenario-btn-title"><span style="color:var(--danger);">&#x2716;</span> Ravi Checks C01 Mumbai</div>
          <div class="scenario-btn-desc">Ravi is restricted to C03 Mumbai imports only. Result: DENY.</div>
        </button>
        <button class="scenario-btn" onclick="applyScenario('u_priya', 'prepare', 'JOB_0003', 'Scenario 3: Client User Boundary — Priya on C02')">
          <div class="scenario-btn-title"><span style="color:var(--danger);">&#x2716;</span> Client User Attempts Prepare</div>
          <div class="scenario-btn-desc">Priya is ClientViewer: view-only for C02. Result: DENY.</div>
        </button>
        <button class="scenario-btn" onclick="applyScenario('u_dev', 'prepare', 'JOB_0001', 'Scenario 4: Admin Separation of Duties')">
          <div class="scenario-btn-title"><span style="color:var(--danger);">&#x2716;</span> Admin Attempts Pipeline Action</div>
          <div class="scenario-btn-desc">AccessAdmin has zero job-pipeline powers. Result: DENY.</div>
        </button>
      </div>

      <!-- Form -->
      <div class="form-row">
        <div class="field-group">
          <label class="field-label">Actor Identity</label>
          <select id="evalActor" class="form-select">
            <option value="u_asha">Asha Sharma (Maker everywhere, Checker C01-C03)</option>
            <option value="u_ravi">Ravi Verma (Checker C03 Mumbai Import only)</option>
            <option value="u_karan">Karan Joshi (Meera's Delegate - Mumbai Supervisor)</option>
            <option value="u_priya">Priya Shah (ClientViewer for C02 - View Only)</option>
            <option value="u_dev">Devendra Patel (AccessAdmin - Security Only)</option>
            <option value="svc_parser">svc_parser (Overnight EDI Parser)</option>
            <option value="u_suresh">Suresh Kumar (Maker Delhi &amp; Kolkata)</option>
            <option value="u_deepa">Deepa Reddy (Checker Delhi &amp; Kolkata)</option>
            <option value="u_manoj">Manoj Tiwari (Filer Mumbai)</option>
          </select>
        </div>
        <div class="field-group">
          <label class="field-label">Action</label>
          <select id="evalAction" class="form-select">
            <option value="check">check (Review and Approve)</option>
            <option value="prepare">prepare (Checklist &amp; Documents)</option>
            <option value="file">file (Submit to Customs Authorities)</option>
            <option value="view">view (Read job status &amp; details)</option>
            <option value="cancel">cancel (Withdraw job)</option>
            <option value="reopen">reopen (Reactivate job)</option>
            <option value="update">update (Modify cargo / invoice content)</option>
            <option value="manage_access">manage_access (Create/Revoke Grants)</option>
          </select>
        </div>
        <div class="field-group">
          <label class="field-label">Job Reference ID</label>
          <input type="text" id="evalJobId" class="form-input" value="JOB_0001">
        </div>
      </div>

      <div style="display:flex; gap: 0.75rem; flex-wrap: wrap;">
        <button class="action-btn" onclick="executeAuthorization()">
          <span>&#x25B6;</span> Evaluate Authorization Request
        </button>
        <button class="action-btn action-btn-secondary" onclick="viewJobAuditFromSim()">
          <span>&#x1F6E1;</span> Inspect Job's Full Audit Log
        </button>
      </div>

      <!-- Result Box -->
      <div id="evalResultPanel" class="decision-panel" style="display: none;">
        <div class="decision-header">
          <div>
            <div id="evalDecisionBadge" class="badge-decision">ALLOW</div>
            <div id="evalCodeText" style="font-family: var(--font-mono); font-size: 0.85rem; color: var(--text-muted); margin-top: 0.35rem;"></div>
          </div>
          <div style="text-align: right;">
            <div style="font-size: 0.72rem; color: var(--text-dim); text-transform: uppercase;">Evaluation Rule</div>
            <div id="evalRuleText" style="font-family: var(--font-mono); font-size: 0.85rem; font-weight: 700; color: #0b3056;">allow_grant</div>
          </div>
        </div>
        <pre class="receipt-code"><code id="evalReceiptJson" style="background:transparent; border:none; color:inherit; padding:0;"></code></pre>
      </div>
    </div>
  </main>

  {footer_html}
  {SHARED_JS}
"""
    return html_body + HOME_PAGE_JS + "\n</body>\n</html>"

# ==============================================================================
# PAGE 2: SHIPMENTS EXPLORER
# ==============================================================================
def render_shipments_page(conn: sqlite3.Connection) -> str:
    header_html = render_header("shipments", conn)
    footer_html = render_footer()

    html_body = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Customs Shipments Explorer — Tez Adhikar</title>
  <style>{SHARED_CSS}</style>
</head>
<body>
  {header_html}

  <main class="main-wrap">
    <div class="surface-card">
      <div class="card-header">
        <div>
          <div class="card-title">Customs Shipments Explorer</div>
          <div class="card-desc">High-performance Keyset Pagination (<code>WHERE id &gt; :after LIMIT 25</code>) with permission-scoped results and client data redaction.</div>
        </div>
        <div id="explorerSessionPanel" hidden style="display:flex; align-items:center; gap:0.75rem;">
          <span>Signed in as <strong id="explorerSessionUser"></strong></span>
          <button id="explorerSignOutButton" class="action-btn action-btn-secondary" type="button">Sign out</button>
        </div>
      </div>

      <section id="explorerLoginPanel" hidden style="margin-bottom:1.25rem; padding:1rem; background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px;">
        <h2 style="margin:0 0 0.35rem; font-size:1rem;">Sign in to view shipments</h2>
        <p style="margin:0 0 0.75rem; color:#64748b; font-size:0.875rem;">Use your account credentials. Shipment visibility and client redaction are determined by your account permissions.</p>
        <form id="explorerLoginForm" style="display:flex; align-items:end; gap:0.75rem; flex-wrap:wrap;">
          <div class="field-group" style="min-width:180px;">
            <label class="field-label" for="explorerUsername">Username</label>
            <input id="explorerUsername" class="form-input" name="username" autocomplete="username" required>
          </div>
          <div class="field-group" style="min-width:180px;">
            <label class="field-label" for="explorerPassword">Password</label>
            <input id="explorerPassword" class="form-input" name="password" type="password" autocomplete="current-password" required>
          </div>
          <button id="explorerLoginButton" class="action-btn" type="submit">Sign in</button>
        </form>
        <p id="explorerLoginMessage" role="status" aria-live="polite" style="margin:0.75rem 0 0; color:#475569; font-size:0.875rem;"></p>
      </section>

      <!-- Quick Filter Bar -->
      <div class="form-row" style="margin-bottom: 1rem;">
        <div class="field-group">
          <label class="field-label">Search by Job ID</label>
          <input type="text" id="shipmentSearchInput" class="form-input" placeholder="e.g. JOB_0001" onkeyup="filterLocalShipments()">
        </div>
        <div class="field-group">
          <label class="field-label">Filter by Stage</label>
          <select id="stageFilterSelect" class="form-select" onchange="filterLocalShipments()">
            <option value="ALL">All Stages</option>
            <option value="Confirmed">Confirmed</option>
            <option value="Prepared">Prepared</option>
            <option value="Checked">Checked</option>
            <option value="Filed">Filed</option>
            <option value="Cancelled">Cancelled</option>
            <option value="Reopened">Reopened</option>
          </select>
        </div>
      </div>

      <div class="data-table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>Job ID</th>
              <th>Client</th>
              <th>Branch</th>
              <th>Direction</th>
              <th>Mode</th>
              <th>Stage</th>
              <th>Prepared By</th>
              <th>Checked By</th>
              <th>Filed By</th>
              <th>Audit Log</th>
            </tr>
          </thead>
          <tbody id="explorerTableBody">
            <tr><td colspan="10" style="text-align:center; padding: 2rem; color: #64748b;">Loading shipments...</td></tr>
          </tbody>
        </table>
      </div>

      <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 1.25rem; flex-wrap: wrap; gap: 1rem;">
        <div style="font-size: 0.85rem; color: var(--text-muted);">
          Displaying: <span id="explorerCountText" style="font-weight:700; color:#0b3056;">0</span> shipments
        </div>
        <div style="display: flex; gap: 0.75rem;">
          <button class="action-btn action-btn-secondary" onclick="loadJobsExplorer(true)">
            <span>&#x21BA;</span> Refresh
          </button>
          <button id="nextPageBtn" class="action-btn" onclick="loadNextJobsPage()">
            Next 25 Shipments &rarr;
          </button>
        </div>
      </div>
    </div>
  </main>

  {footer_html}
  {SHARED_JS}
"""
    return html_body + SHIPMENTS_PAGE_JS + "\n</body>\n</html>"

# ==============================================================================
# PAGE 3: MY WORK QUEUE
# ==============================================================================
def render_queue_page(conn: sqlite3.Connection) -> str:
    header_html = render_header("queue", conn)
    footer_html = render_footer()

    html_body = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Work Queue ("Jobs Waiting for Me") — Tez Adhikar</title>
  <style>{SHARED_CSS}</style>
</head>
<body>
  {header_html}

  <main class="main-wrap">
    <div class="surface-card">
      <div class="card-header">
        <div>
          <div class="card-title">"Jobs Waiting for Me" Work Queue</div>
          <div class="card-desc">Compiled with Unified Predicate Compiler SQL WHERE clause — returns exact actionable jobs for each employee in under 30 ms.</div>
        </div>
        <div style="display:flex; align-items:center; gap: 0.75rem;">
          <select id="queueUserSelect" class="form-select" onchange="loadWaitingQueue()" style="width: auto; font-weight:600;">
            <option value="u_asha">Asha Sharma (Maker / Checker C01-C03)</option>
            <option value="u_ravi">Ravi Verma (Checker C03 Mumbai Import)</option>
            <option value="u_suresh">Suresh Kumar (Maker Delhi &amp; Kolkata)</option>
            <option value="u_deepa">Deepa Reddy (Checker Delhi &amp; Kolkata)</option>
            <option value="u_manoj">Manoj Tiwari (Filer Mumbai)</option>
            <option value="u_pooja">Pooja Hegde (Filer Delhi)</option>
            <option value="u_karan">Karan Joshi (Meera's Delegate - Mumbai)</option>
          </select>
          <button class="action-btn" onclick="loadWaitingQueue()" style="padding: 0.6rem 1rem;">
            <span>&#x21BA;</span> Refresh
          </button>
        </div>
      </div>

      <div style="display: flex; gap: 1rem; align-items: center; margin-bottom: 1.25rem; background: #f8fafc; padding: 0.75rem 1rem; border-radius: var(--radius-sm); border: 1px solid var(--border);">
        <div style="font-size: 0.95rem; font-weight: 700; color: #0b3056;">
          Total Actionable Shipments in Queue: <span id="queueTotalCount" style="color: var(--primary-accent); font-size: 1.2rem;">Loading...</span>
        </div>
      </div>

      <div class="data-table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>Job ID</th>
              <th>Client</th>
              <th>Branch</th>
              <th>Direction</th>
              <th>Mode</th>
              <th>Current Stage</th>
              <th>Preparer</th>
              <th>Action to Perform</th>
              <th>Audit Trail</th>
            </tr>
          </thead>
          <tbody id="waitingTableBody">
            <tr><td colspan="9" style="text-align:center; padding: 2rem; color: #64748b;">Loading queue...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </main>

  {footer_html}
  {SHARED_JS}
"""
    return html_body + QUEUE_PAGE_JS + "\n</body>\n</html>"

# ==============================================================================
# PAGE 4: JOB AUDIT & LIFECYCLE LOG
# ==============================================================================
def render_logs_page(conn: sqlite3.Connection, default_job_id: Optional[str] = None) -> str:
    target_job_id = default_job_id or "JOB_0001"
    header_html = render_header("logs", conn)
    footer_html = render_footer()

    html_body = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Job Audit &amp; Lifecycle Log — Tez Adhikar</title>
  <style>{SHARED_CSS}</style>
</head>
<body>
  {header_html}

  <main class="main-wrap">
    <div class="surface-card">
      <div class="card-header">
        <div>
          <div class="card-title">Shipment Audit Trail &amp; Incident Log</div>
          <div class="card-desc">Complete timeline of who created, accessed, and modified each customs shipment, including all security incidents and denials.</div>
        </div>
      </div>

      <!-- Job Selection & Search Bar -->
      <div style="display: flex; gap: 0.75rem; align-items: center; flex-wrap: wrap; margin-bottom: 1.25rem;">
        <div style="flex: 1; min-width: 240px;">
          <input type="text" id="logJobInput" class="form-input" value="{target_job_id}" placeholder="Enter Job ID e.g. JOB_0001">
        </div>
        <button class="action-btn" onclick="fetchJobAuditLog()">
          <span>&#x1F50D;</span> Inspect Shipment Audit Log
        </button>
        <div style="display:flex; gap: 0.4rem; align-items:center; font-size:0.8rem; color:var(--text-muted);">
          <span>Quick Pick:</span>
          <button class="action-btn action-btn-secondary action-btn-sm" onclick="pickJob('JOB_0001')">JOB_0001 (Demo)</button>
          <button class="action-btn action-btn-secondary action-btn-sm" onclick="pickJob('JOB_0003')">JOB_0003</button>
          <button class="action-btn action-btn-secondary action-btn-sm" onclick="pickJob('JOB_0015')">JOB_0015</button>
          <button class="action-btn action-btn-secondary action-btn-sm" onclick="pickJob('JOB_0080')">JOB_0080</button>
        </div>
      </div>

      <!-- Shipment Profile Overview Card -->
      <div id="jobProfileCard" style="display:none; background: #f8fafc; border: 1px solid var(--border); border-radius: var(--radius-md); padding: 1.25rem; margin-bottom: 1.5rem;">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 1rem;">
          <div>
            <div style="display:flex; align-items:center; gap: 0.75rem;">
              <span id="profJobId" style="font-size: 1.25rem; font-weight: 800; color: #0b3056;">JOB_0001</span>
              <span id="profStageBadge" class="badge-stage stage-Confirmed">Confirmed</span>
            </div>
            <div id="profMetaText" style="font-size: 0.85rem; color: var(--text-muted); margin-top: 0.35rem;">
              Client: C01 &bull; Branch: Ahmedabad &bull; Direction: import &bull; Mode: air
            </div>
          </div>
          <div style="text-align: right;">
            <div style="font-size: 0.75rem; text-transform: uppercase; font-weight: 700; color: var(--text-dim);">Filing Status</div>
            <div id="profStatusBadge" style="font-size: 0.88rem; font-weight: 700; color: #0b3056; margin-top: 0.2rem;">Checking...</div>
          </div>
        </div>

        <!-- Interactive Access Testing Directly on This Job -->
        <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid #e2e8f0; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.75rem;">
          <div style="font-size: 0.82rem; font-weight: 700; color: #0b3056;">
            Perform / Test Access on this Shipment (Adds Event to Job Log Immediately):
          </div>
          <div style="display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap;">
            <select id="quickActorSelect" class="form-select" style="width: auto; padding: 0.4rem 0.65rem; font-size: 0.82rem;">
              <option value="u_asha">Asha Sharma (Checker C01-C03)</option>
              <option value="u_ravi">Ravi Verma (Checker C03 Mumbai)</option>
              <option value="u_priya">Priya Shah (Client C02 External)</option>
              <option value="u_dev">Devendra Patel (AccessAdmin)</option>
              <option value="u_suresh">Suresh Kumar (Maker Delhi/Kolkata)</option>
            </select>
            <select id="quickActionSelect" class="form-select" style="width: auto; padding: 0.4rem 0.65rem; font-size: 0.82rem;">
              <option value="check">check</option>
              <option value="prepare">prepare</option>
              <option value="file">file</option>
              <option value="view">view</option>
              <option value="cancel">cancel</option>
              <option value="reopen">reopen</option>
            </select>
            <button class="action-btn action-btn-sm" onclick="executeQuickAccessTest()">
              <span>&#x25B6;</span> Test &amp; Log
            </button>
          </div>
        </div>
      </div>

      <!-- Timeline & Event Stream -->
      <div>
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
          <h3 style="font-size: 1.05rem; font-weight: 800; color: #0b3056;">Shipment Audit Timeline &amp; Incident Log</h3>
          <span id="logEventCount" style="font-size: 0.8rem; color: var(--text-dim);">0 events recorded</span>
        </div>

        <div id="timelineContainer" class="timeline">
          <div style="color: #64748b; font-size: 0.85rem; padding: 1rem 0;">Loading shipment audit trail...</div>
        </div>
      </div>
    </div>
  </main>

  {footer_html}
  {SHARED_JS}
"""
    return html_body + LOGS_PAGE_JS + "\n</body>\n</html>"

# ==============================================================================
# PAGE 5: STAFF ACCESS DIRECTORY & EXPLAINER
# ==============================================================================
def render_staff_page(conn: sqlite3.Connection) -> str:
    header_html = render_header("staff", conn)
    footer_html = render_footer()

    html_body = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Staff Access Directory &amp; Explainer — Tez Adhikar</title>
  <style>{SHARED_CSS}</style>
</head>
<body>
  {header_html}

  <main class="main-wrap">
    <!-- Explainer Module -->
    <div class="surface-card">
      <div class="card-header">
        <div>
          <div class="card-title">Decision Explainer: Side-by-Side Comparison</div>
          <div class="card-desc">Explains exactly why Person A is authorized while Person B is denied on the same job with signed receipts.</div>
        </div>
      </div>

      <div class="form-row">
        <div class="field-group">
          <label class="field-label">User A</label>
          <select id="expUserA" class="form-select">
            <option value="u_asha">Asha Sharma (Checker C01-C03)</option>
            <option value="u_suresh">Suresh Kumar (Maker Delhi/Kolkata)</option>
            <option value="u_karan">Karan Joshi (Meera's Delegate)</option>
          </select>
        </div>
        <div class="field-group">
          <label class="field-label">User B (Comparison)</label>
          <select id="expUserB" class="form-select">
            <option value="u_ravi">Ravi Verma (Checker C03 Mumbai Import)</option>
            <option value="u_priya">Priya Shah (Client C02 External)</option>
            <option value="u_dev">Devendra Patel (AccessAdmin)</option>
          </select>
        </div>
        <div class="field-group">
          <label class="field-label">Action</label>
          <select id="expAction" class="form-select">
            <option value="check">check</option>
            <option value="prepare">prepare</option>
            <option value="file">file</option>
            <option value="cancel">cancel</option>
          </select>
        </div>
        <div class="field-group">
          <label class="field-label">Job ID</label>
          <input type="text" id="expJobId" class="form-input" value="JOB_0001">
        </div>
      </div>

      <button class="action-btn" onclick="executeExplain()">
        <span>&#x2696;</span> Compare Decisions Side-by-Side
      </button>

      <div id="expResultPanel" style="display: none; margin-top: 1.5rem;">
        <div id="expSummaryBanner" style="background: #eff6ff; border: 1px solid #bfdbfe; border-radius: var(--radius-sm); padding: 0.9rem 1.25rem; font-size: 0.9rem; color: #1e40af; font-weight: 600; margin-bottom: 1rem;">
        </div>
        <div class="compare-grid">
          <div class="compare-col">
            <div style="font-weight: 800; color: #0b3056; margin-bottom: 0.5rem;" id="expColTitleA">User A</div>
            <div id="expBadgeA" class="badge-decision" style="font-size: 0.9rem; display: inline-block; margin-bottom: 0.75rem;"></div>
            <pre class="receipt-code"><code id="expCodeA" style="background:transparent; border:none; color:inherit; padding:0;"></code></pre>
          </div>
          <div class="compare-col">
            <div style="font-weight: 800; color: #0b3056; margin-bottom: 0.5rem;" id="expColTitleB">User B</div>
            <div id="expBadgeB" class="badge-decision" style="font-size: 0.9rem; display: inline-block; margin-bottom: 0.75rem;"></div>
            <pre class="receipt-code"><code id="expCodeB" style="background:transparent; border:none; color:inherit; padding:0;"></code></pre>
          </div>
        </div>
      </div>
    </div>

    <!-- Staff Access Directory -->
    <div class="surface-card">
      <div class="card-header">
        <div>
          <div class="card-title">Staff Access Directory &amp; Plain-English Matrix</div>
          <div class="card-desc">Standard dataset: 20 staff across 5 branches (Mumbai, Delhi, Chennai, Kolkata, Ahmedabad) and 10 corporate clients.</div>
        </div>
      </div>

      <div class="data-table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>User ID</th>
              <th>Name</th>
              <th>Role</th>
              <th>Scope &amp; Branch Assignment</th>
              <th>Special Constraints / Behaviors</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>u_asha</code></td>
              <td><strong>Asha Sharma</strong></td>
              <td><span class="badge-stage stage-Prepared">Maker &amp; Checker</span></td>
              <td>Maker: ALL clients/branches<br>Checker: Clients C01, C02, C03</td>
              <td>Separation of Duties (SoD) blocks Asha from checking or filing jobs she prepared.</td>
            </tr>
            <tr>
              <td><code>u_ravi</code></td>
              <td><strong>Ravi Verma</strong></td>
              <td><span class="badge-stage stage-Checked">Checker</span></td>
              <td>Client C03, Mumbai Branch, Imports only</td>
              <td>Narrow specialist scope.</td>
            </tr>
            <tr>
              <td><code>u_meera</code></td>
              <td><strong>Meera Nair</strong></td>
              <td><span class="badge-stage stage-Reopened">Supervisor</span></td>
              <td>Mumbai Branch</td>
              <td>Currently absent on leave; delegated authority to Karan.</td>
            </tr>
            <tr>
              <td><code>u_karan</code></td>
              <td><strong>Karan Joshi</strong></td>
              <td><span class="badge-stage stage-Reopened">Delegate (Supervisor)</span></td>
              <td>Mumbai Branch</td>
              <td>Acts under Meera's authority. Real-actor SoD applies. No chaining.</td>
            </tr>
            <tr>
              <td><code>u_priya</code></td>
              <td><strong>Priya Shah</strong></td>
              <td><span class="badge-stage stage-Cancelled">ClientViewer</span></td>
              <td>Client C02 (Zenith Global) only</td>
              <td>External client user: view-only. Internal identities and margins redacted.</td>
            </tr>
            <tr>
              <td><code>u_dev</code></td>
              <td><strong>Devendra Patel</strong></td>
              <td><span class="badge-stage stage-Confirmed">AccessAdmin</span></td>
              <td>Security Administration</td>
              <td>Manages access. Zero job pipeline powers. Self-escalation blocked.</td>
            </tr>
            <tr>
              <td><code>u_arun</code></td>
              <td><strong>Arun Mukherjee</strong></td>
              <td><span class="badge-stage stage-Confirmed">AccessAdmin</span></td>
              <td>Security Administration</td>
              <td>Second admin required to co-approve administrative grant modifications.</td>
            </tr>
            <tr>
              <td><code>svc_parser</code></td>
              <td><strong>Overnight Parser</strong></td>
              <td><span class="badge-stage stage-Confirmed">Service</span></td>
              <td>All branches / EDI</td>
              <td>Restricted strictly to Confirmed stage job create and update.</td>
            </tr>
            <tr>
              <td><code>u_arjun</code></td>
              <td><strong>Arjun Kapoor</strong></td>
              <td><span class="badge-stage stage-Checked">Auditor</span></td>
              <td>All branches</td>
              <td>Cross-branch compliance read-only visibility and time-machine audit access.</td>
            </tr>
            <tr>
              <td><code>u_vikram</code></td>
              <td><strong>Vikram Singh</strong></td>
              <td><span class="badge-stage stage-Reopened">Supervisor</span></td>
              <td>Delhi Branch</td>
              <td>Oversees northern regional branch customs operations.</td>
            </tr>
            <tr>
              <td><code>u_ananya</code></td>
              <td><strong>Ananya Iyer</strong></td>
              <td><span class="badge-stage stage-Reopened">Supervisor</span></td>
              <td>Chennai Branch</td>
              <td>Oversees southern regional branch customs operations.</td>
            </tr>
            <tr>
              <td><code>u_rajesh</code></td>
              <td><strong>Rajesh Ghosh</strong></td>
              <td><span class="badge-stage stage-Reopened">Supervisor</span></td>
              <td>Kolkata Branch</td>
              <td>Oversees eastern regional branch customs operations.</td>
            </tr>
            <tr>
              <td><code>u_sneha</code></td>
              <td><strong>Sneha Mehta</strong></td>
              <td><span class="badge-stage stage-Reopened">Supervisor</span></td>
              <td>Ahmedabad Branch</td>
              <td>Oversees western ICD customs operations.</td>
            </tr>
            <tr>
              <td><code>u_suresh</code></td>
              <td><strong>Suresh Kumar</strong></td>
              <td><span class="badge-stage stage-Prepared">Maker</span></td>
              <td>Delhi &amp; Kolkata branches</td>
              <td>Prepares documents for northern and eastern clients.</td>
            </tr>
            <tr>
              <td><code>u_deepa</code></td>
              <td><strong>Deepa Reddy</strong></td>
              <td><span class="badge-stage stage-Checked">Checker</span></td>
              <td>Delhi &amp; Kolkata branches</td>
              <td>Reviews declarations for northern and eastern clients.</td>
            </tr>
            <tr>
              <td><code>u_manoj</code></td>
              <td><strong>Manoj Tiwari</strong></td>
              <td><span class="badge-stage stage-Filed">Filer</span></td>
              <td>Mumbai branch</td>
              <td>Submits filings for western shipments.</td>
            </tr>
            <tr>
              <td><code>u_pooja</code></td>
              <td><strong>Pooja Hegde</strong></td>
              <td><span class="badge-stage stage-Filed">Filer</span></td>
              <td>Delhi branch</td>
              <td>Submits filings for northern shipments.</td>
            </tr>
            <tr>
              <td><code>u_rahul</code></td>
              <td><strong>Rahul Sen</strong></td>
              <td><span class="badge-stage stage-Confirmed">Viewer</span></td>
              <td>Mumbai branch</td>
              <td>Internal read-only observer for western branch shipments.</td>
            </tr>
            <tr>
              <td><code>u_rohit</code></td>
              <td><strong>Rohit Deshmukh</strong></td>
              <td><span class="badge-stage stage-Prepared">Maker</span></td>
              <td>Chennai &amp; Ahmedabad branches</td>
              <td>Prepares declarations for southern and western shipments.</td>
            </tr>
            <tr>
              <td><code>u_neha</code></td>
              <td><strong>Neha Kulkarni</strong></td>
              <td><span class="badge-stage stage-Checked">Checker</span></td>
              <td>Chennai &amp; Ahmedabad branches</td>
              <td>Reviews declarations for southern and western shipments.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </main>

  {footer_html}
  {SHARED_JS}
"""
    return html_body + STAFF_PAGE_JS + "\n</body>\n</html>"

# Compatibility alias: redirect any security request to the clean Job Logs page
def render_security_page(conn: sqlite3.Connection) -> str:
    return render_logs_page(conn)

# Compatibility alias for existing unit tests
def render_modern_dashboard_html(conn: sqlite3.Connection) -> str:
    return render_home_page(conn)
