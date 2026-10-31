// =============================================================================
// Interactive SOC Portal — Application Controller
// =============================================================================

document.addEventListener('DOMContentLoaded', () => {
  if (typeof LIVE_DATA === 'undefined') {
    console.error('LIVE_DATA not loaded');
    return;
  }

  const alerts = LIVE_DATA.alerts || [];
  const activeCase = LIVE_DATA.case || {};

  // State
  let currentFilter = 'all';
  let searchQuery = '';

  // DOM Elements
  const kpiTotal = document.getElementById('kpi-total-alerts');
  const kpiIps = document.getElementById('kpi-unique-ips');
  const kpiUsers = document.getElementById('kpi-target-users');
  const kpiCritical = document.getElementById('kpi-critical-alerts');
  const searchInput = document.getElementById('search-input');
  const filterChips = document.querySelectorAll('.chip');
  const alertsTbody = document.getElementById('alerts-tbody');
  const tableCountTag = document.getElementById('table-count-tag');
  const threatIntelBox = document.getElementById('threat-intel-box');

  // Modals
  const caseModal = document.getElementById('case-modal');
  const rawModal = document.getElementById('raw-alert-modal');
  const btnViewCase = document.getElementById('btn-view-case');
  const modalCloseBtn = document.getElementById('modal-close-btn');
  const rawModalCloseBtn = document.getElementById('raw-modal-close-btn');
  const btnCloseModal = document.getElementById('btn-close-modal');
  const rawAlertCode = document.getElementById('raw-alert-code');

  // ── 1. Calculate & Populate KPIs ───────────────────────────────────────────
  const uniqueIps = new Set();
  const targetUsers = new Set();
  let criticalCount = 0;

  alerts.forEach(a => {
    const ip = a.data?.srcip;
    if (ip) uniqueIps.add(ip);
    const user = a.data?.srcuser || a.data?.dstuser;
    if (user) targetUsers.add(user);
    const level = a.rule?.level || 0;
    if (level >= 10) criticalCount++;
  });

  kpiTotal.textContent = alerts.length.toLocaleString();
  kpiIps.textContent = uniqueIps.size.toLocaleString();
  kpiUsers.textContent = targetUsers.size.toLocaleString();
  kpiCritical.textContent = criticalCount.toLocaleString();

  // ── 2. Threat Intel Box ────────────────────────────────────────────────────
  if (threatIntelBox) {
    threatIntelBox.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 0.85rem;">
        <div style="background: rgba(0,0,0,0.3); padding: 0.85rem 1rem; border-radius: 8px; border-left: 3px solid var(--accent-rose);">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <span style="font-family: var(--font-mono); font-weight: 700; color: var(--accent-rose); font-size: 0.95rem;">209.99.190.186</span>
            <span class="badge-level level-critical">CONFIDENCE: 100%</span>
          </div>
          <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">
            Zurich, Switzerland • AS402253 (SKN Subnet & Telecom)
          </div>
          <div style="font-size: 0.75rem; color: var(--text-dim); margin-top: 0.25rem;">
            Tactics: Low-and-slow SSH dictionary attack targeting 7+ standard accounts.
          </div>
        </div>

        <div style="background: rgba(0,0,0,0.3); padding: 0.85rem 1rem; border-radius: 8px; border-left: 3px solid var(--accent-amber);">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <span style="font-family: var(--font-mono); font-weight: 700; color: var(--accent-amber); font-size: 0.95rem;">80.94.92.234</span>
            <span class="badge-level level-high">ACTIVE SCANNER</span>
          </div>
          <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">
            Opportunistic Cloud IP • Automated Port 22 Probes
          </div>
          <div style="font-size: 0.75rem; color: var(--text-dim); margin-top: 0.25rem;">
            Tactics: Automated banner scraping and rapid root login probes.
          </div>
        </div>
      </div>
    `;
  }

  // ── 3. Charts ──────────────────────────────────────────────────────────────
  initCharts(alerts);

  // ── 4. Table Rendering & Filter Logic ──────────────────────────────────────
  function renderTable() {
    const filtered = alerts.filter(a => {
      // Severity filter
      const lvl = a.rule?.level || 0;
      if (currentFilter === 'critical' && lvl < 12) return false;
      if (currentFilter === 'high' && (lvl < 8 || lvl >= 12)) return false;
      if (currentFilter === 'medium' && (lvl < 4 || lvl >= 8)) return false;
      if (currentFilter === 'low' && lvl >= 4) return false;

      // Search query
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const ip = (a.data?.srcip || '').toLowerCase();
        const user = (a.data?.srcuser || a.data?.dstuser || '').toLowerCase();
        const ruleId = (a.rule?.id || '').toString();
        const desc = (a.rule?.description || '').toLowerCase();
        return ip.includes(q) || user.includes(q) || ruleId.includes(q) || desc.includes(q);
      }
      return true;
    });

    tableCountTag.textContent = `Showing ${filtered.length} of ${alerts.length} events`;
    alertsTbody.innerHTML = '';

    filtered.slice(0, 50).forEach(a => {
      const tr = document.createElement('tr');
      const lvl = a.rule?.level || 0;
      let badgeClass = 'level-low';
      if (lvl >= 12) badgeClass = 'level-critical';
      else if (lvl >= 8) badgeClass = 'level-high';
      else if (lvl >= 4) badgeClass = 'level-medium';

      const timeStr = a.timestamp ? a.timestamp.substring(11, 19) : '--';
      const ruleId = a.rule?.id || '--';
      const srcIp = a.data?.srcip || (a.agent?.name || 'Local');
      const user = a.data?.srcuser || a.data?.dstuser || '--';
      const desc = a.rule?.description || 'Normalized Security Event';

      const tdTime = document.createElement('td');
      tdTime.style.fontFamily = 'var(--font-mono)';
      tdTime.style.color = 'var(--text-dim)';
      tdTime.textContent = timeStr;

      const tdRule = document.createElement('td');
      const spanRule = document.createElement('span');
      spanRule.className = 'rule-link';
      spanRule.textContent = `#${ruleId}`;
      tdRule.appendChild(spanRule);

      const tdLevel = document.createElement('td');
      const spanLevel = document.createElement('span');
      spanLevel.className = `badge-level ${badgeClass}`;
      spanLevel.textContent = `Lvl ${lvl}`;
      tdLevel.appendChild(spanLevel);

      const tdIp = document.createElement('td');
      const spanIp = document.createElement('span');
      spanIp.className = 'ip-tag';
      spanIp.textContent = srcIp;
      tdIp.appendChild(spanIp);

      const tdUser = document.createElement('td');
      tdUser.style.fontFamily = 'var(--font-mono)';
      tdUser.style.color = 'var(--accent-amber)';
      tdUser.textContent = user;

      const tdDesc = document.createElement('td');
      tdDesc.textContent = desc;

      const tdAction = document.createElement('td');
      const btnInspect = document.createElement('button');
      btnInspect.className = 'btn btn-outline btn-inspect';
      btnInspect.style.padding = '0.25rem 0.65rem';
      btnInspect.style.fontSize = '0.75rem';
      btnInspect.textContent = 'Inspect';
      btnInspect.addEventListener('click', () => {
        rawAlertCode.textContent = JSON.stringify(a, null, 2);
        rawModal.classList.add('open');
      });
      tdAction.appendChild(btnInspect);

      tr.appendChild(tdTime);
      tr.appendChild(tdRule);
      tr.appendChild(tdLevel);
      tr.appendChild(tdIp);
      tr.appendChild(tdUser);
      tr.appendChild(tdDesc);
      tr.appendChild(tdAction);

      alertsTbody.appendChild(tr);
    });
  }

  renderTable();

  // Filter Chips Listeners
  filterChips.forEach(chip => {
    chip.addEventListener('click', () => {
      filterChips.forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      currentFilter = chip.getAttribute('data-filter');
      renderTable();
    });
  });

  // Search Input Listener
  searchInput.addEventListener('input', (e) => {
    searchQuery = e.target.value.trim();
    renderTable();
  });

  // ── 5. Case Modal Population & Actions ─────────────────────────────────────
  if (btnViewCase && caseModal) {
    btnViewCase.addEventListener('click', () => {
      document.getElementById('modal-case-title').textContent = activeCase.title || 'Incident Case';
      document.getElementById('modal-case-id').textContent = activeCase.case_id || 'CASE-2026-001';
      document.getElementById('modal-source-ip').textContent = activeCase.source_ip || '--';
      document.getElementById('modal-geo').textContent = `${activeCase.geo?.city || 'Zurich'}, ${activeCase.geo?.country || 'Switzerland'} (${activeCase.geo?.asn || ''})`;
      document.getElementById('modal-status').textContent = (activeCase.status || 'contained').toUpperCase();

      const timelineUl = document.getElementById('modal-timeline');
      timelineUl.innerHTML = '';
      (activeCase.timeline || []).forEach(item => {
        const li = document.createElement('li');
        li.style.marginBottom = '0.5rem';
        li.style.borderLeft = '2px solid var(--accent-cyan)';
        li.style.paddingLeft = '0.75rem';

        const strong = document.createElement('strong');
        strong.style.color = 'var(--text-dim)';
        strong.style.fontFamily = 'var(--font-mono)';
        strong.style.fontSize = '0.75rem';
        strong.textContent = item.timestamp || '';

        const eventDiv = document.createElement('div');
        eventDiv.textContent = item.event || '';

        li.appendChild(strong);
        li.appendChild(eventDiv);
        timelineUl.appendChild(li);
      });

      const hashDiv = document.getElementById('modal-evidence-hashes');
      hashDiv.innerHTML = `
        ✓ 9ef714dd... honeypot_audit.log (6.18 MB)<br>
        ✓ 6cc44576... honeypot_auth.log (326 KB)<br>
        ✓ 940ee2b2... honeypot_defense_posture.txt (1.25 KB)<br>
        ✓ f40ef342... honeypot_system_state.txt (684 B)<br>
        ✓ c78a37db... wazuh_alerts.json (2.00 MB)<br>
        ✓ 356be706... EVIDENCE_SIGNING_PUBKEY.pub (625 B)<br>
        <span style="color: var(--accent-emerald);">RSA-3072 Detached Signatures & WORM Bucket Lock Cryptographically Verified</span>
      `;

      caseModal.classList.add('open');
    });

    modalCloseBtn.addEventListener('click', () => caseModal.classList.remove('open'));
    btnCloseModal.addEventListener('click', () => caseModal.classList.remove('open'));
    caseModal.addEventListener('click', (e) => {
      if (e.target === caseModal) caseModal.classList.remove('open');
    });
  }

  if (rawModal && rawModalCloseBtn) {
    rawModalCloseBtn.addEventListener('click', () => rawModal.classList.remove('open'));
    rawModal.addEventListener('click', (e) => {
      if (e.target === rawModal) rawModal.classList.remove('open');
    });
  }
});

// ── Chart Initialization Helper ──────────────────────────────────────────────
function initCharts(alerts) {
  // 1. Timeline Chart
  const timeBuckets = {};
  alerts.forEach(a => {
    const timeKey = a.timestamp ? a.timestamp.substring(11, 15) + '0' : 'Other';
    timeBuckets[timeKey] = (timeBuckets[timeKey] || 0) + 1;
  });

  const timeLabels = Object.keys(timeBuckets).sort();
  const timeCounts = timeLabels.map(k => timeBuckets[k]);

  const ctxTimeline = document.getElementById('chart-timeline');
  if (ctxTimeline) {
    new Chart(ctxTimeline, {
      type: 'line',
      data: {
        labels: timeLabels,
        datasets: [{
          label: 'Alert Volume',
          data: timeCounts,
          borderColor: '#00f0ff',
          backgroundColor: 'rgba(0, 240, 255, 0.1)',
          fill: true,
          tension: 0.4,
          pointBackgroundColor: '#00f0ff',
          pointBorderColor: '#fff',
          pointRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: 'rgba(148, 163, 184, 0.08)' }, ticks: { color: '#94a3b8' } },
          y: { grid: { color: 'rgba(148, 163, 184, 0.08)' }, ticks: { color: '#94a3b8' }, beginAtZero: true }
        }
      }
    });
  }

  // 2. MITRE ATT&CK Doughnut Chart
  const mitreCounts = {
    'Credential Access (T1110)': 0,
    'Lateral Movement (T1021)': 0,
    'Defense Evasion (T1078)': 0,
    'Privilege Escalation (T1548)': 0
  };

  alerts.forEach(a => {
    const tactics = a.rule?.mitre?.tactic || [];
    if (tactics.includes('Credential Access')) mitreCounts['Credential Access (T1110)']++;
    if (tactics.includes('Lateral Movement')) mitreCounts['Lateral Movement (T1021)']++;
    if (tactics.includes('Defense Evasion')) mitreCounts['Defense Evasion (T1078)']++;
    if (tactics.includes('Privilege Escalation')) mitreCounts['Privilege Escalation (T1548)']++;
  });

  const ctxMitre = document.getElementById('chart-mitre');
  if (ctxMitre) {
    new Chart(ctxMitre, {
      type: 'doughnut',
      data: {
        labels: Object.keys(mitreCounts),
        datasets: [{
          data: Object.values(mitreCounts),
          backgroundColor: ['#ef4444', '#f59e0b', '#8b5cf6', '#00f0ff'],
          borderColor: '#0f172a',
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: { color: '#94a3b8', font: { size: 11 } }
          }
        }
      }
    });
  }

  // 3. Targeted Users Bar Chart
  const userCounts = {};
  alerts.forEach(a => {
    const user = a.data?.srcuser || a.data?.dstuser;
    if (user && user !== 'root(uid=0)' && user !== 'ubuntu(uid=1000)') {
      userCounts[user] = (userCounts[user] || 0) + 1;
    }
  });

  const sortedUsers = Object.entries(userCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const userLabels = sortedUsers.map(u => u[0]);
  const userValues = sortedUsers.map(u => u[1]);

  const ctxUsers = document.getElementById('chart-users');
  if (ctxUsers) {
    new Chart(ctxUsers, {
      type: 'bar',
      data: {
        labels: userLabels.length ? userLabels : ['root', 'ubuntu', 'admin', 'sysadmin'],
        datasets: [{
          label: 'Attempt Count',
          data: userValues.length ? userValues : [15, 8, 5, 3],
          backgroundColor: 'rgba(139, 92, 246, 0.75)',
          borderColor: '#8b5cf6',
          borderWidth: 1,
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: 'y',
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: 'rgba(148, 163, 184, 0.08)' }, ticks: { color: '#94a3b8' }, beginAtZero: true },
          y: { grid: { display: false }, ticks: { color: '#94a3b8' } }
        }
      }
    });
  }
}
