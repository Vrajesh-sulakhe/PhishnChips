// app.js - High-End Monera-Style Controller & Real-Time Orchestrator for Phish&Chips

let currentJobId = null;
let eventSource = null;
let currentVerdictData = null;
let currentLanguage = 'en';
let totalEventCount = 0;

// DOM Elements
const scanForm = document.getElementById('scanForm');
const targetUrlInput = document.getElementById('targetUrl');
const submitBtn = document.getElementById('submitBtn');
const detonationWorkspace = document.getElementById('detonationWorkspace');
const terminalLog = document.getElementById('terminalLog');
const eventCountSpan = document.getElementById('eventCount');
const primaryShot = document.getElementById('primaryShot');
const shotCountSpan = document.getElementById('shotCount');
const approvalModal = document.getElementById('approvalModal');
const approveBtn = document.getElementById('approveBtn');
const denyBtn = document.getElementById('denyBtn');
const sseIndicator = document.getElementById('sseIndicator');
const topbarTitle = document.getElementById('topbarTitle');

// View Switchers
const dashboardSection = document.getElementById('dashboardSection');
const landingSection = document.getElementById('landingSection');
const viewDashboardBtn = document.getElementById('viewDashboardBtn');
const viewLandingBtn = document.getElementById('viewLandingBtn');
const ctaLaunchBtn = document.getElementById('ctaLaunchBtn');

// Verdict Card Elements
const verdictCard = document.getElementById('verdictCard');
const verdictHeading = document.getElementById('verdictHeading');
const verdictBadge = document.getElementById('verdictBadge');
const brandBanner = document.getElementById('brandBanner');
const brandName = document.getElementById('brandName');
const targetedDataBox = document.getElementById('targetedDataBox');
const targetedDataList = document.getElementById('targetedDataList');
const reasonsList = document.getElementById('reasonsList');
const threatSourceText = document.getElementById('threatSourceText');
const confidenceText = document.getElementById('confidenceText');
const escalationDrawer = document.getElementById('escalationDrawer');

// Modal Preview
const zoomModal = document.getElementById('zoomModal');
const modalImg = document.getElementById('modalImg');
const closeModalBtn = document.getElementById('closeModalBtn');

// Control Plane Telemetry Elements
const slotsBadge = document.getElementById('slotsBadge');
const activityTableBody = document.getElementById('activityTableBody');

// Translations Catalog
const LOCALIZATIONS = {
  en: {
    safe: "SAFE",
    suspicious: "SUSPICIOUS",
    scam: "SCAM DETECTED",
    brandMismatch: "Brand Impersonation:",
    escalationTitle: "Emergency Incident Escalation",
    escalationDesc: "If you or a family member entered passwords, UPI PINs, or OTPs on this site, take immediate defensive action:",
    noThreats: "No credential harvesting forms, deceptive branding, or unauthorized downloads detected."
  },
  hi: {
    safe: "सुरक्षित (SAFE)",
    suspicious: "संदिग्ध (SUSPICIOUS)",
    scam: "धोखाधड़ी / स्कैम (SCAM)",
    brandMismatch: "फर्जी ब्रांड नकल:",
    escalationTitle: "आपातकालीन वित्तीय साइबर सुरक्षा अलर्ट",
    escalationDesc: "यदि आपने या किसी परिजन ने इस लिंक पर पासवर्ड, यूपीआई पिन या ओटीपी दर्ज किया है, तो तुरंत अपने बैंक खाते को फ्रीज करें:",
    noThreats: "कोई क्रेडेंशियल चोरी, भ्रामक ब्रांडिंग या अनधिकृत डाउनलोड नहीं पाया गया।"
  },
  kn: {
    safe: "ಸುರಕ್ಷಿತ (SAFE)",
    suspicious: "ಸಂಶಯಾಸ್ಪದ (SUSPICIOUS)",
    scam: "ವಂಚನೆ / ಸ್ಕ್ಯಾಮ್ (SCAM)",
    brandMismatch: "ನಕಲಿ ಬ್ರ್ಯಾಂಡ್ ವಂಚನೆ:",
    escalationTitle: "ತುರ್ತು ಸೈಬರ್ ಕ್ರೈಂ ಎಚ್ಚರಿಕೆ",
    escalationDesc: "ನೀವು ಅಥವಾ ನಿಮ್ಮ ಕುಟುಂಬದವರು ಈ ಲಿಂಕ್‌ನಲ್ಲಿ ಪಾಸ್‌ವರ್ಡ್, ಯುಪಿಐ ಪಿನ್ ಅಥವಾ ಒಟಿಪಿಯನ್ನು ನಮೂದಿಸಿದ್ದರೆ, ತಕ್ಷಣ ಬ್ಯಾಂಕ್ ಖಾತೆಯನ್ನು ನಿರ್ಬಂಧಿಸಿ:",
    noThreats: "ಯಾವುದೇ ಪಾಸ್‌ವರ್ಡ್ ಕಳ್ಳತನ ಅಥವಾ ಅನಧಿಕೃತ ಡೌನ್‌ಲೋಡ್ ಕಂಡುಬಂದಿಲ್ಲ."
  }
};

// 1. Navigation & View Switcher (Dashboard vs Landing Page)
function showView(view) {
  if (view === 'dashboard') {
    dashboardSection.classList.remove('hidden');
    landingSection.classList.add('hidden');
    topbarTitle.innerText = 'Overview';

    if (viewDashboardBtn) {
      viewDashboardBtn.className = 'px-3.5 py-1 rounded-full bg-white/10 text-white font-semibold transition-all shadow-sm';
      viewLandingBtn.className = 'px-3.5 py-1 rounded-full text-zinc-400 hover:text-white transition-all';
    }

    document.querySelectorAll('.sidebar-nav-item').forEach(item => {
      if (item.getAttribute('data-nav') === 'dashboard') item.classList.add('active');
      else item.classList.remove('active');
    });
  } else if (view === 'landing') {
    dashboardSection.classList.add('hidden');
    landingSection.classList.remove('hidden');
    topbarTitle.innerText = 'Product Showcase';

    if (viewLandingBtn) {
      viewLandingBtn.className = 'px-3.5 py-1 rounded-full bg-white/10 text-white font-semibold transition-all shadow-sm';
      viewDashboardBtn.className = 'px-3.5 py-1 rounded-full text-zinc-400 hover:text-white transition-all';
    }

    document.querySelectorAll('.sidebar-nav-item').forEach(item => {
      if (item.getAttribute('data-nav') === 'landing') item.classList.add('active');
      else item.classList.remove('active');
    });
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
}

if (viewDashboardBtn) viewDashboardBtn.addEventListener('click', () => showView('dashboard'));
if (viewLandingBtn) viewLandingBtn.addEventListener('click', () => showView('landing'));
if (ctaLaunchBtn) ctaLaunchBtn.addEventListener('click', () => showView('dashboard'));

document.querySelectorAll('.sidebar-nav-item').forEach(btn => {
  btn.addEventListener('click', () => {
    const nav = btn.getAttribute('data-nav');
    if (nav) showView(nav);
  });
});

document.querySelectorAll('.sidebar-sub-item').forEach(sub => {
  sub.addEventListener('click', () => {
    document.querySelectorAll('.sidebar-sub-item').forEach(s => s.classList.remove('active'));
    sub.classList.add('active');
    showView('dashboard');
  });
});

// Mobile Sidebar Toggle
const mobileMenuBtn = document.getElementById('mobileMenuBtn');
if (mobileMenuBtn) {
  mobileMenuBtn.addEventListener('click', () => {
    const sidebar = document.querySelector('.sidebar');
    if (sidebar) {
      sidebar.classList.toggle('hidden');
      sidebar.classList.toggle('fixed');
      sidebar.classList.toggle('z-50');
      sidebar.classList.toggle('inset-y-0');
      sidebar.classList.toggle('left-0');
    }
  });
}

// 2. Control Plane Telemetry Polling (/api/health)
async function fetchControlPlaneHealth() {
  try {
    const res = await fetch('/api/health');
    if (!res.ok) return;
    const data = await res.json();
    if (slotsBadge) {
      slotsBadge.innerText = `${data.active_sandboxes || 0} / ${data.max_sandboxes || 3} Active`;
    }
  } catch (err) {
    console.error("Health check error:", err);
  }
}

fetchControlPlaneHealth();
setInterval(fetchControlPlaneHealth, 5000);

// Presets Click Listeners
document.querySelectorAll('.preset-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    targetUrlInput.value = btn.getAttribute('data-url');
    showView('dashboard');
  });
});

// Activity Table Rows Click Handlers
document.querySelectorAll('#activityTableBody tr').forEach(row => {
  row.addEventListener('click', () => {
    const url = row.getAttribute('data-url');
    if (url) {
      targetUrlInput.value = url;
      scanForm.dispatchEvent(new Event('submit', { cancelable: true }));
    }
  });
});

// Image Zoom Modal Listeners
if (primaryShot) {
  primaryShot.addEventListener('click', () => {
    if (primaryShot.src && !primaryShot.src.endsWith('/')) {
      modalImg.src = primaryShot.src;
      zoomModal.classList.remove('hidden');
    }
  });
}

if (closeModalBtn) closeModalBtn.addEventListener('click', () => zoomModal.classList.add('hidden'));
zoomModal.addEventListener('click', (e) => {
  if (e.target === zoomModal) zoomModal.classList.add('hidden');
});

// Language Switcher Listeners
document.querySelectorAll('.lang-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.lang-btn').forEach(b => {
      b.classList.remove('text-amber-400', 'font-bold', 'bg-zinc-800');
      b.classList.add('text-zinc-400');
    });
    btn.classList.add('text-amber-400', 'font-bold', 'bg-zinc-800');
    btn.classList.remove('text-zinc-400');
    currentLanguage = btn.getAttribute('data-lang');
    if (currentVerdictData) {
      renderVerdict(currentVerdictData);
    }
  });
});

// 3. Scan Submission & SSE Streaming
scanForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = targetUrlInput.value.trim();
  if (!url) return;

  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }

  // Reset UI State for Detonation
  submitBtn.disabled = true;
  submitBtn.innerHTML = `<span>Detonating...</span> <span class="animate-spin">⏳</span>`;
  detonationWorkspace.classList.remove('hidden');
  verdictCard.classList.add('hidden');
  approvalModal.classList.add('hidden');
  primaryShot.src = '';
  shotCountSpan.innerText = '0 captures';
  terminalLog.innerHTML = '';
  totalEventCount = 0;
  eventCountSpan.innerText = '0 events';

  // Smooth scroll to workspace
  detonationWorkspace.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Scan request failed.');
    }

    const data = await res.json();
    currentJobId = data.job_id;

    // Connect to SSE Stream
    connectSSEStream(currentJobId);

  } catch (err) {
    alert(`Detonation error: ${err.message}`);
    submitBtn.disabled = false;
    submitBtn.innerHTML = `<span>Detonate in Sandbox</span> <span>⚡</span>`;
  }
});

// Connect to Server-Sent Events (SSE) Stream
function connectSSEStream(jobId) {
  eventSource = new EventSource(`/api/scan/${jobId}/stream`);

  eventSource.onmessage = (event) => {
    try {
      const payload = JSON.parse(event.data);

      if (payload.stage === 'JOB_SNAPSHOT') {
        const job = payload.job;
        if (job) {
          handleJobCompletion(job);
        }
        return;
      }

      handleStreamEvent(payload);

    } catch (e) {
      console.error("Error parsing SSE event:", e);
    }
  };

  eventSource.onerror = () => {
    checkJobStatusFallback(jobId);
  };
}

// Render Incoming SSE Event to Terminal
function handleStreamEvent(ev) {
  totalEventCount++;
  eventCountSpan.innerText = `${totalEventCount} event(s)`;

  const line = document.createElement('div');
  line.className = 'terminal-line';

  const tsSpan = document.createElement('span');
  tsSpan.className = 'text-zinc-500 font-mono text-[10px] flex-shrink-0';
  tsSpan.innerText = ev.time || (ev.ts ? ev.ts.split('T')[1].split('.')[0] : '');

  const badgeSpan = document.createElement('span');
  badgeSpan.className = `terminal-badge ${getBadgeClass(ev.stage)}`;
  badgeSpan.innerText = getBadgeLabel(ev.stage);

  const msgSpan = document.createElement('span');
  msgSpan.className = 'font-mono text-zinc-200 text-xs flex-1 break-words';

  if (ev.message && ev.message.includes('🍟')) {
    msgSpan.innerHTML = `<span class="terminal-fries">${ev.message}</span>`;
  } else if (ev.message && ev.message.includes('Blocked')) {
    msgSpan.className = 'font-mono text-amber-300 font-semibold text-xs flex-1 break-words';
    msgSpan.innerText = ev.message;
  } else {
    msgSpan.innerText = ev.message || '';
  }

  line.appendChild(tsSpan);
  line.appendChild(badgeSpan);
  line.appendChild(msgSpan);
  terminalLog.appendChild(line);
  terminalLog.scrollTop = terminalLog.scrollHeight;

  // Pattern B Human-in-the-Loop check
  if (ev.stage === 'AWAITING_APPROVAL') {
    approvalModal.classList.remove('hidden');
  } else if (ev.stage === 'P2_INIT') {
    approvalModal.classList.add('hidden');
  }
}

function getBadgeClass(stage) {
  switch (stage) {
    case 'SANDBOX_INIT': return 'badge-init';
    case 'CAP_DROP': return 'badge-contain';
    case 'NAVIGATING': return 'badge-init';
    case 'INTERCEPT': return 'badge-intercept';
    case 'EVIDENCE_COLLECTED': return 'badge-evidence';
    case 'AWAITING_APPROVAL': return 'badge-approval';
    case 'P2_INIT': return 'badge-approval';
    case 'INFERENCE_DISPATCH': return 'badge-inference';
    case 'CONTAINER_DESTROYED': return 'badge-contain';
    case 'DONE': return 'badge-done';
    default: return 'badge-init';
  }
}

function getBadgeLabel(stage) {
  switch (stage) {
    case 'SANDBOX_INIT': return 'INIT';
    case 'CAP_DROP': return 'CONTAIN';
    case 'NAVIGATING': return 'BROWSER';
    case 'INTERCEPT': return 'BLOCKED';
    case 'EVIDENCE_COLLECTED': return 'EVIDENCE';
    case 'AWAITING_APPROVAL': return 'APPROVAL';
    case 'P2_INIT': return 'DECOY_PASS';
    case 'INFERENCE_DISPATCH': return 'INFERENCE';
    case 'CONTAINER_DESTROYED': return 'PURGED';
    case 'DONE': return 'SUCCESS';
    default: return 'LOG';
  }
}

// 4. Pattern B Approval Event Handlers
approveBtn.addEventListener('click', async () => {
  if (!currentJobId) return;
  approveBtn.disabled = true;
  denyBtn.disabled = true;
  await fetch(`/api/scan/${currentJobId}/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ approve: true })
  });
  approvalModal.classList.add('hidden');
});

denyBtn.addEventListener('click', async () => {
  if (!currentJobId) return;
  approveBtn.disabled = true;
  denyBtn.disabled = true;
  await fetch(`/api/scan/${currentJobId}/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ approve: false })
  });
  approvalModal.classList.add('hidden');
});

// Fallback Poll Check
async function checkJobStatusFallback(jobId) {
  try {
    const res = await fetch(`/api/scan/${jobId}`);
    if (!res.ok) return;
    const job = await res.json();
    if (job.status === 'done' || job.status === 'error') {
      handleJobCompletion(job);
    }
  } catch (err) {}
}

// 5. Job Completion & Verdict Display
function handleJobCompletion(job) {
  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }

  submitBtn.disabled = false;
  submitBtn.innerHTML = `<span>Detonate in Sandbox</span> <span>⚡</span>`;

  // Render Screenshots
  if (job.screenshots && job.screenshots.length > 0) {
    shotCountSpan.innerText = `${job.screenshots.length} capture(s)`;
    primaryShot.src = job.screenshots[job.screenshots.length - 1];
  }

  // Render Verdict
  if (job.result) {
    currentVerdictData = job.result;
    renderVerdict(job.result);
    prependActivityRow(job);
  }

  fetchControlPlaneHealth();
}

function renderVerdict(result) {
  const verdict = (result.verdict || 'SUSPICIOUS').toUpperCase();
  const loc = LOCALIZATIONS[currentLanguage] || LOCALIZATIONS.en;

  confidenceText.innerText = `Confidence: ${Math.round((result.confidence || 0.8) * 100)}%`;
  threatSourceText.innerText = result.threat_source || 'Vultr Serverless Inference';

  if (verdict === 'SCAM') {
    verdictHeading.innerText = loc.scam;
    verdictHeading.className = 'text-2xl font-extrabold tracking-tight font-mono text-[#ef4444]';
    verdictBadge.className = 'mt-1 inline-block md-chip md-chip-error font-mono';
    verdictBadge.innerText = '🔴 ' + loc.scam;
    escalationDrawer.classList.remove('hidden');
  } else if (verdict === 'SUSPICIOUS') {
    verdictHeading.innerText = loc.suspicious;
    verdictHeading.className = 'text-2xl font-extrabold tracking-tight font-mono text-[#f59e0b]';
    verdictBadge.className = 'mt-1 inline-block md-chip md-chip-warning font-mono';
    verdictBadge.innerText = '🟡 ' + loc.suspicious;
    escalationDrawer.classList.remove('hidden');
  } else {
    verdictHeading.innerText = loc.safe;
    verdictHeading.className = 'text-2xl font-extrabold tracking-tight font-mono text-[#10b981]';
    verdictBadge.className = 'mt-1 inline-block md-chip md-chip-success font-mono';
    verdictBadge.innerText = '🟢 ' + loc.safe;
    escalationDrawer.classList.add('hidden');
  }

  // Brand Impersonation Banner
  if (result.pretending_to_be) {
    brandName.innerText = result.pretending_to_be;
    brandBanner.classList.remove('hidden');
  } else {
    brandBanner.classList.add('hidden');
  }

  // Targeted Data Badges
  if (result.asks_for && result.asks_for.length > 0) {
    targetedDataBox.classList.remove('hidden');
    targetedDataList.innerHTML = '';
    result.asks_for.forEach(item => {
      const tag = document.createElement('span');
      tag.className = 'md-chip md-chip-error text-[11px]';
      tag.innerText = item;
      targetedDataList.appendChild(tag);
    });
  } else {
    targetedDataBox.classList.add('hidden');
  }

  // Reasons List
  reasonsList.innerHTML = '';
  const reasons = (result.reasons && result.reasons.length > 0) ? result.reasons : [loc.noThreats];
  reasons.forEach(r => {
    const li = document.createElement('li');
    li.innerText = r;
    reasonsList.appendChild(li);
  });

  // Localized Escalation Content
  const escTitle = document.getElementById('escalationTitle');
  const escDesc = document.getElementById('escalationDesc');
  if (escTitle) escTitle.innerText = loc.escalationTitle;
  if (escDesc) escDesc.innerText = loc.escalationDesc;

  verdictCard.classList.remove('hidden');
}

// Add newly finished scan to recent activity table
function prependActivityRow(job) {
  if (!activityTableBody || !job.result) return;

  const tr = document.createElement('tr');
  tr.className = 'cursor-pointer hover:bg-[#161616] transition-colors';
  tr.setAttribute('data-url', job.target_url);

  const verdict = (job.result.verdict || 'SUSPICIOUS').toUpperCase();
  let statusBadge = '<span class="md-chip md-chip-success">COMPLETED</span>';
  if (verdict === 'SCAM') {
    statusBadge = '<span class="md-chip md-chip-error">SCAM DETECTED</span>';
  } else if (verdict === 'SUSPICIOUS') {
    statusBadge = '<span class="md-chip md-chip-warning">SUSPICIOUS</span>';
  }

  const now = new Date();
  const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  tr.innerHTML = `
    <td class="text-zinc-400">${timeStr}</td>
    <td class="font-bold truncate max-w-[200px] ${verdict === 'SCAM' ? 'text-red-400' : 'text-zinc-200'}">${job.target_url}</td>
    <td>${job.result.asks_for && job.result.asks_for.length > 0 ? 'Credential Harvester' : 'General Detonation'}</td>
    <td>phishnet Caged</td>
    <td class="${verdict === 'SCAM' ? 'text-red-400' : 'text-emerald-400'}">${Math.round((job.result.confidence || 0.9) * 100)}%</td>
    <td>${job.result.pretending_to_be || 'Generic'}</td>
    <td>${statusBadge}</td>
  `;

  tr.addEventListener('click', () => {
    targetUrlInput.value = job.target_url;
  });

  activityTableBody.insertBefore(tr, activityTableBody.firstChild);
}
