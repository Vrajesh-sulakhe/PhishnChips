// app.js - Luxury Bento Dashboard Controller & Real-Time Orchestrator for Phish&Chips

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
const pipelineStatusText = document.getElementById('pipelineStatusText');
const sseIndicator = document.getElementById('sseIndicator');
const clearWorkspaceBtn = document.getElementById('clearWorkspaceBtn');
const quickSbiBtn = document.getElementById('quickSbiBtn');
const inspectPhishnetBtn = document.getElementById('inspectPhishnetBtn');
const viewPerimeterBtn = document.getElementById('viewPerimeterBtn');
const refreshHealthBtn = document.getElementById('refreshHealthBtn');

// Pipeline Timeline Nodes (6 nodes along the timeline ruler)
const nodeUser = document.getElementById('nodeUser');
const nodeHost = document.getElementById('nodeHost');
const nodeSandbox = document.getElementById('nodeSandbox');
const nodeInspector = document.getElementById('nodeInspector');
const nodeInference = document.getElementById('nodeInference');
const nodeDone = document.getElementById('nodeDone');

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

// Translations Catalog
const LOCALIZATIONS = {
  en: {
    safe: "SAFE",
    suspicious: "SUSPICIOUS",
    scam: "SCAM DETECTED",
    brandMismatch: "Brand Mismatch:",
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

// 1. Dynamic Control Plane Telemetry Polling (/api/health)
async function fetchControlPlaneHealth() {
  try {
    const res = await fetch('/api/health');
    if (!res.ok) return;
    const data = await res.json();
    if (slotsBadge) {
      slotsBadge.innerText = data.slots_display || `${data.active_sandboxes || 0} / ${data.max_sandboxes || 3} Allocated`;
    }
  } catch (err) {
    console.error("Health check error:", err);
  }
}

fetchControlPlaneHealth();
setInterval(fetchControlPlaneHealth, 5000);

if (refreshHealthBtn) {
  refreshHealthBtn.addEventListener('click', () => {
    fetchControlPlaneHealth();
  });
}

// Nav Tab Click Handlers
document.querySelectorAll('.nav-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('nav-tab-active'));
    tab.classList.add('nav-tab-active');
  });
});

// Quick Action Buttons
if (quickSbiBtn) {
  quickSbiBtn.addEventListener('click', () => {
    targetUrlInput.value = 'demo://fake-bank';
    scanForm.dispatchEvent(new Event('submit', { cancelable: true }));
  });
}

function scrollToPerimeter() {
  const visCard = document.querySelector('.visualizer-card');
  if (visCard) {
    visCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
    visCard.classList.add('ring-2', 'ring-amber-400');
    setTimeout(() => visCard.classList.remove('ring-2', 'ring-amber-400'), 1500);
  }
}

if (inspectPhishnetBtn) inspectPhishnetBtn.addEventListener('click', scrollToPerimeter);
if (viewPerimeterBtn) viewPerimeterBtn.addEventListener('click', scrollToPerimeter);

// Preset Buttons
document.querySelectorAll('.preset-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    targetUrlInput.value = btn.getAttribute('data-url');
  });
});

// Reset Session
if (clearWorkspaceBtn) {
  clearWorkspaceBtn.addEventListener('click', () => {
    if (eventSource) {
      eventSource.close();
      eventSource = null;
    }
    targetUrlInput.value = '';
    detonationWorkspace.classList.add('hidden');
    verdictCard.classList.add('hidden');
    approvalModal.classList.add('hidden');
    resetPipelineNodes();
    pipelineStatusText.innerText = 'Real-Time Orchestration Pipeline';
    terminalLog.innerHTML = '<div class="terminal-line text-zinc-600 font-mono">Waiting for sandbox detonation...</div>';
    primaryShot.src = '';
    shotCountSpan.innerText = '0 captures';
    totalEventCount = 0;
    eventCountSpan.innerText = '0 events';
    submitBtn.disabled = false;
    submitBtn.innerHTML = `<span>Detonate in Sandbox</span> <span>⚡</span>`;
  });
}

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

// 2. Scan Submission & SSE Connection
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

  // Animate Pipeline Start
  resetPipelineNodes();
  setNodeState(nodeUser, 'completed');
  setNodeState(nodeHost, 'active');
  pipelineStatusText.innerText = 'DISPATCHING TO EPHEMERAL DETONATION CHAMBER...';

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
    resetPipelineNodes();
  }
});

// 3. Server-Sent Events (SSE) Listener
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
    // Fallback poll check if SSE disconnects prematurely
    checkJobStatusFallback(jobId);
  };
}

// Render Incoming Stream Event
function handleStreamEvent(ev) {
  totalEventCount++;
  eventCountSpan.innerText = `${totalEventCount} event(s)`;

  // Create terminal line
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

  // Update Pipeline State Machine
  updatePipelineNodes(ev.stage, ev.message);
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

// 4. Pipeline Timeline Animation Updates
function setNodeState(node, state) {
  if (!node) return;
  node.classList.remove('active', 'completed', 'warning');
  if (state) node.classList.add(state);
}

function updatePipelineNodes(stage, message) {
  if (stage === 'SANDBOX_INIT') {
    setNodeState(nodeHost, 'completed');
    setNodeState(nodeSandbox, 'active');
    pipelineStatusText.innerText = 'CAGED CONTAINER SPAWNED (phishnet 172.30.0.0/16)...';
  } else if (stage === 'CAP_DROP') {
    setNodeState(nodeSandbox, 'completed');
    setNodeState(nodeInspector, 'active');
  } else if (stage === 'NAVIGATING') {
    setNodeState(nodeInspector, 'active');
    pipelineStatusText.innerText = 'HEADLESS CHROMIUM NAVIGATING TARGET LINK...';
  } else if (stage === 'INTERCEPT') {
    setNodeState(nodeInspector, 'warning');
    pipelineStatusText.innerText = '⚠️ CONTAINMENT TRIGGERED: UNTRUSTED SSRF/DOWNLOAD BLOCKED';
  } else if (stage === 'EVIDENCE_COLLECTED') {
    setNodeState(nodeInspector, 'completed');
  } else if (stage === 'AWAITING_APPROVAL') {
    setNodeState(nodeInspector, 'warning');
    approvalModal.classList.remove('hidden');
    pipelineStatusText.innerText = 'PAUSED: AWAITING HUMAN AUTHORIZATION (PATTERN B)';
  } else if (stage === 'P2_INIT') {
    approvalModal.classList.add('hidden');
    setNodeState(nodeInspector, 'active');
    pipelineStatusText.innerText = 'INJECTING DECOY CANARY VALUES IN SANDBOX PASS...';
  } else if (stage === 'INFERENCE_DISPATCH') {
    setNodeState(nodeInspector, 'completed');
    setNodeState(nodeInference, 'active');
    pipelineStatusText.innerText = 'DISPATCHING FORENSICS TO VULTR SERVERLESS INFERENCE...';
  } else if (stage === 'DONE') {
    setNodeState(nodeInference, 'completed');
    setNodeState(nodeDone, 'completed');
    pipelineStatusText.innerText = '🍟 PHISH FRIED. SANDBOX DESTROYED & PURGED.';
  }
}

function resetPipelineNodes() {
  [nodeUser, nodeHost, nodeSandbox, nodeInspector, nodeInference, nodeDone].forEach(node => {
    if (node) {
      node.classList.remove('active', 'completed', 'warning');
    }
  });
}

// 5. Pattern B Approval Event Handlers
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

// 6. Job Completion & Verdict Display
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
    verdictHeading.className = 'text-2xl font-extrabold tracking-tight font-mono text-red-500';
    verdictBadge.className = 'mt-1 inline-block px-3 py-0.5 text-xs font-bold rounded-full font-mono bg-red-950 text-red-300 border border-red-700';
    verdictBadge.innerText = '🔴 ' + loc.scam;
    escalationDrawer.classList.remove('hidden');
  } else if (verdict === 'SUSPICIOUS') {
    verdictHeading.innerText = loc.suspicious;
    verdictHeading.className = 'text-2xl font-extrabold tracking-tight font-mono text-amber-500';
    verdictBadge.className = 'mt-1 inline-block px-3 py-0.5 text-xs font-bold rounded-full font-mono bg-amber-950 text-amber-300 border border-amber-700';
    verdictBadge.innerText = '🟡 ' + loc.suspicious;
    escalationDrawer.classList.remove('hidden');
  } else {
    verdictHeading.innerText = loc.safe;
    verdictHeading.className = 'text-2xl font-extrabold tracking-tight font-mono text-emerald-400';
    verdictBadge.className = 'mt-1 inline-block px-3 py-0.5 text-xs font-bold rounded-full font-mono bg-emerald-950 text-emerald-300 border border-emerald-700';
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
      tag.className = 'px-2.5 py-0.5 bg-red-900/40 text-red-300 border border-red-800 rounded-full text-[11px] font-mono font-medium';
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
