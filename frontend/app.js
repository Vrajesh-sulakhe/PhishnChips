// app.js - Real-Time Control Plane, SSE Stream Listener & Pattern B Engine for Phish&Chips

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

// Pipeline Nodes
const nodeUser = document.getElementById('nodeUser');
const nodeHost = document.getElementById('nodeHost');
const nodeSandbox = document.getElementById('nodeSandbox');
const nodeInference = document.getElementById('nodeInference');

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

// Control Plane Status Elements
const slotsBadge = document.getElementById('slotsBadge');
const netBadge = document.getElementById('netBadge');
const inferenceBadge = document.getElementById('inferenceBadge');

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
    if (slotsBadge) slotsBadge.innerText = data.slots_display || `${data.active_sandboxes} / ${data.max_sandboxes} Sandboxes Active`;
    if (netBadge) netBadge.innerText = "phishnet: Enforced";
    if (inferenceBadge) inferenceBadge.innerText = data.inference_status.includes("Connected") ? "Inference: Connected" : "Inference: Standby";
  } catch (err) {
    console.error("Health check error:", err);
  }
}

fetchControlPlaneHealth();
setInterval(fetchControlPlaneHealth, 5000);

// Preset Buttons
document.querySelectorAll('.preset-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    targetUrlInput.value = btn.getAttribute('data-url');
  });
});

// Image Modal Listeners
primaryShot.addEventListener('click', () => {
  if (primaryShot.src && !primaryShot.src.endsWith('/')) {
    modalImg.src = primaryShot.src;
    zoomModal.classList.remove('hidden');
  }
});

closeModalBtn.addEventListener('click', () => zoomModal.classList.add('hidden'));
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

// 2. Scan Submission & EventSource (SSE) Integration
scanForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = targetUrlInput.value.trim();
  if (!url) return;

  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }

  // Reset UI State
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
  nodeUser.classList.add('completed');
  nodeHost.classList.add('active');
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

// 4. Pipeline Node Graph Animation Updates
function updatePipelineNodes(stage, message) {
  if (stage === 'SANDBOX_INIT') {
    nodeHost.classList.remove('active');
    nodeHost.classList.add('completed');
    nodeSandbox.classList.add('active');
    pipelineStatusText.innerText = 'SANDBOX CAGED & DETONATING IN CHROMIUM...';
  } else if (stage === 'INTERCEPT') {
    nodeSandbox.classList.add('warning');
    pipelineStatusText.innerText = '⚠️ CONTAINMENT MOMENT: UNTRUSTED PROBE BLOCKED BY CAGED BOUNDARIES';
  } else if (stage === 'AWAITING_APPROVAL') {
    nodeSandbox.classList.add('warning');
    approvalModal.classList.remove('hidden');
    pipelineStatusText.innerText = 'PAUSED: AWAITING HUMAN IN-THE-LOOP AUTHORIZATION (PATTERN B)';
  } else if (stage === 'P2_INIT') {
    approvalModal.classList.add('hidden');
    nodeSandbox.classList.remove('warning');
    nodeSandbox.classList.add('active');
    pipelineStatusText.innerText = 'INJECTING DECOY CREDENTIALS IN SECOND CONTAINER PASS...';
  } else if (stage === 'INFERENCE_DISPATCH') {
    nodeSandbox.classList.remove('active', 'warning');
    nodeSandbox.classList.add('completed');
    nodeInference.classList.add('active');
    pipelineStatusText.innerText = 'DISPATCHING DETONATION FORENSICS TO VULTR SERVERLESS INFERENCE...';
  } else if (stage === 'DONE') {
    nodeInference.classList.remove('active');
    nodeInference.classList.add('completed');
    pipelineStatusText.innerText = '🍟 DETONATION COMPLETE & SANDBOX PURGED';
  }
}

function resetPipelineNodes() {
  [nodeUser, nodeHost, nodeSandbox, nodeInference].forEach(node => {
    node.className = 'pipeline-node';
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
    verdictBadge.className = 'mt-1 inline-block px-2.5 py-0.5 text-xs font-bold rounded font-mono bg-red-950 text-red-300 border border-red-700';
    verdictBadge.innerText = '🔴 ' + loc.scam;
    escalationDrawer.classList.remove('hidden');
  } else if (verdict === 'SUSPICIOUS') {
    verdictHeading.innerText = loc.suspicious;
    verdictHeading.className = 'text-2xl font-extrabold tracking-tight font-mono text-amber-500';
    verdictBadge.className = 'mt-1 inline-block px-2.5 py-0.5 text-xs font-bold rounded font-mono bg-amber-950 text-amber-300 border border-amber-700';
    verdictBadge.innerText = '🟡 ' + loc.suspicious;
    escalationDrawer.classList.remove('hidden');
  } else {
    verdictHeading.innerText = loc.safe;
    verdictHeading.className = 'text-2xl font-extrabold tracking-tight font-mono text-emerald-400';
    verdictBadge.className = 'mt-1 inline-block px-2.5 py-0.5 text-xs font-bold rounded font-mono bg-emerald-950 text-emerald-300 border border-emerald-700';
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
      tag.className = 'px-2 py-0.5 bg-red-900/40 text-red-300 border border-red-800 rounded text-[11px] font-mono font-medium';
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
