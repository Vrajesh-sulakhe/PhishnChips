// app.js - Frontend Detonation Controller & Live Polling Engine for Phish&Chips

let currentJobId = null;
let pollInterval = null;
let lastRenderedEventCount = 0;

const scanForm = document.getElementById('scanForm');
const targetUrlInput = document.getElementById('targetUrl');
const submitBtn = document.getElementById('submitBtn');
const stepperContainer = document.getElementById('stepperContainer');
const approvalBanner = document.getElementById('approvalBanner');
const approveBtn = document.getElementById('approveBtn');
const denyBtn = document.getElementById('denyBtn');
const resultsArea = document.getElementById('resultsArea');
const terminalLog = document.getElementById('terminalLog');
const primaryShot = document.getElementById('primaryShot');
const shotCountSpan = document.getElementById('shotCount');
const zoomModal = document.getElementById('zoomModal');
const modalImg = document.getElementById('modalImg');
const closeModalBtn = document.getElementById('closeModalBtn');

// Setup Presets
document.querySelectorAll('.preset-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    targetUrlInput.value = btn.getAttribute('data-url');
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

if (closeModalBtn) {
  closeModalBtn.addEventListener('click', () => {
    zoomModal.classList.add('hidden');
  });
}

zoomModal.addEventListener('click', (e) => {
  if (e.target === zoomModal) {
    zoomModal.classList.add('hidden');
  }
});

// Handle Detonation Form Submit
scanForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = targetUrlInput.value.trim();
  if (!url) return;

  if (pollInterval) {
    clearInterval(pollInterval);
    pollInterval = null;
  }

  // Reset UI State
  submitBtn.disabled = true;
  submitBtn.innerHTML = `<span>Detonating...</span> <span class="animate-spin">⏳</span>`;
  stepperContainer.classList.remove('hidden');
  resultsArea.classList.remove('hidden');
  approvalBanner.classList.add('hidden');
  resetStepper();
  setStepActive('step1');

  terminalLog.innerHTML = '';
  lastRenderedEventCount = 0;
  primaryShot.src = '';
  shotCountSpan.innerText = '0 screenshots';

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    if (!res.ok) {
      const errData = await res.json();
      throw new Error(errData.detail || 'Scan request failed.');
    }

    const data = await res.json();
    currentJobId = data.job_id;

    // Start Polling
    pollInterval = setInterval(pollJobStatus, 1000);
    pollJobStatus();

  } catch (err) {
    alert(`Detonation Failed: ${err.message}`);
    submitBtn.disabled = false;
    submitBtn.innerHTML = `<span>Detonate in Sandbox</span> <span>⚡</span>`;
    resetStepper();
  }
});

// Polling Worker
async function pollJobStatus() {
  if (!currentJobId) return;

  try {
    const res = await fetch(`/api/scan/${currentJobId}`);
    if (!res.ok) return;

    const job = await res.json();

    // 1. Render Log Events
    renderEvents(job.events || []);

    // 2. Update Screenshots
    if (job.screenshots && job.screenshots.length > 0) {
      shotCountSpan.innerText = `${job.screenshots.length} screenshot(s)`;
      const latestShot = job.screenshots[job.screenshots.length - 1];
      if (primaryShot.src !== window.location.origin + latestShot) {
        primaryShot.src = latestShot;
      }
      setStepCompleted('step2');
      setStepActive('step3');
    }

    // 3. Update Stepper & State
    if (job.status === 'running') {
      setStepCompleted('step1');
      setStepActive('step2');
    } else if (job.status === 'awaiting_approval') {
      setStepCompleted('step2');
      setStepActive('step3');
      approvalBanner.classList.remove('hidden');
    } else if (job.status === 'analyzing') {
      approvalBanner.classList.add('hidden');
      setStepCompleted('step3');
      setStepActive('step4');
    } else if (job.status === 'done') {
      approvalBanner.classList.add('hidden');
      setStepCompleted('step4');
      setStepCompleted('step5');
      clearInterval(pollInterval);
      pollInterval = null;
      submitBtn.disabled = false;
      submitBtn.innerHTML = `<span>Detonate in Sandbox</span> <span>⚡</span>`;
      renderVerdict(job.result);
    } else if (job.status === 'error') {
      approvalBanner.classList.add('hidden');
      clearInterval(pollInterval);
      pollInterval = null;
      submitBtn.disabled = false;
      submitBtn.innerHTML = `<span>Detonate in Sandbox</span> <span>⚡</span>`;
      alert(`Scan encountered error: ${job.error || 'Unknown failure'}`);
    }

  } catch (err) {
    console.error('Polling error:', err);
  }
}

// Pattern B Approval Actions
approveBtn.addEventListener('click', async () => {
  if (!currentJobId) return;
  approveBtn.disabled = true;
  denyBtn.disabled = true;
  await fetch(`/api/scan/${currentJobId}/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ approve: true })
  });
  approvalBanner.classList.add('hidden');
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
  approvalBanner.classList.add('hidden');
});

// Render Log Events to Terminal
function renderEvents(events) {
  if (!events || events.length === lastRenderedEventCount) return;

  for (let i = lastRenderedEventCount; i < events.length; i++) {
    const e = events[i];
    const line = document.createElement('div');
    line.className = 'terminal-line';

    const timeSpan = document.createElement('span');
    timeSpan.className = 'terminal-ts';
    timeSpan.innerText = e.time || (e.ts ? e.ts.split('T')[1].split('.')[0] : '');

    const msgSpan = document.createElement('span');
    if (e.msg.includes('🍟')) {
      msgSpan.className = 'terminal-fries';
    } else if (e.msg.includes('Blocked')) {
      msgSpan.className = 'text-amber-400 font-semibold';
    } else {
      msgSpan.className = 'terminal-msg';
    }
    msgSpan.innerText = e.msg;

    line.appendChild(timeSpan);
    line.appendChild(msgSpan);
    terminalLog.appendChild(line);
  }

  lastRenderedEventCount = events.length;
  terminalLog.scrollTop = terminalLog.scrollHeight;
}

// Render Verdict Card
function renderVerdict(result) {
  if (!result) return;

  const verdict = (result.verdict || 'SUSPICIOUS').toUpperCase();
  const heading = document.getElementById('verdictHeading');
  const badge = document.getElementById('verdictBadge');
  const brandBanner = document.getElementById('brandMismatchBanner');
  const brandName = document.getElementById('brandName');
  const asksForContainer = document.getElementById('asksForContainer');
  const asksForList = document.getElementById('asksForList');
  const reasonsList = document.getElementById('reasonsList');
  const threatSource = document.getElementById('threatSource');
  const confidenceScore = document.getElementById('confidenceScore');

  heading.innerText = verdict;
  confidenceScore.innerText = `Confidence: ${Math.round((result.confidence || 0.8) * 100)}%`;
  threatSource.innerText = result.threat_source || 'Vultr Serverless Inference';

  if (verdict === 'SCAM') {
    heading.className = 'text-2xl font-extrabold tracking-tight text-red-500';
    badge.className = 'px-2.5 py-1 text-xs font-bold rounded bg-red-950 text-red-300 border border-red-700';
    badge.innerText = '🔴 SCAM DETECTED';
  } else if (verdict === 'SUSPICIOUS') {
    heading.className = 'text-2xl font-extrabold tracking-tight text-amber-500';
    badge.className = 'px-2.5 py-1 text-xs font-bold rounded bg-amber-950 text-amber-300 border border-amber-700';
    badge.innerText = '🟡 SUSPICIOUS';
  } else {
    heading.className = 'text-2xl font-extrabold tracking-tight text-emerald-400';
    badge.className = 'px-2.5 py-1 text-xs font-bold rounded bg-emerald-950 text-emerald-300 border border-emerald-700';
    badge.innerText = '🟢 SAFE';
  }

  // Brand mismatch
  if (result.pretending_to_be) {
    brandName.innerText = result.pretending_to_be;
    brandBanner.classList.remove('hidden');
  } else {
    brandBanner.classList.add('hidden');
  }

  // Asks For Badges
  if (result.asks_for && result.asks_for.length > 0) {
    asksForContainer.classList.remove('hidden');
    asksForList.innerHTML = '';
    result.asks_for.forEach(item => {
      const tag = document.createElement('span');
      tag.className = 'px-2 py-0.5 bg-red-900/40 text-red-300 border border-red-800 rounded text-[11px] font-medium';
      tag.innerText = item;
      asksForList.appendChild(tag);
    });
  } else {
    asksForContainer.classList.add('hidden');
  }

  // Reasons List
  reasonsList.innerHTML = '';
  (result.reasons || []).forEach(r => {
    const li = document.createElement('li');
    li.innerText = r;
    reasonsList.appendChild(li);
  });
}

// Stepper Helpers
function resetStepper() {
  ['step1', 'step2', 'step3', 'step4', 'step5'].forEach(id => {
    const el = document.getElementById(id);
    el.className = 'stepper-item';
  });
}

function setStepActive(id) {
  const el = document.getElementById(id);
  if (el) el.className = 'stepper-item active';
}

function setStepCompleted(id) {
  const el = document.getElementById(id);
  if (el) el.className = 'stepper-item completed';
}
