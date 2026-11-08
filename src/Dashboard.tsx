import { lazy, Suspense, useEffect, useRef, useState } from "react";
import Brand from "./Brand";
import CubeFallback from "./CubeFallback";

const InvestigationCube = lazy(() => import("./InvestigationCube"));

type IconName =
  | "shield"
  | "grid"
  | "activity"
  | "book"
  | "chevron"
  | "arrow"
  | "link"
  | "bolt"
  | "check"
  | "globe"
  | "layers"
  | "cpu"
  | "lock"
  | "search"
  | "refresh"
  | "download"
  | "close"
  | "external"
  | "alert"
  | "clock"
  | "help";

export function Icon({
  name,
  size = 20,
  className = "",
}: {
  name: IconName;
  size?: number;
  className?: string;
}) {
  const paths: Record<IconName, React.ReactNode> = {
    shield: (
      <>
        <path d="M12 3 4.5 6v5.5c0 4.5 3.2 7.5 7.5 9.5 4.3-2 7.5-5 7.5-9.5V6L12 3Z" />
        <path d="m8.5 12 2.3 2.3 4.7-4.8" />
      </>
    ),
    grid: (
      <>
        <rect x="3.5" y="3.5" width="6" height="6" rx="1.5" />
        <rect x="14.5" y="3.5" width="6" height="6" rx="1.5" />
        <rect x="3.5" y="14.5" width="6" height="6" rx="1.5" />
        <rect x="14.5" y="14.5" width="6" height="6" rx="1.5" />
      </>
    ),
    activity: <path d="M3 12h4l3-7 4 14 3-7h4" />,
    book: (
      <>
        <path d="M12 5v15M12 5C9 3 5 3 3 4v15c3-1 6-1 9 1 3-2 6-2 9-1V4c-3-1-6-1-9 1Z" />
      </>
    ),
    chevron: <path d="m8 10 4 4 4-4" />,
    arrow: <path d="M5 12h14m-5-5 5 5-5 5" />,
    link: (
      <>
        <path d="m10 13 4-4m-6 6-1 1a4 4 0 0 1-5-5l4-4a4 4 0 0 1 6 0m0 2 1-1a4 4 0 0 1 6 5l-4 4a4 4 0 0 1-6 0" />
      </>
    ),
    bolt: <path d="m13 2-9 12h7l-1 8 10-13h-7l1-7Z" />,
    check: <path d="m5 12 4 4L19 6" />,
    globe: (
      <>
        <circle cx="12" cy="12" r="9" />
        <ellipse cx="12" cy="12" rx="4" ry="9" />
        <path d="M3 12h18" />
      </>
    ),
    layers: (
      <>
        <path d="m12 3 9 5-9 5-9-5 9-5Zm-9 9 9 5 9-5M3 16l9 5 9-5" />
      </>
    ),
    cpu: (
      <>
        <rect x="6" y="6" width="12" height="12" rx="3" />
        <path d="M9 2v4m6-4v4M9 18v4m6-4v4M2 9h4m-4 6h4m12-6h4m-4 6h4" />
        <rect x="9" y="9" width="6" height="6" rx="1" />
      </>
    ),
    lock: (
      <>
        <rect x="5" y="10" width="14" height="11" rx="3" />
        <path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2" />
      </>
    ),
    search: (
      <>
        <circle cx="10.5" cy="10.5" r="6.5" />
        <path d="m16 16 4 4" />
      </>
    ),
    refresh: (
      <>
        <path d="M20 8a8 8 0 1 0 .3 7M20 3v5h-5" />
      </>
    ),
    download: (
      <>
        <path d="M12 3v12m-4-4 4 4 4-4M4 16v5h16v-5" />
      </>
    ),
    close: <path d="m6 6 12 12M6 18 18 6" />,
    external: (
      <>
        <path d="M14 3h7v7m0-7L10 14M10 4H4v16h16v-6" />
      </>
    ),
    alert: (
      <>
        <path d="m12 3 10 18H2L12 3Zm0 6v5m0 3v.5" />
      </>
    ),
    clock: (
      <>
        <circle cx="12" cy="12" r="9" />
        <path d="M12 7v5l3 2" />
      </>
    ),
    help: (
      <>
        <circle cx="12" cy="12" r="9" />
        <path d="M9.5 9a2.5 2.5 0 1 1 4 2c-1 .5-1.5 1-1.5 2m0 3v.5" />
      </>
    ),
  };
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.65"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      {paths[name]}
    </svg>
  );
}

export type Outcome = "benign" | "suspicious" | "malicious" | "indeterminate";

export type ScanRecord = {
  id: string;
  raw_job_id?: string;
  url: string;
  time: string;
  malicious: boolean;
  outcome?: Outcome;
  threat_type?: string;
  evidence_chain?: string[];
  confidence: number;
  brand: string;
  screenshots?: string[];
  reasons?: string[];
  asks_for?: string[];
  threat_source?: string;
  c2_intelligence?: {
    has_c2_exfiltration: boolean;
    drop_destinations?: Array<{
      channel_type: string;
      target_endpoint: string;
      identifier: string;
      risk_rating: string;
      actionable_takedown_recipient?: string;
    }>;
    attribution_summary?: string;
  };
  re_intelligence?: {
    has_disassembly: boolean;
    attribution_summary?: string;
    mitre_tactics?: string[];
    artifacts?: Array<{
      name: string;
      type: "pe" | "wasm";
      sha256: string;
      size_bytes: number;
      entropy: number;
      is_packed: boolean;
      format?: string;
      sections?: Array<{ name: string; virtual_size: number; raw_size: number; entropy: number }>;
      suspicious_apis?: string[];
      capabilities?: string[];
      ioc_strings?: string[];
      wat_preview?: string;
      exports?: string[];
      imports?: Array<{ module: string; field: string }>;
    }>;
  };
};

/** Single source of truth for verdict interpretation. Only an explicit malicious verdict is "malicious":
 *  suspicious / indeterminate (timeout, API failure) must never be rendered as a confirmed threat. */
function outcomeFrom(v: any): Outcome {
  // Defensive guard: if telemetry explicitly confirms legitimate domain or verified top-tier domain without hard anomalies, never classify as malicious
  const reasonsText = Array.isArray(v?.reasons) ? v.reasons.join(" ").toLowerCase() : "";
  if (reasonsText.includes("landed on legitimate") || reasonsText.includes("verified top-tier domain")) {
    if (!reasonsText.includes("credential form submits") && !reasonsText.includes("auto-download attempted") && !reasonsText.includes("outbound post")) {
      return "benign";
    }
  }
  const c = String(v?.verdict_class || "").toLowerCase();
  if (c === "benign" || c === "suspicious" || c === "malicious" || c === "indeterminate") return c;
  const legacy = String(v?.verdict || "").toUpperCase();
  if (legacy === "SCAM" || legacy === "MALICIOUS") return "malicious";
  if (legacy === "SUSPICIOUS") return "suspicious";
  if (legacy === "SAFE" || legacy === "BENIGN") return "benign";
  return "indeterminate";
}

const outcomeText: Record<Outcome, string> = {
  benign: "Safe",
  suspicious: "Suspicious",
  malicious: "Malicious",
  indeterminate: "Manual review",
};

const threatTypeText: Record<string, string> = {
  credential_harvest: "Credential harvester",
  malware_delivery: "Malware delivery",
  open_redirect: "Open redirect",
  scareware: "Scareware",
  suspicious_behavior: "Suspicious behavior",
};

function outcomeOf(r: ScanRecord): Outcome {
  return r.outcome ?? (r.malicious ? "malicious" : "benign");
}

function verdictClass(r: ScanRecord): string {
  const o = outcomeOf(r);
  return o === "benign" ? "safe" : o;
}

function outcomeTone(r: ScanRecord): { bg: string; border: string; fg: string } {
  switch (outcomeOf(r)) {
    case "malicious":
      return { bg: "rgba(213, 53, 43, 0.08)", border: "rgba(213, 53, 43, 0.25)", fg: "var(--accent)" };
    case "benign":
      return { bg: "rgba(34, 197, 94, 0.08)", border: "rgba(34, 197, 94, 0.25)", fg: "#4ade80" };
    default:
      return { bg: "rgba(234, 179, 8, 0.08)", border: "rgba(234, 179, 8, 0.25)", fg: "#facc15" };
  }
}

function threatLabel(r: ScanRecord): string {
  const o = outcomeOf(r);
  if (o === "benign") return "No threats found";
  if (o === "indeterminate") return "Analysis incomplete";
  return threatTypeText[r.threat_type || ""] || (o === "malicious" ? "Malicious activity" : "Needs review");
}

const bankPresetUrl = "demo://fake-bank";

const initialRecords: ScanRecord[] = [];

const stages = [
  { icon: "globe" as IconName, name: "Client dispatch", detail: "Secure URL handoff" },
  { icon: "lock" as IconName, name: "Network isolation", detail: "Host-level firewall" },
  { icon: "layers" as IconName, name: "Micro-VM execution", detail: "Ephemeral container" },
  { icon: "cpu" as IconName, name: "AI verdict", detail: "Real-time classification" },
];

export default function Dashboard({
  viewer,
  onSignOut,
  onHome,
}: {
  viewer: { name: string; email: string };
  onSignOut: () => void;
  onHome: () => void;
}) {
  const [tab, setTab] = useState("Dashboard");
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");
  const [records, setRecords] = useState<ScanRecord[]>(initialRecords);
  const [filter, setFilter] = useState("All records");
  const [search, setSearch] = useState("");
  const [scanStep, setScanStep] = useState(-1);
  const [selected, setSelected] = useState<ScanRecord | null>(null);
  const [docs, setDocs] = useState(false);
  const [profile, setProfile] = useState(false);
  const [refresh, setRefresh] = useState(false);
  const [notice, setNotice] = useState("");
  const [liveMessage, setLiveMessage] = useState("");
  const [approvalJobId, setApprovalJobId] = useState<string | null>(null);
  const [systemHealth, setSystemHealth] = useState<any>(null);
  const [takedownModal, setTakedownModal] = useState<{
    isOpen: boolean;
    loading: boolean;
    data: any | null;
    copied: boolean;
  }>({
    isOpen: false,
    loading: false,
    data: null,
    copied: false,
  });

  const inputRef = useRef<HTMLInputElement>(null);
  const recordsRef = useRef<HTMLElement>(null);
  const activeEventSource = useRef<EventSource | null>(null);
  const running = scanStep >= 0;

  const loadRecentScans = async () => {
    try {
      const token = window.sessionStorage.getItem("phishchips_token");
      const headers: Record<string, string> = {};
      if (token) headers["Authorization"] = `Bearer ${token}`;

      const res = await fetch("/api/scans/recent", {
        credentials: "same-origin",
        headers,
      });
      if (!res.ok) return;
      const data = await res.json();
      if (data && Array.isArray(data.scans)) {
        if (data.scans.length === 0) {
          setRecords([]);
          return;
        }
        const mapped: ScanRecord[] = data.scans.map((s: any) => {
          const outcome = outcomeFrom(s);
          const isMalicious = outcome === "malicious";
          const timeStr = s.created_at
            ? new Date(s.created_at).toLocaleTimeString("en-GB")
            : "Recent";
          return {
            id: s.job_id ? `DET-${s.job_id.slice(0, 6).toUpperCase()}` : "DET-0001",
            raw_job_id: s.job_id,
            url: s.target_url || "",
            time: timeStr,
            malicious: isMalicious,
            outcome,
            threat_type: s.threat_type || (isMalicious ? "credential_harvest" : "none"),
            evidence_chain: s.evidence_chain || [],
            confidence: Math.round((s.confidence || 0) > 1 ? s.confidence : (s.confidence || 0) * 100),
            brand: s.pretending_to_be || (isMalicious ? "Generic website" : "Authentic portal"),
            screenshots: s.screenshots || [],
            reasons: s.reasons || [],
            asks_for: s.asks_for || [],
            threat_source: s.threat_source || "",
            c2_intelligence: s.c2_intelligence,
            re_intelligence: s.re_intelligence,
          };
        });
        setRecords(mapped);
      }
    } catch {}
  };

  const loadHealth = async () => {
    try {
      const res = await fetch("/api/health");
      if (res.ok) {
        const d = await res.json();
        setSystemHealth(d);
      }
    } catch {}
  };

  useEffect(() => {
    loadHealth();
    loadRecentScans();
  }, []);

  useEffect(() => {
    if (!notice) return;
    const timer = window.setTimeout(() => setNotice(""), 3500);
    return () => window.clearTimeout(timer);
  }, [notice]);

  useEffect(() => {
    const onEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setSelected(null);
        setDocs(false);
        setProfile(false);
      }
    };
    window.addEventListener("keydown", onEscape);
    return () => window.removeEventListener("keydown", onEscape);
  }, []);

  function finishScan(jobId: string, targetUrl: string, data: any) {
    if (activeEventSource.current) {
      activeEventSource.current.close();
      activeEventSource.current = null;
    }
    const result = data.result || data.verdict || {};
    const raw = data.raw_telemetry || data.raw_result || {};
    // Verdict comes only from the backend; never infer maliciousness from URL substrings.
    const outcome = outcomeFrom(result);
    const isMalicious = outcome === "malicious";
    const confidence = Math.round((result.confidence || 0) > 1 ? result.confidence : (result.confidence || 0) * 100);
    const brand = result.pretending_to_be || result.impersonating || "Generic website";
    const screenshots =
      data.screenshots && data.screenshots.length > 0
        ? data.screenshots
        : (raw.screenshots || []).map((s: string) => `/api/scan/${jobId}/shot/${s}`);

    const record: ScanRecord = {
      id: `DET-${jobId.slice(0, 6).toUpperCase()}`,
      raw_job_id: jobId,
      url: targetUrl,
      time: new Date().toLocaleTimeString("en-GB"),
      malicious: isMalicious,
      outcome,
      threat_type: result.threat_type,
      evidence_chain: result.evidence_chain || [],
      confidence,
      brand,
      screenshots,
      reasons: result.reasons || raw.reasons || [],
      asks_for: result.asks_for || (raw.fields?.password ? ["Password", "OTP / Security PIN"] : []),
      threat_source: result.threat_source || "Vultr Serverless Inference",
      c2_intelligence: data.c2_intelligence || raw.c2_intelligence,
      re_intelligence: data.re_intelligence || raw.re_intelligence,
    };

    setRecords((prev) => [record, ...prev.filter((r) => r.id !== record.id)]);
    setScanStep(-1);
    setLiveMessage("");
    setApprovalJobId(null);
    setSelected(record);
    setUrl("");
    setNotice(`Investigation ${record.id} complete: ${isMalicious ? "Threat Contained" : outcome === "benign" ? "Clean Target" : outcome === "suspicious" ? "Flagged for review" : "Analysis incomplete, retry"}`);
    loadRecentScans();
    loadHealth();
  }

  const openTakedownPackage = async (record: ScanRecord) => {
    const targetJobId = record.raw_job_id || record.id.replace("DET-", "").toLowerCase();
    setTakedownModal({
      isOpen: true,
      loading: true,
      data: null,
      copied: false,
    });
    try {
      const res = await fetch(`/api/scan/${targetJobId}/takedown`);
      if (res.ok) {
        const d = await res.json();
        setTakedownModal({
          isOpen: true,
          loading: false,
          data: d,
          copied: false,
        });
      } else {
        setNotice("Failed to generate takedown package.");
        setTakedownModal((prev) => ({ ...prev, isOpen: false, loading: false }));
      }
    } catch {
      setNotice("Error contacting takedown generator.");
      setTakedownModal((prev) => ({ ...prev, isOpen: false, loading: false }));
    }
  };

  const downloadEvidenceLocker = (record: ScanRecord) => {
    const targetJobId = record.raw_job_id || record.id.replace("DET-", "").toLowerCase();
    window.location.href = `/api/scan/${targetJobId}/evidence.tar.gz`;
    setNotice(`Downloading Signed Evidence Locker for ${record.id}...`);
  };

  async function handleApproval(approve: boolean) {
    if (!approvalJobId) return;
    try {
      setLiveMessage(approve ? "Delivering human authorization to container..." : "Declining decoy pass...");
      await fetch(`/api/scan/${approvalJobId}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ approve }),
      });
    } catch (e) {
      console.error("Approval error", e);
    }
    setApprovalJobId(null);
  }

  async function detonate(event: React.FormEvent) {
    event.preventDefault();
    const value = url.trim();
    try {
      const parsed = new URL(value);
      if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname.includes("."))
        throw new Error();
    } catch {
      if (!value.startsWith("demo://")) {
        setError("Enter a valid http or https URL, or choose a preset.");
        inputRef.current?.focus();
        return;
      }
    }

    setError("");
    setUrl(value);
    setScanStep(0);
    setLiveMessage("Dispatching job to ephemeral orchestrator...");
    setApprovalJobId(null);

    try {
      const token = window.sessionStorage.getItem("phishchips_token");
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (token) headers["Authorization"] = `Bearer ${token}`;

      const res = await fetch("/api/scan", {
        method: "POST",
        credentials: "same-origin",
        headers,
        body: JSON.stringify({ url: value }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || "Scan request failed with HTTP " + res.status);
      }

      const data = await res.json();
      const jobId = data.job_id;
      setLiveMessage(`Sandbox queued [${jobId}]... Initializing phishnet isolated boundary`);

      if (activeEventSource.current) {
        activeEventSource.current.close();
      }

      const sse = new EventSource(`/api/scan/${jobId}/stream`);
      activeEventSource.current = sse;

      // 55s safety timeout
      const safetyTimeout = window.setTimeout(async () => {
        if (activeEventSource.current === sse) {
          sse.close();
          activeEventSource.current = null;
          try {
            const finalRes = await fetch(`/api/scan/${jobId}`);
            if (finalRes.ok) {
              const finalData = await finalRes.json();
              finishScan(jobId, value, finalData);
              return;
            }
          } catch {}
          setScanStep(-1);
          setLiveMessage("");
          setError("Sandbox execution timed out after 55s. Container safely reclaimed.");
        }
      }, 55000);

      sse.onmessage = async (evt) => {
        try {
          const ev = JSON.parse(evt.data);
          const stage = ev.stage;
          const msg = ev.message || ev.msg || "";
          if (msg) setLiveMessage(msg);

          if (stage === "SANDBOX_INIT" || stage === "CAP_DROP" || stage === "NAVIGATING") {
            setScanStep(1); // Stage 2: Network isolation
          } else if (stage === "EVIDENCE_COLLECTED" || stage === "INTERCEPT") {
            setScanStep(2); // Stage 3: Micro-VM execution
          } else if (stage === "AWAITING_APPROVAL") {
            setScanStep(2);
            setApprovalJobId(jobId);
            setLiveMessage("⚠️ Credential harvester detected. Paused for human authorization.");
          } else if (stage === "P2_INIT") {
            setApprovalJobId(null);
            setScanStep(2);
            setLiveMessage("Human authorization received: Executing decoy submission pass...");
          } else if (stage === "INFERENCE_DISPATCH") {
            setApprovalJobId(null);
            setScanStep(3); // Stage 4: AI verdict
            setLiveMessage("Synthesizing threat vectors via Vultr Serverless Inference...");
          } else if (stage === "DONE" || stage === "JOB_SNAPSHOT") {
            window.clearTimeout(safetyTimeout);
            sse.close();
            activeEventSource.current = null;
            setApprovalJobId(null);

            // Fetch final complete job state
            const finalRes = await fetch(`/api/scan/${jobId}`);
            const finalData = finalRes.ok ? await finalRes.json() : null;
            finishScan(jobId, value, finalData || ev);
          }
        } catch (parseErr) {
          console.error("SSE parse error", parseErr);
        }
      };

      sse.onerror = async () => {
        // Fallback check
        try {
          const checkRes = await fetch(`/api/scan/${jobId}`);
          if (checkRes.ok) {
            const checkData = await checkRes.json();
            if (checkData.status === "done" || checkData.result) {
              window.clearTimeout(safetyTimeout);
              sse.close();
              activeEventSource.current = null;
              finishScan(jobId, value, checkData);
            }
          }
        } catch {}
      };
    } catch (err: any) {
      setScanStep(-1);
      setLiveMessage("");
      setError(err.message || "Failed to contact detonation backend.");
    }
  }

  const visibleRecords = records.filter((record) => {
    const text =
      `${record.url} ${record.brand} ${outcomeText[outcomeOf(record)]} ${threatLabel(record)}`.toLowerCase();
    return (
      text.includes(search.toLowerCase()) &&
      (filter === "All records" ||
        (filter === "Threats detected" ? record.malicious : !record.malicious))
    );
  });

  function exportRecords() {
    const csv = [
      "ID,URL,Time,Verdict,Confidence,Brand",
      ...visibleRecords.map((record) =>
        [
          record.id,
          `"${record.url.replace(/"/g, '""')}"`,
          record.time,
          outcomeText[outcomeOf(record)],
          `${record.confidence}%`,
          `"${record.brand.replace(/"/g, '""')}"`,
        ].join(","),
      ),
    ].join("\n");
    const objectUrl = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    const anchor = document.createElement("a");
    anchor.href = objectUrl;
    anchor.download = "phish-and-chips-records.csv";
    anchor.click();
    URL.revokeObjectURL(objectUrl);
    setNotice("Your detonation records have been exported.");
  }

  return (
    <div className="app-shell">
      <header className="navbar">
        <Brand onClick={onHome} />
        <nav className="nav-links" aria-label="Main navigation">
          {(
            [
              { name: "Dashboard", icon: "grid" },
              { name: "Activity", icon: "activity" },
              { name: "Documentation", icon: "book" },
            ] as const
          ).map((item) => (
            <button
              key={item.name}
              className={`nav-link ${tab === item.name ? "active" : ""}`}
              aria-current={tab === item.name ? "page" : undefined}
              onClick={() => {
                if (item.name === "Documentation") setDocs(true);
                else {
                  setTab(item.name);
                  if (item.name === "Activity")
                    recordsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
                  else window.scrollTo({ top: 0, behavior: "smooth" });
                }
              }}
            >
              <span>{item.name}</span>
            </button>
          ))}
        </nav>
        <div className="nav-right">
          <span className="system-status">
            <span className="status-dot" />
            {systemHealth?.slots_display || "Analyst workspace"}
          </span>
          <div className="profile-wrap">
            <button
              className="profile-button"
              onClick={() => setProfile(!profile)}
              aria-expanded={profile}
              aria-label="Open analyst menu"
            >
              <span className="avatar">
                {viewer.name
                  .split(" ")
                  .map((part) => part[0])
                  .slice(0, 2)
                  .join("")
                  .toUpperCase()}
              </span>
              <Icon name="chevron" size={15} />
            </button>
            {profile && (
              <div className="profile-menu">
                <strong>{viewer.name}</strong>
                <span>{viewer.email}</span>
                <div className="profile-divider" />
                <span className="profile-role">
                  <Icon name="shield" size={15} /> Network: phishnet (172.30.0.0/16)
                </span>
                <span className="profile-role" style={{ marginTop: "4px" }}>
                  <Icon name="cpu" size={15} /> Vultr Serverless Vision Engine
                </span>
                <div className="profile-divider" />
                <button className="profile-action" onClick={onHome}>
                  Back to home
                  <Icon name="arrow" size={15} />
                </button>
                <button className="profile-action" onClick={onSignOut}>
                  Sign out
                  <Icon name="external" size={15} />
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      <main>
        <section className="command-console" aria-label="URL investigation workspace">
          <Suspense
            fallback={
              <div className="cube-scene" aria-hidden="true">
                <CubeFallback />
              </div>
            }
          >
            <InvestigationCube scanning={running} />
          </Suspense>
          <div className="console-content">
            <div className="console-eyebrow">
              <span className="status-dot" />A SAFE SPACE FOR SUSPICIOUS LINKS
            </div>
            <h1>
              Good links. Bad links.
              <br />
              <span>Know the difference.</span>
            </h1>
            <p className="console-description">
              A little curiosity shouldn’t cost you everything.
              <br />
              Investigate any link. Keep the threat on the other side.
            </p>
            <form onSubmit={detonate} className={`command-form ${running ? "is-analyzing" : ""}`}>
              <div className="command-label">
                <span>01 / NEW INVESTIGATION</span>
                <span>
                  <span className="status-dot" />
                  {running ? "ANALYSIS IN PROGRESS" : "SANDBOX READY"}
                </span>
              </div>
              <div className={`command-bar ${error ? "input-error" : ""}`}>
                <span className="command-link-icon">
                  <Icon name="link" size={21} />
                </span>
                <input
                  ref={inputRef}
                  aria-label="URL to investigate"
                  placeholder="Drop a suspicious URL here (e.g. demo://fake-bank)..."
                  value={url}
                  onChange={(event) => {
                    setUrl(event.target.value);
                    setError("");
                  }}
                  disabled={running}
                  aria-invalid={!!error}
                  aria-describedby={error ? "url-error" : undefined}
                />
                <button className="command-submit" disabled={running} type="submit">
                  <Icon
                    name={running ? "refresh" : "bolt"}
                    size={17}
                    className={running ? "spinning" : ""}
                  />
                  {running ? "Analyzing..." : "Detonate"}
                  {!running && <Icon name="arrow" size={17} />}
                </button>
              </div>
              {error && (
                <p className="form-error" id="url-error" role="alert">
                  {error}
                </p>
              )}
              <div className="command-progress" role="status" aria-live="polite">
                {running ? (
                  <>
                    <span className="progress-track">
                      <span style={{ width: `${Math.max(15, (scanStep + 1) * 25)}%` }} />
                    </span>
                    <span>
                      {stages[scanStep]?.name || "Executing"}
                      <span className="progress-count">0{Math.max(1, scanStep + 1)} / 04</span>
                    </span>
                  </>
                ) : null}
              </div>

              {running && liveMessage && !approvalJobId && (
                <div style={{ marginTop: "10px", fontSize: "12px", fontFamily: "var(--mono)", color: "var(--signal-bright)" }}>
                  &gt; {liveMessage}
                </div>
              )}

              {approvalJobId && (
                <div
                  style={{
                    marginTop: "14px",
                    padding: "14px 16px",
                    background: "rgba(213, 53, 43, 0.12)",
                    border: "1px solid #e44b41",
                    borderRadius: "6px",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: "12px",
                    flexWrap: "wrap",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "12px", color: "#f2eeed" }}>
                    <Icon name="alert" size={17} />
                    <span>
                      <strong>Human Authorization Required (Pattern B):</strong> Credential harvester detected. Authorize decoy submission pass?
                    </span>
                  </div>
                  <div style={{ display: "flex", gap: "8px" }}>
                    <button
                      type="button"
                      className="red-button"
                      style={{ padding: "8px 14px", fontSize: "11px", gap: "6px" }}
                      onClick={() => handleApproval(true)}
                    >
                      <Icon name="check" size={14} />
                      Authorize Decoy Pass
                    </button>
                    <button
                      type="button"
                      className="outline-button"
                      style={{ padding: "8px 14px", fontSize: "11px", background: "transparent", color: "#a59995", border: "1px solid #554442" }}
                      onClick={() => handleApproval(false)}
                    >
                      Skip to Verdict
                    </button>
                  </div>
                </div>
              )}
            </form>
            <div className="console-presets">
              <span>Just exploring? Try</span>
              <div className="preset-list">
                <button
                  disabled={running}
                  onClick={() => {
                    setUrl("https://example.com");
                    setError("");
                    inputRef.current?.focus();
                  }}
                >
                  <Icon name="globe" size={14} />
                  example.com
                </button>
                <button
                  disabled={running}
                  onClick={() => {
                    setUrl("https://wikipedia.org");
                    setError("");
                    inputRef.current?.focus();
                  }}
                >
                  <Icon name="globe" size={14} />
                  wikipedia.org
                </button>
                <button
                  className="danger-preset"
                  disabled={running}
                  onClick={() => {
                    setUrl(bankPresetUrl);
                    setError("");
                    inputRef.current?.focus();
                  }}
                >
                  <Icon name="alert" size={14} />
                  Bank login
                </button>
              </div>
            </div>
          </div>
          <div className="console-bottom">
            <button
              onClick={() =>
                recordsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" })
              }
            >
              EXPLORE THE EVIDENCE
              <Icon name="arrow" size={14} />
            </button>
            <span className="console-coordinate">ZERO HOST EXPOSURE</span>
          </div>
        </section>

        <section ref={recordsRef} className="records-section">
          <div className="records-heading">
            <div>
              <div className="title-with-count">
                <h2>Recent investigations</h2>
                <span>{records.length.toString().padStart(2, "0")}</span>
              </div>
              <p>Every link leaves a trace. Here’s yours.</p>
            </div>
            <button className="outline-button" onClick={exportRecords}>
              <Icon name="download" size={16} />
              Export records
            </button>
          </div>
          <div className="records-card">
            <div className="table-toolbar">
              <div className="filter-tabs" role="tablist" aria-label="Filter records">
                {["All records", "Threats detected", "Safe"].map((item) => (
                  <button
                    role="tab"
                    aria-selected={filter === item}
                    className={filter === item ? "selected" : ""}
                    key={item}
                    onClick={() => setFilter(item)}
                  >
                    {item}
                    {item === "Threats detected" && (
                      <span className="threat-count">
                        {records.filter((record) => record.malicious).length}
                      </span>
                    )}
                  </button>
                ))}
              </div>
              <div className="table-actions">
                <label className="table-search">
                  <Icon name="search" size={16} />
                  <input
                    aria-label="Search records"
                    placeholder="Search domain or verdict..."
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                  />
                  {search && (
                    <button onClick={() => setSearch("")} aria-label="Clear search">
                      <Icon name="close" size={14} />
                    </button>
                  )}
                </label>
                <button
                  className="refresh-button"
                  aria-label="Refresh records"
                  onClick={() => {
                    setRefresh(true);
                    loadRecentScans();
                    loadHealth();
                    window.setTimeout(() => {
                      setRefresh(false);
                      setNotice("Records are up to date.");
                    }, 650);
                  }}
                >
                  <Icon name="refresh" size={17} className={refresh ? "spinning" : ""} />
                </button>
              </div>
            </div>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>TARGET URL</th>
                    <th>THREAT TYPE</th>
                    <th>ISOLATION</th>
                    <th>CONFIDENCE</th>
                    <th>VERDICT</th>
                    <th aria-label="View details" />
                  </tr>
                </thead>
                <tbody>
                  {visibleRecords.map((record) => (
                    <tr key={record.id} onClick={() => setSelected(record)}>
                      <td>
                        <div className="target-cell">
                          <span
                            className={`domain-icon ${record.malicious ? "domain-danger" : ""}`}
                          >
                            <Icon name={record.malicious ? "link" : "globe"} size={18} />
                          </span>
                          <div>
                            <button
                              className="record-link"
                              onClick={(event) => {
                                event.stopPropagation();
                                setSelected(record);
                              }}
                            >
                              {record.url}
                            </button>
                            <span className="record-time">
                              {record.id}
                              <span>·</span>{record.time}
                            </span>
                          </div>
                        </div>
                      </td>
                      <td>
                        <span className="threat-type">
                          {threatLabel(record)}
                        </span>
                        <span className="cell-subtitle">
                          {record.re_intelligence?.has_disassembly
                            ? `🔬 Dissected: ${record.re_intelligence.artifacts?.[0]?.name || "Binary/WASM"}`
                            : record.c2_intelligence?.has_c2_exfiltration
                            ? `🎯 C2: ${record.c2_intelligence.drop_destinations?.[0]?.channel_type || "Drop"} vector`
                            : record.malicious ? record.brand : "Caged detonation"}
                        </span>
                      </td>
                      <td>
                        <span className="isolation-cell">
                          <Icon name="shield" size={14} />
                          Network caged
                        </span>
                      </td>
                      <td>
                        <div
                          className={`confidence ${record.malicious ? "confidence-danger" : ""}`}
                        >
                          <span>
                            {record.confidence}
                            <small>%</small>
                          </span>
                          <div className="confidence-track">
                            <span style={{ width: `${record.confidence}%` }} />
                          </div>
                        </div>
                      </td>
                      <td>
                        <span className={`verdict ${verdictClass(record)}`}>
                          <span className="verdict-dot" />
                          {outcomeText[outcomeOf(record)]}
                        </span>
                      </td>
                      <td>
                        <button
                          className="detail-arrow"
                          aria-label={`View ${record.id}`}
                          onClick={(event) => {
                            event.stopPropagation();
                            setSelected(record);
                          }}
                        >
                          <Icon name="arrow" size={18} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {visibleRecords.length === 0 && (
                <div className="empty-state">
                  <Icon name="search" size={28} />
                  {records.length === 0 ? (
                    <>
                      <h3>No investigations in this workspace</h3>
                      <p>Your account has no detonations recorded yet. Submit a URL above to inspect and contain threats in the sandbox.</p>
                    </>
                  ) : (
                    <>
                      <h3>No matching records</h3>
                      <p>Try another domain or change your filters.</p>
                      <button
                        onClick={() => {
                          setSearch("");
                          setFilter("All records");
                        }}
                      >
                        Clear filters
                      </button>
                    </>
                  )}
                </div>
              )}
            </div>
            <div className="table-footer">
              <span>
                Showing <strong>{visibleRecords.length}</strong> of{" "}
                <strong>{records.length}</strong> records
              </span>
              <span>
                <Icon name="lock" size={12} />
                Investigation history · SQLite 3 WAL
              </span>
            </div>
          </div>
        </section>
        <footer className="page-footer">
          <span>
            <span className="footer-brand">phish&chips.</span> A little curiosity. A lot of
            protection.
          </span>
          <button onClick={() => setDocs(true)}>
            How it works
            <Icon name="external" size={13} />
          </button>
          <span className="footer-powered">
            <span className="status-dot" />
            Powered by Vultr Serverless Vision AI
          </span>
        </footer>
      </main>

      {notice && (
        <div className="toast" role="status">
          <Icon name="check" size={17} />
          {notice}
        </div>
      )}
      {(selected || docs) && (
        <div
          className="modal-backdrop"
          onClick={() => {
            setSelected(null);
            setDocs(false);
          }}
        >
          <section
            className="modal"
            role="dialog"
            aria-modal="true"
            aria-label={docs ? "How it works" : "Detonation details"}
            onClick={(event) => event.stopPropagation()}
            style={{ maxWidth: "620px" }}
          >
            <button
              autoFocus
              className="modal-close"
              aria-label="Close dialog"
              onClick={() => {
                setSelected(null);
                setDocs(false);
              }}
            >
              <Icon name="close" />
            </button>
            {docs ? (
              <>
                <span className="modal-symbol">
                  <Icon name="book" size={26} />
                </span>
                <div className="eyebrow">THE LAYERS OF PROTECTION</div>
                <h2>Curiosity meets containment.</h2>
                <p className="modal-intro">
                  A safer way to understand what’s behind a suspicious link.
                </p>
                <div className="doc-stages">
                  {stages.map((stage, index) => (
                    <div key={stage.name}>
                      <span className="stage-icon">
                        <Icon name={stage.icon} />
                      </span>
                      <div>
                        <h3>
                          0{index + 1} · {stage.name}
                        </h3>
                        <p>
                          {
                            [
                              "Your URL is passed to the analysis environment without opening it in your browser.",
                              "A host-level firewall keeps the investigation separate from your network.",
                              "The target is opened in a disposable, isolated execution environment.",
                              "Visual and behavioral signals are analyzed to produce a clear threat verdict.",
                            ][index]
                          }
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              selected && (
                <>
                  <span className={`modal-symbol ${selected.malicious ? "symbol-danger" : ""}`}>
                    <Icon name={selected.malicious ? "alert" : "shield"} size={28} />
                  </span>
                  <div className="eyebrow">INVESTIGATION COMPLETE</div>
                  <h2>
                    {selected.malicious
                      ? "A threat. Safely contained."
                      : outcomeOf(selected) === "benign"
                        ? "A clean bill of health."
                        : outcomeOf(selected) === "suspicious"
                          ? "Flagged for manual review."
                          : "Analysis incomplete. Retry."}
                  </h2>
                  <p className="modal-intro">
                    {selected.malicious
                      ? `${threatLabel(selected)} indicators confirmed in the sandbox${selected.brand !== "Generic website" ? `. Impersonating ${selected.brand}` : ""}.`
                      : outcomeOf(selected) === "benign"
                        ? "No threat indicators detected in this record."
                        : outcomeOf(selected) === "suspicious"
                          ? "Anomalies were observed but not conclusive. A human should review this record."
                          : "The analysis did not finish within the time budget. This is NOT a threat verdict; retry the scan."}
                  </p>
                  <div className="result-url">
                    <Icon name="link" size={17} />
                    <span>{selected.url}</span>
                  </div>

                  {selected.screenshots && selected.screenshots.length > 0 && (
                    <div
                      style={{
                        margin: "16px 0",
                        borderRadius: "8px",
                        overflow: "hidden",
                        border: "1px solid #3b2e2d",
                        background: "#0d0908",
                      }}
                    >
                      <div
                        style={{
                          padding: "6px 12px",
                          background: "#1c1413",
                          fontSize: "11px",
                          color: "#9f9995",
                          display: "flex",
                          justifyContent: "space-between",
                          fontFamily: "var(--mono)",
                        }}
                      >
                        <span>SANDBOX ARTIFACT // HEADLESS CHROMIUM</span>
                        <span>BLAST RADIUS ZERO</span>
                      </div>
                      <img
                        src={selected.screenshots[selected.screenshots.length - 1]}
                        alt="Sandbox screenshot"
                        style={{
                          width: "100%",
                          maxHeight: "220px",
                          objectFit: "contain",
                          display: "block",
                          background: "#080606",
                        }}
                      />
                    </div>
                  )}

                  {selected.reasons && selected.reasons.length > 0 && (
                    <div
                      style={{
                        margin: "12px 0",
                        padding: "12px 14px",
                        background: outcomeTone(selected).bg,
                        border: `1px solid ${outcomeTone(selected).border}`,
                        borderRadius: "6px",
                      }}
                    >
                      <span
                        style={{
                          fontSize: "11px",
                          fontWeight: 600,
                          color: outcomeTone(selected).fg,
                          textTransform: "uppercase",
                          letterSpacing: "0.05em",
                        }}
                      >
                        Forensic Telemetry:
                      </span>
                      <ul style={{ margin: "6px 0 0", paddingLeft: "18px", fontSize: "12px", color: "var(--text)" }}>
                        {selected.reasons.map((r, i) => (
                          <li key={i} style={{ marginBottom: "4px" }}>
                            {r}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {selected.c2_intelligence?.has_c2_exfiltration && (
                    <div
                      style={{
                        margin: "12px 0",
                        padding: "12px 14px",
                        background: "rgba(239, 68, 68, 0.12)",
                        border: "1px solid rgba(239, 68, 68, 0.4)",
                        borderRadius: "6px",
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: "8px",
                          color: "#f87171",
                          fontWeight: 700,
                          fontSize: "12px",
                          textTransform: "uppercase",
                          letterSpacing: "0.05em",
                        }}
                      >
                        <Icon name="bolt" size={16} />
                        <span>Attacker C2 Exfiltration Vector Discovered</span>
                      </div>
                      <p style={{ margin: "6px 0 8px", fontSize: "12px", color: "var(--text)" }}>
                        {selected.c2_intelligence.attribution_summary || "Covert credential drop channel intercepted."}
                      </p>
                      {selected.c2_intelligence.drop_destinations?.map((d: any, i: number) => (
                        <div
                          key={i}
                          style={{
                            fontSize: "11px",
                            fontFamily: "var(--mono)",
                            background: "rgba(0,0,0,0.5)",
                            padding: "6px 10px",
                            borderRadius: "4px",
                            marginBottom: "4px",
                            border: "1px solid rgba(255,255,255,0.08)",
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                          }}
                        >
                          <span>DROP: {d.channel_type.toUpperCase()} ({d.identifier})</span>
                          <span style={{ color: "#ef4444", fontWeight: 700 }}>{d.risk_rating} RISK</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {selected.re_intelligence?.has_disassembly && (
                    <div
                      style={{
                        margin: "14px 0",
                        padding: "14px 16px",
                        background: "rgba(139, 92, 246, 0.08)",
                        border: "1px solid rgba(139, 92, 246, 0.35)",
                        borderRadius: "8px",
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "space-between",
                          gap: "8px",
                          marginBottom: "10px",
                        }}
                      >
                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: "8px",
                            color: "#c084fc",
                            fontWeight: 700,
                            fontSize: "12px",
                            textTransform: "uppercase",
                            letterSpacing: "0.05em",
                          }}
                        >
                          <Icon name="terminal" size={16} />
                          <span>Pure Static Reverse Engineering & Disassembly (Blast Radius Zero)</span>
                        </div>
                        <span
                          style={{
                            fontSize: "10px",
                            fontFamily: "var(--mono)",
                            padding: "2px 8px",
                            borderRadius: "4px",
                            background: "rgba(139, 92, 246, 0.2)",
                            color: "#d8b4fe",
                            border: "1px solid rgba(139, 92, 246, 0.4)",
                          }}
                        >
                          {selected.re_intelligence.artifacts?.length || 0} Quarantined Artifact(s)
                        </span>
                      </div>

                      <p style={{ margin: "4px 0 10px", fontSize: "12px", color: "#e2e8f0" }}>
                        {selected.re_intelligence.attribution_summary}
                      </p>

                      {selected.re_intelligence.mitre_tactics && selected.re_intelligence.mitre_tactics.length > 0 && (
                        <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", marginBottom: "12px" }}>
                          {selected.re_intelligence.mitre_tactics.map((t, idx) => (
                            <span
                              key={idx}
                              style={{
                                fontSize: "10px",
                                fontFamily: "var(--mono)",
                                padding: "2px 6px",
                                borderRadius: "3px",
                                background: "rgba(239, 68, 68, 0.15)",
                                color: "#fca5a5",
                                border: "1px solid rgba(239, 68, 68, 0.3)",
                              }}
                            >
                              MITRE: {t}
                            </span>
                          ))}
                        </div>
                      )}

                      {selected.re_intelligence.artifacts?.map((art, aIdx) => (
                        <div
                          key={aIdx}
                          style={{
                            background: "rgba(15, 23, 42, 0.7)",
                            border: "1px solid rgba(255, 255, 255, 0.08)",
                            borderRadius: "6px",
                            padding: "10px 12px",
                            marginBottom: "10px",
                            fontSize: "11px",
                          }}
                        >
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                            <div>
                              <strong style={{ color: "#f1f5f9", fontSize: "12px" }}>{art.name}</strong>
                              <span style={{ marginLeft: "8px", color: "#94a3b8", fontFamily: "var(--mono)" }}>
                                ({art.type.toUpperCase()} • {Math.round(art.size_bytes / 1024 * 10) / 10} KB)
                              </span>
                            </div>
                            <span
                              style={{
                                padding: "2px 6px",
                                borderRadius: "3px",
                                fontSize: "10px",
                                fontWeight: 700,
                                background: art.is_packed ? "rgba(239, 68, 68, 0.25)" : "rgba(34, 197, 94, 0.15)",
                                color: art.is_packed ? "#f87171" : "#4ade80",
                                border: `1px solid ${art.is_packed ? "rgba(239, 68, 68, 0.5)" : "rgba(34, 197, 94, 0.3)"}`,
                              }}
                            >
                              {art.is_packed ? "PACKED / CRYPTED" : "UNPACKED"}
                            </span>
                          </div>

                          {/* Entropy Meter */}
                          <div style={{ marginBottom: "8px" }}>
                            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "10px", color: "#94a3b8", marginBottom: "2px" }}>
                              <span>Shannon Entropy: <strong style={{ color: art.entropy > 7.0 ? "#ef4444" : art.entropy > 6.0 ? "#f59e0b" : "#10b981" }}>{art.entropy.toFixed(2)}</strong> / 8.0</span>
                              <span>{art.entropy > 7.0 ? "High Randomness (Encrypted/Packed)" : "Normal Distribution"}</span>
                            </div>
                            <div style={{ width: "100%", height: "6px", background: "rgba(255,255,255,0.1)", borderRadius: "3px", overflow: "hidden" }}>
                              <div
                                style={{
                                  width: `${Math.min(100, (art.entropy / 8.0) * 100)}%`,
                                  height: "100%",
                                  background: art.entropy > 7.0 ? "linear-gradient(90deg, #f59e0b, #ef4444)" : "linear-gradient(90deg, #10b981, #3b82f6)",
                                  borderRadius: "3px",
                                }}
                              />
                            </div>
                          </div>

                          {/* Suspicious APIs / Capabilities */}
                          {art.capabilities && art.capabilities.length > 0 && (
                            <div style={{ marginTop: "6px" }}>
                              <span style={{ color: "#94a3b8", fontSize: "10px" }}>Capabilities: </span>
                              {art.capabilities.map((cap, cIdx) => (
                                <span
                                  key={cIdx}
                                  style={{
                                    display: "inline-block",
                                    fontSize: "10px",
                                    fontFamily: "var(--mono)",
                                    padding: "1px 5px",
                                    borderRadius: "3px",
                                    background: "rgba(244, 63, 94, 0.15)",
                                    color: "#fda4af",
                                    marginRight: "4px",
                                    marginBottom: "4px",
                                    border: "1px solid rgba(244, 63, 94, 0.3)",
                                  }}
                                >
                                  {cap.replace(/_/g, " ")}
                                </span>
                              ))}
                            </div>
                          )}

                          {art.suspicious_apis && art.suspicious_apis.length > 0 && (
                            <div style={{ marginTop: "4px" }}>
                              <span style={{ color: "#94a3b8", fontSize: "10px" }}>IAT APIs: </span>
                              {art.suspicious_apis.map((api, apiIdx) => (
                                <code
                                  key={apiIdx}
                                  style={{
                                    fontSize: "10px",
                                    color: "#fbbf24",
                                    background: "rgba(0,0,0,0.4)",
                                    padding: "1px 4px",
                                    borderRadius: "3px",
                                    marginRight: "4px",
                                  }}
                                >
                                  {api}
                                </code>
                              ))}
                            </div>
                          )}

                          {/* WAT Preview for WASM */}
                          {art.type === "wasm" && art.wat_preview && (
                            <details style={{ marginTop: "8px" }}>
                              <summary style={{ cursor: "pointer", color: "#a78bfa", fontSize: "10px", fontWeight: 600 }}>
                                View Disassembled WebAssembly Text (WAT)
                              </summary>
                              <pre
                                style={{
                                  marginTop: "6px",
                                  padding: "8px 10px",
                                  background: "#090d16",
                                  border: "1px solid rgba(139, 92, 246, 0.3)",
                                  borderRadius: "4px",
                                  fontSize: "10px",
                                  fontFamily: "var(--mono)",
                                  color: "#cbd5e1",
                                  maxHeight: "160px",
                                  overflowY: "auto",
                                  whiteSpace: "pre",
                                }}
                              >
                                {art.wat_preview}
                              </pre>
                            </details>
                          )}

                          {/* Extracted IOCs */}
                          {art.ioc_strings && art.ioc_strings.length > 0 && (
                            <div style={{ marginTop: "6px" }}>
                              <span style={{ color: "#94a3b8", fontSize: "10px" }}>Extracted IOCs: </span>
                              {art.ioc_strings.map((ioc, iocIdx) => (
                                <code
                                  key={iocIdx}
                                  style={{
                                    fontSize: "10px",
                                    color: "#38bdf8",
                                    background: "rgba(0,0,0,0.4)",
                                    padding: "1px 4px",
                                    borderRadius: "3px",
                                    marginRight: "4px",
                                  }}
                                >
                                  {ioc}
                                </code>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  <dl className="result-details">
                    <div>
                      <dt>Verdict</dt>
                      <dd>
                        <span className={`verdict ${verdictClass(selected)}`}>
                          <span className="verdict-dot" />
                          {outcomeText[outcomeOf(selected)]}
                        </span>
                      </dd>
                    </div>
                    <div>
                      <dt>Confidence</dt>
                      <dd>{selected.confidence}%</dd>
                    </div>
                    <div>
                      <dt>Threat classification</dt>
                      <dd>{threatLabel(selected)}</dd>
                    </div>
                    <div>
                      <dt>Network isolation</dt>
                      <dd className="result-protected">
                        <Icon name="shield" size={15} />
                        Fully contained (phishnet drop)
                      </dd>
                    </div>
                    <div>
                      <dt>Investigation ID</dt>
                      <dd>{selected.id}</dd>
                    </div>
                    {selected.threat_source && (
                      <div>
                        <dt>Analysis engine</dt>
                        <dd style={{ fontSize: "12px" }}>{selected.threat_source}</dd>
                      </div>
                    )}
                  </dl>

                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", margin: "16px 0 10px" }}>
                    <button
                      className="primary-button"
                      style={{
                        background: selected.malicious ? "#b91c1c" : "#27272a",
                        borderColor: selected.malicious ? "#ef4444" : "#3f3f46",
                        fontSize: "12px",
                        padding: "9px 10px",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        gap: "6px",
                      }}
                      onClick={() => openTakedownPackage(selected)}
                    >
                      <Icon name="alert" size={15} />
                      1-Click Abuse Takedown
                    </button>
                    <button
                      className="primary-button"
                      style={{
                        background: "#18181b",
                        borderColor: "#3f3f46",
                        fontSize: "12px",
                        padding: "9px 10px",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        gap: "6px",
                      }}
                      onClick={() => downloadEvidenceLocker(selected)}
                    >
                      <Icon name="download" size={15} />
                      Evidence Locker (.tar.gz)
                    </button>
                  </div>

                  <button className="primary-button modal-done" onClick={() => setSelected(null)}>
                    Back to workspace
                    <Icon name="arrow" size={17} />
                  </button>
                </>
              )
            )}
          </section>
        </div>
      )}

      {takedownModal.isOpen && (
        <div
          className="modal-backdrop"
          onClick={() => setTakedownModal((prev) => ({ ...prev, isOpen: false }))}
        >
          <section
            className="modal"
            role="dialog"
            aria-modal="true"
            aria-label="Automated Abuse Takedown & STIX 2.1 Package"
            onClick={(event) => event.stopPropagation()}
            style={{ maxWidth: "680px", maxHeight: "90vh", overflowY: "auto" }}
          >
            <button
              autoFocus
              className="modal-close"
              aria-label="Close dialog"
              onClick={() => setTakedownModal((prev) => ({ ...prev, isOpen: false }))}
            >
              <Icon name="close" />
            </button>
            <span className="modal-symbol symbol-danger">
              <Icon name="alert" size={28} />
            </span>
            <div className="eyebrow">AUTOMATED INCIDENT RESPONSE</div>
            <h2>1-Click Takedown & Threat Intelligence</h2>
            <p className="modal-intro">
              RFC 2822 formal legal abuse notice pre-addressed to hosting providers and registrars, plus standard STIX 2.1 IoC feed.
            </p>

            {takedownModal.loading ? (
              <div style={{ padding: "40px", textAlign: "center", color: "#9f9995" }}>
                <Icon name="refresh" size={24} className="spin" />
                <p style={{ marginTop: "12px" }}>Synthesizing abuse contacts and STIX 2.1 bundle...</p>
              </div>
            ) : takedownModal.data ? (
              <>
                <div style={{ margin: "16px 0 12px" }}>
                  <div style={{ fontSize: "11px", fontWeight: 700, color: "#9f9995", marginBottom: "6px", textTransform: "uppercase" }}>
                    DESIGNATED ABUSE CONTACTS
                  </div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                    {takedownModal.data.abuse_contacts?.map((contact: string, idx: number) => (
                      <span
                        key={idx}
                        style={{
                          background: "#27272a",
                          color: "#38bdf8",
                          fontFamily: "var(--mono)",
                          fontSize: "12px",
                          padding: "4px 8px",
                          borderRadius: "4px",
                          border: "1px solid #3f3f46",
                        }}
                      >
                        {contact}
                      </span>
                    ))}
                  </div>
                </div>

                <div style={{ margin: "14px 0" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                    <span style={{ fontSize: "11px", fontWeight: 700, color: "#9f9995", textTransform: "uppercase" }}>
                      FORMAL RFC 2822 ABUSE NOTICE
                    </span>
                    <button
                      className="primary-button"
                      style={{ fontSize: "11px", padding: "4px 10px", height: "auto" }}
                      onClick={() => {
                        navigator.clipboard.writeText(takedownModal.data.abuse_letter_text || takedownModal.data.abuse_letter || "");
                        setTakedownModal((prev) => ({ ...prev, copied: true }));
                        setTimeout(() => setTakedownModal((prev) => ({ ...prev, copied: false })), 2000);
                      }}
                    >
                      {takedownModal.copied ? "✓ Copied Notice!" : "Copy Legal Notice"}
                    </button>
                  </div>
                  <textarea
                    readOnly
                    rows={8}
                    value={takedownModal.data.abuse_letter_text || takedownModal.data.abuse_letter || ""}
                    style={{
                      width: "100%",
                      fontFamily: "var(--mono)",
                      fontSize: "11px",
                      background: "#09090b",
                      color: "#e4e4e7",
                      border: "1px solid #27272a",
                      borderRadius: "6px",
                      padding: "10px",
                      resize: "vertical",
                    }}
                  />
                </div>

                <div style={{ margin: "14px 0" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                    <span style={{ fontSize: "11px", fontWeight: 700, color: "#9f9995", textTransform: "uppercase" }}>
                      STIX 2.1 THREAT INTEL BUNDLE (JSON)
                    </span>
                    <button
                      className="primary-button"
                      style={{ fontSize: "11px", padding: "4px 10px", height: "auto" }}
                      onClick={() => {
                        const blob = new Blob([JSON.stringify(takedownModal.data.stix_bundle, null, 2)], { type: "application/json" });
                        const dlUrl = URL.createObjectURL(blob);
                        const a = document.createElement("a");
                        a.href = dlUrl;
                        a.download = `STIX-2.1-${takedownModal.data.domain || "threat"}.json`;
                        a.click();
                        URL.revokeObjectURL(dlUrl);
                      }}
                    >
                      Export STIX 2.1
                    </button>
                  </div>
                  <pre
                    style={{
                      fontFamily: "var(--mono)",
                      fontSize: "10px",
                      background: "#09090b",
                      color: "#a1a1aa",
                      border: "1px solid #27272a",
                      borderRadius: "6px",
                      padding: "10px",
                      maxHeight: "140px",
                      overflowY: "auto",
                      whiteSpace: "pre-wrap",
                      margin: 0,
                    }}
                  >
                    {JSON.stringify(takedownModal.data.stix_bundle, null, 2)}
                  </pre>
                </div>

                <button
                  className="primary-button modal-done"
                  onClick={() => setTakedownModal((prev) => ({ ...prev, isOpen: false }))}
                  style={{ marginTop: "16px" }}
                >
                  Done
                </button>
              </>
            ) : null}
          </section>
        </div>
      )}
    </div>
  );
}
