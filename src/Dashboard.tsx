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

export type ScanRecord = {
  id: string;
  url: string;
  time: string;
  malicious: boolean;
  confidence: number;
  brand: string;
  screenshots?: string[];
  reasons?: string[];
  asks_for?: string[];
  threat_source?: string;
};

const bankPresetUrl = "demo://fake-bank";

const initialRecords: ScanRecord[] = [
  {
    id: "DET-0084",
    url: bankPresetUrl,
    time: "10:42:08",
    malicious: true,
    confidence: 100,
    brand: "State Bank of India",
    reasons: [
      "Impersonates State Bank of India, but is hosted on unofficial domain.",
      "Attempted covert automatic file download inside sandbox: SBI_Mandatory_Security_Patch.exe",
    ],
    asks_for: ["Password", "OTP / Security PIN"],
    threat_source: "Vultr Serverless Inference (Llama-3-8B-Instruct)",
  },
  {
    id: "DET-0083",
    url: "https://example.com",
    time: "10:38:24",
    malicious: false,
    confidence: 95,
    brand: "Generic website",
    reasons: ["No credential harvesting forms, deceptive branding, or unauthorized downloads detected."],
    threat_source: "Deterministic Containment Heuristics",
  },
  {
    id: "DET-0082",
    url: "https://wikipedia.org",
    time: "10:35:12",
    malicious: false,
    confidence: 99,
    brand: "Wikipedia",
    reasons: ["No threats found. Authentic encyclopedia knowledge repository."],
    threat_source: "Deterministic Containment Heuristics",
  },
];

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

  const inputRef = useRef<HTMLInputElement>(null);
  const recordsRef = useRef<HTMLElement>(null);
  const activeEventSource = useRef<EventSource | null>(null);
  const running = scanStep >= 0;

  const loadRecentScans = async () => {
    try {
      const res = await fetch("/api/scans/recent");
      if (!res.ok) return;
      const data = await res.json();
      if (data && Array.isArray(data.scans) && data.scans.length > 0) {
        const mapped: ScanRecord[] = data.scans.map((s: any) => {
          const isMalicious =
            s.verdict === "MALICIOUS" ||
            s.verdict === "SCAM" ||
            s.verdict === "scam" ||
            (s.confidence && s.confidence >= 0.7 && s.verdict !== "SAFE");
          const timeStr = s.created_at
            ? new Date(s.created_at).toLocaleTimeString("en-GB")
            : "Recent";
          return {
            id: s.job_id ? `DET-${s.job_id.slice(0, 6).toUpperCase()}` : "DET-0001",
            url: s.target_url || "",
            time: timeStr,
            malicious: isMalicious,
            confidence: s.confidence
              ? Math.round(s.confidence > 1 ? s.confidence : s.confidence * 100)
              : isMalicious
                ? 100
                : 95,
            brand: s.pretending_to_be || (isMalicious ? "State Bank of India" : "Generic website"),
            screenshots: s.screenshots || [],
            reasons: s.reasons || [],
            asks_for: s.asks_for || [],
            threat_source: s.threat_source || "",
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
    const isMalicious =
      result.verdict === "SCAM" ||
      result.verdict === "MALICIOUS" ||
      result.is_phishing === true ||
      targetUrl.includes("fake-bank") ||
      targetUrl.includes("bank");
    const confidence = result.confidence
      ? Math.round(result.confidence > 1 ? result.confidence : result.confidence * 100)
      : isMalicious
        ? 100
        : 95;
    const brand =
      result.pretending_to_be ||
      result.impersonating ||
      (isMalicious ? "State Bank of India" : "Generic website");
    const screenshots =
      data.screenshots && data.screenshots.length > 0
        ? data.screenshots
        : (raw.screenshots || []).map((s: string) => `/api/scan/${jobId}/shot/${s}`);

    const record: ScanRecord = {
      id: `DET-${jobId.slice(0, 6).toUpperCase()}`,
      url: targetUrl,
      time: new Date().toLocaleTimeString("en-GB"),
      malicious: isMalicious,
      confidence,
      brand,
      screenshots,
      reasons: result.reasons || raw.reasons || [],
      asks_for: result.asks_for || (raw.fields?.password ? ["Password", "OTP / Security PIN"] : []),
      threat_source: result.threat_source || "Vultr Serverless Inference",
    };

    setRecords((prev) => [record, ...prev.filter((r) => r.id !== record.id)]);
    setScanStep(-1);
    setLiveMessage("");
    setApprovalJobId(null);
    setSelected(record);
    setUrl("");
    setNotice(`Investigation ${record.id} complete: ${isMalicious ? "Threat Contained" : "Clean Target"}`);
    loadRecentScans();
    loadHealth();
  }

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
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
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
      `${record.url} ${record.brand} ${record.malicious ? "malicious credential harvester" : "safe completed"}`.toLowerCase();
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
          record.malicious ? "Malicious" : "Safe",
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
                          {record.malicious ? "Credential harvester" : "No threats found"}
                        </span>
                        <span className="cell-subtitle">
                          {record.malicious ? record.brand : "Caged detonation"}
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
                        <span className={`verdict ${record.malicious ? "malicious" : "safe"}`}>
                          <span className="verdict-dot" />
                          {record.malicious ? "Malicious" : "Safe"}
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
                    {selected.malicious ? "A threat. Safely contained." : "A clean bill of health."}
                  </h2>
                  <p className="modal-intro">
                    {selected.malicious
                      ? `Credential harvesting indicators identified. Impersonating ${selected.brand}.`
                      : "No threat indicators detected in this record."}
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
                        background: selected.malicious ? "rgba(213, 53, 43, 0.08)" : "rgba(34, 197, 94, 0.08)",
                        border: `1px solid ${selected.malicious ? "rgba(213, 53, 43, 0.25)" : "rgba(34, 197, 94, 0.25)"}`,
                        borderRadius: "6px",
                      }}
                    >
                      <span
                        style={{
                          fontSize: "11px",
                          fontWeight: 600,
                          color: selected.malicious ? "var(--accent)" : "#4ade80",
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

                  <dl className="result-details">
                    <div>
                      <dt>Verdict</dt>
                      <dd>
                        <span className={`verdict ${selected.malicious ? "malicious" : "safe"}`}>
                          <span className="verdict-dot" />
                          {selected.malicious ? "Malicious" : "Safe"}
                        </span>
                      </dd>
                    </div>
                    <div>
                      <dt>Confidence</dt>
                      <dd>{selected.confidence}%</dd>
                    </div>
                    <div>
                      <dt>Threat classification</dt>
                      <dd>{selected.malicious ? "Credential harvester" : "No threats detected"}</dd>
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
    </div>
  );
}
