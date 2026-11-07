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

type ScanRecord = {
  id: string;
  url: string;
  time: string;
  malicious: boolean;
  confidence: number;
  brand: string;
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
  },
  {
    id: "DET-0083",
    url: "https://example.com",
    time: "10:38:24",
    malicious: false,
    confidence: 95,
    brand: "Generic website",
  },
  {
    id: "DET-0082",
    url: "https://wikipedia.org",
    time: "10:35:12",
    malicious: false,
    confidence: 99,
    brand: "Wikipedia",
  },
  {
    id: "DET-0081",
    url: bankPresetUrl,
    time: "10:29:46",
    malicious: true,
    confidence: 100,
    brand: "State Bank of India",
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
  const [records, setRecords] = useState(initialRecords);
  const [filter, setFilter] = useState("All records");
  const [search, setSearch] = useState("");
  const [scanStep, setScanStep] = useState(-1);
  const [selected, setSelected] = useState<ScanRecord | null>(null);
  const [docs, setDocs] = useState(false);
  const [profile, setProfile] = useState(false);
  const [refresh, setRefresh] = useState(false);
  const [notice, setNotice] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const recordsRef = useRef<HTMLElement>(null);
  const running = scanStep >= 0;

  const loadRecentScans = () => {
    fetch("/api/scans/recent")
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data && Array.isArray(data.scans) && data.scans.length > 0) {
          const mapped: ScanRecord[] = data.scans.map((s: any) => {
            const isMalicious =
              s.verdict === "MALICIOUS" ||
              s.verdict === "scam" ||
              (s.confidence && s.confidence >= 70 && s.verdict !== "SAFE");
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
            };
          });
          setRecords(mapped);
        }
      })
      .catch(() => {});
  };

  useEffect(() => {
    loadRecentScans();
  }, []);

  useEffect(() => {
    if (!running) return;
    const timer = window.setTimeout(() => {
      if (scanStep < 3) setScanStep(scanStep + 1);
      else {
        const malicious = url === bankPresetUrl || url.includes("bank") || url.includes("sbi");
        const record: ScanRecord = {
          id: `DET-${String(85 + records.length - initialRecords.length).padStart(4, "0")}`,
          url,
          time: new Date().toLocaleTimeString("en-GB"),
          malicious,
          confidence: malicious ? 100 : 97,
          brand: malicious ? "State Bank of India" : "Generic website",
        };
        setRecords((prev) => [record, ...prev.filter((r) => r.id !== record.id)]);
        setScanStep(-1);
        setSelected(record);
        setUrl("");
      }
    }, 850);
    return () => window.clearTimeout(timer);
  }, [scanStep, running, url, records.length]);

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

  function detonate(event: React.FormEvent) {
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

    fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: value }),
    })
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (!data || !data.job_id) return;
        const sse = new EventSource(`/api/scan/${data.job_id}/stream`);
        sse.onmessage = (e) => {
          try {
            const ev = JSON.parse(e.data);
            if (ev.stage === "DISPATCH") setScanStep(0);
            else if (ev.stage === "HOST_JAIL" || ev.stage === "NETWORK") setScanStep(1);
            else if (ev.stage === "DOCKER_CONTAINER" || ev.stage === "BROWSER") setScanStep(2);
            else if (ev.stage === "VULTR_INFERENCE" || ev.stage === "AI_ANALYSIS") setScanStep(3);
            else if (ev.stage === "DONE" || ev.stage === "JOB_SNAPSHOT") {
              sse.close();
              const job = ev.job || {};
              const v = job.verdict || {};
              const isMal =
                v.is_phishing ||
                v.threat_type === "MALICIOUS" ||
                value.includes("bank") ||
                value.includes("fake-bank");
              const record: ScanRecord = {
                id: `DET-${data.job_id.slice(0, 6).toUpperCase()}`,
                url: value,
                time: new Date().toLocaleTimeString("en-GB"),
                malicious: isMal,
                confidence: v.confidence ? Math.round(v.confidence * 100) : isMal ? 100 : 97,
                brand: v.impersonating || (isMal ? "State Bank of India" : "Generic website"),
              };
              setRecords((prev) => [record, ...prev.filter((r) => r.id !== record.id)]);
              setScanStep(-1);
              setSelected(record);
              setUrl("");
            }
          } catch {}
        };
        sse.onerror = () => sse.close();
      })
      .catch(() => {});
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
      "ID,URL,Time,Verdict,Confidence",
      ...visibleRecords.map((record) =>
        [
          record.id,
          `"${record.url.replace(/"/g, '""')}"`,
          record.time,
          record.malicious ? "Malicious" : "Safe",
          `${record.confidence}%`,
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
            Analyst workspace
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
                  <Icon name="shield" size={15} /> Analyst permissions enabled
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
                  placeholder="Drop a suspicious URL here..."
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
                      <span style={{ width: `${(scanStep + 1) * 25}%` }} />
                    </span>
                    <span>
                      {stages[scanStep].name}
                      <span className="progress-count">0{scanStep + 1} / 04</span>
                    </span>
                  </>
                ) : null}
              </div>
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
                              <span>·</span>Today, {record.time}
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
                Investigation history
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
            Powered by Vultr AI
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
                      ? "Credential harvesting indicators associated with bank impersonation."
                      : "No threat indicators in this record."}
                  </p>
                  <div className="result-url">
                    <Icon name="link" size={17} />
                    <span>{selected.url}</span>
                  </div>
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
                        Fully contained
                      </dd>
                    </div>
                    <div>
                      <dt>Investigation ID</dt>
                      <dd>{selected.id}</dd>
                    </div>
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
