
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Bug,
  CheckCircle,
  ChevronRight,
  Cpu,
  Database,
  LayoutDashboard,
  Menu,
  Moon,
  Monitor,
  RefreshCw,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sun,
  X,
  Zap,
} from "lucide-react";
import "./App.css";

const API_BASE = "http://127.0.0.1:8000";

const navigation = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "monitoring", label: "Live Monitoring", icon: Activity },
  { id: "threats", label: "Threat Detection", icon: ShieldAlert },
  { id: "performance", label: "Model Performance", icon: BarChart3 },
  { id: "settings", label: "Settings", icon: Settings },
];

const threatTypes = ["Ransomware", "Spyware", "Trojan"];

function formatNumber(value, digits = 1) {
  const number = Number(value);
  return Number.isFinite(number) ? number.toFixed(digits) : "—";
}

function formatDate(value) {
  if (!value) return "Waiting for data";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Waiting for data" : date.toLocaleString();
}

function StatusPill({ children, type = "neutral" }) {
  return <span className={`status-pill ${type}`}>{children}</span>;
}

function MetricCard({ icon: Icon, label, value, detail, tone = "blue" }) {
  return (
    <div className="metric-card">
      <div className={`metric-icon ${tone}`}>
        <Icon size={21} />
      </div>
      <div className="metric-copy">
        <p>{label}</p>
        <h2>{value}</h2>
        <span>{detail}</span>
      </div>
    </div>
  );
}

function EmptyState({ icon: Icon = Database, title, message }) {
  return (
    <div className="empty-state">
      <Icon size={34} />
      <h3>{title}</h3>
      <p>{message}</p>
    </div>
  );
}

function App() {
  const [activePage, setActivePage] = useState("dashboard");
  const [processes, setProcesses] = useState([]);
  const [modelStatus, setModelStatus] = useState(null);
  const [apiOnline, setApiOnline] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [theme, setTheme] = useState("dark");
  const [refreshInterval, setRefreshInterval] = useState(3000);
  const [selectedThreat, setSelectedThreat] = useState("Ransomware");
  const [simulation, setSimulation] = useState(null);
  const [simulationLoading, setSimulationLoading] = useState(false);
  const [simulationError, setSimulationError] = useState("");
  // Live process scanner
  const [processName, setProcessName] = useState("notepad.exe");
  const [processScan, setProcessScan] = useState(null);
  const [processScanLoading, setProcessScanLoading] = useState(false);
  const [processScanError, setProcessScanError] = useState("");

  
const fetchProcesses = useCallback(async () => {
  try {
    const response = await fetch(`${API_BASE}/api/processes`);

    if (!response.ok) {
      throw new Error(`Process API returned ${response.status}`);
    }

    const data = await response.json();

    setProcesses(
      Array.isArray(data.processes) ? data.processes : []
    );

    setLastUpdated(data.updated_at || new Date().toISOString());
    setApiOnline(true);
    setError("");

  } catch (err) {
    setApiOnline(false);
    setError(
      "Unable to connect to the backend. Check that the FastAPI server is running."
    );

  } finally {
    setLoading(false);
  }
}, []);

  

  const fetchModelStatus = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/api/model-status`);
      if (!response.ok) throw new Error("Model status request failed");
      const data = await response.json();
      setModelStatus(data);
    } catch {
      setModelStatus(null);
    }
  }, []);

  const refreshAll = useCallback(() => {
    fetchProcesses();
    fetchModelStatus();
  }, [fetchProcesses, fetchModelStatus]);

  useEffect(() => {
    refreshAll();
    const timer = window.setInterval(fetchProcesses, refreshInterval);
    const modelTimer = window.setInterval(fetchModelStatus, 15000);

    return () => {
      window.clearInterval(timer);
      window.clearInterval(modelTimer);
    };
  }, [refreshAll, fetchProcesses, fetchModelStatus, refreshInterval]);

  const filteredProcesses = useMemo(() => {
    const term = search.trim().toLowerCase();
    if (!term) return processes;

    return processes.filter((process) =>
      [
        process.name,
        process.pid,
        process.username,
        process.os_status,
      ]
        .join(" ")
        .toLowerCase()
        .includes(term)
    );
  }, [processes, search]);

  const modelReady = modelStatus?.status === "ready";
  const reportedAccuracy = modelStatus?.reported_accuracy_percent;

  async function runSimulation() {
    setSimulationLoading(true);
    setSimulation(null);
    setSimulationError("");

    try {
      const response = await fetch(`${API_BASE}/api/simulate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ threat_type: selectedThreat }),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Simulation request failed.");
      }

      setSimulation(data);
    } catch (err) {
      setSimulationError(err.message || "Could not run the simulation.");
    } finally {
      setSimulationLoading(false);
    }
  }


async function runProcessScan() {
  const name = processName.trim();

  if (!name) {
    setProcessScanError("Please enter a process name.");
    return;
  }

  setProcessScanLoading(true);
  setProcessScan(null);
  setProcessScanError("");

  try {
    const response = await fetch(`${API_BASE}/api/scan-process`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        process_name: name,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail || "Process scan failed.");
    }

    setProcessScan(data);
  } catch (err) {
    setProcessScanError(
      err.message || "Unable to scan the requested process."
    );
  } finally {
    setProcessScanLoading(false);
  }
}


  function navigate(page) {
    setActivePage(page);
    setSidebarOpen(false);
  }

  function renderProcessTable(rows) {
    if (loading && rows.length === 0) {
      return <EmptyState title="Loading processes" message="Fetching live process information from your computer." />;
    }

    if (rows.length === 0) {
      return <EmptyState title="No processes found" message="Try changing your search or refresh the process list." />;
    }

    return (
      <div className="table-wrap">
        <table className="process-table">
          <thead>
            <tr>
              <th>Process</th>
              <th>PID</th>
              <th>Username</th>
              <th>CPU Usage</th>
              <th>Memory</th>
              <th>OS Status</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((process) => (
              <tr key={`${process.pid}-${process.name}`}>
                <td>
                  <div className="process-name">
                    <span className="process-mini-icon"><Monitor size={16} /></span>
                    <strong>{process.name || "Unknown"}</strong>
                  </div>
                </td>
                <td>{process.pid}</td>
                <td>{process.username || "—"}</td>
                <td>{formatNumber(process.cpu_percent)}%</td>
                <td>{formatNumber(process.memory_mb)} MB</td>
                <td>{process.os_status || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  function renderDashboard() {
    return (
      <>
        <section className="welcome-row">
          <div>
            <p className="eyebrow">SECURITY OVERVIEW</p>
            <h2>System Dashboard</h2>
            <p className="muted">Monitor system activity and check your detection model status.</p>
          </div>
          <button className="secondary-button" onClick={refreshAll}>
            <RefreshCw size={16} /> Refresh data
          </button>
        </section>

        {error && <div className="alert-banner"><AlertTriangle size={18} />{error}</div>}

        <section className="metric-grid">
          <MetricCard icon={Monitor} label="Active Processes" value={processes.length} detail="Currently reported by the OS" tone="blue" />
          <MetricCard icon={ShieldCheck} label="Model Status" value={modelReady ? "Ready" : "Unavailable"} detail={modelReady ? "Model and scaler loaded" : "Check backend and model files"} tone="green" />
          <MetricCard icon={Database} label="Dataset Records" value={modelStatus?.dataset_rows?.toLocaleString?.() ?? "—"} detail="Records available to the model" tone="purple" />
          <MetricCard
            icon={Activity}
            label="Live Scanner"
            value="Experimental"
            detail="Manual process scans available"
            tone="orange"
          />
        </section>
        <section className="content-grid">
          <div className="panel">
            <div className="panel-heading">
              <div>
                <h3><Activity size={18} /> Live Process Activity</h3>
                <p>Process information retrieved from your operating system</p>
              </div>
              <StatusPill type={apiOnline ? "success" : "danger"}>{apiOnline ? "API Connected" : "API Offline"}</StatusPill>
            </div>
            <div className="activity-summary">
              <div>
                <span className="summary-dot blue-dot" />
                Processes monitored <strong>{processes.length}</strong>
              </div>
            </div>

            <p className="data-note">
              Live process information is retrieved from your operating system.
              Use the Live Process Scanner for experimental ML predictions.
            </p>
            <button className="text-button" onClick={() => navigate("monitoring")}>View all processes <ChevronRight size={16} /></button>
          </div>

          <div className="panel model-panel">
            <div className="panel-heading">
              <div>
                <h3><Cpu size={18} /> Detection Model</h3>
                <p>Backend model information</p>
              </div>
              <StatusPill type={modelReady ? "success" : "warning"}>{modelReady ? "Ready" : "Not ready"}</StatusPill>
            </div>
            <div className="model-highlight">
              <span>Reported accuracy</span>
              <strong>{reportedAccuracy != null ? `${formatNumber(reportedAccuracy, 2)}%` : "—"}</strong>
            </div>
            <p className="data-note">{modelStatus?.accuracy_note || "Accuracy is shown only when reported by the backend."}</p>
            <button className="text-button" onClick={() => navigate("performance")}>View model details <ChevronRight size={16} /></button>
          </div>
        </section>

        <section className="panel process-panel">
          <div className="panel-heading">
            <div>
              <h3><Monitor size={18} /> Current Processes</h3>
              <p>Latest process snapshot · Updated {formatDate(lastUpdated)}</p>
            </div>
            <button className="text-button" onClick={() => navigate("monitoring")}>View all <ChevronRight size={16} /></button>
          </div>
          {renderProcessTable(processes.slice(0, 6))}
        </section>
      </>
    );
  }

  function renderMonitoring() {
    return (
      <>
        <section className="welcome-row">
          <div>
            <p className="eyebrow">SYSTEM ACTIVITY</p>
            <h2>Live Monitoring</h2>
            <p className="muted">View running processes and their current operating-system metrics.</p>
          </div>
          <button className="secondary-button" onClick={fetchProcesses}><RefreshCw size={16} /> Refresh</button>
        </section>
        {error && <div className="alert-banner"><AlertTriangle size={18} />{error}</div>}

        {/* EXPERIMENTAL LIVE PROCESS SCANNER */}
        <section className="panel simulation-panel">
          <div className="panel-heading">
            <div>
              <h3><Shield size={18} /> Live Process Scanner</h3>
              <p>Enter a running Windows process to request an ML prediction.</p>
            </div>
            <StatusPill type="warning">Experimental</StatusPill>
          </div>

          <div className="table-toolbar">
            <div className="search-box">
              <Search size={17} />
              <input
                value={processName}
                onChange={(event) => setProcessName(event.target.value)}
                onKeyDown={(event) => {
                if (event.key === "Enter" && !processScanLoading) {
                  runProcessScan();
                }
              }}
              placeholder="Enter process name, e.g. chrome.exe"
              aria-label="Process executable name"
            />
          </div>

          <button
            className="primary-button"
            onClick={runProcessScan}
            disabled={processScanLoading || !modelReady}
          >
            {processScanLoading ? (
              <RefreshCw className="spin" size={17} />
            ) : (
              <Search size={17} />
            )}
            {processScanLoading ? "Scanning..." : "Scan Process"}
          </button>
        </div>

  {!modelReady && (
    <p className="data-note">
      The ML model must be ready before scanning.
    </p>
  )}

  {processScanError && (
    <div className="alert-banner error-banner">
      <AlertTriangle size={18} />
      {processScanError}
    </div>
  )}

  {processScan && (
    <div className="scan-result">
      <div className="panel-heading">
        <div>
          <h3><Activity size={18} /> Scan Result</h3>
          <p>
            {processScan.process_name} · PID {processScan.pid}
          </p>
        </div>

        <StatusPill type="success">Scan completed</StatusPill>
      </div>

      <div className="result-highlight">
        <div>
          <span>Predicted class</span>
          <h2>{processScan.predicted_class}</h2>
        </div>

        <div>
          <span>Model confidence</span>
          <h2>
            {formatNumber(processScan.confidence_percent, 2)}%
          </h2>
        </div>
      </div>

      <div className="details-grid">
        <div>
          <span>Process</span>
          <strong>{processScan.process_name}</strong>
        </div>

        <div>
          <span>Process ID</span>
          <strong>{processScan.pid}</strong>
        </div>

        <div>
          <span>Input features</span>
          <strong>{processScan.feature_count}</strong>
        </div>

        <div>
          <span>Scanner status</span>
          <strong>{processScan.status}</strong>
        </div>
      </div>

      <h4>Class probabilities</h4>

      <div className="probability-list">
        {Object.entries(processScan.class_probabilities || {}).map(
          ([label, value]) => (
            <div className="probability-row" key={label}>
              <div>
                <span>{label}</span>
                <strong>{formatNumber(value, 2)}%</strong>
              </div>

              <div className="probability-track">
                <div
                  style={{
                    width: `${Math.max(
                      0,
                      Math.min(100, Number(value) || 0)
                    )}%`,
                  }}
                />
              </div>
            </div>
          )
        )}
      </div>

      <h4>Feature information</h4>

      <div className="details-grid">
        <div>
          <span>Observed fields</span>
          <strong>
            {processScan.observed_fields?.length ?? 0}
          </strong>
        </div>

        <div>
          <span>Assumed fields</span>
          <strong>
            {processScan.assumed_fields?.length ?? 0}
          </strong>
        </div>
      </div>

      <p className="data-note">
        {processScan.disclaimer}
      </p>
    </div>
  )}
</section>

        <section className="panel process-panel">
          <div className="panel-heading">
            <div>
              <h3><Activity size={18} /> Running Processes</h3>
              <p>{processes.length} processes · Last update: {formatDate(lastUpdated)}</p>
            </div>
            <StatusPill type={apiOnline ? "success" : "danger"}>{apiOnline ? "Connected" : "Disconnected"}</StatusPill>
          </div>
          <div className="table-toolbar">
            <div className="search-box">
              <Search size={17} />
              <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search process, PID or username..." />
            </div>
            <span className="muted small-text">{filteredProcesses.length} results</span>
          </div>
          {renderProcessTable(filteredProcesses)}
          <p className="data-note">Note: these are live OS metrics only. The dataset-trained ML model does not currently classify these live processes.</p>
        </section>
      </>
    );
  }

  function renderThreats() {
    const probabilities = simulation?.class_probabilities || {};
    const indicators = simulation?.feature_indicators || {};

    return (
      <>
        <section className="welcome-row">
          <div>
            <p className="eyebrow">CONTROLLED TESTING</p>
            <h2>Threat Detection</h2>
            <p className="muted">Run a safe prediction using a sample from the research dataset.</p>
          </div>
          <StatusPill type="warning">Dataset simulation</StatusPill>
        </section>

        <div className="notice-panel">
          <AlertTriangle size={20} />
          <div><strong>Simulation, not live malware scanning</strong><p>This feature selects a labelled sample from the dataset and passes its features to the trained model. It does not execute malware or scan running processes.</p></div>
        </div>

        <section className="panel simulation-panel">
          <div className="panel-heading">
            <div><h3><Bug size={18} /> Run threat simulation</h3><p>Choose a threat category to select a dataset sample.</p></div>
          </div>
          <div className="threat-options">
            {threatTypes.map((type) => (
              <button key={type} className={`threat-option ${selectedThreat === type ? "selected" : ""}`} onClick={() => { setSelectedThreat(type); setSimulation(null); setSimulationError(""); }}>
                <ShieldAlert size={19} />
                <span>{type}</span>
                {selectedThreat === type && <CheckCircle size={17} />}
              </button>
            ))}
          </div>
          <button className="primary-button" onClick={runSimulation} disabled={simulationLoading || !modelReady}>
            {simulationLoading ? <RefreshCw className="spin" size={17} /> : <Zap size={17} />}
            {simulationLoading ? "Running simulation..." : "Run simulation"}
          </button>
          {!modelReady && <p className="data-note">The model must be ready before you can run a simulation.</p>}
          {simulationError && <div className="alert-banner error-banner">{simulationError}</div>}
        </section>

        {simulation && (
          <section className="panel result-panel">
            <div className="panel-heading">
              <div><h3><ShieldCheck size={18} /> Simulation Result</h3><p>Prediction returned by the trained model</p></div>
              <StatusPill type="success">Completed</StatusPill>
            </div>
            <div className="result-highlight">
              <div><span>Predicted class</span><h2>{simulation.predicted_class || "Unknown"}</h2></div>
              <div><span>Confidence</span><h2>{simulation.confidence_percent != null ? `${formatNumber(simulation.confidence_percent, 2)}%` : "—"}</h2></div>
            </div>
            <p className="data-note">Requested sample category: {simulation.requested_threat || selectedThreat}. The model prediction may differ from the requested category.</p>
            <h4>Class probabilities</h4>
            <div className="probability-list">
              {Object.entries(probabilities).map(([label, value]) => (
                <div className="probability-row" key={label}>
                  <div><span>{label}</span><strong>{formatNumber(value, 2)}%</strong></div>
                  <div className="probability-track"><div style={{ width: `${Math.max(0, Math.min(100, Number(value) || 0))}%` }} /></div>
                </div>
              ))}
              {Object.keys(probabilities).length === 0 && <p className="muted">No probability details were returned.</p>}
            </div>
            <h4>Sample information</h4>
            <div className="details-grid">
              <div><span>Sample source</span><strong>{simulation.sample_source || "—"}</strong></div>
              <div><span>Matched using</span><strong>{simulation.matched_using || "—"}</strong></div>
              <div><span>Available samples</span><strong>{simulation.available_samples ?? "—"}</strong></div>
              <div><span>Feature count</span><strong>{simulation.feature_count ?? "—"}</strong></div>
            </div>
            {Object.keys(indicators).length > 0 && (
              <>
                <h4>Feature indicators</h4>
                <pre className="indicator-output">{JSON.stringify(indicators, null, 2)}</pre>
              </>
            )}
            <p className="data-note">{simulation.disclaimer || "This is a controlled dataset simulation, not a live process scan."}</p>
          </section>
        )}
      </>
    );
  }

  function renderPerformance() {
    return (
      <>
        <section className="welcome-row">
          <div><p className="eyebrow">MODEL INFORMATION</p><h2>Model Performance</h2><p className="muted">Details reported by the backend about the trained model.</p></div>
          <button className="secondary-button" onClick={fetchModelStatus}><RefreshCw size={16} /> Refresh</button>
        </section>
        {!modelStatus ? (
          <EmptyState icon={Cpu} title="Model information unavailable" message="Check that the backend is running and the model files are present." />
        ) : (
          <>
            <section className="metric-grid">
              <MetricCard icon={ShieldCheck} label="Model Status" value={modelReady ? "Ready" : "Not ready"} detail="Artifact loading status" tone="green" />
              <MetricCard icon={BarChart3} label="Reported Accuracy" value={reportedAccuracy != null ? `${formatNumber(reportedAccuracy, 2)}%` : "—"} detail="Reported in project README" tone="purple" />
              <MetricCard icon={Database} label="Dataset Records" value={modelStatus.dataset_rows?.toLocaleString?.() ?? "—"} detail="Available CSV records" tone="blue" />
              <MetricCard icon={Cpu} label="Input Features" value={modelStatus.feature_count ?? "—"} detail="Expected model inputs" tone="orange" />
            </section>
            <section className="panel">
              <div className="panel-heading"><div><h3><Cpu size={18} /> Model configuration</h3><p>Technical details returned by the API</p></div><StatusPill type={modelReady ? "success" : "warning"}>{modelStatus.status || "Unknown"}</StatusPill></div>
              <div className="details-grid">
                <div><span>Model type</span><strong>{modelStatus.model_type || "—"}</strong></div>
                <div><span>Scaler type</span><strong>{modelStatus.scaler_type || "—"}</strong></div>
                <div><span>Scaler feature count</span><strong>{modelStatus.scaler_feature_count ?? "—"}</strong></div>
                <div><span>Dataset file</span><strong>{modelStatus.dataset_file || "—"}</strong></div>
              </div>
              <h4>Classes</h4>
              <div className="tag-list">{(modelStatus.classes || []).map((item) => <span key={item}>{item}</span>)}</div>
              <h4>Estimators</h4>
              <div className="tag-list">{(modelStatus.estimators || []).map((item) => <span key={item}>{item}</span>)}</div>
              <p className="data-note">{modelStatus.accuracy_note || "Accuracy is reported project information and has not been recalculated by this dashboard."}</p>
            </section>
          </>
        )}
      </>
    );
  }

  function renderSettings() {
    return (
      <>
        <section className="welcome-row">
          <div><p className="eyebrow">PREFERENCES</p><h2>Settings</h2><p className="muted">Configure dashboard appearance and refresh behaviour.</p></div>
        </section>
        <section className="panel settings-panel">
          <div className="setting-row">
            <div className="setting-description"><h3><Sun size={18} /> Appearance</h3><p>Choose the dashboard colour theme.</p></div>
            <button className="secondary-button" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
              {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
              Switch to {theme === "dark" ? "Light" : "Dark"} mode
            </button>
          </div>
          <div className="setting-row">
            <div className="setting-description"><h3><RefreshCw size={18} /> Process refresh interval</h3><p>How often live process information is requested.</p></div>
            <select value={refreshInterval} onChange={(event) => setRefreshInterval(Number(event.target.value))}>
              <option value={1000}>1 second</option>
              <option value={3000}>3 seconds</option>
              <option value={5000}>5 seconds</option>
              <option value={10000}>10 seconds</option>
            </select>
          </div>
          <div className="setting-row">
            <div className="setting-description"><h3><Activity size={18} /> Backend connection</h3><p>FastAPI service at {API_BASE}</p></div>
            <StatusPill type={apiOnline ? "success" : "danger"}>{apiOnline ? "Connected" : "Disconnected"}</StatusPill>
          </div>
        </section>
      </>
    );
  }

  const pageTitles = {
    dashboard: "Dashboard",
    monitoring: "Live Monitoring",
    threats: "Threat Detection",
    performance: "Model Performance",
    settings: "Settings",
  };

  return (
    <div className={`app-shell ${theme}`}>
      {sidebarOpen && <button className="mobile-overlay" aria-label="Close menu" onClick={() => setSidebarOpen(false)} />}
      <aside className={`sidebar ${sidebarOpen ? "sidebar-open" : ""}`}>
        <div className="brand">
          <div className="brand-mark"><ShieldCheck size={25} /></div>
          <div><h1>Sentinel<span>AI</span></h1><p>THREAT INTELLIGENCE</p></div>
          <button className="mobile-close" onClick={() => setSidebarOpen(false)} aria-label="Close menu"><X size={20} /></button>
        </div>

        <p className="nav-caption">WORKSPACE</p>
        <nav className="navigation">
          {navigation.map(({ id, label, icon: Icon }) => (
            <button key={id} className={`nav-item ${activePage === id ? "active" : ""}`} onClick={() => navigate(id)}>
              <Icon size={19} /><span>{label}</span>
              {activePage === id && <span className="nav-active-mark" />}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="connection-card">
            <span className={`connection-indicator ${apiOnline ? "online" : ""}`} />
            <div><strong>{apiOnline ? "Backend connected" : "Backend offline"}</strong><p>FastAPI service</p></div>
          </div>
          <p className="sidebar-version">Sentinel AI · Project Dashboard</p>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="topbar-left">
            <button className="mobile-menu" onClick={() => setSidebarOpen(true)} aria-label="Open menu"><Menu size={21} /></button>
            <div><span className="breadcrumb">Workspace</span><ChevronRight size={14} /><strong>{pageTitles[activePage]}</strong></div>
          </div>
          <div className="topbar-right">
            <span className={`topbar-status ${apiOnline ? "online" : ""}`}><span />{apiOnline ? "System online" : "System offline"}</span>
            <button className="icon-button" onClick={() => setTheme(theme === "dark" ? "light" : "dark")} aria-label="Toggle theme">
              {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
            </button>
          </div>
        </header>

        <div className="page-content">
          {activePage === "dashboard" && renderDashboard()}
          {activePage === "monitoring" && renderMonitoring()}
          {activePage === "threats" && renderThreats()}
          {activePage === "performance" && renderPerformance()}
          {activePage === "settings" && renderSettings()}
        </div>
      </main>
    </div>
  );
}

export default App;
