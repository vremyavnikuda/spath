import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

interface PathIssue {
  path: string;
  level: string;
  message: string;
}

interface ScanResult {
  total_paths: number;
  issues: PathIssue[];
  health_score: number;
  critical_count: number;
  warning_count: number;
  info_count: number;
}

interface PathEntry {
  path: string;
  location: string;
  category: string;
  exists: boolean;
  has_spaces: boolean;
  is_quoted: boolean;
}

interface AnalysisResult {
  entries: PathEntry[];
  system_count: number;
  user_count: number;
}

interface BackupInfo {
  filename: string;
  timestamp: string;
  full_path: string;
}

interface AuditLogEntry {
  timestamp: string;
  action: string;
  target: string;
  changes_count: number;
  changes: string[];
  success: boolean;
  error: string | null;
}

interface VerifyResult {
  path: string;
  is_exploitable: boolean;
  exploit_files: string[];
  threat_level: string;
}

interface CleanResult {
  removed_duplicates: string[];
  total_removed: number;
}

type Tab = "scan" | "analyze" | "backups" | "audit" | "verify" | "clean" | "visualize";

interface ConfirmModal {
  title: string;
  message: string;
  onConfirm: () => void;
  confirmText?: string;
  danger?: boolean;
}

type ScanMode = "USER" | "SYSTEM" | "VERBOSE" | "DEEP";

interface Suggestion {
  type: "system" | "verbose" | "security" | "clean";
  title: string;
  message: string;
  action: () => void;
  actionText: string;
  info?: string;
}

function App() {
  const [tab, setTab] = useState<Tab>("scan");
  const [loading, setLoading] = useState(false);
  const [loadingMessage, setLoadingMessage] = useState("");
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const [backups, setBackups] = useState<BackupInfo[]>([]);
  const [changes, setChanges] = useState<string[]>([]);
  const [auditLog, setAuditLog] = useState<AuditLogEntry[]>([]);
  const [verifyResults, setVerifyResults] = useState<VerifyResult[]>([]);
  const [cleanResult, setCleanResult] = useState<CleanResult | null>(null);
  const [scanMode, setScanMode] = useState<ScanMode>("USER");
  const [suggestion, setSuggestion] = useState<Suggestion | null>(null);
  const [hasAdminRights, setHasAdminRights] = useState(false);
  const [visualizeFilter, setVisualizeFilter] = useState<"all" | "issues" | "user" | "system">("all");
  const [expandedPaths, setExpandedPaths] = useState<Set<number>>(new Set());
  const [hoveredPath, setHoveredPath] = useState<number | null>(null);
  const [toast, setToast] = useState<{ message: string; type: "success" | "error" } | null>(null);
  const [confirmModal, setConfirmModal] = useState<ConfirmModal | null>(null);

  const showToast = (message: string, type: "success" | "error") => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 3000);
  };

  const runScan = async (mode?: ScanMode) => {
    const currentMode = mode || scanMode;
    setScanMode(currentMode);
    
    setLoading(true);
    setLoadingMessage("Scanning PATH...");
    setSuggestion(null);
    
    try {
      const scanSystem = currentMode === "SYSTEM" || currentMode === "DEEP";
      const verbose = currentMode === "VERBOSE" || currentMode === "DEEP";
      
      const result = await invoke<ScanResult>("scan_path", { 
        scanSystem,
        verbose 
      });
      setScanResult(result);
      
      generateSuggestions(result, currentMode);
    } catch (e) {
      showToast(String(e), "error");
    }
    setLoading(false);
    setLoadingMessage("");
  };

  const generateSuggestions = (result: ScanResult, mode: ScanMode) => {
    if (result.critical_count > 0 && mode !== "DEEP") {
      setSuggestion({
        type: "security",
        title: "Issues detected",
        message: `Found ${result.critical_count} critical issue(s). Run deep scan to check for real security threats?`,
        action: () => runSecurityAudit(),
        actionText: "Run Security Audit",
        info: "Will check for exploit files and duplicates"
      });
      return;
    }

    if (result.critical_count === 0 && result.warning_count === 0 && mode === "USER") {
      if (hasAdminRights) {
        setSuggestion({
          type: "system",
          title: "Suggestion",
          message: "Your USER PATH looks clean! Want to check SYSTEM PATH too?",
          action: () => runScan("SYSTEM"),
          actionText: "Scan SYSTEM PATH",
          info: "Requires administrator privileges"
        });
      } else {
        setSuggestion({
          type: "verbose",
          title: "No issues found",
          message: "Your PATH is clean! Want to see all paths including valid ones?",
          action: () => runScan("VERBOSE"),
          actionText: "Show All Paths"
        });
      }
      return;
    }

    if (result.critical_count === 0 && result.warning_count > 0 && mode !== "VERBOSE") {
      setSuggestion({
        type: "verbose",
        title: "Suggestion",
        message: `Found ${result.warning_count} warning(s). Want to see detailed information?`,
        action: () => runScan("VERBOSE"),
        actionText: "Show Details"
      });
    }
  };

  const runSecurityAudit = async () => {
    setSuggestion(null);
    await runScan("DEEP");
    setTab("verify");
  };

  const runAnalysis = async () => {
    setLoading(true);
    setLoadingMessage("Analyzing PATH entries...");
    try {
      const result = await invoke<AnalysisResult>("analyze_path");
      setAnalysisResult(result);
    } catch (e) {
      showToast(String(e), "error");
    }
    setLoading(false);
    setLoadingMessage("");
  };

  const loadBackups = async () => {
    setLoading(true);
    setLoadingMessage("Loading backups...");
    try {
      const result = await invoke<BackupInfo[]>("list_backups");
      setBackups(result);
    } catch (e) {
      showToast(String(e), "error");
    }
    setLoading(false);
    setLoadingMessage("");
  };

  const createBackup = async () => {
    setLoading(true);
    setLoadingMessage("Creating backup...");
    try {
      await invoke<string>("create_backup");
      showToast("Backup created", "success");
      await loadBackups();
    } catch (e) {
      showToast(String(e), "error");
    }
    setLoading(false);
    setLoadingMessage("");
  };

  const confirmRestoreBackup = (path: string, filename: string) => {
    setConfirmModal({
      title: "Restore Backup",
      message: `Are you sure you want to restore PATH from "${filename}"? Current PATH will be backed up automatically.`,
      confirmText: "Restore",
      danger: true,
      onConfirm: () => restoreBackup(path),
    });
  };

  const restoreBackup = async (path: string) => {
    setConfirmModal(null);
    setLoading(true);
    setLoadingMessage("Restoring backup...");
    try {
      await invoke("restore_backup", { backupPath: path });
      showToast("PATH restored from backup", "success");
      await runScan();
    } catch (e) {
      showToast(String(e), "error");
    }
    setLoading(false);
    setLoadingMessage("");
  };

  const previewFix = async () => {
    setLoading(true);
    setLoadingMessage("Analyzing changes...");
    try {
      const result = await invoke<string[]>("fix_user_path", { dryRun: true });
      setChanges(result);
      if (result.length === 0) {
        showToast("No changes needed", "success");
      }
    } catch (e) {
      showToast(String(e), "error");
    }
    setLoading(false);
    setLoadingMessage("");
  };

  const confirmApplyFix = () => {
    setConfirmModal({
      title: "Apply Changes",
      message: `Apply ${changes.length} change(s) to your PATH? A backup will be created automatically.`,
      confirmText: "Apply",
      danger: true,
      onConfirm: applyFix,
    });
  };

  const applyFix = async () => {
    setConfirmModal(null);
    setLoading(true);
    setLoadingMessage("Applying changes...");
    try {
      await invoke<string[]>("fix_user_path", { dryRun: false });
      showToast("PATH fixed successfully", "success");
      setChanges([]);
      await runScan();
    } catch (e) {
      showToast(String(e), "error");
    }
    setLoading(false);
    setLoadingMessage("");
  };

  useEffect(() => {
    const checkAdminRights = async () => {
      try {
        await invoke<ScanResult>("scan_path", { scanSystem: true, verbose: false });
        setHasAdminRights(true);
      } catch {
        setHasAdminRights(false);
      }
    };
    
    checkAdminRights();
    runScan("USER");
  }, []);

  const loadAuditLog = async () => {
    setLoading(true);
    setLoadingMessage("Loading audit log...");
    try {
      const result = await invoke<AuditLogEntry[]>("get_audit_log", { count: 50 });
      setAuditLog(result);
    } catch (e) {
      showToast(String(e), "error");
    }
    setLoading(false);
    setLoadingMessage("");
  };

  const runVerify = async () => {
    setLoading(true);
    setLoadingMessage("Verifying PATH exploitability...");
    try {
      const result = await invoke<VerifyResult[]>("verify_path");
      setVerifyResults(result);
      if (result.length === 0) {
        showToast("No exploitable paths found", "success");
      }
    } catch (e) {
      showToast(String(e), "error");
    }
    setLoading(false);
    setLoadingMessage("");
  };

  const previewClean = async () => {
    setLoading(true);
    setLoadingMessage("Analyzing duplicates...");
    try {
      const result = await invoke<CleanResult>("clean_path", { dryRun: true });
      setCleanResult(result);
      if (result.total_removed === 0) {
        showToast("No duplicates found", "success");
      }
    } catch (e) {
      showToast(String(e), "error");
    }
    setLoading(false);
    setLoadingMessage("");
  };

  const confirmApplyClean = () => {
    if (!cleanResult || cleanResult.total_removed === 0) return;
    setConfirmModal({
      title: "Remove Duplicates",
      message: `Remove ${cleanResult.total_removed} duplicate(s) from your PATH? A backup will be created automatically.`,
      confirmText: "Remove",
      danger: true,
      onConfirm: applyClean,
    });
  };

  const applyClean = async () => {
    setConfirmModal(null);
    setLoading(true);
    setLoadingMessage("Removing duplicates...");
    try {
      await invoke<CleanResult>("clean_path", { dryRun: false });
      showToast("Duplicates removed successfully", "success");
      setCleanResult(null);
      await runScan();
    } catch (e) {
      showToast(String(e), "error");
    }
    setLoading(false);
    setLoadingMessage("");
  };

  useEffect(() => {
    if (tab === "analyze" && !analysisResult) runAnalysis();
    if (tab === "backups") loadBackups();
    if (tab === "audit") loadAuditLog();
    if (tab === "verify" && verifyResults.length === 0) runVerify();
    if (tab === "clean" && !cleanResult) previewClean();
    if (tab === "visualize" && !analysisResult) runAnalysis();
  }, [tab]);

  const togglePathExpand = (idx: number) => {
    const newExpanded = new Set(expandedPaths);
    if (newExpanded.has(idx)) {
      newExpanded.delete(idx);
    } else {
      newExpanded.add(idx);
    }
    setExpandedPaths(newExpanded);
  };

  const getPathIssues = (path: string) => {
    if (!scanResult) return [];
    return scanResult.issues.filter(issue => issue.path === path);
  };

  const getFilteredPaths = () => {
    if (!analysisResult) return [];
    
    return analysisResult.entries.filter(entry => {
      if (visualizeFilter === "all") return true;
      if (visualizeFilter === "user") return entry.location === "USER";
      if (visualizeFilter === "system") return entry.location === "SYSTEM";
      if (visualizeFilter === "issues") {
        const issues = getPathIssues(entry.path);
        return issues.length > 0;
      }
      return true;
    });
  };

  const getHealthClass = (score: number) => {
    if (score >= 80) return "good";
    if (score >= 50) return "warning";
    return "bad";
  };

  return (
    <div className="app">
      <header className="header">
        <h1>spath</h1>
        {scanResult && (
          <div className="header-stats">
            <div className="stat">
              <span className="stat-label">Paths:</span>
              <span className="stat-value">{scanResult.total_paths}</span>
            </div>
            <div className="stat">
              <span className="stat-label">Health:</span>
              <span className={`stat-value ${getHealthClass(scanResult.health_score)}`}>
                {scanResult.health_score}%
              </span>
            </div>
            <div className={`smart-badge mode-${scanMode.toLowerCase()}`}>
              Auto: {scanMode}
            </div>
          </div>
        )}
      </header>

      <nav className="nav">
        <button className={`nav-btn ${tab === "scan" ? "active" : ""}`} onClick={() => setTab("scan")}>
          Scan
        </button>
        <button className={`nav-btn ${tab === "verify" ? "active" : ""}`} onClick={() => setTab("verify")}>
          Verify
        </button>
        <button className={`nav-btn ${tab === "clean" ? "active" : ""}`} onClick={() => setTab("clean")}>
          Clean
        </button>
        <button className={`nav-btn ${tab === "visualize" ? "active" : ""}`} onClick={() => setTab("visualize")}>
          Visualize
        </button>
        <button className={`nav-btn ${tab === "analyze" ? "active" : ""}`} onClick={() => setTab("analyze")}>
          Analyze
        </button>
        <button className={`nav-btn ${tab === "backups" ? "active" : ""}`} onClick={() => setTab("backups")}>
          Backups
        </button>
        <button className={`nav-btn ${tab === "audit" ? "active" : ""}`} onClick={() => setTab("audit")}>
          Audit Log
        </button>
      </nav>

      <main className="content">
        {loading && (
          <div className="loading-overlay">
            <div className="loading-spinner"></div>
            <div className="loading-text">{loadingMessage}</div>
          </div>
        )}

        {!loading && tab === "scan" && scanResult && (
          <>
            <div className="health-score">
              <div className={`health-circle ${getHealthClass(scanResult.health_score)}`}>
                {scanResult.health_score}
              </div>
              <div className="health-info">
                <h3>PATH Health Score</h3>
                <p>
                  {scanResult.critical_count} critical, {scanResult.warning_count} warnings, {scanResult.info_count} info
                </p>
              </div>
            </div>

            {suggestion && (
              <div className={`suggestion-card suggestion-${suggestion.type}`}>
                <div className="suggestion-header">
                  <span className="suggestion-title">{suggestion.title}</span>
                </div>
                <div className="suggestion-body">
                  <p>{suggestion.message}</p>
                  <div className="suggestion-actions">
                    <button className="btn" onClick={suggestion.action}>
                      {suggestion.actionText}
                    </button>
                    <button className="btn btn-secondary" onClick={() => setSuggestion(null)}>
                      {suggestion.type === "verbose" ? "No, I'm good" : suggestion.type === "system" ? "No, thanks" : "Skip"}
                    </button>
                  </div>
                  {suggestion.info && (
                    <div className="suggestion-info">
                      Info: {suggestion.info}
                    </div>
                  )}
                </div>
              </div>
            )}

            {changes.length > 0 && (
              <div className="card">
                <div className="card-header">
                  <span className="card-title">Pending Changes ({changes.length})</span>
                </div>
                <div className="card-body">
                  <div className="changes-list">
                    {changes.map((change, idx) => (
                      <div key={idx} className="change-item">{change}</div>
                    ))}
                  </div>
                  <div className="actions-bar">
                    <button className="btn" onClick={confirmApplyFix} disabled={loading}>Apply Changes</button>
                    <button className="btn btn-secondary" onClick={() => setChanges([])} disabled={loading}>Cancel</button>
                  </div>
                </div>
              </div>
            )}

            <div className="card">
              <div className="card-header">
                <span className="card-title">Issues ({scanResult.issues.filter(i => i.level !== "info").length})</span>
                <div style={{ display: "flex", gap: "8px" }}>
                  <button className="btn btn-secondary" onClick={() => runScan()} disabled={loading}>Rescan</button>
                  {scanResult.critical_count > 0 || scanResult.warning_count > 0 ? (
                    <button className="btn" onClick={previewFix} disabled={loading}>
                      Fix Issues
                    </button>
                  ) : null}
                </div>
              </div>
              <div className="card-body">
                {scanResult.issues.filter(i => i.level !== "info").length === 0 ? (
                  <div className="empty-state">
                    <p>No issues found. Your PATH is clean!</p>
                  </div>
                ) : (
                  <div className="issue-list">
                    {scanResult.issues
                      .filter(i => i.level !== "info")
                      .map((issue, idx) => (
                        <div key={idx} className={`issue-item ${issue.level}`}>
                          <span className={`issue-badge ${issue.level}`}>{issue.level}</span>
                          <div className="issue-content">
                            <div className="issue-path">{issue.path}</div>
                            <div className="issue-message">{issue.message}</div>
                          </div>
                        </div>
                      ))}
                  </div>
                )}
              </div>
            </div>
          </>
        )}

        {!loading && tab === "verify" && (
          <>
            <div className="card">
              <div className="card-header">
                <span className="card-title">Verify PATH Exploitability</span>
                <button className="btn btn-secondary" onClick={runVerify} disabled={loading}>
                  Re-verify
                </button>
              </div>
              <div className="card-body">
                {verifyResults.length === 0 ? (
                  <div className="empty-state">
                    <p>No exploitable paths found. Your PATH is secure!</p>
                  </div>
                ) : (
                  <div className="issue-list">
                    {verifyResults.map((result, idx) => (
                      <div key={idx} className={`issue-item ${result.is_exploitable ? 'critical' : 'warning'}`}>
                        <span className={`issue-badge ${result.is_exploitable ? 'critical' : 'warning'}`}>
                          {result.threat_level}
                        </span>
                        <div className="issue-content">
                          <div className="issue-path">{result.path}</div>
                          <div className="issue-message">
                            {result.is_exploitable ? (
                              <>
                                <strong>EXPLOITABLE!</strong> Found {result.exploit_files.length} exploit file(s):
                                <ul style={{ marginTop: "8px", paddingLeft: "20px" }}>
                                  {result.exploit_files.map((file, fidx) => (
                                    <li key={fidx}>{file}</li>
                                  ))}
                                </ul>
                              </>
                            ) : (
                              "Not currently exploitable (no malicious files found)"
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </>
        )}

        {!loading && tab === "clean" && (
          <>
            <div className="card">
              <div className="card-header">
                <span className="card-title">Clean Duplicates</span>
                <button className="btn btn-secondary" onClick={previewClean} disabled={loading}>
                  Re-scan
                </button>
              </div>
              <div className="card-body">
                {cleanResult && cleanResult.total_removed === 0 ? (
                  <div className="empty-state">
                    <p>No duplicates found. Your PATH is clean!</p>
                  </div>
                ) : cleanResult ? (
                  <>
                    <div className="changes-list">
                      <p style={{ marginBottom: "12px" }}>
                        Found {cleanResult.total_removed} duplicate(s) to remove:
                      </p>
                      {cleanResult.removed_duplicates.map((dup, idx) => (
                        <div key={idx} className="change-item">Remove: {dup}</div>
                      ))}
                    </div>
                    <div className="actions-bar">
                      <button className="btn" onClick={confirmApplyClean} disabled={loading}>
                        Remove Duplicates
                      </button>
                      <button className="btn btn-secondary" onClick={() => setCleanResult(null)} disabled={loading}>
                        Cancel
                      </button>
                    </div>
                  </>
                ) : (
                  <div className="empty-state">
                    <p>Loading...</p>
                  </div>
                )}
              </div>
            </div>
          </>
        )}

        {!loading && tab === "visualize" && analysisResult && (
          <>
            <div className="card">
              <div className="card-header">
                <span className="card-title">PATH Visualization</span>
                <div style={{ display: "flex", gap: "8px" }}>
                  <button className="btn btn-secondary" onClick={runAnalysis} disabled={loading}>Refresh</button>
                </div>
              </div>
              <div className="card-body">
                <div className="visualize-filters">
                  <button 
                    className={`filter-btn ${visualizeFilter === "all" ? "active" : ""}`}
                    onClick={() => setVisualizeFilter("all")}
                  >
                    All ({analysisResult.entries.length})
                  </button>
                  <button 
                    className={`filter-btn ${visualizeFilter === "user" ? "active" : ""}`}
                    onClick={() => setVisualizeFilter("user")}
                  >
                    USER ({analysisResult.user_count})
                  </button>
                  <button 
                    className={`filter-btn ${visualizeFilter === "system" ? "active" : ""}`}
                    onClick={() => setVisualizeFilter("system")}
                  >
                    SYSTEM ({analysisResult.system_count})
                  </button>
                  <button 
                    className={`filter-btn ${visualizeFilter === "issues" ? "active" : ""}`}
                    onClick={() => setVisualizeFilter("issues")}
                  >
                    Issues Only ({scanResult ? scanResult.issues.length : 0})
                  </button>
                </div>

                <div className="visualize-tree">
                  {getFilteredPaths().map((entry, idx) => {
                    const issues = getPathIssues(entry.path);
                    const hasIssues = issues.length > 0;
                    const isExpanded = expandedPaths.has(idx);
                    const isHovered = hoveredPath === idx;
                    
                    return (
                      <div 
                        key={idx} 
                        className={`tree-node ${hasIssues ? 'has-issues' : ''} ${isExpanded ? 'expanded' : ''}`}
                        onMouseEnter={() => setHoveredPath(idx)}
                        onMouseLeave={() => setHoveredPath(null)}
                      >
                        <div className="tree-node-header" onClick={() => togglePathExpand(idx)}>
                          <span className="tree-expand-icon">{isExpanded ? '▼' : '▶'}</span>
                          <span className={`tree-location ${entry.location.toLowerCase()}`}>
                            {entry.location}
                          </span>
                          <span className={`tree-status ${entry.exists ? 'exists' : 'missing'}`}>
                            {entry.exists ? '●' : '○'}
                          </span>
                          <span className="tree-path">{entry.path}</span>
                          {hasIssues && (
                            <span className="tree-issue-badge">{issues.length}</span>
                          )}
                        </div>

                        {isHovered && (
                          <div className="tree-tooltip">
                            <div className="tooltip-row">
                              <span className="tooltip-label">Location:</span>
                              <span className="tooltip-value">{entry.location}</span>
                            </div>
                            <div className="tooltip-row">
                              <span className="tooltip-label">Category:</span>
                              <span className="tooltip-value">{entry.category}</span>
                            </div>
                            <div className="tooltip-row">
                              <span className="tooltip-label">Exists:</span>
                              <span className="tooltip-value">{entry.exists ? 'Yes' : 'No'}</span>
                            </div>
                            <div className="tooltip-row">
                              <span className="tooltip-label">Has Spaces:</span>
                              <span className="tooltip-value">{entry.has_spaces ? 'Yes' : 'No'}</span>
                            </div>
                            <div className="tooltip-row">
                              <span className="tooltip-label">Quoted:</span>
                              <span className="tooltip-value">{entry.is_quoted ? 'Yes' : 'No'}</span>
                            </div>
                            {hasIssues && (
                              <div className="tooltip-row">
                                <span className="tooltip-label">Issues:</span>
                                <span className="tooltip-value">{issues.length} problem(s)</span>
                              </div>
                            )}
                          </div>
                        )}

                        {isExpanded && (
                          <div className="tree-node-details">
                            <div className="detail-row">
                              <span className="detail-label">Full Path:</span>
                              <span className="detail-value">{entry.path}</span>
                            </div>
                            <div className="detail-row">
                              <span className="detail-label">Category:</span>
                              <span className="detail-value">{entry.category}</span>
                            </div>
                            <div className="detail-row">
                              <span className="detail-label">Properties:</span>
                              <span className="detail-value">
                                {entry.exists ? 'Exists' : 'Missing'} • 
                                {entry.has_spaces ? ' Has Spaces' : ' No Spaces'} • 
                                {entry.is_quoted ? ' Quoted' : ' Unquoted'}
                              </span>
                            </div>
                            {hasIssues && (
                              <div className="detail-issues">
                                <span className="detail-label">Issues:</span>
                                {issues.map((issue, iidx) => (
                                  <div key={iidx} className={`detail-issue ${issue.level}`}>
                                    <span className={`issue-badge ${issue.level}`}>{issue.level}</span>
                                    <span className="issue-message">{issue.message}</span>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          </>
        )}

        {!loading && tab === "analyze" && analysisResult && (
          <>
            <div className="card">
              <div className="card-header">
                <span className="card-title">
                  PATH Entries ({analysisResult.system_count} system, {analysisResult.user_count} user)
                </span>
                <button className="btn btn-secondary" onClick={runAnalysis} disabled={loading}>Refresh</button>
              </div>
              <div className="card-body">
                <div className="path-list">
                  {analysisResult.entries.map((entry, idx) => (
                    <div key={idx} className="path-item">
                      <span className={`path-location ${entry.location.toLowerCase()}`}>
                        {entry.location}
                      </span>
                      <span className="path-value">{entry.path}</span>
                      <span className={`path-status ${entry.exists ? "exists" : "missing"}`}>
                        {entry.exists ? "OK" : "Missing"}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </>
        )}

        {!loading && tab === "backups" && (
          <>
            <div className="card">
              <div className="card-header">
                <span className="card-title">Backups</span>
                <button className="btn" onClick={createBackup} disabled={loading}>Create Backup</button>
              </div>
              <div className="card-body">
                {backups.length === 0 ? (
                  <div className="empty-state">
                    <p>No backups found</p>
                  </div>
                ) : (
                  <div className="backup-list">
                    {backups.map((backup, idx) => (
                      <div key={idx} className="backup-item">
                        <div className="backup-info">
                          <span className="backup-name">{backup.filename}</span>
                          <span className="backup-date">{backup.timestamp}</span>
                        </div>
                        <div className="backup-actions">
                          <button
                            className="btn btn-secondary"
                            onClick={() => confirmRestoreBackup(backup.full_path, backup.filename)}
                            disabled={loading}
                          >
                            Restore
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </>
        )}

        {!loading && tab === "audit" && (
          <>
            <div className="card">
              <div className="card-header">
                <span className="card-title">Audit Log (Last 50 entries)</span>
                <button className="btn btn-secondary" onClick={loadAuditLog} disabled={loading}>Refresh</button>
              </div>
              <div className="card-body">
                {auditLog.length === 0 ? (
                  <div className="empty-state">
                    <p>No audit log entries found</p>
                  </div>
                ) : (
                  <div className="audit-list">
                    {auditLog.map((entry, idx) => (
                      <div key={idx} className={`audit-item ${entry.success ? 'success' : 'error'}`}>
                        <div className="audit-header">
                          <span className="audit-timestamp">{entry.timestamp}</span>
                          <span className={`audit-action ${entry.action.toLowerCase()}`}>{entry.action}</span>
                          <span className="audit-target">{entry.target}</span>
                          <span className={`audit-status ${entry.success ? 'success' : 'error'}`}>
                            {entry.success ? '✓' : '✗'}
                          </span>
                        </div>
                        {entry.changes_count > 0 && (
                          <div className="audit-changes">
                            <div className="audit-changes-count">{entry.changes_count} change(s):</div>
                            {entry.changes.map((change, cidx) => (
                              <div key={cidx} className="audit-change">{change}</div>
                            ))}
                          </div>
                        )}
                        {entry.error && (
                          <div className="audit-error">{entry.error}</div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </>
        )}
      </main>

      {toast && (
        <div className={`toast ${toast.type}`}>
          {toast.message}
        </div>
      )}

      {confirmModal && (
        <div className="modal-overlay" onClick={() => setConfirmModal(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>{confirmModal.title}</h3>
            </div>
            <div className="modal-body">
              <p>{confirmModal.message}</p>
            </div>
            <div className="modal-footer">
              <button 
                className="btn btn-secondary" 
                onClick={() => setConfirmModal(null)}
              >
                Cancel
              </button>
              <button 
                className={`btn ${confirmModal.danger ? 'btn-danger' : ''}`}
                onClick={confirmModal.onConfirm}
              >
                {confirmModal.confirmText || "Confirm"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
