/\* \==========================================================================  
   TLSFingerprintForge Pro \- Cyber Dark Theme Stylesheet  
   \========================================================================== \*/

:root {  
  \--bg-primary: \#070913;  
  \--bg-card: \#0d1224;  
  \--bg-card-hover: \#121933;  
  \--bg-input: \#080c1b;  
  \--border-color: \#1e294b;  
  \--border-focus: \#06b6d4;

  \--text-main: \#f8fafc;  
  \--text-muted: \#94a3b8;  
  \--text-dim: \#64748b;

  \--accent-cyan: \#06b6d4;  
  \--accent-blue: \#3b82f6;  
  \--accent-indigo: \#6366f1;  
  \--accent-green: \#10b981;  
  \--accent-amber: \#f59e0b;  
  \--accent-red: \#ef4444;

  \--font-sans: \-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;  
  \--font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;  
}

\* {  
  box-sizing: border-box;  
  margin: 0;  
  padding: 0;  
}

body {  
  background-color: var(--bg-primary);  
  color: var(--text-main);  
  font-family: var(--font-sans);  
  line-height: 1.5;  
  padding: 24px;  
}

.container {  
  max-width: 1440px;  
  margin: 0 auto;  
}

/\* Header \*/  
header {  
  display: flex;  
  justify-content: space-between;  
  align-items: center;  
  padding-bottom: 20px;  
  margin-bottom: 24px;  
  border-bottom: 1px solid var(--border-color);  
  flex-wrap: wrap;  
  gap: 16px;  
}

.logo-area {  
  display: flex;  
  align-items: center;  
  gap: 14px;  
}

.logo-icon {  
  width: 44px;  
  height: 44px;  
  background: linear-gradient(135deg, var(--accent-cyan), var(--accent-indigo));  
  border-radius: 10px;  
  display: flex;  
  align-items: center;  
  justify-content: center;  
  font-weight: 800;  
  font-size: 20px;  
  color: \#fff;  
  box-shadow: 0 0 20px rgba(6, 182, 212, 0.35);  
}

.logo-text h1 {  
  font-size: 24px;  
  font-weight: 700;  
  letter-spacing: \-0.5px;  
}

.logo-text p {  
  font-size: 13px;  
  color: var(--text-muted);  
}

.header-badges {  
  display: flex;  
  gap: 8px;  
  flex-wrap: wrap;  
}

.badge {  
  font-size: 11px;  
  font-weight: 600;  
  padding: 4px 10px;  
  border-radius: 9999px;  
  text-transform: uppercase;  
  letter-spacing: 0.5px;  
}

.badge-cyan { background: rgba(6, 182, 212, 0.15); color: \#22d3ee; border: 1px solid rgba(6, 182, 212, 0.4); }  
.badge-green { background: rgba(16, 185, 129, 0.15); color: \#34d399; border: 1px solid rgba(16, 185, 129, 0.4); }  
.badge-amber { background: rgba(245, 158, 11, 0.15); color: \#fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }  
.badge-red { background: rgba(239, 68, 68, 0.15); color: \#f87171; border: 1px solid rgba(239, 68, 68, 0.4); }  
.badge-indigo { background: rgba(99, 102, 241, 0.15); color: \#818cf8; border: 1px solid rgba(99, 102, 241, 0.4); }

/\* Presets Bar \*/  
.presets-bar {  
  background: var(--bg-card);  
  border: 1px solid var(--border-color);  
  border-radius: 12px;  
  padding: 14px 20px;  
  margin-bottom: 24px;  
  display: flex;  
  align-items: center;  
  justify-content: space-between;  
  gap: 16px;  
  flex-wrap: wrap;  
}

.presets-label {  
  font-size: 13px;  
  font-weight: 600;  
  color: var(--text-muted);  
}

.presets-buttons {  
  display: flex;  
  gap: 10px;  
  flex-wrap: wrap;  
}

.preset-btn {  
  background: \#141c38;  
  border: 1px solid var(--border-color);  
  color: var(--text-main);  
  padding: 8px 14px;  
  border-radius: 8px;  
  font-size: 12px;  
  font-weight: 500;  
  cursor: pointer;  
  transition: all 0.2s ease;  
}

.preset-btn:hover {  
  background: \#1a254b;  
  border-color: var(--accent-cyan);  
  color: var(--accent-cyan);  
}

.preset-btn.active {  
  background: rgba(6, 182, 212, 0.2);  
  border-color: var(--accent-cyan);  
  color: \#22d3ee;  
  font-weight: 600;  
}

/\* Main Grid \*/  
.main-grid {  
  display: grid;  
  grid-template-columns: 1fr 1fr;  
  gap: 24px;  
}

@media (max-width: 1080px) {  
  .main-grid {  
    grid-template-columns: 1fr;  
  }  
}

.card {  
  background: var(--bg-card);  
  border: 1px solid var(--border-color);  
  border-radius: 12px;  
  padding: 22px;  
  margin-bottom: 24px;  
}

.card-title {  
  font-size: 16px;  
  font-weight: 700;  
  margin-bottom: 16px;  
  display: flex;  
  justify-content: space-between;  
  align-items: center;  
  color: var(--text-main);  
}

.form-group {  
  margin-bottom: 16px;  
}

.form-label {  
  display: flex;  
  justify-content: space-between;  
  font-size: 12px;  
  font-weight: 600;  
  color: var(--text-muted);  
  margin-bottom: 6px;  
}

.form-input, .form-textarea, .form-select {  
  width: 100%;  
  background: var(--bg-input);  
  border: 1px solid var(--border-color);  
  color: var(--text-main);  
  border-radius: 8px;  
  padding: 10px 12px;  
  font-family: var(--font-mono);  
  font-size: 13px;  
  transition: border-color 0.2s;  
}

.form-input:focus, .form-textarea:focus, .form-select:focus {  
  outline: none;  
  border-color: var(--border-focus);  
  box-shadow: 0 0 10px rgba(6, 182, 212, 0.2);  
}

.form-textarea {  
  min-height: 80px;  
  resize: vertical;  
  word-break: break-all;  
}

.action-row {  
  display: flex;  
  gap: 10px;  
  margin-bottom: 16px;  
  flex-wrap: wrap;  
}

.btn {  
  background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));  
  color: \#fff;  
  border: none;  
  padding: 9px 16px;  
  border-radius: 8px;  
  font-size: 13px;  
  font-weight: 600;  
  cursor: pointer;  
  transition: opacity 0.2s, transform 0.1s;  
  display: inline-flex;  
  align-items: center;  
  gap: 6px;  
}

.btn:hover {  
  opacity: 0.92;  
  transform: translateY(-1px);  
}

.btn-secondary {  
  background: \#151e3a;  
  border: 1px solid var(--border-color);  
  color: var(--text-main);  
}

.btn-secondary:hover {  
  background: \#1c284f;  
  border-color: var(--accent-cyan);  
}

/\* Metric Pills \*/  
.metric-row {  
  display: grid;  
  grid-template-columns: repeat(3, 1fr);  
  gap: 12px;  
  margin-bottom: 16px;  
}

.metric-box {  
  background: var(--bg-input);  
  border: 1px solid var(--border-color);  
  border-radius: 8px;  
  padding: 10px 12px;  
  text-align: center;  
}

.metric-val {  
  font-size: 15px;  
  font-weight: 700;  
  font-family: var(--font-mono);  
  color: \#22d3ee;  
  word-break: break-all;  
}

.metric-title {  
  font-size: 11px;  
  color: var(--text-muted);  
  text-transform: uppercase;  
  margin-top: 2px;  
}

/\* Scorecard Header \*/  
.score-banner {  
  display: flex;  
  align-items: center;  
  justify-content: space-between;  
  background: linear-gradient(135deg, \#0d1a33, \#0a1329);  
  border: 1px solid var(--border-color);  
  border-radius: 10px;  
  padding: 16px 20px;  
  margin-bottom: 20px;  
}

.score-left {  
  display: flex;  
  align-items: center;  
  gap: 16px;  
}

.score-badge-huge {  
  font-size: 32px;  
  font-weight: 800;  
  line-height: 1;  
  padding: 12px 18px;  
  border-radius: 12px;  
  font-family: var(--font-mono);  
}

.grade-aplus { background: rgba(16, 185, 129, 0.2); color: \#34d399; border: 1px solid \#10b981; }  
.grade-a { background: rgba(6, 182, 212, 0.2); color: \#22d3ee; border: 1px solid \#06b6d4; }  
.grade-b { background: rgba(59, 130, 246, 0.2); color: \#60a5fa; border: 1px solid \#3b82f6; }  
.grade-c { background: rgba(245, 158, 11, 0.2); color: \#fbbf24; border: 1px solid \#f59e0b; }  
.grade-f { background: rgba(239, 68, 68, 0.2); color: \#f87171; border: 1px solid \#ef4444; }

.checks-list {  
  display: flex;  
  flex-direction: column;  
  gap: 10px;  
}

.check-item {  
  background: var(--bg-input);  
  border: 1px solid var(--border-color);  
  border-radius: 8px;  
  padding: 12px 14px;  
  display: flex;  
  flex-direction: column;  
  gap: 4px;  
}

.check-header {  
  display: flex;  
  justify-content: space-between;  
  align-items: center;  
}

.check-title {  
  font-size: 13px;  
  font-weight: 600;  
  display: flex;  
  align-items: center;  
  gap: 8px;  
}

.check-msg {  
  font-size: 12px;  
  color: var(--text-muted);  
}

.check-remediation {  
  font-size: 11px;  
  color: \#fbbf24;  
  background: rgba(245, 158, 11, 0.1);  
  padding: 4px 8px;  
  border-radius: 4px;  
  margin-top: 4px;  
}

/\* Alert Box \*/  
.alert-banner {  
  background: rgba(239, 68, 68, 0.15);  
  border: 1px solid \#ef4444;  
  border-radius: 8px;  
  padding: 12px 16px;  
  margin-bottom: 16px;  
  display: flex;  
  align-items: flex-start;  
  gap: 12px;  
}

.alert-icon {  
  font-size: 20px;  
}

.alert-text {  
  font-size: 12px;  
  color: \#fca5a5;  
}

/\* Code Synthesizer Tabs \*/  
.code-tabs {  
  display: flex;  
  gap: 6px;  
  margin-bottom: 12px;  
  flex-wrap: wrap;  
}

.code-tab {  
  background: \#131a33;  
  border: 1px solid var(--border-color);  
  color: var(--text-muted);  
  padding: 6px 12px;  
  border-radius: 6px;  
  font-size: 12px;  
  font-weight: 500;  
  cursor: pointer;  
  transition: all 0.2s;  
}

.code-tab.active {  
  background: rgba(6, 182, 212, 0.2);  
  border-color: var(--accent-cyan);  
  color: \#22d3ee;  
}

.code-block {  
  background: \#050711;  
  border: 1px solid var(--border-color);  
  border-radius: 8px;  
  padding: 14px;  
  font-family: var(--font-mono);  
  font-size: 12px;  
  color: \#e2e8f0;  
  white-space: pre;  
  overflow-x: auto;  
  max-height: 380px;  
}

.copy-notify {  
  font-size: 11px;  
  color: \#34d399;  
  display: none;  
  margin-left: 8px;  
}  
