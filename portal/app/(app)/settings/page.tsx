"use client";
import { useState } from "react";
import { Settings, Lock, Eye, EyeOff, CheckCircle, Info } from "lucide-react";

export default function SettingsPage() {
    const [vtKey, setVtKey] = useState(() => typeof window !== "undefined" ? (localStorage.getItem("cs-vt-key") ?? "") : "");
    const [threshold, setThreshold] = useState(() => typeof window !== "undefined" ? parseFloat(localStorage.getItem("cs-threshold") ?? "0.4") : 0.4);
    const [mode, setMode] = useState(() => typeof window !== "undefined" ? (localStorage.getItem("cs-mode") ?? "balanced") : "balanced");
    const [privacy, setPrivacy] = useState(false);
    const [showKey, setShowKey] = useState(false);
    const [saved, setSaved] = useState(false);

    const save = () => {
        localStorage.setItem("cs-vt-key", vtKey);
        localStorage.setItem("cs-threshold", String(threshold));
        localStorage.setItem("cs-mode", mode);
        setSaved(true);
        setTimeout(() => setSaved(false), 2500);
    };

    return (
        <div className="space-y-5 max-w-2xl mx-auto">
            <div className="flex items-center justify-between flex-wrap gap-3">
                <div>
                    <h1 className="text-2xl font-black flex items-center gap-3" style={{ color: "var(--text)" }}>
                        <Settings size={22} style={{ color: "var(--accent)" }} /> Settings
                    </h1>
                    <p className="text-sm mt-1" style={{ color: "var(--text-3)" }}>API keys & detection parameters</p>
                </div>
                <button onClick={save}
                    className="flex items-center gap-2 px-5 py-2.5 rounded-xl font-semibold text-white text-sm transition-all hover:scale-105"
                    style={{ background: saved ? "linear-gradient(135deg,#059669,#10b981)" : "linear-gradient(135deg,#4f46e5,#7c3aed)" }}>
                    {saved ? <><CheckCircle size={15} /> Saved!</> : "Save Settings"}
                </button>
            </div>

            <div className="glass rounded-2xl p-5 space-y-5">
                <div className="flex items-center gap-2 mb-1">
                    <Lock size={14} style={{ color: "var(--accent)" }} />
                    <h3 className="text-sm font-bold" style={{ color: "var(--text)" }}>VirusTotal API Key</h3>
                </div>
                <p className="text-xs" style={{ color: "var(--text-3)" }}>
                    Used to cross-check file hashes against VT cloud intelligence. Get key at{" "}
                    <a href="https://virustotal.com" target="_blank" className="hover:underline" style={{ color: "var(--accent)" }}>virustotal.com</a>.
                </p>
                <div className="relative">
                    <input type={showKey ? "text" : "password"} value={vtKey} onChange={e => setVtKey(e.target.value)}
                        placeholder="Enter your VirusTotal API key…" className="w-full rounded-xl px-4 py-3 pr-11 text-sm focus:outline-none"
                        style={{ background: "var(--surface-2)", border: "1px solid var(--border)", color: "var(--text)" }} />
                    <button onClick={() => setShowKey(!showKey)} className="absolute right-3 top-1/2 -translate-y-1/2" style={{ color: "var(--text-3)" }}>
                        {showKey ? <EyeOff size={15} /> : <Eye size={15} />}
                    </button>
                </div>
                <div className="flex items-start gap-2 px-3 py-2.5 rounded-xl text-xs"
                    style={{ background: "var(--accent-bg)", border: "1px solid var(--accent-brd)", color: "var(--text-3)" }}>
                    <Info size={12} className="mt-0.5 shrink-0" style={{ color: "var(--accent)" }} />
                    The key is stored in localStorage only — never sent to any third party except VirusTotal.
                </div>
            </div>

            <div className="glass rounded-2xl p-5 space-y-5">
                <h3 className="text-sm font-bold" style={{ color: "var(--text)" }}>Detection Parameters</h3>
                <div>
                    <div className="flex items-center justify-between mb-3">
                        <label className="text-xs font-semibold uppercase tracking-wide" style={{ color: "var(--text-3)" }}>Detection Threshold</label>
                        <span className="text-sm font-black font-mono" style={{ color: "var(--accent)" }}>{threshold.toFixed(2)}</span>
                    </div>
                    <input type="range" min={0.1} max={0.9} step={0.05} value={threshold}
                        onChange={e => setThreshold(Number(e.target.value))} className="w-full h-1.5 accent-indigo-500" />
                    <div className="flex justify-between text-xs mt-1" style={{ color: "var(--text-3)" }}>
                        <span>0.1 — Sensitive</span><span>0.5 — Balanced</span><span>0.9 — Strict</span>
                    </div>
                </div>
                <div style={{ height: 1, background: "var(--border)" }} />
                <div>
                    <label className="text-xs font-semibold uppercase tracking-wide mb-3 block" style={{ color: "var(--text-3)" }}>Default Detection Mode</label>
                    <div className="flex gap-2">
                        {[
                            { id: "conservative", label: "Conservative", color: "#10b981", glow: "#10b981" },
                            { id: "balanced",     label: "Balanced",     color: "#818cf8", glow: "#4f46e5" },
                            { id: "aggressive",   label: "Aggressive",   color: "#f87171", glow: "#ef4444" },
                        ].map(m => (
                            <button key={m.id} onClick={() => setMode(m.id)}
                                className="flex-1 py-2.5 rounded-xl text-xs font-semibold transition-all"
                                style={mode === m.id
                                    ? { background: `${m.glow}12`, border: `1px solid ${m.glow}35`, color: m.color }
                                    : { background: "var(--surface)", border: "1px solid var(--border)", color: "var(--text-3)" }}>
                                {m.label}
                            </button>
                        ))}
                    </div>
                </div>
            </div>

            <div className="glass rounded-2xl p-5 space-y-4">
                <h3 className="text-sm font-bold" style={{ color: "var(--text)" }}>Privacy</h3>
                <div className="flex items-start justify-between gap-4">
                    <div>
                        <p className="text-sm font-medium" style={{ color: "var(--text)" }}>Offline Mode</p>
                        <p className="text-xs mt-0.5" style={{ color: "var(--text-3)" }}>Disable all external requests (VirusTotal, CDN). Use only local ML models.</p>
                    </div>
                    <button onClick={() => setPrivacy(!privacy)}
                        className="w-11 h-6 rounded-full transition-all duration-300 relative shrink-0 mt-0.5"
                        style={{ background: privacy ? "linear-gradient(135deg,#4f46e5,#7c3aed)" : "var(--border-2)" }}>
                        <span className={`absolute top-1 w-4 h-4 bg-white rounded-full shadow-lg transition-all duration-300 ${privacy ? "left-6" : "left-1"}`} />
                    </button>
                </div>
            </div>

            <div className="glass rounded-2xl p-5">
                <h3 className="text-sm font-bold mb-4" style={{ color: "var(--text)" }}>About</h3>
                <div className="space-y-2">
                    {[
                        ["Version", "2.0.0"],
                        ["Stack", "FastAPI · Next.js · SQLite"],
                        ["Models", "RF · XGBoost · LightGBM"],
                        ["Dataset", "DS1 · 51 408 samples · 62 features"],
                        ["Author", "Diploma Project 2026"],
                    ].map(([k, v]) => (
                        <div key={k} className="flex justify-between text-sm py-2" style={{ borderBottom: "1px solid var(--border)" }}>
                            <span style={{ color: "var(--text-3)", fontSize: 12 }}>{k}</span>
                            <span className="font-mono text-xs" style={{ color: "var(--text-2)" }}>{v}</span>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}
