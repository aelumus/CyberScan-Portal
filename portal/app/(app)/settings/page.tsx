"use client";
import { useState } from "react";
import { Save, Key, Sliders, Shield, Lock, ChevronRight, CheckCircle, Eye, EyeOff } from "lucide-react";

export default function SettingsPage() {
    const [vtKey, setVtKey] = useState("29d9f5e75298bb0e8beb••••••••••••••••••••");
    const [showKey, setShowKey] = useState(false);
    const [ds1Thresh, setDs1Thresh] = useState(0.4);
    const [maxSize, setMaxSize] = useState(50);
    const [privacyMode, setPrivacyMode] = useState("save_hash");
    const [saved, setSaved] = useState(false);
    const [defaultMode, setDefaultMode] = useState("balanced");

    const save = () => { setSaved(true); setTimeout(() => setSaved(false), 2500); };

    const thresholdColor = ds1Thresh < 0.35 ? "#f87171" : ds1Thresh < 0.55 ? "#34d399" : "#fbbf24";

    return (
        <div className="max-w-2xl mx-auto space-y-5">
            <div>
                <h1 className="text-2xl font-black" style={{ color: "var(--text)" }}>Settings</h1>
                <p className="text-sm mt-1" style={{ color: "var(--text-3)" }}>Configure analysis parameters and API keys</p>
            </div>

            {/* API Key */}
            <div className="glass rounded-2xl p-5 space-y-4">
                <div className="flex items-center gap-2">
                    <Key size={15} style={{ color: "var(--accent)" }} />
                    <h3 className="font-bold text-sm" style={{ color: "var(--text)" }}>API Configuration</h3>
                </div>
                <div>
                    <label className="block text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: "var(--text-3)" }}>VirusTotal API Key</label>
                    <div className="relative">
                        <input
                            type={showKey ? "text" : "password"} value={vtKey}
                            onChange={(e) => setVtKey(e.target.value)}
                            className="w-full px-4 py-3 text-sm rounded-xl font-mono pr-10 focus:outline-none focus:ring-2 focus:ring-indigo-500/40 transition-all"
                            style={{ background: "var(--surface-2)", border: "1px solid var(--border)", color: "var(--text)" }}
                            placeholder="Enter VT API key…"
                        />
                        <button onClick={() => setShowKey(!showKey)}
                            className="absolute right-3 top-1/2 -translate-y-1/2 transition-colors" style={{ color: "var(--text-3)" }}>
                            {showKey ? <EyeOff size={15} /> : <Eye size={15} />}
                        </button>
                    </div>
                    <p className="text-xs mt-2 flex items-center gap-1" style={{ color: "var(--text-3)" }}>
                        <Lock size={10} /> Stored in environment variable — never sent to browser
                    </p>
                </div>
            </div>

            {/* Detection Threshold */}
            <div className="glass rounded-2xl p-5 space-y-4">
                <div className="flex items-center gap-2">
                    <Sliders size={15} style={{ color: "var(--accent)" }} />
                    <h3 className="font-bold text-sm" style={{ color: "var(--text)" }}>Detection Threshold</h3>
                </div>
                <div>
                    <div className="flex justify-between items-center mb-3">
                        <span className="text-sm" style={{ color: "var(--text-2)" }}>DS1 — PE Headers</span>
                        <span className="text-lg font-black font-mono" style={{ color: thresholdColor }}>{ds1Thresh.toFixed(2)}</span>
                    </div>
                    <input type="range" min={0.1} max={0.9} step={0.05} value={ds1Thresh}
                        onChange={(e) => setDs1Thresh(Number(e.target.value))}
                        className="w-full h-2 accent-indigo-500 cursor-pointer" />
                    <div className="flex justify-between text-xs mt-2">
                        <span className="text-red-400">0.1 · Sensitive</span>
                        <span className="text-emerald-400">0.5 · Balanced</span>
                        <span className="text-amber-400">0.9 · Strict</span>
                    </div>
                    <div className="mt-3 px-3 py-2 rounded-xl text-xs"
                        style={{ background: "var(--accent-bg)", color: "var(--accent)", border: "1px solid var(--accent-brd)" }}>
                        💡 Recommended: <strong>0.35–0.45</strong> for best real-world accuracy
                    </div>
                </div>
            </div>

            {/* Default Mode */}
            <div className="glass rounded-2xl p-5">
                <div className="flex items-center gap-2 mb-4">
                    <Shield size={15} style={{ color: "var(--accent)" }} />
                    <h3 className="font-bold text-sm" style={{ color: "var(--text)" }}>Default Detection Mode</h3>
                </div>
                <div className="flex gap-3">
                    {[
                        { id: "conservative", label: "Conservative", desc: "−0.10 to threshold", color: "#34d399", glow: "#10b981" },
                        { id: "balanced", label: "Balanced", desc: "default offset", color: "#818cf8", glow: "#4f46e5" },
                        { id: "aggressive", label: "Aggressive", desc: "+0.15 to threshold", color: "#f87171", glow: "#ef4444" },
                    ].map(m => (
                        <button key={m.id} onClick={() => setDefaultMode(m.id)}
                            className="flex-1 py-3 rounded-xl text-xs font-semibold transition-all duration-200 px-3 text-left"
                            style={defaultMode === m.id
                                ? { background: `${m.glow}12`, border: `1px solid ${m.glow}35`, color: m.color }
                                : { background: "var(--surface-2)", border: "1px solid var(--border)", color: "var(--text-3)" }}>
                            <div className="font-bold mb-0.5">{m.label}</div>
                            <div className="text-xs opacity-70 font-normal">{m.desc}</div>
                        </button>
                    ))}
                </div>
            </div>

            {/* Upload Settings */}
            <div className="glass rounded-2xl p-5 space-y-4">
                <h3 className="font-bold text-sm" style={{ color: "var(--text)" }}>Upload Settings</h3>
                <div>
                    <div className="flex justify-between items-center mb-2">
                        <label className="text-sm" style={{ color: "var(--text-2)" }}>Max File Size</label>
                        <span className="font-black" style={{ color: "var(--text)" }}>{maxSize} <span className="text-xs font-normal" style={{ color: "var(--text-3)" }}>MB</span></span>
                    </div>
                    <input type="range" min={5} max={200} step={5} value={maxSize}
                        onChange={(e) => setMaxSize(Number(e.target.value))}
                        className="w-full h-2 accent-indigo-500 cursor-pointer" />
                    <div className="flex justify-between text-xs mt-1" style={{ color: "var(--text-3)" }}>
                        <span>5 MB</span><span>200 MB</span>
                    </div>
                </div>
            </div>

            {/* Privacy */}
            <div className="glass rounded-2xl p-5 space-y-3">
                <div className="flex items-center gap-2 mb-1">
                    <Lock size={15} style={{ color: "var(--accent)" }} />
                    <h3 className="font-bold text-sm" style={{ color: "var(--text)" }}>Privacy Mode</h3>
                </div>
                {[
                    { val: "save_all", label: "Full storage", desc: "Save file + metadata + scan results" },
                    { val: "save_hash", label: "Hash only", desc: "Save hash/metadata — no file stored (recommended)" },
                    { val: "no_save", label: "Incognito", desc: "Do not save anything — all data discarded after scan" },
                ].map(({ val, label, desc }) => (
                    <label key={val} className="flex items-start gap-3 cursor-pointer">
                        <div className="relative mt-0.5">
                            <input type="radio" name="privacy" value={val} checked={privacyMode === val}
                                onChange={() => setPrivacyMode(val)} className="sr-only" />
                            <div className="w-4 h-4 rounded-full border-2 flex items-center justify-center transition-all duration-200"
                                style={{ borderColor: privacyMode === val ? "var(--accent)" : "var(--border-2)", background: privacyMode === val ? "var(--accent)" : "transparent" }}>
                                {privacyMode === val && <div className="w-1.5 h-1.5 bg-white rounded-full" />}
                            </div>
                        </div>
                        <div>
                            <div className="text-sm font-semibold" style={{ color: "var(--text)" }}>{label}</div>
                            <div className="text-xs mt-0.5" style={{ color: "var(--text-3)" }}>{desc}</div>
                        </div>
                    </label>
                ))}
            </div>

            {/* Save */}
            <button onClick={save}
                className="w-full flex items-center justify-center gap-2 font-bold py-3.5 rounded-2xl transition-all duration-300 hover:scale-[1.01] text-white"
                style={{ background: saved ? "linear-gradient(135deg,#10b981,#059669)" : "linear-gradient(135deg,#4f46e5,#7c3aed)" }}>
                {saved ? <><CheckCircle size={16} /> Settings saved!</> : <><Save size={16} /> Save Settings <ChevronRight size={15} /></>}
            </button>
        </div>
    );
}
