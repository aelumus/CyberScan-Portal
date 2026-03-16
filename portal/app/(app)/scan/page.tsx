"use client";
import { useState, useRef, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/components/AuthProvider";
import { Upload, X, Play, AlertTriangle, Cpu, Lock, ChevronRight } from "lucide-react";
import { buildApiUrl, createFormData, readApiError } from "@/lib/api";

export default function ScanPage() {
    const router = useRouter();
    const { authHeaders } = useAuth();
    const [file, setFile] = useState<File | null>(null);
    const [dragging, setDragging] = useState(false);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");
    const [progress, setProgress] = useState(0);
    const fileRef = useRef<HTMLInputElement>(null);
    const [useVt, setUseVt] = useState(false);
    const [threshold, setThreshold] = useState(0.4);
    const [mode, setMode] = useState("balanced");

    const handleDrop = useCallback((e: React.DragEvent) => {
        e.preventDefault(); setDragging(false);
        const f = e.dataTransfer.files[0];
        if (f && (f.name.endsWith(".exe") || f.name.endsWith(".dll"))) { setFile(f); setError(""); }
        else setError("Please upload a .exe or .dll file");
    }, []);

    const submit = async () => {
        if (!file) { setError("No file selected"); return; }
        setLoading(true); setError(""); setProgress(0);
        const interval = setInterval(() => setProgress(p => Math.min(p + Math.random() * 15, 85)), 300);
        const form = createFormData({
            file,
            use_vt: String(useVt),
            threshold: String(threshold),
            mode,
        });
        try {
            const res = await fetch(buildApiUrl("/api/scan"), {
                method: "POST", body: form, headers: authHeaders()
            });
            clearInterval(interval); setProgress(100);
            if (!res.ok) {
                throw new Error(await readApiError(res, `Scan failed (${res.status})`));
            }
            const data = await res.json();
            setTimeout(() => router.push(`/scans/${data.id}`), 300);
        } catch (e: unknown) {
            clearInterval(interval); setProgress(0);
            setError(e instanceof Error ? e.message : "Backend unreachable");
            setLoading(false);
        }
    };

    return (
        <div className="max-w-2xl mx-auto space-y-4">
            <div className="mb-6">
                <h1 className="text-2xl font-black" style={{ color: "var(--text)" }}>New Scan</h1>
                <p className="text-sm mt-1" style={{ color: "var(--text-3)" }}>Upload a Windows PE binary for ML-powered malware analysis</p>
            </div>

            {/* Upload Zone */}
            <div onClick={() => fileRef.current?.click()}
                onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
                onDragLeave={() => setDragging(false)}
                onDrop={handleDrop}
                className="relative rounded-2xl p-10 text-center cursor-pointer transition-all duration-300 overflow-hidden group"
                style={{
                    background: dragging ? "rgba(99,102,241,0.1)" : file ? "rgba(16,185,129,0.06)" : "var(--surface)",
                    border: dragging ? "2px dashed #6366f1" : file ? "2px dashed #10b981" : "2px dashed var(--border-2)",
                    backdropFilter: "blur(20px)",
                }}>
                <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none"
                    style={{ background: "radial-gradient(circle at 50% 50%, rgba(99,102,241,0.06), transparent 70%)" }} />
                <input ref={fileRef} type="file" accept=".exe,.dll" className="hidden"
                    onChange={(e) => { const f = e.target.files?.[0]; if (f) { setFile(f); setError(""); } }} />
                {file ? (
                    <div className="space-y-3">
                        <div className="w-14 h-14 mx-auto rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
                            <span className="text-2xl">🛡️</span>
                        </div>
                        <div className="font-bold text-lg" style={{ color: "var(--text)" }}>{file.name}</div>
                        <div className="text-sm" style={{ color: "var(--text-3)" }}>{(file.size / 1024).toFixed(1)} KB · Windows PE</div>
                        <button onClick={(e) => { e.stopPropagation(); setFile(null); }}
                            className="inline-flex items-center gap-1 text-xs text-red-400 hover:text-red-500 transition-colors mt-1">
                            <X size={12} /> Remove file
                        </button>
                    </div>
                ) : (
                    <>
                        <div className="w-16 h-16 mx-auto rounded-2xl flex items-center justify-center mb-4 group-hover:scale-110 transition-transform duration-300"
                            style={{ background: "var(--accent-bg)", border: "1px solid var(--accent-brd)" }}>
                            <Upload size={28} style={{ color: "var(--accent)" }} />
                        </div>
                        <p className="font-semibold" style={{ color: "var(--text)" }}>Drag & drop your binary here</p>
                        <p className="text-sm mt-1" style={{ color: "var(--text-3)" }}>
                            or click to browse · <span className="font-mono" style={{ color: "var(--accent)" }}>.exe</span> and <span className="font-mono" style={{ color: "var(--accent)" }}>.dll</span> supported
                        </p>
                        <p className="text-xs mt-3" style={{ color: "var(--text-3)", opacity: 0.6 }}>x86 / x64 PE files only</p>
                    </>
                )}
            </div>

            {/* Progress */}
            {loading && (
                <div className="glass rounded-xl p-4">
                    <div className="flex items-center justify-between text-xs mb-2">
                        <span style={{ color: "var(--text-2)" }}>Analyzing binary…</span>
                        <span className="font-mono" style={{ color: "var(--accent)" }}>{Math.round(progress)}%</span>
                    </div>
                    <div className="h-1.5 rounded-full overflow-hidden" style={{ background: "var(--border)" }}>
                        <div className="h-full rounded-full transition-all duration-300"
                            style={{ width: `${progress}%`, background: "linear-gradient(90deg,#4f46e5,#7c3aed,#ec4899)" }} />
                    </div>
                    <div className="flex gap-2 mt-3 text-xs flex-wrap" style={{ color: "var(--text-3)" }}>
                        {["Parsing PE", "Extracting 54 features", "Running RF · XGB · LGB", "Computing verdict"].map((s, i) => (
                            <span key={s} className="flex items-center gap-1" style={{ color: progress > i * 25 ? "var(--accent)" : "var(--text-3)" }}>
                                {progress > i * 25 ? "✓" : "○"} {s}
                            </span>
                        ))}
                    </div>
                </div>
            )}

            {/* Error */}
            {error && (
                <div className="flex items-start gap-3 rounded-xl px-4 py-3 text-sm"
                    style={{ background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.2)" }}>
                    <AlertTriangle size={16} className="text-red-400 mt-0.5 shrink-0" />
                    <span className="text-red-400">{error}</span>
                </div>
            )}

            {/* Models info */}
            <div className="glass rounded-2xl px-5 py-4 flex items-center gap-4">
                <div className="w-10 h-10 rounded-xl flex items-center justify-center" style={{ background: "var(--accent-bg)" }}>
                    <Cpu size={18} style={{ color: "var(--accent)" }} />
                </div>
                <div className="flex-1">
                    <div className="text-sm font-semibold" style={{ color: "var(--text)" }}>DS1 — PE Headers · 3 Models</div>
                    <div className="text-xs mt-0.5" style={{ color: "var(--text-3)" }}>Random Forest · XGBoost · LightGBM — ensemble vote</div>
                </div>
                <div className="flex gap-2">
                    {["RF", "XGB", "LGB"].map(m => (
                        <span key={m} className="text-xs px-2 py-0.5 rounded-full font-mono font-semibold"
                            style={{ background: "var(--accent-bg)", color: "var(--accent)", border: "1px solid var(--accent-brd)" }}>{m}</span>
                    ))}
                </div>
            </div>

            {/* Options */}
            <div className="glass rounded-2xl p-5 space-y-5">
                <h3 className="text-sm font-bold" style={{ color: "var(--text)" }}>Analysis Configuration</h3>

                {/* VT toggle */}
                <div className="flex items-center justify-between">
                    <div>
                        <div className="text-sm font-medium flex items-center gap-2" style={{ color: "var(--text)" }}>
                            <Lock size={13} style={{ color: "var(--text-3)" }} /> VirusTotal Lookup
                        </div>
                        <div className="text-xs mt-0.5" style={{ color: "var(--text-3)" }}>Cross-check with cloud threat intelligence (~15s extra)</div>
                    </div>
                    <button onClick={() => setUseVt(!useVt)}
                        className="w-11 h-6 rounded-full transition-all duration-300 relative"
                        style={{ background: useVt ? "linear-gradient(135deg,#4f46e5,#7c3aed)" : "var(--border-2)" }}>
                        <span className={`absolute top-1 w-4 h-4 bg-white rounded-full shadow-lg transition-all duration-300 ${useVt ? "left-6" : "left-1"}`} />
                    </button>
                </div>

                <div style={{ height: 1, background: "var(--border)" }} />

                {/* Threshold */}
                <div>
                    <div className="flex justify-between items-center mb-3">
                        <label className="text-xs font-semibold uppercase tracking-wide" style={{ color: "var(--text-3)" }}>Detection Threshold</label>
                        <span className="text-sm font-bold font-mono" style={{ color: "var(--accent)" }}>{threshold.toFixed(2)}</span>
                    </div>
                    <input type="range" min={0.1} max={0.9} step={0.05} value={threshold}
                        onChange={(e) => setThreshold(Number(e.target.value))} className="w-full h-1.5 accent-indigo-500" />
                    <div className="flex justify-between text-xs mt-1" style={{ color: "var(--text-3)" }}>
                        <span>0.1 Sensitive</span><span>0.5 Balanced</span><span>0.9 Strict</span>
                    </div>
                    <div className="mt-3 px-3 py-1.5 rounded-xl text-xs inline-block"
                        style={{ background: "var(--accent-bg)", color: "var(--accent)", border: "1px solid var(--accent-brd)" }}>
                        💡 Recommended: 0.35–0.45 for best real-world accuracy
                    </div>
                </div>

                <div style={{ height: 1, background: "var(--border)" }} />

                {/* Mode */}
                <div>
                    <label className="text-xs font-semibold uppercase tracking-wide mb-3 block" style={{ color: "var(--text-3)" }}>Detection Mode</label>
                    <div className="flex gap-2">
                        {[
                            { id: "conservative", label: "Conservative", desc: "−0.10", color: "#10b981", glw: "#10b981" },
                            { id: "balanced", label: "Balanced", desc: "default", color: "#818cf8", glw: "#4f46e5" },
                            { id: "aggressive", label: "Aggressive", desc: "+0.15", color: "#f87171", glw: "#ef4444" },
                        ].map((m) => (
                            <button key={m.id} onClick={() => setMode(m.id)}
                                className="flex-1 py-2.5 rounded-xl text-xs font-semibold transition-all duration-200"
                                style={mode === m.id
                                    ? { background: `${m.glw}12`, border: `1px solid ${m.glw}35`, color: m.color }
                                    : { background: "var(--surface)", border: "1px solid var(--border)", color: "var(--text-3)" }}>
                                {m.label}
                                <div className="text-xs mt-0.5 opacity-60 font-normal">{m.desc}</div>
                            </button>
                        ))}
                    </div>
                </div>
            </div>

            {/* Submit */}
            <button onClick={submit} disabled={loading || !file}
                className="w-full flex items-center justify-center gap-2 font-bold py-4 rounded-2xl transition-all duration-300 disabled:opacity-40 disabled:cursor-not-allowed hover:scale-[1.02] text-white"
                style={{ background: "linear-gradient(135deg,#4f46e5,#7c3aed)" }}>
                {loading
                    ? <><span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Analyzing binary…</>
                    : <><Play size={16} /> Start Analysis <ChevronRight size={15} /></>}
            </button>
        </div>
    );
}
