"use client";
import { useState, useEffect, useRef, useCallback } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { useAuth } from "@/components/AuthProvider";
import { VerdictBadge, RiskBadge } from "@/components/Badges";
import { buildApiUrl } from "@/lib/api";
import type {
    FeatureImportance,
    ScanModelResult,
    ScanRecord,
    ShapValue,
    StringsAnalysis,
    YaraMatch,
    YaraResponse,
} from "@/lib/types";
import {
    BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
    ReferenceLine, Cell
} from "recharts";
import { ArrowLeft, FileJson, Download, Loader2, Shield, AlertTriangle, CheckCircle, Bug, Zap, Code2 } from "lucide-react";

type ShapResponse = {
    shap_values: ShapValue[];
    expected_value: number;
};

const TABS = ["Summary", "Models", "Features", "Strings", "YARA", "Artifacts"] as const;

const MODEL_COLORS: Record<string, string> = {
    "Random Forest": "#818cf8", "RF": "#818cf8",
    "XGBoost": "#fb923c", "XGB": "#fb923c",
    "LightGBM": "#c084fc", "LGB": "#c084fc",
};

const STEP_LABELS: Record<string, string> = {
    queued: "In queue…",
    starting: "Starting analysis…",
    extracting_features: "Extracting 54 PE features…",
    running_models: "Running RF · XGB · LGB models…",
    computing_verdict: "Computing verdict…",
    done: "Analysis complete",
    error: "Analysis failed",
};

const STEP_ORDER = ["queued", "starting", "extracting_features", "running_models", "computing_verdict", "done"];

export default function ScanDetailPage() {
    const { id } = useParams<{ id: string }>();
    const { authHeaders } = useAuth();
    const [tab, setTab] = useState<(typeof TABS)[number]>("Summary");
    const [scan, setScan] = useState<ScanRecord | null>(null);
    const [shapData, setShapData] = useState<ShapResponse | null>(null);
    const [stringsData, setStringsData] = useState<StringsAnalysis | null>(null);
    const [shapLoading, setShapLoading] = useState(false);
    const [stringsLoading, setStringsLoading] = useState(false);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

    // YARA State
    const [yaraRule, setYaraRule] = useState("rule ExampleRule {\n  strings:\n    $a = \"http\"\n  condition:\n    $a\n}");
    const [yaraLoading, setYaraLoading] = useState(false);
    const [yaraResults, setYaraResults] = useState<YaraResponse | null>(null);

    const fetchScan = useCallback(() => {
        if (!id) return;
        fetch(buildApiUrl(`/api/scans/${id}`), { headers: authHeaders() })
            .then(r => { if (!r.ok) throw new Error(`Scan not found (${r.status})`); return r.json(); })
            .then((data: ScanRecord) => {
                setScan(data);
                setLoading(false);
                if (data.strings_analysis) setStringsData(data.strings_analysis);

                const status = data.status ?? "completed";
                if (status === "completed" || status === "failed") {
                    if (pollRef.current) {
                        clearInterval(pollRef.current);
                        pollRef.current = null;
                    }
                }
            })
            .catch(e => { setError(e.message); setLoading(false); });
    }, [id, authHeaders]);

    useEffect(() => {
        fetchScan();
    }, [fetchScan]);

    useEffect(() => {
        if (!scan) return;
        const status = scan.status ?? "completed";
        if ((status === "pending" || status === "processing") && !pollRef.current) {
            pollRef.current = setInterval(fetchScan, 2000);
        }
        return () => {
            if (pollRef.current) {
                clearInterval(pollRef.current);
                pollRef.current = null;
            }
        };
    }, [scan?.status, fetchScan]);

    useEffect(() => {
        if (tab === "Features" && scan && !shapData && !shapLoading) {
            setShapLoading(true);
            fetch(buildApiUrl(`/api/scans/${id}/shap`), { headers: authHeaders() })
                .then(r => r.json())
                .then((data: ShapResponse) => setShapData(data))
                .catch(() => setShapData(null))
                .finally(() => setShapLoading(false));
        }
        if (tab === "Strings" && scan && !stringsData && !stringsLoading) {
            setStringsLoading(true);
            fetch(buildApiUrl(`/api/scans/${id}/strings`), { headers: authHeaders() })
                .then(r => r.json())
                .then((data: StringsAnalysis) => setStringsData(data))
                .catch(() => setStringsData(null))
                .finally(() => setStringsLoading(false));
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [tab, scan, authHeaders]);

    const handleDownloadPDF = async () => {
        try {
            const res = await fetch(buildApiUrl(`/api/scans/${id}/pdf`), { headers: authHeaders() });
            if (!res.ok) throw new Error("Failed to generate PDF");
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            // The backend already sets the filename in Content-Disposition, but we can provide a fallback
            a.download = `cyberscan_${scan?.filename}_${id}.pdf`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        } catch (e) {
            console.error("PDF download failed:", e);
        }
    };

    const handleRunYara = async () => {
        if (!yaraRule.trim()) return;
        setYaraLoading(true);
        setYaraResults(null);
        try {
            const res = await fetch(buildApiUrl(`/api/scans/${id}/yara`), {
                method: "POST",
                headers: { ...authHeaders(), "Content-Type": "application/json" },
                body: JSON.stringify({ rule: yaraRule })
            });
            const data = await res.json() as YaraResponse;
            setYaraResults(data);
        } catch (e) {
            setYaraResults({ success: false, error: String(e), matches: [] });
        } finally {
            setYaraLoading(false);
        }
    };

    if (loading) return (
        <div className="flex items-center justify-center h-64 gap-3" style={{ color: "var(--text-3)" }}>
            <Loader2 size={22} className="animate-spin" style={{ color: "var(--accent)" }} /> Loading scan data…
        </div>
    );

    if (error || !scan) return (
        <div className="space-y-4 max-w-5xl">
            <Link href="/scans" className="flex items-center gap-2 text-sm" style={{ color: "var(--text-3)" }}>
                <ArrowLeft size={16} /> Back to History
            </Link>
            <div className="rounded-xl px-5 py-4 text-sm flex items-center gap-3"
                style={{ background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.18)", color: "#f87171" }}>
                <AlertTriangle size={16} /> {error || "Scan not found"}
            </div>
        </div>
    );

    const scanStatus = scan.status ?? "completed";
    const isProcessing = scanStatus === "pending" || scanStatus === "processing";

    if (isProcessing) {
        const step = scan.progress_step ?? "queued";
        const stepIdx = STEP_ORDER.indexOf(step);
        const progressPct = Math.max(5, Math.min(90, ((stepIdx + 1) / STEP_ORDER.length) * 100));

        return (
            <div className="space-y-5 max-w-2xl mx-auto">
                <Link href="/scans" className="flex items-center gap-2 text-sm transition-colors" style={{ color: "var(--text-3)" }}>
                    <ArrowLeft size={16} /> Back to History
                </Link>

                <div className="glass rounded-2xl p-8 text-center space-y-6">
                    <div className="w-16 h-16 mx-auto rounded-full flex items-center justify-center"
                        style={{ background: "var(--accent-bg)", border: "1px solid var(--accent-brd)" }}>
                        <Loader2 size={28} className="animate-spin" style={{ color: "var(--accent)" }} />
                    </div>

                    <div>
                        <h2 className="text-xl font-black" style={{ color: "var(--text)" }}>Analyzing {scan.filename}</h2>
                        <p className="text-sm mt-1" style={{ color: "var(--text-3)" }}>
                            {STEP_LABELS[step] ?? step}
                        </p>
                    </div>

                    <div className="space-y-2">
                        <div className="h-2 rounded-full overflow-hidden" style={{ background: "var(--border)" }}>
                            <div className="h-full rounded-full transition-all duration-700"
                                style={{ width: `${progressPct}%`, background: "linear-gradient(90deg,#4f46e5,#7c3aed,#ec4899)" }} />
                        </div>
                        <div className="flex gap-3 justify-center flex-wrap">
                            {STEP_ORDER.slice(0, -1).map((s, i) => (
                                <span key={s} className="flex items-center gap-1 text-xs"
                                    style={{ color: i <= stepIdx ? "var(--accent)" : "var(--text-3)" }}>
                                    {i <= stepIdx ? "✓" : "○"} {STEP_LABELS[s]?.replace("…", "") ?? s}
                                </span>
                            ))}
                        </div>
                    </div>

                    <p className="text-xs" style={{ color: "var(--text-3)", opacity: 0.5 }}>
                        Auto-refreshing every 2 seconds
                    </p>
                </div>
            </div>
        );
    }

    if (scanStatus === "failed") {
        return (
            <div className="space-y-5 max-w-2xl mx-auto">
                <Link href="/scans" className="flex items-center gap-2 text-sm transition-colors" style={{ color: "var(--text-3)" }}>
                    <ArrowLeft size={16} /> Back to History
                </Link>
                <div className="glass rounded-2xl p-8 text-center space-y-4">
                    <div className="w-16 h-16 mx-auto rounded-full flex items-center justify-center"
                        style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.2)" }}>
                        <AlertTriangle size={28} className="text-red-400" />
                    </div>
                    <h2 className="text-xl font-black" style={{ color: "var(--text)" }}>Analysis Failed</h2>
                    <p className="text-sm" style={{ color: "var(--text-3)" }}>{scan.error ?? "Unknown error during processing"}</p>
                    <p className="text-xs font-mono" style={{ color: "var(--text-3)" }}>{scan.filename}</p>
                </div>
            </div>
        );
    }

    const mlResults: ScanModelResult[] = scan.ml_results ?? [];
    const topFeatures: FeatureImportance[] = scan.features?.DS1 ?? [];
    const verdictGlow = scan.verdict === "Malicious" ? "#ef4444" : scan.verdict === "Suspicious" ? "#f59e0b" : "#10b981";

    return (
        <div className="space-y-5 max-w-5xl">
            {/* Back + Actions */}
            <div className="flex items-center justify-between flex-wrap gap-3">
                <Link href="/scans" className="flex items-center gap-2 text-sm transition-colors" style={{ color: "var(--text-3)" }}>
                    <ArrowLeft size={16} /> Back to History
                </Link>
                <div className="flex gap-2">
                    <a href={buildApiUrl(`/api/scans/${id}`)} target="_blank" rel="noreferrer"
                        className="glass flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-xl transition-colors"
                        style={{ color: "var(--text-2)" }}>
                        <FileJson size={14} /> JSON
                    </a>
                    <button onClick={handleDownloadPDF}
                        className="flex items-center gap-2 px-4 py-2 text-xs font-bold rounded-xl transition-all hover:scale-105 text-white"
                        style={{ background: "linear-gradient(135deg,#4f46e5,#7c3aed)" }}>
                        <Download size={14} /> Download PDF
                    </button>
                </div>
            </div>

            {/* Header card */}
            <div className="glass rounded-2xl p-6 overflow-hidden relative"
                style={{ boxShadow: `0 0 60px ${verdictGlow}15` }}>
                <div className="absolute inset-0 pointer-events-none"
                    style={{ background: `radial-gradient(ellipse at 0% 0%, ${verdictGlow}08, transparent 60%)` }} />
                <div className="relative flex flex-wrap items-start gap-5">
                    <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-3 mb-3 flex-wrap">
                            <VerdictBadge verdict={scan.verdict} />
                            {scan.risk_level && <RiskBadge level={scan.risk_level} />}
                        </div>
                        <h2 className="text-xl font-black truncate" style={{ color: "var(--text)" }}>{scan.filename}</h2>
                        <p className="text-xs font-mono mt-1 break-all" style={{ color: "var(--text-3)" }}>{scan.sha256}</p>
                    </div>
                    <div className="flex gap-3">
                        {[
                            ["Score", `${Math.round((scan.score ?? 0) * 100)}%`, verdictGlow],
                            ["Scan Time", `${scan.scan_time ?? 0}s`, "#818cf8"],
                            ["File Size", `${((scan.file_size ?? 0) / 1024).toFixed(0)} KB`, "#38bdf8"],
                        ].map(([l, v, c]) => (
                            <div key={l} className="rounded-xl px-4 py-3 text-center min-w-[70px]" style={{ background: "var(--surface-2)" }}>
                                <div className="text-lg font-black" style={{ color: c }}>{v}</div>
                                <div className="text-xs mt-0.5" style={{ color: "var(--text-3)" }}>{l}</div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {/* Tabs */}
            <div className="flex gap-1 p-1 rounded-xl w-fit flex-wrap" style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
                {TABS.map(t => (
                    <button key={t} onClick={() => setTab(t)}
                        className="px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200"
                        style={tab === t
                            ? { background: "linear-gradient(135deg,rgba(79,70,229,0.3),rgba(124,58,237,0.2))", color: "var(--accent)", border: "1px solid var(--accent-brd)" }
                            : { color: "var(--text-3)", border: "1px solid transparent" }}>
                        {t}
                    </button>
                ))}
            </div>

            {/* ── SUMMARY ── */}
            {tab === "Summary" && (
                <div className="grid md:grid-cols-2 gap-5">
                    <div className="glass rounded-2xl p-5 space-y-3">
                        <h3 className="text-xs font-bold uppercase tracking-widest mb-4 flex items-center gap-2" style={{ color: "var(--text-3)" }}>
                            <Shield size={12} style={{ color: "var(--accent)" }} /> File Details
                        </h3>
                        {[
                            ["Filename", scan.filename],
                            ["SHA256", (scan.sha256 ?? "").slice(0, 20) + "…"],
                            ["MD5", scan.md5 ?? "—"],
                            ["Size", `${((scan.file_size ?? 0) / 1024).toFixed(0)} KB`],
                            ["Scan Date", scan.created_at ? new Date(scan.created_at).toLocaleString() : "—"],
                            ["Mode", scan.mode ?? "—"],
                            ["Threshold", scan.threshold ?? "—"],
                            ["PE Parse OK", scan.pe_parse_ok ? "✅ Yes" : "⚠️ No"],
                        ].map(([k, v]) => (
                            <div key={k} className="flex justify-between items-center text-sm pb-2" style={{ borderBottom: "1px solid var(--border)" }}>
                                <span className="text-xs" style={{ color: "var(--text-3)" }}>{k}</span>
                                <span className="font-medium font-mono text-xs text-right max-w-[55%] truncate" style={{ color: "var(--text)" }}>{String(v)}</span>
                            </div>
                        ))}
                    </div>

                    {scan.vt_result && !scan.vt_result.error ? (
                        <div className="glass rounded-2xl p-5">
                            <h3 className="text-xs font-bold uppercase tracking-widest mb-5" style={{ color: "var(--text-3)" }}>VirusTotal</h3>
                            <div className="text-center py-4">
                                <div className="text-5xl font-black mb-1"
                                    style={{ color: scan.vt_result.positives > 0 ? "#f87171" : "#34d399" }}>
                                    {scan.vt_result.positives}
                                </div>
                                <div className="text-sm" style={{ color: "var(--text-3)" }}>/ {scan.vt_result.total} vendors flagged</div>
                            </div>
                            <div className="h-2 rounded-full overflow-hidden mt-3" style={{ background: "var(--border)" }}>
                                <div className="h-full rounded-full"
                                    style={{ width: `${(scan.vt_result.positives / scan.vt_result.total) * 100}%`, background: scan.vt_result.positives > 0 ? "#ef4444" : "#10b981" }} />
                            </div>
                            {scan.vt_result.permalink && (
                                <a href={scan.vt_result.permalink} target="_blank" className="block text-center text-xs mt-4" style={{ color: "var(--accent)" }}>
                                    View on VirusTotal ↗
                                </a>
                            )}
                        </div>
                    ) : (
                        <div className="glass rounded-2xl p-5 flex flex-col items-center justify-center gap-3">
                            <Shield size={32} style={{ color: "var(--border-2)" }} />
                            <p className="text-sm" style={{ color: "var(--text-3)" }}>VirusTotal not used</p>
                        </div>
                    )}
                </div>
            )}

            {/* ── MODELS ── */}
            {tab === "Models" && (
                <div className="space-y-5">
                    <div className="glass rounded-2xl p-5">
                        <h3 className="text-xs font-bold uppercase tracking-widest mb-5" style={{ color: "var(--text-3)" }}>
                            ML Models · {mlResults.length} Results
                        </h3>
                        {mlResults.length === 0 ? (
                            <p className="text-sm" style={{ color: "var(--text-3)" }}>No model results</p>
                        ) : (
                            <div className="space-y-4">
                                {mlResults.map(r => {
                                    const modelLabel = r.name ?? r.algo ?? "Unknown";
                                    const col = MODEL_COLORS[modelLabel] ?? "#818cf8";
                                    return (
                                        <div key={r.model_key ?? r.algo} className="space-y-1.5">
                                            <div className="flex items-center justify-between">
                                                <span className="font-bold text-xs font-mono px-2 py-0.5 rounded-md"
                                                    style={{ background: `${col}12`, color: col }}>{modelLabel}</span>
                                                <div className="flex items-center gap-3">
                                                    <span className="font-black text-sm" style={{ color: col }}>{Math.round(r.score * 100)}%</span>
                                                    <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${r.triggered
                                                        ? "text-red-400 bg-red-500/10 border border-red-500/20"
                                                        : "text-emerald-400 bg-emerald-500/10 border border-emerald-500/20"}`}>
                                                        {r.triggered ? "Malicious" : "Benign"}
                                                    </span>
                                                </div>
                                            </div>
                                            <div className="h-2 rounded-full overflow-hidden" style={{ background: "var(--border)" }}>
                                                <div className="h-full rounded-full transition-all duration-700"
                                                    style={{ width: `${r.score * 100}%`, background: r.triggered ? "#ef4444" : `${col}cc` }} />
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        )}
                    </div>
                    {mlResults.length > 0 && (
                        <div className="glass rounded-2xl p-5">
                            <h3 className="text-xs font-bold uppercase tracking-widest mb-4" style={{ color: "var(--text-3)" }}>Score Comparison</h3>
                            <ResponsiveContainer width="100%" height={200}>
                                <BarChart data={mlResults.map(r => ({ algo: r.name ?? r.algo, score: Math.round(r.score * 100) }))}>
                                    <XAxis dataKey="algo" tick={{ fontSize: 11, fill: "var(--text-3)" }} axisLine={false} tickLine={false} />
                                    <YAxis domain={[0, 100]} tickFormatter={v => `${v}%`} tick={{ fontSize: 11, fill: "var(--text-3)" }} axisLine={false} tickLine={false} />
                                    <Tooltip contentStyle={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 10, fontSize: 11, color: "var(--text)" }}
                                        formatter={v => [`${v}%`, "Score"]} />
                                    <Bar dataKey="score" fill="#6366f1" radius={[6, 6, 0, 0]} />
                                </BarChart>
                            </ResponsiveContainer>
                        </div>
                    )}
                </div>
            )}

            {/* ── FEATURES + SHAP ── */}
            {tab === "Features" && (
                <div className="space-y-5">
                    {/* Feature Importances */}
                    <div className="glass rounded-2xl p-5">
                        <h3 className="text-xs font-bold uppercase tracking-widest mb-5" style={{ color: "var(--text-3)" }}>
                            RF Feature Importances
                        </h3>
                        {topFeatures.length === 0 ? (
                            <p className="text-sm" style={{ color: "var(--text-3)" }}>No feature data</p>
                        ) : (
                            <div className="space-y-3">
                                {topFeatures.map(f => (
                                    <div key={f.name} className="flex items-center gap-4">
                                        <div className="w-40 text-xs font-mono shrink-0" style={{ color: "var(--text-3)" }}>{f.name}</div>
                                        <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: "var(--border)" }}>
                                            <div className="h-full rounded-full" style={{ width: `${Math.min(f.importance * 1000, 100)}%`, background: "linear-gradient(90deg,#4f46e5,#7c3aed)" }} />
                                        </div>
                                        <span className="text-xs w-12 text-right font-mono" style={{ color: "var(--text-3)" }}>{(f.importance * 100).toFixed(1)}%</span>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>

                    {/* SHAP Waterfall */}
                    <div className="glass rounded-2xl p-5">
                        <h3 className="text-xs font-bold uppercase tracking-widest mb-2 flex items-center gap-2" style={{ color: "var(--text-3)" }}>
                            <Zap size={12} style={{ color: "var(--accent)" }} /> SHAP Values — Why This Verdict?
                        </h3>
                        <p className="text-xs mb-5" style={{ color: "var(--text-3)" }}>
                            Positive (red) → pushes toward Malicious · Negative (green) → pushes toward Benign
                        </p>
                        {shapLoading && (
                            <div className="flex items-center gap-2" style={{ color: "var(--text-3)" }}>
                                <Loader2 size={14} className="animate-spin" style={{ color: "var(--accent)" }} /> Computing SHAP values…
                            </div>
                        )}
                        {!shapLoading && shapData?.shap_values && (
                            <ResponsiveContainer width="100%" height={320}>
                                <BarChart
                                    data={[...shapData.shap_values].reverse()}
                                    layout="vertical"
                                    margin={{ left: 80, right: 60, top: 0, bottom: 0 }}>
                                    <XAxis type="number" tick={{ fontSize: 10, fill: "var(--text-3)" }} axisLine={false} tickLine={false}
                                        tickFormatter={v => v.toFixed(3)} />
                                    <YAxis type="category" dataKey="feature" tick={{ fontSize: 10, fill: "var(--text-3)" }} axisLine={false} tickLine={false} width={80} />
                                    <Tooltip
                                        contentStyle={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 10, fontSize: 11, color: "var(--text)" }}
                                        formatter={(v: unknown, _: unknown, payload: { payload?: ShapValue }) => [
                                            `SHAP: ${Number(v).toFixed(4)} (value: ${payload?.payload?.feature_value ?? "?"})`, ""
                                        ]}
                                    />
                                    <ReferenceLine x={0} stroke="var(--border-2)" />
                                    <Bar dataKey="shap_value" radius={[3, 3, 3, 3]}>
                                        {shapData.shap_values.slice().reverse().map((entry: ShapValue, idx: number) => (
                                            <Cell key={idx} fill={entry.shap_value >= 0 ? "#ef4444" : "#10b981"} />
                                        ))}
                                    </Bar>
                                </BarChart>
                            </ResponsiveContainer>
                        )}
                        {!shapLoading && !shapData && (
                            <p className="text-xs" style={{ color: "var(--text-3)" }}>SHAP values unavailable — RF model required</p>
                        )}
                    </div>
                </div>
            )}

            {/* ── STRINGS ── */}
            {tab === "Strings" && (
                <div className="space-y-5">
                    {stringsLoading && (
                        <div className="glass rounded-2xl p-8 flex items-center justify-center gap-2" style={{ color: "var(--text-3)" }}>
                            <Loader2 size={16} className="animate-spin" style={{ color: "var(--accent)" }} /> Scanning strings…
                        </div>
                    )}
                    {!stringsLoading && stringsData && (
                        <>
                            {/* Risk Score */}
                            <div className="glass rounded-2xl p-5">
                                <div className="flex items-center justify-between mb-3 flex-wrap gap-3">
                                    <h3 className="text-xs font-bold uppercase tracking-widest flex items-center gap-2" style={{ color: "var(--text-3)" }}>
                                        <Bug size={12} style={{ color: "var(--accent)" }} /> String Analysis Risk
                                    </h3>
                                    <span className="text-2xl font-black" style={{
                                        color: stringsData.risk_score >= 70 ? "#f87171" :
                                            stringsData.risk_score >= 40 ? "#fbbf24" : "#34d399"
                                    }}>{stringsData.risk_score}/100</span>
                                </div>
                                <div className="h-2 rounded-full overflow-hidden" style={{ background: "var(--border)" }}>
                                    <div className="h-full rounded-full transition-all duration-700"
                                        style={{
                                            width: `${stringsData.risk_score}%`,
                                            background: stringsData.risk_score >= 70 ? "#ef4444" :
                                                stringsData.risk_score >= 40 ? "#f59e0b" : "#10b981"
                                        }} />
                                </div>
                                <div className="grid grid-cols-3 gap-3 mt-4">
                                    {[
                                        ["Dangerous Imports", stringsData.summary?.dangerous_count ?? 0, "#f87171"],
                                        ["Suspicious Strings", stringsData.summary?.suspicious_count ?? 0, "#fbbf24"],
                                        ["Risk Level", (stringsData.summary?.risk_level ?? "low").toUpperCase(), "#818cf8"],
                                    ].map(([l, v, c]) => (
                                        <div key={String(l)} className="rounded-xl p-3 text-center" style={{ background: "var(--surface-2)" }}>
                                            <div className="font-black text-sm" style={{ color: String(c) }}>{String(v)}</div>
                                            <div className="text-xs mt-0.5" style={{ color: "var(--text-3)" }}>{String(l)}</div>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            {/* MITRE ATT&CK */}
                            {stringsData.mitre_techniques?.length > 0 && (
                                <div className="glass rounded-2xl p-5">
                                    <h3 className="text-xs font-bold uppercase tracking-widest mb-4 flex items-center gap-2" style={{ color: "var(--text-3)" }}>
                                        <Shield size={12} className="text-indigo-400" /> MITRE ATT&CK Techniques ({stringsData.mitre_techniques.length})
                                    </h3>
                                    <div className="flex flex-wrap gap-2">
                                        {stringsData.mitre_techniques.map((t: { id: string; name: string; url: string }) => (
                                            <a key={t.id} href={t.url} target="_blank" rel="noreferrer"
                                                className="px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-2 hover:opacity-80 transition-opacity"
                                                style={{ background: "rgba(129, 140, 248, 0.1)", color: "#818cf8", border: "1px solid rgba(129, 140, 248, 0.2)" }}>
                                                <span>{t.id}</span>
                                                <span className="opacity-75">|</span>
                                                <span>{t.name}</span>
                                            </a>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {/* Dangerous Imports */}
                            {stringsData.dangerous_imports?.length > 0 && (
                                <div className="glass rounded-2xl p-5">
                                    <h3 className="text-xs font-bold uppercase tracking-widest mb-4 flex items-center gap-2" style={{ color: "var(--text-3)" }}>
                                        <AlertTriangle size={12} className="text-red-400" /> Dangerous Imports ({stringsData.dangerous_imports.length})
                                    </h3>
                                    <div className="space-y-2">
                                        {stringsData.dangerous_imports.map((imp: { function: string; dll: string; severity: string }, i: number) => (
                                            <div key={i} className="flex items-center justify-between p-3 rounded-xl" style={{ background: "var(--surface-2)" }}>
                                                <div>
                                                    <span className="font-mono text-sm font-semibold" style={{ color: "var(--text)" }}>{imp.function}</span>
                                                    <span className="text-xs ml-2" style={{ color: "var(--text-3)" }}>{imp.dll}</span>
                                                </div>
                                                <span className={`text-xs px-2 py-0.5 rounded-full font-semibold ${imp.severity === "high"
                                                    ? "text-red-400 bg-red-500/10 border border-red-500/20"
                                                    : "text-amber-400 bg-amber-500/10 border border-amber-500/20"}`}>
                                                    {imp.severity}
                                                </span>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {/* Suspicious Strings */}
                            {stringsData.suspicious_strings?.length > 0 && (
                                <div className="glass rounded-2xl p-5">
                                    <h3 className="text-xs font-bold uppercase tracking-widest mb-4" style={{ color: "var(--text-3)" }}>
                                        Suspicious Strings ({stringsData.suspicious_strings.length})
                                    </h3>
                                    <div className="space-y-2">
                                        {stringsData.suspicious_strings.map((s: { string: string; type: string }, i: number) => (
                                            <div key={i} className="p-3 rounded-xl" style={{ background: "var(--surface-2)" }}>
                                                <div className="flex items-center justify-between mb-1">
                                                    <span className="text-xs px-2 py-0.5 rounded-full font-semibold"
                                                        style={{ background: "var(--accent-bg)", color: "var(--accent)", border: "1px solid var(--accent-brd)" }}>
                                                        {s.type}
                                                    </span>
                                                </div>
                                                <code className="text-xs break-all" style={{ color: "var(--text-2)" }}>{s.string}</code>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {stringsData.dangerous_imports?.length === 0 && stringsData.suspicious_strings?.length === 0 && (
                                <div className="glass rounded-2xl p-8 flex flex-col items-center gap-3">
                                    <CheckCircle size={32} className="text-emerald-400" />
                                    <p className="text-sm" style={{ color: "var(--text-3)" }}>No suspicious strings or dangerous imports found</p>
                                </div>
                            )}
                        </>
                    )}
                </div>
            )}

            {/* ── YARA ── */}
            {tab === "YARA" && (
                <div className="space-y-5">
                    <div className="glass rounded-2xl p-5">
                        <h3 className="text-xs font-bold uppercase tracking-widest mb-4 flex items-center gap-2" style={{ color: "var(--text-3)" }}>
                            <Code2 size={12} style={{ color: "var(--accent)" }} /> Custom YARA Rule Tester
                        </h3>
                        <p className="text-xs mb-4" style={{ color: "var(--text-3)" }}>
                            Write a custom YARA rule to scan the uploaded file <code>{scan.filename}</code> on the fly.
                        </p>
                        <textarea
                            value={yaraRule}
                            onChange={(e) => setYaraRule(e.target.value)}
                            className="w-full h-48 rounded-xl p-4 font-mono text-sm mb-4 focus:outline-none focus:ring-2"
                            style={{ background: "var(--surface-2)", color: "var(--text)", border: "1px solid var(--border)", outlineColor: "var(--accent)" }}
                            spellCheck={false}
                        />
                        <div className="flex items-center gap-4">
                            <button
                                onClick={handleRunYara}
                                disabled={yaraLoading || !yaraRule.trim()}
                                className="px-5 py-2.5 rounded-lg text-sm font-semibold flex items-center gap-2 transition-all hover:brightness-110 disabled:opacity-50"
                                style={{ background: "var(--accent)", color: "white" }}>
                                {yaraLoading ? <Loader2 size={16} className="animate-spin" /> : <Zap size={16} />}
                                {yaraLoading ? "Scanning..." : "Run YARA Rule"}
                            </button>
                        </div>
                    </div>

                    {yaraResults && (
                        <div className="glass rounded-2xl p-5">
                            <h3 className="text-xs font-bold uppercase tracking-widest mb-4" style={{ color: "var(--text-3)" }}>
                                Results
                            </h3>
                            {!yaraResults.success ? (
                                <div className="p-4 rounded-xl text-sm font-mono border" style={{ background: "rgba(239,68,68,0.1)", color: "#f87171", borderColor: "rgba(239,68,68,0.2)" }}>
                                    {yaraResults.error}
                                </div>
                            ) : yaraResults.matches.length === 0 ? (
                                <div className="p-4 rounded-xl text-sm font-medium border flex items-center gap-2" style={{ background: "rgba(16,185,129,0.1)", color: "#34d399", borderColor: "rgba(16,185,129,0.2)" }}>
                                    <CheckCircle size={16} /> No matches found.
                                </div>
                            ) : (
                                <div className="space-y-4">
                                    <div className="p-4 rounded-xl text-sm font-bold border flex items-center gap-2" style={{ background: "rgba(245,158,11,0.1)", color: "#fbbf24", borderColor: "rgba(245,158,11,0.2)" }}>
                                        <AlertTriangle size={16} /> Rule Matched!
                                    </div>
                                    {yaraResults.matches.map((m: YaraMatch, idx: number) => (
                                        <div key={idx} className="p-4 rounded-xl border" style={{ background: "var(--surface-2)", borderColor: "var(--border)" }}>
                                            <div className="font-mono text-lg font-bold mb-2" style={{ color: "var(--accent)" }}>{m.rule}</div>
                                            {m.strings?.length > 0 && (
                                                <div className="mt-4">
                                                    <div className="text-xs uppercase font-bold mb-2" style={{ color: "var(--text-3)" }}>Matched Strings:</div>
                                                    <div className="space-y-1">
                                                        {m.strings.map((str, sIdx: number) => (
                                                            <div key={sIdx} className="text-xs font-mono p-2 rounded bg-black/50 overflow-x-auto" style={{ color: "var(--text-2)" }}>
                                                                <span style={{ color: "var(--text-3)" }}>{str.identifier}</span> at 0x{str.offset.toString(16)}: {str.data}
                                                            </div>
                                                        ))}
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    )}
                </div>
            )}

            {/* ── ARTIFACTS ── */}
            {tab === "Artifacts" && (
                <div className="glass rounded-2xl p-5 space-y-3">
                    <h3 className="text-xs font-bold uppercase tracking-widest mb-4" style={{ color: "var(--text-3)" }}>Download Artifacts</h3>
                    <div className="flex items-center justify-between p-4 rounded-xl" style={{ border: "1px solid var(--border)" }}
                        onMouseEnter={e => (e.currentTarget.style.background = "var(--surface-2)")}
                        onMouseLeave={e => (e.currentTarget.style.background = "")}>
                        <div className="flex items-center gap-3">
                            <div className="w-9 h-9 rounded-lg flex items-center justify-center" style={{ background: "var(--accent-bg)" }}>
                                <FileJson size={18} style={{ color: "var(--accent)" }} />
                            </div>
                            <div>
                                <div className="font-semibold text-sm" style={{ color: "var(--text)" }}>JSON Report</div>
                                <div className="text-xs" style={{ color: "var(--text-3)" }}>Full scan data — all model scores, features, metadata</div>
                            </div>
                        </div>
                        <a href={buildApiUrl(`/api/scans/${id}`)} target="_blank" rel="noreferrer"
                            className="px-3 py-1.5 text-xs font-semibold rounded-lg"
                            style={{ background: "var(--accent-bg)", border: "1px solid var(--accent-brd)", color: "var(--accent)" }}>
                            Open ↗
                        </a>
                    </div>
                    <button onClick={handleDownloadPDF}
                        className="w-full flex items-center justify-between p-4 rounded-xl transition-all hover:-translate-y-0.5 hover:shadow-lg group"
                        style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
                        <div className="flex items-center gap-3">
                            <div className="p-2 rounded-lg" style={{ background: "var(--accent-bg)", color: "var(--accent)" }}>
                                <Download size={16} />
                            </div>
                            <div className="text-left">
                                <div className="text-sm font-bold" style={{ color: "var(--text)" }}>PDF Report</div>
                                <div className="text-xs" style={{ color: "var(--text-3)" }}>Detailed analysis summary</div>
                            </div>
                        </div>
                        <Download size={16} style={{ color: "var(--text-3)" }} className="group-hover:text-indigo-400 transition-colors" />
                    </button>
                </div>
            )}
        </div>
    );
}
