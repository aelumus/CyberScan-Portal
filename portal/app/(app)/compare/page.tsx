"use client";
import { useState } from "react";
import { VerdictBadge, ScoreBar } from "@/components/Badges";
import { GitCompare, Loader2, ArrowRight, RefreshCw } from "lucide-react";
import Link from "next/link";
import { useScans } from "@/hooks/useScans";
import type { FeatureImportance, ScanRecord, ScanModelResult } from "@/lib/types";

const MODEL_NAMES: Record<string, string> = {
    "ds1_rf": "Random Forest", "ds1_xgb": "XGBoost", "ds1_lgbm": "LightGBM"
};
const MODEL_COLORS: Record<string, string> = {
    "ds1_rf": "#818cf8", "ds1_xgb": "#fb923c", "ds1_lgbm": "#c084fc"
};

export default function ComparePage() {
    const [left, setLeft] = useState<string>("");
    const [right, setRight] = useState<string>("");
    const { scans, loading } = useScans();

    const leftScan = scans.find(s => s.id === left);
    const rightScan = scans.find(s => s.id === right);
    const canCompare = leftScan && rightScan;

    const getModelScore = (scan: ScanRecord, key: string) => {
        const r = scan.ml_results?.find((model: ScanModelResult) => model.model_key === key);
        return r ? Math.round(r.score * 100) : null;
    };

    const verdictColor = (v: string) => v === "Malicious" ? "#f87171" : v === "Suspicious" ? "#fbbf24" : "#34d399";

    return (
        <div className="space-y-6 max-w-6xl mx-auto">
            <div>
                <h1 className="text-2xl font-black flex items-center gap-3" style={{ color: "var(--text)" }}>
                    <GitCompare size={24} style={{ color: "var(--accent)" }} /> Compare Scans
                </h1>
                <p className="text-sm mt-1" style={{ color: "var(--text-3)" }}>Select two scans to compare side-by-side</p>
            </div>

            {/* Selectors */}
            <div className="grid md:grid-cols-2 gap-4">
                {[
                    { label: "Scan A", value: left, setter: setLeft, other: right },
                    { label: "Scan B", value: right, setter: setRight, other: left },
                ].map(({ label, value, setter, other }) => (
                    <div key={label}>
                        <label className="block text-xs font-semibold uppercase tracking-widest mb-2" style={{ color: "var(--text-3)" }}>{label}</label>
                        {loading ? (
                            <div className="glass rounded-xl p-3 text-sm" style={{ color: "var(--text-3)" }}>
                                <Loader2 size={14} className="animate-spin inline mr-2" />Loading…
                            </div>
                        ) : (
                            <select value={value} onChange={e => setter(e.target.value)}
                                className="w-full px-4 py-3 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/30"
                                style={{ background: "var(--surface)", border: "1px solid var(--border)", color: "var(--text)" }}>
                                <option value="">— Select scan —</option>
                                {scans.filter(s => s.id !== other).map(s => (
                                    <option key={s.id} value={s.id}>
                                        {s.filename} ({Math.round((s.score ?? 0) * 100)}% — {s.verdict})
                                    </option>
                                ))}
                            </select>
                        )}
                    </div>
                ))}
            </div>

            {/* Swap button */}
            {left && right && (
                <div className="flex justify-center">
                    <button onClick={() => { const tmp = left; setLeft(right); setRight(tmp); }}
                        className="flex items-center gap-2 text-xs px-4 py-2 rounded-xl transition-all"
                        style={{ background: "var(--accent-bg)", border: "1px solid var(--accent-brd)", color: "var(--accent)" }}>
                        <RefreshCw size={13} /> Swap A ↔ B
                    </button>
                </div>
            )}

            {!canCompare && (
                <div className="glass rounded-2xl p-16 flex flex-col items-center gap-4">
                    <GitCompare size={40} style={{ color: "var(--border-2)" }} />
                    <p className="text-sm" style={{ color: "var(--text-3)" }}>Select two scans above to start comparing</p>
                    {scans.length === 0 && !loading && (
                        <Link href="/scan" className="flex items-center gap-1 text-xs" style={{ color: "var(--accent)" }}>
                            Upload a file first <ArrowRight size={12} />
                        </Link>
                    )}
                </div>
            )}

            {canCompare && (
                <div className="space-y-5">
                    {/* Header cards */}
                    <div className="grid md:grid-cols-2 gap-4">
                        {[leftScan, rightScan].map((scan, idx) => {
                            const vc = verdictColor(scan.verdict);
                            return (
                                <div key={idx} className="glass rounded-2xl p-5 relative overflow-hidden"
                                    style={{ boxShadow: `0 0 30px ${vc}15` }}>
                                    <div className="absolute top-3 right-3 text-xs font-bold px-2 py-0.5 rounded-full"
                                        style={{ background: "var(--accent-bg)", color: "var(--accent)", border: "1px solid var(--accent-brd)" }}>
                                        Scan {idx === 0 ? "A" : "B"}
                                    </div>
                                    <h3 className="font-bold text-sm truncate pr-12 mb-2" style={{ color: "var(--text)" }}>{scan.filename}</h3>
                                    <div className="flex items-center gap-2 mb-3"><VerdictBadge verdict={scan.verdict} /></div>
                                    <div className="text-3xl font-black mb-1" style={{ color: vc }}>{Math.round((scan.score ?? 0) * 100)}%</div>
                                    <div className="text-xs" style={{ color: "var(--text-3)" }}>malware score · {scan.scan_time}s scan time</div>
                                    <div className="mt-3 pt-3" style={{ borderTop: "1px solid var(--border)" }}>
                                        <ScoreBar score={scan.score ?? 0} />
                                    </div>
                                </div>
                            );
                        })}
                    </div>

                    {/* Score comparison table */}
                    <div className="glass rounded-2xl overflow-hidden">
                        <div className="px-5 py-3 text-xs font-bold uppercase tracking-widest"
                            style={{ borderBottom: "1px solid var(--border)", color: "var(--text-3)" }}>
                            Metric Comparison
                        </div>
                        <div className="divide-y" style={{ borderColor: "var(--border)" }}>
                            {[
                                ["Final Verdict", leftScan.verdict, rightScan.verdict, "verdict"],
                                ["Risk Level", leftScan.risk_level?.toUpperCase(), rightScan.risk_level?.toUpperCase(), "text"],
                                ["Overall Score", `${Math.round((leftScan.score ?? 0) * 100)}%`, `${Math.round((rightScan.score ?? 0) * 100)}%`, "score"],
                                ["File Size", `${Math.round((leftScan.file_size ?? 0) / 1024)} KB`, `${Math.round((rightScan.file_size ?? 0) / 1024)} KB`, "text"],
                                ["Scan Time", `${leftScan.scan_time}s`, `${rightScan.scan_time}s`, "text"],
                                ["PE Parse OK", leftScan.pe_parse_ok ? "Yes" : "No", rightScan.pe_parse_ok ? "Yes" : "No", "text"],
                                ...["ds1_rf", "ds1_xgb", "ds1_lgbm"].map(k => {
                                    const lv = getModelScore(leftScan, k);
                                    const rv = getModelScore(rightScan, k);
                                    return [MODEL_NAMES[k], lv !== null ? `${lv}%` : "—", rv !== null ? `${rv}%` : "—", "model", MODEL_COLORS[k]];
                                }),
                            ].map(([label, lv, rv, type, color]) => {
                                const isScore = type === "score" || type === "model";
                                const lNum = parseFloat(String(lv));
                                const rNum = parseFloat(String(rv));
                                const lWins = isScore && !isNaN(lNum) && !isNaN(rNum) && lNum < rNum;
                                const rWins = isScore && !isNaN(lNum) && !isNaN(rNum) && rNum < lNum;
                                return (
                                    <div key={String(label)} className="grid grid-cols-[1fr_1fr_1fr] gap-4 px-5 py-3 text-sm items-center">
                                        <span className="text-xs font-semibold" style={{ color: type === "model" ? String(color) : "var(--text-3)" }}>
                                            {label}
                                        </span>
                                        <span className="font-bold font-mono text-center" style={{
                                            color: type === "verdict" ? verdictColor(String(lv)) : lWins ? "#34d399" : "var(--text)"
                                        }}>{lv}</span>
                                        <span className="font-bold font-mono text-center" style={{
                                            color: type === "verdict" ? verdictColor(String(rv)) : rWins ? "#34d399" : "var(--text)"
                                        }}>{rv}</span>
                                    </div>
                                );
                            })}
                        </div>
                    </div>

                    {/* Feature comparison */}
                    {leftScan.features?.DS1 && rightScan.features?.DS1 && (
                        <div className="glass rounded-2xl p-5">
                            <h3 className="text-xs font-bold uppercase tracking-widest mb-5" style={{ color: "var(--text-3)" }}>
                                Top Feature Importances (RF)
                            </h3>
                            <div className="grid md:grid-cols-2 gap-6">
                                {[leftScan, rightScan].map((scan, idx) => (
                                    <div key={idx}>
                                        <div className="text-xs font-bold mb-3" style={{ color: "var(--accent)" }}>Scan {idx === 0 ? "A" : "B"} — {scan.filename.slice(0, 24)}</div>
                                        <div className="space-y-2.5">
                                            {(scan.features?.DS1 ?? []).slice(0, 8).map((f: FeatureImportance) => (
                                                <div key={f.name} className="flex items-center gap-3">
                                                    <div className="w-28 text-xs font-mono truncate" style={{ color: "var(--text-3)" }}>{f.name}</div>
                                                    <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: "var(--border)" }}>
                                                        <div className="h-full rounded-full" style={{ width: `${Math.min(f.importance * 1000, 100)}%`, background: idx === 0 ? "#818cf8" : "#fb923c" }} />
                                                    </div>
                                                    <span className="text-xs w-10 text-right font-mono" style={{ color: "var(--text-3)" }}>{(f.importance * 100).toFixed(1)}%</span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Links to full reports */}
                    <div className="grid md:grid-cols-2 gap-4">
                        {[leftScan, rightScan].map((scan, idx) => (
                            <Link key={idx} href={`/scans/${scan.id}`}
                                className="glass flex items-center justify-between p-4 rounded-xl transition-all hover:-translate-y-0.5 hover:shadow-lg group">
                                <div>
                                    <div className="text-xs font-bold mb-0.5" style={{ color: "var(--accent)" }}>Scan {idx === 0 ? "A" : "B"} — Full Report</div>
                                    <div className="text-sm font-medium" style={{ color: "var(--text)" }}>{scan.filename}</div>
                                </div>
                                <ArrowRight size={16} style={{ color: "var(--accent)" }} className="group-hover:translate-x-1 transition-transform" />
                            </Link>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}
