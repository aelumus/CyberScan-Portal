"use client";
import { useState } from "react";
import { useScans } from "@/hooks/useScans";
import { VerdictBadge, RiskBadge, ScoreBar } from "@/components/Badges";
import type { ScanRecord } from "@/lib/types";
import { GitCompare, ChevronDown, Shield } from "lucide-react";

function ScanSelect({ selected, scans, onChange, label }: {
    selected: string; scans: ScanRecord[]; onChange: (id: string) => void; label: string;
}) {
    return (
        <div className="glass rounded-2xl p-5">
            <label className="text-xs font-bold uppercase tracking-widest mb-3 block" style={{ color: "var(--text-3)" }}>{label}</label>
            <div className="relative">
                <select value={selected} onChange={e => onChange(e.target.value)}
                    className="w-full rounded-xl px-4 py-3 text-sm appearance-none focus:outline-none focus:ring-2 focus:ring-indigo-500/30"
                    style={{ background: "var(--surface-2)", border: "1px solid var(--border)", color: "var(--text)" }}>
                    <option value="">— Select scan —</option>
                    {scans.map(s => (
                        <option key={s.id} value={s.id}>{s.filename} · {s.verdict} · {new Date(s.created_at).toLocaleDateString()}</option>
                    ))}
                </select>
                <ChevronDown size={14} className="absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: "var(--text-3)" }} />
            </div>
        </div>
    );
}

function ScanSummary({ scan }: { scan: ScanRecord }) {
    const mlResults = scan.ml_results ?? [];
    return (
        <div className="space-y-4">
            <div className="glass rounded-2xl p-5">
                <div className="flex items-center gap-3 mb-3 flex-wrap">
                    <VerdictBadge verdict={scan.verdict} />
                    {scan.risk_level && <RiskBadge level={scan.risk_level} />}
                </div>
                <div className="text-lg font-black truncate mb-1" style={{ color: "var(--text)" }}>{scan.filename}</div>
                <div className="text-xs font-mono mb-4" style={{ color: "var(--text-3)" }}>{(scan.sha256 ?? "").slice(0, 24)}…</div>
                <div className="space-y-2">
                    {[
                        ["Overall Score", `${Math.round((scan.score ?? 0) * 100)}%`],
                        ["Scan Time", `${scan.scan_time ?? 0}s`],
                        ["File Size", `${((scan.file_size ?? 0) / 1024).toFixed(0)} KB`],
                        ["Mode", scan.mode ?? "—"],
                        ["Threshold", String(scan.threshold ?? "—")],
                    ].map(([k, v]) => (
                        <div key={k} className="flex justify-between text-sm pb-2" style={{ borderBottom: "1px solid var(--border)" }}>
                            <span style={{ color: "var(--text-3)", fontSize: 12 }}>{k}</span>
                            <span className="font-mono text-xs font-semibold" style={{ color: "var(--text)" }}>{v}</span>
                        </div>
                    ))}
                </div>
            </div>
            {mlResults.length > 0 && (
                <div className="glass rounded-2xl p-5">
                    <h4 className="text-xs font-bold uppercase tracking-widest mb-4" style={{ color: "var(--text-3)" }}>Model Scores</h4>
                    <div className="space-y-3">
                        {mlResults.map(r => (
                            <div key={r.model_key ?? r.algo}>
                                <div className="flex items-center justify-between text-xs mb-1">
                                    <span className="font-mono" style={{ color: "var(--text-2)" }}>{r.name ?? r.algo}</span>
                                    <span className="font-bold" style={{ color: r.triggered ? "#f87171" : "#34d399" }}>{Math.round(r.score * 100)}%</span>
                                </div>
                                <ScoreBar score={r.score} />
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}

export default function ComparePage() {
    const { scans, loading } = useScans();
    const [leftId, setLeftId] = useState("");
    const [rightId, setRightId] = useState("");

    const leftScan = scans.find(s => s.id === leftId);
    const rightScan = scans.find(s => s.id === rightId);
    const bothSelected = Boolean(leftScan && rightScan);

    return (
        <div className="space-y-6 max-w-6xl mx-auto">
            <div>
                <h1 className="text-2xl font-black flex items-center gap-3" style={{ color: "var(--text)" }}>
                    <GitCompare size={24} style={{ color: "var(--accent)" }} /> Compare Scans
                </h1>
                <p className="text-sm mt-1" style={{ color: "var(--text-3)" }}>Side-by-side comparison of two scan results</p>
            </div>

            <div className="grid md:grid-cols-2 gap-4">
                <ScanSelect label="Scan A" selected={leftId} scans={scans} onChange={setLeftId} />
                <ScanSelect label="Scan B" selected={rightId} scans={scans} onChange={setRightId} />
            </div>

            {loading && (
                <div className="text-center py-10 text-sm" style={{ color: "var(--text-3)" }}>Loading scans…</div>
            )}

            {!loading && scans.length < 2 && (
                <div className="glass rounded-2xl p-10 flex flex-col items-center gap-3">
                    <Shield size={36} style={{ color: "var(--border-2)" }} />
                    <p className="text-sm" style={{ color: "var(--text-3)" }}>Need at least 2 scans to compare. Upload more files first.</p>
                </div>
            )}

            {bothSelected && leftScan && rightScan && (
                <>
                    <div className="grid md:grid-cols-2 gap-5">
                        <div>
                            <div className="text-xs font-bold uppercase tracking-widest mb-3 px-1" style={{ color: "var(--accent)" }}>Scan A</div>
                            <ScanSummary scan={leftScan} />
                        </div>
                        <div>
                            <div className="text-xs font-bold uppercase tracking-widest mb-3 px-1" style={{ color: "#c084fc" }}>Scan B</div>
                            <ScanSummary scan={rightScan} />
                        </div>
                    </div>

                    <div className="glass rounded-2xl p-5">
                        <h3 className="text-xs font-bold uppercase tracking-widest mb-5" style={{ color: "var(--text-3)" }}>Key Differences</h3>
                        <div className="space-y-3">
                            {[
                                { label: "Verdict", a: leftScan.verdict, b: rightScan.verdict, changed: leftScan.verdict !== rightScan.verdict },
                                { label: "Risk Level", a: leftScan.risk_level ?? "—", b: rightScan.risk_level ?? "—", changed: leftScan.risk_level !== rightScan.risk_level },
                                { label: "Score", a: `${Math.round((leftScan.score ?? 0) * 100)}%`, b: `${Math.round((rightScan.score ?? 0) * 100)}%`, changed: Math.abs((leftScan.score ?? 0) - (rightScan.score ?? 0)) > 0.05 },
                                { label: "Scan Time", a: `${leftScan.scan_time ?? 0}s`, b: `${rightScan.scan_time ?? 0}s`, changed: false },
                                { label: "File Size", a: `${((leftScan.file_size ?? 0) / 1024).toFixed(0)} KB`, b: `${((rightScan.file_size ?? 0) / 1024).toFixed(0)} KB`, changed: leftScan.file_size !== rightScan.file_size },
                            ].map(row => (
                                <div key={row.label} className="flex items-center gap-4 p-3 rounded-xl"
                                    style={{ background: row.changed ? "rgba(245,158,11,0.06)" : "var(--surface-2)", border: `1px solid ${row.changed ? "rgba(245,158,11,0.2)" : "var(--border)"}` }}>
                                    <span className="text-xs font-medium w-24 shrink-0" style={{ color: "var(--text-3)" }}>{row.label}</span>
                                    <span className="flex-1 text-center text-sm font-bold" style={{ color: "var(--accent)" }}>{row.a}</span>
                                    {row.changed ? <span className="text-amber-400 font-bold">⇄</span> : <span style={{ color: "var(--text-3)" }}>═</span>}
                                    <span className="flex-1 text-center text-sm font-bold" style={{ color: "#c084fc" }}>{row.b}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                </>
            )}

            {!bothSelected && !loading && scans.length >= 2 && (
                <div className="glass rounded-2xl p-10 flex flex-col items-center gap-3">
                    <GitCompare size={36} style={{ color: "var(--border-2)" }} />
                    <p className="text-sm" style={{ color: "var(--text-3)" }}>Select two scans above to compare them</p>
                </div>
            )}
        </div>
    );
}
