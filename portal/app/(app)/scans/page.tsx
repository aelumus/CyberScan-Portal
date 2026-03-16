"use client";
import Link from "next/link";
import { useState } from "react";
import { VerdictBadge, ScoreBar } from "@/components/Badges";
import { Search, Loader2, ArrowUpRight, Shield, Zap } from "lucide-react";
import { useScans } from "@/hooks/useScans";

export default function ScansPage() {
    const [search, setSearch] = useState("");
    const [filter, setFilter] = useState("All");
    const { scans, loading } = useScans();

    const filtered = scans.filter(s => {
        const matchSearch = s.filename.toLowerCase().includes(search.toLowerCase()) || (s.sha256 ?? "").includes(search);
        const matchFilter = filter === "All" || s.verdict === filter;
        return matchSearch && matchFilter;
    });

    const stats = {
        All: scans.length,
        Malicious: scans.filter(s => s.verdict === "Malicious").length,
        Suspicious: scans.filter(s => s.verdict === "Suspicious").length,
        Benign: scans.filter(s => s.verdict === "Benign").length,
    };

    const filterColors: Record<string, string> = {
        All: "#818cf8", Malicious: "#f87171", Suspicious: "#fbbf24", Benign: "#34d399",
    };

    return (
        <div className="space-y-5 max-w-6xl mx-auto">
            {/* Header */}
            <div className="flex items-center justify-between flex-wrap gap-3">
                <div>
                    <h1 className="text-2xl font-black" style={{ color: "var(--text)" }}>Scan History</h1>
                    <p className="text-sm mt-1" style={{ color: "var(--text-3)" }}>{scans.length} scans this session</p>
                </div>
                <Link href="/scan"
                    className="flex items-center gap-2 px-5 py-2.5 rounded-xl font-semibold text-white text-sm transition-all duration-200 hover:scale-105"
                    style={{ background: "linear-gradient(135deg,#4f46e5,#7c3aed)" }}>
                    <Zap size={15} /> New Scan
                </Link>
            </div>

            {/* Filter pills */}
            <div className="flex gap-3 flex-wrap">
                {(["All", "Malicious", "Suspicious", "Benign"] as const).map(v => {
                    const c = filterColors[v];
                    const active = filter === v;
                    return (
                        <button key={v} onClick={() => setFilter(v)}
                            className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all duration-200"
                            style={active
                                ? { background: `${c}12`, border: `1px solid ${c}35`, color: c }
                                : { background: "var(--surface)", border: "1px solid var(--border)", color: "var(--text-3)" }}>
                            <span style={{ color: c }}>{stats[v]}</span> {v}
                        </button>
                    );
                })}
            </div>

            {/* Search */}
            <div className="relative">
                <Search size={15} className="absolute left-4 top-1/2 -translate-y-1/2" style={{ color: "var(--text-3)" }} />
                <input type="text" placeholder="Search by filename or SHA256 hash…" value={search}
                    onChange={e => setSearch(e.target.value)}
                    className="w-full pl-10 pr-4 py-3 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/30 transition-all"
                    style={{ background: "var(--surface)", border: "1px solid var(--border)", color: "var(--text)" }}
                />
            </div>

            {/* Table */}
            <div className="glass rounded-2xl overflow-x-auto">
                <div className="min-w-[700px]">
                    {/* Header */}
                    <div className="grid grid-cols-[1fr_150px_100px_120px_60px] gap-4 px-5 py-3 text-xs font-semibold uppercase tracking-widest"
                        style={{ borderBottom: "1px solid var(--border)", color: "var(--text-3)" }}>
                        <span>Filename</span>
                        <span>SHA256</span>
                        <span>Verdict</span>
                        <span>Score</span>
                        <span></span>
                    </div>

                    {loading && (
                        <div className="flex items-center justify-center py-16 gap-2" style={{ color: "var(--text-3)" }}>
                            <Loader2 size={16} className="animate-spin" style={{ color: "var(--accent)" }} /> Loading scan history…
                        </div>
                    )}

                    {!loading && filtered.length === 0 && (
                        <div className="flex flex-col items-center justify-center py-16 gap-3">
                            <Shield size={32} style={{ color: "var(--border-2)" }} />
                            <p className="text-sm" style={{ color: "var(--text-3)" }}>
                                {scans.length === 0 ? "No scans yet" : "No matching scans"}
                            </p>
                            {scans.length === 0 && (
                                <Link href="/scan" className="text-xs flex items-center gap-1" style={{ color: "var(--accent)" }}>
                                    Upload a file to start <ArrowUpRight size={12} />
                                </Link>
                            )}
                        </div>
                    )}

                    <div className="divide-y" style={{ borderColor: "var(--border)" }}>
                        {filtered.map(scan => (
                            <div key={scan.id} className="grid grid-cols-[1fr_150px_100px_120px_60px] gap-4 px-5 py-3.5 transition-all items-center group cursor-pointer"
                                style={{ ["--hover-bg" as string]: "var(--surface-2)" }}
                                onMouseEnter={e => (e.currentTarget.style.background = "var(--surface-2)")}
                                onMouseLeave={e => (e.currentTarget.style.background = "")}>
                                <div>
                                    <div className="font-medium text-sm truncate pr-4" style={{ color: "var(--text)" }}>{scan.filename}</div>
                                    <div className="text-xs mt-0.5" style={{ color: "var(--text-3)" }}>
                                        {scan.created_at ? new Date(scan.created_at).toLocaleString("ru-RU", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" }) : "—"}
                                    </div>
                                </div>
                                <span className="font-mono text-xs truncate" style={{ color: "var(--text-3)" }}>{(scan.sha256 ?? "").slice(0, 16)}…</span>
                                <span><VerdictBadge verdict={scan.verdict} /></span>
                                <span><ScoreBar score={scan.score} /></span>
                                <Link href={`/scans/${scan.id}`}
                                    className="flex items-center gap-1 text-xs font-medium opacity-100 sm:opacity-0 group-hover:opacity-100 transition-all"
                                    style={{ color: "var(--accent)" }}>
                                    Open <ArrowUpRight size={11} />
                                </Link>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
}
