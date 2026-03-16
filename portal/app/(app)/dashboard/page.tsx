"use client";
import Link from "next/link";
import React, { useEffect, useRef, useState } from "react";
import { VerdictBadge, ScoreBar } from "@/components/Badges";
import { Activity, Clock, Cpu, ArrowUpRight, TrendingUp, AlertTriangle, CheckCircle, Zap } from "lucide-react";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";
import { useScans } from "@/hooks/useScans";
import type { ScanRecord } from "@/lib/types";

/* ─── CountUp animated number ─── */
function CountUp({ target, suffix = "", decimals = 0 }: { target: number; suffix?: string; decimals?: number }) {
    const [val, setVal] = useState(0);
    const ref = useRef<HTMLSpanElement>(null);
    useEffect(() => {
        if (target === 0) return;
        const obs = new IntersectionObserver(([e]) => {
            if (!e.isIntersecting) return;
            let start = 0;
            const step = target / 50;
            const t = setInterval(() => {
                start = Math.min(start + step, target);
                setVal(start);
                if (start >= target) clearInterval(t);
            }, 20);
            obs.disconnect();
        }, { threshold: 0.5 });
        if (ref.current) obs.observe(ref.current);
        return () => obs.disconnect();
    }, [target]);
    return <span ref={ref}>{val.toFixed(decimals)}{suffix}</span>;
}

const CHART_DATA = [
    { date: "Mar 5", scans: 28, malicious: 4 },
    { date: "Mar 6", scans: 35, malicious: 8 },
    { date: "Mar 7", scans: 22, malicious: 3 },
    { date: "Mar 8", scans: 47, malicious: 11 },
    { date: "Mar 9", scans: 31, malicious: 6 },
    { date: "Mar 10", scans: 55, malicious: 9 },
    { date: "Mar 11", scans: 41, malicious: 7 },
];

function StatCard({ label, value, icon: Icon, color, glow, sub, animTarget, suffix = "", decimals = 0 }: {
    label: string; value?: string; animTarget?: number; suffix?: string; decimals?: number;
    icon: React.ElementType; color: string; glow: string; sub?: string;
}) {
    return (
        <div className="glass group relative rounded-2xl p-5 overflow-hidden transition-all duration-300 hover:-translate-y-1"
            onMouseEnter={e => (e.currentTarget.style.boxShadow = `0 20px 50px ${glow}25`)}
            onMouseLeave={e => (e.currentTarget.style.boxShadow = "")}>
            <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none"
                style={{ background: `radial-gradient(circle at 0% 0%, ${glow}10, transparent 70%)` }} />
            <div className="flex items-start justify-between mb-3">
                <div className="w-10 h-10 rounded-xl flex items-center justify-center" style={{ background: `${glow}18` }}>
                    <Icon size={18} style={{ color }} />
                </div>
                <ArrowUpRight size={14} style={{ color: "var(--text-3)" }} />
            </div>
            <div className="text-2xl font-black mb-0.5" style={{ color: "var(--text)" }}>
                {animTarget !== undefined
                    ? <CountUp target={animTarget} suffix={suffix} decimals={decimals} />
                    : value}
            </div>
            <div className="text-xs font-medium" style={{ color: "var(--text-2)" }}>{label}</div>
            {sub && <div className="text-xs mt-0.5" style={{ color: "var(--text-3)" }}>{sub}</div>}
        </div>
    );
}

export default function DashboardPage() {
    const { scans } = useScans();

    const total = scans.length;
    const malicious = scans.filter(s => s.verdict === "Malicious").length;
    const totalScanTime = scans.reduce((sum, scan) => sum + Number(scan.scan_time ?? 0), 0);
    const averageScanTime = total > 0 ? totalScanTime / total : 0;
    const recent: ScanRecord[] = scans.slice(-5).reverse();

    return (
        <div className="space-y-6 max-w-6xl mx-auto">
            {/* Header */}
            <div className="flex items-center justify-between flex-wrap gap-3">
                <div>
                    <div className="flex items-center gap-2 mb-1">
                        <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                        <span className="text-xs text-emerald-500 font-medium">System Online</span>
                    </div>
                    <h1 className="text-2xl font-black" style={{ color: "var(--text)" }}>Security Dashboard</h1>
                    <p className="text-sm mt-1" style={{ color: "var(--text-3)" }}>Real-time malware detection analytics</p>
                </div>
                <Link href="/scan"
                    className="flex items-center gap-2 px-5 py-2.5 rounded-xl font-semibold text-white text-sm transition-all duration-200 hover:scale-105"
                    style={{ background: "linear-gradient(135deg,#4f46e5,#7c3aed)" }}>
                    <Zap size={15} /> New Scan
                </Link>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <StatCard label="Total Scans" animTarget={total} suffix="" icon={Activity} color="#818cf8" glow="#4f46e5" sub="this session" />
                <StatCard label="Malicious Rate"
                    animTarget={total > 0 ? parseFloat(((malicious / total) * 100).toFixed(1)) : 0}
                    suffix="%" decimals={1} icon={AlertTriangle} color="#f87171" glow="#ef4444" sub="of scanned files" />
                <StatCard label="Avg Scan Time"
                    animTarget={total > 0 ? parseFloat(averageScanTime.toFixed(1)) : 0}
                    suffix="s" decimals={1} icon={Clock} color="#fbbf24" glow="#f59e0b" sub="per file" />
                <StatCard label="Models Online" animTarget={3} suffix=" / 3" icon={Cpu} color="#34d399" glow="#10b981" sub="RF · XGB · LGB" />
            </div>

            {/* Chart */}
            <div className="glass rounded-2xl p-5">
                <div className="flex items-center justify-between mb-5">
                    <div>
                        <h2 className="text-sm font-bold" style={{ color: "var(--text)" }}>Scan Activity</h2>
                        <p className="text-xs mt-0.5" style={{ color: "var(--text-3)" }}>Last 7 days</p>
                    </div>
                    <TrendingUp size={16} className="text-indigo-400" />
                </div>
                <ResponsiveContainer width="100%" height={200}>
                    <AreaChart data={CHART_DATA}>
                        <defs>
                            <linearGradient id="gTotal" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3} />
                                <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                            </linearGradient>
                            <linearGradient id="gMal" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                                <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                            </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                        <XAxis dataKey="date" tick={{ fontSize: 11, fill: "var(--text-3)" }} axisLine={false} tickLine={false} />
                        <YAxis tick={{ fontSize: 11, fill: "var(--text-3)" }} axisLine={false} tickLine={false} />
                        <Tooltip contentStyle={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 12, fontSize: 12, color: "var(--text)" }} />
                        <Area type="monotone" dataKey="scans" stroke="#6366f1" strokeWidth={2} fill="url(#gTotal)" name="Total" />
                        <Area type="monotone" dataKey="malicious" stroke="#ef4444" strokeWidth={2} fill="url(#gMal)" name="Malicious" />
                    </AreaChart>
                </ResponsiveContainer>
            </div>

            {/* Recent Scans */}
            <div className="glass rounded-2xl overflow-hidden">
                <div className="flex items-center justify-between px-5 py-4" style={{ borderBottom: "1px solid var(--border)" }}>
                    <h2 className="text-sm font-bold" style={{ color: "var(--text)" }}>Latest Scans</h2>
                    <Link href="/scans" className="text-xs font-medium flex items-center gap-1" style={{ color: "var(--accent)" }}>
                        View all <ArrowUpRight size={12} />
                    </Link>
                </div>
                {recent.length === 0 ? (
                    <div className="px-5 py-10 text-center text-sm" style={{ color: "var(--text-3)" }}>
                        No scans yet — <Link href="/scan" style={{ color: "var(--accent)" }} className="hover:underline">upload a file</Link>
                    </div>
                ) : (
                    <div className="divide-y" style={{ borderColor: "var(--border)" }}>
                        {recent.map((scan) => (
                            <div key={scan.id} className="flex items-center gap-4 px-5 py-3 transition-colors group"
                                style={{ ["&:hover" as string]: { background: "var(--surface-2)" } }}>
                                <div className="flex-1 min-w-0">
                                    <div className="font-medium text-sm truncate" style={{ color: "var(--text)" }}>{scan.filename}</div>
                                    <div className="text-xs mt-0.5" style={{ color: "var(--text-3)" }}>{new Date(scan.created_at).toLocaleString()}</div>
                                </div>
                                <VerdictBadge verdict={scan.verdict} />
                                <div className="w-28 hidden sm:block"><ScoreBar score={scan.score} /></div>
                                <Link href={`/scans/${scan.id}`} className="text-xs font-medium opacity-0 group-hover:opacity-100 transition-opacity" style={{ color: "var(--accent)" }}>
                                    Open →
                                </Link>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* Model status */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                {[
                    { name: "Random Forest", abbr: "RF", color: "#818cf8", glow: "#4f46e5" },
                    { name: "XGBoost", abbr: "XGB", color: "#fb923c", glow: "#f97316" },
                    { name: "LightGBM", abbr: "LGB", color: "#c084fc", glow: "#a855f7" },
                ].map(m => (
                    <div key={m.name} className="glass rounded-2xl p-4 flex items-center gap-3">
                        <div className="w-8 h-8 rounded-lg flex items-center justify-center text-xs font-bold" style={{ background: `${m.glow}18`, color: m.color }}>
                            {m.abbr}
                        </div>
                        <div className="flex-1 min-w-0">
                            <div className="text-xs font-semibold truncate" style={{ color: "var(--text)" }}>{m.name}</div>
                            <div className="flex items-center gap-1 mt-0.5">
                                <CheckCircle size={10} className="text-emerald-400" />
                                <span className="text-xs text-emerald-500">Active</span>
                            </div>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}
