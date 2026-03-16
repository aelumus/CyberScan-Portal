import type { RiskLevel, Verdict } from "@/lib/types";

export function VerdictBadge({ verdict }: { verdict: Verdict | string }) {
    const styles: Record<string, React.CSSProperties> = {
        Malicious: { background: "rgba(239,68,68,0.12)", border: "1px solid rgba(239,68,68,0.28)", color: "#f87171" },
        Suspicious: { background: "rgba(245,158,11,0.12)", border: "1px solid rgba(245,158,11,0.28)", color: "#fbbf24" },
        Benign: { background: "rgba(16,185,129,0.12)", border: "1px solid rgba(16,185,129,0.28)", color: "#34d399" },
        Unknown: { background: "var(--surface-2)", border: "1px solid var(--border)", color: "var(--text-3)" },
    };
    const s = styles[verdict] ?? styles.Unknown;
    return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold" style={s}>
            {verdict}
        </span>
    );
}

export function RiskBadge({ level }: { level: RiskLevel | string }) {
    const styles: Record<string, React.CSSProperties> = {
        critical: { background: "rgba(239,68,68,0.15)", border: "1px solid rgba(239,68,68,0.3)", color: "#f87171" },
        high: { background: "rgba(249,115,22,0.15)", border: "1px solid rgba(249,115,22,0.3)", color: "#fb923c" },
        medium: { background: "rgba(245,158,11,0.15)", border: "1px solid rgba(245,158,11,0.3)", color: "#fbbf24" },
        low: { background: "rgba(16,185,129,0.15)", border: "1px solid rgba(16,185,129,0.3)", color: "#34d399" },
    };
    const s = styles[level?.toLowerCase()] ?? styles.low;
    return (
        <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wide" style={s}>
            {level} Risk
        </span>
    );
}

export function ScoreBar({ score }: { score: number }) {
    const pct = Math.round(score * 100);
    const barColor = pct >= 70 ? "#ef4444" : pct >= 40 ? "#f59e0b" : "#10b981";
    return (
        <div className="flex items-center gap-2">
            <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: "var(--border)" }}>
                <div className="h-full rounded-full transition-all duration-500" style={{ width: `${pct}%`, background: barColor }} />
            </div>
            <span className="text-xs w-8 text-right font-mono" style={{ color: "var(--text-3)" }}>{pct}%</span>
        </div>
    );
}
