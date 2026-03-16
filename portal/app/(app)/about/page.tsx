"use client";
import { Shield, Cpu, Zap, Lock, Users, Github, Globe, CheckCircle } from "lucide-react";

const TECH = [
    { name: "Python 3.12", role: "Backend Runtime", icon: "🐍", color: "#fbbf24" },
    { name: "FastAPI", role: "REST API", icon: "⚡", color: "#34d399" },
    { name: "scikit-learn", role: "Random Forest", icon: "🌲", color: "#818cf8" },
    { name: "XGBoost", role: "Gradient Boosting", icon: "🎯", color: "#fb923c" },
    { name: "LightGBM", role: "Leaf-wise Boost", icon: "🔥", color: "#c084fc" },
    { name: "pefile", role: "PE Parsing", icon: "📂", color: "#38bdf8" },
    { name: "Next.js 14", role: "Frontend", icon: "▲", color: "#818cf8" },
    { name: "VirusTotal", role: "Threat Intel", icon: "🛡️", color: "#f87171" },
];

export default function AboutPage() {
    return (
        <div className="space-y-6 max-w-4xl mx-auto">
            {/* Hero */}
            <div className="relative rounded-3xl p-8 overflow-hidden"
                style={{ background: "var(--accent-bg)", border: "1px solid var(--accent-brd)" }}>
                <div className="absolute inset-0 pointer-events-none"
                    style={{ background: "radial-gradient(ellipse at 0% 0%, rgba(99,102,241,0.15), transparent 60%)" }} />
                <div className="relative flex items-start gap-5 flex-wrap">
                    <div className="w-14 h-14 rounded-2xl flex items-center justify-center shrink-0"
                        style={{ background: "linear-gradient(135deg,#4f46e5,#7c3aed)" }}>
                        <Shield size={24} className="text-white" />
                    </div>
                    <div>
                        <h1 className="text-2xl font-black" style={{ color: "var(--text)" }}>CyberScan Portal</h1>
                        <p className="text-sm mt-0.5" style={{ color: "var(--accent)" }}>Malware Detection System · Static Analysis + Machine Learning</p>
                        <p className="text-sm mt-3 leading-relaxed max-w-xl" style={{ color: "var(--text-2)" }}>
                            A hybrid malware detection platform combining PE file static analysis with three
                            Machine Learning models and VirusTotal cloud intelligence. Designed for academic
                            research and practical threat analysis.
                        </p>
                        <div className="flex flex-wrap gap-3 mt-4">
                            <span className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-full"
                                style={{ background: "rgba(16,185,129,0.1)", border: "1px solid rgba(16,185,129,0.2)", color: "#34d399" }}>
                                <CheckCircle size={11} /> 3 ML Models Active
                            </span>
                            <span className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-full"
                                style={{ background: "var(--accent-bg)", border: "1px solid var(--accent-brd)", color: "var(--accent)" }}>
                                <Cpu size={11} /> 54 PE Features
                            </span>
                            <span className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-full"
                                style={{ background: "rgba(251,146,60,0.1)", border: "1px solid rgba(251,146,60,0.2)", color: "#fb923c" }}>
                                <Zap size={11} /> Real-time Analysis
                            </span>
                        </div>
                    </div>
                </div>
            </div>

            {/* Architecture Flow */}
            <div className="glass rounded-2xl p-6">
                <h2 className="text-sm font-bold mb-5 flex items-center gap-2" style={{ color: "var(--text)" }}>
                    <Zap size={15} style={{ color: "var(--accent)" }} /> System Architecture
                </h2>
                <div className="flex flex-col sm:flex-row items-center gap-2 flex-wrap">
                    {[
                        { step: "Upload", icon: "📁", color: "#818cf8", desc: ".exe / .dll" },
                        { step: "PE Parse", icon: "⚙️", color: "#38bdf8", desc: "pefile library" },
                        { step: "54 Features", icon: "📊", color: "#fbbf24", desc: "numpy vector" },
                        { step: "3 ML Models", icon: "🤖", color: "#c084fc", desc: "RF · XGB · LGB" },
                        { step: "VirusTotal", icon: "🛡️", color: "#f87171", desc: "cloud check" },
                        { step: "Verdict", icon: "✅", color: "#34d399", desc: "final result" },
                    ].map(({ step, icon, color, desc }, i) => (
                        <div key={step} className="flex items-center gap-2 flex-1">
                            <div className="text-center flex-1">
                                <div className="text-xl mb-1">{icon}</div>
                                <div className="text-xs font-bold" style={{ color }}>{step}</div>
                                <div className="text-xs" style={{ color: "var(--text-3)" }}>{desc}</div>
                            </div>
                            {i < 5 && <div className="font-mono text-xs" style={{ color: "var(--text-3)" }}>→</div>}
                        </div>
                    ))}
                </div>
                <div className="mt-5 rounded-xl p-4" style={{ background: "var(--accent-bg)", border: "1px solid var(--accent-brd)" }}>
                    <div className="flex items-center gap-3 flex-wrap">
                        <span className="font-black text-sm" style={{ color: "var(--accent)" }}>DS1</span>
                        <span className="text-xs" style={{ color: "var(--text-3)" }}>PE Headers Dataset · 51 408 files</span>
                        <div className="flex gap-2 ml-auto flex-wrap">
                            {[["RF", "#818cf8"], ["XGB", "#fb923c"], ["LGB", "#c084fc"]].map(([n, c]) => (
                                <span key={n} className="text-xs px-2.5 py-1 rounded-lg font-mono font-bold"
                                    style={{ background: `${c}12`, border: `1px solid ${c}28`, color: c }}>{n}</span>
                            ))}
                        </div>
                    </div>
                </div>
            </div>

            {/* Tech Stack */}
            <div className="glass rounded-2xl p-6">
                <h2 className="text-sm font-bold mb-5" style={{ color: "var(--text)" }}>Technology Stack</h2>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    {TECH.map(({ name, role, icon, color }) => (
                        <div key={name} className="rounded-xl p-4 text-center transition-all duration-200 hover:-translate-y-0.5"
                            style={{ background: "var(--surface-2)" }}>
                            <div className="text-2xl mb-2">{icon}</div>
                            <div className="font-bold text-sm" style={{ color }}>{name}</div>
                            <div className="text-xs mt-0.5" style={{ color: "var(--text-3)" }}>{role}</div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Privacy + Team */}
            <div className="grid md:grid-cols-2 gap-5">
                <div className="glass rounded-2xl p-5">
                    <div className="flex items-center gap-2 mb-3">
                        <Lock size={15} style={{ color: "var(--accent)" }} />
                        <h3 className="text-sm font-bold" style={{ color: "var(--text)" }}>Privacy Policy</h3>
                    </div>
                    <div className="space-y-2">
                        {[
                            "ML analysis is fully local — no external file uploads",
                            "Files are not shared externally",
                            "VirusTotal lookup only if explicitly enabled",
                            "Scan results stored in-memory (cleared on restart)",
                        ].map(p => (
                            <div key={p} className="flex items-start gap-2 text-xs" style={{ color: "var(--text-2)" }}>
                                <CheckCircle size={11} className="text-emerald-400 mt-0.5 shrink-0" /><span>{p}</span>
                            </div>
                        ))}
                    </div>
                </div>
                <div className="glass rounded-2xl p-5">
                    <div className="flex items-center gap-2 mb-3">
                        <Users size={15} style={{ color: "var(--accent)" }} />
                        <h3 className="text-sm font-bold" style={{ color: "var(--text)" }}>Project Info</h3>
                    </div>
                    <div className="space-y-2 text-sm" style={{ color: "var(--text-2)" }}>
                        <p>🎓 <strong style={{ color: "var(--text)" }}>Faculty of Computer Science</strong></p>
                        <p>📅 Bachelor&apos;s Thesis · 2026</p>
                        <p className="text-xs mt-3" style={{ color: "var(--text-3)" }}>
                            CyberScan Portal combines modern ML techniques with VirusTotal cloud intelligence for hybrid malware detection.
                        </p>
                    </div>
                    <div className="flex gap-3 mt-4">
                        <div className="flex items-center gap-1.5 text-xs transition-colors cursor-pointer" style={{ color: "var(--text-3)" }}>
                            <Globe size={12} /> localhost:3000
                        </div>
                        <div className="flex items-center gap-1.5 text-xs transition-colors cursor-pointer" style={{ color: "var(--text-3)" }}>
                            <Github size={12} /> Source code
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
