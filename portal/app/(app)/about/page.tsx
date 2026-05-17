"use client";
import { Shield, Cpu, Database, Activity, ArrowRight, CheckCircle } from "lucide-react";

const TECH_STACK = [
    { name: "FastAPI", role: "REST API / Backend", color: "#34d399", glow: "#10b981", icon: "⚡" },
    { name: "Next.js 14", role: "React Frontend (App Router)", color: "#818cf8", glow: "#4f46e5", icon: "⟩" },
    { name: "SQLite", role: "Scan storage / Auth DB", color: "#38bdf8", glow: "#0ea5e9", icon: "🗄" },
    { name: "scikit-learn", role: "Random Forest (RF)", color: "#fbbf24", glow: "#f59e0b", icon: "🌲" },
    { name: "XGBoost", role: "Gradient Boosting (XGB)", color: "#fb923c", glow: "#f97316", icon: "⚡" },
    { name: "LightGBM", role: "Leaf-Wise Boosting (LGB)", color: "#c084fc", glow: "#a855f7", icon: "🔥" },
    { name: "pefile", role: "PE Header Parsing", color: "#f87171", glow: "#ef4444", icon: "📄" },
    { name: "SHAP", role: "Model Explainability", color: "#2dd4bf", glow: "#14b8a6", icon: "🔍" },
    { name: "ReportLab", role: "PDF Report Generation", color: "#a78bfa", glow: "#8b5cf6", icon: "📋" },
];

const PIPELINE_STEPS = [
    { step: "01", icon: <Shield size={18} />, title: "Upload PE Binary", desc: ".exe or .dll (x86/x64 Windows)" },
    { step: "02", icon: <Database size={18} />, title: "Extract 62 Features", desc: "pefile parses section entropy, header fields, addresses, version info" },
    { step: "03", icon: <Cpu size={18} />, title: "Ensemble Inference", desc: "RF · XGBoost · LightGBM vote in parallel" },
    { step: "04", icon: <Activity size={18} />, title: "Verdict & Report", desc: "Score, risk level, SHAP values, PDF download" },
];

const CAPABILITIES = [
    "54 static PE features — headers, entropy, sections",
    "3 independent ML models with majority voting",
    "SHAP explainability — why each verdict was reached",
    "Suspicious string & dangerous import detection",
    "MITRE ATT&CK technique mapping",
    "Custom YARA rule scanning",
    "VirusTotal cross-check integration",
    "PDF report generation via ReportLab",
    "JWT authentication & user sessions",
    "Prometheus metrics & monitoring",
];

export default function AboutPage() {
    return (
        <div className="space-y-8 max-w-4xl mx-auto">
            <div className="glass rounded-3xl p-8 overflow-hidden relative">
                <div className="absolute inset-0 pointer-events-none" style={{ background: "radial-gradient(ellipse at 0% 0%, rgba(99,102,241,0.12), transparent 60%)" }} />
                <div className="relative flex flex-wrap items-center gap-5">
                    <div className="w-16 h-16 rounded-2xl flex items-center justify-center shrink-0"
                        style={{ background: "linear-gradient(135deg,#4f46e5,#7c3aed)", boxShadow: "0 0 40px rgba(99,102,241,0.35)" }}>
                        <Shield size={30} className="text-white" />
                    </div>
                    <div>
                        <h1 className="text-3xl font-black" style={{ color: "var(--text)" }}>CyberScan Portal</h1>
                        <p className="text-sm mt-1" style={{ color: "var(--text-3)" }}>
                            Automated Malware Analysis System · Diploma Project 2026
                        </p>
                        <div className="flex items-center gap-2 mt-2 flex-wrap">
                            {["v2.0.0", "Python 3.11", "Next.js 14", "MIT License"].map(tag => (
                                <span key={tag} className="text-xs px-2 py-0.5 rounded-full"
                                    style={{ background: "var(--accent-bg)", color: "var(--accent)", border: "1px solid var(--accent-brd)" }}>{tag}</span>
                            ))}
                        </div>
                    </div>
                </div>
                <p className="mt-6 text-sm leading-relaxed" style={{ color: "var(--text-2)" }}>
                    CyberScan Portal is a graduation project for automated static analysis of malicious software.
                    The system extracts 62 features from the PE headers of Windows binaries and applies ensemble voting
                    of three machine learning models (Random Forest, XGBoost, LightGBM) to classify files as malicious or legitimate.
                    Major: Information Security - IITU-2026.
                </p>
            </div>

            <div className="glass rounded-2xl p-6">
                <h2 className="text-sm font-bold uppercase tracking-widest mb-6 flex items-center gap-2" style={{ color: "var(--text-3)" }}>
                    <ArrowRight size={14} style={{ color: "var(--accent)" }} /> Analysis Pipeline
                </h2>
                <div className="grid sm:grid-cols-4 gap-4">
                    {PIPELINE_STEPS.map(({ step, icon, title, desc }) => (
                        <div key={step} className="relative rounded-2xl p-5 text-center" style={{ background: "var(--surface-2)" }}>
                            <div className="absolute -top-3 left-1/2 -translate-x-1/2 text-xs font-bold px-2 py-0.5 rounded-full"
                                style={{ background: "var(--accent-bg)", border: "1px solid var(--accent-brd)", color: "var(--accent)" }}>{step}</div>
                            <div className="flex justify-center mb-3 mt-2" style={{ color: "var(--accent)" }}>{icon}</div>
                            <div className="font-semibold text-sm mb-1.5" style={{ color: "var(--text)" }}>{title}</div>
                            <div className="text-xs leading-relaxed" style={{ color: "var(--text-3)" }}>{desc}</div>
                        </div>
                    ))}
                </div>
            </div>

            <div className="glass rounded-2xl p-6">
                <h2 className="text-sm font-bold uppercase tracking-widest mb-5 flex items-center gap-2" style={{ color: "var(--text-3)" }}>
                    <Cpu size={14} style={{ color: "var(--accent)" }} /> Technology Stack
                </h2>
                <div className="grid sm:grid-cols-3 gap-3">
                    {TECH_STACK.map(t => (
                        <div key={t.name} className="flex items-center gap-3 rounded-xl p-3" style={{ background: "var(--surface-2)" }}>
                            <span className="text-lg w-7 text-center">{t.icon}</span>
                            <div>
                                <div className="font-bold text-sm" style={{ color: t.color }}>{t.name}</div>
                                <div className="text-xs" style={{ color: "var(--text-3)" }}>{t.role}</div>
                            </div>
                        </div>
                    ))}
                </div>
            </div>

            <div className="glass rounded-2xl p-6">
                <h2 className="text-sm font-bold uppercase tracking-widest mb-5 flex items-center gap-2" style={{ color: "var(--text-3)" }}>
                    <CheckCircle size={14} style={{ color: "#34d399" }} /> System Capabilities
                </h2>
                <div className="grid sm:grid-cols-2 gap-2">
                    {CAPABILITIES.map(c => (
                        <div key={c} className="flex items-start gap-2.5 text-sm" style={{ color: "var(--text-2)" }}>
                            <CheckCircle size={14} className="text-emerald-400 mt-0.5 shrink-0" />
                            {c}
                        </div>
                    ))}
                </div>
            </div>

            <div className="glass rounded-2xl p-6">
                <h2 className="text-sm font-bold uppercase tracking-widest mb-5" style={{ color: "var(--text-3)" }}>ML Model Overview</h2>
                <div className="grid sm:grid-cols-3 gap-4">
                    {[
                        { name: "Random Forest", abbr: "RF", icon: "🌲", color: "#818cf8", desc: "100 decision trees, majority vote, robust against noise", acc: "99.6%" },
                        { name: "XGBoost", abbr: "XGB", icon: "⚡", color: "#fb923c", desc: "Gradient boosted trees with L1/L2 regularisation", acc: "99.6%" },
                        { name: "LightGBM", abbr: "LGB", icon: "🔥", color: "#c084fc", desc: "Leaf-wise tree growth, fast inference, low FPR", acc: "99.7%" },
                    ].map(m => (
                        <div key={m.name} className="rounded-2xl p-5" style={{ background: "var(--surface-2)", border: `1px solid ${m.color}20` }}>
                            <div className="text-2xl mb-3">{m.icon}</div>
                            <div className="flex items-center gap-2 mb-2">
                                <span className="font-bold text-sm" style={{ color: m.color }}>{m.name}</span>
                                <span className="text-xs px-1.5 py-0.5 rounded font-mono" style={{ background: `${m.color}12`, color: m.color }}>{m.abbr}</span>
                            </div>
                            <p className="text-xs leading-relaxed mb-3" style={{ color: "var(--text-3)" }}>{m.desc}</p>
                            <div className="text-xs font-bold" style={{ color: "#34d399" }}>Accuracy: {m.acc}</div>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}
