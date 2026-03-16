"use client";
import { useState, useEffect } from "react";
import { useAuth } from "@/components/AuthProvider";
import { getJson } from "@/lib/api";
import type { ConfusionResponse, ModelsResponse, RocResponse } from "@/lib/types";
import {
    LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
    Legend, CartesianGrid
} from "recharts";
import { Activity, Cpu, Shield } from "lucide-react";

const MODEL_META: Record<string, { name: string; color: string; icon: string }> = {
    ds1_rf: { name: "Random Forest", color: "#818cf8", icon: "🌲" },
    ds1_xgb: { name: "XGBoost", color: "#fb923c", icon: "⚡" },
    ds1_lgbm: { name: "LightGBM", color: "#c084fc", icon: "🔥" },
};

export default function ModelsPage() {
    const [models, setModels] = useState<ModelsResponse["models"]>([]);
    const [roc, setRoc] = useState<RocResponse | null>(null);
    const [confusion, setConfusion] = useState<ConfusionResponse | null>(null);
    const [loading, setLoading] = useState(true);
    const { authHeaders } = useAuth();

    useEffect(() => {
        Promise.all([
            getJson<ModelsResponse>("/api/models", { headers: authHeaders() }),
            getJson<RocResponse>("/api/models/roc", { headers: authHeaders() }),
            getJson<ConfusionResponse>("/api/models/confusion", { headers: authHeaders() }),
        ]).then(([m, r, c]) => {
            setModels(m.models ?? []);
            setRoc(r);
            setConfusion(c);
            setLoading(false);
        }).catch(() => setLoading(false));
    }, [authHeaders]);

    // Build ROC chart data: zip fpr/tpr from each model into a single array indexed by point
    const rocChartData = () => {
        if (!roc?.roc) return [];
        // Use the first model's FPR as x-axis (all models have same length)
        const keys = Object.keys(roc.roc);
        if (!keys.length) return [];
        const firstFpr = roc.roc[keys[0]].fpr;
        return firstFpr.map((fpr, i) => {
            const pt: Record<string, number> = { fpr: Math.round(fpr * 1000) / 10 };
            keys.forEach(k => { pt[k] = Math.round(roc.roc[k].tpr[i] * 1000) / 10; });
            return pt;
        });
    };

    return (
        <div className="space-y-6 max-w-5xl mx-auto">
            <div>
                <h1 className="text-2xl font-black" style={{ color: "var(--text)" }}>ML Models</h1>
                <p className="text-sm mt-1" style={{ color: "var(--text-3)" }}>Performance metrics and evaluation charts for all 3 models</p>
            </div>

            {/* Model Cards */}
            <div className="grid md:grid-cols-3 gap-4">
                {loading ? [1, 2, 3].map(i => (
                    <div key={i} className="glass rounded-2xl p-5 animate-pulse h-40" style={{ background: "var(--surface-2)" }} />
                )) : models.map(m => {
                    const meta = MODEL_META[m.id] ?? { name: m.name, color: "#818cf8", icon: "🤖" };
                    return (
                        <div key={m.id} className="glass rounded-2xl p-5">
                            <div className="flex items-center gap-3 mb-4">
                                <span className="text-2xl">{meta.icon}</span>
                                <div>
                                    <div className="font-bold text-sm" style={{ color: "var(--text)" }}>{meta.name}</div>
                                    <div className="flex items-center gap-1.5 mt-0.5">
                                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                                        <span className="text-xs" style={{ color: "var(--text-3)" }}>
                                            {m.loaded ? "Loaded" : "Not loaded"}
                                        </span>
                                    </div>
                                </div>
                            </div>
                            <div className="grid grid-cols-2 gap-2">
                                {[
                                    ["AUC", (m.metrics.auc * 100).toFixed(2) + "%", meta.color],
                                    ["F1", (m.metrics.f1 * 100).toFixed(1) + "%", "#34d399"],
                                    ["Accuracy", (m.metrics.accuracy * 100).toFixed(1) + "%", "#38bdf8"],
                                    ["FPR", (m.metrics.fpr * 100).toFixed(1) + "%", "#fbbf24"],
                                ].map(([label, val, color]) => (
                                    <div key={label} className="rounded-lg p-2 text-center" style={{ background: "var(--surface-2)" }}>
                                        <div className="font-black text-sm" style={{ color }}>{val}</div>
                                        <div className="text-xs mt-0.5" style={{ color: "var(--text-3)" }}>{label}</div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    );
                })}
            </div>

            {/* ROC Curves */}
            <div className="glass rounded-2xl p-6">
                <div className="flex items-center justify-between mb-5 flex-wrap gap-3">
                    <div>
                        <h2 className="font-bold text-sm flex items-center gap-2" style={{ color: "var(--text)" }}>
                            <Activity size={15} style={{ color: "var(--accent)" }} /> ROC Curves
                        </h2>
                        <p className="text-xs mt-1" style={{ color: "var(--text-3)" }}>Receiver Operating Characteristic · TPR vs FPR at varying thresholds</p>
                    </div>
                    <div className="flex gap-3 flex-wrap">
                        {roc && Object.entries(roc.roc).map(([key, data]) => (
                            <span key={key} className="text-xs px-2 py-1 rounded-lg font-medium"
                                style={{ background: `${MODEL_META[key]?.color ?? "#818cf8"}12`, color: MODEL_META[key]?.color ?? "#818cf8" }}>
                                {MODEL_META[key]?.name} AUC={data.auc.toFixed(4)}
                            </span>
                        ))}
                    </div>
                </div>
                <ResponsiveContainer width="100%" height={280}>
                    <LineChart data={rocChartData()} margin={{ left: 0, right: 10, top: 5, bottom: 5 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                        <XAxis dataKey="fpr" tickFormatter={v => `${v}%`} tick={{ fontSize: 10, fill: "var(--text-3)" }} axisLine={false} tickLine={false} label={{ value: "FPR (%)", position: "insideBottom", offset: -2, fill: "var(--text-3)", fontSize: 10 }} />
                        <YAxis tickFormatter={v => `${v}%`} tick={{ fontSize: 10, fill: "var(--text-3)" }} axisLine={false} tickLine={false} domain={[0, 100]} label={{ value: "TPR (%)", angle: -90, position: "insideLeft", fill: "var(--text-3)", fontSize: 10 }} />
                        <Tooltip contentStyle={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 10, fontSize: 11, color: "var(--text)" }}
                            formatter={(v: unknown) => [`${Number(v).toFixed(1)}%`]} />
                        <Legend formatter={(value) => MODEL_META[value]?.name ?? value} />
                        {/* Diagonal reference line (random classifier) */}
                        <Line type="linear" dataKey="__diagonal__" dot={false} strokeDasharray="4 4" stroke="var(--border-2)" name="Random" />
                        {roc && Object.keys(roc.roc).map(key => (
                            <Line key={key} type="monotone" dataKey={key}
                                stroke={MODEL_META[key]?.color ?? "#818cf8"}
                                strokeWidth={2.5} dot={false}
                                name={key} activeDot={{ r: 4 }} />
                        ))}
                    </LineChart>
                </ResponsiveContainer>
                <p className="text-xs mt-3 italic" style={{ color: "var(--text-3)", opacity: 0.6 }}>
                    * Representative ROC curves from offline evaluation on test split (10 282 samples: 5 141 benign / 5 141 malicious).
                </p>
            </div>

            {/* Confusion Matrices */}
            {confusion && (
                <div className="glass rounded-2xl p-6">
                    <h2 className="font-bold text-sm flex items-center gap-2 mb-5" style={{ color: "var(--text)" }}>
                        <Cpu size={15} style={{ color: "var(--accent)" }} /> Confusion Matrices
                        <span className="text-xs font-normal" style={{ color: "var(--text-3)" }}>at threshold 0.40</span>
                    </h2>
                    <div className="grid md:grid-cols-3 gap-5">
                        {Object.entries(confusion.confusion).map(([key, cm]) => {
                            const meta = MODEL_META[key] ?? { name: key, color: "#818cf8", icon: "🤖" };
                            const acc = ((cm.tp + cm.tn) / cm.total * 100).toFixed(1);
                            const precision = (cm.tp / (cm.tp + cm.fp) * 100).toFixed(1);
                            const recall = (cm.tp / (cm.tp + cm.fn) * 100).toFixed(1);
                            return (
                                <div key={key}>
                                    <div className="flex items-center gap-2 mb-3">
                                        <span className="text-lg">{meta.icon}</span>
                                        <span className="font-bold text-sm" style={{ color: meta.color }}>{meta.name}</span>
                                    </div>
                                    {/* 2×2 grid */}
                                    <div className="grid grid-cols-2 gap-1.5">
                                        {[
                                            { label: "TP", value: cm.tp, color: "#10b981", bg: "rgba(16,185,129,0.1)", desc: "True Positive" },
                                            { label: "FN", value: cm.fn, color: "#f87171", bg: "rgba(239,68,68,0.1)", desc: "False Negative" },
                                            { label: "FP", value: cm.fp, color: "#fbbf24", bg: "rgba(245,158,11,0.1)", desc: "False Positive" },
                                            { label: "TN", value: cm.tn, color: "#34d399", bg: "rgba(52,211,153,0.1)", desc: "True Negative" },
                                        ].map(cell => (
                                            <div key={cell.label} className="rounded-xl p-3 text-center"
                                                style={{ background: cell.bg, border: `1px solid ${cell.color}28` }}>
                                                <div className="font-black text-lg" style={{ color: cell.color }}>{cell.value.toLocaleString()}</div>
                                                <div className="text-xs font-bold" style={{ color: cell.color }}>{cell.label}</div>
                                                <div className="text-xs mt-0.5" style={{ color: "var(--text-3)" }}>{cell.desc}</div>
                                            </div>
                                        ))}
                                    </div>
                                    <div className="grid grid-cols-3 gap-1.5 mt-1.5">
                                        {[["Acc", acc + "%", "#818cf8"], ["Prec", precision + "%", "#c084fc"], ["Recall", recall + "%", "#34d399"]].map(([l, v, c]) => (
                                            <div key={l} className="rounded-lg p-2 text-center" style={{ background: "var(--surface-2)" }}>
                                                <div className="font-bold text-sm" style={{ color: String(c) }}>{v}</div>
                                                <div className="text-xs" style={{ color: "var(--text-3)" }}>{l}</div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                    <p className="text-xs mt-5 italic" style={{ color: "var(--text-3)", opacity: 0.6 }}>
                        * Evaluated on 10 282-sample test split. Results computed offline and preloaded.
                    </p>
                </div>
            )}

            {/* Dataset info */}
            <div className="glass rounded-2xl p-5">
                <h2 className="font-bold text-sm flex items-center gap-2 mb-4" style={{ color: "var(--text)" }}>
                    <Shield size={15} style={{ color: "var(--accent)" }} /> Training Dataset — DS1
                </h2>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    {[
                        ["51 408", "Total samples", "#818cf8"],
                        ["62", "Features (SOMLAP)", "#c084fc"],
                        ["~50/50", "Benign / Malicious", "#34d399"],
                        ["80/20", "Train / Test split", "#fbbf24"],
                    ].map(([v, l, c]) => (
                        <div key={l} className="rounded-xl p-3 text-center" style={{ background: "var(--surface-2)" }}>
                            <div className="font-black text-sm mb-0.5" style={{ color: c }}>{v}</div>
                            <div className="text-xs" style={{ color: "var(--text-3)" }}>{l}</div>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}
