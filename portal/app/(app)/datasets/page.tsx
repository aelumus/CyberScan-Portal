"use client";
import { useState } from "react";
import { Database, ChevronDown, ChevronUp, CheckCircle, Hash } from "lucide-react";

const FEATURE_GROUPS = [
    { group: "Section Entropy",   icon: "🔬", count: 5,  desc: "Text_entro, Rsrc_entro, Data_entro, Idata_entro, bss_entro" },
    { group: "Header Fields",     icon: "📋", count: 10, desc: "nsec, codesize, initdatsize, uninitdatsize, adrentpt, soi, optcksum, char, dllch, sig" },
    { group: "Section Chars",     icon: "⚙️", count: 5,  desc: "Text_char, Rsrc_char, Data_char, Idata_char, bss_char" },
    { group: "Raw / Virt Sizes",  icon: "📊", count: 8,  desc: "Text/Rsrc/Data/Idata_secsize & datsize" },
    { group: "Addresses",         icon: "📍", count: 13, desc: "bss_virsize, ibase, secalign, filealign, byteaddr × 4, mscfaddr × 4, bss_viraddr, bss_phyaddr" },
    { group: "Base & Align",      icon: "🔧", count: 4,  desc: "cbase, dbase, ss, filealign" },
    { group: "Version Fields",    icon: "🏷️", count: 8,  desc: "majssver, minssver, majosver, minosver, majiver, miniver, majlv, minlv" },
    { group: "Size Fields",       icon: "📦", count: 4,  desc: "sosr, sosc, sohr, sohc" },
    { group: "Misc",              icon: "🔩", count: 5,  desc: "ndirent, mach, ohs, win32vv, soh" },
];

const ALL_FEATURES = [
    "Text_entro", "Rsrc_entro", "Data_entro", "Idata_entro", "bss_entro",
    "nsec", "codesize", "initdatsize", "uninitdatsize", "adrentpt",
    "soi", "optcksum", "char", "dllch",
    "Text_char", "Rsrc_char", "Data_char", "Idata_char", "bss_char",
    "Text_secsize", "Text_datsize", "Rsrc_secsize", "Rsrc_datsize",
    "Data_secsize", "Data_datsize", "Idata_secsize", "Idata_datsize",
    "bss_virsize", "ibase", "ss", "secalign", "filealign",
    "Text_byteaddr", "Rsrc_byteaddr", "Data_byteaddr", "Idata_byteaddr",
    "bss_viraddr", "Text_mscfaddr", "Rsrc_mscfaddr", "Data_mscfaddr",
    "Idata_mscfaddr", "bss_phyaddr", "cbase", "dbase",
    "majssver", "minssver", "majosver", "minosver",
    "majiver", "miniver", "majlv", "minlv",
    "sosr", "sosc", "sohr", "sohc",
    "ndirent", "mach", "sig", "ohs", "win32vv", "soh",
];

export default function DatasetsPage() {
    const [expanded, setExpanded] = useState(false);
    const [showFeatures, setShowFeatures] = useState(false);

    return (
        <div className="space-y-6 max-w-4xl mx-auto">
            <div>
                <h1 className="text-2xl font-black" style={{ color: "var(--text)" }}>Datasets</h1>
                <p className="text-sm mt-1" style={{ color: "var(--text-3)" }}>Training data used to build all three ML models</p>
            </div>

            <div className="glass rounded-2xl overflow-hidden">
                <div className="p-6">
                    <div className="flex items-start gap-5">
                        <div className="w-16 h-16 rounded-2xl flex items-center justify-center font-black text-2xl shrink-0"
                            style={{ background: "var(--accent-bg)", border: "1px solid var(--accent-brd)", color: "var(--accent)" }}>
                            DS1
                        </div>
                        <div className="flex-1">
                            <div className="flex items-start justify-between flex-wrap gap-3">
                                <div>
                                    <h3 className="font-black text-xl" style={{ color: "var(--text)" }}>PE Headers Dataset</h3>
                                    <p className="text-xs mt-1 font-mono" style={{ color: "var(--text-3)" }}>SOMLAP_filtered_metrics_dataset.csv</p>
                                </div>
                                <div className="flex items-center gap-3">
                                    <span className="inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-full"
                                        style={{ background: "rgba(16,185,129,0.1)", border: "1px solid rgba(16,185,129,0.2)", color: "#34d399" }}>
                                        <CheckCircle size={11} /> Active
                                    </span>
                                    <button onClick={() => setExpanded(!expanded)}
                                        className="p-1 transition-colors hover:opacity-70" style={{ color: "var(--text-3)" }}>
                                        {expanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                                    </button>
                                </div>
                            </div>

                            <p className="text-sm mt-3 leading-relaxed" style={{ color: "var(--text-2)" }}>
                                Static PE analysis dataset: 54 numeric features extracted from Windows Portable Executable headers
                                using <span style={{ color: "var(--accent)" }} className="font-mono">pefile</span>.{" "}
                                Target: <code className="text-xs px-1.5 py-0.5 rounded" style={{ background: "var(--surface-2)" }}>class</code>{" "}
                                (1 = benign, 0 = malicious).
                            </p>

                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-5">
                                {([
                                    ["51 408", "Total Samples", "#818cf8"],
                                    ["54",     "Features",      "#c084fc"],
                                    ["class",  "Target Label",  "#34d399"],
                                    ["CSV",    "Format",        "#fbbf24"],
                                ] as [string, string, string][]).map(([val, label, color]) => (
                                    <div key={label} className="rounded-xl p-3 text-center" style={{ background: "var(--surface-2)" }}>
                                        <div className="font-black text-sm mb-0.5" style={{ color }}>{val}</div>
                                        <div className="text-xs" style={{ color: "var(--text-3)" }}>{label}</div>
                                    </div>
                                ))}
                            </div>

                            <div className="mt-4 flex gap-2 flex-wrap">
                                {[
                                    { n: "Random Forest", c: "#818cf8" },
                                    { n: "XGBoost",       c: "#fb923c" },
                                    { n: "LightGBM",      c: "#c084fc" },
                                ].map(({ n, c }) => (
                                    <span key={n} className="text-xs px-3 py-1 rounded-full font-medium"
                                        style={{ background: `${c}12`, border: `1px solid ${c}28`, color: c }}>{n}</span>
                                ))}
                            </div>
                        </div>
                    </div>
                </div>

                {expanded && (
                    <div style={{ borderTop: "1px solid var(--border)" }} className="px-6 py-5">
                        <h4 className="text-xs font-bold uppercase tracking-widest mb-4 flex items-center gap-2" style={{ color: "var(--text-3)" }}>
                            <Database size={12} /> Feature Groups ({ALL_FEATURES.length} total)
                        </h4>
                        <div className="grid sm:grid-cols-2 gap-3 mb-5">
                            {FEATURE_GROUPS.map(({ group, icon, count, desc }) => (
                                <div key={group} className="rounded-xl p-4" style={{ background: "var(--surface-2)" }}>
                                    <div className="flex items-center gap-2 mb-1.5">
                                        <span>{icon}</span>
                                        <span className="font-semibold text-sm" style={{ color: "var(--text)" }}>{group}</span>
                                        <span className="text-xs px-1.5 py-0.5 rounded-full font-mono font-bold ml-auto"
                                            style={{ background: "var(--accent-bg)", color: "var(--accent)" }}>{count}</span>
                                    </div>
                                    <p className="text-xs leading-relaxed" style={{ color: "var(--text-3)" }}>{desc}</p>
                                </div>
                            ))}
                        </div>

                        <button onClick={() => setShowFeatures(!showFeatures)}
                            className="flex items-center gap-2 text-xs mb-3 transition-colors" style={{ color: "var(--accent)" }}>
                            <Hash size={12} /> {showFeatures ? "Hide" : "Show"} all {ALL_FEATURES.length} feature names
                        </button>

                        {showFeatures && (
                            <div className="flex flex-wrap gap-1.5 mb-4">
                                {ALL_FEATURES.map(f => (
                                    <span key={f} className="text-xs px-2 py-0.5 rounded-md font-mono"
                                        style={{ background: "var(--surface-2)", color: "var(--text-2)" }}>{f}</span>
                                ))}
                            </div>
                        )}
                        <p className="text-xs" style={{ color: "var(--text-3)", opacity: 0.6 }}>
                            Source: SOMLAP_filtered_metrics_dataset.csv · Separator: comma · x86/x64 PE files · 51 408 samples
                        </p>
                    </div>
                )}
            </div>

            <div className="glass rounded-2xl p-5">
                <h3 className="text-sm font-bold mb-4 flex items-center gap-2" style={{ color: "var(--text)" }}>
                    <span className="w-6 h-6 rounded-lg flex items-center justify-center text-xs" style={{ background: "var(--accent-bg)", color: "var(--accent)" }}>⚙</span>
                    Feature Extraction Pipeline
                </h3>
                <div className="grid sm:grid-cols-3 gap-3">
                    {[
                        { step: "01", title: "pefile.PE()",   desc: "Parse PE binary with fast_load + manual directory parsing for imports/exports/resources" },
                        { step: "02", title: "62 features",   desc: "Extract section entropy, header fields, sizes, addresses, version & misc fields" },
                        { step: "03", title: "DataFrame",     desc: "Return pandas DataFrame with exact column order matching RF.feature_names_in_" },
                    ].map(({ step, title, desc }) => (
                        <div key={step} className="rounded-xl p-4 relative" style={{ background: "var(--surface-2)" }}>
                            <div className="absolute top-3 right-3 text-xs font-bold font-mono" style={{ color: "var(--accent)", opacity: 0.4 }}>{step}</div>
                            <div className="font-semibold text-sm mb-1 font-mono" style={{ color: "var(--text)" }}>{title}</div>
                            <div className="text-xs leading-relaxed" style={{ color: "var(--text-3)" }}>{desc}</div>
                        </div>
                    ))}
                </div>
            </div>

            <div className="glass rounded-2xl p-5">
                <h3 className="text-sm font-bold mb-4" style={{ color: "var(--text)" }}>Class Distribution</h3>
                <div className="grid grid-cols-2 gap-4">
                    {[
                        { label: "Benign",    count: "25 779", pct: 50.1, color: "#34d399", bg: "rgba(16,185,129,0.1)" },
                        { label: "Malicious", count: "25 629", pct: 49.9, color: "#f87171", bg: "rgba(239,68,68,0.1)"  },
                    ].map(c => (
                        <div key={c.label} className="rounded-xl p-4" style={{ background: c.bg }}>
                            <div className="font-black text-2xl mb-1" style={{ color: c.color }}>{c.count}</div>
                            <div className="text-sm font-semibold" style={{ color: c.color }}>{c.label}</div>
                            <div className="h-1.5 rounded-full mt-3 overflow-hidden" style={{ background: "var(--border)" }}>
                                <div className="h-full rounded-full" style={{ width: `${c.pct}%`, background: c.color }} />
                            </div>
                            <div className="text-xs mt-1" style={{ color: "var(--text-3)" }}>{c.pct}% of total</div>
                        </div>
                    ))}
                </div>
                <p className="text-xs mt-4" style={{ color: "var(--text-3)", opacity: 0.6 }}>
                    Near-balanced dataset — no SMOTE or oversampling required. 80/20 stratified train/test split used during training.
                </p>
            </div>
        </div>
    );
}
