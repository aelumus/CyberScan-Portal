"use client";
import { useState } from "react";
import { Database, ChevronDown, ChevronUp, CheckCircle, Hash } from "lucide-react";

const DS1_FEATURE_GROUPS = [
    { group: "File Header", icon: "📋", count: 3, desc: "Machine, SizeOfOptionalHeader, Characteristics" },
    { group: "Optional Header", icon: "⚙️", count: 28, desc: "EntryPoint, ImageBase, Subsystem, Checksums, Stack/Heap sizes, Linker versions…" },
    { group: "Section Statistics", icon: "📊", count: 10, desc: "Count, mean/min/max entropy, mean/min/max raw & virtual sizes" },
    { group: "Import Analysis", icon: "📥", count: 3, desc: "ImportsNbDLL, ImportsNb, ImportsNbOrdinal" },
    { group: "Export Analysis", icon: "📤", count: 1, desc: "ExportNb — number of exported symbols" },
    { group: "Resource Analysis", icon: "🎨", count: 7, desc: "ResourcesNb, mean/min/max entropy, mean/min/max size" },
    { group: "Misc", icon: "🔧", count: 2, desc: "LoadConfigurationSize, VersionInformationSize" },
];

const ALL_FEATURES = [
    "Machine", "SizeOfOptionalHeader", "Characteristics", "MajorLinkerVersion", "MinorLinkerVersion",
    "SizeOfCode", "SizeOfInitializedData", "SizeOfUninitializedData", "AddressOfEntryPoint", "BaseOfCode",
    "BaseOfData", "ImageBase", "SectionAlignment", "FileAlignment", "MajorOperatingSystemVersion",
    "MinorOperatingSystemVersion", "MajorImageVersion", "MinorImageVersion", "MajorSubsystemVersion",
    "MinorSubsystemVersion", "SizeOfImage", "SizeOfHeaders", "CheckSum", "Subsystem", "DllCharacteristics",
    "SizeOfStackReserve", "SizeOfStackCommit", "SizeOfHeapReserve", "SizeOfHeapCommit", "LoaderFlags",
    "NumberOfRvaAndSizes", "SectionsNb", "SectionsMeanEntropy", "SectionsMinEntropy", "SectionsMaxEntropy",
    "SectionsMeanRawsize", "SectionsMinRawsize", "SectionMaxRawsize", "SectionsMeanVirtualsize",
    "SectionsMinVirtualsize", "SectionMaxVirtualsize", "ImportsNbDLL", "ImportsNb", "ImportsNbOrdinal",
    "ExportNb", "ResourcesNb", "ResourcesMeanEntropy", "ResourcesMinEntropy", "ResourcesMaxEntropy",
    "ResourcesMeanSize", "ResourcesMinSize", "ResourcesMaxSize", "LoadConfigurationSize", "VersionInformationSize",
];

export default function DatasetsPage() {
    const [expanded, setExpanded] = useState(false);
    const [showFeatures, setShowFeatures] = useState(false);

    return (
        <div className="space-y-6 max-w-4xl mx-auto">
            <div>
                <h1 className="text-2xl font-black" style={{ color: "var(--text)" }}>Datasets</h1>
                <p className="text-sm mt-1" style={{ color: "var(--text-3)" }}>Training data used to build the ML models</p>
            </div>

            {/* DS1 card */}
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
                                    <button onClick={() => setExpanded(!expanded)} style={{ color: "var(--text-3)" }} className="transition-colors hover:opacity-70 p-1">
                                        {expanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                                    </button>
                                </div>
                            </div>
                            <p className="text-sm mt-3 leading-relaxed" style={{ color: "var(--text-2)" }}>
                                Static PE analysis dataset: 54 numeric features extracted from Windows Portable Executable headers
                                using <span style={{ color: "var(--accent)" }} className="font-mono">pefile</span>. Target: <code className="text-xs px-1.5 py-0.5 rounded" style={{ background: "var(--surface-2)" }}>class</code> (1 = benign, 0 = malicious).
                            </p>

                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-5">
                                {[
                                    ["51 408", "Total Samples", "#818cf8"],
                                    ["54", "Features", "#c084fc"],
                                    ["class", "Target Label", "#34d399"],
                                    ["CSV", "Format", "#fbbf24"],
                                ].map(([val, label, color]) => (
                                    <div key={label} className="rounded-xl p-3 text-center" style={{ background: "var(--surface-2)" }}>
                                        <div className="font-black text-sm mb-0.5" style={{ color }}>{val}</div>
                                        <div className="text-xs" style={{ color: "var(--text-3)" }}>{label}</div>
                                    </div>
                                ))}
                            </div>

                            <div className="mt-4 flex gap-2 flex-wrap">
                                {[{ n: "Random Forest", c: "#818cf8" }, { n: "XGBoost", c: "#fb923c" }, { n: "LightGBM", c: "#c084fc" }].map(({ n, c }) => (
                                    <span key={n} className="text-xs px-3 py-1 rounded-full font-medium" style={{ background: `${c}12`, border: `1px solid ${c}28`, color: c }}>{n}</span>
                                ))}
                            </div>
                        </div>
                    </div>
                </div>

                {expanded && (
                    <div style={{ borderTop: "1px solid var(--border)" }} className="px-6 py-5">
                        <h4 className="text-xs font-bold uppercase tracking-widest mb-4 flex items-center gap-2" style={{ color: "var(--text-3)" }}>
                            <Database size={12} /> Feature Groups (54 total)
                        </h4>
                        <div className="grid sm:grid-cols-2 gap-3 mb-5">
                            {DS1_FEATURE_GROUPS.map(({ group, icon, count, desc }) => (
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
                            <Hash size={12} /> {showFeatures ? "Hide" : "Show"} all 54 feature names
                        </button>
                        {showFeatures && (
                            <div className="flex flex-wrap gap-1.5">
                                {ALL_FEATURES.map(f => (
                                    <span key={f} className="text-xs px-2 py-0.5 rounded-md font-mono" style={{ background: "var(--surface-2)", color: "var(--text-2)" }}>{f}</span>
                                ))}
                            </div>
                        )}
                        <p className="text-xs mt-4" style={{ color: "var(--text-3)", opacity: 0.6 }}>
                            Source: SOMLAP_filtered_metrics_dataset.csv · Separator: comma · x86/x64 PE files only
                        </p>
                    </div>
                )}
            </div>

            {/* Extraction method */}
            <div className="glass rounded-2xl p-5">
                <h3 className="text-sm font-bold mb-4 flex items-center gap-2" style={{ color: "var(--text)" }}>
                    <span className="w-6 h-6 rounded-lg flex items-center justify-center text-xs" style={{ background: "var(--accent-bg)", color: "var(--accent)" }}>⚙</span>
                    Feature Extraction Method
                </h3>
                <div className="grid sm:grid-cols-3 gap-3">
                    {[
                        { step: "01", title: "pefile.PE()", desc: "Parse PE binary with fast_load + manual directory parsing" },
                        { step: "02", title: "54 features", desc: "Extract headers, section stats, imports, exports, resources" },
                        { step: "03", title: "DataFrame", desc: "Return pandas DataFrame with exact column order from RF.feature_names_in_" },
                    ].map(({ step, title, desc }) => (
                        <div key={step} className="rounded-xl p-4 relative" style={{ background: "var(--surface-2)" }}>
                            <div className="absolute top-3 right-3 text-xs font-bold font-mono" style={{ color: "var(--accent)", opacity: 0.5 }}>{step}</div>
                            <div className="font-semibold text-sm mb-1 font-mono" style={{ color: "var(--text)" }}>{title}</div>
                            <div className="text-xs" style={{ color: "var(--text-3)" }}>{desc}</div>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}
