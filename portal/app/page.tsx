"use client";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import {
  Shield, ArrowRight, Cpu, Lock, Zap, ChevronRight,
  Activity, AlertTriangle, CheckCircle, BarChart2, Sun, Moon
} from "lucide-react";
import { useTheme } from "@/components/ThemeProvider";

/* ─── Animated floating particle background ─── */
function ParticleCanvas({ light }: { light: boolean }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = ref.current!;
    const ctx = canvas.getContext("2d")!;
    let raf: number;
    const resize = () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; };
    resize();
    window.addEventListener("resize", resize);
    const N = 70;
    const pts = Array.from({ length: N }, () => ({
      x: Math.random() * window.innerWidth,
      y: Math.random() * window.innerHeight,
      vx: (Math.random() - 0.5) * 0.3,
      vy: (Math.random() - 0.5) * 0.3,
      r: Math.random() * 1.5 + 0.5,
    }));
    const dotColor = light ? "rgba(99,102,241,0.3)" : "rgba(99,102,241,0.55)";
    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      pts.forEach(p => {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
        if (p.y < 0 || p.y > canvas.height) p.vy *= -1;
        ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = dotColor; ctx.fill();
      });
      for (let i = 0; i < N; i++) for (let j = i + 1; j < N; j++) {
        const dx = pts[i].x - pts[j].x, dy = pts[i].y - pts[j].y;
        const d = Math.sqrt(dx * dx + dy * dy);
        if (d < 130) {
          ctx.beginPath(); ctx.moveTo(pts[i].x, pts[i].y); ctx.lineTo(pts[j].x, pts[j].y);
          ctx.strokeStyle = `rgba(99,102,241,${(light ? 0.08 : 0.12) * (1 - d / 130)})`;
          ctx.lineWidth = 0.6; ctx.stroke();
        }
      }
      raf = requestAnimationFrame(draw);
    };
    draw();
    return () => { cancelAnimationFrame(raf); window.removeEventListener("resize", resize); };
  }, [light]);
  return <canvas ref={ref} className="absolute inset-0 pointer-events-none" />;
}

/* ─── Counting number animation ─── */
function CountUp({ target, suffix = "" }: { target: number; suffix?: string }) {
  const [val, setVal] = useState(0);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const obs = new IntersectionObserver(([e]) => {
      if (!e.isIntersecting) return;
      let start = 0;
      const step = target / 60;
      const t = setInterval(() => {
        start += step;
        if (start >= target) { setVal(target); clearInterval(t); } else setVal(Math.floor(start));
      }, 16);
      obs.disconnect();
    }, { threshold: 0.4 });
    if (ref.current) obs.observe(ref.current);
    return () => obs.disconnect();
  }, [target]);
  return <div ref={ref} className="tabular-nums">{val}{suffix}</div>;
}

/* ─── Scan ticker ─── */
const TICKER = [
  { name: "ransomware_v2.exe", verdict: "Malicious", rf: 94, xgb: 97, lgb: 99 },
  { name: "setup_installer.exe", verdict: "Benign", rf: 8, xgb: 12, lgb: 6 },
  { name: "keylogger_x86.exe", verdict: "Malicious", rf: 88, xgb: 91, lgb: 95 },
  { name: "notepad_patch.exe", verdict: "Suspicious", rf: 52, xgb: 61, lgb: 58 },
  { name: "system_update.dll", verdict: "Benign", rf: 4, xgb: 7, lgb: 3 },
];

export default function LandingPage() {
  const [tick, setTick] = useState(0);
  const { theme, toggle } = useTheme();
  const light = theme === "light";

  useEffect(() => {
    const id = setInterval(() => setTick(t => (t + 1) % TICKER.length), 2800);
    return () => clearInterval(id);
  }, []);
  const cur = TICKER[tick];

  const bg = light
    ? "linear-gradient(135deg,#eef2ff 0%,#f5f3ff 50%,#fdf4ff 100%)"
    : "linear-gradient(135deg,#020617 0%,#0a0f2e 40%,#060d1f 100%)";

  const cardBg = light ? "rgba(255,255,255,0.85)" : "rgba(15,23,42,0.7)";
  const cardBorder = light ? "rgba(99,102,241,0.15)" : "rgba(255,255,255,0.08)";
  const navBorder = light ? "rgba(99,102,241,0.1)" : "rgba(255,255,255,0.05)";
  const textMuted = light ? "#64748b" : "#94a3b8";
  const textDimmed = light ? "#94a3b8" : "#475569";
  const headingColor = light ? "#0f172a" : "#ffffff";

  const getBadgeStyle = (verdict: string) => {
    if (verdict === "Malicious") return { background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.2)", color: "#f87171" };
    if (verdict === "Suspicious") return { background: "rgba(245,158,11,0.1)", border: "1px solid rgba(245,158,11,0.2)", color: "#fbbf24" };
    return { background: "rgba(16,185,129,0.1)", border: "1px solid rgba(16,185,129,0.2)", color: "#34d399" };
  };
  const verdictScore = cur.verdict === "Malicious" ? cur.rf : cur.verdict === "Suspicious" ? cur.xgb : cur.lgb;
  const scoreColor = verdictScore >= 60 ? "#f87171" : verdictScore >= 40 ? "#fbbf24" : "#34d399";

  return (
    <div className="relative min-h-screen overflow-x-hidden transition-all duration-500" style={{ background: bg }}>
      <ParticleCanvas light={light} />

      {/* Gradient orbs */}
      <div className="absolute top-[-10%] left-[-5%] w-[500px] h-[500px] rounded-full pointer-events-none"
        style={{ background: "radial-gradient(circle,#4f46e5 0%,transparent 70%)", filter: "blur(60px)", opacity: light ? 0.07 : 0.18 }} />
      <div className="absolute bottom-[-5%] right-[-5%] w-[400px] h-[400px] rounded-full pointer-events-none"
        style={{ background: "radial-gradient(circle,#7c3aed 0%,transparent 70%)", filter: "blur(60px)", opacity: light ? 0.07 : 0.13 }} />

      {/* ── NAV ── */}
      <nav className="relative z-10 flex items-center justify-between px-8 py-5 backdrop-blur-sm"
        style={{ borderBottom: `1px solid ${navBorder}` }}>
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl flex items-center justify-center"
            style={{ background: "linear-gradient(135deg,#4f46e5,#7c3aed)" }}>
            <Shield size={18} className="text-white" />
          </div>
          <span className="font-semibold text-lg tracking-tight" style={{ color: headingColor }}>
            CyberScan<span className="text-indigo-400">.</span>
          </span>
        </div>
        <div className="hidden md:flex items-center gap-8 text-sm" style={{ color: textMuted }}>
          <Link href="/about" className="hover:text-indigo-500 transition-colors">About</Link>
          <Link href="/datasets" className="hover:text-indigo-500 transition-colors">Datasets</Link>
          <Link href="/scans" className="hover:text-indigo-500 transition-colors">History</Link>
        </div>
        <div className="flex items-center gap-2">
          {/* Theme toggle */}
          <button onClick={toggle}
            className="p-2 rounded-xl transition-all duration-300 hover:scale-110"
            style={{ background: "rgba(99,102,241,0.1)", border: "1px solid rgba(99,102,241,0.2)", color: "#818cf8" }}>
            {light ? <Moon size={15} /> : <Sun size={15} />}
          </button>
          <Link href="/scan"
            className="flex items-center gap-2 text-sm font-medium px-4 py-2 rounded-xl transition-all duration-200"
            style={{ border: "1px solid rgba(99,102,241,0.35)", color: "#818cf8", background: "rgba(99,102,241,0.08)" }}>
            Launch App <ChevronRight size={15} />
          </Link>
        </div>
      </nav>

      {/* ── HERO ── */}
      <section className="relative z-10 flex flex-col items-center text-center px-6 pt-28 pb-20">
        <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full text-xs font-medium mb-8"
          style={{ border: "1px solid rgba(99,102,241,0.25)", background: "rgba(99,102,241,0.08)", color: "#818cf8", animation: "fadeDown 0.6s ease both" }}>
          <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 animate-pulse" />
          v2.0 · 3 ML models · PE Static Analysis
        </div>

        <h1 className="text-5xl md:text-7xl font-black leading-[1.05] tracking-tight mb-6"
          style={{ color: headingColor, animation: "fadeUp 0.7s 0.1s ease both" }}>
          Detect Malware<br />
          <span style={{ background: "linear-gradient(90deg,#818cf8,#c084fc,#fb7185)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>
            Before It Strikes
          </span>
        </h1>

        <p className="max-w-xl text-lg leading-relaxed mb-10" style={{ color: textMuted, animation: "fadeUp 0.7s 0.2s ease both" }}>
          Military-grade static analysis powered by Random Forest, XGBoost and LightGBM.
          Upload a binary, get a verdict in seconds.
        </p>

        <div className="flex flex-wrap gap-4 justify-center" style={{ animation: "fadeUp 0.7s 0.3s ease both" }}>
          <Link href="/scan"
            className="group flex items-center gap-2 px-7 py-3.5 rounded-2xl font-semibold text-white text-sm transition-all duration-300 hover:scale-105 hover:shadow-2xl hover:shadow-indigo-500/30"
            style={{ background: "linear-gradient(135deg,#4f46e5,#7c3aed)" }}>
            Start Scanning
            <ArrowRight size={17} className="group-hover:translate-x-1 transition-transform" />
          </Link>
          <Link href="/dashboard"
            className="flex items-center gap-2 px-7 py-3.5 rounded-2xl font-semibold text-sm transition-all duration-200"
            style={{ border: `1px solid ${cardBorder}`, background: cardBg, color: textMuted, backdropFilter: "blur(12px)" }}>
            Dashboard
          </Link>
        </div>
      </section>

      {/* ── LIVE SCAN TICKER ── */}
      <section className="relative z-10 flex justify-center px-6 mb-20">
        <div className="w-full max-w-3xl rounded-2xl overflow-hidden"
          style={{ background: cardBg, border: `1px solid ${cardBorder}`, backdropFilter: "blur(20px)" }}>
          <div className="flex items-center gap-2 px-5 py-3 text-xs" style={{ borderBottom: `1px solid ${cardBorder}`, color: textDimmed }}>
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            Live scan feed
          </div>
          <div className="px-5 py-4 transition-all duration-700" key={tick}>
            <div className="flex items-center justify-between flex-wrap gap-3">
              <div className="flex items-center gap-3">
                <Activity size={15} style={{ color: textDimmed }} />
                <span className="font-mono text-sm" style={{ color: headingColor }}>{cur.name}</span>
                <span className="text-xs font-semibold px-2 py-0.5 rounded-full" style={getBadgeStyle(cur.verdict)}>{cur.verdict}</span>
              </div>
              <div className="flex gap-5 text-xs" style={{ color: textMuted }}>
                <span>RF <span className="font-bold" style={{ color: scoreColor }}>{cur.rf}%</span></span>
                <span>XGB <span className="font-bold" style={{ color: scoreColor }}>{cur.xgb}%</span></span>
                <span>LGB <span className="font-bold" style={{ color: scoreColor }}>{cur.lgb}%</span></span>
              </div>
            </div>
            <div className="mt-3 grid grid-cols-3 gap-2">
              {[["RF", cur.rf], ["XGB", cur.xgb], ["LGB", cur.lgb]].map(([label, pct]) => (
                <div key={label}>
                  <div className="text-xs mb-1" style={{ color: textDimmed }}>{label}</div>
                  <div className="h-1.5 rounded-full overflow-hidden" style={{ background: light ? "rgba(99,102,241,0.1)" : "rgba(255,255,255,0.05)" }}>
                    <div className="h-full rounded-full transition-all duration-700"
                      style={{
                        width: `${pct}%`,
                        background: Number(pct) >= 60 ? "linear-gradient(90deg,#ef4444,#dc2626)" :
                          Number(pct) >= 40 ? "linear-gradient(90deg,#f59e0b,#d97706)" :
                            "linear-gradient(90deg,#10b981,#059669)"
                      }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ── STATS ── */}
      <section className="relative z-10 max-w-5xl mx-auto px-6 mb-24">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { icon: <Cpu size={22} />, val: 3, suffix: "", label: "ML Models", sub: "RF · XGBoost · LightGBM", color: "#818cf8" },
            { icon: <BarChart2 size={22} />, val: 54, suffix: "", label: "PE Features", sub: "Extracted per binary", color: "#c084fc" },
            { icon: <Zap size={22} />, val: 2, suffix: "s", label: "Avg Scan Time", sub: "Real-time analysis", color: "#fb7185" },
            { icon: <Lock size={22} />, val: 95, suffix: "%", label: "Detection Rate", sub: "On training set", color: "#34d399" },
          ].map(({ icon, val, suffix, label, sub, color }) => (
            <div key={label} className="group relative rounded-2xl p-5 overflow-hidden transition-all duration-300 hover:-translate-y-1"
              style={{ background: cardBg, border: `1px solid ${cardBorder}`, backdropFilter: "blur(16px)" }}
              onMouseEnter={e => (e.currentTarget.style.boxShadow = `0 16px 40px ${color}20`)}
              onMouseLeave={e => (e.currentTarget.style.boxShadow = "")}>
              <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none"
                style={{ background: `radial-gradient(circle at 50% 0%, ${color}12, transparent 70%)` }} />
              <div className="mb-3" style={{ color }}>{icon}</div>
              <div className="text-3xl font-black mb-1" style={{ color: headingColor }}>
                <CountUp target={val} suffix={suffix} />
              </div>
              <div className="text-sm font-semibold mb-0.5" style={{ color: headingColor, opacity: 0.8 }}>{label}</div>
              <div className="text-xs" style={{ color: textDimmed }}>{sub}</div>
            </div>
          ))}
        </div>
      </section>

      {/* ── 3 ML MODELS ── */}
      <section className="relative z-10 max-w-5xl mx-auto px-6 mb-24">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-black mb-3" style={{ color: headingColor }}>
            Three Models. One{" "}
            <span style={{ background: "linear-gradient(90deg,#818cf8,#c084fc)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>
              Verdict.
            </span>
          </h2>
          <p className="text-sm max-w-md mx-auto" style={{ color: textMuted }}>
            Ensemble of three industry-standard algorithms vote on every binary for maximum accuracy.
          </p>
        </div>

        <div className="grid md:grid-cols-3 gap-5">
          {[
            { name: "Random Forest", abbr: "RF", desc: "Ensemble of 100 decision trees trained on PE header features. Robust against overfitting.", badge: "scikit-learn", accuracy: "97.1%", icon: "🌲", glow: "#4f46e5", accent: "#818cf8" },
            { name: "XGBoost", abbr: "XGB", desc: "Gradient boosted trees with regularisation. Excels at tabular PE header data.", badge: "xgboost.json", accuracy: "97.5%", icon: "⚡", glow: "#7c3aed", accent: "#a78bfa" },
            { name: "LightGBM", abbr: "LGB", desc: "Leaf-wise gradient boost. Fastest inference, high recall on packed malware samples.", badge: "lgbm.txt", accuracy: "97.9%", icon: "🔥", glow: "#ec4899", accent: "#f472b6" },
          ].map(m => (
            <div key={m.name} className="group relative rounded-2xl p-6 transition-all duration-300 hover:-translate-y-2 overflow-hidden"
              style={{ background: cardBg, border: `1px solid ${cardBorder}`, backdropFilter: "blur(16px)" }}
              onMouseEnter={e => (e.currentTarget.style.boxShadow = `0 20px 60px ${m.glow}25`)}
              onMouseLeave={e => (e.currentTarget.style.boxShadow = "")}>
              <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none"
                style={{ background: `radial-gradient(circle at 50% 0%, ${m.glow}10, transparent 70%)` }} />
              <div className="text-3xl mb-4">{m.icon}</div>
              <div className="flex items-center gap-2 mb-2">
                <span className="font-bold text-lg" style={{ color: headingColor }}>{m.name}</span>
                <span className="text-xs px-2 py-0.5 rounded-full font-mono" style={{ background: `${m.accent}18`, border: `1px solid ${m.accent}28`, color: m.accent }}>{m.abbr}</span>
              </div>
              <p className="text-sm leading-relaxed mb-5" style={{ color: textMuted }}>{m.desc}</p>
              <div className="flex items-center justify-between text-xs">
                <span className="font-mono" style={{ color: textDimmed }}>{m.badge}</span>
                <span className="text-emerald-500 font-bold">{m.accuracy} accuracy</span>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ── HOW IT WORKS ── */}
      <section className="relative z-10 max-w-4xl mx-auto px-6 mb-24">
        <h2 className="text-2xl font-black text-center mb-10" style={{ color: headingColor }}>
          How It <span style={{ background: "linear-gradient(90deg,#818cf8,#c084fc)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>Works</span>
        </h2>
        <div className="grid md:grid-cols-4 gap-4">
          {[
            { step: "01", icon: <Shield size={20} />, title: "Upload Binary", body: "Drop any .exe or .dll (x86/x64)" },
            { step: "02", icon: <Cpu size={20} />, title: "Extract 54 Features", body: "pefile parses PE headers, sections, imports, resources" },
            { step: "03", icon: <Activity size={20} />, title: "3-Model Ensemble", body: "RF · XGBoost · LightGBM vote in parallel" },
            { step: "04", icon: <CheckCircle size={20} />, title: "Verdict + Report", body: "Score, risk, features, optional VirusTotal check" },
          ].map(({ step, icon, title, body }) => (
            <div key={step} className="relative rounded-2xl p-5 text-center"
              style={{ background: cardBg, border: `1px solid ${cardBorder}`, backdropFilter: "blur(12px)" }}>
              <div className="absolute -top-3 left-1/2 -translate-x-1/2 text-xs font-bold px-2 py-0.5 rounded-full"
                style={{ background: "rgba(99,102,241,0.12)", border: "1px solid rgba(99,102,241,0.25)", color: "#818cf8" }}>{step}</div>
              <div className="flex justify-center mb-3 mt-2" style={{ color: "#818cf8" }}>{icon}</div>
              <div className="font-semibold text-sm mb-1" style={{ color: headingColor }}>{title}</div>
              <div className="text-xs leading-relaxed" style={{ color: textDimmed }}>{body}</div>
            </div>
          ))}
        </div>
      </section>

      {/* ── CTA ── */}
      <section className="relative z-10 flex flex-col items-center text-center px-6 pb-28">
        <div className="relative rounded-3xl px-12 py-14 overflow-hidden max-w-2xl w-full"
          style={{ background: cardBg, border: `1px solid ${cardBorder}`, backdropFilter: "blur(24px)" }}>
          <div className="absolute inset-0 pointer-events-none"
            style={{ background: "radial-gradient(ellipse at 50% 0%,rgba(99,102,241,0.1),transparent 70%)" }} />
          <AlertTriangle size={36} className="text-indigo-400 mx-auto mb-5" />
          <h2 className="text-3xl font-black mb-3" style={{ color: headingColor }}>Ready to scan?</h2>
          <p className="mb-8 text-sm max-w-sm mx-auto" style={{ color: textMuted }}>
            Upload an executable and get a detailed malware report with model scores and VirusTotal integration.
          </p>
          <Link href="/scan"
            className="inline-flex items-center gap-2 px-8 py-4 rounded-2xl font-bold text-white transition-all duration-300 hover:scale-105 hover:shadow-2xl hover:shadow-indigo-500/30"
            style={{ background: "linear-gradient(135deg,#4f46e5,#7c3aed)" }}>
            Scan a File Now <ArrowRight size={18} />
          </Link>
          <p className="text-xs mt-6" style={{ color: textDimmed }}>Diploma Project · Computer Science · 2026</p>
        </div>
      </section>

      {/* ── FOOTER ── */}
      <footer className="relative z-10 px-8 py-6 flex items-center justify-between text-xs"
        style={{ borderTop: `1px solid ${navBorder}`, color: textDimmed }}>
        <span className="flex items-center gap-2">
          <Shield size={13} className="text-indigo-400" /> CyberScan Portal
        </span>
        <span>ML-powered malware detection · 2026</span>
      </footer>

      <style>{`
                @keyframes fadeUp{from{opacity:0;transform:translateY(24px)}to{opacity:1;transform:translateY(0)}}
                @keyframes fadeDown{from{opacity:0;transform:translateY(-12px)}to{opacity:1;transform:translateY(0)}}
            `}</style>
    </div>
  );
}
