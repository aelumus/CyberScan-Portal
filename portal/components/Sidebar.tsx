"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard, Search, List, Shield, Database,
  Settings, Info, Activity, ChevronRight, GitCompare
} from "lucide-react";

const navItems = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/scan", label: "New Scan", icon: Search, highlight: true },
  { href: "/scans", label: "Scan History", icon: List },
  { href: "/compare", label: "Compare Scans", icon: GitCompare },
  { href: "/models", label: "ML Models", icon: Activity },
  { href: "/datasets", label: "Datasets", icon: Database },
  { href: "/settings", label: "Settings", icon: Settings },
  { href: "/about", label: "About", icon: Info },
];

export default function Sidebar({ onClose }: { onClose?: () => void }) {
  const pathname = usePathname();
  return (
    <aside className="w-64 min-h-screen flex-shrink-0 flex flex-col relative transition-all duration-300"
      style={{ background: "var(--sidebar-bg)", borderRight: "1px solid var(--border)", backdropFilter: "blur(24px)" }}>

      {/* Gradient orb */}
      <div className="absolute top-0 left-0 w-full h-48 pointer-events-none"
        style={{ background: "radial-gradient(ellipse at 30% 0%, rgba(99,102,241,0.1), transparent 70%)" }} />

      {/* Logo */}
      <div className="relative flex items-center gap-3 px-5 py-5" style={{ borderBottom: "1px solid var(--border)" }}>
        <div className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0"
          style={{ background: "linear-gradient(135deg,#4f46e5,#7c3aed)" }}>
          <Shield size={17} className="text-white" />
        </div>
        <div>
          <div className="font-black text-sm leading-tight" style={{ color: "var(--text)" }}>
            CyberScan<span style={{ color: "#818cf8" }}>.</span>
          </div>
          <div className="text-xs" style={{ color: "var(--text-3)" }}>Detection Portal</div>
        </div>
      </div>

      {/* Nav */}
      <nav className="relative flex-1 px-3 py-4 space-y-0.5">
        <div className="text-xs font-semibold uppercase tracking-widest px-3 mb-3" style={{ color: "var(--text-3)" }}>Navigation</div>
        {navItems.map(({ href, label, icon: Icon }) => {
          const active = pathname === href || pathname.startsWith(href + "/");
          return (
            <Link key={href} href={href}
              onClick={onClose}
              className="flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all duration-200 group"
              style={active ? {
                background: "var(--accent-bg)",
                border: "1px solid var(--accent-brd)",
                color: "var(--accent)",
              } : {
                color: "var(--text-3)",
                border: "1px solid transparent",
              }}>
              <Icon size={16} className="shrink-0" />
              <span className="flex-1">{label}</span>
              {active && <ChevronRight size={12} className="opacity-50" />}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="relative px-4 py-4" style={{ borderTop: "1px solid var(--border)" }}>
        <div className="flex items-center gap-2 mb-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          <span className="text-xs text-emerald-500 font-medium">All systems online</span>
        </div>
        <div className="text-xs font-mono" style={{ color: "var(--text-3)" }}>RF · XGB · LGB · FastAPI</div>
        <div className="text-xs mt-0.5" style={{ color: "var(--text-3)", opacity: 0.5 }}>v2.0 · 2026</div>
      </div>
    </aside>
  );
}
