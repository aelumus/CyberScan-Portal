"use client";
import { usePathname, useRouter } from "next/navigation";
import { Bell, Zap, Sun, Moon, LogOut, User, Menu } from "lucide-react";
import Link from "next/link";
import { useTheme } from "@/components/ThemeProvider";
import { useAuth } from "@/components/AuthProvider";

const titles: Record<string, { label: string; desc: string }> = {
    "/dashboard": { label: "Dashboard", desc: "Security overview & analytics" },
    "/scan": { label: "New Scan", desc: "Upload & analyze a binary" },
    "/scans": { label: "Scan History", desc: "All previous analysis results" },
    "/compare": { label: "Compare Scans", desc: "Side-by-side scan comparison" },
    "/models": { label: "ML Models", desc: "Random Forest · XGBoost · LightGBM" },
    "/datasets": { label: "Datasets", desc: "Training data & feature info" },
    "/settings": { label: "Settings", desc: "API keys & detection parameters" },
    "/about": { label: "About", desc: "System architecture & tech stack" },
};

export default function Topbar({ onMenuClick }: { onMenuClick?: () => void }) {
    const pathname = usePathname();
    const { theme, toggle } = useTheme();
    const { user, logout } = useAuth();
    const router = useRouter();
    const base = "/" + pathname.split("/")[1];
    const page = titles[base] ?? { label: "CyberScan", desc: "Malware detection portal" };
    const isLight = theme === "light";
    const initials = user?.username?.slice(0, 2).toUpperCase() ?? "?";

    const handleLogout = () => {
        logout();
        router.push("/login");
    };

    return (
        <header className="h-14 flex items-center justify-between px-6 flex-shrink-0 transition-all duration-300"
            style={{
                background: "var(--topbar-bg)",
                borderBottom: "1px solid var(--border)",
                backdropFilter: "blur(20px)",
            }}>
            <div className="flex items-center gap-3">
                {onMenuClick && (
                    <button onClick={onMenuClick} className="md:hidden p-1.5 rounded-lg hover:bg-white/5 transition-colors" style={{ color: "var(--text)" }}>
                        <Menu size={20} />
                    </button>
                )}
                <h1 className="font-bold text-sm" style={{ color: "var(--text)" }}>{page.label}</h1>
                <span style={{ color: "var(--text-3)" }} className="text-xs hidden sm:block">/</span>
                <span style={{ color: "var(--text-3)" }} className="text-xs hidden sm:block">{page.desc}</span>
            </div>
            <div className="flex items-center gap-2">
                <Link href="/scan"
                    className="hidden sm:flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-lg transition-all duration-200"
                    style={{ background: "var(--accent-bg)", border: "1px solid var(--accent-brd)", color: "var(--accent)" }}>
                    <Zap size={12} /> Quick Scan
                </Link>

                {/* Theme toggle */}
                <button onClick={toggle}
                    className="p-2 rounded-lg transition-all duration-300 hover:scale-110"
                    style={{ background: "var(--accent-bg)", border: "1px solid var(--border)", color: "var(--accent)" }}
                    title={isLight ? "Switch to Dark" : "Switch to Light"}>
                    {isLight ? <Moon size={15} /> : <Sun size={15} />}
                </button>

                <button className="p-2 rounded-lg transition-colors" style={{ color: "var(--text-3)" }}>
                    <Bell size={16} />
                </button>

                {/* User chip */}
                <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl"
                    style={{ border: "1px solid var(--border)", background: "var(--surface)" }}>
                    <div className="w-6 h-6 rounded-lg flex items-center justify-center text-white text-xs font-black"
                        style={{ background: "linear-gradient(135deg,#4f46e5,#7c3aed)" }}>
                        {user ? initials : <User size={12} />}
                    </div>
                    <span className="text-xs font-medium hidden sm:block" style={{ color: "var(--text-2)" }}>
                        {user?.username ?? "Analyst"}
                    </span>
                    {user && (
                        <button onClick={handleLogout} title="Sign out"
                            className="ml-1 p-0.5 rounded transition-colors hover:text-red-400"
                            style={{ color: "var(--text-3)" }}>
                            <LogOut size={13} />
                        </button>
                    )}
                </div>
            </div>
        </header>
    );
}
