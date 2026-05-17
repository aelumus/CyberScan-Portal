"use client";
import { useState } from "react";
import { useAuth } from "@/components/AuthProvider";
import { useRouter } from "next/navigation";
import { useEffect } from "react";
import Sidebar from "@/components/Sidebar";
import Topbar from "@/components/Topbar";
import type { ReactNode } from "react";
import { Loader2 } from "lucide-react";

export default function AppLayout({ children }: { children: ReactNode }) {
    const { loading, user } = useAuth();
    const router = useRouter();
    const [sidebarOpen, setSidebarOpen] = useState(false);

    useEffect(() => {
        if (!loading && !user) router.push("/login");
    }, [loading, user, router]);

    if (loading) return (
        <div className="min-h-screen flex items-center justify-center" style={{ background: "var(--bg-grad)" }}>
            <div className="flex flex-col items-center gap-4">
                <div className="w-12 h-12 rounded-2xl flex items-center justify-center"
                    style={{ background: "linear-gradient(135deg,#4f46e5,#7c3aed)" }}>
                    <Loader2 size={22} className="text-white animate-spin" />
                </div>
                <p className="text-sm" style={{ color: "var(--text-3)" }}>Loading CyberScan…</p>
            </div>
        </div>
    );

    if (!user) return null;

    return (
        <div className="flex min-h-screen" style={{ background: "var(--bg)" }}>
            <div className={`fixed inset-0 z-40 md:hidden transition-opacity duration-300 ${sidebarOpen ? "opacity-100 pointer-events-auto" : "opacity-0 pointer-events-none"}`}
                style={{ background: "rgba(0,0,0,0.5)" }}
                onClick={() => setSidebarOpen(false)} />
            <div className={`fixed left-0 top-0 z-50 h-full transition-transform duration-300 md:hidden ${sidebarOpen ? "translate-x-0" : "-translate-x-full"}`}>
                <Sidebar onClose={() => setSidebarOpen(false)} />
            </div>
            <div className="hidden md:flex">
                <Sidebar />
            </div>
            <div className="flex-1 flex flex-col min-h-screen min-w-0">
                <Topbar onMenuClick={() => setSidebarOpen(true)} />
                <main className="flex-1 p-6 overflow-auto">{children}</main>
            </div>
        </div>
    );
}
