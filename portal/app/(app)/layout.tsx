"use client";
import { useEffect, useState, type ReactNode } from "react";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "@/components/AuthProvider";
import Sidebar from "@/components/Sidebar";
import Topbar from "@/components/Topbar";

function AuthGuard({ children }: { children: ReactNode }) {
    const { user, loading } = useAuth();
    const router = useRouter();
    const pathname = usePathname();
    const [isSidebarOpen, setIsSidebarOpen] = useState(false);

    // Close sidebar on route change on mobile
    useEffect(() => {
        const timeoutId = window.setTimeout(() => {
            setIsSidebarOpen(false);
        }, 0);

        return () => {
            window.clearTimeout(timeoutId);
        };
    }, [pathname]);

    useEffect(() => {
        if (!loading && !user) {
            router.push("/login");
        }
    }, [user, loading, router]);

    if (loading) {
        return (
            <div className="flex items-center justify-center min-h-screen" style={{ background: "var(--bg-grad)" }}>
                <div className="flex flex-col items-center gap-4">
                    <div className="w-12 h-12 rounded-2xl flex items-center justify-center animate-pulse"
                        style={{ background: "linear-gradient(135deg,#4f46e5,#7c3aed)" }}>
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                        </svg>
                    </div>
                    <p className="text-xs font-medium" style={{ color: "var(--text-3)" }}>Authenticating…</p>
                </div>
            </div>
        );
    }

    if (!user) return null;

    return (
        <div className="flex h-screen overflow-hidden" style={{ background: "var(--bg-grad)" }}>
            {/* Mobile Overlay */}
            {isSidebarOpen && (
                <div
                    className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm md:hidden"
                    onClick={() => setIsSidebarOpen(false)}
                />
            )}

            {/* Sidebar */}
            <div className={`fixed inset-y-0 left-0 z-50 transform transition-transform duration-300 ease-in-out md:static md:translate-x-0 ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full'}`}>
                <Sidebar onClose={() => setIsSidebarOpen(false)} />
            </div>

            {/* Main Content */}
            <div className="flex flex-col flex-1 h-screen overflow-hidden min-w-0">
                <Topbar onMenuClick={() => setIsSidebarOpen(!isSidebarOpen)} />
                <main className="flex-1 overflow-x-hidden overflow-y-auto bg-transparent p-4 md:p-6" id="main-scroll">
                    {children}
                </main>
            </div>
        </div>
    );
}

export default function AppLayout({ children }: { children: ReactNode }) {
    return <AuthGuard>{children}</AuthGuard>;
}
