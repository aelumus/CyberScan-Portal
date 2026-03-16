import { Shield } from "lucide-react";
import type { CSSProperties, ReactNode } from "react";

const ORB_STYLES: Record<"login" | "register", Array<{ className: string; style: CSSProperties }>> = {
    login: [
        {
            className: "fixed top-[-10%] left-[-5%] h-96 w-96 rounded-full pointer-events-none",
            style: {
                background: "radial-gradient(circle,#4f46e5,transparent 70%)",
                filter: "blur(60px)",
                opacity: 0.15,
            },
        },
        {
            className: "fixed bottom-[-5%] right-[-5%] h-80 w-80 rounded-full pointer-events-none",
            style: {
                background: "radial-gradient(circle,#7c3aed,transparent 70%)",
                filter: "blur(60px)",
                opacity: 0.12,
            },
        },
    ],
    register: [
        {
            className: "fixed top-[-10%] right-[-5%] h-96 w-96 rounded-full pointer-events-none",
            style: {
                background: "radial-gradient(circle,#7c3aed,transparent 70%)",
                filter: "blur(60px)",
                opacity: 0.15,
            },
        },
        {
            className: "fixed bottom-[-5%] left-[-5%] h-80 w-80 rounded-full pointer-events-none",
            style: {
                background: "radial-gradient(circle,#4f46e5,transparent 70%)",
                filter: "blur(60px)",
                opacity: 0.12,
            },
        },
    ],
};

interface AuthShellProps {
    variant: "login" | "register";
    subtitle: string;
    cardTitle: string;
    footer: ReactNode;
    children: ReactNode;
    bottomNote?: ReactNode;
}

export function AuthShell({ variant, subtitle, cardTitle, footer, children, bottomNote }: AuthShellProps) {
    return (
        <div
            className={`min-h-screen flex items-center justify-center px-4 ${variant === "register" ? "py-8" : ""}`}
            style={{ background: "var(--bg-grad)" }}
        >
            {ORB_STYLES[variant].map((orb, index) => (
                <div key={index} aria-hidden="true" className={orb.className} style={orb.style} />
            ))}

            <div className="relative z-10 w-full max-w-md">
                <div className="mb-8 flex flex-col items-center">
                    <div
                        className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl"
                        style={{
                            background: "linear-gradient(135deg,#4f46e5,#7c3aed)",
                            boxShadow: "0 0 40px rgba(99,102,241,0.4)",
                        }}
                    >
                        <Shield size={28} className="text-white" />
                    </div>
                    <h1 className="text-2xl font-black" style={{ color: "var(--text)" }}>
                        CyberScan<span className="text-indigo-400">.</span>
                    </h1>
                    <p className="mt-1 text-sm" style={{ color: "var(--text-3)" }}>
                        {subtitle}
                    </p>
                </div>

                <div
                    className="rounded-2xl p-8"
                    style={{
                        background: "var(--surface)",
                        border: "1px solid var(--border)",
                        backdropFilter: "blur(20px)",
                    }}
                >
                    <h2 className="mb-6 text-lg font-bold" style={{ color: "var(--text)" }}>
                        {cardTitle}
                    </h2>
                    {children}
                    {footer}
                </div>

                {bottomNote ? (
                    <div className="mt-6 text-center text-xs" style={{ color: "var(--text-3)" }}>
                        {bottomNote}
                    </div>
                ) : null}
            </div>
        </div>
    );
}
