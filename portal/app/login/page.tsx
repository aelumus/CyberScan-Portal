"use client";
import Link from "next/link";
import { useState } from "react";
import { useAuth } from "@/components/AuthProvider";
import { AuthAlert, AuthField, AuthPasswordField, AuthSubmitButton } from "@/components/auth/AuthFormControls";
import { AuthShell } from "@/components/auth/AuthShell";

export default function LoginPage() {
    const { login } = useAuth();
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [showPass, setShowPass] = useState(false);
    const [loading, setLoading] = useState(false);
    const [errMsg, setErrMsg] = useState("");

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setErrMsg(""); setLoading(true);
        try {
            await login(email, password);
        } catch (err: unknown) {
            setErrMsg(err instanceof Error ? err.message : "Login failed");
        } finally {
            setLoading(false);
        }
    };

    return (
        <AuthShell variant="login" subtitle="Sign in to your account" cardTitle="Welcome back"
            footer={(
                <p className="mt-6 text-center text-sm" style={{ color: "var(--text-3)" }}>
                    No account?{" "}
                    <Link href="/register" className="font-semibold" style={{ color: "var(--accent)" }}>Create one</Link>
                </p>
            )}>
            {errMsg ? <AuthAlert message={errMsg} /> : null}
            <form onSubmit={handleSubmit} className="space-y-4">
                <AuthField label="Email" type="email" value={email} onChange={setEmail}
                    required placeholder="you@example.com" autoComplete="email" />
                <AuthPasswordField label="Password" value={password} onChange={setPassword}
                    visible={showPass} placeholder="••••••••" autoComplete="current-password"
                    onToggleVisibility={() => setShowPass(v => !v)} />
                <AuthSubmitButton loading={loading} loadingLabel="Signing in…" label="Sign In" />
            </form>
        </AuthShell>
    );
}
