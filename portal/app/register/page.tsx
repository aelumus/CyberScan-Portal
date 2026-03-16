"use client";
import Link from "next/link";
import { useState } from "react";
import { useAuth } from "@/components/AuthProvider";
import {
    AuthAlert,
    AuthField,
    AuthPasswordField,
    AuthSubmitButton,
    ConfirmPasswordAdornment,
    PasswordStrengthIndicator,
} from "@/components/auth/AuthFormControls";
import { AuthShell } from "@/components/auth/AuthShell";

export default function RegisterPage() {
    const { register } = useAuth();
    const [username, setUsername] = useState("");
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [confirm, setConfirm] = useState("");
    const [showPass, setShowPass] = useState(false);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");
    const passwordsMatch = confirm.length > 0 && confirm === password;

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError("");
        if (password !== confirm) { setError("Passwords do not match"); return; }
        if (password.length < 6) { setError("Password must be at least 6 characters"); return; }
        setLoading(true);
        try {
            await register(username, email, password);
        } catch (err: unknown) {
            setError(err instanceof Error ? err.message : "Registration failed");
        } finally {
            setLoading(false);
        }
    };

    return (
        <AuthShell
            variant="register"
            subtitle="Create your account"
            cardTitle="Create account"
            footer={(
                <p className="mt-6 text-center text-sm" style={{ color: "var(--text-3)" }}>
                    Already have an account?{" "}
                    <Link href="/login" className="font-semibold" style={{ color: "var(--accent)" }}>
                        Sign in
                    </Link>
                </p>
            )}
        >
            {error ? <AuthAlert message={error} /> : null}

            <form onSubmit={handleSubmit} className="space-y-4">
                <AuthField
                    label="Username"
                    type="text"
                    value={username}
                    onChange={setUsername}
                    required
                    minLength={2}
                    placeholder="analyst"
                    autoComplete="username"
                />

                <AuthField
                    label="Email"
                    type="email"
                    value={email}
                    onChange={setEmail}
                    required
                    placeholder="you@example.com"
                    autoComplete="email"
                />

                <div>
                    <AuthPasswordField
                        label="Password"
                        value={password}
                        onChange={setPassword}
                        visible={showPass}
                        placeholder="••••••••"
                        autoComplete="new-password"
                        onToggleVisibility={() => setShowPass((value) => !value)}
                    />
                    <PasswordStrengthIndicator password={password} />
                </div>

                <AuthPasswordField
                    label="Confirm Password"
                    value={confirm}
                    onChange={setConfirm}
                    visible={showPass}
                    placeholder="••••••••"
                    autoComplete="new-password"
                    inputStyle={{
                        border: `1px solid ${passwordsMatch ? "#10b981" : confirm ? "#ef4444" : "var(--border)"}`,
                    }}
                    onInputFocus={(event) => {
                        if (!passwordsMatch) {
                            event.target.style.borderColor = "var(--accent)";
                        }
                    }}
                    onInputBlur={(event) => {
                        event.target.style.borderColor = passwordsMatch
                            ? "#10b981"
                            : confirm
                                ? "#ef4444"
                                : "var(--border)";
                    }}
                    endAdornment={<ConfirmPasswordAdornment matches={passwordsMatch} />}
                />

                <AuthSubmitButton loading={loading} loadingLabel="Creating account..." label="Create Account" />
            </form>
        </AuthShell>
    );
}
