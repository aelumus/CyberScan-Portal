"use client";
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { buildApiUrl, postForm } from "@/lib/api";
import type { AuthResponse, User } from "@/lib/types";

const TOKEN_KEY = "cs-token";

interface AuthCtxType {
    user: User | null;
    token: string | null;
    loading: boolean;
    login: (email: string, password: string) => Promise<void>;
    register: (username: string, email: string, password: string) => Promise<void>;
    logout: () => void;
    authHeaders: () => Record<string, string>;
}

const AuthCtx = createContext<AuthCtxType | null>(null);

export function useAuth() {
    const ctx = useContext(AuthCtx);
    if (!ctx) throw new Error("useAuth must be inside AuthProvider");
    return ctx;
}

export function AuthProvider({ children }: { children: ReactNode }) {
    const [user, setUser] = useState<User | null>(null);
    const [token, setToken] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);
    const router = useRouter();

    const clearSession = useCallback(() => {
        localStorage.removeItem(TOKEN_KEY);
        setToken(null);
        setUser(null);
    }, []);

    const saveSession = useCallback((session: AuthResponse) => {
        localStorage.setItem(TOKEN_KEY, session.token);
        setToken(session.token);
        setUser(session.user);
    }, []);

    useEffect(() => {
        let alive = true;
        const checkToken = async () => {
            const saved = localStorage.getItem(TOKEN_KEY);
            if (!saved) { if (alive) setLoading(false); return; }
            try {
                const resp = await fetch(buildApiUrl("/api/auth/me"), { headers: { Authorization: `Bearer ${saved}` } });
                const userData = resp.ok ? ((await resp.json()) as User) : null;
                if (!alive) return;
                if (userData) { setToken(saved); setUser(userData); }
                else clearSession();
            } catch {
                if (alive) clearSession();
            } finally {
                if (alive) setLoading(false);
            }
        };
        void checkToken();
        return () => { alive = false; };
    }, [clearSession]);

    const login = useCallback(async (email: string, password: string) => {
        const resp = await postForm<AuthResponse>("/api/auth/login", { email, password });
        saveSession(resp);
        router.push("/dashboard");
    }, [saveSession, router]);

    const register = useCallback(async (username: string, email: string, password: string) => {
        const resp = await postForm<AuthResponse>("/api/auth/register", { username, email, password });
        saveSession(resp);
        router.push("/dashboard");
    }, [saveSession, router]);

    const logout = useCallback(() => {
        clearSession();
        router.push("/login");
    }, [clearSession, router]);

    const authHeaders = useCallback((): Record<string, string> => {
        return token ? { Authorization: `Bearer ${token}` } : {};
    }, [token]);

    return (
        <AuthCtx.Provider value={{ user, token, loading, login, register, logout, authHeaders }}>
            {children}
        </AuthCtx.Provider>
    );
}
