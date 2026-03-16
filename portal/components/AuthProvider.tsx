"use client";
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { buildApiUrl, postForm } from "@/lib/api";
import type { AuthResponse, User } from "@/lib/types";

const TOKEN_STORAGE_KEY = "cs-token";

interface AuthContextType {
    user: User | null;
    token: string | null;
    loading: boolean;
    login: (email: string, password: string) => Promise<void>;
    register: (username: string, email: string, password: string) => Promise<void>;
    logout: () => void;
    authHeaders: () => Record<string, string>;
}

const AuthCtx = createContext<AuthContextType | null>(null);

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
        localStorage.removeItem(TOKEN_STORAGE_KEY);
        setToken(null);
        setUser(null);
    }, []);

    const persistSession = useCallback((session: AuthResponse) => {
        localStorage.setItem(TOKEN_STORAGE_KEY, session.token);
        setToken(session.token);
        setUser(session.user);
    }, []);

    // Validate saved token on mount
    useEffect(() => {
        let isActive = true;

        const validateSession = async () => {
            const savedToken = localStorage.getItem(TOKEN_STORAGE_KEY);

            if (!savedToken) {
                if (isActive) {
                    setLoading(false);
                }
                return;
            }

            try {
                const response = await fetch(buildApiUrl("/api/auth/me"), {
                    headers: { Authorization: `Bearer ${savedToken}` },
                });

                const data = response.ok ? ((await response.json()) as User) : null;

                if (!isActive) {
                    return;
                }

                if (data) {
                    setToken(savedToken);
                    setUser(data);
                } else {
                    clearSession();
                }
            } catch {
                if (isActive) {
                    clearSession();
                }
            } finally {
                if (isActive) {
                    setLoading(false);
                }
            }
        };

        void validateSession();

        return () => {
            isActive = false;
        };
    }, [clearSession]);

    const login = useCallback(async (email: string, password: string) => {
        const data = await postForm<AuthResponse>("/api/auth/login", { email, password });
        persistSession(data);
        router.push("/dashboard");
    }, [persistSession, router]);

    const register = useCallback(async (username: string, email: string, password: string) => {
        const data = await postForm<AuthResponse>("/api/auth/register", {
            username,
            email,
            password,
        });
        persistSession(data);
        router.push("/dashboard");
    }, [persistSession, router]);

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
