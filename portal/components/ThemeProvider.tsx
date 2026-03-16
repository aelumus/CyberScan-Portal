"use client";
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

type Theme = "dark" | "light";
const ThemeCtx = createContext<{ theme: Theme; toggle: () => void }>({ theme: "dark", toggle: () => { } });

export function ThemeProvider({ children }: { children: ReactNode }) {
    const [theme, setTheme] = useState<Theme>("dark");

    useEffect(() => {
        let isActive = true;

        const loadTheme = async () => {
            const saved = localStorage.getItem("cs-theme") as Theme | null;

            if (saved && isActive) {
                setTheme(saved);
            }
        };

        void loadTheme();

        return () => {
            isActive = false;
        };
    }, []);

    useEffect(() => {
        const root = document.documentElement;
        root.setAttribute("data-theme", theme);
        localStorage.setItem("cs-theme", theme);
    }, [theme]);

    const toggle = () => setTheme(t => t === "dark" ? "light" : "dark");

    return (
        <ThemeCtx.Provider value={{ theme, toggle }}>
            {children}
        </ThemeCtx.Provider>
    );
}

export const useTheme = () => useContext(ThemeCtx);
