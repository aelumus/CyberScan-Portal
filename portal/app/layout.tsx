import type { Metadata } from "next";
import { Inter } from "next/font/google";
import type { ReactNode } from "react";
import "./globals.css";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/components/AuthProvider";

const inter = Inter({ subsets: ["latin"], weight: ["300", "400", "500", "600", "700", "800", "900"] });

export const metadata: Metadata = {
    title: "CyberScan Portal — Automated Malware Analysis",
    description: "Static PE analysis with Random Forest, XGBoost and LightGBM. Diploma project 2026.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
    return (
        <html lang="en">
            <body className={inter.className}>
                <ThemeProvider>
                    <AuthProvider>
                        {children}
                    </AuthProvider>
                </ThemeProvider>
            </body>
        </html>
    );
}
