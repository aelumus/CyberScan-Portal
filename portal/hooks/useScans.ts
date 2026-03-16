"use client";

import { useEffect, useState } from "react";
import { useAuth } from "@/components/AuthProvider";
import { getJson } from "@/lib/api";
import type { ScanRecord, ScansResponse } from "@/lib/types";

export function useScans() {
    const { authHeaders } = useAuth();
    const [scans, setScans] = useState<ScanRecord[]>([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        let isActive = true;

        getJson<ScansResponse>("/api/scans", { headers: authHeaders() })
            .then((data) => {
                if (isActive) {
                    setScans(data.scans ?? []);
                }
            })
            .catch(() => {
                if (isActive) {
                    setScans([]);
                }
            })
            .finally(() => {
                if (isActive) {
                    setLoading(false);
                }
            });

        return () => {
            isActive = false;
        };
    }, [authHeaders]);

    return { scans, loading };
}
