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
        let alive = true;
        getJson<ScansResponse>("/api/scans", { headers: authHeaders() })
            .then(resp => { if (alive) setScans(resp.scans ?? []); })
            .catch(() => { if (alive) setScans([]); })
            .finally(() => { if (alive) setLoading(false); });
        return () => { alive = false; };
    }, [authHeaders]);

    return { scans, loading };
}
