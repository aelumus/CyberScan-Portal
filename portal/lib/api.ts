type FormVal = string | Blob;

const BACKEND_URL = (process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");

export function buildApiUrl(path: string) {
    const normalized = path.startsWith("/") ? path : `/${path}`;
    return `${BACKEND_URL}${normalized}`;
}

export function createFormData(fields: Record<string, FormVal>) {
    const form = new FormData();
    for (const [k, v] of Object.entries(fields)) form.append(k, v);
    return form;
}

export async function readApiError(resp: Response, fallback = "Request failed") {
    try {
        const body = (await resp.json()) as { detail?: unknown; error?: string; message?: string };
        if (typeof body.detail === "string") return body.detail;
        if (body.detail && typeof body.detail === "object") {
            const d = body.detail as { error?: string; message?: string };
            if (d.message) return d.message;
            if (d.error) return d.error;
        }
        return body.message ?? body.error ?? fallback;
    } catch {
        return fallback;
    }
}

export async function getJson<T>(path: string, init?: RequestInit) {
    const resp = await fetch(buildApiUrl(path), init);
    if (!resp.ok) throw new Error(await readApiError(resp, `Request failed (${resp.status})`));
    return resp.json() as Promise<T>;
}

export async function postForm<T>(path: string, fields: Record<string, FormVal>, init?: Omit<RequestInit, "body" | "method">) {
    const resp = await fetch(buildApiUrl(path), { ...init, method: "POST", body: createFormData(fields) });
    if (!resp.ok) throw new Error(await readApiError(resp, "Request failed"));
    return resp.json() as Promise<T>;
}
