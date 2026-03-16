type FormDataValue = string | Blob;

const DEFAULT_API_BASE_URL = "http://127.0.0.1:8000";

function normalizeApiPath(path: string) {
    return path.startsWith("/") ? path : `/${path}`;
}

export const API_BASE_URL = (process.env.NEXT_PUBLIC_API_URL ?? DEFAULT_API_BASE_URL).replace(/\/$/, "");

export function buildApiUrl(path: string) {
    return `${API_BASE_URL}${normalizeApiPath(path)}`;
}

export function createFormData(entries: Record<string, FormDataValue>) {
    const formData = new FormData();

    for (const [key, value] of Object.entries(entries)) {
        formData.append(key, value);
    }

    return formData;
}

export async function readApiError(response: Response, fallbackMessage = "Request failed") {
    try {
        const payload = (await response.json()) as {
            detail?: unknown;
            error?: string;
            message?: string;
        };

        if (typeof payload.detail === "string") {
            return payload.detail;
        }

        if (payload.detail && typeof payload.detail === "object") {
            const detail = payload.detail as {
                error?: string;
                message?: string;
            };

            if (detail.message) {
                return detail.message;
            }

            if (detail.error) {
                return detail.error;
            }
        }

        return payload.message ?? payload.error ?? fallbackMessage;
    } catch {
        return fallbackMessage;
    }
}

export async function getJson<T>(path: string, init?: RequestInit) {
    const response = await fetch(buildApiUrl(path), init);

    if (!response.ok) {
        throw new Error(await readApiError(response, `Request failed (${response.status})`));
    }

    return response.json() as Promise<T>;
}

export async function postForm<T>(
    path: string,
    entries: Record<string, FormDataValue>,
    init?: Omit<RequestInit, "body" | "method">,
) {
    const response = await fetch(buildApiUrl(path), {
        ...init,
        method: "POST",
        body: createFormData(entries),
    });

    if (!response.ok) {
        throw new Error(await readApiError(response, "Request failed"));
    }

    return response.json() as Promise<T>;
}
