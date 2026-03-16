import { Check, Eye, EyeOff, Loader2 } from "lucide-react";
import type { CSSProperties, FocusEventHandler, InputHTMLAttributes, ReactNode } from "react";

const LABEL_STYLE: CSSProperties = { color: "var(--text-3)" };
const DEFAULT_INPUT_STYLE: CSSProperties = {
    background: "var(--surface-2)",
    border: "1px solid var(--border)",
    color: "var(--text)",
};

function handleDefaultFocus(event: React.FocusEvent<HTMLInputElement>) {
    event.target.style.borderColor = "var(--accent)";
}

function handleDefaultBlur(event: React.FocusEvent<HTMLInputElement>) {
    event.target.style.borderColor = "var(--border)";
}

interface AuthAlertProps {
    message: string;
}

export function AuthAlert({ message }: AuthAlertProps) {
    return (
        <div
            className="mb-4 rounded-xl px-4 py-3 text-sm"
            style={{
                background: "rgba(239,68,68,0.1)",
                border: "1px solid rgba(239,68,68,0.2)",
                color: "#f87171",
            }}
        >
            {message}
        </div>
    );
}

interface AuthFieldProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "className" | "style" | "value" | "onChange"> {
    label: string;
    value: string;
    onChange: (value: string) => void;
    inputStyle?: CSSProperties;
    onInputFocus?: FocusEventHandler<HTMLInputElement>;
    onInputBlur?: FocusEventHandler<HTMLInputElement>;
}

export function AuthField({
    label,
    value,
    onChange,
    inputStyle,
    onInputFocus,
    onInputBlur,
    ...inputProps
}: AuthFieldProps) {
    return (
        <div>
            <label className="mb-2 block text-xs font-semibold uppercase tracking-wider" style={LABEL_STYLE}>
                {label}
            </label>
            <input
                {...inputProps}
                value={value}
                onChange={(event) => onChange(event.target.value)}
                className="w-full rounded-xl px-4 py-3 text-sm transition-all focus:outline-none"
                style={{ ...DEFAULT_INPUT_STYLE, ...inputStyle }}
                onFocus={onInputFocus ?? handleDefaultFocus}
                onBlur={onInputBlur ?? handleDefaultBlur}
            />
        </div>
    );
}

interface AuthPasswordFieldProps {
    label: string;
    value: string;
    onChange: (value: string) => void;
    visible: boolean;
    placeholder: string;
    autoComplete: string;
    required?: boolean;
    inputStyle?: CSSProperties;
    endAdornment?: ReactNode;
    onToggleVisibility?: () => void;
    onInputFocus?: FocusEventHandler<HTMLInputElement>;
    onInputBlur?: FocusEventHandler<HTMLInputElement>;
}

export function AuthPasswordField({
    label,
    value,
    onChange,
    visible,
    placeholder,
    autoComplete,
    required = true,
    inputStyle,
    endAdornment,
    onToggleVisibility,
    onInputFocus,
    onInputBlur,
}: AuthPasswordFieldProps) {
    return (
        <div>
            <label className="mb-2 block text-xs font-semibold uppercase tracking-wider" style={LABEL_STYLE}>
                {label}
            </label>
            <div className="relative">
                <input
                    type={visible ? "text" : "password"}
                    value={value}
                    onChange={(event) => onChange(event.target.value)}
                    required={required}
                    autoComplete={autoComplete}
                    placeholder={placeholder}
                    className="w-full rounded-xl px-4 py-3 pr-11 text-sm transition-all focus:outline-none"
                    style={{ ...DEFAULT_INPUT_STYLE, ...inputStyle }}
                    onFocus={onInputFocus ?? handleDefaultFocus}
                    onBlur={onInputBlur ?? handleDefaultBlur}
                />
                {onToggleVisibility ? (
                    <button
                        type="button"
                        onClick={onToggleVisibility}
                        className="absolute right-3 top-1/2 -translate-y-1/2"
                        style={{ color: "var(--text-3)" }}
                    >
                        {visible ? <EyeOff size={15} /> : <Eye size={15} />}
                    </button>
                ) : null}
                {!onToggleVisibility && endAdornment ? (
                    <div className="absolute right-3 top-1/2 -translate-y-1/2">{endAdornment}</div>
                ) : null}
            </div>
        </div>
    );
}

interface PasswordStrengthIndicatorProps {
    password: string;
}

export function PasswordStrengthIndicator({ password }: PasswordStrengthIndicatorProps) {
    if (password.length === 0) {
        return null;
    }

    const passwordStrength =
        password.length === 0 ? 0 : password.length < 6 ? 1 : password.length < 10 ? 2 : 3;
    const strengthColor = ["#ef4444", "#ef4444", "#f59e0b", "#10b981"][passwordStrength];
    const strengthLabel = ["", "Too short", "Fair", "Strong"][passwordStrength];

    return (
        <div className="mt-2 flex items-center gap-2">
            <div className="flex flex-1 gap-1">
                {[1, 2, 3].map((segment) => (
                    <div
                        key={segment}
                        className="h-1 flex-1 rounded-full transition-colors duration-300"
                        style={{
                            background: segment <= passwordStrength ? strengthColor : "var(--border)",
                        }}
                    />
                ))}
            </div>
            <span className="text-xs font-medium" style={{ color: strengthColor }}>
                {strengthLabel}
            </span>
        </div>
    );
}

interface AuthSubmitButtonProps {
    label: string;
    loadingLabel: string;
    loading: boolean;
}

export function AuthSubmitButton({ label, loadingLabel, loading }: AuthSubmitButtonProps) {
    return (
        <button
            type="submit"
            disabled={loading}
            className="flex w-full items-center justify-center gap-2 rounded-xl py-3 text-sm font-bold text-white transition-all duration-200 hover:scale-[1.02] hover:shadow-lg hover:shadow-indigo-500/30 disabled:cursor-not-allowed disabled:opacity-60"
            style={{ background: "linear-gradient(135deg,#4f46e5,#7c3aed)" }}
        >
            {loading ? (
                <>
                    <Loader2 size={15} className="animate-spin" /> {loadingLabel}
                </>
            ) : (
                label
            )}
        </button>
    );
}

export function ConfirmPasswordAdornment({ matches }: { matches: boolean }) {
    if (!matches) {
        return null;
    }

    return <Check size={14} className="text-emerald-400" />;
}
