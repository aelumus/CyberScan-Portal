import { Check, Eye, EyeOff, Loader2 } from "lucide-react";
import type { CSSProperties, FocusEventHandler, InputHTMLAttributes, ReactNode } from "react";

const LABEL_ST: CSSProperties = { color: "var(--text-3)" };
const INPUT_ST: CSSProperties = { background: "var(--surface-2)", border: "1px solid var(--border)", color: "var(--text)" };

function onFocusBorder(e: React.FocusEvent<HTMLInputElement>) { e.target.style.borderColor = "var(--accent)"; }
function onBlurBorder(e: React.FocusEvent<HTMLInputElement>) { e.target.style.borderColor = "var(--border)"; }

interface AlertProps { message: string; }
export function AuthAlert({ message }: AlertProps) {
    return (
        <div className="mb-4 rounded-xl px-4 py-3 text-sm"
            style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.2)", color: "#f87171" }}>
            {message}
        </div>
    );
}

interface FieldProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "className" | "style" | "value" | "onChange"> {
    label: string;
    value: string;
    onChange: (v: string) => void;
    inputStyle?: CSSProperties;
    onInputFocus?: FocusEventHandler<HTMLInputElement>;
    onInputBlur?: FocusEventHandler<HTMLInputElement>;
}
export function AuthField({ label, value, onChange, inputStyle, onInputFocus, onInputBlur, ...rest }: FieldProps) {
    return (
        <div>
            <label className="mb-2 block text-xs font-semibold uppercase tracking-wider" style={LABEL_ST}>{label}</label>
            <input {...rest} value={value} onChange={e => onChange(e.target.value)}
                className="w-full rounded-xl px-4 py-3 text-sm transition-all focus:outline-none"
                style={{ ...INPUT_ST, ...inputStyle }}
                onFocus={onInputFocus ?? onFocusBorder}
                onBlur={onInputBlur ?? onBlurBorder} />
        </div>
    );
}

interface PwdFieldProps {
    label: string; value: string; onChange: (v: string) => void;
    visible: boolean; placeholder: string; autoComplete: string;
    required?: boolean; inputStyle?: CSSProperties; endAdornment?: ReactNode;
    onToggleVisibility?: () => void;
    onInputFocus?: FocusEventHandler<HTMLInputElement>;
    onInputBlur?: FocusEventHandler<HTMLInputElement>;
}
export function AuthPasswordField({ label, value, onChange, visible, placeholder, autoComplete, required = true, inputStyle, endAdornment, onToggleVisibility, onInputFocus, onInputBlur }: PwdFieldProps) {
    return (
        <div>
            <label className="mb-2 block text-xs font-semibold uppercase tracking-wider" style={LABEL_ST}>{label}</label>
            <div className="relative">
                <input type={visible ? "text" : "password"} value={value} onChange={e => onChange(e.target.value)}
                    required={required} autoComplete={autoComplete} placeholder={placeholder}
                    className="w-full rounded-xl px-4 py-3 pr-11 text-sm transition-all focus:outline-none"
                    style={{ ...INPUT_ST, ...inputStyle }}
                    onFocus={onInputFocus ?? onFocusBorder}
                    onBlur={onInputBlur ?? onBlurBorder} />
                {onToggleVisibility ? (
                    <button type="button" onClick={onToggleVisibility}
                        className="absolute right-3 top-1/2 -translate-y-1/2" style={{ color: "var(--text-3)" }}>
                        {visible ? <EyeOff size={15} /> : <Eye size={15} />}
                    </button>
                ) : endAdornment ? (
                    <div className="absolute right-3 top-1/2 -translate-y-1/2">{endAdornment}</div>
                ) : null}
            </div>
        </div>
    );
}

export function PasswordStrengthIndicator({ password }: { password: string }) {
    if (!password.length) return null;
    const strength = password.length < 6 ? 1 : password.length < 10 ? 2 : 3;
    const colors = ["#ef4444", "#ef4444", "#f59e0b", "#10b981"];
    const labels = ["", "Too short", "Fair", "Strong"];
    return (
        <div className="mt-2 flex items-center gap-2">
            <div className="flex flex-1 gap-1">
                {[1, 2, 3].map(i => (
                    <div key={i} className="h-1 flex-1 rounded-full transition-colors duration-300"
                        style={{ background: i <= strength ? colors[strength] : "var(--border)" }} />
                ))}
            </div>
            <span className="text-xs font-medium" style={{ color: colors[strength] }}>{labels[strength]}</span>
        </div>
    );
}

interface SubmitProps { label: string; loadingLabel: string; loading: boolean; }
export function AuthSubmitButton({ label, loadingLabel, loading }: SubmitProps) {
    return (
        <button type="submit" disabled={loading}
            className="flex w-full items-center justify-center gap-2 rounded-xl py-3 text-sm font-bold text-white transition-all duration-200 hover:scale-[1.02] hover:shadow-lg hover:shadow-indigo-500/30 disabled:cursor-not-allowed disabled:opacity-60"
            style={{ background: "linear-gradient(135deg,#4f46e5,#7c3aed)" }}>
            {loading ? <><Loader2 size={15} className="animate-spin" /> {loadingLabel}</> : label}
        </button>
    );
}

export function ConfirmPasswordAdornment({ matches }: { matches: boolean }) {
    return matches ? <Check size={14} className="text-emerald-400" /> : null;
}
