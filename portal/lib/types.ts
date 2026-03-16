export type Verdict = "Malicious" | "Suspicious" | "Benign" | "Unknown";
export type RiskLevel = "critical" | "high" | "medium" | "low";

export interface User {
    id: number;
    username: string;
    email: string;
    created_at?: string;
    scan_count?: number;
}

export interface AuthResponse {
    token: string;
    user: User;
}

export interface ModelMetrics {
    auc: number;
    f1: number;
    accuracy: number;
    fpr: number;
}

export interface ScanModelResult {
    model_key: string;
    score: number;
    label: string;
    threshold: number;
    triggered: boolean;
    using_real_model: boolean;
    name?: string;
    dataset?: string;
    algo?: string;
    version?: string;
    status?: string;
    metrics?: ModelMetrics;
}

export interface FeatureImportance {
    name: string;
    importance: number;
}

export interface ScanFeatures {
    DS1?: FeatureImportance[];
}

export interface VirusTotalResult {
    positives: number;
    total: number;
    scan_date: string;
    permalink: string;
    error?: string;
}

export interface MitreTechnique {
    id: string;
    name: string;
    url: string;
}

export interface DangerousImport {
    function: string;
    dll: string;
    severity: string;
}

export interface SuspiciousStringMatch {
    string: string;
    type: string;
}

export interface StringsAnalysisSummary {
    dangerous_count: number;
    suspicious_count: number;
    mitre_count: number;
    risk_level: RiskLevel | string;
}

export interface StringsAnalysis {
    dangerous_imports: DangerousImport[];
    suspicious_strings: SuspiciousStringMatch[];
    mitre_techniques: MitreTechnique[];
    risk_score: number;
    summary?: StringsAnalysisSummary;
}

export interface ShapValue {
    feature: string;
    shap_value: number;
    feature_value: number;
}

export interface YaraMatchString {
    offset: number;
    identifier: string;
    data: string;
}

export interface YaraMatch {
    rule: string;
    tags: string[];
    meta: Record<string, unknown>;
    strings: YaraMatchString[];
}

export interface YaraResponse {
    success: boolean;
    error: string | null;
    matches: YaraMatch[];
}

export interface ScanRecord {
    id: string;
    filename: string;
    sha256: string;
    md5?: string;
    verdict: Verdict | string;
    risk_level?: RiskLevel | string;
    score: number;
    scan_time: number;
    created_at: string;
    file_size?: number;
    threshold?: number;
    mode?: string;
    ml_results?: ScanModelResult[];
    features?: ScanFeatures;
    vt_result?: VirusTotalResult | null;
    models_used?: {
        ds1?: boolean;
        vt?: boolean;
    };
    pe_parse_ok?: boolean;
    strings_analysis?: StringsAnalysis;
    shap_values?: ShapValue[];
    shap_expected?: number;
    user_id?: number;
    original_filename?: string;
}

export interface ScansResponse {
    scans: ScanRecord[];
}

export interface RocEntry {
    fpr: number[];
    tpr: number[];
    auc: number;
}

export interface RocResponse {
    roc: Record<string, RocEntry>;
}

export interface ConfusionEntry {
    tp: number;
    fp: number;
    tn: number;
    fn: number;
    total: number;
}

export interface ConfusionResponse {
    confusion: Record<string, ConfusionEntry>;
}

export interface ModelDefinition {
    id: string;
    name: string;
    algo: string;
    status: string;
    metrics: ModelMetrics;
    loaded: boolean;
    dataset?: string;
    version?: string;
}

export interface ModelsResponse {
    models: ModelDefinition[];
}
