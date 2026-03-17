"""
Scan processing engine — ML models, feature extraction, and analysis.
Shared between the API (main.py) and the background worker (worker.py).
"""

import re
import time
import warnings
from pathlib import Path

import joblib
import pandas as pd
import pefile
import requests

from settings import settings

warnings.filterwarnings("ignore")

# ── Paths & Constants ─────────────────────────────────────────────────────────
BASE = Path(__file__).parent.parent / "Malware-Detection-and-Analysis-using-Machine-Learning-main"
MODEL_DIR = BASE / "ML_model"
MODEL_FILES = {
    "ds1_rf": "random_forest.pkl",
    "ds1_xgb": "xgboost.pkl",
    "ds1_lgbm": "lightgbm.pkl",
}
MODEL_ORDER = tuple(MODEL_FILES.keys())
MODE_THRESHOLD_OFFSETS = {"conservative": -0.1, "balanced": 0.0, "aggressive": 0.15}
SUPPORTED_MACHINE_ARCHS = {0x014C, 0x8664}
LEGACY_MACHINE_NAMES = {0xAA64: "ARM64", 0x01C0: "ARM", 0x0200: "IA64"}

DS1_FEATURE_COLS = [
    "Text_entro",
    "Rsrc_entro",
    "Data_entro",
    "Idata_entro",
    "bss_entro",
    "nsec",
    "codesize",
    "initdatsize",
    "uninitdatsize",
    "adrentpt",
    "soi",
    "optcksum",
    "char",
    "dllch",
    "Text_char",
    "Rsrc_char",
    "Data_char",
    "Idata_char",
    "bss_char",
    "Text_secsize",
    "Text_datsize",
    "Rsrc_secsize",
    "Rsrc_datsize",
    "Data_secsize",
    "Data_datsize",
    "Idata_secsize",
    "Idata_datsize",
    "bss_virsize",
    "ibase",
    "ss",
    "secalign",
    "filealign",
    "Text_byteaddr",
    "Rsrc_byteaddr",
    "Data_byteaddr",
    "Idata_byteaddr",
    "bss_viraddr",
    "Text_mscfaddr",
    "Rsrc_mscfaddr",
    "Data_mscfaddr",
    "Idata_mscfaddr",
    "bss_phyaddr",
    "cbase",
    "dbase",
    "majssver",
    "minssver",
    "majosver",
    "minosver",
    "majiver",
    "miniver",
    "majlv",
    "minlv",
    "sosr",
    "sosc",
    "sohr",
    "sohc",
    "ndirent",
    "mach",
    "sig",
    "ohs",
    "win32vv",
    "soh",
]

MODEL_REGISTRY = {
    "ds1_rf": {
        "name": "Random Forest",
        "dataset": "DS1 — PE Headers",
        "algo": "RandomForest",
        "version": "2.0.0",
        "status": "active",
    },
    "ds1_xgb": {
        "name": "XGBoost",
        "dataset": "DS1 — PE Headers",
        "algo": "XGBoost",
        "version": "2.0.0",
        "status": "active",
    },
    "ds1_lgbm": {
        "name": "LightGBM",
        "dataset": "DS1 — PE Headers",
        "algo": "LightGBM",
        "version": "2.0.0",
        "status": "active",
    },
}

MOCK_METRICS = {
    "ds1_rf": {"auc": 0.9998, "f1": 0.996, "accuracy": 0.996, "fpr": 0.004},
    "ds1_xgb": {"auc": 0.9998, "f1": 0.996, "accuracy": 0.996, "fpr": 0.003},
    "ds1_lgbm": {"auc": 0.9998, "f1": 0.997, "accuracy": 0.997, "fpr": 0.002},
}

# ── Model Loading ─────────────────────────────────────────────────────────────
REAL_MODELS: dict = {}


def load_models() -> dict:
    global REAL_MODELS
    for key, fname in MODEL_FILES.items():
        p = MODEL_DIR / fname
        if p.exists():
            try:
                REAL_MODELS[key] = joblib.load(p)
                print(f"[models] Loaded {key} from {p}")
            except Exception as e:
                print(f"[models] {key} load failed: {e}")
        else:
            print(f"[models] {key} not found at {p}")
    return REAL_MODELS


load_models()


# ── PE Validation ─────────────────────────────────────────────────────────────
def validate_pe(file_path: str) -> tuple[bool, str | None]:
    """Quick PE header check. Returns (is_valid, error_message)."""
    try:
        pe = pefile.PE(file_path, fast_load=True)
    except Exception:
        return False, "Not a valid PE file"
    machine = pe.FILE_HEADER.Machine
    if machine not in SUPPORTED_MACHINE_ARCHS:
        arch = LEGACY_MACHINE_NAMES.get(machine, f"unknown (0x{machine:04X})")
        return False, f"{arch} binary. Only x86/x64 supported."
    return True, None


# ── Feature Extraction ────────────────────────────────────────────────────────
def extract_ds1_features(file_path: str) -> pd.DataFrame | None:
    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"],
            ]
        )
    except Exception as e:
        print(f"PE parse error: {e}")
        return None

    def safe(fn, default=0):
        try:
            return fn()
        except Exception:
            return default

    fh = pe.FILE_HEADER
    oh = pe.OPTIONAL_HEADER

    def find_section(names):
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode(errors="ignore").lower()
            if name in names:
                return s
        return None

    s_text = find_section([".text", "text"])
    s_rsrc = find_section([".rsrc", "rsrc"])
    s_data = find_section([".data", "data"])
    s_idata = find_section([".idata", "idata"])
    s_bss = find_section([".bss", "bss"])

    def sec_entropy(sec):
        if not sec:
            return 0.0
        try:
            return float(sec.get_entropy() or 0.0)
        except Exception:
            return 0.0

    def sec_char(sec):
        return int(getattr(sec, "Characteristics", 0)) if sec else 0

    def sec_raw_size(sec):
        return int(getattr(sec, "SizeOfRawData", 0)) if sec else 0

    def sec_virt_size(sec):
        return int(getattr(sec, "Misc_VirtualSize", 0)) if sec else 0

    def sec_raw_addr(sec):
        return int(getattr(sec, "PointerToRawData", 0)) if sec else 0

    def sec_virt_addr(sec):
        return int(getattr(sec, "VirtualAddress", 0)) if sec else 0

    feat = {
        "Text_entro": sec_entropy(s_text),
        "Rsrc_entro": sec_entropy(s_rsrc),
        "Data_entro": sec_entropy(s_data),
        "Idata_entro": sec_entropy(s_idata),
        "bss_entro": sec_entropy(s_bss),
        "nsec": len(pe.sections or []),
        "codesize": safe(lambda: oh.SizeOfCode),
        "initdatsize": safe(lambda: oh.SizeOfInitializedData),
        "uninitdatsize": safe(lambda: oh.SizeOfUninitializedData),
        "adrentpt": safe(lambda: oh.AddressOfEntryPoint),
        "soi": safe(lambda: oh.SizeOfImage),
        "optcksum": safe(lambda: oh.CheckSum),
        "char": safe(lambda: fh.Characteristics),
        "dllch": safe(lambda: oh.DllCharacteristics),
        "Text_char": sec_char(s_text),
        "Rsrc_char": sec_char(s_rsrc),
        "Data_char": sec_char(s_data),
        "Idata_char": sec_char(s_idata),
        "bss_char": sec_char(s_bss),
        "Text_secsize": sec_raw_size(s_text),
        "Text_datsize": sec_virt_size(s_text),
        "Rsrc_secsize": sec_raw_size(s_rsrc),
        "Rsrc_datsize": sec_virt_size(s_rsrc),
        "Data_secsize": sec_raw_size(s_data),
        "Data_datsize": sec_virt_size(s_data),
        "Idata_secsize": sec_raw_size(s_idata),
        "Idata_datsize": sec_virt_size(s_idata),
        "bss_virsize": sec_virt_size(s_bss),
        "ibase": safe(lambda: oh.ImageBase),
        "ss": safe(lambda: oh.Subsystem),
        "secalign": safe(lambda: oh.SectionAlignment),
        "filealign": safe(lambda: oh.FileAlignment),
        "Text_byteaddr": sec_raw_addr(s_text),
        "Rsrc_byteaddr": sec_raw_addr(s_rsrc),
        "Data_byteaddr": sec_raw_addr(s_data),
        "Idata_byteaddr": sec_raw_addr(s_idata),
        "bss_viraddr": sec_virt_addr(s_bss),
        "Text_mscfaddr": sec_virt_addr(s_text),
        "Rsrc_mscfaddr": sec_virt_addr(s_rsrc),
        "Data_mscfaddr": sec_virt_addr(s_data),
        "Idata_mscfaddr": sec_virt_addr(s_idata),
        "bss_phyaddr": sec_raw_addr(s_bss),
        "cbase": safe(lambda: oh.BaseOfCode),
        "dbase": safe(lambda: getattr(oh, "BaseOfData", 0)),
        "majssver": safe(lambda: oh.MajorSubsystemVersion),
        "minssver": safe(lambda: oh.MinorSubsystemVersion),
        "majosver": safe(lambda: oh.MajorOperatingSystemVersion),
        "minosver": safe(lambda: oh.MinorOperatingSystemVersion),
        "majiver": safe(lambda: oh.MajorImageVersion),
        "miniver": safe(lambda: oh.MinorImageVersion),
        "majlv": safe(lambda: oh.MajorLinkerVersion),
        "minlv": safe(lambda: oh.MinorLinkerVersion),
        "sosr": safe(lambda: oh.SizeOfStackReserve),
        "sosc": safe(lambda: oh.SizeOfStackCommit),
        "sohr": safe(lambda: oh.SizeOfHeapReserve),
        "sohc": safe(lambda: oh.SizeOfHeapCommit),
        "ndirent": safe(lambda: oh.NumberOfRvaAndSizes),
        "mach": safe(lambda: fh.Machine),
        "sig": safe(lambda: pe.NT_HEADERS.Signature),
        "ohs": safe(lambda: fh.SizeOfOptionalHeader),
        "win32vv": safe(lambda: oh.Win32VersionValue),
        "soh": safe(lambda: oh.SizeOfHeaders),
    }
    return pd.DataFrame([feat])[DS1_FEATURE_COLS]


# ── Prediction ────────────────────────────────────────────────────────────────
def predict_ds1(features_df: pd.DataFrame | None, model_key: str, threshold: float) -> dict | None:
    if features_df is None or model_key not in REAL_MODELS:
        return None
    info = MODEL_REGISTRY[model_key]
    metrics = MOCK_METRICS[model_key]
    try:
        proba = REAL_MODELS[model_key].predict_proba(features_df)
        score = float(proba[0][1])
    except Exception as e:
        print(f"[predict] {model_key}: {e}")
        return None
    label = "Malicious" if score >= threshold else "Benign"
    return {
        "model_key": model_key,
        "score": round(score, 4),
        "label": label,
        "threshold": threshold,
        "triggered": score >= threshold,
        "using_real_model": True,
        **info,
        "metrics": metrics,
    }


def get_top_features(features_df: pd.DataFrame | None) -> list:
    if features_df is None or "ds1_rf" not in REAL_MODELS:
        return []
    try:
        importances = REAL_MODELS["ds1_rf"].feature_importances_
        pairs = sorted(zip(DS1_FEATURE_COLS, importances), key=lambda x: x[1], reverse=True)[:15]
        return [{"name": n, "importance": round(float(v), 4)} for n, v in pairs]
    except Exception:
        return []


def compute_verdict(results: list[dict]) -> tuple[str, float, str]:
    if not results:
        return "Unknown", 0.0, "low"
    avg_score = sum(r["score"] for r in results) / len(results)
    malicious_count = sum(1 for r in results if r["triggered"])
    max_score = max(r["score"] for r in results)
    majority = malicious_count >= 2
    if avg_score >= 0.70:
        verdict, risk = "Malicious", "critical"
    elif avg_score >= 0.55 or (majority and avg_score >= 0.45):
        verdict, risk = "Malicious", "high"
    elif avg_score >= 0.40 or majority:
        verdict, risk = "Suspicious", "medium"
    elif malicious_count >= 1 or max_score >= 0.30:
        verdict, risk = "Suspicious", "low"
    else:
        verdict, risk = "Benign", "low"
    return verdict, round(avg_score, 4), risk


# ── VirusTotal ────────────────────────────────────────────────────────────────
def lookup_virustotal(sha256: str, api_key: str = "", api_url: str = "") -> dict | None:
    api_key = api_key or settings.vt_api_key
    api_url = api_url or settings.vt_url
    if not api_key:
        return None
    try:
        resp = requests.get(api_url, params={"apikey": api_key, "resource": sha256}, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("response_code") == 1:
                return {
                    "positives": data.get("positives", 0),
                    "total": data.get("total", 0),
                    "scan_date": data.get("scan_date", ""),
                    "permalink": data.get("permalink", ""),
                }
    except Exception:
        return {"error": "VirusTotal request failed"}
    return None


def apply_vt_adjustments(
    ml_results: list[dict], vt_result: dict | None, threshold: float
) -> tuple[str, float, str]:
    """Adjust ML scores with VT data and compute final verdict."""
    if vt_result and "error" not in vt_result and vt_result["total"] > 0:
        vt_ratio = vt_result["positives"] / vt_result["total"]
        for r in ml_results:
            adjusted = round(r["score"] * 0.5 + vt_ratio * 0.5, 4)
            r["score"] = adjusted
            r["triggered"] = adjusted >= threshold
            r["label"] = "Malicious" if r["triggered"] else "Benign"

    verdict, avg_score, risk_level = compute_verdict(ml_results)

    if vt_result and "error" not in vt_result:
        pos, vt_total = vt_result["positives"], vt_result["total"]
        if pos > 5:
            verdict, risk_level = "Malicious", "critical"
        elif pos > 0 and verdict == "Benign":
            verdict, risk_level = "Suspicious", "medium"
        elif pos == 0 and vt_total >= 10 and avg_score < 0.65:
            verdict, risk_level = "Benign", "low"

    return verdict, avg_score, risk_level


# ── Suspicious Strings ────────────────────────────────────────────────────────
DANGEROUS_IMPORTS = {
    "CreateRemoteThread",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "SetThreadContext",
    "GetThreadContext",
    "ShellExecute",
    "ShellExecuteEx",
    "WinExec",
    "CreateProcess",
    "URLDownloadToFile",
    "URLDownloadToCacheFile",
    "InternetOpen",
    "InternetOpenUrl",
    "HttpSendRequest",
    "WSAStartup",
    "RegSetValueEx",
    "RegCreateKeyEx",
    "RegDeleteKey",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "SetWindowsHookEx",
    "GetAsyncKeyState",
    "GetKeyState",
    "keybd_event",
    "CryptEncrypt",
    "CryptDecrypt",
    "CryptGenKey",
    "CreateService",
    "OpenService",
    "StartService",
    "ControlService",
}

MITRE_MAPPING = {
    "VirtualAlloc": {
        "id": "T1055",
        "name": "Process Injection",
        "url": "https://attack.mitre.org/techniques/T1055/",
    },
    "CreateRemoteThread": {
        "id": "T1055",
        "name": "Process Injection",
        "url": "https://attack.mitre.org/techniques/T1055/",
    },
    "WriteProcessMemory": {
        "id": "T1055",
        "name": "Process Injection",
        "url": "https://attack.mitre.org/techniques/T1055/",
    },
    "RegSetValueExA": {
        "id": "T1112",
        "name": "Modify Registry",
        "url": "https://attack.mitre.org/techniques/T1112/",
    },
    "RegSetValueExW": {
        "id": "T1112",
        "name": "Modify Registry",
        "url": "https://attack.mitre.org/techniques/T1112/",
    },
    "GetKeyboardState": {
        "id": "T1056.001",
        "name": "Keylogging",
        "url": "https://attack.mitre.org/techniques/T1056/001/",
    },
    "GetAsyncKeyState": {
        "id": "T1056.001",
        "name": "Keylogging",
        "url": "https://attack.mitre.org/techniques/T1056/001/",
    },
    "SetWindowsHookEx": {
        "id": "T1056.001",
        "name": "Keylogging",
        "url": "https://attack.mitre.org/techniques/T1056/001/",
    },
    "URLDownloadToFile": {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "url": "https://attack.mitre.org/techniques/T1105/",
    },
    "InternetOpenUrlA": {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "url": "https://attack.mitre.org/techniques/T1105/",
    },
    "WINEXEC": {
        "id": "T1059.003",
        "name": "Windows Command Shell",
        "url": "https://attack.mitre.org/techniques/T1059/003/",
    },
    "ShellExecute": {
        "id": "T1059.003",
        "name": "Windows Command Shell",
        "url": "https://attack.mitre.org/techniques/T1059/003/",
    },
    "CreateProcessA": {
        "id": "T1059.003",
        "name": "Windows Command Shell",
        "url": "https://attack.mitre.org/techniques/T1059/003/",
    },
    "GetProcAddress": {
        "id": "T1129",
        "name": "Shared Modules",
        "url": "https://attack.mitre.org/techniques/T1129/",
    },
    "LoadLibraryA": {
        "id": "T1129",
        "name": "Shared Modules",
        "url": "https://attack.mitre.org/techniques/T1129/",
    },
}

SUSPICIOUS_PATTERNS = [
    (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "IP-based URL"),
    (r"cmd\.exe|powershell|wscript|cscript", "Shell executor"),
    (r"\\\\[A-Za-z0-9_.-]+\\[A-Za-z0-9$]+", "UNC network path"),
    (r"HKEY_(LOCAL_MACHINE|CURRENT_USER)\\", "Registry key path"),
    (r"\.onion", "TOR domain"),
    (r"base64_decode|base64decode", "Base64 decoding"),
    (r"eval\s*\(|exec\s*\(", "Code execution"),
    (r"/etc/passwd|/proc/self|/dev/null", "Unix system paths"),
    (r"winlogon\.exe|lsass\.exe|svchost\.exe", "System process reference"),
    (r"SELECT\s+\*\s+FROM|DROP\s+TABLE|INSERT\s+INTO", "SQL query"),
    (r"\\AppData\\Roaming\\|\\Temp\\|%APPDATA%", "AppData/Temp paths"),
]

HIGH_SEVERITY_IMPORTS = {
    "CreateRemoteThread",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "URLDownloadToFile",
    "SetWindowsHookEx",
}


def extract_suspicious_strings(file_path: str) -> dict:
    dangerous_found = []
    suspicious_strings = []
    mitre_techniques = []
    mitre_seen: set[str] = set()

    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(errors="ignore") if entry.dll else ""
                for imp in entry.imports:
                    func_name = ""
                    if imp.name:
                        func_name = imp.name.decode(errors="ignore")
                    elif imp.ordinal:
                        func_name = f"Ordinal_{imp.ordinal}"
                    for danger in DANGEROUS_IMPORTS:
                        if func_name.lower().startswith(danger.lower()):
                            dangerous_found.append(
                                {
                                    "function": func_name,
                                    "dll": dll_name,
                                    "severity": "high"
                                    if danger in HIGH_SEVERITY_IMPORTS
                                    else "medium",
                                }
                            )
                            break
                    for mitre_func, mitre_data in MITRE_MAPPING.items():
                        if mitre_func.lower() in func_name.lower():
                            if mitre_data["id"] not in mitre_seen:
                                mitre_seen.add(mitre_data["id"])
                                mitre_techniques.append(mitre_data)
                            break
    except Exception:
        pass

    try:
        with open(file_path, "rb") as f:
            raw = f.read()
        ascii_strings = re.findall(rb"[\x20-\x7e]{6,}", raw)
        ascii_decoded = [s.decode("ascii", errors="ignore") for s in ascii_strings[:5000]]
        for s in ascii_decoded:
            for pattern, label in SUSPICIOUS_PATTERNS:
                if re.search(pattern, s, re.IGNORECASE):
                    suspicious_strings.append({"string": s[:120], "type": label})
                    break
    except Exception:
        pass

    seen: set[str] = set()
    deduped = []
    for item in suspicious_strings:
        if item["string"] not in seen:
            seen.add(item["string"])
            deduped.append(item)

    risk_score = min(100, len(dangerous_found) * 12 + len(deduped) * 5)
    return {
        "dangerous_imports": dangerous_found[:30],
        "suspicious_strings": deduped[:30],
        "mitre_techniques": mitre_techniques,
        "risk_score": risk_score,
        "summary": {
            "dangerous_count": len(dangerous_found),
            "suspicious_count": len(deduped),
            "mitre_count": len(mitre_techniques),
            "risk_level": (
                "critical"
                if risk_score >= 70
                else "high"
                if risk_score >= 40
                else "medium"
                if risk_score >= 20
                else "low"
            ),
        },
    }


# ── Full Scan Pipeline ────────────────────────────────────────────────────────
def process_scan(
    file_path: str,
    threshold: float,
    mode: str,
    use_vt: bool,
    sha256: str = "",
    on_step=None,
) -> dict:
    """Run the complete ML analysis pipeline on a PE file.

    *on_step* is an optional callback ``f(step_name)`` the caller can use
    to report progress (e.g. the worker updates the DB row).

    Returns a dict with all analysis results (verdict, ml_results, etc.).
    Raises ValueError for invalid PE / architecture, RuntimeError if models
    are not loaded.
    """

    def _step(name: str):
        if on_step:
            on_step(name)

    start = time.time()

    mode_offset = MODE_THRESHOLD_OFFSETS.get(mode, 0.0)
    thr = max(0.1, min(0.95, threshold + mode_offset))

    _step("extracting_features")
    ds1_features = extract_ds1_features(file_path)
    if ds1_features is None:
        raise ValueError("PE parsing failed")

    machine_val = int(ds1_features["mach"].iloc[0])
    if machine_val not in SUPPORTED_MACHINE_ARCHS:
        arch = LEGACY_MACHINE_NAMES.get(machine_val, f"unknown (0x{machine_val:04X})")
        raise ValueError(f"{arch} binary. Only x86/x64 supported.")

    _step("running_models")
    ml_results = []
    for key in MODEL_ORDER:
        result = predict_ds1(ds1_features, key, thr)
        if result is not None:
            ml_results.append(result)

    if not ml_results:
        raise RuntimeError("Models not loaded")

    features_by_ds = {"DS1": get_top_features(ds1_features)}

    _step("computing_verdict")
    vt_result = None
    if use_vt and sha256:
        vt_result = lookup_virustotal(sha256)

    verdict, avg_score, risk_level = apply_vt_adjustments(ml_results, vt_result, thr)
    strings_analysis = extract_suspicious_strings(file_path)

    scan_time = round(time.time() - start, 2)

    return {
        "verdict": verdict,
        "risk_level": risk_level,
        "score": avg_score,
        "scan_time": scan_time,
        "threshold": thr,
        "ml_results": ml_results,
        "features": features_by_ds,
        "vt_result": vt_result,
        "models_used": {"ds1": True, "vt": use_vt},
        "pe_parse_ok": True,
        "strings_analysis": strings_analysis,
    }
