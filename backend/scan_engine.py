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

BASE = Path(__file__).parent.parent / "Malware-Detection-and-Analysis-using-Machine-Learning-main"
MODEL_DIR = BASE / "ML_model"
MODEL_FILES = {
    "ds1_rf": "random_forest.pkl",
    "ds1_xgb": "xgboost.pkl",
    "ds1_lgbm": "lightgbm.pkl",
}
MODEL_ORDER = tuple(MODEL_FILES.keys())
MODE_THRESHOLD_OFFSETS = {"conservative": -0.1, "balanced": 0.0, "aggressive": 0.15}
SUPPORTED_ARCHS = {0x014C, 0x8664}
ARCH_NAMES = {0xAA64: "ARM64", 0x01C0: "ARM", 0x0200: "IA64"}

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

REAL_MODELS: dict = {}


def load_models() -> dict:
    global REAL_MODELS
    for model_key, fname in MODEL_FILES.items():
        model_path = MODEL_DIR / fname
        if model_path.exists():
            try:
                REAL_MODELS[model_key] = joblib.load(model_path)
                print(f"[models] Loaded {model_key} from {model_path}")
            except Exception as exc:
                print(f"[models] {model_key} load failed: {exc}")
        else:
            print(f"[models] {model_key} not found at {model_path}")
    return REAL_MODELS


load_models()


def validate_pe(file_path: str) -> tuple[bool, str | None]:
    try:
        pe_obj = pefile.PE(file_path, fast_load=True)
    except Exception:
        return False, "Not a valid PE file"
    machine_type = pe_obj.FILE_HEADER.Machine
    if machine_type not in SUPPORTED_ARCHS:
        arch_label = ARCH_NAMES.get(machine_type, f"unknown (0x{machine_type:04X})")
        return False, f"{arch_label} binary. Only x86/x64 supported."
    return True, None


def _find_section(pe_obj, names):
    for sect in pe_obj.sections:
        sect_name = sect.Name.rstrip(b"\x00").decode(errors="ignore").lower()
        if sect_name in names:
            return sect
    return None


def extract_ds1_features(file_path: str) -> pd.DataFrame | None:
    try:
        pe_obj = pefile.PE(file_path, fast_load=True)
        pe_obj.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"],
            ]
        )
    except Exception as exc:
        print(f"PE parse error: {exc}")
        return None

    def safe_get(fn, fallback=0):
        try:
            return fn()
        except Exception:
            return fallback

    fh = pe_obj.FILE_HEADER
    oh = pe_obj.OPTIONAL_HEADER

    sect_text = _find_section(pe_obj, [".text", "text"])
    sect_rsrc = _find_section(pe_obj, [".rsrc", "rsrc"])
    sect_data = _find_section(pe_obj, [".data", "data"])
    sect_idata = _find_section(pe_obj, [".idata", "idata"])
    sect_bss = _find_section(pe_obj, [".bss", "bss"])

    def sect_entropy(s):
        if not s:
            return 0.0
        try:
            return float(s.get_entropy() or 0.0)
        except Exception:
            return 0.0

    def sect_chars(s):
        return int(getattr(s, "Characteristics", 0)) if s else 0

    def sect_raw_sz(s):
        return int(getattr(s, "SizeOfRawData", 0)) if s else 0

    def sect_virt_sz(s):
        return int(getattr(s, "Misc_VirtualSize", 0)) if s else 0

    def sect_raw_off(s):
        return int(getattr(s, "PointerToRawData", 0)) if s else 0

    def sect_virt_rva(s):
        return int(getattr(s, "VirtualAddress", 0)) if s else 0

    pe_fields = {
        "Text_entro": sect_entropy(sect_text),
        "Rsrc_entro": sect_entropy(sect_rsrc),
        "Data_entro": sect_entropy(sect_data),
        "Idata_entro": sect_entropy(sect_idata),
        "bss_entro": sect_entropy(sect_bss),
        "nsec": len(pe_obj.sections or []),
        "codesize": safe_get(lambda: oh.SizeOfCode),
        "initdatsize": safe_get(lambda: oh.SizeOfInitializedData),
        "uninitdatsize": safe_get(lambda: oh.SizeOfUninitializedData),
        "adrentpt": safe_get(lambda: oh.AddressOfEntryPoint),
        "soi": safe_get(lambda: oh.SizeOfImage),
        "optcksum": safe_get(lambda: oh.CheckSum),
        "char": safe_get(lambda: fh.Characteristics),
        "dllch": safe_get(lambda: oh.DllCharacteristics),
        "Text_char": sect_chars(sect_text),
        "Rsrc_char": sect_chars(sect_rsrc),
        "Data_char": sect_chars(sect_data),
        "Idata_char": sect_chars(sect_idata),
        "bss_char": sect_chars(sect_bss),
        "Text_secsize": sect_raw_sz(sect_text),
        "Text_datsize": sect_virt_sz(sect_text),
        "Rsrc_secsize": sect_raw_sz(sect_rsrc),
        "Rsrc_datsize": sect_virt_sz(sect_rsrc),
        "Data_secsize": sect_raw_sz(sect_data),
        "Data_datsize": sect_virt_sz(sect_data),
        "Idata_secsize": sect_raw_sz(sect_idata),
        "Idata_datsize": sect_virt_sz(sect_idata),
        "bss_virsize": sect_virt_sz(sect_bss),
        "ibase": safe_get(lambda: oh.ImageBase),
        "ss": safe_get(lambda: oh.Subsystem),
        "secalign": safe_get(lambda: oh.SectionAlignment),
        "filealign": safe_get(lambda: oh.FileAlignment),
        "Text_byteaddr": sect_raw_off(sect_text),
        "Rsrc_byteaddr": sect_raw_off(sect_rsrc),
        "Data_byteaddr": sect_raw_off(sect_data),
        "Idata_byteaddr": sect_raw_off(sect_idata),
        "bss_viraddr": sect_virt_rva(sect_bss),
        "Text_mscfaddr": sect_virt_rva(sect_text),
        "Rsrc_mscfaddr": sect_virt_rva(sect_rsrc),
        "Data_mscfaddr": sect_virt_rva(sect_data),
        "Idata_mscfaddr": sect_virt_rva(sect_idata),
        "bss_phyaddr": sect_raw_off(sect_bss),
        "cbase": safe_get(lambda: oh.BaseOfCode),
        "dbase": safe_get(lambda: getattr(oh, "BaseOfData", 0)),
        "majssver": safe_get(lambda: oh.MajorSubsystemVersion),
        "minssver": safe_get(lambda: oh.MinorSubsystemVersion),
        "majosver": safe_get(lambda: oh.MajorOperatingSystemVersion),
        "minosver": safe_get(lambda: oh.MinorOperatingSystemVersion),
        "majiver": safe_get(lambda: oh.MajorImageVersion),
        "miniver": safe_get(lambda: oh.MinorImageVersion),
        "majlv": safe_get(lambda: oh.MajorLinkerVersion),
        "minlv": safe_get(lambda: oh.MinorLinkerVersion),
        "sosr": safe_get(lambda: oh.SizeOfStackReserve),
        "sosc": safe_get(lambda: oh.SizeOfStackCommit),
        "sohr": safe_get(lambda: oh.SizeOfHeapReserve),
        "sohc": safe_get(lambda: oh.SizeOfHeapCommit),
        "ndirent": safe_get(lambda: oh.NumberOfRvaAndSizes),
        "mach": safe_get(lambda: fh.Machine),
        "sig": safe_get(lambda: pe_obj.NT_HEADERS.Signature),
        "ohs": safe_get(lambda: fh.SizeOfOptionalHeader),
        "win32vv": safe_get(lambda: oh.Win32VersionValue),
        "soh": safe_get(lambda: oh.SizeOfHeaders),
    }
    return pd.DataFrame([pe_fields])[DS1_FEATURE_COLS]


def predict_ds1(feat_df: pd.DataFrame | None, model_key: str, thr: float) -> dict | None:
    if feat_df is None or model_key not in REAL_MODELS:
        return None
    model_info = MODEL_REGISTRY[model_key]
    model_metrics = MOCK_METRICS[model_key]
    try:
        proba = REAL_MODELS[model_key].predict_proba(feat_df)
        threat_score = float(proba[0][1])
    except Exception as exc:
        print(f"[predict] {model_key}: {exc}")
        return None
    is_malicious = threat_score >= thr
    return {
        "model_key": model_key,
        "score": round(threat_score, 4),
        "label": "Malicious" if is_malicious else "Benign",
        "threshold": thr,
        "triggered": is_malicious,
        "using_real_model": True,
        **model_info,
        "metrics": model_metrics,
    }


def get_top_features(feat_df: pd.DataFrame | None) -> list:
    if feat_df is None or "ds1_rf" not in REAL_MODELS:
        return []
    try:
        importances = REAL_MODELS["ds1_rf"].feature_importances_
        ranked = sorted(zip(DS1_FEATURE_COLS, importances), key=lambda x: x[1], reverse=True)[:15]
        return [{"name": fname, "importance": round(float(imp), 4)} for fname, imp in ranked]
    except Exception:
        return []


def compute_verdict(ml_predictions: list[dict]) -> tuple[str, float, str]:
    if not ml_predictions:
        return "Unknown", 0.0, "low"
    avg_score = sum(r["score"] for r in ml_predictions) / len(ml_predictions)
    triggered_count = sum(1 for r in ml_predictions if r["triggered"])
    max_score = max(r["score"] for r in ml_predictions)
    majority_vote = triggered_count >= 2
    if avg_score >= 0.70:
        verdict, threat_level = "Malicious", "critical"
    elif avg_score >= 0.55 or (majority_vote and avg_score >= 0.45):
        verdict, threat_level = "Malicious", "high"
    elif avg_score >= 0.40 or majority_vote:
        verdict, threat_level = "Suspicious", "medium"
    elif triggered_count >= 1 or max_score >= 0.30:
        verdict, threat_level = "Suspicious", "low"
    else:
        verdict, threat_level = "Benign", "low"
    return verdict, round(avg_score, 4), threat_level


def lookup_virustotal(sha256: str, api_key: str = "", api_url: str = "") -> dict | None:
    api_key = api_key or settings.vt_api_key
    api_url = api_url or settings.vt_url
    if not api_key:
        return None
    try:
        resp = requests.get(api_url, params={"apikey": api_key, "resource": sha256}, timeout=15)
        if resp.status_code == 200:
            vt_payload = resp.json()
            if vt_payload.get("response_code") == 1:
                return {
                    "positives": vt_payload.get("positives", 0),
                    "total": vt_payload.get("total", 0),
                    "scan_date": vt_payload.get("scan_date", ""),
                    "permalink": vt_payload.get("permalink", ""),
                }
    except Exception:
        return {"error": "VirusTotal request failed"}
    return None


def apply_vt_adjustments(
    ml_predictions: list[dict], vt_info: dict | None, thr: float
) -> tuple[str, float, str]:
    if vt_info and "error" not in vt_info and vt_info["total"] > 0:
        vt_ratio = vt_info["positives"] / vt_info["total"]
        for pred in ml_predictions:
            blended = round(pred["score"] * 0.5 + vt_ratio * 0.5, 4)
            pred["score"] = blended
            pred["triggered"] = blended >= thr
            pred["label"] = "Malicious" if pred["triggered"] else "Benign"

    verdict, avg_score, threat_level = compute_verdict(ml_predictions)

    if vt_info and "error" not in vt_info:
        pos_count = vt_info["positives"]
        vt_total = vt_info["total"]
        if pos_count > 5:
            verdict, threat_level = "Malicious", "critical"
        elif pos_count > 0 and verdict == "Benign":
            verdict, threat_level = "Suspicious", "medium"
        elif pos_count == 0 and vt_total >= 10 and avg_score < 0.65:
            verdict, threat_level = "Benign", "low"

    return verdict, avg_score, threat_level


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

HIGH_RISK_IMPORTS = {
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
        pe_obj = pefile.PE(file_path, fast_load=True)
        pe_obj.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        if hasattr(pe_obj, "DIRECTORY_ENTRY_IMPORT"):
            for imp_entry in pe_obj.DIRECTORY_ENTRY_IMPORT:
                dll_name = imp_entry.dll.decode(errors="ignore") if imp_entry.dll else ""
                for imp_func in imp_entry.imports:
                    func_name = ""
                    if imp_func.name:
                        func_name = imp_func.name.decode(errors="ignore")
                    elif imp_func.ordinal:
                        func_name = f"Ordinal_{imp_func.ordinal}"
                    for danger_fn in DANGEROUS_IMPORTS:
                        if func_name.lower().startswith(danger_fn.lower()):
                            dangerous_found.append(
                                {
                                    "function": func_name,
                                    "dll": dll_name,
                                    "severity": "high"
                                    if danger_fn in HIGH_RISK_IMPORTS
                                    else "medium",
                                }
                            )
                            break
                    for mitre_fn, mitre_data in MITRE_MAPPING.items():
                        if mitre_fn.lower() in func_name.lower():
                            if mitre_data["id"] not in mitre_seen:
                                mitre_seen.add(mitre_data["id"])
                                mitre_techniques.append(mitre_data)
                            break
    except Exception:
        pass

    # тут иногда падает, если файл пустой, пока оставил так
    try:
        with open(file_path, "rb") as fh:
            raw_bytes = fh.read()
        ascii_chunks = re.findall(rb"[\x20-\x7e]{6,}", raw_bytes)
        decoded_strings = [s.decode("ascii", errors="ignore") for s in ascii_chunks[:5000]]
        for s in decoded_strings:
            for pattern, label in SUSPICIOUS_PATTERNS:
                if re.search(pattern, s, re.IGNORECASE):
                    suspicious_strings.append({"string": s[:120], "type": label})
                    break
    except Exception:
        pass

    seen_strings: set[str] = set()
    deduped = []
    for entry in suspicious_strings:
        if entry["string"] not in seen_strings:
            seen_strings.add(entry["string"])
            deduped.append(entry)

    risk_score = min(100, len(dangerous_found) * 12 + len(deduped) * 5)

    if risk_score >= 70:
        risk_level = "critical"
    elif risk_score >= 40:
        risk_level = "high"
    elif risk_score >= 20:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "dangerous_imports": dangerous_found[:30],
        "suspicious_strings": deduped[:30],
        "mitre_techniques": mitre_techniques,
        "risk_score": risk_score,
        "summary": {
            "dangerous_count": len(dangerous_found),
            "suspicious_count": len(deduped),
            "mitre_count": len(mitre_techniques),
            "risk_level": risk_level,
        },
    }


def process_scan(
    file_path: str,
    threshold: float,
    mode: str,
    use_vt: bool,
    sha256: str = "",
    on_step=None,
) -> dict:
    def _notify(step_name: str):
        if on_step:
            on_step(step_name)

    scan_start = time.time()
    mode_offset = MODE_THRESHOLD_OFFSETS.get(mode, 0.0)
    effective_thr = max(0.1, min(0.95, threshold + mode_offset))

    _notify("extracting_features")
    feat_df = extract_ds1_features(file_path)
    if feat_df is None:
        raise ValueError("PE parsing failed")

    machine_val = int(feat_df["mach"].iloc[0])
    if machine_val not in SUPPORTED_ARCHS:
        arch_label = ARCH_NAMES.get(machine_val, f"unknown (0x{machine_val:04X})")
        raise ValueError(f"{arch_label} binary. Only x86/x64 supported.")

    _notify("running_models")
    ml_predictions = []
    for model_key in MODEL_ORDER:
        pred_result = predict_ds1(feat_df, model_key, effective_thr)
        if pred_result is not None:
            ml_predictions.append(pred_result)

    if not ml_predictions:
        raise RuntimeError("Models not loaded")

    feat_importance = {"DS1": get_top_features(feat_df)}

    _notify("computing_verdict")
    vt_info = None
    if use_vt and sha256:
        vt_info = lookup_virustotal(sha256)

    verdict, avg_score, threat_level = apply_vt_adjustments(ml_predictions, vt_info, effective_thr)
    strings_report = extract_suspicious_strings(file_path)
    scan_duration = round(time.time() - scan_start, 2)

    return {
        "verdict": verdict,
        "risk_level": threat_level,
        "score": avg_score,
        "scan_time": scan_duration,
        "threshold": effective_thr,
        "ml_results": ml_predictions,
        "features": feat_importance,
        "vt_result": vt_info,
        "models_used": {"ds1": True, "vt": use_vt},
        "pe_parse_ok": True,
        "strings_analysis": strings_report,
    }
