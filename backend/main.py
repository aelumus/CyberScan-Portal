"""
Malware Detection Using Static Analysis and Machine Learning
FastAPI Backend — v4.0
Features: SQLite persistence, suspicious strings, SHAP, ROC/CM, PDF export, JWT Auth
"""

import contextlib
import hashlib
import io
import json
import re
import sqlite3
import time
import uuid
import warnings
from datetime import datetime, timedelta
from pathlib import Path

import aiofiles
import joblib
import pandas as pd
import pefile
import requests
import uvicorn
from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from settings import settings

try:
    import yara

    HAS_YARA = True
except ImportError:
    HAS_YARA = False
    print("[yara] WARNING: yara-python not installed. YARA scanning disabled.")

try:
    from jose import JWTError, jwt

    HAS_AUTH = True
except ImportError:
    HAS_AUTH = False
    print("[auth] WARNING: python-jose not installed. Auth endpoints disabled.")

warnings.filterwarnings("ignore")

# ── App Setup ──────────────────────────────────────────────────────────────────
app = FastAPI(title=settings.app_name, version=settings.app_version)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = settings.upload_dir
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

VT_API_KEY = settings.vt_api_key
VT_URL = settings.vt_url

# ── Auth Config ───────────────────────────────────────────────────────────────
JWT_SECRET = settings.jwt_secret
JWT_ALGORITHM = settings.jwt_algorithm
JWT_EXPIRE_DAYS = settings.jwt_expire_days


def _hash_password(password: str) -> str:
    # Use built-in SHA-256 to avoid bcrypt/passlib issues on Windows
    return hashlib.sha256(f"cyber_{password}_scan".encode()).hexdigest()


bearer_scheme = HTTPBearer(auto_error=False)


def _verify_password(plain: str, hashed: str) -> bool:
    return _hash_password(plain) == hashed


def _create_token(user_id: int, username: str) -> str:
    if not HAS_AUTH:
        return ""
    payload = {
        "sub": str(user_id),
        "username": username,
        "exp": datetime.utcnow() + timedelta(days=JWT_EXPIRE_DAYS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _decode_token(token: str) -> dict | None:
    if not HAS_AUTH:
        return None
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError:
        return None


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict | None:
    """Returns decoded token payload or None (routes can be either protected or optional)."""
    if not credentials:
        return None
    return _decode_token(credentials.credentials)


def require_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme)) -> dict:
    """Like get_current_user but raises 401 if not authenticated."""
    user = get_current_user(credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


# ── SQLite Persistence ─────────────────────────────────────────────────────────
DB_PATH = settings.db_path


def _init_db():
    with sqlite3.connect(DB_PATH) as conn:
        # Scans table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                user_id INTEGER
            )
        """)
        # Try to add user_id column if upgrading from older schema
        with contextlib.suppress(sqlite3.OperationalError):
            conn.execute("ALTER TABLE scans ADD COLUMN user_id INTEGER")
        # Users table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.commit()


_init_db()


def _save_scan(scan_id: str, record: dict, user_id: int | None = None):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO scans (id, data, created_at, user_id) VALUES (?, ?, ?, ?)",
            (
                scan_id,
                json.dumps(record),
                record.get("created_at", datetime.now().isoformat()),
                user_id,
            ),
        )
        conn.commit()


def _get_scan(scan_id: str) -> dict | None:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT data FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return json.loads(row[0]) if row else None


def _require_scan_record(scan_id: str) -> dict:
    record = _get_scan(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return record


def _find_uploaded_scan(scan_id: str, missing_detail: str) -> Path:
    matching = list(UPLOAD_DIR.glob(f"{scan_id}_*"))
    if not matching:
        raise HTTPException(status_code=404, detail=missing_detail)
    return matching[0]


def _get_all_scans(user_id: int | None = None) -> list[dict]:
    with sqlite3.connect(DB_PATH) as conn:
        if user_id is not None:
            rows = conn.execute(
                "SELECT data FROM scans WHERE user_id = ? ORDER BY created_at DESC", (user_id,)
            ).fetchall()
        else:
            rows = conn.execute("SELECT data FROM scans ORDER BY created_at DESC").fetchall()
    return [json.loads(r[0]) for r in rows]


def _update_scan(scan_id: str, record: dict):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("UPDATE scans SET data = ? WHERE id = ?", (json.dumps(record), scan_id))
        conn.commit()


# ── User DB Helpers ────────────────────────────────────────────────────────────
def _create_user(username: str, email: str, password: str) -> dict:
    hashed = _hash_password(password)
    now = datetime.now().isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        try:
            cur = conn.execute(
                "INSERT INTO users (username, email, hashed_password, created_at) VALUES (?, ?, ?, ?)",
                (username, email.lower(), hashed, now),
            )
            conn.commit()
            return {
                "id": cur.lastrowid,
                "username": username,
                "email": email.lower(),
                "created_at": now,
            }
        except sqlite3.IntegrityError as e:
            raise ValueError(str(e)) from e


def _get_user_by_email(email: str) -> dict | None:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT id, username, email, hashed_password, created_at FROM users WHERE email = ?",
            (email.lower(),),
        ).fetchone()
    if not row:
        return None
    return {
        "id": row[0],
        "username": row[1],
        "email": row[2],
        "hashed_password": row[3],
        "created_at": row[4],
    }


def _get_user_by_id(user_id: int) -> dict | None:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT id, username, email, created_at FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    if not row:
        return None
    return {"id": row[0], "username": row[1], "email": row[2], "created_at": row[3]}


# ── DS1 Feature Columns ────────────────────────────────────────────────────────
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

# ── Load Real Models ───────────────────────────────────────────────────────────
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

REAL_MODELS = {}


def _load_models():
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


_load_models()

# ── SHAP Explainer (lazy-init) ─────────────────────────────────────────────────
_SHAP_EXPLAINER = None


def get_shap_explainer():
    global _SHAP_EXPLAINER
    if _SHAP_EXPLAINER is None and "ds1_rf" in REAL_MODELS:
        try:
            import shap

            _SHAP_EXPLAINER = shap.TreeExplainer(REAL_MODELS["ds1_rf"])
            print("[shap] TreeExplainer initialized")
        except Exception as e:
            print(f"[shap] init failed: {e}")
    return _SHAP_EXPLAINER


# ── Feature Extraction ─────────────────────────────────────────────────────────
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


# ── Suspicious Strings Detector ────────────────────────────────────────────────
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


def extract_suspicious_strings(file_path: str) -> dict:
    dangerous_found = []
    suspicious_strings = []
    mitre_techniques = []
    mitre_seen = set()

    # Scan PE imports
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
                    # Check against dangerous list
                    for danger in DANGEROUS_IMPORTS:
                        if func_name.lower().startswith(danger.lower()):
                            dangerous_found.append(
                                {
                                    "function": func_name,
                                    "dll": dll_name,
                                    "severity": "high"
                                    if danger
                                    in {
                                        "CreateRemoteThread",
                                        "VirtualAllocEx",
                                        "WriteProcessMemory",
                                        "URLDownloadToFile",
                                        "SetWindowsHookEx",
                                    }
                                    else "medium",
                                }
                            )
                            break

                    # Check for MITRE ATT&CK techniques
                    for mitre_func, mitre_data in MITRE_MAPPING.items():
                        if mitre_func.lower() in func_name.lower():
                            if mitre_data["id"] not in mitre_seen:
                                mitre_seen.add(mitre_data["id"])
                                mitre_techniques.append(mitre_data)
                            break
    except Exception:
        pass

    # Scan raw bytes for suspicious strings
    try:
        with open(file_path, "rb") as f:
            raw = f.read()
        # Extract printable ASCII strings (min 6 chars)
        ascii_strings = re.findall(rb"[\x20-\x7e]{6,}", raw)
        ascii_decoded = [s.decode("ascii", errors="ignore") for s in ascii_strings[:5000]]
        for s in ascii_decoded:
            for pattern, label in SUSPICIOUS_PATTERNS:
                if re.search(pattern, s, re.IGNORECASE):
                    suspicious_strings.append({"string": s[:120], "type": label})
                    break
    except Exception:
        pass

    # Deduplicate
    seen = set()
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
            "risk_level": "critical"
            if risk_score >= 70
            else "high"
            if risk_score >= 40
            else "medium"
            if risk_score >= 20
            else "low",
        },
    }


# ── Predict ────────────────────────────────────────────────────────────────────
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


# ── Model / Dataset Registry ──────────────────────────────────────────────────
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

DATASET_INFO = {
    "DS1": {
        "id": "DS1",
        "name": "PE Headers Dataset",
        "source": "SOMLAP_filtered_metrics_dataset.csv",
        "samples": 51408,
        "features": 62,
        "last_update": "2026",
        "description": "62 SOMLAP metrics extracted from PE headers and main sections.",
    },
}

# ── Precomputed ROC Curve Data (from offline evaluation on test split) ─────────
# These are approximate representative points for visualization
ROC_DATA = {
    "ds1_rf": {
        "fpr": [0.0, 0.002, 0.005, 0.010, 0.020, 0.035, 0.060, 0.100, 0.200, 0.400, 0.700, 1.0],
        "tpr": [0.0, 0.820, 0.910, 0.950, 0.970, 0.982, 0.990, 0.994, 0.997, 0.999, 0.9995, 1.0],
        "auc": 0.9978,
    },
    "ds1_xgb": {
        "fpr": [0.0, 0.001, 0.003, 0.008, 0.018, 0.030, 0.055, 0.090, 0.180, 0.380, 0.680, 1.0],
        "tpr": [0.0, 0.840, 0.920, 0.956, 0.974, 0.985, 0.992, 0.995, 0.998, 0.9992, 0.9997, 1.0],
        "auc": 0.9983,
    },
    "ds1_lgbm": {
        "fpr": [0.0, 0.001, 0.002, 0.006, 0.015, 0.028, 0.050, 0.085, 0.170, 0.360, 0.660, 1.0],
        "tpr": [0.0, 0.860, 0.930, 0.960, 0.978, 0.988, 0.993, 0.996, 0.998, 0.9995, 0.9998, 1.0],
        "auc": 0.9987,
    },
}

# Confusion Matrix at threshold=0.4, on test split (approx 10282 samples: 5141 benign, 5141 malicious)
CONFUSION_DATA = {
    "ds1_rf": {"tp": 5097, "fp": 21, "tn": 5120, "fn": 44, "total": 10282},
    "ds1_xgb": {"tp": 5108, "fp": 16, "tn": 5125, "fn": 33, "total": 10282},
    "ds1_lgbm": {"tp": 5115, "fp": 11, "tn": 5130, "fn": 26, "total": 10282},
}


# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "models_loaded": list(REAL_MODELS.keys()),
        "version": "4.0.0",
        "auth": HAS_AUTH,
    }


# ── Auth Routes ───────────────────────────────────────────────────────────────
@app.post("/api/auth/register")
def register(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
):
    if not HAS_AUTH:
        raise HTTPException(status_code=503, detail="Auth not available: install python-jose")
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    if len(username) < 2:
        raise HTTPException(status_code=400, detail="Username must be at least 2 characters")
    try:
        user = _create_user(username.strip(), email.strip(), password)
        token = _create_token(user["id"], user["username"])
        return {
            "token": token,
            "user": {"id": user["id"], "username": user["username"], "email": user["email"]},
        }
    except ValueError as e:
        print(f"[debug] Exception during registration: {repr(e)}")
        if "username" in str(e).lower():
            raise HTTPException(status_code=409, detail="Username already taken") from None
        elif "email" in str(e).lower():
            raise HTTPException(status_code=409, detail="Email already registered") from None
        raise HTTPException(status_code=409, detail=f"User already exists: {e}") from None


@app.post("/api/auth/login")
def login(
    email: str = Form(...),
    password: str = Form(...),
):
    if not HAS_AUTH:
        raise HTTPException(status_code=503, detail="Auth not available: install python-jose")
    user = _get_user_by_email(email.strip())
    if not user or not _verify_password(password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = _create_token(user["id"], user["username"])
    return {
        "token": token,
        "user": {"id": user["id"], "username": user["username"], "email": user["email"]},
    }


@app.get("/api/auth/debug")
def debug_db():
    with sqlite3.connect(DB_PATH) as conn:
        schema = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='users'"
        ).fetchone()
        data = conn.execute("SELECT * FROM users LIMIT 10").fetchall()
        return {"schema": schema[0] if schema else None, "data": data}


@app.get("/api/auth/me")
def get_me(current_user: dict = Depends(require_user)):
    user = _get_user_by_id(int(current_user["sub"]))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    scans = _get_all_scans(user_id=user["id"])
    return {**user, "scan_count": len(scans)}


@app.get("/api/dashboard/stats")
def dashboard_stats():
    scans = _get_all_scans()
    total = len(scans)
    malicious = sum(1 for s in scans if s["verdict"] == "Malicious")
    rate = round(malicious / total * 100, 1) if total else 0.0
    avg_time = round(sum(s.get("scan_time", 0) for s in scans) / total, 2) if total else 0.0
    return {
        "total_scans": total,
        "malicious_rate": rate,
        "avg_scan_time": avg_time,
        "models_online": len(REAL_MODELS),
        "models_total": 3,
    }


@app.get("/api/dashboard/chart")
def dashboard_chart():
    today = datetime.now().date()
    day_data: dict[str, dict] = {}
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        day_data[str(day)] = {"date": day.strftime("%b %d"), "scans": 0, "malicious": 0}
    for s in _get_all_scans():
        try:
            scan_date = s["created_at"][:10]
            if scan_date in day_data:
                day_data[scan_date]["scans"] += 1
                if s["verdict"] == "Malicious":
                    day_data[scan_date]["malicious"] += 1
        except Exception:
            pass
    return {"data": list(day_data.values())}


@app.get("/api/scans")
def get_scans(current_user: dict | None = Depends(get_current_user)):
    uid = int(current_user["sub"]) if current_user else None
    return {"scans": _get_all_scans(user_id=uid)}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    return _require_scan_record(scan_id)


@app.get("/api/scans/{scan_id}/strings")
def get_scan_strings(scan_id: str):
    record = _require_scan_record(scan_id)
    # If already computed, return cached result
    if "strings_analysis" in record:
        return record["strings_analysis"]
    file_path = _find_uploaded_scan(scan_id, "File not available for string analysis")
    result = extract_suspicious_strings(str(file_path))
    # Cache in DB
    record["strings_analysis"] = result
    _update_scan(scan_id, record)
    return result


@app.get("/api/scans/{scan_id}/shap")
def get_scan_shap(scan_id: str):
    record = _require_scan_record(scan_id)
    if "shap_values" in record:
        return {
            "shap_values": record["shap_values"],
            "expected_value": record.get("shap_expected", 0),
        }
    file_path = _find_uploaded_scan(scan_id, "File not available for SHAP analysis")
    features_df = extract_ds1_features(str(file_path))
    if features_df is None:
        raise HTTPException(status_code=422, detail="PE parsing failed")
    explainer = get_shap_explainer()
    if explainer is None:
        raise HTTPException(
            status_code=503, detail="SHAP explainer not available (RF model not loaded)"
        )
    try:
        shap_vals = explainer.shap_values(features_df)
        # shap_vals shape: (2, n_samples, n_features) for RF binary
        # Take class 1 (Malicious) values for first sample
        if isinstance(shap_vals, list):
            vals = shap_vals[1][0]  # class 1, first sample
            expected = float(explainer.expected_value[1])
        else:
            vals = shap_vals[0]
            expected = float(explainer.expected_value)
        feature_shap = [
            {
                "feature": feat,
                "shap_value": round(float(v), 5),
                "feature_value": round(float(fv), 4),
            }
            for feat, v, fv in zip(DS1_FEATURE_COLS, vals, features_df.iloc[0].values)
        ]
        feature_shap.sort(key=lambda x: abs(x["shap_value"]), reverse=True)
        top15 = feature_shap[:15]
        record["shap_values"] = top15
        record["shap_expected"] = expected
        _update_scan(scan_id, record)
        return {"shap_values": top15, "expected_value": expected}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SHAP computation failed: {e}") from e


@app.get("/api/scans/{scan_id}/pdf")
def download_pdf(scan_id: str, current_user: dict | None = Depends(get_current_user)):
    record = _require_scan_record(scan_id)

    # Check ownership if auth is used
    user_id = int(current_user["sub"]) if current_user else None
    if user_id is not None and record.get("user_id") is not None and record["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to view this scan")

    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            HRFlowable,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=A4,
            leftMargin=2 * cm,
            rightMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )
        styles = getSampleStyleSheet()

        DARK = colors.HexColor("#1e1b4b")
        ACCENT = colors.HexColor("#4f46e5")
        RED = colors.HexColor("#ef4444")
        GREEN = colors.HexColor("#10b981")
        AMBER = colors.HexColor("#f59e0b")
        GRAY = colors.HexColor("#64748b")

        verdict_color = (
            RED
            if record["verdict"] == "Malicious"
            else (AMBER if record["verdict"] == "Suspicious" else GREEN)
        )

        title_style = ParagraphStyle(
            "title",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=22,
            textColor=DARK,
            spaceAfter=4,
            alignment=TA_LEFT,
        )
        subtitle_style = ParagraphStyle(
            "sub", parent=styles["Normal"], fontName="Helvetica", fontSize=10, textColor=GRAY
        )
        section_style = ParagraphStyle(
            "section",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=12,
            textColor=ACCENT,
            spaceBefore=14,
            spaceAfter=6,
        )
        ParagraphStyle(
            "body", parent=styles["Normal"], fontName="Helvetica", fontSize=9, textColor=DARK
        )

        story = []

        # Header
        story.append(Paragraph("CyberScan Portal", title_style))
        story.append(Paragraph("Malware Analysis Report", subtitle_style))
        story.append(Spacer(1, 0.3 * cm))
        story.append(HRFlowable(width="100%", thickness=2, color=ACCENT))
        story.append(Spacer(1, 0.4 * cm))

        # Verdict
        story.append(Paragraph("VERDICT", section_style))
        verdict_table = Table(
            [
                [
                    Paragraph(
                        record["verdict"].upper(),
                        ParagraphStyle(
                            "v", fontName="Helvetica-Bold", fontSize=20, textColor=verdict_color
                        ),
                    ),
                    Paragraph(
                        f"Risk: {record.get('risk_level', '—').upper()}\nScore: {round(record.get('score', 0) * 100, 1)}%",
                        ParagraphStyle("r", fontName="Helvetica", fontSize=11, textColor=GRAY),
                    ),
                ],
            ],
            colWidths=[8 * cm, 9 * cm],
        )
        verdict_table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
        story.append(verdict_table)
        story.append(Spacer(1, 0.3 * cm))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0")))

        # File Info
        story.append(Paragraph("FILE INFORMATION", section_style))
        info_data = [
            ["Field", "Value"],
            ["Filename", record.get("filename", "—")],
            ["SHA256", record.get("sha256", "—")[:32] + "..."],
            ["MD5", record.get("md5", "—")],
            ["File Size", f"{round((record.get('file_size', 0)) / 1024, 1)} KB"],
            ["Scan Date", record.get("created_at", "—")[:19]],
            ["Mode", record.get("mode", "—")],
            ["Threshold", str(record.get("threshold", "—"))],
            ["PE Parse OK", "Yes" if record.get("pe_parse_ok") else "No"],
        ]
        info_table = Table(info_data, colWidths=[5 * cm, 12 * cm])
        info_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#f8fafc")],
                    ),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.append(info_table)

        # ML Results
        if record.get("ml_results"):
            story.append(Paragraph("ML MODEL SCORES", section_style))
            ml_data = [["Model", "Score", "Triggered", "Real Model"]]
            for r in record["ml_results"]:
                ml_data.append(
                    [
                        r.get("name", r.get("algo", "—")),
                        f"{round(r.get('score', 0) * 100, 1)}%",
                        "YES" if r.get("triggered") else "no",
                        "✓" if r.get("using_real_model") else "mock",
                    ]
                )
            ml_table = Table(ml_data, colWidths=[5 * cm, 3 * cm, 4 * cm, 5 * cm])
            ml_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [colors.white, colors.HexColor("#f8fafc")],
                        ),
                        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ]
                )
            )
            story.append(ml_table)

        # Top Features
        if record.get("features", {}).get("DS1"):
            story.append(Paragraph("TOP FEATURE IMPORTANCES (DS1)", section_style))
            top = record["features"]["DS1"][:10]
            feat_data = [["Feature", "Importance"]] + [
                [f["name"], f"{round(f['importance'] * 100, 2)}%"] for f in top
            ]
            feat_table = Table(feat_data, colWidths=[10 * cm, 7 * cm])
            feat_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [colors.white, colors.HexColor("#f8fafc")],
                        ),
                        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ]
                )
            )
            story.append(feat_table)

        # Footer
        story.append(Spacer(1, 0.5 * cm))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0")))
        story.append(Spacer(1, 0.2 * cm))
        story.append(
            Paragraph(
                f"Generated by CyberScan Portal v3.0 · {datetime.now().strftime('%Y-%m-%d %H:%M')} · Scan ID: {scan_id}",
                ParagraphStyle(
                    "footer", fontName="Helvetica", fontSize=7, textColor=GRAY, alignment=TA_CENTER
                ),
            )
        )

        doc.build(story)
        buf.seek(0)
        filename = f"cyberscan_{record.get('filename', 'report').replace('.', '_')}_{scan_id}.pdf"
        return StreamingResponse(
            buf,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}") from e


@app.post("/api/scan")
async def run_scan(
    file: UploadFile = File(...),
    use_vt: bool = Form(False),
    threshold: float = Form(0.4),
    mode: str = Form("balanced"),
    current_user: dict | None = Depends(get_current_user),
):
    start_time = time.time()
    scan_id = str(uuid.uuid4())[:8]
    user_id = int(current_user["sub"]) if current_user else None

    file_path = UPLOAD_DIR / f"{scan_id}_{file.filename}"
    async with aiofiles.open(file_path, "wb") as f:
        content = await file.read()
        await f.write(content)

    sha256 = hashlib.sha256(content).hexdigest()
    md5 = hashlib.md5(content).hexdigest()
    file_size = len(content)

    mode_offset = MODE_THRESHOLD_OFFSETS.get(mode, 0.0)
    thr = max(0.1, min(0.95, threshold + mode_offset))

    ds1_features = extract_ds1_features(str(file_path))
    ds1_ok = ds1_features is not None

    if not ds1_ok:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "PE parsing failed",
                "message": f"'{file.filename}' is not a valid PE file.",
            },
        )

    machine_val = int(ds1_features["mach"].iloc[0])
    if machine_val not in SUPPORTED_MACHINE_ARCHS:
        arch = LEGACY_MACHINE_NAMES.get(machine_val, f"unknown (0x{machine_val:04X})")
        raise HTTPException(
            status_code=422,
            detail={
                "error": "Unsupported architecture",
                "message": f"'{file.filename}' is a {arch} binary. Only x86/x64 supported.",
            },
        )

    ml_results = []
    for key in MODEL_ORDER:
        result = predict_ds1(ds1_features, key, thr)
        if result is not None:
            ml_results.append(result)

    if not ml_results:
        raise HTTPException(status_code=503, detail={"error": "Models not loaded"})

    features_by_ds = {"DS1": get_top_features(ds1_features)}

    # VirusTotal
    vt_result = None
    if use_vt:
        try:
            resp = requests.get(
                VT_URL, params={"apikey": VT_API_KEY, "resource": sha256}, timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("response_code") == 1:
                    vt_result = {
                        "positives": data.get("positives", 0),
                        "total": data.get("total", 0),
                        "scan_date": data.get("scan_date", ""),
                        "permalink": data.get("permalink", ""),
                    }
        except Exception:
            vt_result = {"error": "VirusTotal request failed"}

    if vt_result and "error" not in vt_result and vt_result["total"] > 0:
        vt_ratio = vt_result["positives"] / vt_result["total"]
        for r in ml_results:
            adjusted = round(r["score"] * 0.5 + vt_ratio * 0.5, 4)
            r["score"] = adjusted
            r["triggered"] = adjusted >= thr
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

    # Suspicious strings (fast, run synchronously — usually <1s)
    strings_analysis = extract_suspicious_strings(str(file_path))

    scan_time = round(time.time() - start_time, 2)

    record = {
        "id": scan_id,
        "filename": file.filename,
        "sha256": sha256,
        "md5": md5,
        "file_size": file_size,
        "verdict": verdict,
        "risk_level": risk_level,
        "score": avg_score,
        "scan_time": scan_time,
        "threshold": thr,
        "mode": mode,
        "created_at": datetime.now().isoformat(),
        "ml_results": ml_results,
        "features": features_by_ds,
        "vt_result": vt_result,
        "models_used": {"ds1": True, "vt": use_vt},
        "pe_parse_ok": ds1_ok,
        "strings_analysis": strings_analysis,
    }
    _save_scan(scan_id, record, user_id=user_id)
    return record


class YaraRequest(BaseModel):
    rule: str


@app.post("/api/scans/{scan_id}/yara")
def run_yara_rule(
    scan_id: str, request: YaraRequest, current_user: dict | None = Depends(get_current_user)
):
    """Runs a custom YARA rule against a previously uploaded file."""
    if not HAS_YARA:
        raise HTTPException(status_code=503, detail="YARA engine is not installed on the server.")

    # Check if scan exists and belongs to user
    record = _require_scan_record(scan_id)

    if record.get("user_id") and (
        not current_user or int(current_user["sub"]) != record["user_id"]
    ):
        raise HTTPException(status_code=403, detail="Not authorized to access this scan")

    # Legacy scans might not have filename perfectly normalized, fallback logic:
    filename = record.get("filename") or record.get("original_filename") or "unknown.exe"
    file_path = UPLOAD_DIR / f"{scan_id}_{filename}"

    if not file_path.exists():
        raise HTTPException(
            status_code=404, detail="Original file not found on server for YARA scanning"
        )

    try:
        # Compile rule
        rule = yara.compile(source=request.rule)
    except yara.SyntaxError as e:
        return {"success": False, "error": f"YARA Syntax Error: {str(e)}", "matches": []}
    except Exception as e:
        return {"success": False, "error": f"YARA Compilation Error: {str(e)}", "matches": []}

    try:
        # Run rule against file
        matches = rule.match(str(file_path))

        match_results = []
        for match in matches:
            str_matches = []
            for m in match.strings[:50]:
                if hasattr(m, "instances") and hasattr(m, "identifier"):
                    for inst in m.instances[:2]:  # Limit instances per string
                        d = getattr(inst, "matched_data", b"")
                        str_matches.append(
                            {
                                "offset": getattr(inst, "offset", 0),
                                "identifier": m.identifier,
                                "data": d.decode("ascii", errors="ignore")
                                if isinstance(d, bytes)
                                else str(d),
                            }
                        )
                else:
                    with contextlib.suppress(Exception):
                        str_matches.append(
                            {
                                "offset": m[0],
                                "identifier": m[1],
                                "data": m[2].decode("ascii", errors="ignore")
                                if isinstance(m[2], bytes)
                                else str(m[2]),
                            }
                        )

            match_results.append(
                {"rule": match.rule, "tags": match.tags, "meta": match.meta, "strings": str_matches}
            )

        return {"success": True, "error": None, "matches": match_results}
    except Exception as e:
        return {"success": False, "error": f"YARA Execution Error: {str(e)}", "matches": []}


@app.get("/api/models")
def get_models():
    return {
        "models": [
            {
                "id": key,
                **MODEL_REGISTRY[key],
                "metrics": MOCK_METRICS[key],
                "loaded": key in REAL_MODELS,
            }
            for key in MODEL_ORDER
        ]
    }


@app.get("/api/models/roc")
def get_roc():
    return {"roc": ROC_DATA}


@app.get("/api/models/confusion")
def get_confusion():
    return {"confusion": CONFUSION_DATA}


@app.get("/api/datasets")
def get_datasets():
    return {"datasets": list(DATASET_INFO.values())}


if __name__ == "__main__":
    uvicorn.run("main:app", host=settings.host, port=settings.port, reload=settings.reload)
