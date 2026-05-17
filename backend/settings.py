import os
from pathlib import Path


def _env_bool(key: str, fallback: bool = False) -> bool:
    raw = os.getenv(key)
    if raw is None:
        return fallback
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(key: str, fallback: int) -> int:
    raw = os.getenv(key)
    return fallback if raw is None else int(raw)


def _env_csv(key: str, fallback: str) -> tuple[str, ...]:
    raw = os.getenv(key, fallback)
    return tuple(x.strip() for x in raw.split(",") if x.strip())


class Settings:
    def __init__(self) -> None:
        self.app_name = os.getenv("APP_NAME", "CyberScan Portal API")
        self.app_version = os.getenv("APP_VERSION", "2.0.0")
        self.cors_origins = _env_csv("CORS_ORIGINS", "http://localhost:3000")
        self.upload_dir = Path(os.getenv("UPLOAD_DIR", "uploads"))
        self.db_path = Path(os.getenv("DB_PATH", "scans.db"))
        self.vt_api_key = os.getenv("VT_API_KEY", "")
        self.vt_url = os.getenv("VT_URL", "https://www.virustotal.com/vtapi/v2/file/report")
        self.jwt_secret = os.getenv("JWT_SECRET", "change-me-in-production")
        self.jwt_algorithm = os.getenv("JWT_ALGORITHM", "HS256")
        self.jwt_expire_days = _env_int("JWT_EXPIRE_DAYS", 7)
        self.host = os.getenv("HOST", "0.0.0.0")
        self.port = _env_int("PORT", 8000)
        self.reload = _env_bool("RELOAD", True)


settings = Settings()
