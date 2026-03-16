import os
from pathlib import Path


def _get_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    return int(raw)


def _get_csv(name: str, default: str) -> tuple[str, ...]:
    raw = os.getenv(name, default)
    return tuple(item.strip() for item in raw.split(",") if item.strip())


class Settings:
    def __init__(self) -> None:
        self.app_name = os.getenv("APP_NAME", "CyberScan Portal API")
        self.app_version = os.getenv("APP_VERSION", "4.0.0")

        self.cors_origins = _get_csv("CORS_ORIGINS", "http://localhost:3000")

        self.upload_dir = Path(os.getenv("UPLOAD_DIR", "uploads"))
        self.db_path = Path(os.getenv("DB_PATH", "scans.db"))

        self.vt_api_key = os.getenv("VT_API_KEY", "")
        self.vt_url = os.getenv(
            "VT_URL",
            "https://www.virustotal.com/vtapi/v2/file/report",
        )

        self.jwt_secret = os.getenv("JWT_SECRET", "change-me-in-production")
        self.jwt_algorithm = os.getenv("JWT_ALGORITHM", "HS256")
        self.jwt_expire_days = _get_int("JWT_EXPIRE_DAYS", 7)

        self.host = os.getenv("HOST", "0.0.0.0")
        self.port = _get_int("PORT", 8000)
        self.reload = _get_bool("RELOAD", True)


settings = Settings()
