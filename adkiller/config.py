"""Minimal, foolproof configuration loader for AI-智能广告杀手."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int_set(name: str) -> set[int]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return set()
    ids: set[int] = set()
    for part in raw.split(","):
        part = part.strip()
        if part:
            try:
                ids.add(int(part))
            except ValueError:
                pass
    return ids


def _env_str_set(name: str, default: str = "") -> set[str]:
    raw = os.getenv(name, default).strip()
    return {p.strip().lower().lstrip("@") for p in raw.split(",") if p.strip()}


@dataclass
class AppConfig:
    # Core 4 fields (everything else has sensible defaults)
    telegram_bot_token: str = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    ai_api_key: str = os.getenv("AI_API_KEY", "").strip()
    ai_base_url: str = os.getenv("AI_BASE_URL", "https://api.deepseek.com/v1").strip()
    ai_model: str = os.getenv("AI_MODEL", "deepseek-flash").strip()

    # Optional access & runtime controls
    owner_ids: set[int] = field(default_factory=lambda: _env_int_set("OWNER_IDS"))
    allowed_group_ids: set[int] = field(default_factory=lambda: _env_int_set("ALLOWED_GROUP_IDS"))
    allowed_via_bots: set[str] = field(
        default_factory=lambda: _env_str_set("ALLOWED_VIA_BOTS", "gif,pic,bing,vid")
    )

    # Defaults for newly joined groups (all toggleable live via /config in Telegram)
    default_spam_score: int = int(os.getenv("DEFAULT_SPAM_SCORE", "80"))
    default_flood_window: int = int(os.getenv("DEFAULT_FLOOD_WINDOW", "8"))
    default_flood_max: int = int(os.getenv("DEFAULT_FLOOD_MAX", "6"))
    default_dry_run: bool = _env_bool("DEFAULT_DRY_RUN", False)
    strict_new_user_msgs: int = int(os.getenv("STRICT_NEW_USER_MSGS", "3"))
    ai_timeout_seconds: float = float(os.getenv("AI_TIMEOUT_SECONDS", "15"))
    ai_concurrency: int = int(os.getenv("AI_CONCURRENCY", "5"))

    db_path: str = os.getenv("DB_PATH", "data/adkiller.db").strip()
    cas_api_key: str = os.getenv("CAS_API_KEY", "").strip()
    log_level: str = os.getenv("LOG_LEVEL", "INFO").strip().upper()

    def validate(self) -> None:
        if not self.telegram_bot_token:
            raise SystemExit("缺少必填配置 TELEGRAM_BOT_TOKEN，请在 .env 中填写。")
        # AI_API_KEY is now optional: without it, AI-智能广告杀手 runs in full Basic Local Defense mode!
