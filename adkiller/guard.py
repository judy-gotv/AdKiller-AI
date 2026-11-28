"""Core anti-spam engine: Flood, Swarm Review, CAS, Split-Pitch, Repeat-Escalation, Graduated Actions."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import secrets
import sqlite3
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Optional

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Message, MessageEntity, Update
from telegram.constants import ChatMemberStatus, ChatType
from telegram.error import TelegramError
from telegram.ext import ContextTypes

from .branding import DEFAULT_AVATAR_PATH
from .captcha import MUTE_PERMS, SimpleCaptchaManager
from .cas import CASChecker
from .config import AppConfig
from .llm import (
    UniversalAIClient,
    format_safe_llm_error,
    url_origin,
    validate_ai_base_url,
    validate_api_key,
    validate_model_name,
)
from .rules import evaluate_basic_rules
from .storage import GroupSettings, Storage
from .xray import (
    MessageXRay,
    analyze_profile_risk,
    extract_image_data_url,
    extract_xray,
)

logger = logging.getLogger("adkiller.guard")

# Telegram treats restrict until_date < 30s from now as permanent; require >= 45s safety margin.
MIN_FINITE_RESTRICT_SECONDS = 45
SHORT_CHAT_LENGTH = 20
_PLAIN_START_RE = re.compile(
    r"/start(?:@[A-Za-z0-9_]{5,32})?(?:[ \t]+[A-Za-z0-9_-]{1,64})?", re.IGNORECASE
)

DEFAULT_ANNOUNCE_TEMPLATE = (
    "🛡 AI-智能广告杀手已封禁用户：{user}\n"
    "• 理由：{reason}\n"
    "• 封禁时长：{duration}\n"
    "• {auto_delete}"
)
ANNOUNCE_MIN_DELETE_SECONDS = 10
ANNOUNCE_MAX_DELETE_SECONDS = 86400  # 24h
ANNOUNCE_MAX_TEMPLATE_LEN = 800
_ANNOUNCE_VAR_RE = re.compile(r"\{(user|user_id|reason|duration|auto_delete)\}")
_DELAY_INPUT_RE = re.compile(
    r"^(\d+)\s*(s|sec|secs|second|seconds|秒|m|min|mins|minute|minutes|分|分钟|h|hr|hrs|hour|hours|时|小时)?$"
)


@dataclass
class PendingAdminInput:
    target_group_id: int
    field_name: str
    panel_chat_id: int
    panel_msg_id: int
    expires_at: float


def format_delete_delay(seconds: int) -> str:
    sec = max(0, int(seconds))
    if sec == 0:
        return "不自动删除（永久保留）"
    if sec < 60:
        return f"{sec} 秒"
    if sec % 3600 == 0:
        return f"{sec // 3600} 小时"
    if sec % 60 == 0:
        return f"{sec // 60} 分钟"
    return f"{sec // 60} 分 {sec % 60} 秒"


def format_delete_short(seconds: int) -> str:
    sec = max(0, int(seconds))
    if sec == 0:
        return "不删"
    if sec < 60:
        return f"{sec}秒删"
    if sec % 3600 == 0:
        return f"{sec // 3600}时删"
    if sec % 60 == 0:
        return f"{sec // 60}分删"
    return f"{sec}秒删"


def parse_delete_delay_input(raw: str) -> Optional[int]:
    """Parse admin auto-delete duration input into seconds (0 = never; plain integer = minutes)."""
    text = (raw or "").strip().lower()
    if not text:
        return None
    if text in {"0", "off", "never", "none", "不删", "不删除", "永久", "永久保留", "关闭", "关"}:
        return 0
    m = _DELAY_INPUT_RE.match(text)
    if not m:
        return None
    val = int(m.group(1))
    unit = m.group(2) or "m"
    if val == 0:
        return 0
    if unit in {"s", "sec", "secs", "second", "seconds", "秒"}:
        secs = val
    elif unit in {"h", "hr", "hrs", "hour", "hours", "时", "小时"}:
        secs = val * 3600
    else:
        secs = val * 60
    if ANNOUNCE_MIN_DELETE_SECONDS <= secs <= ANNOUNCE_MAX_DELETE_SECONDS:
        return secs
    return None


def render_ban_announcement(
    gs: GroupSettings,
    *,
    display_name: str,
    actor_id: int,
    reason: str,
    duration: str = "永久封禁",
) -> str:
    """Safely render a group ban notice using single-pass placeholder substitution."""
    tpl = (gs.announce_template or "").strip() or DEFAULT_ANNOUNCE_TEMPLATE
    safe_user = re.sub(r"[\r\n]+", " ", (display_name or "未知用户").strip())[:80]
    safe_reason = re.sub(r"[\r\n]+", " ", (reason or "违规广告").strip())[:300]
    safe_duration = re.sub(r"[\r\n]+", " ", (duration or "永久封禁").strip())[:40]
    del_sec = max(0, int(gs.announce_delete_seconds))
    auto_del_text = (
        f"本提示将在 {format_delete_delay(del_sec)} 后自动删除"
        if del_sec > 0
        else "本提示将长期保留"
    )
    mapping = {
        "user": safe_user,
        "user_id": str(actor_id),
        "reason": safe_reason,
        "duration": safe_duration,
        "auto_delete": auto_del_text,
    }
    return _ANNOUNCE_VAR_RE.sub(lambda m: mapping[m.group(1)], tpl)[:1500]


@dataclass
class AdminRights:
    is_admin: bool = False
    is_creator: bool = False
    can_delete_messages: bool = False
    can_restrict_members: bool = False

    def satisfies(self, *, require_delete: bool = False, require_restrict: bool = False) -> bool:
        if not self.is_admin:
            return False
        if self.is_creator:
            return True
        if require_delete and not self.can_delete_messages:
            return False
        if require_restrict and not self.can_restrict_members:
            return False
        return True


def _extract_member_rights(member: Any) -> AdminRights:
    status = getattr(member, "status", None)
    if status == ChatMemberStatus.OWNER:
        return AdminRights(True, True, True, True)
    if status == ChatMemberStatus.ADMINISTRATOR:
        return AdminRights(
            is_admin=True,
            is_creator=False,
            can_delete_messages=bool(getattr(member, "can_delete_messages", False)),
            can_restrict_members=bool(getattr(member, "can_restrict_members", False)),
        )
    return AdminRights()


class FloodTracker:
    """Bounded, TTL-pruned sliding-window flood detector with album deduplication & repeat detection."""

    def __init__(self, max_keys: int = 5000) -> None:
        self.max_keys = max_keys
        # Each entry: (timestamp, message_id, media_group_id, normalized_text_prefix)
        self._buckets: dict[tuple[int, int], deque[tuple[float, int, Optional[str], str]]] = {}

    def _prune(self, ts: float, max_age: float) -> None:
        expired = [
            k for k, q in self._buckets.items() if (not q) or (ts - q[-1][0]) > max_age
        ]
        for k in expired:
            self._buckets.pop(k, None)
        while len(self._buckets) >= self.max_keys:
            self._buckets.pop(next(iter(self._buckets)))

    def clear_actor(self, chat_id: int, actor_id: int) -> None:
        self._buckets.pop((chat_id, actor_id), None)

    def get_burst_max_duplicate_count(self, chat_id: int, actor_id: int) -> int:
        """Count maximum identical non-empty text repeats in the current burst window."""
        q = self._buckets.get((chat_id, actor_id))
        if not q:
            return 0
        counts: dict[str, int] = {}
        for _, _, _, norm_txt in q:
            if norm_txt:
                counts[norm_txt] = counts.get(norm_txt, 0) + 1
        return max(counts.values()) if counts else 0

    def record_and_check(
        self,
        chat_id: int,
        actor_id: int,
        message_id: int,
        media_group_id: Optional[str],
        *,
        window_seconds: int,
        max_messages: int,
        text_norm: str = "",
        now: Optional[float] = None,
    ) -> tuple[bool, list[int]]:
        ts = now if now is not None else time.time()
        key = (chat_id, actor_id)
        if key not in self._buckets and len(self._buckets) >= self.max_keys:
            self._prune(ts, max(float(window_seconds), 60.0))

        q = self._buckets.get(key)
        if q is None:
            q = deque(maxlen=30)
            self._buckets[key] = q
        while q and (ts - q[0][0]) > window_seconds:
            q.popleft()

        cleaned = " ".join((text_norm or "").strip().lower().split())[:120]
        q.append((ts, message_id, media_group_id, cleaned))

        seen_albums: set[str] = set()
        effective = 0
        burst_ids: list[int] = []
        for _, mid, mgid, _ in q:
            burst_ids.append(mid)
            if mgid:
                if mgid not in seen_albums:
                    seen_albums.add(mgid)
                    effective += 1
            else:
                effective += 1

        if effective >= max_messages:
            return True, burst_ids
        return False, []


class SwarmTracker:
    """Bounded, TTL-pruned detector for multi-account identical repeats (triggers review, never blind-bans)."""

    def __init__(
        self,
        window_seconds: int = 60,
        min_distinct_actors: int = 3,
        max_keys: int = 4000,
    ) -> None:
        self.window = window_seconds
        self.min_actors = min_distinct_actors
        self.max_keys = max_keys
        self._events: dict[tuple[int, str], deque[tuple[float, int, int]]] = {}

    def _prune(self, ts: float) -> None:
        expired = [
            k
            for k, q in self._events.items()
            if (not q) or (ts - q[-1][0]) > self.window
        ]
        for k in expired:
            self._events.pop(k, None)
        while len(self._events) >= self.max_keys:
            self._events.pop(next(iter(self._events)))

    def record_and_check(
        self,
        chat_id: int,
        content_hash: Optional[str],
        actor_id: int,
        message_id: int,
        *,
        now: Optional[float] = None,
    ) -> tuple[bool, list[tuple[int, int]]]:
        """Returns (is_swarm, list_of_(actor_id, message_id))."""
        if not content_hash:
            return False, []
        ts = now if now is not None else time.time()
        key = (chat_id, content_hash)

        if key not in self._events and len(self._events) >= self.max_keys:
            self._prune(ts)

        q = self._events.get(key)
        if q is None:
            q = deque(maxlen=25)
            self._events[key] = q

        while q and (ts - q[0][0]) > self.window:
            q.popleft()

        q.append((ts, actor_id, message_id))
        distinct_actors = {aid for _, aid, _ in q}
        if len(distinct_actors) >= self.min_actors:
            return True, [(aid, mid) for _, aid, mid in q]
        return False, []


class SpamFingerprintCache:
    """Per-group, whole-message composite TTL cache of confirmed spam SHA-256 fingerprints.

    - Strictly isolated by chat_id (Group A can NEVER ban users in Group B).
    - Composite key prevents a mixed photo+caption spam verdict from banning standalone text or standalone photos.
    - Enforces min_score on lookup so raising a group's threshold immediately invalidates weaker entries.
    """

    def __init__(self, ttl_seconds: int = 1800, max_entries: int = 2000) -> None:
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self._items: dict[str, tuple[float, int, str]] = {}

    @staticmethod
    def _text_blob(xray: MessageXRay) -> str:
        base = xray.normalized_text or xray.text
        parts = [
            " ".join(base.strip().lower().split()),
            "|".join(xray.hidden_links),
            "|".join(xray.inline_buttons),
            xray.poll_info.strip().lower(),
            f"ext:{xray.external_reply.strip().lower()}" if xray.external_reply else "",
            f"fwd:{xray.forward_from.strip().lower()}" if xray.forward_from else "",
            f"ch:{xray.sender_chat.strip().lower()}" if xray.sender_chat else "",
            f"via:{xray.via_bot.strip().lower()}" if xray.via_bot else "",
            f"sp:{xray.special_payload.strip().lower()}" if xray.special_payload else "",
            f"df:{xray.dangerous_filename.strip().lower()}" if xray.dangerous_filename else "",
            f"stk:{xray.sticker_info.strip().lower()}" if xray.sticker_info else "",
        ]
        return "||".join(p for p in parts if p)

    @classmethod
    def fingerprint_message(
        cls,
        chat_id: int,
        xray: MessageXRay,
        image_data_url: Optional[str],
    ) -> Optional[str]:
        """Build a per-chat whole-message fingerprint (txt-only, img-only, or combo)."""
        text_blob = cls._text_blob(xray)
        has_media_without_bytes = bool(xray.media_type) and not image_data_url

        # If message has media whose bytes weren't loaded (e.g., video/photo when vision off),
        # do not collapse it into a pure-text fingerprint unless it has no media at all.
        if has_media_without_bytes:
            return None

        if image_data_url and text_blob:
            raw = f"{text_blob}###{image_data_url}"
            digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
            return f"{chat_id}:combo:{digest}"

        if image_data_url:
            digest = hashlib.sha256(image_data_url.encode("ascii")).hexdigest()[:24]
            return f"{chat_id}:img:{digest}"

        if len(text_blob) >= 16:
            digest = hashlib.sha256(text_blob.encode("utf-8")).hexdigest()[:24]
            return f"{chat_id}:txt:{digest}"

        return None

    @classmethod
    def fingerprint_text_only(cls, xray: MessageXRay) -> Optional[str]:
        """Used purely for same-actor repeat-send tracking (never cross-user auto-ban)."""
        blob = cls._text_blob(xray)
        if len(blob) < 12:
            return None
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:24]

    def lookup(
        self,
        key: Optional[str],
        *,
        min_score: int = 80,
        now: Optional[float] = None,
    ) -> Optional[tuple[int, str]]:
        if not key:
            return None
        ts = now if now is not None else time.time()
        entry = self._items.get(key)
        if not entry:
            return None
        expires_at, score, reason = entry
        if expires_at <= ts:
            self._items.pop(key, None)
            return None
        if score < min_score:
            return None
        return score, reason

    def remember(
        self,
        key: Optional[str],
        score: int,
        reason: str,
        *,
        now: Optional[float] = None,
    ) -> None:
        if not key:
            return
        ts = now if now is not None else time.time()
        if len(self._items) >= self.max_entries:
            expired = [k for k, v in self._items.items() if v[0] <= ts]
            for k in expired:
                self._items.pop(k, None)
            if len(self._items) >= self.max_entries:
                self._items.pop(next(iter(self._items)))
        self._items[key] = (ts + self.ttl, score, reason)


class GuardEngine:
    def __init__(self, cfg: AppConfig, storage: Storage, llm: UniversalAIClient):
        self.cfg = cfg
        self.storage = storage
        self.llm = llm
        self.cas = CASChecker(api_key=getattr(cfg, "cas_api_key", ""))
        self.captcha = SimpleCaptchaManager(storage=storage, timeout_seconds=90)
        self.flood = FloodTracker()
        self.swarm = SwarmTracker(window_seconds=60, min_distinct_actors=3)
        self.spam_cache = SpamFingerprintCache()

        # Owner claim security: explicit OWNER_IDS strictly overrides and wipes legacy auto_owner_id!
        self.claim_code: Optional[str] = None
        self.claim_expires_at: float = 0.0
        self.claim_failed_by_user: dict[int, int] = {}
        self.claim_max_attempts: int = 5
        self.claim_ttl_seconds: int = 900  # 15 minutes
        if self.cfg.owner_ids:
            if self.storage.get_meta("auto_owner_id"):
                self.storage.delete_meta("auto_owner_id")
                logger.info("检测到显式 OWNER_IDS 配置，已自动清除历史 auto_owner_id 认领记录。")
        elif not self.storage.get_meta("auto_owner_id"):
            self.claim_code = secrets.token_urlsafe(12)
            self.claim_expires_at = time.time() + self.claim_ttl_seconds

        # DM anti-abuse rate limiter for non-owners (prevents /start & /claim flooding)
        self._dm_user_last: dict[int, float] = {}
        self._dm_global_window: deque[float] = deque(maxlen=25)
        # Guided private-DM input state for Owners configuring AI settings via /start buttons (uid -> (field, expires_at))
        self.pending_owner_input: dict[int, tuple[str, float]] = {}
        # Guided group/DM input state for Admins configuring per-group settings via GUI buttons ((chat_id, uid) -> PendingAdminInput)
        self.pending_admin_input: dict[tuple[int, int], PendingAdminInput] = {}
        # Active auto-delete timer tasks (strong refs; cancelled cleanly on shutdown while DB rows persist)
        self._delete_tasks: set[asyncio.Task[Any]] = set()
        self._ai_config_lock = asyncio.Lock()
        self.ai_config_warning: str = ""

        # Load Owner-saved in-bot AI config override (unless server .env AI settings changed more recently)
        self._load_persisted_ai_config()

        # Bounded in-memory caches & per-member indices (all TTL-pruned & capacity-capped)
        self.admin_cache: dict[int, tuple[float, dict[int, AdminRights]]] = {}
        # Stale admin fallback cache (chat_id -> (grace_until, set_of_admin_uids)), ONLY for moderation anti-false-delete!
        # NEVER used for privileged command/callback authorization (check_admin_perm stays strictly live fail-closed).
        self._last_known_admins: dict[int, tuple[float, set[int]]] = {}
        self.linked_chat_cache: dict[int, tuple[float, Optional[int]]] = {}
        self.profile_cache: dict[int, tuple[float, dict[str, Any]]] = {}
        self.recent_context: dict[int, deque[str]] = {}
        self.user_fragments: dict[tuple[int, int], deque[tuple[float, int, str]]] = {}
        self.recent_msgs: dict[tuple[int, int], deque[tuple[float, int]]] = {}
        self.recently_banned: dict[tuple[int, int], float] = {}
        # Bounded per-member 10-min anti-flood strike tracker (key -> (expires_at, strikes))
        self._flood_strikes: dict[tuple[int, int], tuple[float, int]] = {}
        self.report_counts: dict[tuple[int, int, str], int] = {}
        self._report_day: str = ""
        # Tracks contextual AI-flagged fingerprints (fp -> (expires_at, first_actor_id)) without auto-banning others
        self._flagged_fps: dict[str, tuple[float, int]] = {}
        # Tracks authorized commands handled in handler group 0 so group 1 moderation skips ONLY valid commands
        self._handled_commands: deque[tuple[int, int]] = deque(maxlen=300)
        # Anti-duplicate cooldown for bot group-join entrance announcements (chat_id -> timestamp)
        self._greeted_chats: dict[int, float] = {}
        # Anti-spam dedup for unauthorized group-join owner DM alerts ((chat_id, inviter_id) -> timestamp)
        self._join_reject_notified: dict[tuple[int, int], float] = {}

    def is_group_allowed(self, chat_id: int) -> bool:
        return (not self.cfg.allowed_group_ids) or (chat_id in self.cfg.allowed_group_ids)

    def has_any_owner(self) -> bool:
        return bool(self.get_owner_ids())

    def is_owner_only_join_enabled(self) -> bool:
        val = self.storage.get_meta("owner_only_join")
        if val is None:
            return True  # Default ON: block strangers from adding the bot and consuming your AI quota
        return val == "1"

    def set_owner_only_join(self, enabled: bool) -> None:
        self.storage.set_meta("owner_only_join", "1" if enabled else "0")

    @staticmethod
    def _env_ai_hash(cfg: AppConfig) -> str:
        raw = f"{cfg.ai_base_url}\x00{cfg.ai_model}\x00{cfg.ai_api_key}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]

    _AI_META_KEYS = (
        "ai_config_override",
        "ai_env_hash",
        "ai_api_key",
        "ai_base_url",
        "ai_model",
        "ai_key_origin",
    )

    @staticmethod
    def _format_origin(url: str) -> str:
        scheme, host, port = url_origin(url)
        return f"{scheme}://{host}:{port}" if host else ""

    @property
    def active_ai_warning(self) -> str:
        return self.ai_config_warning or self.llm.config_warning

    def _load_persisted_ai_config(self) -> None:
        """Apply in-bot saved AI settings across restarts; yield automatically if server .env was edited."""
        if self.storage.get_meta("ai_config_override") != "1":
            return
        cur_hash = self._env_ai_hash(self.cfg)
        saved_hash = self.storage.get_meta("ai_env_hash") or ""
        if saved_hash != cur_hash:
            self.storage.delete_meta_many(list(self._AI_META_KEYS))
            logger.info("检测到服务器 .env 中的 AI 配置已变更，已自动切换为 .env 最新配置。")
            return
        api_key = self.storage.get_meta("ai_api_key")
        base_url = self.storage.get_meta("ai_base_url")
        model = self.storage.get_meta("ai_model")
        saved_origin = self.storage.get_meta("ai_key_origin") or ""

        eff_url = base_url if base_url is not None else self.cfg.ai_base_url
        eff_key = api_key if api_key is not None else self.cfg.ai_api_key
        eff_origin = self._format_origin(eff_url)
        # Strict origin binding (including legacy DB upgrades lacking ai_key_origin):
        # Refuse to send any persisted key without a verified matching origin record!
        if eff_key and (not saved_origin or not eff_origin or saved_origin != eff_origin):
            self.ai_config_warning = (
                "⚠️ 安全迁移保护：检测到历史保存的 AI API Key 缺少来源主机绑定记录（或与当前接口主机不匹配），"
                "已暂停外发并切回纯本地基础防护模式。请私聊机器人 /start 点「🤖 配置 AI 接口 / API Key」重新录入密钥。"
            )
            logger.warning("%s", self.ai_config_warning)
            eff_key = ""

        self.llm.apply_sync(
            api_key=eff_key,
            base_url=eff_url,
            model=model if model is not None else self.cfg.ai_model,
        )

    async def update_ai_config(
        self,
        *,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
    ) -> bool:
        """Validate, atomically persist, and hot-reload AI settings.

        Binds credentials to service origin: changing base_url to a different (scheme, host, port)
        without providing a new api_key automatically clears the old key so credentials are NEVER
        sent to a new host. Returns True if an existing API key was cleared.
        """
        async with self._ai_config_lock:
            old_origin = url_origin(self.llm.base_url)

            if base_url is not None:
                valid_url = validate_ai_base_url(base_url)
                if not valid_url:
                    raise ValueError(
                        "无效的接口地址：远程接口必须使用 https://（仅本机回环地址允许 http://）"
                    )
                next_base_url = valid_url
            else:
                next_base_url = self.llm.base_url

            if model is not None:
                valid_model = validate_model_name(model)
                if not valid_model:
                    raise ValueError("无效的模型名称")
                next_model = valid_model
            else:
                next_model = self.llm.model

            new_origin = url_origin(next_base_url)
            origin_changed = base_url is not None and new_origin != old_origin

            if api_key is not None:
                if api_key.strip() == "":
                    key_cleared = bool(self.llm.api_key)
                    next_api_key = ""
                else:
                    valid_key = validate_api_key(api_key)
                    if not valid_key:
                        raise ValueError("无效的 API Key 格式")
                    next_api_key = valid_key
                    key_cleared = False
            elif origin_changed:
                key_cleared = bool(self.llm.api_key)
                next_api_key = ""
            else:
                next_api_key = self.llm.api_key
                key_cleared = False

            # Atomic single-transaction DB write FIRST so crash/failure never leaves torn state or diverges from runtime
            self.storage.set_meta_many(
                {
                    "ai_api_key": next_api_key,
                    "ai_base_url": next_base_url,
                    "ai_model": next_model,
                    "ai_key_origin": self._format_origin(next_base_url) if next_api_key else "",
                    "ai_env_hash": self._env_ai_hash(self.cfg),
                    "ai_config_override": "1",
                }
            )
            await self.llm.reconfigure(
                api_key=next_api_key,
                base_url=next_base_url,
                model=next_model,
            )
            self.ai_config_warning = ""
            return key_cleared

    async def reset_ai_config_to_env(self) -> None:
        """Atomically clear in-bot AI override and restore server .env AI settings live."""
        async with self._ai_config_lock:
            self.storage.delete_meta_many(list(self._AI_META_KEYS))
            self.ai_config_warning = ""
            await self.llm.reconfigure(
                api_key=self.cfg.ai_api_key,
                base_url=self.cfg.ai_base_url,
                model=self.cfg.ai_model,
            )

    def set_owner_input_state(
        self, user_id: int, field_name: str, *, ttl: float = 300.0, now: Optional[float] = None
    ) -> None:
        ts = now if now is not None else time.time()
        if len(self.pending_owner_input) >= 100:
            stale = [u for u, (_, exp) in self.pending_owner_input.items() if exp <= ts]
            for u in stale:
                self.pending_owner_input.pop(u, None)
            while len(self.pending_owner_input) >= 100:
                self.pending_owner_input.pop(next(iter(self.pending_owner_input)))
        self.pending_owner_input[user_id] = (field_name, ts + ttl)

    def pop_owner_input_state(self, user_id: int, *, now: Optional[float] = None) -> Optional[str]:
        entry = self.pending_owner_input.pop(user_id, None)
        if not entry:
            return None
        field_name, expires_at = entry
        ts = now if now is not None else time.time()
        if ts > expires_at:
            return None
        return field_name

    def clear_owner_input_state(self, user_id: int) -> None:
        self.pending_owner_input.pop(user_id, None)

    def set_admin_input_state(
        self,
        panel_chat_id: int,
        user_id: int,
        target_group_id: int,
        field_name: str,
        panel_msg_id: int = 0,
        *,
        ttl: float = 300.0,
        now: Optional[float] = None,
    ) -> None:
        ts = now if now is not None else time.time()
        if len(self.pending_admin_input) >= 500:
            stale = [k for k, v in self.pending_admin_input.items() if v.expires_at <= ts]
            for k in stale:
                self.pending_admin_input.pop(k, None)
            while len(self.pending_admin_input) >= 500:
                self.pending_admin_input.pop(next(iter(self.pending_admin_input)))
        self.pending_admin_input[(panel_chat_id, user_id)] = PendingAdminInput(
            target_group_id=target_group_id,
            field_name=field_name,
            panel_chat_id=panel_chat_id,
            panel_msg_id=panel_msg_id,
            expires_at=ts + ttl,
        )

    def pop_admin_input_state(
        self, panel_chat_id: int, user_id: int, *, now: Optional[float] = None
    ) -> Optional[PendingAdminInput]:
        entry = self.pending_admin_input.pop((panel_chat_id, user_id), None)
        if not entry:
            return None
        ts = now if now is not None else time.time()
        if ts > entry.expires_at:
            return None
        return entry

    def clear_admin_input_state(self, panel_chat_id: int, user_id: int) -> None:
        self.pending_admin_input.pop((panel_chat_id, user_id), None)

    # ---- Restart-safe persistent message auto-delete & group ban announcements ----
    def schedule_auto_delete(
        self,
        bot: Any,
        chat_id: int,
        message_id: int,
        delay_seconds: int,
        *,
        persist: bool = True,
        delete_at: Optional[float] = None,
    ) -> None:
        if delay_seconds <= 0 and delete_at is None:
            return
        now = time.time()
        target_ts = delete_at if delete_at is not None else (now + delay_seconds)
        if persist:
            self.storage.save_pending_delete(chat_id, message_id, target_ts)
        wait_sec = max(0.0, target_ts - now)
        task = asyncio.create_task(
            self._auto_delete_worker(bot, chat_id, message_id, wait_sec, persist=persist)
        )
        self._delete_tasks.add(task)
        task.add_done_callback(self._delete_tasks.discard)

    async def _auto_delete_worker(
        self, bot: Any, chat_id: int, message_id: int, delay: float, *, persist: bool
    ) -> None:
        try:
            if delay > 0:
                await asyncio.sleep(delay)
        except asyncio.CancelledError:
            # Leave DB row intact so restart resumes countdown!
            return
        try:
            await bot.delete_message(chat_id, message_id)
        except TelegramError:
            pass
        if persist:
            try:
                self.storage.delete_pending_delete(chat_id, message_id)
            except sqlite3.Error:
                pass

    async def restore_pending_deletes(self, bot: Any) -> None:
        """Restore persisted pending auto-delete timers across restarts."""
        now = time.time()
        for chat_id, message_id, delete_at in self.storage.list_pending_deletes():
            if now - delete_at > 172800:
                # Over 48h past due — prune stale record cleanly
                self.storage.delete_pending_delete(chat_id, message_id)
                continue
            self.schedule_auto_delete(
                bot, chat_id, message_id, delay_seconds=0, persist=True, delete_at=delete_at
            )

    def cancel_pending_delete_tasks(self) -> None:
        """Cancel in-memory sleep tasks on shutdown without dropping persisted DB schedules."""
        for task in list(self._delete_tasks):
            task.cancel()
        self._delete_tasks.clear()

    async def announce_ban_in_group(
        self,
        bot: Any,
        chat_id: int,
        gs: GroupSettings,
        *,
        display_name: str,
        actor_id: int,
        reason: str,
        duration: str = "永久封禁",
        force_when_dry_run: bool = False,
    ) -> Optional[int]:
        """Send customizable ban notice in group chat and schedule persistent auto-delete if configured."""
        if not gs.announce_in_group or (gs.dry_run and not force_when_dry_run):
            return None
        text = render_ban_announcement(
            gs,
            display_name=display_name,
            actor_id=actor_id,
            reason=reason,
            duration=duration,
        )
        try:
            sent = await bot.send_message(chat_id, text)
        except TelegramError:
            return None
        sent_mid = getattr(sent, "message_id", None)
        if isinstance(sent_mid, int) and sent_mid > 0 and gs.announce_delete_seconds > 0:
            self.schedule_auto_delete(
                bot, chat_id, sent_mid, int(gs.announce_delete_seconds), persist=True
            )
            return sent_mid
        return sent_mid if isinstance(sent_mid, int) else None

    def mark_command_handled(self, chat_id: int, message_id: int) -> None:
        self._handled_commands.append((chat_id, message_id))

    def consume_handled_command(self, chat_id: int, message_id: int) -> bool:
        key = (chat_id, message_id)
        if key in self._handled_commands:
            try:
                self._handled_commands.remove(key)
            except ValueError:
                pass
            return True
        return False

    def get_owner_ids(self) -> set[int]:
        """Explicit OWNER_IDS always supersedes auto_owner_id (never merged)."""
        if self.cfg.owner_ids:
            return set(self.cfg.owner_ids)
        saved = self.storage.get_meta("auto_owner_id")
        if saved:
            try:
                return {int(saved)}
            except ValueError:
                return set()
        return set()

    def allow_dm_reply(
        self,
        user_id: int,
        *,
        per_user_cooldown: float = 10.0,
        global_per_minute: int = 20,
        now: Optional[float] = None,
    ) -> bool:
        """Memory-only rate limiter protecting private /start & /claim from DoS / TG 429 floods."""
        if self.is_owner(user_id):
            return True
        ts = now if now is not None else time.time()

        # Per-user cooldown
        last = self._dm_user_last.get(user_id)
        if last is not None and (ts - last) < per_user_cooldown:
            return False

        # Global non-owner DM budget per minute
        while self._dm_global_window and (ts - self._dm_global_window[0]) > 60.0:
            self._dm_global_window.popleft()
        if len(self._dm_global_window) >= global_per_minute:
            return False

        # Keep per-user dict bounded
        if len(self._dm_user_last) >= 5000:
            cutoff = ts - per_user_cooldown
            stale = [u for u, t in self._dm_user_last.items() if t < cutoff]
            for u in stale:
                self._dm_user_last.pop(u, None)
            if len(self._dm_user_last) >= 5000:
                self._dm_user_last.pop(next(iter(self._dm_user_last)))

        self._dm_user_last[user_id] = ts
        self._dm_global_window.append(ts)
        return True

    def is_claim_locked_for(self, user_id: int) -> bool:
        return self.claim_failed_by_user.get(user_id, 0) >= self.claim_max_attempts

    def try_claim_owner(
        self, user_id: int, code: str, *, now: Optional[float] = None
    ) -> tuple[bool, str]:
        ts = now if now is not None else time.time()
        if self.cfg.owner_ids or self.storage.get_meta("auto_owner_id"):
            return False, "口令无效或已失效。"
        if not self.claim_code:
            return False, "口令无效或已失效。"
        if ts > self.claim_expires_at:
            self.claim_code = None
            self.claim_failed_by_user.clear()
            logger.warning("一次性 /claim 认领口令已超过 15 分钟自动过期作废，请在 .env 填写 OWNER_IDS 或重启容器。")
            return False, "口令无效或已失效。"
        if self.is_claim_locked_for(user_id):
            return False, "口令无效或已失效。"
        if not secrets.compare_digest(code.strip(), self.claim_code):
            if user_id not in self.claim_failed_by_user and len(self.claim_failed_by_user) >= 5000:
                # Evict unlocked entries first so locked attackers stay locked
                unlocked = [u for u, c in self.claim_failed_by_user.items() if c < self.claim_max_attempts]
                if unlocked:
                    self.claim_failed_by_user.pop(unlocked[0], None)
                else:
                    self.claim_failed_by_user.pop(next(iter(self.claim_failed_by_user)))
            attempts = self.claim_failed_by_user.get(user_id, 0) + 1
            self.claim_failed_by_user[user_id] = attempts
            if attempts == self.claim_max_attempts:
                logger.warning(
                    "用户 %s 连续输错 /claim 口令 %d 次，已锁定该用户的认领尝试（不影响部署者本人认领）。",
                    user_id,
                    self.claim_max_attempts,
                )
            return False, "口令无效或已失效。"
        self.storage.set_meta("auto_owner_id", str(user_id))
        self.claim_code = None
        self.claim_failed_by_user.clear()
        logger.info("👑 超级管理员已由用户 %s 通过一次性口令认领成功。", user_id)
        return True, "👑 认领成功！你已成为AI-智能广告杀手超级管理员（一次性口令已立即失效）。"

    def is_owner(self, user_id: int) -> bool:
        return user_id in self.get_owner_ids()

    def get_group_settings(self, chat_id: int, chat_title: str = "") -> GroupSettings:
        return self.storage.get_group(
            chat_id,
            chat_title,
            default_dry_run=self.cfg.default_dry_run,
            default_spam_score=self.cfg.default_spam_score,
            default_flood_window=self.cfg.default_flood_window,
            default_flood_max=self.cfg.default_flood_max,
        )

    async def get_linked_chat_id(self, bot: Any, chat_id: int) -> Optional[int]:
        now = time.time()
        cached = self.linked_chat_cache.get(chat_id)
        if cached and cached[0] > now:
            return cached[1]
        linked_id: Optional[int] = None
        try:
            chat_info = await bot.get_chat(chat_id)
            linked_id = getattr(chat_info, "linked_chat_id", None)
        except TelegramError:
            pass
        if len(self.linked_chat_cache) >= 2000:
            expired = [k for k, v in self.linked_chat_cache.items() if v[0] <= now]
            for k in expired:
                self.linked_chat_cache.pop(k, None)
            if len(self.linked_chat_cache) >= 2000:
                self.linked_chat_cache.pop(next(iter(self.linked_chat_cache)))
        self.linked_chat_cache[chat_id] = (now + 600, linked_id)
        return linked_id

    async def try_get_member_rights(
        self, bot: Any, chat_id: int, user_id: int, *, fresh: bool = False
    ) -> Optional[AdminRights]:
        """Lookup member rights; returns None on transient TelegramError so callers can distinguish outage vs demotion."""
        if self.is_owner(user_id):
            return AdminRights(True, True, True, True)

        if fresh:
            try:
                member = await bot.get_chat_member(chat_id, user_id)
                rights = _extract_member_rights(member)
                cached = self.admin_cache.get(chat_id)
                if cached:
                    if rights.is_admin:
                        cached[1][user_id] = rights
                    else:
                        cached[1].pop(user_id, None)
                fb = self._last_known_admins.get(chat_id)
                if fb:
                    if rights.is_admin:
                        fb[1].add(user_id)
                    else:
                        fb[1].discard(user_id)
                return rights
            except TelegramError as exc:
                logger.warning("实时核验群 %s 成员 %s 权限失败（临时异常）: %s", chat_id, user_id, exc)
                return None

        now = time.time()
        cached = self.admin_cache.get(chat_id)
        if cached and cached[0] > now:
            return cached[1].get(user_id, AdminRights())
        try:
            admins = await bot.get_chat_administrators(chat_id)
            rights_map = {m.user.id: _extract_member_rights(m) for m in admins if m.user}
            if len(self.admin_cache) >= 2000:
                expired = [k for k, v in self.admin_cache.items() if v[0] <= now]
                for k in expired:
                    self.admin_cache.pop(k, None)
                if len(self.admin_cache) >= 2000:
                    self.admin_cache.pop(next(iter(self.admin_cache)))
            self.admin_cache[chat_id] = (now + 300, rights_map)
            # Refresh bounded 30-min stale-grace snapshot for moderation-only outage fallback
            if len(self._last_known_admins) >= 2000:
                stale = [k for k, v in self._last_known_admins.items() if v[0] <= now]
                for k in stale:
                    self._last_known_admins.pop(k, None)
                if len(self._last_known_admins) >= 2000:
                    self._last_known_admins.pop(next(iter(self._last_known_admins)))
            self._last_known_admins[chat_id] = (now + 1800, set(rights_map.keys()))
            return rights_map.get(user_id, AdminRights())
        except TelegramError as exc:
            logger.warning("获取群 %s 管理员列表失败（临时异常）: %s", chat_id, exc)
            return None

    async def get_member_rights(
        self, bot: Any, chat_id: int, user_id: int, *, fresh: bool = False
    ) -> AdminRights:
        rights = await self.try_get_member_rights(bot, chat_id, user_id, fresh=fresh)
        return rights if rights is not None else AdminRights()

    async def is_group_admin(self, bot: Any, chat_id: int, user_id: int) -> bool:
        rights = await self.get_member_rights(bot, chat_id, user_id, fresh=False)
        return rights.is_admin

    async def is_chat_admin_only(
        self,
        bot: Any,
        chat_id: int,
        user_id: int,
        *,
        allow_stale_fallback: bool = True,
    ) -> bool:
        """Check actual Telegram group admin status (independent of global OWNER_IDS).

        When allow_stale_fallback=True and Telegram API temporarily times out, falls back to the
        last known admin set (<=30 min grace) to prevent deleting admin messages during outages.
        """
        now = time.time()
        cached = self.admin_cache.get(chat_id)
        if cached and cached[0] > now:
            return cached[1].get(user_id, AdminRights()).is_admin
        try:
            admins = await bot.get_chat_administrators(chat_id)
            rights_map = {m.user.id: _extract_member_rights(m) for m in admins if m.user}
            if len(self.admin_cache) >= 2000:
                expired = [k for k, v in self.admin_cache.items() if v[0] <= now]
                for k in expired:
                    self.admin_cache.pop(k, None)
                if len(self.admin_cache) >= 2000:
                    self.admin_cache.pop(next(iter(self.admin_cache)))
            self.admin_cache[chat_id] = (now + 300, rights_map)
            if len(self._last_known_admins) >= 2000:
                stale = [k for k, v in self._last_known_admins.items() if v[0] <= now]
                for k in stale:
                    self._last_known_admins.pop(k, None)
                if len(self._last_known_admins) >= 2000:
                    self._last_known_admins.pop(next(iter(self._last_known_admins)))
            self._last_known_admins[chat_id] = (now + 1800, set(rights_map.keys()))
            return rights_map.get(user_id, AdminRights()).is_admin
        except TelegramError as exc:
            logger.warning("获取群 %s 管理员列表失败（临时异常）: %s", chat_id, exc)
            if allow_stale_fallback:
                fallback = self._last_known_admins.get(chat_id)
                if fallback and fallback[0] > now:
                    return user_id in fallback[1]
            return False

    async def check_admin_perm(
        self,
        bot: Any,
        chat_id: int,
        user_id: int,
        *,
        require_delete: bool = False,
        require_restrict: bool = False,
        fresh: bool = True,
    ) -> bool:
        rights = await self.get_member_rights(bot, chat_id, user_id, fresh=fresh)
        return rights.satisfies(require_delete=require_delete, require_restrict=require_restrict)

    async def check_message_admin_perm(
        self,
        bot: Any,
        msg: Message,
        *,
        user: Any = None,
        require_delete: bool = False,
        require_restrict: bool = False,
        allow_readonly_sender_chat: bool = False,
    ) -> bool:
        """Authorize a group command message, safely supporting Anonymous Group Admins & Linked Channel.

        - Anonymous Group Admin (sender_chat.id == chat.id): Telegram guarantees only a real
          anonymous admin of THIS group can send this. For read-only panel open commands
          (where every button click later checks the clicker's real user ID), allow if ANY
          anonymous admin satisfies the rights. For mutating commands, require ALL anonymous
          admins in the group to satisfy the rights (prevents limited anonymous admin escalation).
        - Linked Channel (sender_chat.id == linked_chat_id, non-auto-forward): allowed ONLY for
          read-only panel open commands (/config, /start), never for mutating commands.
        - External random channels: ALWAYS denied.
        - Regular user: standard live check_admin_perm(fresh=True).
        """
        chat = getattr(msg, "chat", None)
        if not chat:
            return False
        sender_chat = getattr(msg, "sender_chat", None)

        if sender_chat:
            # Case 1: Anonymous Group Admin posting as the group itself
            if sender_chat.id == chat.id:
                try:
                    admins = await bot.get_chat_administrators(chat.id)
                except TelegramError as exc:
                    logger.warning("实时核验群 %s 匿名管理员权限失败: %s", chat.id, exc)
                    return False
                anon_admins = [m for m in admins if getattr(m, "is_anonymous", False)]
                if not anon_admins:
                    return False
                checks = [
                    _extract_member_rights(m).satisfies(
                        require_delete=require_delete, require_restrict=require_restrict
                    )
                    for m in anon_admins
                ]
                return any(checks) if allow_readonly_sender_chat else all(checks)

            # Case 2: Group's linked channel (manual Send-As, NOT auto-forward) -> read-only panel open only
            if allow_readonly_sender_chat and not getattr(msg, "is_automatic_forward", False):
                linked_id = await self.get_linked_chat_id(bot, chat.id)
                if linked_id and sender_chat.id == linked_id:
                    return True

            # Case 3: External/unrelated channel -> strictly denied!
            return False

        eff_user = getattr(msg, "from_user", None) or user
        if not eff_user:
            return False
        return await self.check_admin_perm(
            bot,
            chat.id,
            eff_user.id,
            require_delete=require_delete,
            require_restrict=require_restrict,
            fresh=True,
        )

    async def resolve_anon_admin_input_uid(self, bot: Any, chat_id: int) -> Optional[int]:
        """Match an anonymous admin's group reply ONLY when that group has a single unambiguous anonymous admin."""
        now = time.time()
        has_active = any(
            pcid == chat_id and entry.target_group_id == chat_id and entry.expires_at >= now
            for (pcid, _uid), entry in self.pending_admin_input.items()
        )
        if not has_active:
            return None
        try:
            admins = await bot.get_chat_administrators(chat_id)
        except TelegramError:
            return None
        anon_admins = [m for m in admins if getattr(m, "is_anonymous", False) and getattr(m, "user", None)]
        # Strict anti-collision guard: if 2+ anonymous admins exist, Telegram cannot distinguish who spoke!
        if len(anon_admins) != 1:
            return None
        sole = anon_admins[0]
        if not _extract_member_rights(sole).satisfies(require_restrict=True):
            return None
        entry = self.pending_admin_input.get((chat_id, sole.user.id))
        if entry and entry.target_group_id == chat_id and entry.expires_at >= now:
            return sole.user.id
        return None

    async def is_ambiguous_anon_admin(self, bot: Any, chat_id: int, user_id: int) -> bool:
        """Return True if user_id is an anonymous admin in a group with 2+ anonymous admins."""
        if not hasattr(bot, "get_chat_administrators"):
            return False
        try:
            admins = await bot.get_chat_administrators(chat_id)
        except TelegramError:
            return False
        anon_uids = [
            m.user.id
            for m in admins
            if getattr(m, "is_anonymous", False) and getattr(m, "user", None)
        ]
        return len(anon_uids) > 1 and user_id in anon_uids

    async def get_profile(self, bot: Any, user: Any) -> dict[str, Any]:
        if not user:
            return {}
        now = time.time()
        cached = self.profile_cache.get(user.id)
        if cached and cached[0] > now:
            return cached[1]

        profile: dict[str, Any] = {
            "full_name": getattr(user, "full_name", "") or "",
            "username": f"@{user.username}" if getattr(user, "username", None) else "(无)",
            "bio": "",
            "personal_channel": "",
            "personal_channel_bio": "",
            "has_photo": None,
        }
        try:
            info = await bot.get_chat(user.id)
            profile["has_photo"] = getattr(info, "photo", None) is not None
            if getattr(info, "bio", None):
                profile["bio"] = str(info.bio)[:300]
            pchat = getattr(info, "personal_chat", None)
            if pchat:
                title = getattr(pchat, "title", "") or ""
                uname = f"@{pchat.username}" if getattr(pchat, "username", None) else ""
                profile["personal_channel"] = f"{title} {uname}".strip()
                try:
                    pinfo = await bot.get_chat(pchat.id)
                    desc = getattr(pinfo, "description", None) or getattr(pinfo, "bio", None)
                    if desc:
                        profile["personal_channel_bio"] = str(desc)[:240]
                except TelegramError:
                    pass
        except TelegramError:
            pass

        if len(self.profile_cache) >= 5000:
            expired = [k for k, v in self.profile_cache.items() if v[0] <= now]
            for k in expired:
                self.profile_cache.pop(k, None)
            if len(self.profile_cache) >= 5000:
                self.profile_cache.pop(next(iter(self.profile_cache)))
        self.profile_cache[user.id] = (now + 600, profile)
        return profile

    def record_recent_msg(
        self,
        chat_id: int,
        actor_id: int,
        msg_id: int,
        *,
        now: Optional[float] = None,
        ttl: float = 120.0,
        max_keys: int = 5000,
    ) -> None:
        ts = now if now is not None else time.time()
        key = (chat_id, actor_id)
        if key not in self.recent_msgs and len(self.recent_msgs) >= max_keys:
            expired = [
                k for k, q in self.recent_msgs.items() if (not q) or (ts - q[-1][0]) > ttl
            ]
            for k in expired:
                self.recent_msgs.pop(k, None)
            while len(self.recent_msgs) >= max_keys:
                self.recent_msgs.pop(next(iter(self.recent_msgs)))

        q = self.recent_msgs.get(key)
        if q is None:
            q = deque(maxlen=20)
            self.recent_msgs[key] = q
        while q and (ts - q[0][0]) > ttl:
            q.popleft()
        q.append((ts, msg_id))

    def get_user_recent_fragments(
        self, chat_id: int, actor_id: int, *, now: Optional[float] = None
    ) -> tuple[list[str], list[int]]:
        ts = now if now is not None else time.time()
        key = (chat_id, actor_id)
        q = self.user_fragments.get(key)
        if not q:
            return [], []
        while q and (ts - q[0][0]) > 600.0:
            q.popleft()
        if not q:
            self.user_fragments.pop(key, None)
            return [], []
        return [snip for _, _, snip in q if snip], [mid for _, mid, _ in q]

    def record_user_fragment(
        self,
        chat_id: int,
        actor_id: int,
        msg_id: int,
        text: str,
        *,
        now: Optional[float] = None,
        ttl: float = 600.0,
        max_keys: int = 5000,
    ) -> None:
        cleaned = (text or "").strip()
        if not cleaned:
            return
        ts = now if now is not None else time.time()
        key = (chat_id, actor_id)
        if key not in self.user_fragments and len(self.user_fragments) >= max_keys:
            expired = [
                k for k, q in self.user_fragments.items() if (not q) or (ts - q[-1][0]) > ttl
            ]
            for k in expired:
                self.user_fragments.pop(k, None)
            while len(self.user_fragments) >= max_keys:
                self.user_fragments.pop(next(iter(self.user_fragments)))

        q = self.user_fragments.get(key)
        if q is None:
            q = deque(maxlen=5)
            self.user_fragments[key] = q
        while q and (ts - q[0][0]) > ttl:
            q.popleft()
        q.append((ts, msg_id, cleaned[:160]))

    def check_and_inc_report_count(
        self,
        chat_id: int,
        user_id: int,
        *,
        limit: int = 5,
        day: Optional[str] = None,
        max_entries: int = 5000,
    ) -> bool:
        """Bounded daily per-user /spam report quota; auto-evicts prior days on date rollover."""
        cur_day = day if day is not None else time.strftime("%Y-%m-%d")
        if cur_day != self._report_day:
            self.report_counts = {
                k: v for k, v in self.report_counts.items() if k[2] == cur_day
            }
            self._report_day = cur_day

        rkey = (chat_id, user_id, cur_day)
        cur = self.report_counts.get(rkey, 0)
        if cur >= limit:
            return False

        if rkey not in self.report_counts and len(self.report_counts) >= max_entries:
            stale = [k for k in self.report_counts if k[2] != cur_day]
            for k in stale:
                self.report_counts.pop(k, None)
            while len(self.report_counts) >= max_entries:
                self.report_counts.pop(next(iter(self.report_counts)))

        self.report_counts[rkey] = cur + 1
        return True

    def _get_flagged_fp(self, fp: Optional[str], *, now: Optional[float] = None) -> Optional[int]:
        if not fp:
            return None
        ts = now if now is not None else time.time()
        entry = self._flagged_fps.get(fp)
        if not entry:
            return None
        expires_at, first_actor = entry
        if expires_at <= ts:
            self._flagged_fps.pop(fp, None)
            return None
        return first_actor

    def _record_flagged_fp(
        self,
        fp: Optional[str],
        actor_id: int,
        *,
        now: Optional[float] = None,
        ttl: float = 1800.0,
        max_entries: int = 4000,
    ) -> None:
        if not fp:
            return
        ts = now if now is not None else time.time()
        if fp not in self._flagged_fps and len(self._flagged_fps) >= max_entries:
            expired = [k for k, v in self._flagged_fps.items() if v[0] <= ts]
            for k in expired:
                self._flagged_fps.pop(k, None)
            while len(self._flagged_fps) >= max_entries:
                self._flagged_fps.pop(next(iter(self._flagged_fps)))
        self._flagged_fps[fp] = (ts + ttl, actor_id)

    def record_flood_strike(
        self,
        chat_id: int,
        actor_id: int,
        *,
        window_seconds: float = 600.0,
        now: Optional[float] = None,
        max_entries: int = 5000,
    ) -> int:
        ts = now if now is not None else time.time()
        key = (chat_id, actor_id)
        if key not in self._flood_strikes and len(self._flood_strikes) >= max_entries:
            expired = [k for k, v in self._flood_strikes.items() if v[0] <= ts]
            for k in expired:
                self._flood_strikes.pop(k, None)
            while len(self._flood_strikes) >= max_entries:
                self._flood_strikes.pop(next(iter(self._flood_strikes)))
        prev = self._flood_strikes.get(key)
        count = (prev[1] + 1) if (prev and prev[0] > ts) else 1
        self._flood_strikes[key] = (ts + window_seconds, count)
        return count

    def should_send_to_ai(
        self,
        xray: MessageXRay,
        clean_count: int,
        profile_boost: int = 0,
        *,
        exempt_veteran_short: bool = True,
        local_rules_enabled: bool = False,
    ) -> bool:
        if xray.has_risk_signal() or profile_boost >= 10:
            return True
        if clean_count < self.cfg.strict_new_user_msgs:
            return True
        if not exempt_veteran_short:
            return True
        text_len = len((xray.normalized_text or xray.text).strip())
        if text_len <= 5:
            return False
        # Established active veterans sending clean short plain-text chat (<=20 chars, zero risk signals)
        # skip AI to keep active chat groups responsive and low-latency.
        if clean_count >= 15 and profile_boost == 0 and text_len <= SHORT_CHAT_LENGTH:
            if local_rules_enabled and (
                evaluate_basic_rules(xray, {}, profile_boost=0, pure_content_only=True).score > 0
            ):
                return True
            return False
        return True

    def record_clean_context(self, msg: Message) -> None:
        text = (msg.text or msg.caption or "").strip()
        if text:
            name = msg.from_user.first_name if msg.from_user else "群友"
            cid = msg.chat.id
            if cid not in self.recent_context and len(self.recent_context) >= 2000:
                self.recent_context.pop(next(iter(self.recent_context)))
            q = self.recent_context.get(cid)
            if q is None:
                q = deque(maxlen=6)
                self.recent_context[cid] = q
            q.append(f"{name}: {text[:80]}")

    async def resolve_log_chat(self, bot: Any, gs: GroupSettings) -> Optional[int]:
        """Resolve audit log destination; revokes DM binding ONLY on confirmed demotion (not transient errors)."""
        if gs.log_chat_id:
            # Positive chat ID = private DM user; verify they are still an authorized admin or owner
            if gs.log_chat_id > 0 and not self.is_owner(gs.log_chat_id):
                rights = await self.try_get_member_rights(
                    bot, gs.chat_id, gs.log_chat_id, fresh=True
                )
                if rights is None:
                    # Transient Telegram/network error: pause delivery for this call ONLY; preserve DB binding!
                    logger.warning(
                        "暂时无法核验群 %s 日志订阅者 %s 权限，本次暂停私聊投递（保留绑定待恢复）。",
                        gs.chat_id,
                        gs.log_chat_id,
                    )
                elif not rights.satisfies(require_restrict=True):
                    logger.info(
                        "检测到群 %s 日志订阅者 %s 已无管理权限，自动撤销其私聊日志订阅。",
                        gs.chat_id,
                        gs.log_chat_id,
                    )
                    gs.log_chat_id = None
                    self.storage.save_group(gs)
                else:
                    return gs.log_chat_id
            else:
                return gs.log_chat_id

        owners = self.get_owner_ids()
        return next(iter(owners)) if owners else None

    async def _reject_and_leave_unauthorized_group(
        self, bot: Any, chat: Any, *, inviter: Any = None, reason_text: str
    ) -> None:
        """Immediately leave an unauthorized group without touching DB/AI and alert Owner(s) in DM."""
        chat_id = chat.id
        chat_title = getattr(chat, "title", "") or str(chat_id)
        inviter_id = getattr(inviter, "id", 0) if inviter else 0
        if inviter:
            inv_uname = f" (@{inviter.username})" if getattr(inviter, "username", None) else ""
            inviter_desc = f"{getattr(inviter, 'full_name', '') or inviter_id}{inv_uname} [{inviter_id}]"
        else:
            inviter_desc = "未知（可能于离线期间拉入）"

        left_ok = False
        if hasattr(bot, "leave_chat"):
            try:
                await bot.leave_chat(chat_id)
                left_ok = True
            except TelegramError as exc:
                logger.warning("退出未授权群组 %s 失败: %s", chat_id, exc)
        logger.warning(
            "🚫 已拦截未授权群组%s: chat=%s (%s) inviter=%s reason=%s",
            "并自动退群" if left_ok else "（退群失败，已拒绝响应）",
            chat_id,
            chat_title,
            inviter_desc,
            reason_text,
        )

        now = time.time()
        dedup_key = (chat_id, inviter_id)
        if now - self._join_reject_notified.get(dedup_key, 0.0) < 300.0:
            return
        if len(self._join_reject_notified) >= 500:
            stale = [k for k, t in self._join_reject_notified.items() if now - t >= 300.0]
            for k in stale:
                self._join_reject_notified.pop(k, None)
            if len(self._join_reject_notified) >= 500:
                self._join_reject_notified.pop(next(iter(self._join_reject_notified)))
        self._join_reject_notified[dedup_key] = now

        alert = (
            f"🚫 [已拦截未授权拉群{'并自动退群' if left_ok else ''}]\n"
            f"• 陌生群组：{chat_title} ({chat_id})\n"
            f"• 拉人者：{inviter_desc}\n"
            f"• 拦截原因：{reason_text}\n"
            f"• 状态：未消耗任何 AI 额度{'，机器人已自动退出该群' if left_ok else '，已拒绝一切响应'}。\n"
            f"（如需允许他人拉群，可在私聊 /start 切换「防陌生人拉群」开关，或将群 ID 加入 .env 的 ALLOWED_GROUP_IDS）"
        )
        for oid in self.get_owner_ids():
            try:
                await bot.send_message(oid, alert)
            except TelegramError:
                pass

    async def _ensure_group_authorized_runtime(self, bot: Any, chat: Any) -> bool:
        """Defense-in-depth runtime authorization check (seals offline-add / drop_pending_updates loophole)."""
        if not self.is_group_allowed(chat.id):
            await self._reject_and_leave_unauthorized_group(
                bot, chat, reason_text="该群不在 ALLOWED_GROUP_IDS 允许列表中"
            )
            return False
        if (
            not self.is_owner_only_join_enabled()
            or not self.has_any_owner()
            or (chat.id in self.cfg.allowed_group_ids)
        ):
            return True
        if self.storage.has_group(chat.id):
            return True
        # Group was not seen via authorized MY_CHAT_MEMBER (e.g., added while bot was offline/restarting).
        # Verify whether any Owner is an admin/creator in this group before activating or leaving!
        if not hasattr(bot, "get_chat_administrators"):
            return False
        try:
            admins = await bot.get_chat_administrators(chat.id)
        except TelegramError:
            return False
        if any(
            getattr(m, "user", None) and self.is_owner(m.user.id)
            for m in admins
        ):
            self.get_group_settings(chat.id, getattr(chat, "title", "") or "")
            return True
        await self._reject_and_leave_unauthorized_group(
            bot, chat, reason_text="未授权陌生群组（群内无超管且非超管拉入）"
        )
        return False

    # ---- Bot's own group membership event (MY_CHAT_MEMBER: owner-only guard + entrance photo report!) ----
    async def handle_my_chat_member(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        cm = update.my_chat_member
        if not cm or not cm.chat or cm.chat.type not in (ChatType.GROUP, ChatType.SUPERGROUP):
            return

        old_st = getattr(cm.old_chat_member, "status", None)
        new_st = getattr(cm.new_chat_member, "status", None)
        self.admin_cache.pop(cm.chat.id, None)

        was_outside = old_st in (ChatMemberStatus.LEFT, ChatMemberStatus.BANNED, None)
        is_now_in = new_st in (
            ChatMemberStatus.MEMBER,
            ChatMemberStatus.RESTRICTED,
            ChatMemberStatus.ADMINISTRATOR,
        )
        if not (was_outside and is_now_in):
            return

        inviter = getattr(cm, "from_user", None)
        if not self.is_group_allowed(cm.chat.id):
            await self._reject_and_leave_unauthorized_group(
                context.bot,
                cm.chat,
                inviter=inviter,
                reason_text="该群不在 ALLOWED_GROUP_IDS 允许列表中",
            )
            return

        if (
            self.is_owner_only_join_enabled()
            and self.has_any_owner()
            and (cm.chat.id not in self.cfg.allowed_group_ids)
            and not (inviter and self.is_owner(inviter.id))
        ):
            await self._reject_and_leave_unauthorized_group(
                context.bot,
                cm.chat,
                inviter=inviter,
                reason_text="已开启「🔒 仅允许超管拉群」，非超管不可拉入新群",
            )
            return

        now = time.time()
        last_greet = self._greeted_chats.get(cm.chat.id, 0.0)
        if now - last_greet < 60.0:
            return
        if len(self._greeted_chats) >= 500:
            stale = [cid for cid, t in self._greeted_chats.items() if now - t >= 60.0]
            for cid in stale:
                self._greeted_chats.pop(cid, None)
            if len(self._greeted_chats) >= 500:
                self._greeted_chats.pop(next(iter(self._greeted_chats)))
        self._greeted_chats[cm.chat.id] = now

        # Register group in SQLite immediately so it appears in Owner /start dashboard
        self.get_group_settings(cm.chat.id, cm.chat.title or "")

        rights = _extract_member_rights(cm.new_chat_member)
        if rights.satisfies(require_delete=True, require_restrict=True):
            caption = (
                "🛡 AI-智能广告杀手入场报到，开始全天候拦截垃圾广告！\n\n"
                "• 当前状态：✅ 已获得管理员权限，反广告防线已就位\n"
                "• 管理面板：管理员发送 /config 即可一键开关全部功能\n"
                "• 群友协助：回复漏网广告发 /spam 即可一键举报"
            )
        else:
            caption = (
                "🛡 AI-智能广告杀手入场报到，准备就绪入场杀广告！\n\n"
                "• 激活提示：请将我设为群管理员（勾选「删除消息」与「封禁用户」）即可自动拦截广告\n"
                "• 管理面板：授权后发送 /config 即可一键开关全部功能"
            )

        photo_sent = False
        if DEFAULT_AVATAR_PATH.is_file() and hasattr(context.bot, "send_photo"):
            try:
                await context.bot.send_photo(
                    cm.chat.id,
                    photo=DEFAULT_AVATAR_PATH.read_bytes(),
                    caption=caption,
                )
                photo_sent = True
            except TelegramError as exc:
                logger.info("群 %s 入场发图失败，降级为纯文本报到: %s", cm.chat.id, exc)
            except OSError:
                pass

        if not photo_sent:
            try:
                await context.bot.send_message(cm.chat.id, caption)
            except TelegramError as exc:
                logger.warning("群 %s 入场报到发送失败: %s", cm.chat.id, exc)

    # ---- Chat Member Events (Admin Demotion Revocation + Join Protection) ----
    async def handle_chat_member(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        cm = update.chat_member
        if not cm or not cm.chat or cm.chat.type not in (ChatType.GROUP, ChatType.SUPERGROUP):
            return
        if not self.is_group_allowed(cm.chat.id):
            return
        if (
            self.is_owner_only_join_enabled()
            and self.has_any_owner()
            and (cm.chat.id not in self.cfg.allowed_group_ids)
            and not self.storage.has_group(cm.chat.id)
        ):
            return

        old_m = cm.old_chat_member
        new_m = cm.new_chat_member
        old_st = old_m.status
        new_st = new_m.status
        user = new_m.user

        # 0. Admin role / permission change: invalidate cache & update stale fallback immediately
        admin_statuses = (ChatMemberStatus.OWNER, ChatMemberStatus.ADMINISTRATOR)
        if old_st in admin_statuses or new_st in admin_statuses:
            self.admin_cache.pop(cm.chat.id, None)
            new_rights = _extract_member_rights(new_m)
            fb = self._last_known_admins.get(cm.chat.id)
            if fb and user:
                if new_rights.is_admin:
                    fb[1].add(user.id)
                else:
                    fb[1].discard(user.id)
            if user and old_st in admin_statuses and not new_rights.satisfies(require_restrict=True):
                gs = self.get_group_settings(cm.chat.id, cm.chat.title or "")
                if gs.log_chat_id == user.id and not self.is_owner(user.id):
                    gs.log_chat_id = None
                    self.storage.save_group(gs)
                    logger.info(
                        "群 %s 管理员 %s 权限被撤销，已自动解除其私聊日志绑定。",
                        cm.chat.id,
                        user.id,
                    )

        was_outside = old_st in (ChatMemberStatus.LEFT, ChatMemberStatus.BANNED)
        is_now_member = new_st in (ChatMemberStatus.MEMBER, ChatMemberStatus.RESTRICTED)
        if not (was_outside and is_now_member):
            return

        if not user or user.is_bot:
            return

        gs = self.get_group_settings(cm.chat.id, cm.chat.title or "")
        if not gs.enabled:
            return
        if self.storage.is_trusted(cm.chat.id, user.id):
            return

        # 1. Anti-Raid emergency lockdown (only restrict if >= 45s remain, avoiding Telegram <30s forever mute!)
        remaining = gs.antiraid_until - time.time()
        if remaining > 0:
            if remaining >= MIN_FINITE_RESTRICT_SECONDS and not gs.dry_run:
                try:
                    await context.bot.restrict_chat_member(
                        cm.chat.id,
                        user.id,
                        permissions=MUTE_PERMS,
                        until_date=int(gs.antiraid_until),
                    )
                except TelegramError:
                    pass
                logger.info(
                    "🚨 AntiRaid 拦截新入群用户: chat=%s uid=%s (剩余 %ds)",
                    cm.chat.id,
                    user.id,
                    int(remaining),
                )
            else:
                logger.info(
                    "🚨 AntiRaid 剩余不足 %ds，跳过限制避免永久禁言: chat=%s uid=%s",
                    MIN_FINITE_RESTRICT_SECONDS,
                    cm.chat.id,
                    user.id,
                )
            return

        # 2. Free CAS global blacklist check on join
        if gs.cas_enabled:
            if await self.cas.is_banned(user.id):
                ban_ok = False
                if not gs.dry_run:
                    try:
                        await context.bot.ban_chat_member(cm.chat.id, user.id, revoke_messages=True)
                        self.storage.inc_metric(cm.chat.id, "bans")
                        self.storage.inc_metric(cm.chat.id, "cas_bans")
                        ban_ok = True
                    except TelegramError as exc:
                        logger.warning("CAS 入群封禁失败 chat=%s uid=%s: %s", cm.chat.id, user.id, exc)
                uname = f" (@{user.username})" if getattr(user, "username", None) else ""
                cas_display = f"{user.full_name}{uname}"
                self.storage.log_action(
                    chat_id=cm.chat.id,
                    user_id=user.id,
                    sender_chat_id=None,
                    display_name=cas_display,
                    trigger_type="cas_join",
                    score=100,
                    reason="命中 Combot Anti-Spam 全球垃圾号库",
                    preview="入群触发 CAS 全球黑库",
                    dry_run=gs.dry_run or (not ban_ok),
                )
                if ban_ok:
                    await self.announce_ban_in_group(
                        context.bot,
                        cm.chat.id,
                        gs,
                        display_name=cas_display,
                        actor_id=user.id,
                        reason="命中 Combot Anti-Spam 全球垃圾号库",
                        duration="永久封禁",
                    )
                log_chat = await self.resolve_log_chat(context.bot, gs)
                if log_chat:
                    badge = "🌐 [CAS 全球黑库入群秒封]" if ban_ok else "🌐 [CAS 命中（未封禁/观察模式）]"
                    try:
                        await context.bot.send_message(
                            log_chat,
                            f"{badge}\n📌 群组：{cm.chat.title or cm.chat.id}\n"
                            f"👤 用户：{user.full_name} (ID: {user.id})\n🧠 理由：命中 Combot Anti-Spam 全球垃圾号库",
                        )
                    except TelegramError:
                        pass
                return

        # 3. Optional simple 1-tap 🍊 emoji join verification
        if gs.join_captcha and not gs.dry_run:
            await self.captcha.start_challenge(context.bot, cm.chat.id, user)

    async def handle_service_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        msg = update.message
        if not msg or not msg.chat or msg.chat.type not in (ChatType.GROUP, ChatType.SUPERGROUP):
            return
        if not self.is_group_allowed(msg.chat.id):
            return
        if (
            self.is_owner_only_join_enabled()
            and self.has_any_owner()
            and (msg.chat.id not in self.cfg.allowed_group_ids)
            and not self.storage.has_group(msg.chat.id)
        ):
            return
        gs = self.get_group_settings(msg.chat.id, msg.chat.title or "")
        if gs.enabled and gs.clean_service_msgs and not gs.dry_run:
            try:
                await context.bot.delete_message(msg.chat.id, msg.message_id)
            except TelegramError:
                pass

    # ---- Main Group Message & Edited Message Pipeline (runs in handler group 1) ----
    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        is_edited = update.edited_message is not None
        msg = update.edited_message or update.message
        if not msg or not msg.chat:
            return
        if msg.chat.type not in (ChatType.GROUP, ChatType.SUPERGROUP):
            return
        if not await self._ensure_group_authorized_runtime(context.bot, msg.chat):
            return

        # Skip ONLY commands that were actually authorized & handled in group 0!
        # Rejected non-admin commands (e.g. spammer typing "/config 广告") continue through moderation!
        if not is_edited and self.consume_handled_command(msg.chat.id, msg.message_id):
            return

        # A plain Telegram start command or deep link is not a moderation sample.
        if _PLAIN_START_RE.fullmatch((msg.text or "").strip()) and all(
            ent.type == MessageEntity.BOT_COMMAND for ent in (msg.entities or ())
        ):
            return

        gs = self.get_group_settings(msg.chat.id, msg.chat.title or "")
        if not gs.enabled:
            return
        if is_edited and not gs.check_edited:
            return

        user = msg.from_user
        if user and user.id == context.bot.id:
            return

        # ---- Configurable Per-Group Exemption / Bypass Checks ----
        is_own_group_anon = bool(msg.sender_chat and msg.sender_chat.id == msg.chat.id)
        linked_id: Optional[int] = None
        if msg.sender_chat and not is_own_group_anon:
            linked_id = await self.get_linked_chat_id(context.bot, msg.chat.id)
        is_linked_channel = bool(
            getattr(msg, "is_automatic_forward", False)
            or (user and user.id == 777000)
            or (msg.sender_chat and linked_id and msg.sender_chat.id == linked_id)
        )
        is_channel_speaker = bool(
            msg.sender_chat and not is_own_group_anon and not is_linked_channel
        )

        if is_own_group_anon and gs.exempt_anon_admin:
            return
        if is_linked_channel and gs.exempt_linked_channel:
            return
        if not user and not is_channel_speaker and not is_own_group_anon and not is_linked_channel:
            return

        # External (non-linked) channel speaker policy: allow | ai (default) | ban
        if is_channel_speaker:
            if gs.external_channel_mode == "allow":
                return
            if gs.external_channel_mode == "ban":
                xray = extract_xray(msg, is_edited=is_edited)
                await self.enforce_action(
                    context.bot,
                    msg,
                    gs,
                    action="ban",
                    trigger_type="external_channel",
                    score=100,
                    reason="本群已开启「一律拦截外部频道马甲」",
                    xray=xray,
                    profile={},
                )
                return

        if user and not is_channel_speaker and not is_own_group_anon and not is_linked_channel:
            if gs.exempt_owners and self.is_owner(user.id):
                self.record_clean_context(msg)
                return
            if gs.exempt_admins and await self.is_chat_admin_only(
                context.bot,
                msg.chat.id,
                user.id,
                allow_stale_fallback=gs.admin_cache_fallback,
            ):
                self.record_clean_context(msg)
                return
            if gs.exempt_trusted and self.storage.is_trusted(msg.chat.id, user.id):
                self.record_clean_context(msg)
                return

        actor_id = (
            msg.sender_chat.id
            if (is_channel_speaker or (not user and msg.sender_chat))
            else (user.id if user else msg.chat.id)
        )
        self.record_recent_msg(msg.chat.id, actor_id, msg.message_id)
        xray = extract_xray(msg, is_edited=is_edited)

        clean_count = (
            self.storage.get_clean_count(msg.chat.id, user.id)
            if (user and not is_channel_speaker)
            else 0
        )

        first_message_only = bool(
            gs.first_message_only
            and (is_channel_speaker or (user and not msg.sender_chat and not is_linked_channel))
        )
        review_message = not first_message_only
        if first_message_only and not is_edited and clean_count == 0:
            review_message = self.storage.claim_first_message_review(msg.chat.id, actor_id)

        # ---- Layer 1: Zero-cost instant rules ----
        if gs.cas_enabled and user and not is_channel_speaker and clean_count == 0:
            if await self.cas.is_banned(user.id):
                profile = await self.get_profile(context.bot, user)
                self.storage.inc_metric(msg.chat.id, "cas_bans")
                await self.enforce_action(
                    context.bot,
                    msg,
                    gs,
                    action="ban",
                    trigger_type="cas_blacklist",
                    score=100,
                    reason="命中 CAS 全球垃圾广告黑名单",
                    xray=xray,
                    profile=profile,
                )
                return

        if gs.anti_flood and not is_edited:
            is_flood, burst_ids = self.flood.record_and_check(
                msg.chat.id,
                actor_id,
                msg.message_id,
                msg.media_group_id,
                window_seconds=gs.flood_window,
                max_messages=gs.flood_max,
                text_norm=xray.normalized_text or xray.text,
            )
            if is_flood:
                max_dup = self.flood.get_burst_max_duplicate_count(msg.chat.id, actor_id)
                pure_flood_rule = (
                    evaluate_basic_rules(xray, {}, profile_boost=0, pure_content_only=True)
                    if gs.local_rules_enabled
                    else None
                )
                flood_rule_score = pure_flood_rule.score if pure_flood_rule else 0
                has_structural_spam = bool(
                    xray.hidden_links or xray.inline_buttons or xray.dangerous_filename
                )
                self.flood.clear_actor(msg.chat.id, actor_id)

                # Separate "talking fast" from "spam flooding":
                # 1. Opt-in local rules hard spam evidence in burst -> ban
                # 2. Suspicious copy-paste/disguise burst -> delete burst + 24h mute_review
                # 3. Normal rapid chatting -> 1st strike: 60s cooldown ONLY (no ban, no history wipe!);
                #    2nd+ strike within 10 min -> delete burst + 24h mute_review (admin confirms any ban)
                if pure_flood_rule and (
                    flood_rule_score >= gs.spam_score
                    or (max_dup >= 3 and flood_rule_score >= 50)
                ):
                    profile = await self.get_profile(context.bot, user)
                    await self.enforce_action(
                        context.bot,
                        msg,
                        gs,
                        action="ban",
                        trigger_type="anti_flood_spam",
                        score=max(90, flood_rule_score),
                        reason=f"{gs.flood_window}秒内刷屏且命中广告特征（{pure_flood_rule.reason}）",
                        xray=xray,
                        profile=profile,
                        extra_msg_ids=burst_ids,
                    )
                    return

                if flood_rule_score >= 50 or max_dup >= 3 or has_structural_spam:
                    profile = await self.get_profile(context.bot, user)
                    dup_note = f"（含 {max_dup} 条重复刷屏内容）" if max_dup >= 3 else ""
                    await self.enforce_action(
                        context.bot,
                        msg,
                        gs,
                        action="mute_review",
                        trigger_type="anti_flood_review",
                        score=75,
                        reason=f"{gs.flood_window}秒内连续刷屏 >= {gs.flood_max} 条{dup_note}，请复核",
                        xray=xray,
                        profile=profile,
                        extra_msg_ids=burst_ids,
                    )
                    return

                strikes = self.record_flood_strike(msg.chat.id, actor_id)
                if strikes == 1 and user and not is_channel_speaker:
                    # Polite 60-second slow-mode cooldown ONLY — never permanently ban normal fast chatters!
                    if not gs.dry_run:
                        try:
                            await context.bot.restrict_chat_member(
                                msg.chat.id,
                                user.id,
                                permissions=MUTE_PERMS,
                                until_date=int(time.time() + 60),
                            )
                            self.storage.inc_metric(msg.chat.id, "mutes")
                            sent = await context.bot.send_message(
                                msg.chat.id,
                                f"🛡 {user.full_name} 发言太快啦（{gs.flood_window}秒内 {gs.flood_max} 条），先冷静 1 分钟再继续聊～",
                            )
                            asyncio.create_task(_delete_later(context.bot, msg.chat.id, sent.message_id, 12))
                        except TelegramError:
                            pass
                    logger.info(
                        "⏱ 首次快聊限流60s（未封禁/未删正常消息）chat=%s uid=%s",
                        msg.chat.id,
                        user.id,
                    )
                    return

                profile = await self.get_profile(context.bot, user)
                await self.enforce_action(
                    context.bot,
                    msg,
                    gs,
                    action="mute_review",
                    trigger_type="anti_flood_repeat",
                    score=75,
                    reason=f"10分钟内第 {strikes} 次连续刷屏（{gs.flood_window}秒 >= {gs.flood_max} 条），已禁言待复核",
                    xray=xray,
                    profile=profile,
                    extra_msg_ids=burst_ids,
                )
                return

        if gs.block_malware_files and xray.dangerous_filename:
            profile = await self.get_profile(context.bot, user)
            await self.enforce_action(
                context.bot,
                msg,
                gs,
                action="mute_review" if gs.gray_zone_mute else "ban",
                trigger_type="malware_file",
                score=90,
                reason=f"发送高危可执行/安装包文件：{xray.dangerous_filename}",
                xray=xray,
                profile=profile,
            )
            return

        if gs.via_bot_mode == "ban" and msg.via_bot:
            via_uname = (msg.via_bot.username or "").lower()
            if via_uname not in self.cfg.allowed_via_bots:
                profile = await self.get_profile(context.bot, user)
                await self.enforce_action(
                    context.bot,
                    msg,
                    gs,
                    action="ban",
                    trigger_type="via_bot",
                    score=100,
                    reason=f"调用未授权外部内联机器人 {xray.via_bot}",
                    xray=xray,
                    profile=profile,
                )
                return

        if not review_message:
            self.record_clean_context(msg)
            return

        # ---- Layer 2: Per-chat whole-message fingerprint & Swarm tracking ----
        profile = await self.get_profile(context.bot, user) if user and not is_channel_speaker else {}
        want_vision = gs.vision_enabled and self.llm.vision_supported
        image_data_url = await extract_image_data_url(context.bot, msg) if want_vision else None

        msg_fp = self.spam_cache.fingerprint_message(msg.chat.id, xray, image_data_url)
        txt_repeat_fp = self.spam_cache.fingerprint_text_only(xray)

        # 2a. Per-chat verified PURE-CONTENT spam cache hit (never populated by profile/history-contaminated verdicts;
        #     when exempt_reply_cache is enabled, replies to any message — including stickers/media — skip shared cache)
        allow_cache = not (first_message_only or is_channel_speaker) and (
            xray.allow_shared_cache() or not gs.exempt_reply_cache
        )
        cached_hit = (
            self.spam_cache.lookup(msg_fp, min_score=gs.spam_score)
            if allow_cache
            else None
        )
        if cached_hit:
            c_score, c_reason = cached_hit
            await self.enforce_action(
                context.bot,
                msg,
                gs,
                action="ban",
                trigger_type="spam_cache",
                score=c_score,
                reason=f"命中本群近期纯内容广告缓存（{c_reason}）",
                xray=xray,
                profile=profile,
            )
            return

        # 2b. Track multi-account identical composite content repeats (triggers review ONLY, never bulk-bans!)
        is_swarm = False
        swarm_hits: list[tuple[int, int]] = []
        if gs.swarm_guard and msg_fp:
            is_swarm, swarm_hits = self.swarm.record_and_check(
                msg.chat.id, msg_fp, actor_id, msg.message_id
            )

        prev_flagged_actor = self._get_flagged_fp(msg_fp)

        # ---- Layer 3: Full X-Ray + AI (or Seamless Local Basic-Rules Fallback) ----
        profile_flags, profile_boost, is_max_risk = analyze_profile_risk(
            profile, clean_count=clean_count
        )
        if (
            not first_message_only
            and not is_swarm
            and not is_max_risk
            and prev_flagged_actor is None
            and not self.should_send_to_ai(
                xray,
                clean_count,
                profile_boost=profile_boost,
                exempt_veteran_short=gs.exempt_veteran_short,
                local_rules_enabled=gs.local_rules_enabled,
            )
        ):
            self.record_user_fragment(msg.chat.id, actor_id, msg.message_id, xray.normalized_text)
            self.record_clean_context(msg)
            return

        prev_snippets, prev_msg_ids = self.get_user_recent_fragments(msg.chat.id, actor_id)

        raw_content_score = 0
        verdict_reason = ""
        used_vision = False
        used_basic_rules = False
        ai_failed = False

        if self.llm.is_configured:
            summary = xray.format_for_ai(
                profile=profile,
                recent_context=list(self.recent_context.get(msg.chat.id, ())),
                user_fragments=prev_snippets,
                clean_count=clean_count,
                vision_attached=bool(image_data_url),
            )
            if is_swarm:
                n_actors = len({a for a, _ in swarm_hits})
                summary = (
                    f"【多人短时复读提醒】: 60秒内已有 {n_actors} 个不同账号发出完全相同内容。"
                    "如果是群友正常玩梗复读请判为正常(state=0)；如果是团伙刷广告请判为垃圾广告(state=1)。\n"
                    + summary
                )
            try:
                self.storage.inc_metric(msg.chat.id, "ai_checks")
                if image_data_url:
                    self.storage.inc_metric(msg.chat.id, "vision_checks")
                verdict = await self.llm.classify(
                    summary_text=summary,
                    group_topic=gs.group_topic,
                    image_data_url=image_data_url,
                    allow_vision=gs.vision_enabled,
                )
                if verdict.prompt_tokens or verdict.completion_tokens:
                    self.storage.record_token_usage(
                        msg.chat.id,
                        verdict.prompt_tokens,
                        verdict.completion_tokens,
                        verdict.cached_tokens,
                    )
                raw_content_score = verdict.score
                verdict_reason = verdict.reason
                used_vision = verdict.used_vision
            except Exception as exc:
                ai_failed = True
                self.storage.inc_metric(msg.chat.id, "ai_errors")
                if gs.local_rules_enabled:
                    logger.warning(
                        "AI 审核异常/损坏响应（%s），已自动降级到本地关键词规则兜底",
                        format_safe_llm_error(exc),
                    )
                    used_basic_rules = True
                else:
                    logger.warning(
                        "AI 审核异常/损坏响应（%s），本地关键词规则默认关闭，本次跳过关键词处置",
                        format_safe_llm_error(exc),
                    )
                    self.record_user_fragment(
                        msg.chat.id, actor_id, msg.message_id, xray.normalized_text
                    )
                    self.record_clean_context(msg)
                    return
        else:
            if not gs.local_rules_enabled:
                # Zero-LLM mode with local keyword rules OFF (default):
                # Deterministic Layer-1 protections (CAS/flood/malware/via_bot/captcha/antiraid) already ran;
                # skip brittle keyword regex completely until AI is configured or admin enables local_rules_enabled.
                self.record_user_fragment(
                    msg.chat.id, actor_id, msg.message_id, xray.normalized_text
                )
                if user and not is_channel_speaker:
                    self.storage.increment_clean_count(msg.chat.id, user.id)
                self.record_clean_context(msg)
                return
            used_basic_rules = True

        # Only compute local keyword rules when opt-in local_rules_enabled is ON
        pure_rule_verdict = (
            evaluate_basic_rules(xray, {}, profile_boost=0, pure_content_only=True)
            if gs.local_rules_enabled
            else None
        )
        pure_rule_score = pure_rule_verdict.score if pure_rule_verdict else 0

        if used_basic_rules:
            basic_full = evaluate_basic_rules(xray, profile, profile_boost=profile_boost)
            raw_content_score = pure_rule_score
            effective_score = basic_full.score
            verdict_reason = basic_full.reason
            profile_note = ""
        else:
            effective_score = raw_content_score
            profile_note = ""
            has_promo_profile = any(("隔断混淆" in f or "引流" in f) for f in profile_flags)
            min_ai_for_boost = 35 if has_promo_profile else 45
            if profile_boost > 0 and raw_content_score >= min_ai_for_boost:
                effective_score = min(100, raw_content_score + profile_boost)
                profile_note = (
                    f"（高危昵称/资料画像加权+{profile_boost}）"
                    if has_promo_profile
                    else f"（空白号画像加权+{profile_boost}）"
                )

        # Repeat-send escalation for borderline messages (50 <= score < spam_score)
        repeat_extra_ids: list[int] = []
        repeat_note = ""
        if 50 <= effective_score < gs.spam_score and txt_repeat_fp:
            suspect_key = hashlib.sha256(
                f"{msg.chat.id}:{actor_id}:{txt_repeat_fp}".encode("utf-8")
            ).hexdigest()[:32]
            eff, hits, tracked_ids = self.storage.record_repeat_suspect(
                suspect_key, msg.chat.id, actor_id, effective_score, msg.message_id
            )
            if hits >= 2:
                effective_score = eff
                repeat_extra_ids = tracked_ids
                repeat_note = f"（24h内第{hits}次重复发送，风险分升权至{eff}）"

        # ---- Graduated Enforcement (strictly per-person judgment!) ----
        if effective_score >= gs.spam_score:
            # Shared same-group spam_cache ONLY accepts strictly pure standalone content verdicts
            # (never contaminated by another member's profile/bio/fragments/chat context!).
            if not gs.dry_run and msg_fp and allow_cache:
                if pure_rule_verdict and pure_rule_score >= gs.spam_score:
                    self.spam_cache.remember(
                        msg_fp, pure_rule_score, pure_rule_verdict.reason
                    )
                elif prev_flagged_actor is None:
                    # 1st actor caught via contextual AI/profile: record hint only, NEVER auto-ban others!
                    self._record_flagged_fp(msg_fp, actor_id)
                elif (
                    prev_flagged_actor != actor_id
                    and self.llm.is_configured
                    and not used_basic_rules
                ):
                    # 2nd distinct actor also confirmed spam on identical content:
                    # Run an independent PURE CONTENT-ONLY AI review (zero profile/history/context)
                    # before allowing future hits to auto-ban from shared cache.
                    try:
                        pure_summary = xray.format_content_only_for_ai(
                            vision_attached=bool(image_data_url)
                        )
                        pure_verdict = await self.llm.classify(
                            summary_text=pure_summary,
                            group_topic=gs.group_topic,
                            image_data_url=image_data_url,
                            allow_vision=gs.vision_enabled,
                        )
                        if pure_verdict.prompt_tokens or pure_verdict.completion_tokens:
                            self.storage.record_token_usage(
                                msg.chat.id,
                                pure_verdict.prompt_tokens,
                                pure_verdict.completion_tokens,
                                pure_verdict.cached_tokens,
                            )
                        if pure_verdict.score >= gs.spam_score:
                            self.spam_cache.remember(
                                msg_fp, pure_verdict.score, pure_verdict.reason
                            )
                    except Exception as exc:
                        logger.debug(
                            "纯内容独立复核跳过（不写入共享缓存）: %s",
                            format_safe_llm_error(exc),
                        )

            trigger = (
                "repeat_escalation"
                if repeat_note
                else (
                    "basic_rules"
                    if used_basic_rules
                    else (
                        "edited_ai"
                        if is_edited
                        else ("ai_vision" if used_vision else "ai_text")
                    )
                )
            )
            # Outage safeguard: when an AI-configured group temporarily falls back to opt-in local rules
            # due to an upstream LLM failure, downgrade to mute_review (delete + 24h mute + admin review)
            # unless overwhelming multi-signal hard spam (>=95), so API outages never cause blind permanent bans!
            enforce_kind = (
                "mute_review"
                if (ai_failed and gs.gray_zone_mute and pure_rule_score < 95)
                else "ban"
            )
            await self.enforce_action(
                context.bot,
                msg,
                gs,
                action=enforce_kind,
                trigger_type=trigger,
                score=effective_score,
                reason=f"{verdict_reason}{profile_note}{repeat_note}",
                xray=xray,
                profile=profile,
                extra_msg_ids=prev_msg_ids + repeat_extra_ids,
            )

            # If multiple earlier accounts posted identical spam content (raw content score >= threshold),
            # DO NOT auto-ban them! Send a per-person review card to admin instead.
            if is_swarm and raw_content_score >= gs.spam_score:
                await self._send_swarm_review_card(
                    context.bot, msg, gs, actor_id, swarm_hits, xray, verdict_reason
                )
            return

        gray_floor = max(60, gs.spam_score - 15)
        if gs.gray_zone_mute and effective_score >= gray_floor:
            await self.enforce_action(
                context.bot,
                msg,
                gs,
                action="mute_review",
                trigger_type="gray_basic" if used_basic_rules else "gray_zone",
                score=effective_score,
                reason=f"{verdict_reason}{profile_note}{repeat_note}",
                xray=xray,
                profile=profile,
            )
            return

        # Record AI suspicions for admin review without taking action.
        if self.llm.is_configured and not used_basic_rules and effective_score >= 40:
            suspect_name = (
                f"[频道马甲] {xray.sender_chat}"
                if is_channel_speaker
                else (profile.get("full_name") or (user.full_name if user else "未知"))
            )
            self.storage.log_action(
                chat_id=msg.chat.id,
                user_id=None if is_channel_speaker else actor_id,
                sender_chat_id=actor_id if is_channel_speaker else None,
                display_name=str(suspect_name),
                trigger_type="ai_suspect",
                score=effective_score,
                reason=f"{verdict_reason}{profile_note}{repeat_note}",
                preview=xray.build_preview(),
                dry_run=True,
            )

        # Preserve clean counts only when the review did not fail.
        self.record_user_fragment(msg.chat.id, actor_id, msg.message_id, xray.normalized_text)
        if user and not is_channel_speaker and not ai_failed:
            self.storage.increment_clean_count(msg.chat.id, user.id)
        self.record_clean_context(msg)

    async def _send_swarm_review_card(
        self,
        bot: Any,
        msg: Message,
        gs: GroupSettings,
        current_actor_id: int,
        swarm_hits: list[tuple[int, int]],
        xray: MessageXRay,
        reason: str,
    ) -> None:
        other_pairs: dict[int, int] = {}
        for aid, mid in swarm_hits:
            if aid != current_actor_id and aid > 0 and aid not in other_pairs:
                other_pairs[aid] = mid
        if not other_pairs:
            return

        log_chat = await self.resolve_log_chat(bot, gs)
        if not log_chat:
            return

        self.storage.inc_metric(msg.chat.id, "swarm_bans")
        lines = [
            "👥 [疑似团伙复读 — 请逐人复核，未自动连坐]",
            f"📌 群组：{msg.chat.title or msg.chat.id}",
            f"🧠 触发原因：{reason}",
            f"💬 相同内容摘要：{xray.build_preview()[:260]}",
            f"🔎 60秒内先前发送过完全相同内容的其他账号（共 {len(other_pairs)} 人）：",
        ]
        buttons: list[list[InlineKeyboardButton]] = []
        for aid, mid in list(other_pairs.items())[:5]:
            lines.append(f"• 用户 ID：{aid}（消息 #{mid}）")
            buttons.append(
                [
                    InlineKeyboardButton(
                        f"🚫 封禁此同伙 ({aid})",
                        callback_data=f"rptban:{msg.chat.id}:{aid}:{mid}",
                    )
                ]
            )
        buttons.append([InlineKeyboardButton("👍 全部忽略（正常复读）", callback_data="noop_confirm")])
        try:
            await bot.send_message(
                log_chat, "\n".join(lines), reply_markup=InlineKeyboardMarkup(buttons)
            )
        except TelegramError as exc:
            logger.warning("发送团伙复核卡片失败: %s", exc)

    async def enforce_action(
        self,
        bot: Any,
        msg: Message,
        gs: GroupSettings,
        *,
        action: str,  # "ban" | "mute_review"
        trigger_type: str,
        score: int,
        reason: str,
        xray: MessageXRay,
        profile: dict[str, Any],
        extra_msg_ids: Optional[list[int]] = None,
    ) -> None:
        chat = msg.chat
        user = msg.from_user
        is_channel_speaker = bool(msg.sender_chat and msg.sender_chat.id != chat.id)
        actor_id = msg.sender_chat.id if is_channel_speaker else (user.id if user else 0)
        if is_channel_speaker and gs.external_channel_mode == "ai":
            # Banning a sender chat restricts all channels owned by that person.
            # Leave this decision to a moderator in the review policy.
            action = "mute_review"
            trigger_type = "channel_review"
        if is_channel_speaker:
            display_name = f"[频道马甲] {xray.sender_chat}"
        else:
            raw_name = profile.get("full_name") or (user.full_name if user else "未知")
            raw_uname = profile.get("username") or (
                f"@{user.username}" if user and getattr(user, "username", None) else ""
            )
            display_name = (
                f"{raw_name} ({raw_uname})"
                if raw_uname and raw_uname != "(无)"
                else str(raw_name)
            )

        dedup_key = (chat.id, actor_id)
        now = time.time()
        if dedup_key in self.recently_banned and (now - self.recently_banned[dedup_key]) < 10:
            if not gs.dry_run:
                try:
                    await bot.delete_message(chat.id, msg.message_id)
                except TelegramError:
                    pass
            return
        if len(self.recently_banned) >= 2000:
            stale = [k for k, t in self.recently_banned.items() if (now - t) > 60.0]
            for k in stale:
                self.recently_banned.pop(k, None)
            while len(self.recently_banned) >= 2000:
                self.recently_banned.pop(next(iter(self.recently_banned)))
        self.recently_banned[dedup_key] = now

        preview = xray.build_preview()
        self.storage.log_action(
            chat_id=chat.id,
            user_id=None if is_channel_speaker else actor_id,
            sender_chat_id=actor_id if is_channel_speaker else None,
            display_name=display_name,
            trigger_type=trigger_type,
            score=score,
            reason=reason,
            preview=preview,
            dry_run=gs.dry_run,
        )

        status_badge = "👀 [观察模式 - 未处置]"
        deleted_ok = False
        ban_ok = False

        if not gs.dry_run:
            to_delete = {msg.message_id}
            if extra_msg_ids:
                to_delete.update(extra_msg_ids)
            if action == "ban":
                for ts, mid in list(self.recent_msgs.get((chat.id, actor_id), [])):
                    if now - ts <= 60:
                        to_delete.add(mid)

            for mid in to_delete:
                try:
                    await bot.delete_message(chat.id, mid)
                    if mid == msg.message_id:
                        deleted_ok = True
                except TelegramError:
                    pass

            if action == "mute_review":
                # Channel identities cannot be muted: ONLY delete current message & ask admin to confirm ban!
                if is_channel_speaker and msg.sender_chat:
                    if deleted_ok:
                        self.storage.inc_metric(chat.id, "deletes")
                    status_badge = (
                        "⚖️ [频道马甲疑似灰区：已删当前消息，请复核是否封禁该频道]"
                        if deleted_ok
                        else "⚠️ [频道马甲疑似灰区：删消息失败，请人工处理]"
                    )
                elif user:
                    try:
                        await bot.restrict_chat_member(
                            chat.id,
                            user.id,
                            permissions=MUTE_PERMS,
                            until_date=int(now + 86400),
                        )
                        self.storage.inc_metric(chat.id, "mutes")
                        status_badge = (
                            "⚖️ [疑似灰区：已删消息并禁言24h，请复核]"
                            if deleted_ok
                            else "⚖️ [疑似灰区：已禁言24h（删消息失败），请复核]"
                        )
                    except TelegramError as exc:
                        status_badge = (
                            f"⚠️ [已删消息，禁言失败: {exc}]"
                            if deleted_ok
                            else f"⚠️ [删消息与禁言均失败: {exc}]"
                        )
            else:
                try:
                    if is_channel_speaker and msg.sender_chat:
                        await bot.ban_chat_sender_chat(chat.id, msg.sender_chat.id)
                    elif user:
                        await bot.ban_chat_member(chat.id, user.id, revoke_messages=True)
                    self.storage.inc_metric(chat.id, "bans")
                    ban_ok = True
                    status_badge = (
                        "🛡 [AI-智能广告杀手已删消息并永久封禁]"
                        if deleted_ok
                        else "🛡 [AI-智能广告杀手已永久封禁（触发消息已由封禁清理或早先删除）]"
                    )
                except TelegramError as exc:
                    logger.error("封禁 %s 失败: %s", actor_id, exc)
                    status_badge = (
                        f"⚠️ [已删消息，封禁失败: {exc}]"
                        if deleted_ok
                        else f"⚠️ [删消息与封禁均失败: {exc}]"
                    )

            # Only announce a ban in group if the ban API call actually succeeded!
            if gs.announce_in_group and action == "ban" and ban_ok:
                await self.announce_ban_in_group(
                    bot,
                    chat.id,
                    gs,
                    display_name=display_name,
                    actor_id=actor_id,
                    reason=reason,
                    duration="永久封禁",
                )

        logger.info(
            "%s chat=%s actor=%s trigger=%s score=%d del_ok=%s ban_ok=%s reason=%s preview=%s",
            status_badge,
            chat.id,
            display_name,
            trigger_type,
            score,
            deleted_ok,
            ban_ok,
            reason,
            preview[:120],
        )

        target_log_chat = await self.resolve_log_chat(bot, gs)
        if target_log_chat:
            text = (
                f"{status_badge}\n"
                f"📌 群组：{chat.title or chat.id}\n"
                f"👤 发送者：{display_name}\n"
                f"🆔 ID：{actor_id}\n"
                f"⚡ 触发：{trigger_type} | 风险分：{score}/100\n"
                f"🧠 理由：{reason}\n"
            )
            if profile.get("bio"):
                text += f"📝 Bio：{profile['bio'][:120]}\n"
            if profile.get("personal_channel"):
                text += f"📣 主页频道：{profile['personal_channel']}\n"
            text += f"💬 摘要：{preview[:400]}"

            keyboard = None
            if is_channel_speaker and msg.sender_chat:
                if action == "mute_review":
                    keyboard = InlineKeyboardMarkup(
                        [
                            [
                                InlineKeyboardButton(
                                    "🚫 永久封禁此频道马甲",
                                    callback_data=f"upbanch:{chat.id}:{msg.sender_chat.id}",
                                ),
                                InlineKeyboardButton("👍 忽略", callback_data="noop_confirm"),
                            ]
                        ]
                    )
            elif user:
                if action == "mute_review":
                    keyboard = InlineKeyboardMarkup(
                        [
                            [
                                InlineKeyboardButton(
                                    "🚫 升级永久封禁",
                                    callback_data=f"upban:{chat.id}:{user.id}",
                                ),
                                InlineKeyboardButton(
                                    "✅ 误杀：解禁并加白",
                                    callback_data=f"unmute:{chat.id}:{user.id}",
                                ),
                            ]
                        ]
                    )
                else:
                    keyboard = InlineKeyboardMarkup(
                        [
                            [
                                InlineKeyboardButton(
                                    "✅ 误杀：解封并加白名单",
                                    callback_data=f"unban:{chat.id}:{user.id}",
                                ),
                                InlineKeyboardButton("👍 确认广告", callback_data="noop_confirm"),
                            ]
                        ]
                    )
            try:
                await bot.send_message(target_log_chat, text, reply_markup=keyboard)
            except TelegramError as exc:
                logger.warning("发送审计日志到 %s 失败: %s", target_log_chat, exc)


async def _delete_later(bot: Any, chat_id: int, message_id: int, delay: int) -> None:
    await asyncio.sleep(delay)
    try:
        await bot.delete_message(chat_id, message_id)
    except TelegramError:
        pass
