"""Bot profile branding helpers: one-click AI-智能广告杀手 avatar, name, short & full descriptions."""

from __future__ import annotations

import asyncio
import io
import json
import logging
import re
from pathlib import Path
from typing import Any, Optional

import httpx
from PIL import Image

logger = logging.getLogger("adkiller.branding")

DEFAULT_BOT_NAME = "AI-智能广告杀手"
DEFAULT_BOT_SHORT_DESC = "🛡 AI-智能广告杀手 · 开源 AI 群管反广告守卫"
DEFAULT_BOT_DESC = (
    "🛡 AI-智能广告杀手 — 开源自托管 AI 反广告守卫。\n"
    "拉我进群设为管理员（勾选删消息、封禁用户），群内发 /config 即可一键开关全部防护。"
)
DEFAULT_AVATAR_PATH = Path(__file__).resolve().parents[1] / "assets" / "avatar.jpg"

MAX_BOT_NAME_LEN = 64
MAX_BOT_SHORT_DESC_LEN = 120
MAX_BOT_DESC_LEN = 512
MAX_AVATAR_BYTES = 5 * 1024 * 1024
MAX_AVATAR_PIXELS = 25_000_000

_TG_TOKEN_RE = re.compile(r"bot\d+:[A-Za-z0-9_-]{15,}")


def scrub_bot_token(text: str) -> str:
    """Defense-in-depth scrub ensuring a Telegram bot token never appears in logs or replies."""
    return _TG_TOKEN_RE.sub("bot***", text or "")


def _transcode_avatar_sync(raw_bytes: bytes, max_side: int = 512) -> Optional[bytes]:
    if not raw_bytes or len(raw_bytes) > MAX_AVATAR_BYTES:
        return None
    if not hasattr(Image, "open"):
        return raw_bytes if raw_bytes[:2] == b"\xff\xd8" else None
    try:
        with Image.open(io.BytesIO(raw_bytes)) as img:
            if img.width * img.height > MAX_AVATAR_PIXELS:
                logger.warning("拒绝超大像素头像 (%dx%d)", img.width, img.height)
                return None
            # Center-crop to square so Telegram circular avatar framing looks crisp
            side = min(img.width, img.height)
            left = (img.width - side) // 2
            top = (img.height - side) // 2
            cropped = img.crop((left, top, left + side, top + side))
            if cropped.mode != "RGB":
                cropped = cropped.convert("RGB")
            if side > max_side:
                cropped.thumbnail((max_side, max_side))
            buf = io.BytesIO()
            cropped.save(buf, format="JPEG", quality=90)
            return buf.getvalue()
    except Exception as exc:
        logger.warning("头像转码 JPEG 失败: %s", type(exc).__name__)
        return None


async def transcode_avatar_jpeg(raw_bytes: bytes, max_side: int = 512) -> Optional[bytes]:
    return await asyncio.to_thread(_transcode_avatar_sync, raw_bytes, max_side)


async def _call_tg_api(
    token: str,
    method: str,
    *,
    data: Optional[dict[str, str]] = None,
    files: Optional[dict[str, Any]] = None,
    client: Optional[Any] = None,
) -> tuple[bool, str]:
    """Call Telegram Bot API safely without ever logging or returning the bot token."""
    if not token:
        return False, "未配置 Bot Token"
    url = f"https://api.telegram.org/bot{token}/{method}"
    own_client = client is None
    http = client or httpx.AsyncClient(timeout=15.0)
    try:
        resp = await http.post(url, data=data, files=files)
        payload: dict[str, Any] = {}
        try:
            payload = resp.json()
        except Exception:
            payload = {}
        if resp.status_code == 200 and payload.get("ok") is True:
            return True, "成功"
        desc = scrub_bot_token(str(payload.get("description") or f"HTTP {resp.status_code}"))
        return False, desc[:160]
    except Exception as exc:
        # NEVER use str(exc): httpx exceptions embed the full request URL containing the bot token!
        return False, f"请求异常 ({type(exc).__name__})"
    finally:
        if own_client:
            await http.aclose()


async def set_bot_name(token: str, name: str, *, client: Optional[Any] = None) -> tuple[bool, str]:
    val = (name or "").strip()
    if not val or len(val) > MAX_BOT_NAME_LEN:
        return False, f"名称长度需在 1 ~ {MAX_BOT_NAME_LEN} 字之间"
    return await _call_tg_api(token, "setMyName", data={"name": val}, client=client)


async def set_bot_short_description(
    token: str, short_desc: str, *, client: Optional[Any] = None
) -> tuple[bool, str]:
    val = (short_desc or "").strip()
    if len(val) > MAX_BOT_SHORT_DESC_LEN:
        return False, f"简短简介长度不能超过 {MAX_BOT_SHORT_DESC_LEN} 字"
    return await _call_tg_api(
        token, "setMyShortDescription", data={"short_description": val}, client=client
    )


async def set_bot_description(
    token: str, desc: str, *, client: Optional[Any] = None
) -> tuple[bool, str]:
    val = (desc or "").strip()
    if len(val) > MAX_BOT_DESC_LEN:
        return False, f"完整介绍长度不能超过 {MAX_BOT_DESC_LEN} 字"
    return await _call_tg_api(token, "setMyDescription", data={"description": val}, client=client)


async def set_bot_profile_photo(
    token: str, jpeg_bytes: bytes, *, client: Optional[Any] = None
) -> tuple[bool, str]:
    if not jpeg_bytes or len(jpeg_bytes) > MAX_AVATAR_BYTES or jpeg_bytes[:2] != b"\xff\xd8":
        return False, "头像必须为有效的 JPG 图片（<= 5MB）"
    photo_spec = json.dumps({"type": "static", "photo": "attach://avatar"}, separators=(",", ":"))
    return await _call_tg_api(
        token,
        "setMyProfilePhoto",
        data={"photo": photo_spec},
        files={"avatar": ("avatar.jpg", jpeg_bytes, "image/jpeg")},
        client=client,
    )


async def apply_default_branding(
    token: str,
    *,
    avatar_path: Optional[Path] = None,
    client: Optional[Any] = None,
) -> list[tuple[str, bool, str]]:
    """Apply AI-智能广告杀手 official name, short description, full description, and avatar photo."""
    results: list[tuple[str, bool, str]] = []
    ok_name, msg_name = await set_bot_name(token, DEFAULT_BOT_NAME, client=client)
    results.append(("名称", ok_name, msg_name))

    ok_short, msg_short = await set_bot_short_description(
        token, DEFAULT_BOT_SHORT_DESC, client=client
    )
    results.append(("简短简介", ok_short, msg_short))

    ok_desc, msg_desc = await set_bot_description(token, DEFAULT_BOT_DESC, client=client)
    results.append(("完整介绍", ok_desc, msg_desc))

    img_path = avatar_path or DEFAULT_AVATAR_PATH
    if not img_path.is_file():
        results.append(("头像", False, "未找到默认头像文件 assets/avatar.jpg"))
    else:
        try:
            raw = img_path.read_bytes()
        except OSError:
            results.append(("头像", False, "读取头像文件失败"))
        else:
            ok_ava, msg_ava = await set_bot_profile_photo(token, raw, client=client)
            results.append(("头像", ok_ava, msg_ava))
    return results


def format_branding_results(results: list[tuple[str, bool, str]]) -> str:
    lines = ["🎨 机器人资料更新结果："]
    for label, ok, detail in results:
        lines.append(f"• {label}：{'✅ 已更新' if ok else '⚠️ ' + detail}")
    return "\n".join(lines)
