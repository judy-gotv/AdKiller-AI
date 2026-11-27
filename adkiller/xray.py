"""Full Bot API disguise X-Ray extractor, Unicode de-obfuscator, and safe image normalizer."""

from __future__ import annotations

import asyncio
import base64
import io
import logging
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Optional

from PIL import Image
from telegram import Message, MessageEntity

logger = logging.getLogger("adkiller.xray")

# Guard against decompression bombs & event-loop blocking during image transcoding
MAX_IMAGE_PIXELS = 25_000_000
MAX_IMAGE_BYTES = 5 * 1024 * 1024
_IMAGE_WORK_SEM: Optional[asyncio.Semaphore] = None


def _get_image_sem() -> asyncio.Semaphore:
    global _IMAGE_WORK_SEM
    if _IMAGE_WORK_SEM is None:
        _IMAGE_WORK_SEM = asyncio.Semaphore(2)
    return _IMAGE_WORK_SEM


def _transcode_jpeg_sync(raw_bytes: bytes) -> Optional[str]:
    """Check pixel dimensions before full decode, resize <=768px, and encode RGB JPEG."""
    if not raw_bytes or len(raw_bytes) > MAX_IMAGE_BYTES:
        return None
    with Image.open(io.BytesIO(raw_bytes)) as img:
        if (img.width * img.height) > MAX_IMAGE_PIXELS:
            logger.warning(
                "跳过超大像素图片 (%dx%d > %d pixels)",
                img.width,
                img.height,
                MAX_IMAGE_PIXELS,
            )
            return None
        # Downscale JPEG/PNG lazily via draft/thumbnail before full RGB conversion where possible
        img.thumbnail((768, 768))
        if img.mode in ("RGBA", "LA", "P"):
            bg = Image.new("RGB", img.size, (255, 255, 255))
            rgba = img.convert("RGBA")
            bg.paste(rgba, mask=rgba.split()[-1])
            out_img = bg
        else:
            out_img = img.convert("RGB")

        out = io.BytesIO()
        out_img.save(out, format="JPEG", quality=80, optimize=True)
        b64 = base64.b64encode(out.getvalue()).decode("ascii")
        return f"data:image/jpeg;base64,{b64}"

# Zero-width & invisible formatting characters commonly abused to bypass filters
_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff\u00ad\u034f\u061c\u180e]")
# Typical bulk-registered account display name: two arbitrary-length Latin alphabetic segments
# e.g. "aawsda sdawsda", "John Smith", "qwerty asdfgh"
_TWO_PART_LATIN_RE = re.compile(r"^[A-Za-z]{2,}\s+[A-Za-z]{2,}$")
_CONSONANT_CLUSTER_RE = re.compile(r"[bcdfghjklmnpqrstvwxz]{4,}", re.IGNORECASE)
_VOWEL_RE = re.compile(r"[aeiouy]", re.IGNORECASE)

# CJK separator / digit-insertion obfuscation commonly used in Telegram spammer nicknames
# e.g. "-点-简界*·看·橡·-木", "好*路·子-在-朱*叶·稳", "·副·业看·简界·曰3K", "🔥*抖音1代2刷🔥"
_CJK_SEP_CHARS = r"\-\*·•~_/|.,、‧+=・—–★☆❖✦✧°•●○◆◇■□▲△▼▽🔥👇👉⬇⚡💰💎🔞"
_CJK_SEP_BETWEEN_RE = re.compile(rf"[\u4e00-\u9fff][{_CJK_SEP_CHARS}\s]+(?=[\u4e00-\u9fff])")
_CJK_DIGIT_BETWEEN_RE = re.compile(r"[\u4e00-\u9fff][0-9](?=[\u4e00-\u9fff])")
_STRIP_NAME_SEP_RE = re.compile(rf"[{_CJK_SEP_CHARS}\s]+")
_STRIP_CJK_INTER_DIGIT_RE = re.compile(r"(?<=[\u4e00-\u9fff])[0-9]+(?=[\u4e00-\u9fff])")

# High-precision profile-bait / homophone-bait patterns (run AFTER stripping separators & NFKC)
_PROFILE_BAIT_RE = re.compile(
    r"(?:"
    r"点简[介界届]|看简[介界届]|简[介界届]看|简[介界届]有|点我简|看我简|"
    r"看[主朱竹][页叶业]|在[主朱竹][页叶业]|点[主朱竹][页叶业]|点我[主朱竹]|看我[主朱竹]|[主朱竹][页叶]有|[主朱竹][页叶]看|"
    r"看[项橡][木目]|橡木|好路子|副业.{0,3}(?:看|简|主|日|曰|稳|赚)|"
    r"(?:抖音|快手|小红书).{0,2}(?:代刷|刷粉|刷赞|刷礼物|点赞)|"
    r"[日曰](?:赚|入)?[1-9][0-9]*[kKwW万千]|[日曰]结|收米|拿码|黑[uU]|跑分|洗钱|代刷|水果机|约炮|裸聊|看片|菠菜|博彩"
    r")",
    re.IGNORECASE,
)


def deobfuscate_profile_text(text: str) -> tuple[str, str, bool]:
    """Normalize & strip CJK separator/digit obfuscation from profile names/channels.

    Returns (sep_stripped, digit_sep_stripped, is_obfuscated).
    """
    if not text:
        return "", "", False
    cleaned, obf_flags = normalize_and_detect_obfuscation(text)
    sep_hits = len(_CJK_SEP_BETWEEN_RE.findall(cleaned))
    digit_hits = len(_CJK_DIGIT_BETWEEN_RE.findall(cleaned))
    is_obf = bool(obf_flags) or sep_hits >= 2 or (sep_hits >= 1 and digit_hits >= 1) or digit_hits >= 2
    sep_stripped = _STRIP_NAME_SEP_RE.sub("", cleaned)
    digit_sep_stripped = _STRIP_CJK_INTER_DIGIT_RE.sub("", sep_stripped)
    return sep_stripped, digit_sep_stripped, is_obf


def has_profile_bait_signal(text: str) -> bool:
    """Return True if a profile name/channel/bio contains explicit TG promo-bait or homophone slang."""
    if not text:
        return False
    sep_stripped, digit_sep_stripped, _ = deobfuscate_profile_text(text)
    return bool(_PROFILE_BAIT_RE.search(sep_stripped) or _PROFILE_BAIT_RE.search(digit_sep_stripped))


def _is_meaningless_bait_body(text: str, media_type: str) -> bool:
    """Detect low-content exposure bait messages (e.g. '5', '7', '1', '.', sticker-only, empty)."""
    s = (text or "").strip()
    if not s:
        return True
    if len(s) <= 4 and re.fullmatch(r"[\d\W_]+", s):
        return True
    if len(s) == 1:
        return True
    return False


def _looks_like_random_latin(full_name: str) -> bool:
    """Detect keyboard-mash / random-letter two-part names like 'aawsda sdawsda'."""
    parts = full_name.strip().split()
    if len(parts) != 2:
        return False
    # All-lowercase two-part Latin (e.g. "aawsda sdawsda") is a strong bulk-bot tell
    if all(p.islower() and len(p) >= 3 for p in parts):
        return True
    for p in parts:
        if len(p) >= 4 and not _VOWEL_RE.search(p):
            return True
        if _CONSONANT_CLUSTER_RE.search(p):
            return True
        # Same letter repeated 3+ times or very low character variety in long string
        if re.search(r"(.)\1\1", p, re.IGNORECASE):
            return True
    return False


def _looks_like_single_gibberish_latin(full_name: str) -> bool:
    """Detect single-word consonant-mash bot names like 'Gbgjf' or 'Zllh' (excludes ALL-CAPS tech acronyms like HTTP/VPS)."""
    s = full_name.strip()
    if len(s) < 4 or not s.isascii() or not s.isalpha():
        return False
    if s.isupper():
        return False
    return not bool(_VOWEL_RE.search(s))


def analyze_profile_risk(profile: dict[str, Any], clean_count: int = 0) -> tuple[list[str], int, bool]:
    """Additive profile risk scoring for blank/bulk-registered & promo-obfuscated spam accounts.

    Each signal contributes independently:
      - Deliberate CJK separator/digit obfuscated nickname (e.g. "-点-简界*·看·橡·-木"): +15
      - Promo-bait / homophone slang in nickname or personal channel:                     +15
      - Two-part random/gibberish Latin name (e.g. "aawsda sdawsda"):                    +12
      - Two-part regular Latin name (e.g. "John Smith"):                                 +10
      - Single-word vowel-less gibberish Latin name (e.g. "Gbgjf", "Zllh"):               +8
      - No real profile photo (default letter avatar):                                    +4
      - Empty profile (no bio and no personal channel):                                   +3
      - No @username set:                                                                 +2
    Full-hit blank account OR obfuscated promo-bait profile sets is_max_risk=True
    (every message forced to AI, even after >=5 clean msgs).
    Note: The score boost is ONLY added when AI already flags suspicious intent,
    so normal conversations are never false-banned.
    """
    if not profile:
        return [], 0, False

    has_photo = profile.get("has_photo", True)
    full_name = str(profile.get("full_name", "") or "").strip()
    username = str(profile.get("username", "") or "").strip()
    bio = str(profile.get("bio", "") or "").strip()
    personal_channel = str(profile.get("personal_channel", "") or "").strip()
    personal_channel_bio = str(profile.get("personal_channel_bio", "") or "").strip()

    no_avatar = has_photo is False
    two_part_latin = bool(_TWO_PART_LATIN_RE.match(full_name))
    random_latin = two_part_latin and _looks_like_random_latin(full_name)
    single_gibberish = (not two_part_latin) and _looks_like_single_gibberish_latin(full_name)
    empty_profile = (not bio) and (not personal_channel)
    no_username = username in {"", "(无)"}

    _, _, name_sep_obf = deobfuscate_profile_text(full_name)
    _, _, pchat_sep_obf = deobfuscate_profile_text(personal_channel)
    promo_bait = (
        has_profile_bait_signal(full_name)
        or has_profile_bait_signal(personal_channel)
        or has_profile_bait_signal(personal_channel_bio)
    )

    full_hit = (
        (no_avatar and (two_part_latin or single_gibberish) and empty_profile and no_username)
        or (promo_bait and (name_sep_obf or pchat_sep_obf))
    )

    # Non-full-hit profiles are exempted once the member has >= 5 clean messages
    if not full_hit and clean_count >= 5:
        return [], 0, False

    flags: list[str] = []
    boost = 0

    if name_sep_obf:
        flags.append("昵称刻意符号隔断混淆(+15)")
        boost += 15
    elif pchat_sep_obf:
        flags.append("主页频道名刻意符号隔断混淆(+10)")
        boost += 10

    if promo_bait:
        flags.append("昵称/主页频道含引流混淆暗语(+15)")
        boost += 15

    if random_latin:
        flags.append("两段随机/无意义字母昵称(+12)")
        boost += 12
    elif two_part_latin:
        flags.append("两段纯字母昵称(+10)")
        boost += 10
    elif single_gibberish:
        flags.append("单段无元音乱码字母昵称(+8)")
        boost += 8

    if no_avatar:
        flags.append("无真实头像(+4)")
        boost += 4

    if empty_profile:
        flags.append("主页Bio空白(+3)")
        boost += 3

    if no_username:
        flags.append("无@用户名(+2)")
        boost += 2

    return flags, boost, full_hit

# Executable/malware extensions frequently used in TG account-stealing scams
DANGEROUS_EXTENSIONS = (
    ".apk",
    ".exe",
    ".msi",
    ".scr",
    ".bat",
    ".cmd",
    ".vbs",
    ".ps1",
    ".dmg",
    ".jar",
    ".lnk",
)


def normalize_and_detect_obfuscation(text: str) -> tuple[str, list[str]]:
    """Strip zero-width characters, apply NFKC normalization, and flag obfuscation tricks."""
    if not text:
        return "", []

    flags: list[str] = []
    zw_matches = _ZERO_WIDTH_RE.findall(text)
    if zw_matches:
        flags.append(f"含{len(zw_matches)}个零宽隐形混淆字符")
    cleaned = _ZERO_WIDTH_RE.sub("", text)

    nfkc = unicodedata.normalize("NFKC", cleaned)
    # Detect full-width / stylized Unicode math/alphanumeric spoofing (excluding standard CJK punctuation)
    if nfkc != cleaned:
        diff_alnum = any(
            (a != b) and b.isascii() and b.isalnum()
            for a, b in zip(cleaned, nfkc)
        )
        if diff_alnum:
            flags.append("含全角/变形字母数字混淆")

    return nfkc, flags


@dataclass
class MessageXRay:
    is_edited: bool = False
    text: str = ""
    normalized_text: str = ""
    obfuscation_flags: list[str] = field(default_factory=list)
    hidden_links: list[str] = field(default_factory=list)
    plain_urls: list[str] = field(default_factory=list)
    mentions: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    custom_emojis: int = 0
    inline_buttons: list[str] = field(default_factory=list)
    via_bot: str = ""
    external_reply: str = ""
    is_reply: bool = False
    reply_preview: str = ""
    forward_from: str = ""
    sender_chat: str = ""
    sticker_info: str = ""
    poll_info: str = ""
    special_payload: str = ""
    dangerous_filename: str = ""
    media_type: str = ""

    def allow_shared_cache(self) -> bool:
        """Replies to another group message (including stickers/captionless media) never populate or hit shared spam cache."""
        return not self.is_reply

    def has_risk_signal(self) -> bool:
        return bool(
            self.is_edited
            or self.obfuscation_flags
            or self.hidden_links
            or self.plain_urls
            or self.inline_buttons
            or self.via_bot
            or self.external_reply
            or self.forward_from
            or self.sender_chat
            or self.poll_info
            or self.special_payload
            or self.dangerous_filename
            or self.media_type
            or self.mentions
            or self.commands
            or self.custom_emojis > 0
        )

    def build_preview(self) -> str:
        parts: list[str] = []
        if self.normalized_text or self.text:
            parts.append((self.normalized_text or self.text)[:220])
        if self.hidden_links:
            parts.append("隐藏链:" + " ".join(self.hidden_links)[:180])
        if self.inline_buttons:
            parts.append("按钮:" + " ".join(self.inline_buttons)[:150])
        if self.via_bot:
            parts.append(f"via:{self.via_bot}")
        if self.external_reply:
            parts.append(f"外引:{self.external_reply[:100]}")
        if self.poll_info:
            parts.append(f"投票:{self.poll_info[:100]}")
        if self.special_payload:
            parts.append(self.special_payload)
        if self.dangerous_filename:
            parts.append(f"高危文件:{self.dangerous_filename}")
        if self.media_type:
            parts.append(f"媒体:{self.media_type}")
        return " | ".join(parts) or "(空消息)"

    def format_for_ai(
        self,
        profile: dict[str, str],
        recent_context: list[str],
        user_fragments: list[str],
        clean_count: int,
        vision_attached: bool,
    ) -> str:
        rep = "新面孔" if clean_count < 3 else ("普通成员" if clean_count < 15 else "高活跃老群友")
        lines = [
            f"【用户信誉】: {rep}（本群历史正常发言 {clean_count} 次）",
            f"【是否编辑后的消息】: {'是（高危：事后修改）' if self.is_edited else '否'}",
            f"【发件人资料】: 昵称={profile.get('full_name', '')} | 用户名={profile.get('username', '(无)')}",
        ]
        if profile.get("bio"):
            lines.append(f"【发件人个人简介(Bio)】: {profile['bio']}")
        if profile.get("personal_channel"):
            lines.append(f"【发件人主页绑定频道】: {profile['personal_channel']}")
        if profile.get("personal_channel_bio"):
            lines.append(f"【发件人主页频道简介】: {profile['personal_channel_bio']}")
        # De-obfuscate obfuscated/promo nicknames & personal channels so AI sees the hidden wording immediately
        deobf_notes: list[str] = []
        raw_fname = str(profile.get("full_name", "") or "")
        if raw_fname:
            s1, s2, fname_obf = deobfuscate_profile_text(raw_fname)
            if fname_obf or has_profile_bait_signal(raw_fname):
                shown = s2 if (s2 and s2 != s1) else s1
                deobf_notes.append(f"昵称去混淆=「{shown}」")
        raw_pchat = str(profile.get("personal_channel", "") or "")
        if raw_pchat:
            c1, c2, ch_obf = deobfuscate_profile_text(raw_pchat)
            if ch_obf or has_profile_bait_signal(raw_pchat):
                shown = c2 if (c2 and c2 != c1) else c1
                deobf_notes.append(f"主页频道去混淆=「{shown}」")
        if deobf_notes:
            lines.append(
                f"【⚠️ 资料去混淆还原】: {' | '.join(deobf_notes)}（刻意插入符号/数字/谐音规避关键词，高度警惕主页引流广告号）"
            )
        profile_flags, profile_boost, is_max_risk = analyze_profile_risk(
            profile, clean_count=clean_count
        )
        if is_max_risk:
            lines.append(
                f"【最高风控画像·全命中 (+{profile_boost}分)】: {' + '.join(profile_flags)}（高度疑似批量/主页引流广告号，请从严审核，仅正常聊天放行）"
            )
        elif profile_flags:
            lines.append(
                f"【账号画像风险信号 (+{profile_boost}分)】: {'、'.join(profile_flags)}（请结合发言内容综合判断）"
            )
        effective_text = self.normalized_text or self.text
        if (
            deobf_notes
            or any(("隔断混淆" in f or "引流" in f) for f in profile_flags)
        ) and _is_meaningless_bait_body(effective_text, self.media_type):
            lines.append(
                "【🚨 疑似“昵称/主页引流+碎片蹭曝光”组合】: 正文故意仅发无意义单字/单数字/空白/贴纸，但昵称或主页资料含引流混淆暗语，属典型引流曝光号！"
            )
        if self.obfuscation_flags:
            lines.append(f"【检测到字符混淆】: {', '.join(self.obfuscation_flags)}")
        if self.sender_chat:
            lines.append(f"【使用外部频道马甲发言】: {self.sender_chat}")
        if self.via_bot:
            lines.append(f"【通过外部内联机器人发送】: {self.via_bot}")
        if self.forward_from:
            lines.append(f"【转发来源】: {self.forward_from}")
        if self.external_reply:
            lines.append(f"【外部引用来源】: {self.external_reply}")
        if self.reply_preview:
            lines.append(f"【回复的群内消息】: {self.reply_preview}")
        if self.hidden_links:
            lines.append(f"【剥出的隐藏超链接】: {', '.join(self.hidden_links)}")
        if self.plain_urls:
            lines.append(f"【明文链接】: {', '.join(self.plain_urls)}")
        if self.inline_buttons:
            lines.append(f"【内联跳转按钮】: {', '.join(self.inline_buttons)}")
        if self.poll_info:
            lines.append(f"【投票内容】: {self.poll_info}")
        if self.special_payload:
            lines.append(f"【特殊消息载体】: {self.special_payload}")
        if self.dangerous_filename:
            lines.append(f"【高危可执行文件】: {self.dangerous_filename}")
        if self.mentions:
            lines.append(f"【@提及】: {', '.join(self.mentions)}")
        if self.commands:
            lines.append(f"【指令】: {', '.join(self.commands)}")
        if self.sticker_info:
            lines.append(f"【贴纸信息】: {self.sticker_info}")
        if self.media_type:
            note = "（已附带图片供视觉审查）" if vision_attached else "（当前未启用图片视觉审查）"
            lines.append(f"【附带媒体】: {self.media_type} {note}")

        effective_text = self.normalized_text or self.text
        body = (effective_text[:800] + "…") if len(effective_text) > 800 else (
            effective_text or "(无文字，请结合附带图片/贴纸/链接/外部引用/投票/资料判断)"
        )
        lines.append(f"【当前消息正文】:\n{body}")

        if user_fragments:
            lines.append(
                "【该用户近10分钟连续发言（排查拆分广告）】:\n"
                + "\n".join(f"- {f}" for f in user_fragments)
            )
        if recent_context:
            lines.append("【群内最近聊天上下文】:\n" + "\n".join(recent_context))

        return "\n".join(lines)

    def format_content_only_for_ai(self, *, vision_attached: bool) -> str:
        """Pure standalone message content prompt (ZERO sender profile, history, or chat context).

        Used exclusively before promoting a fingerprint into a shared same-group spam cache so
        one member's bio/fragments/context can NEVER cause another member to be auto-banned.
        """
        lines = [
            "【纯消息内容独立复核（不含发言人资料、历史发言与群聊上下文）】",
            "请仅依据以下单条消息内容本身（及附带图片）判断是否属于垃圾广告/引流/欺诈；"
            "若脱离发言人资料或上下文无法独立断定为垃圾广告，请判为正常(state=0，给低分)。",
        ]
        if self.obfuscation_flags:
            lines.append(f"【检测到字符混淆】: {', '.join(self.obfuscation_flags)}")
        if self.sender_chat:
            lines.append(f"【外部频道马甲】: {self.sender_chat}")
        if self.via_bot:
            lines.append(f"【外部内联机器人】: {self.via_bot}")
        if self.forward_from:
            lines.append(f"【转发来源】: {self.forward_from}")
        if self.external_reply:
            lines.append(f"【外部引用来源】: {self.external_reply}")
        if self.hidden_links:
            lines.append(f"【剥出的隐藏超链接】: {', '.join(self.hidden_links)}")
        if self.plain_urls:
            lines.append(f"【明文链接】: {', '.join(self.plain_urls)}")
        if self.inline_buttons:
            lines.append(f"【内联跳转按钮】: {', '.join(self.inline_buttons)}")
        if self.poll_info:
            lines.append(f"【投票内容】: {self.poll_info}")
        if self.special_payload:
            lines.append(f"【特殊消息载体】: {self.special_payload}")
        if self.dangerous_filename:
            lines.append(f"【高危可执行文件】: {self.dangerous_filename}")
        if self.mentions:
            lines.append(f"【@提及】: {', '.join(self.mentions)}")
        if self.commands:
            lines.append(f"【指令】: {', '.join(self.commands)}")
        if self.sticker_info:
            lines.append(f"【贴纸信息】: {self.sticker_info}")
        if self.media_type:
            note = "（已附带图片供视觉审查）" if vision_attached else "（当前未启用图片视觉审查）"
            lines.append(f"【附带媒体】: {self.media_type} {note}")

        effective_text = self.normalized_text or self.text
        body = (effective_text[:800] + "…") if len(effective_text) > 800 else (
            effective_text or "(无文字，请仅结合附带图片/贴纸/链接/外部引用/投票判断)"
        )
        lines.append(f"【当前消息正文】:\n{body}")
        return "\n".join(lines)


def _describe_origin(origin: Any) -> str:
    if not origin:
        return ""
    chat = getattr(origin, "chat", None) or getattr(origin, "sender_chat", None)
    if chat:
        title = getattr(chat, "title", "") or ""
        uname = f"@{chat.username}" if getattr(chat, "username", None) else ""
        return f"{title} {uname}".strip()
    user = getattr(origin, "sender_user", None)
    if user:
        uname = f"@{user.username}" if getattr(user, "username", None) else ""
        return f"{getattr(user, 'full_name', '')} {uname}".strip()
    hidden = getattr(origin, "sender_user_name", None)
    if hidden:
        return str(hidden)
    return str(getattr(origin, "type", "unknown"))


def _safe_slice_utf16(text: str, offset: int, length: int) -> str:
    if not text:
        return ""
    raw = text.encode("utf-16-le")
    return raw[offset * 2 : (offset + length) * 2].decode("utf-16-le", errors="ignore")


def extract_xray(msg: Any, is_edited: bool = False) -> MessageXRay:
    text = getattr(msg, "text", None) or getattr(msg, "caption", None) or ""
    normalized_text, obfuscation_flags = normalize_and_detect_obfuscation(text)

    entity_pairs: list[tuple[Any, str]] = []
    for ent in getattr(msg, "entities", None) or ():
        if hasattr(msg, "parse_entity"):
            try:
                seg = msg.parse_entity(ent)
            except Exception:
                seg = _safe_slice_utf16(getattr(msg, "text", "") or "", ent.offset, ent.length)
        else:
            seg = _safe_slice_utf16(getattr(msg, "text", "") or "", ent.offset, ent.length)
        entity_pairs.append((ent, seg))

    for ent in getattr(msg, "caption_entities", None) or ():
        if hasattr(msg, "parse_caption_entity"):
            try:
                seg = msg.parse_caption_entity(ent)
            except Exception:
                seg = _safe_slice_utf16(getattr(msg, "caption", "") or "", ent.offset, ent.length)
        else:
            seg = _safe_slice_utf16(getattr(msg, "caption", "") or "", ent.offset, ent.length)
        entity_pairs.append((ent, seg))

    hidden_links: list[str] = []
    plain_urls: list[str] = []
    mentions: list[str] = []
    commands: list[str] = []
    custom_emojis = 0

    for ent, seg in entity_pairs:
        etype = getattr(ent, "type", "")
        if etype == MessageEntity.TEXT_LINK and getattr(ent, "url", None):
            hidden_links.append(f"[{seg or '隐形字符'} -> {ent.url}]")
        elif etype == MessageEntity.URL:
            plain_urls.append(seg)
        elif etype == MessageEntity.MENTION:
            mentions.append(seg)
        elif etype == MessageEntity.TEXT_MENTION and getattr(ent, "user", None):
            mentions.append(f"{seg}(uid:{ent.user.id})")
        elif etype == MessageEntity.BOT_COMMAND:
            commands.append(seg)
        elif etype == MessageEntity.CUSTOM_EMOJI:
            custom_emojis += 1

    lpo = getattr(msg, "link_preview_options", None)
    if lpo and getattr(lpo, "url", None):
        hidden_links.append(f"[网页预览隐藏链接 -> {lpo.url}]")

    inline_buttons: list[str] = []
    markup = getattr(msg, "reply_markup", None)
    if markup and getattr(markup, "inline_keyboard", None):
        for row in markup.inline_keyboard:
            for btn in row:
                web_app = getattr(btn, "web_app", None)
                target = (
                    getattr(btn, "url", None)
                    or (getattr(web_app, "url", None) if web_app else None)
                    or getattr(btn, "callback_data", None)
                    or ""
                )
                inline_buttons.append(f"[{getattr(btn, 'text', '')} -> {target}]")

    via_bot = ""
    vb = getattr(msg, "via_bot", None)
    if vb:
        via_bot = f"@{vb.username}" if getattr(vb, "username", None) else getattr(vb, "full_name", "bot")

    external_reply = ""
    ext = getattr(msg, "external_reply", None)
    quote = getattr(msg, "quote", None)
    quote_text = getattr(quote, "text", "") or ""
    if ext:
        origin_desc = _describe_origin(getattr(ext, "origin", None))
        ext_chat = getattr(ext, "chat", None)
        if ext_chat:
            ctitle = getattr(ext_chat, "title", "") or ""
            cuser = f"@{ext_chat.username}" if getattr(ext_chat, "username", None) else ""
            origin_desc = f"{origin_desc} ({ctitle} {cuser})".strip()
        external_reply = f"来源:{origin_desc}; 引用:{quote_text[:200]}".strip()
    elif quote_text:
        external_reply = f"引用片段:{quote_text[:200]}"

    reply_preview = ""
    reply_msg = getattr(msg, "reply_to_message", None)
    is_reply = bool(
        reply_msg is not None and not getattr(reply_msg, "forum_topic_created", None)
    )
    if reply_msg:
        rtext = getattr(reply_msg, "text", None) or getattr(reply_msg, "caption", None) or ""
        if rtext:
            reply_preview = rtext[:160]

    forward_from = _describe_origin(getattr(msg, "forward_origin", None))

    sender_chat = ""
    sc = getattr(msg, "sender_chat", None)
    chat = getattr(msg, "chat", None)
    if sc and chat and getattr(sc, "id", None) != getattr(chat, "id", None):
        sc_title = getattr(sc, "title", "") or ""
        sc_user = f"@{sc.username}" if getattr(sc, "username", None) else ""
        sender_chat = f"{sc_title} {sc_user}".strip()

    # Poll / Story / Paid Media coverage
    poll_info = ""
    poll = getattr(msg, "poll", None)
    if poll:
        opts = [getattr(o, "text", "") for o in (getattr(poll, "options", None) or [])]
        poll_info = f"问题:{getattr(poll, 'question', '')} | 选项:{' / '.join(opts[:10])}"

    special_parts: list[str] = []
    if getattr(msg, "story", None):
        st_chat = getattr(msg.story, "chat", None)
        st_name = getattr(st_chat, "title", "") or getattr(st_chat, "username", "") if st_chat else ""
        special_parts.append(f"转发动态(Story:{st_name})")
    if getattr(msg, "paid_media", None):
        stars = getattr(msg.paid_media, "star_count", 0)
        special_parts.append(f"付费星币媒体({stars} Stars)")
    contact = getattr(msg, "contact", None)
    if contact:
        c_name = " ".join(
            p for p in (getattr(contact, "first_name", "") or "", getattr(contact, "last_name", "") or "") if p
        )
        c_phone = getattr(contact, "phone_number", "") or ""
        c_vcard = (getattr(contact, "vcard", "") or "").strip()
        vcard_note = f" vcard={c_vcard[:160]}" if c_vcard else ""
        special_parts.append(f"分享名片({c_name} {c_phone}{vcard_note})".strip())
    venue = getattr(msg, "venue", None)
    if venue:
        special_parts.append(
            f"地点卡片({getattr(venue, 'title', '') or ''} / {getattr(venue, 'address', '') or ''})"
        )
    elif getattr(msg, "location", None):
        special_parts.append("位置坐标")
    dice = getattr(msg, "dice", None)
    if dice:
        special_parts.append(f"随机动画({getattr(dice, 'emoji', '') or ''}={getattr(dice, 'value', '')})")
    game = getattr(msg, "game", None)
    if game:
        special_parts.append(
            f"游戏卡片({getattr(game, 'title', '') or ''}: {getattr(game, 'description', '') or ''})"
        )
    special_payload = ", ".join(special_parts)

    # Sticker, media & dangerous executable file detection
    sticker_info = ""
    media_type = ""
    dangerous_filename = ""
    if getattr(msg, "photo", None):
        media_type = "photo"
    elif getattr(msg, "sticker", None):
        media_type = "sticker"
        st = msg.sticker
        st_kind = "animated" if getattr(st, "is_animated", False) else (
            "video" if getattr(st, "is_video", False) else "static"
        )
        has_thumb = bool(getattr(st, "thumbnail", None))
        sticker_info = (
            f"kind={st_kind}, thumb={'yes' if has_thumb else 'no'}, "
            f"emoji={getattr(st, 'emoji', '') or ''}, set={getattr(st, 'set_name', '') or ''}"
        )
    elif getattr(msg, "video", None):
        media_type = "video"
    elif getattr(msg, "video_note", None):
        media_type = "video_note"
    elif getattr(msg, "animation", None):
        media_type = "gif"
    elif getattr(msg, "voice", None):
        dur = getattr(msg.voice, "duration", 0) or 0
        media_type = f"voice({dur}s)"
    elif getattr(msg, "audio", None):
        au = msg.audio
        au_label = getattr(au, "title", "") or getattr(au, "file_name", "") or ""
        media_type = f"audio({au_label})" if au_label else "audio"
    elif getattr(msg, "document", None):
        fname = getattr(msg.document, "file_name", "") or ""
        media_type = f"document({fname})"
        if fname.lower().endswith(DANGEROUS_EXTENSIONS):
            dangerous_filename = fname

    return MessageXRay(
        is_edited=is_edited,
        text=text[:1500],
        normalized_text=normalized_text[:1500],
        obfuscation_flags=obfuscation_flags,
        hidden_links=hidden_links[:10],
        plain_urls=plain_urls[:10],
        mentions=mentions[:10],
        commands=commands[:5],
        custom_emojis=custom_emojis,
        inline_buttons=inline_buttons[:10],
        via_bot=via_bot,
        external_reply=external_reply,
        is_reply=is_reply,
        reply_preview=reply_preview,
        forward_from=forward_from,
        sender_chat=sender_chat,
        sticker_info=sticker_info,
        poll_info=poll_info[:300],
        special_payload=special_payload,
        dangerous_filename=dangerous_filename,
        media_type=media_type,
    )


async def extract_image_data_url(bot: Any, msg: Message) -> Optional[str]:
    """Download photo/sticker/video thumbnail and normalize to <=768px RGB JPEG base64."""
    file_id: Optional[str] = None
    if msg.photo:
        chosen = msg.photo[-1]
        for p in msg.photo:
            if p.width >= 640 or p.height >= 640:
                chosen = p
                break
        file_id = chosen.file_id
    elif msg.sticker:
        if msg.sticker.thumbnail:
            file_id = msg.sticker.thumbnail.file_id
        elif not msg.sticker.is_animated and not msg.sticker.is_video:
            file_id = msg.sticker.file_id
    elif msg.video and msg.video.thumbnail:
        file_id = msg.video.thumbnail.file_id
    elif getattr(msg, "video_note", None) and getattr(msg.video_note, "thumbnail", None):
        file_id = msg.video_note.thumbnail.file_id
    elif msg.animation and msg.animation.thumbnail:
        file_id = msg.animation.thumbnail.file_id
    elif msg.document and msg.document.thumbnail:
        file_id = msg.document.thumbnail.file_id
    elif msg.document and (msg.document.mime_type or "").startswith("image/"):
        if (msg.document.file_size or 0) <= 5 * 1024 * 1024:
            file_id = msg.document.file_id

    if not file_id:
        return None

    try:
        async with _get_image_sem():
            tg_file = await bot.get_file(file_id)
            if (getattr(tg_file, "file_size", None) or 0) > MAX_IMAGE_BYTES:
                return None
            buf = io.BytesIO()
            await tg_file.download_to_memory(out=buf)
            raw_bytes = buf.getvalue()
            if not raw_bytes:
                return None
            return await asyncio.to_thread(_transcode_jpeg_sync, raw_bytes)
    except Exception as exc:
        logger.debug("提取图片缩略图失败（忽略识图）: %s", exc)
        return None


def inspect_raw_message_fields(msg: Any) -> dict[str, Any]:
    """Capture a bounded, JSON-serializable inventory of Telegram Bot API fields on a message for diagnostics."""
    info: dict[str, Any] = {}
    if getattr(msg, "text", None):
        info["text"] = str(msg.text)[:1000]
    if getattr(msg, "caption", None):
        info["caption"] = str(msg.caption)[:1000]

    ents_out: list[dict[str, Any]] = []
    for key in ("entities", "caption_entities"):
        for ent in getattr(msg, key, None) or ():
            item: dict[str, Any] = {
                "src": key,
                "type": str(getattr(ent, "type", "")),
                "offset": getattr(ent, "offset", 0),
                "length": getattr(ent, "length", 0),
            }
            if getattr(ent, "url", None):
                item["url"] = str(ent.url)[:300]
            if getattr(ent, "custom_emoji_id", None):
                item["custom_emoji_id"] = str(ent.custom_emoji_id)
            if getattr(ent, "user", None):
                item["user_id"] = getattr(ent.user, "id", None)
            ents_out.append(item)
    if ents_out:
        info["entities"] = ents_out[:30]

    origin = getattr(msg, "forward_origin", None)
    if origin:
        o_dict: dict[str, Any] = {"type": str(getattr(origin, "type", ""))}
        su = getattr(origin, "sender_user", None)
        if su:
            o_dict["sender_user_id"] = getattr(su, "id", None)
            o_dict["sender_user_name"] = getattr(su, "full_name", "") or ""
            o_dict["sender_username"] = getattr(su, "username", "") or ""
        if getattr(origin, "sender_user_name", None):
            o_dict["hidden_sender_name"] = str(origin.sender_user_name)
        och = getattr(origin, "chat", None) or getattr(origin, "sender_chat", None)
        if och:
            o_dict["chat_id"] = getattr(och, "id", None)
            o_dict["chat_title"] = getattr(och, "title", "") or ""
            o_dict["chat_username"] = getattr(och, "username", "") or ""
        info["forward_origin"] = o_dict

    if getattr(msg, "photo", None):
        sizes = msg.photo
        info["photo"] = {
            "count": len(sizes),
            "largest": f"{getattr(sizes[-1], 'width', 0)}x{getattr(sizes[-1], 'height', 0)}" if sizes else "",
        }
    st = getattr(msg, "sticker", None)
    if st:
        info["sticker"] = {
            "type": str(getattr(st, "type", "")),
            "is_animated": bool(getattr(st, "is_animated", False)),
            "is_video": bool(getattr(st, "is_video", False)),
            "has_thumbnail": bool(getattr(st, "thumbnail", None)),
            "emoji": getattr(st, "emoji", "") or "",
            "set_name": getattr(st, "set_name", "") or "",
            "custom_emoji_id": getattr(st, "custom_emoji_id", "") or "",
        }
    for attr in ("video", "animation", "video_note", "voice", "audio", "document"):
        obj = getattr(msg, attr, None)
        if obj:
            info[attr] = {
                "mime_type": getattr(obj, "mime_type", "") or "",
                "file_name": getattr(obj, "file_name", "") or "",
                "file_size": getattr(obj, "file_size", None),
                "duration": getattr(obj, "duration", None),
                "has_thumbnail": bool(getattr(obj, "thumbnail", None)),
            }
    for attr in ("contact", "location", "venue", "dice", "poll", "story", "paid_media", "game", "via_bot"):
        if getattr(msg, attr, None):
            info[attr] = True
    if getattr(msg, "link_preview_options", None):
        lpo = msg.link_preview_options
        info["link_preview_options"] = {"url": getattr(lpo, "url", "") or ""}
    if getattr(msg, "external_reply", None):
        info["external_reply"] = True
    if getattr(msg, "quote", None):
        info["quote"] = str(getattr(msg.quote, "text", "") or "")[:300]
    if getattr(msg, "reply_markup", None):
        info["has_reply_markup"] = True
    if getattr(msg, "media_group_id", None):
        info["media_group_id"] = str(msg.media_group_id)
    return info
