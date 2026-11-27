"""Zero-LLM local heuristic anti-spam rule engine for AI-智能广告杀手.

Provides conservative, polysemy-safe baseline protection when AI_API_KEY is not configured
OR when the upstream LLM API is temporarily unreachable/out of quota.

Key anti-false-positive invariants:
1. Everyday polysemous words (e.g. 菠菜 / 跑分 / 四件套) NEVER trigger mute or ban on their own,
   and are ignored altogether in benign culinary/hardware/bedding contexts.
2. Anti-scam warning sentences ("提醒新人：刷单和洗钱都是骗局，别信") are recognized and released.
3. Without independent promotion/conversion evidence (recruitment pitch, contact funnel,
   hidden/invite link, inline button, or obfuscation), local score is hard-capped <= 50 so
   normal discussion can NEVER trigger mute or permanent ban.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .xray import MessageXRay

# Tier A: Explicit commercial solicitation / recruitment pitches (inherently promotional)
_PROMO_HARD_PATTERNS: list[tuple[re.Pattern[str], int, str]] = [
    (
        re.compile(
            r"(预付开工|拿.{0,6}预付|秒结算|帮发消息|代发频道|代发广告|做的联系|做单联系|招代发)",
            re.IGNORECASE,
        ),
        68,
        "命中灰产招工/代发话术",
    ),
    (
        re.compile(
            r"(飞机号批发|协议号出售|老号出售|实名卡出售|黑卡出售|银行卡四件套.{0,6}[出收办卖])",
            re.IGNORECASE,
        ),
        68,
        "命中灰产账号/卡证售卖词",
    ),
    (
        re.compile(
            r"(看片群|成人福利群|同城约炮|裸聊加|色粉引流|资源群.{0,6}[进加私领]|资源频道.{0,6}[进加私领])",
            re.IGNORECASE,
        ),
        68,
        "命中色情/引流推广词",
    ),
    (
        re.compile(
            r"(棋牌代理|网赌代投|博彩招代理|稳赚包赢|高返利.{0,6}[私加联群]|usdt\s*搬砖套利)",
            re.IGNORECASE,
        ),
        68,
        "命中博彩/资金盘推广词",
    ),
    (
        re.compile(
            r"([出收]\s*u\b.{0,8}[私联找秒担走]|代开会员.{0,8}[私联低秒]|低价开会员|tg会员代开)",
            re.IGNORECASE,
        ),
        65,
        "命中灰产交易/代开推广词",
    ),
]

# Tier B: Sensitive illicit topic keywords — NEVER enough for mute/ban without promo evidence!
_TOPIC_RISK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(色粉|约炮|裸聊|楼凤|外围女|嫩模|福利姬|成人福利)", re.IGNORECASE), "含色情敏感词"),
    (re.compile(r"(博彩|赌台|网赌|体育盘|六合彩|时时彩|百家乐|代投)", re.IGNORECASE), "含博彩敏感词"),
    (re.compile(r"(洗钱|代收代付|假交易所|高返利)", re.IGNORECASE), "含非法支付敏感词"),
    (re.compile(r"(社工库|查开房|查户籍|实名卡|黑卡|代办证件|买粉|刷粉|刷单)", re.IGNORECASE), "含灰产/刷单敏感词"),
]

# Tier C: Polysemous everyday words — ONLY score when paired with independent promo evidence
#         AND NOT surrounded by benign everyday context!
_AMBIGUOUS_PATTERNS: list[tuple[re.Pattern[str], re.Pattern[str] | None, str]] = [
    (
        re.compile(r"菠菜", re.IGNORECASE),
        re.compile(r"(吃|炒|菜|汤|煮|蒜|鸡蛋|焯水|蔬菜|买菜|清炒|凉拌|做法|好吃|做菜)", re.IGNORECASE),
        "含疑似博彩黑话(菠菜)",
    ),
    (
        re.compile(r"跑分", re.IGNORECASE),
        re.compile(r"(显卡|cpu|gpu|手机|安兔兔|3dmark|鲁大师|geekbench|cinebench|芯片|性能|测试|测评|核显|独显|处理器|分数)", re.IGNORECASE),
        "含疑似灰产黑话(跑分)",
    ),
    (
        re.compile(r"四件套", re.IGNORECASE),
        re.compile(r"(床上|床单|被套|枕套|纯棉|全棉|磨毛|水洗棉|家居|寝室|宿舍|卧室|天丝|贡缎|买床|床品)", re.IGNORECASE),
        "含疑似黑卡黑话(四件套)",
    ),
    (
        re.compile(r"(兼职日结|日结\s*\d{2,4}|换汇|承兑|[出收]\s*u\b|代开会员)", re.IGNORECASE),
        None,
        "含高频推广交易词",
    ),
]

# Anti-scam / warning cues: helpful group members warning others about scams
_ANTI_SCAM_RE = re.compile(
    r"(都是骗局|全是骗局|是骗局|别信|不要信|不要相信|切勿轻信|谨防.{0,6}骗|防骗|反诈|小心被骗|小心骗子|都是骗子|别上当|谨防上当)",
    re.IGNORECASE,
)

# Solicitation / funnel cues (contact conversion intent)
_FUNNEL_RE = re.compile(
    r"(加\s*[vV薇微]|➕\s*[vV薇微]|vx\s*[:：]|微信\s*[:：]|qq\s*[:：]|私聊我|私信我|点我头像|看我主页|看主页|看简介|进群领|点击下方|飞机联系)",
    re.IGNORECASE,
)

# Private Telegram invite links hidden inside text_link / buttons / URLs
_TG_INVITE_RE = re.compile(r"(t\.me/\+|t\.me/joinchat/|telegram\.me/\+|tg://join)", re.IGNORECASE)


@dataclass
class BasicRuleVerdict:
    score: int
    reason: str
    matched_signals: list[str]


def evaluate_basic_rules(
    xray: MessageXRay,
    profile: dict[str, Any],
    profile_boost: int = 0,
    *,
    pure_content_only: bool = False,
) -> BasicRuleVerdict:
    """Evaluate a message using polysemy-safe local heuristics (0 LLM calls).

    When pure_content_only=True, ignores sender profile/bio/channel, profile_boost,
    and is_edited so the result depends strictly on standalone message payload.
    """
    score = 0
    signals: list[str] = []

    surfaces = [
        xray.normalized_text or xray.text,
        xray.external_reply,
        xray.poll_info,
        " ".join(xray.inline_buttons),
        " ".join(xray.hidden_links),
    ]
    if not pure_content_only:
        surfaces.extend(
            [
                str(profile.get("bio", "") or ""),
                str(profile.get("personal_channel", "") or ""),
                str(profile.get("personal_channel_bio", "") or ""),
            ]
        )
    combined = "\n".join(s for s in surfaces if s)

    # Check independent structural & conversion signals first
    has_funnel = bool(_FUNNEL_RE.search(combined))
    all_links_blob = " ".join(xray.hidden_links + xray.plain_urls + xray.inline_buttons)
    has_tg_invite = bool(_TG_INVITE_RE.search(all_links_blob))

    # 1. Tier A: Explicit promotional/recruitment pitches
    promo_hard_hits = 0
    for pattern, pts, label in _PROMO_HARD_PATTERNS:
        if pattern.search(combined):
            promo_hard_hits += 1
            score += pts if promo_hard_hits == 1 else 25
            signals.append(label)

    has_promo_action = bool(
        promo_hard_hits > 0
        or has_funnel
        or has_tg_invite
        or xray.hidden_links
        or xray.inline_buttons
        or xray.obfuscation_flags
    )

    # Anti-scam warning shield: a member warning others ("都是骗局，别信") with ZERO promo/contact/links
    if not has_promo_action and _ANTI_SCAM_RE.search(combined):
        return BasicRuleVerdict(score=0, reason="本地基础规则放行（防骗提醒语境）", matched_signals=[])

    # 2. Tier B: Sensitive topic words (capped strictly below gray-zone if no promo action!)
    topic_hits = 0
    for pattern, label in _TOPIC_RISK_PATTERNS:
        if pattern.search(combined):
            topic_hits += 1
            score += 35 if topic_hits == 1 else 15
            signals.append(label)

    # 3. Tier C: Polysemous everyday words — ONLY count when paired with promo action & non-benign context!
    if has_promo_action:
        amb_hits = 0
        for pattern, benign_re, label in _AMBIGUOUS_PATTERNS:
            if pattern.search(combined):
                if benign_re is not None and benign_re.search(combined):
                    continue
                amb_hits += 1
                score += 25 if amb_hits == 1 else 15
                signals.append(label)

    # 4. Funnel / solicitation cues
    if has_funnel:
        score += 28
        signals.append("含引流/私聊/加微话术")

    # 5. Structural disguise signals (links hidden behind text, invite links, buttons, obfuscation)
    if has_tg_invite:
        score += 45
        signals.append("含TG私密拉群邀请链接")
    elif xray.hidden_links:
        score += 22
        signals.append("含隐形超链接伪装")

    if xray.inline_buttons:
        score += 30
        signals.append("含内联跳转按钮卡片")

    if xray.obfuscation_flags:
        score += 25
        signals.append("含零宽/全角混淆字符")

    if xray.external_reply and (has_promo_action or topic_hits > 0):
        score += 20
        signals.append("外部引用引流")

    if xray.sender_chat and (has_promo_action or (topic_hits > 0 and xray.plain_urls)):
        score += 20
        signals.append("外部频道马甲推广")

    if (
        not pure_content_only
        and xray.is_edited
        and has_promo_action
    ):
        score += 20
        signals.append("事后编辑为推广内容")

    # Hard safeguard: without independent promotion/conversion evidence, NEVER trigger mute (65) or ban (80)!
    if not has_promo_action:
        score = min(score, 50)

    # 6. Conditional blank/bulk-account profile boost (only when message already shows promotion/suspicion >= 45)
    if not pure_content_only and profile_boost > 0 and has_promo_action and score >= 45:
        score += profile_boost
        signals.append(f"空白号画像加权+{profile_boost}")

    score = min(100, score)
    reason = "本地基础规则命中：" + " + ".join(signals[:4]) if signals else "本地基础规则放行"
    return BasicRuleVerdict(score=score, reason=reason, matched_signals=signals)
