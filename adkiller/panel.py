"""Interactive /config panel, /claim, /spam reports, /antiraid, and permission-checked callbacks."""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from typing import Optional

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ChatType
from telegram.error import TelegramError
from telegram.ext import ContextTypes

from .updater import request_update

from . import __app_name__, __app_name_cn__, __version__
from .branding import (
    DEFAULT_AVATAR_PATH,
    DEFAULT_BOT_DESC,
    DEFAULT_BOT_NAME,
    DEFAULT_BOT_SHORT_DESC,
    MAX_BOT_DESC_LEN,
    MAX_BOT_NAME_LEN,
    MAX_BOT_SHORT_DESC_LEN,
    apply_default_branding,
    format_branding_results,
    set_bot_description,
    set_bot_name,
    set_bot_profile_photo,
    set_bot_short_description,
    transcode_avatar_jpeg,
)
from .captcha import DEFAULT_UNMUTE_PERMS
from .cli_stats import trigger_label
from .guard import (
    ANNOUNCE_MAX_TEMPLATE_LEN,
    DEFAULT_ANNOUNCE_TEMPLATE,
    GuardEngine,
    _delete_later,
    format_delete_delay,
    format_delete_short,
    parse_delete_delay_input,
    render_ban_announcement,
)
from .llm import (
    mask_api_key,
    sanitize_url_for_display,
    validate_ai_base_url,
    validate_api_key,
    validate_model_name,
)
from .storage import GroupSettings
from .xray import (
    analyze_profile_risk,
    extract_image_data_url,
    extract_xray,
    inspect_raw_message_fields,
)

logger = logging.getLogger("adkiller.panel")

_VIA_LABELS = {"ban": "直接秒封", "ai": "交给AI判", "off": "不拦截"}
_EXT_CH_LABELS = {"ai": "审核后由管理员决定封禁", "ban": "一律拦截", "allow": "放行跳过"}
_CYCLE_VIA = {"ban": "ai", "ai": "off", "off": "ban"}
_CYCLE_EXT_CH = {"ai": "ban", "ban": "allow", "allow": "ai"}
_CYCLE_SCORE = {70: 80, 80: 85, 85: 90, 90: 70}

_AI_PRESETS: dict[str, tuple[str, str, str]] = {
    "deepseek": ("DeepSeek", "https://api.deepseek.com/v1", "deepseek-flash"),
    "openai": ("OpenAI", "https://api.openai.com/v1", "gpt-5-mini"),
    "gemini": (
        "Gemini",
        "https://generativelanguage.googleapis.com/v1beta/openai/",
        "gemini-2.5-flash",
    ),
    "openrouter": ("OpenRouter", "https://openrouter.ai/api/v1", "google/gemini-2.5-flash"),
}


_validate_base_url = validate_ai_base_url
_validate_model_name = validate_model_name
_validate_api_key = validate_api_key


def build_start_dashboard(
    engine: GuardEngine, user_id: int, *, bot_username: str = ""
) -> tuple[str, InlineKeyboardMarkup]:
    """Build Owner's private /start dashboard with 1-click AI config, branding & group buttons."""
    if not engine.llm.is_configured:
        model_display = "🛡 基础硬防模式（未配置 API Key）"
        vision_line = "ℹ️ 点击下方「🤖 配置 AI 接口 / API Key」即可解锁 AI 语义审核与识图"
    elif engine.llm.vision_supported:
        model_display = f"{engine.llm.model}（Key: {mask_api_key(engine.llm.api_key)}）"
        vision_line = "✅ 支持多模态识图（图片/贴纸/二维码自动开启）"
    else:
        model_display = f"{engine.llm.model}（Key: {mask_api_key(engine.llm.api_key)}）"
        vision_line = "⚠️ 当前模型不支持识图，已自动降级为纯文本+伪装解析模式"

    groups_all = [g for g in engine.storage.list_groups() if engine.is_group_allowed(g.chat_id)]
    groups_on = sum(1 for g in groups_all if g.enabled)
    td = engine.storage.get_today_metrics()
    lt = engine.storage.get_lifetime_metrics()

    join_guard_on = engine.is_owner_only_join_enabled()
    join_guard_line = (
        "🔒 仅超管可拉群（陌生人拉入自动退群防白嫖）"
        if join_guard_on
        else "🔓 允许所有人拉群（已关闭防陌生人拉群）"
    )
    bot_link_line = f"• 机器人链接：https://t.me/{bot_username}\n" if bot_username else ""
    text = (
        f"🛡 欢迎使用 {__app_name_cn__} v{__version__}\n\n"
        f"{bot_link_line}"
        f"• 防护群组：共 {len(groups_all)} 个群（已开启 {groups_on} 个）| 今日杀广告 {td['bans']} / 累计 {lt['bans']}\n"
        f"• 拉群权限：{join_guard_line}\n"
        f"• 当前引擎：{model_display}\n"
        f"• 识图能力：{vision_line}\n"
        f"• 你的用户 ID：{user_id}\n\n"
        f"📖 极简用法：\n"
        f"1. 点下方按钮可随时免命令行填写/更换 AI 接口、模型与 API Key（热生效）\n"
        f"2. 点「📊 运行状态与战报」查看防护群数、广告击杀明细、疑似排查与 AI 汇报\n"
        f"3. 点「🛡 更换头像 / 名称 / 简介」可一键应用AI-智能广告杀手官方形象或自定义\n"
        f"4. 拉我进群设为管理员（勾选「删除消息」和「封禁用户」），发 /config 点按钮管理"
    )

    ai_btn_label = (
        "🤖 修改 AI 接口 / 更换 Key"
        if engine.llm.is_configured
        else "🤖 配置 AI 接口 / API Key"
    )
    join_btn_label = (
        "🔒 防陌生人拉群：仅超管"
        if join_guard_on
        else "🔓 防陌生人拉群：已放开"
    )
    buttons: list[list[InlineKeyboardButton]] = [
        [
            InlineKeyboardButton("📊 运行状态与战报", callback_data="stats:overview"),
            InlineKeyboardButton(ai_btn_label, callback_data="aiconf:menu"),
        ],
        [
            InlineKeyboardButton("🛡 更换头像 / 简介", callback_data="brand:menu"),
            InlineKeyboardButton(join_btn_label, callback_data="aiconf:toggle_join_guard"),
        ],
    ]
    for gs in groups_all[:8]:
        buttons.append(
            [
                InlineKeyboardButton(
                    f"⚙️ 管理：{gs.chat_title or gs.chat_id}",
                    callback_data=f"cfg:open:{gs.chat_id}",
                )
            ]
        )
    return text, InlineKeyboardMarkup(buttons)


def build_stats_view(
    engine: GuardEngine, view: str = "overview"
) -> tuple[str, InlineKeyboardMarkup]:
    """Build Owner-only private runtime status & detailed audit report views."""
    td = engine.storage.get_today_metrics()
    lt = engine.storage.get_lifetime_metrics()
    groups = [
        r for r in engine.storage.get_group_summary_rows() if engine.is_group_allowed(r["chat_id"])
    ]
    suspect_total, suspects = engine.storage.get_recent_suspects(limit=8)

    def _fmt_t(ts: float) -> str:
        try:
            return time.strftime("%m-%d %H:%M", time.localtime(float(ts)))
        except Exception:
            return "--:--"

    lines: list[str] = []
    if view == "kills":
        breakdown = engine.storage.get_trigger_breakdown()
        kills = engine.storage.get_recent_kills(limit=8)
        lines.append("⚔️ 广告击杀明细（广告是怎么被杀的）")
        lines.append("━━━━━━━━━━━━━━")
        if breakdown:
            lines.append("📊 按拦截方式统计：")
            for trig, cnt in breakdown[:10]:
                lines.append(f"• {trigger_label(trig)}：{cnt} 条")
        else:
            lines.append("暂无广告封禁记录。")
        if kills:
            lines.append("")
            lines.append("🧾 最近击杀记录（最新 8 条）：")
            for r in kills:
                gname = r.get("chat_title") or str(r["chat_id"])
                lines.append(
                    f"• [{_fmt_t(r['created_at'])}] {gname[:14]} | {trigger_label(r['trigger_type'])} ({r['score']}分)"
                )
                lines.append(f"  👤 {str(r['display_name'])[:22]} — {str(r['reason'])[:45]}")
    elif view == "suspects":
        lines.append("🔎 疑似与待复核排查（有没有怀疑的）")
        lines.append("━━━━━━━━━━━━━━")
        if suspect_total == 0:
            lines.append("✅ 当前暂无疑似或待复核记录，群内很干净！")
        else:
            lines.append(f"⚠️ 累计发现 {suspect_total} 条疑似/待复核记录（展示最新 8 条）：")
            for r in suspects:
                gname = r.get("chat_title") or str(r["chat_id"])
                tag = (
                    "观察标记"
                    if (r.get("dry_run") and r["trigger_type"] != "ai_suspect")
                    else trigger_label(r["trigger_type"])
                )
                lines.append(f"• [{_fmt_t(r['created_at'])}] {gname[:14]} | {tag} ({r['score']}分)")
                lines.append(f"  👤 {str(r['display_name'])[:22]} — {str(r['reason'])[:45]}")
                if r.get("preview"):
                    lines.append(f"  💬 {str(r['preview'])[:60]}")
    elif view == "ai":
        ai_rows = engine.storage.get_recent_ai_reports(limit=8)
        hit_rate = (
            f"{int(round(td['cached_tokens'] * 100 / td['prompt_tokens']))}%"
            if td["prompt_tokens"] > 0
            else "0%"
        )
        lines.append("🤖 AI 审核汇报")
        lines.append("━━━━━━━━━━━━━━")
        if engine.llm.is_configured:
            lines.append(f"• 模型：{engine.llm.model} | 接口：{sanitize_url_for_display(engine.llm.base_url)}")
            lines.append(f"• 识图：{'✅ 支持多模态' if engine.llm.vision_supported else '⚠️ 纯文本模式'}")
        else:
            lines.append("• 当前状态：未配置 API Key（基础硬防模式）")
        lines.append(f"• 今日审核：{td['ai_checks']} 次（识图 {td['vision_checks']} / 异常 {td['ai_errors']}）")
        lines.append(f"• 累计审核：{lt['ai_checks']} 次（识图 {lt['vision_checks']} / 异常 {lt['ai_errors']}）")
        lines.append(
            f"• 今日 Token：输入 {td['prompt_tokens']:,}（缓存 {hit_rate}）| 输出 {td['completion_tokens']:,}"
        )
        if ai_rows:
            lines.append("")
            lines.append("🧠 最近 AI 判定汇报（最新 8 条）：")
            for r in ai_rows:
                gname = r.get("chat_title") or str(r["chat_id"])
                lines.append(
                    f"• [{_fmt_t(r['created_at'])}] {gname[:14]} | {trigger_label(r['trigger_type'])} {r['score']}分"
                )
                lines.append(f"  👤 {str(r['display_name'])[:20]} | AI理由：{str(r['reason'])[:45]}")
        else:
            lines.append("\nℹ️ 暂无 AI 命中或疑似记录（正常聊天不写入审计表）。")
    else:
        enabled_n = sum(1 for g in groups if g["enabled"] and not g["dry_run"])
        dry_n = sum(1 for g in groups if g["enabled"] and g["dry_run"])
        paused_n = sum(1 for g in groups if not g["enabled"])
        lines.append("📊 AI-智能广告杀手 · 运行状态总览")
        lines.append("━━━━━━━━━━━━━━")
        lines.append(f"• 防护群组：共 {len(groups)} 个群（全自动 {enabled_n} / 观察 {dry_n} / 暂停 {paused_n}）")
        lines.append(f"• 累计杀广告：封禁 {lt['bans']} 条 | 灰区禁言复核 {lt['mutes']} 条")
        lines.append(f"• 今日战果：封禁 {td['bans']} | 禁言 {td['mutes']} | AI审 {td['ai_checks']}")
        lines.append(f"• 疑似记录：共 {suspect_total} 条（含灰区与 AI 轻度怀疑）")
        if engine.llm.is_configured:
            lines.append(f"• AI 引擎：✅ {engine.llm.model}")
        else:
            lines.append("• AI 引擎：⬜ 未配置（基础硬防运行中）")
        if groups:
            lines.append("")
            lines.append("📌 已接入群组：")
            for g in groups[:10]:
                mode = (
                    "全自动"
                    if (g["enabled"] and not g["dry_run"])
                    else ("观察" if g["enabled"] else "暂停")
                )
                title = g["chat_title"] or str(g["chat_id"])
                lines.append(
                    f"• {title[:18]} [{mode}] — 今日杀 {g['today_bans']} / 累计 {g['total_bans']}"
                )

    keyboard = InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    f"{'✓ ' if view == 'overview' else ''}📊 运行总览",
                    callback_data="stats:overview",
                ),
                InlineKeyboardButton(
                    f"{'✓ ' if view == 'kills' else ''}⚔️ 广告击杀明细",
                    callback_data="stats:kills",
                ),
            ],
            [
                InlineKeyboardButton(
                    f"{'✓ ' if view == 'suspects' else ''}🔎 疑似与待复核",
                    callback_data="stats:suspects",
                ),
                InlineKeyboardButton(
                    f"{'✓ ' if view == 'ai' else ''}🤖 AI 审核汇报",
                    callback_data="stats:ai",
                ),
            ],
            [InlineKeyboardButton("⬅️ 返回主菜单", callback_data="stats:back")],
        ]
    )
    return "\n".join(lines)[:3900], keyboard


def build_branding_view(
    engine: GuardEngine, *, bot_username: str = "", notice: str = ""
) -> tuple[str, InlineKeyboardMarkup]:
    """Build Owner-only private panel to set bot avatar, name, short & full descriptions."""
    lines = [
        "🛡 AI-智能广告杀手 · 机器人形象设置（热生效）",
        "",
    ]
    if bot_username:
        lines.append(f"• 机器人链接：https://t.me/{bot_username}")
    lines.extend(
        [
            f"• 官方默认名称：{DEFAULT_BOT_NAME}",
            f"• 官方简短简介：{DEFAULT_BOT_SHORT_DESC}",
            f"• 官方完整介绍：{DEFAULT_BOT_DESC}",
            "• 官方默认头像：AI-智能广告杀手图标 (assets/avatar.jpg)",
        ]
    )
    if notice:
        lines.extend(["", notice])
    lines.extend(
        [
            "",
            "💡 点击下方第一个按钮即可一键换上AI-智能广告杀手头像、名称与简介，也可单项自定义：",
        ]
    )
    rows: list[list[InlineKeyboardButton]] = [
        [InlineKeyboardButton("🛡 一键套用AI-智能广告杀手头像 + 名称 + 简介", callback_data="brand:apply_all")],
        [
            InlineKeyboardButton("🖼 仅换AI-智能广告杀手头像", callback_data="brand:apply_avatar"),
            InlineKeyboardButton("📷 上传自定义头像", callback_data="brand:ask:avatar"),
        ],
        [
            InlineKeyboardButton("✏️ 自定义名称", callback_data="brand:ask:name"),
            InlineKeyboardButton("📝 自定义简介", callback_data="brand:ask:short_desc"),
        ],
        [InlineKeyboardButton("📄 自定义完整介绍（/start 前展示）", callback_data="brand:ask:desc")],
        [InlineKeyboardButton("⬅️ 返回主菜单", callback_data="brand:back")],
    ]
    return "\n".join(lines), InlineKeyboardMarkup(rows)


def build_ai_config_view(
    engine: GuardEngine, *, notice: str = ""
) -> tuple[str, InlineKeyboardMarkup]:
    """Build Owner-only private AI configuration panel (presets + guided input + live probe)."""
    status_line = (
        "✅ 已启用 AI 语义引擎"
        if engine.llm.is_configured
        else "🛡 纯本地基础防护模式（未填写 API Key）"
    )
    lines = [
        "🤖 AI-智能广告杀手 · AI 引擎配置（热生效，无需重启）",
        "",
        f"• 当前状态：{status_line}",
        f"• 接口地址：{sanitize_url_for_display(engine.llm.base_url)}",
        f"• 模型名称：{engine.llm.model or '(未设置)'}",
        f"• API Key：{mask_api_key(engine.llm.api_key)}",
        f"• 识图探测：{engine.llm.vision_note}",
    ]
    if notice:
        lines.extend(["", notice])
    elif engine.active_ai_warning:
        lines.extend(["", engine.active_ai_warning])
    lines.extend(
        [
            "",
            "💡 快速配置：点一家厂商预设（或自定义地址/模型），再点「🔑 填写 API Key」发给我即可！",
        ]
    )

    rows: list[list[InlineKeyboardButton]] = [
        [
            InlineKeyboardButton("🐳 DeepSeek", callback_data="aiconf:preset:deepseek"),
            InlineKeyboardButton("🟢 OpenAI", callback_data="aiconf:preset:openai"),
        ],
        [
            InlineKeyboardButton("✨ Gemini", callback_data="aiconf:preset:gemini"),
            InlineKeyboardButton("🌐 OpenRouter", callback_data="aiconf:preset:openrouter"),
        ],
        [InlineKeyboardButton("🔑 填写 / 更换 API Key", callback_data="aiconf:ask:api_key")],
        [
            InlineKeyboardButton("✏️ 自定义模型名", callback_data="aiconf:ask:model"),
            InlineKeyboardButton("🔗 自定义接口地址", callback_data="aiconf:ask:base_url"),
        ],
        [
            InlineKeyboardButton("🧪 测试连通 & 识图", callback_data="aiconf:test"),
            InlineKeyboardButton("🧹 清除 Key（纯本地）", callback_data="aiconf:clear_key"),
        ],
    ]
    if engine.storage.get_meta("ai_config_override") == "1" and engine.cfg.ai_api_key:
        rows.append(
            [InlineKeyboardButton("↩️ 恢复服务器 .env 默认", callback_data="aiconf:reset_env")]
        )
    rows.append([InlineKeyboardButton("⬅️ 返回主菜单", callback_data="aiconf:back")])
    return "\n".join(lines), InlineKeyboardMarkup(rows)


def build_panel_view(engine: GuardEngine, gs: GroupSettings) -> tuple[str, InlineKeyboardMarkup]:
    m = engine.storage.get_today_metrics(gs.chat_id)
    trusted = engine.storage.trusted_count(gs.chat_id)
    now = time.time()

    if not gs.enabled:
        mode_str = "⏸ 已暂停"
    elif gs.dry_run:
        mode_str = "👀 观察模式（只告警不封禁）"
    else:
        mode_str = "🛡 全自动秒封"

    if not engine.llm.is_configured:
        model_line = (
            "未配置（基础硬防 + 本地关键词规则）"
            if gs.local_rules_enabled
            else "未配置（仅基础硬防；本地关键词默认关，配 AI 启语义审）"
        )
        vision_status = "ℹ️ 未配置大模型（填 AI_API_KEY 即可解锁 AI 语义与识图）"
        vision_btn = "🖼 识图：需配置大模型"
    elif engine.llm.vision_supported:
        model_line = f"{engine.llm.model}（本地关键词：{'开' if gs.local_rules_enabled else '关'}）"
        vision_status = "✅ 已开启（模型支持多模态）" if gs.vision_enabled else "⏸ 已手动关闭（模型支持）"
        vision_btn = f"🖼 图片/贴纸识图：{'开启' if gs.vision_enabled else '关闭'}"
    else:
        model_line = f"{engine.llm.model}（本地关键词：{'开' if gs.local_rules_enabled else '关'}）"
        vision_status = "⚠️ 当前模型不支持多模态（已自动降级为纯文本+伪装解析）"
        vision_btn = "🖼 识图：模型不支持（点此重检）"

    raid_rem = int(max(0, gs.antiraid_until - now) // 60)
    raid_btn = f"🚨 反炸群：剩余{raid_rem}分（点关）" if raid_rem > 0 else "🚨 一键反炸群 (1h)"

    log_status = f"已绑定 ({gs.log_chat_id})" if gs.log_chat_id else "默认发给超级管理员"
    topic_line = gs.group_topic or "未设置（默认通用反垃圾规则）"

    tok_line = (
        f"输入 {m['prompt_tokens']:,}（缓存命中 {m['cached_tokens']:,}）| 输出 {m['completion_tokens']:,}"
    )
    err_note = f" | AI异常 {m['ai_errors']}" if m.get("ai_errors") else ""

    text = (
        f"🛡 {__app_name_cn__} v{__version__} 管理面板\n"
        f"📌 群组：{gs.chat_title or gs.chat_id}\n"
        f"━━━━━━━━━━━━━━\n"
        f"• 运行状态：{mode_str}\n"
        f"• 当前引擎：{model_line}\n"
        f"• 多模态识图：{vision_status}\n"
        f"• 封禁阈值：{gs.spam_score} 分 | 灰区禁言：{'开' if gs.gray_zone_mute else '关'} | 白名单：{trusted} 人\n"
        f"• 群主题：{topic_line}\n"
        f"• 审计日志：{log_status}\n"
        f"• 今日战果：AI审 {m['ai_checks']}（识图 {m['vision_checks']}{err_note}）| 封禁 {m['bans']}（CAS {m['cas_bans']}/团伙复核 {m['swarm_bans']}）| 灰区禁言 {m['mutes']}\n"
        f"• 今日 Token：{tok_line}\n"
        f"━━━━━━━━━━━━━━\n"
        f"点击下方按钮实时生效，无需重启服务器："
    )

    cid = gs.chat_id
    keyboard = InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    f"🛡 模式：{'暂停' if not gs.enabled else ('观察' if gs.dry_run else '全自动封禁')}",
                    callback_data=f"cfg:mode:{cid}",
                ),
                InlineKeyboardButton(
                    f"🎯 阈值：{gs.spam_score}分",
                    callback_data=f"cfg:score:{cid}",
                ),
            ],
            [
                InlineKeyboardButton(vision_btn, callback_data=f"cfg:vision:{cid}"),
            ],
            [
                InlineKeyboardButton(
                    f"⚖️ 灰区禁言复核：{'开' if gs.gray_zone_mute else '关'}",
                    callback_data=f"cfg:gray:{cid}",
                ),
                InlineKeyboardButton(
                    f"🌐 CAS黑库：{'开' if gs.cas_enabled else '关'}",
                    callback_data=f"cfg:cas:{cid}",
                ),
            ],
            [
                InlineKeyboardButton(
                    f"🍊 简易入群验证：{'开' if gs.join_captcha else '关'}",
                    callback_data=f"cfg:captcha:{cid}",
                ),
                InlineKeyboardButton(raid_btn, callback_data=f"cfg:antiraid:{cid}"),
            ],
            [
                InlineKeyboardButton(
                    f"⚡ 限流防刷屏：{'开' if gs.anti_flood else '关'}",
                    callback_data=f"cfg:flood:{cid}",
                ),
                InlineKeyboardButton(
                    f"👥 团伙复读联动：{'AI核验' if gs.swarm_guard else '关'}",
                    callback_data=f"cfg:swarm:{cid}",
                ),
            ],
            [
                InlineKeyboardButton(
                    f"✏️ 盯编辑消息：{'开' if gs.check_edited else '关'}",
                    callback_data=f"cfg:edited:{cid}",
                ),
                InlineKeyboardButton(
                    f"🦠 拦木马安装包：{'开' if gs.block_malware_files else '关'}",
                    callback_data=f"cfg:malware:{cid}",
                ),
            ],
            [
                InlineKeyboardButton(
                    f"🧩 外联卡片：{_VIA_LABELS.get(gs.via_bot_mode, gs.via_bot_mode)}",
                    callback_data=f"cfg:viabot:{cid}",
                ),
            ],
            [
                InlineKeyboardButton(
                    f"🧹 清进退群提示：{'开' if gs.clean_service_msgs else '关'}",
                    callback_data=f"cfg:service:{cid}",
                ),
                InlineKeyboardButton(
                    (
                        f"📢 封禁播报：开({format_delete_short(gs.announce_delete_seconds)}) ▸"
                        if gs.announce_in_group
                        else "📢 封禁播报：关 ▸"
                    ),
                    callback_data=f"cfg:announce_menu:{cid}",
                ),
            ],
            [
                InlineKeyboardButton(
                    f"📝 本地关键词规则：{'开' if gs.local_rules_enabled else '关(交AI)'}",
                    callback_data=f"cfg:localrules:{cid}",
                ),
                InlineKeyboardButton(
                    "🛡 豁免 / 绕过规则 ▸",
                    callback_data=f"cfg:exempts:{cid}",
                ),
            ],
            [
                InlineKeyboardButton(
                    "📬 绑定日志到我私聊",
                    callback_data=f"cfg:bindlog:{cid}",
                ),
                InlineKeyboardButton("🔄 重新探测多模态", callback_data=f"cfg:reprobe:{cid}"),
            ],
            [
                InlineKeyboardButton("🗑 关闭面板", callback_data=f"cfg:close:{cid}"),
            ],
        ]
    )
    return text, keyboard


def build_exempts_view(engine: GuardEngine, gs: GroupSettings) -> tuple[str, InlineKeyboardMarkup]:
    """Build per-group interactive GUI subpanel for all moderation exemptions & bypass rules."""
    cid = gs.chat_id
    ext_label = _EXT_CH_LABELS.get(gs.external_channel_mode, "正常审核")
    review_scope = "仅审首条" if gs.first_message_only else "持续审核"

    def _onoff(flag: bool, on_txt: str = "✅ 豁免", off_txt: str = "⬜ 照常审核") -> str:
        return on_txt if flag else off_txt

    text = (
        f"🛡 豁免与绕过规则 — {gs.chat_title or cid}\n"
        f"━━━━━━━━━━━━━━\n"
        f"点击下方按钮实时开关，按需控制哪些身份/场景可绕过拦截：\n\n"
        f"• 👮 群主/管理员：{_onoff(gs.exempt_admins)}（想用自己号测拦截可临时关）\n"
        f"• 🎭 匿名管理员：{_onoff(gs.exempt_anon_admin)}\n"
        f"• 📡 本群关联频道：{_onoff(gs.exempt_linked_channel)}\n"
        f"• 🤝 白名单(/trust)：{_onoff(gs.exempt_trusted)}\n"
        f"• 👑 全局超管免检：{_onoff(gs.exempt_owners, '✅ 跨群免检', '⬜ 关闭（按群管理判定）')}\n"
        f"• 📣 外部频道马甲：{ext_label}\n"
        f"• 👤 成员与频道语义审核：{review_scope}（后续仍检查刷屏和危险文件）\n"
        f"• 👴 持续审核时老群友短句免AI：{_onoff(gs.exempt_veteran_short, '✅ 开启', '⬜ 关闭')}\n"
        f"• 💬 回复免缓存秒封：{_onoff(gs.exempt_reply_cache, '✅ 开启（逐人复核）', '⬜ 关闭（允许缓存秒封）')}\n"
        f"• 🛡 查管理超时防误删：{_onoff(gs.admin_cache_fallback, '✅ 开启（30分钟兜底）', '⬜ 关闭（严格实时）')}\n"
        f"━━━━━━━━━━━━━━\n"
        f"注：即使关闭「群主/管理员豁免」，Telegram 底层仍禁止封禁管理员，仅触发日志与删消息，方便实测。"
    )
    keyboard = InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    f"👮 管理员豁免：{'开' if gs.exempt_admins else '关'}",
                    callback_data=f"cfg:ex_admins:{cid}",
                ),
                InlineKeyboardButton(
                    f"🎭 匿名管理：{'开' if gs.exempt_anon_admin else '关'}",
                    callback_data=f"cfg:ex_anon:{cid}",
                ),
            ],
            [
                InlineKeyboardButton(
                    f"📡 关联频道：{'开' if gs.exempt_linked_channel else '关'}",
                    callback_data=f"cfg:ex_linked:{cid}",
                ),
                InlineKeyboardButton(
                    f"🤝 白名单豁免：{'开' if gs.exempt_trusted else '关'}",
                    callback_data=f"cfg:ex_trusted:{cid}",
                ),
            ],
            [
                InlineKeyboardButton(
                    f"👑 超管免检：{'开' if gs.exempt_owners else '关'}",
                    callback_data=f"cfg:ex_owners:{cid}",
                ),
                InlineKeyboardButton(
                    f"📣 外部频道：{ext_label}",
                    callback_data=f"cfg:ex_extch:{cid}",
                ),
            ],
            [
                InlineKeyboardButton(
                    f"👤 成员与频道：{review_scope}",
                    callback_data=f"cfg:ex_first_msg:{cid}",
                ),
            ],
            [
                InlineKeyboardButton(
                    f"👴 老群友短句免AI：{'开' if gs.exempt_veteran_short else '关'}",
                    callback_data=f"cfg:ex_short:{cid}",
                ),
                InlineKeyboardButton(
                    f"💬 回复免缓存：{'开' if gs.exempt_reply_cache else '关'}",
                    callback_data=f"cfg:ex_reply:{cid}",
                ),
            ],
            [
                InlineKeyboardButton(
                    f"🛡 查管理超时防误删兜底：{'开' if gs.admin_cache_fallback else '关'}",
                    callback_data=f"cfg:ex_fallback:{cid}",
                ),
            ],
            [
                InlineKeyboardButton("⬅️ 返回主面板", callback_data=f"cfg:open:{cid}"),
                InlineKeyboardButton("🗑 关闭面板", callback_data=f"cfg:close:{cid}"),
            ],
        ]
    )
    return text, keyboard


def build_announce_view(
    engine: GuardEngine, gs: GroupSettings, *, notice: str = ""
) -> tuple[str, InlineKeyboardMarkup]:
    """Build per-group interactive GUI subpanel for customizable ban notice & auto-delete timer."""
    cid = gs.chat_id
    cur_del = max(0, int(gs.announce_delete_seconds))
    is_custom_tpl = bool((gs.announce_template or "").strip())
    tpl_display = (gs.announce_template or "").strip() or DEFAULT_ANNOUNCE_TEMPLATE

    lines = [
        f"📢 群内封禁播报设置 — {gs.chat_title or cid}",
        "━━━━━━━━━━━━━━",
        f"• 群内播报：{'✅ 开启（封禁成功后在群内提醒）' if gs.announce_in_group else '⬜ 关闭（静默封禁，仅发审计日志）'}",
        f"• 自动删除：{'⏱ ' + format_delete_delay(cur_del) + '后自动删除' if cur_del > 0 else '📌 不自动删除（永久保留）'}",
        f"• 当前模板（{'自定义' if is_custom_tpl else '默认'}）：",
        tpl_display[:500],
        "━━━━━━━━━━━━━━",
        "可用变量：{user} 被封用户 | {user_id} 用户ID | {reason} 封禁理由 | {duration} 封禁时长 | {auto_delete} 自动删除提示",
    ]
    if notice:
        lines.extend(["", notice])

    def _mark(sec: int, label: str) -> str:
        return f"✓ {label}" if cur_del == sec else label

    keyboard = InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    f"📢 群内播报：{'✅ 开' if gs.announce_in_group else '⬜ 关'}",
                    callback_data=f"cfg:an_toggle:{cid}",
                ),
                InlineKeyboardButton(
                    f"🗑 自动删除：{'✅ 开' if cur_del > 0 else '⬜ 不删'}",
                    callback_data=f"cfg:an_deltoggle:{cid}",
                ),
            ],
            [
                InlineKeyboardButton(_mark(60, "1分钟"), callback_data=f"cfg:an_del60:{cid}"),
                InlineKeyboardButton(_mark(300, "5分钟"), callback_data=f"cfg:an_del300:{cid}"),
                InlineKeyboardButton(_mark(1800, "30分钟"), callback_data=f"cfg:an_del1800:{cid}"),
                InlineKeyboardButton(_mark(3600, "1小时"), callback_data=f"cfg:an_del3600:{cid}"),
            ],
            [
                InlineKeyboardButton("⌨️ 自定义删除时间", callback_data=f"cfg:an_ask_delay:{cid}"),
                InlineKeyboardButton(
                    _mark(0, "📌 永久保留(不删)"), callback_data=f"cfg:an_del0:{cid}"
                ),
            ],
            [
                InlineKeyboardButton("✏️ 自定义播报文案", callback_data=f"cfg:an_ask_tpl:{cid}"),
                InlineKeyboardButton("↩️ 恢复默认文案", callback_data=f"cfg:an_reset_tpl:{cid}"),
            ],
            [
                InlineKeyboardButton("👀 预览播报效果", callback_data=f"cfg:an_preview:{cid}"),
            ],
            [
                InlineKeyboardButton("⬅️ 返回主面板", callback_data=f"cfg:open:{cid}"),
                InlineKeyboardButton("🗑 关闭面板", callback_data=f"cfg:close:{cid}"),
            ],
        ]
    )
    return "\n".join(lines), keyboard


async def cmd_claim(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Private /claim <code>: securely binds deployer as owner using server-log one-time code."""
    engine: GuardEngine = context.application.bot_data["engine"]
    msg = update.message
    user = update.effective_user
    if not msg or not user or msg.chat.type != ChatType.PRIVATE:
        return
    code = " ".join(context.args or []).strip()
    if not code or not engine.claim_code or engine.is_claim_locked_for(user.id):
        # Silent O(1) drop when empty, inactive, or this user already exhausted failed attempts
        return
    if not secrets.compare_digest(code, engine.claim_code) and not engine.allow_dm_reply(user.id):
        return
    ok, feedback = engine.try_claim_owner(user.id, code)
    if ok:
        feedback += "\n\n现在发送 /start 即可点按钮配置 AI 接口与群防护！"
    await msg.reply_text(feedback)


async def cmd_start_private(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Private /start: full dashboard for owners; minimal 2-line neutral reply (rate-limited) for others."""
    engine: GuardEngine = context.application.bot_data["engine"]
    msg = update.message
    user = update.effective_user
    if not msg or not user:
        return

    # Non-owners (including before owner is bound): rate-limited minimal 2-line reply.
    # Reveals ZERO internal state (no model name, no vision status, no unbound/claim hint).
    if not engine.is_owner(user.id):
        if not engine.allow_dm_reply(user.id):
            return
        await msg.reply_text(
            f"🛡 {__app_name_cn__}\n"
            f"你的用户 ID：{user.id}"
        )
        return

    engine.clear_owner_input_state(user.id)
    bot_uname = getattr(getattr(context, "bot", None), "username", "") or ""
    text, markup = build_start_dashboard(engine, user.id, bot_username=bot_uname)
    await msg.reply_text(text, reply_markup=markup)


async def cmd_start_group(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show the group setup guide to verified administrators."""
    engine: GuardEngine = context.application.bot_data["engine"]
    msg = update.message
    user = update.effective_user
    if not msg or (not user and not getattr(msg, "sender_chat", None)):
        return
    if msg.chat.type not in (ChatType.GROUP, ChatType.SUPERGROUP):
        return
    if not engine.is_group_allowed(msg.chat.id):
        return
    if not await engine.check_message_admin_perm(
        context.bot, msg, user=user, require_restrict=True, allow_readonly_sender_chat=True
    ):
        return

    engine.mark_command_handled(msg.chat.id, msg.message_id)
    gs = engine.get_group_settings(msg.chat.id, msg.chat.title or "")
    bot_uname = getattr(getattr(context, "bot", None), "username", "") or ""
    dm_hint = (
        f"私聊 https://t.me/{bot_uname} 发送 /start"
        if bot_uname
        else "私聊机器人发送 /start"
    )
    text = (
        f"🛡 {__app_name_cn__} 正在守护本群！\n\n"
        f"• 群内设置：发送 /config 或点击下方按钮打开可视化面板\n"
        f"• 全局战报 / 改 AI Key / 换头像：{dm_hint}\n"
        f"• 常用群指令：/config、/settopic、/antiraid、/trust、/sban、/spam\n"
        f"（本提示 30 秒后自动清理）"
    )
    buttons: list[list[InlineKeyboardButton]] = [
        [InlineKeyboardButton("⚙️ 打开本群管理面板", callback_data=f"cfg:open:{gs.chat_id}")]
    ]
    if bot_uname:
        buttons.append(
            [InlineKeyboardButton("🤖 前往私聊主控台", url=f"https://t.me/{bot_uname}?start=panel")]
        )
    sent = await msg.reply_text(text, reply_markup=InlineKeyboardMarkup(buttons))
    sent_mid = getattr(sent, "message_id", None)
    if isinstance(sent_mid, int):
        asyncio.create_task(_delete_later(context.bot, msg.chat.id, sent_mid, 30))


async def _process_admin_config_input(
    update: Update, context: ContextTypes.DEFAULT_TYPE, *, override_uid: Optional[int] = None
) -> bool:
    """Process guided text input for per-group GUI settings (works in group, anonymous admin, & private DM)."""
    engine: GuardEngine = context.application.bot_data["engine"]
    msg = update.message
    user = update.effective_user
    actor_uid = override_uid if override_uid is not None else (user.id if user else None)
    if not msg or actor_uid is None:
        return False

    if (msg.chat.id, actor_uid) not in engine.pending_admin_input:
        return False

    pending = engine.pop_admin_input_state(msg.chat.id, actor_uid)
    if not pending:
        return False

    target_cid = pending.target_group_id
    if not engine.is_group_allowed(target_cid):
        return True
    if not await engine.check_admin_perm(
        context.bot, target_cid, actor_uid, require_restrict=True, fresh=True
    ):
        return True

    is_group_chat = msg.chat.type in (ChatType.GROUP, ChatType.SUPERGROUP)
    if is_group_chat:
        # Exempt authorized admin config input from Group 1 moderation
        engine.mark_command_handled(msg.chat.id, msg.message_id)

    gs = engine.get_group_settings(target_cid)
    raw_text = (msg.text or "").strip()
    cancel_markup = InlineKeyboardMarkup(
        [[InlineKeyboardButton("❌ 取消输入", callback_data=f"cfg:an_cancel:{target_cid}")]]
    )

    notice = ""
    if pending.field_name == "announce_template":
        if raw_text.lower() in {"默认", "恢复默认", "reset", "default"}:
            gs.announce_template = ""
            engine.storage.save_group(gs)
            notice = "✅ 已恢复默认封禁播报文案！"
        elif not raw_text or len(raw_text) > ANNOUNCE_MAX_TEMPLATE_LEN:
            engine.set_admin_input_state(
                msg.chat.id, actor_uid, target_cid, "announce_template", pending.panel_msg_id
            )
            sent_err = await msg.reply_text(
                f"⚠️ 播报文案不能为空，且长度需在 {ANNOUNCE_MAX_TEMPLATE_LEN} 字以内。请重新发送（发送「默认」可恢复默认文案）：",
                reply_markup=cancel_markup,
            )
            if is_group_chat:
                sent_mid = getattr(sent_err, "message_id", None)
                if isinstance(sent_mid, int):
                    asyncio.create_task(_delete_later(context.bot, msg.chat.id, sent_mid, 20))
            return True
        else:
            gs.announce_template = raw_text
            engine.storage.save_group(gs)
            notice = "✅ 已保存自定义封禁播报文案！"
    elif pending.field_name == "announce_delete_seconds":
        parsed = parse_delete_delay_input(raw_text)
        if parsed is None:
            engine.set_admin_input_state(
                msg.chat.id, actor_uid, target_cid, "announce_delete_seconds", pending.panel_msg_id
            )
            sent_err = await msg.reply_text(
                "⚠️ 时间格式无效！请发送 10秒 ~ 24小时 的时间（纯数字按分钟计，如 30、45s、15m、2h；发送 0 或「不删」表示永久保留）：",
                reply_markup=cancel_markup,
            )
            if is_group_chat:
                sent_mid = getattr(sent_err, "message_id", None)
                if isinstance(sent_mid, int):
                    asyncio.create_task(_delete_later(context.bot, msg.chat.id, sent_mid, 20))
            return True
        gs.announce_delete_seconds = parsed
        engine.storage.save_group(gs)
        notice = f"✅ 自动删除时间已更新为：{format_delete_delay(parsed)}"
    else:
        return True

    text, markup = build_announce_view(engine, gs, notice=notice)
    edited = False
    if pending.panel_msg_id and hasattr(context.bot, "edit_message_text"):
        try:
            await context.bot.edit_message_text(
                chat_id=pending.panel_chat_id,
                message_id=pending.panel_msg_id,
                text=text,
                reply_markup=markup,
            )
            edited = True
        except TelegramError:
            pass
    if not edited:
        await msg.reply_text(text, reply_markup=markup)
    elif is_group_chat:
        # Keep the group chat tidy after saving the admin's input message
        asyncio.create_task(_delete_later(context.bot, msg.chat.id, msg.message_id, 3))
    return True


async def handle_group_admin_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Group-chat O(1) handler for guided admin GUI text input (supports anonymous admins too!)."""
    msg = update.message
    user = update.effective_user
    if not msg or msg.chat.type not in (ChatType.GROUP, ChatType.SUPERGROUP):
        return
    engine: GuardEngine = context.application.bot_data["engine"]
    if user and (msg.chat.id, user.id) in engine.pending_admin_input:
        await _process_admin_config_input(update, context)
        return
    # Support Anonymous Group Admins replying to a GUI input prompt they triggered by button click!
    sender_chat = getattr(msg, "sender_chat", None)
    if sender_chat and sender_chat.id == msg.chat.id and engine.pending_admin_input:
        anon_uid = await engine.resolve_anon_admin_input_uid(context.bot, msg.chat.id)
        if anon_uid is not None:
            await _process_admin_config_input(update, context, override_uid=anon_uid)


async def _diagnose_forwarded_sample(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Owner-only private DM diagnostic: inspect, AI-test, and archive any forwarded spam sample."""
    engine: GuardEngine = context.application.bot_data["engine"]
    msg = update.message
    user = update.effective_user
    if not msg or not user:
        return

    origin = getattr(msg, "forward_origin", None)
    origin_user = getattr(origin, "sender_user", None) if origin else None
    origin_uid: Optional[int] = getattr(origin_user, "id", None) if origin_user else None

    # Reconstruct original sender profile as faithfully as Telegram allows
    if origin_user is not None:
        orig_profile = await engine.get_profile(context.bot, origin_user)
    elif origin and getattr(origin, "sender_user_name", None):
        orig_profile = {
            "full_name": str(origin.sender_user_name),
            "username": "(转发隐私隐藏)",
            "bio": "",
            "personal_channel": "",
            "personal_channel_bio": "",
            "has_photo": None,
        }
    else:
        och = (getattr(origin, "chat", None) or getattr(origin, "sender_chat", None)) if origin else None
        orig_profile = {
            "full_name": (getattr(och, "title", "") or "") if och else "",
            "username": f"@{och.username}" if (och and getattr(och, "username", None)) else "(无)",
            "bio": "",
            "personal_channel": "",
            "personal_channel_bio": "",
            "has_photo": None,
        }

    xray = extract_xray(msg, is_edited=False)
    raw_payload = inspect_raw_message_fields(msg)
    want_vision = engine.llm.is_configured and engine.llm.vision_supported
    image_data_url = await extract_image_data_url(context.bot, msg) if want_vision else None

    summary = xray.format_for_ai(
        profile=orig_profile,
        recent_context=[],
        user_fragments=[],
        clean_count=0,
        vision_attached=bool(image_data_url),
    )
    profile_flags, profile_boost, _ = analyze_profile_risk(orig_profile, clean_count=0)
    has_promo_profile = any(("隔断混淆" in f or "引流" in f) for f in profile_flags)

    raw_score = -1
    eff_score = -1
    ai_reason = "未配置 AI 模型（仅保存原始透视样本）"
    used_vision = False
    if engine.llm.is_configured:
        try:
            verdict = await engine.llm.classify(
                summary_text=summary,
                group_topic="",
                image_data_url=image_data_url,
                allow_vision=True,
            )
            raw_score = verdict.score
            eff_score = raw_score
            min_ai = 35 if has_promo_profile else 45
            if profile_boost > 0 and raw_score >= min_ai:
                eff_score = min(100, raw_score + profile_boost)
            ai_reason = verdict.reason or "(无)"
            used_vision = verdict.used_vision
        except Exception as exc:
            ai_reason = f"AI 试跑异常: {type(exc).__name__}"

    origin_desc = xray.forward_from or str(getattr(origin, "type", "forwarded"))
    sample_id = engine.storage.save_forwarded_sample(
        owner_id=user.id,
        origin_desc=origin_desc,
        origin_user_id=origin_uid,
        origin_profile=orig_profile,
        media_type=xray.media_type or "",
        raw_payload=raw_payload,
        xray_summary=summary,
        vision_attached=bool(image_data_url),
        ai_score=eff_score,
        ai_reason=ai_reason,
    )

    score_line = (
        f"• AI 实测得分：{eff_score} 分（原始 {raw_score} + 画像加权 {max(0, eff_score - raw_score)}）"
        if raw_score >= 0
        else "• AI 实测得分：未评分"
    )
    flags_line = "、".join(profile_flags) if profile_flags else "无"
    media_line = xray.media_type or ("特殊载体: " + xray.special_payload if xray.special_payload else "纯文本/无媒体")
    vis_line = (
        "已提取图片并送审视觉"
        if used_vision
        else ("已提取图片" if image_data_url else "无可用视觉图/缩略图")
    )
    reply = (
        f"🔬 [AI-智能广告杀手样本诊断 #{sample_id}]\n"
        f"• 转发来源：{origin_desc}\n"
        f"• 原始载体：{media_line} | 视觉：{vis_line}\n"
        f"• 透视摘要：{xray.build_preview()[:260]}\n"
        f"• 还原资料：昵称={orig_profile.get('full_name') or '(隐藏)'}"
        f"{' | Bio=' + orig_profile['bio'][:80] if orig_profile.get('bio') else ''}"
        f"{' | 频道=' + orig_profile['personal_channel'][:80] if orig_profile.get('personal_channel') else ''}\n"
        f"• 画像信号：{flags_line}\n"
        f"{score_line}\n"
        f"• AI 判定理由：{ai_reason}\n\n"
        f"✅ 完整 Bot API 原始结构与透视快照已存档（样本 #{sample_id}），可直接在服务器查看分析！"
    )
    await msg.reply_text(reply)


async def handle_private_owner_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles guided private-chat input for Owner AI config, DM group-panel inputs, and forwarded spam diagnostics."""
    engine: GuardEngine = context.application.bot_data["engine"]
    msg = update.message
    user = update.effective_user
    if not msg or not user or msg.chat.type != ChatType.PRIVATE:
        return

    field_name = engine.pop_owner_input_state(user.id) if engine.is_owner(user.id) else None
    if not field_name:
        handled_cfg = await _process_admin_config_input(update, context)
        if not handled_cfg and engine.is_owner(user.id) and getattr(msg, "forward_origin", None) is not None:
            await _diagnose_forwarded_sample(update, context)
        return

    raw_text = (msg.text or "").strip()
    cancel_markup = InlineKeyboardMarkup(
        [[InlineKeyboardButton("❌ 取消输入", callback_data="aiconf:cancel")]]
    )

    if field_name == "api_key":
        # Best-effort cleanup of the plaintext secret message (Telegram may restrict deleting user DMs)
        try:
            await msg.delete()
        except TelegramError:
            pass
        val = _validate_api_key(raw_text)
        if not val:
            engine.set_owner_input_state(user.id, "api_key")
            await msg.reply_text(
                "⚠️ API Key 格式无效（不能包含空格或换行，且长度需在 300 字符以内）。请重新发送：",
                reply_markup=cancel_markup,
            )
            return
        await engine.update_ai_config(api_key=val)
        report = await engine.llm.probe_capabilities()
        notice = (
            f"✅ API Key 已保存并热加载（{mask_api_key(val)}）\n"
            f"• 文本连通：{'✅ ' + report.text_detail if report.text_ok else '❌ ' + report.text_detail}\n"
            f"• 识图能力：{'✅ 已自动开启' if report.vision_supported else '⚠️ ' + report.vision_detail}\n"
            f"🔒 安全提示：建议顺手手动删掉你刚才发送的那条 API Key 消息。"
        )
        text, markup = build_ai_config_view(engine, notice=notice)
        await msg.reply_text(text, reply_markup=markup)
        return

    if field_name == "base_url":
        val = _validate_base_url(raw_text)
        if not val:
            engine.set_owner_input_state(user.id, "base_url")
            await msg.reply_text(
                "⚠️ 接口地址无效！远程接口必须使用 https://（防凭据明文泄露）；"
                "仅本机回环地址（localhost / 127.0.0.1 / ::1 / host.docker.internal）允许 http://。\n"
                "请重新发送，例如 https://api.deepseek.com/v1：",
                reply_markup=cancel_markup,
            )
            return
        key_cleared = await engine.update_ai_config(base_url=val)
        notice = f"✅ 接口地址已更新为：{sanitize_url_for_display(val)}"
        if key_cleared:
            notice += (
                "\n🔒 检测到接口主机已变更，已自动清空旧 API Key（防止将旧密钥发往新主机）。\n"
                "👉 请点击下方「🔑 填写 / 更换 API Key」填写新接口密钥后再探测！"
            )
        elif engine.llm.is_configured:
            report = await engine.llm.probe_capabilities()
            notice += (
                f"\n• 文本连通：{'✅ 正常' if report.text_ok else '❌ ' + report.text_detail}"
                f"\n• 识图能力：{'✅ 支持' if report.vision_supported else '⚠️ 纯文本模式'}"
            )
        text, markup = build_ai_config_view(engine, notice=notice)
        await msg.reply_text(text, reply_markup=markup)
        return

    if field_name == "model":
        val = _validate_model_name(raw_text)
        if not val:
            engine.set_owner_input_state(user.id, "model")
            await msg.reply_text(
                "⚠️ 模型名称格式无效（不能包含空格或换行，长度 <= 120）。请重新发送，例如 deepseek-flash：",
                reply_markup=cancel_markup,
            )
            return
        await engine.update_ai_config(model=val)
        notice = f"✅ 模型名称已更新为：{val}"
        if engine.llm.is_configured:
            report = await engine.llm.probe_capabilities()
            notice += (
                f"\n• 文本连通：{'✅ 正常' if report.text_ok else '❌ ' + report.text_detail}"
                f"\n• 识图能力：{'✅ 支持' if report.vision_supported else '⚠️ 纯文本模式'}"
            )
        text, markup = build_ai_config_view(engine, notice=notice)
        await msg.reply_text(text, reply_markup=markup)
        return

    bot_uname = getattr(getattr(context, "bot", None), "username", "") or ""
    brand_cancel = InlineKeyboardMarkup(
        [[InlineKeyboardButton("❌ 取消输入", callback_data="brand:cancel")]]
    )

    if field_name == "brand_name":
        if not raw_text or len(raw_text) > MAX_BOT_NAME_LEN:
            engine.set_owner_input_state(user.id, "brand_name")
            await msg.reply_text(
                f"⚠️ 机器人名称不能为空，且长度需在 {MAX_BOT_NAME_LEN} 字以内。请重新发送：",
                reply_markup=brand_cancel,
            )
            return
        ok, detail = await set_bot_name(engine.cfg.telegram_bot_token, raw_text)
        notice = f"✅ 机器人名称已更新为：{raw_text}" if ok else f"⚠️ 修改名称失败：{detail}"
        text, markup = build_branding_view(engine, bot_username=bot_uname, notice=notice)
        await msg.reply_text(text, reply_markup=markup)
        return

    if field_name == "brand_short_desc":
        if len(raw_text) > MAX_BOT_SHORT_DESC_LEN:
            engine.set_owner_input_state(user.id, "brand_short_desc")
            await msg.reply_text(
                f"⚠️ 简短简介长度不能超过 {MAX_BOT_SHORT_DESC_LEN} 字。请重新发送：",
                reply_markup=brand_cancel,
            )
            return
        ok, detail = await set_bot_short_description(engine.cfg.telegram_bot_token, raw_text)
        notice = "✅ 机器人简短简介已更新！" if ok else f"⚠️ 修改简介失败：{detail}"
        text, markup = build_branding_view(engine, bot_username=bot_uname, notice=notice)
        await msg.reply_text(text, reply_markup=markup)
        return

    if field_name == "brand_desc":
        if len(raw_text) > MAX_BOT_DESC_LEN:
            engine.set_owner_input_state(user.id, "brand_desc")
            await msg.reply_text(
                f"⚠️ 完整介绍长度不能超过 {MAX_BOT_DESC_LEN} 字。请重新发送：",
                reply_markup=brand_cancel,
            )
            return
        ok, detail = await set_bot_description(engine.cfg.telegram_bot_token, raw_text)
        notice = "✅ 机器人完整介绍已更新！" if ok else f"⚠️ 修改完整介绍失败：{detail}"
        text, markup = build_branding_view(engine, bot_username=bot_uname, notice=notice)
        await msg.reply_text(text, reply_markup=markup)
        return

    if field_name == "brand_avatar":
        photos = getattr(msg, "photo", None)
        if not photos:
            engine.set_owner_input_state(user.id, "brand_avatar")
            await msg.reply_text(
                "⚠️ 请直接发送一张图片（非文件附件）作为机器人新头像：",
                reply_markup=brand_cancel,
            )
            return
        try:
            tg_file = await photos[-1].get_file()
            raw_img = bytes(await tg_file.download_as_bytearray())
        except Exception:
            notice = "⚠️ 下载图片失败，请重试。"
            text, markup = build_branding_view(engine, bot_username=bot_uname, notice=notice)
            await msg.reply_text(text, reply_markup=markup)
            return
        jpeg_bytes = await transcode_avatar_jpeg(raw_img)
        if not jpeg_bytes:
            notice = "⚠️ 图片格式无效或体积过大（需 <= 5MB），请换一张图片重试。"
        else:
            ok, detail = await set_bot_profile_photo(engine.cfg.telegram_bot_token, jpeg_bytes)
            notice = "✅ 机器人头像已更换成功！" if ok else f"⚠️ 更换头像失败：{detail}"
        text, markup = build_branding_view(engine, bot_username=bot_uname, notice=notice)
        await msg.reply_text(text, reply_markup=markup)
        return


async def cmd_config(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    engine: GuardEngine = context.application.bot_data["engine"]
    msg = update.message
    user = update.effective_user
    if not msg or (not user and not getattr(msg, "sender_chat", None)):
        return

    if msg.chat.type == ChatType.PRIVATE:
        await cmd_start_private(update, context)
        return

    if not engine.is_group_allowed(msg.chat.id):
        return
    if not await engine.check_message_admin_perm(
        context.bot, msg, user=user, require_restrict=True, allow_readonly_sender_chat=True
    ):
        return

    engine.mark_command_handled(msg.chat.id, msg.message_id)
    gs = engine.get_group_settings(msg.chat.id, msg.chat.title or "")
    text, markup = build_panel_view(engine, gs)
    await msg.reply_text(text, reply_markup=markup)


async def cmd_antiraid(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    engine: GuardEngine = context.application.bot_data["engine"]
    msg = update.message
    user = update.effective_user
    if not msg or (not user and not getattr(msg, "sender_chat", None)):
        return
    if msg.chat.type not in (ChatType.GROUP, ChatType.SUPERGROUP):
        return
    if not engine.is_group_allowed(msg.chat.id):
        return
    if not await engine.check_message_admin_perm(context.bot, msg, user=user, require_restrict=True):
        return

    engine.mark_command_handled(msg.chat.id, msg.message_id)
    gs = engine.get_group_settings(msg.chat.id, msg.chat.title or "")
    arg = (context.args[0].lower() if context.args else "60").strip()
    if arg in {"off", "0", "stop", "关"}:
        gs.antiraid_until = 0.0
        engine.storage.save_group(gs)
        sent = await msg.reply_text("✅ 已关闭应急反炸群模式，恢复正常入群。")
    else:
        try:
            minutes = max(5, min(1440, int(arg)))
        except ValueError:
            minutes = 60
        gs.antiraid_until = time.time() + minutes * 60
        engine.storage.save_group(gs)
        sent = await msg.reply_text(
            f"🚨 已开启应急反炸群模式（持续 {minutes} 分钟）：期间新进群成员将自动静默限制，发 /antiraid off 可提前解除。"
        )
    asyncio.create_task(_delete_later(context.bot, msg.chat.id, sent.message_id, 20))


async def cmd_report_spam(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Community /spam or /report command: forwards snapshot to admin DM with 1-click ban."""
    engine: GuardEngine = context.application.bot_data["engine"]
    msg = update.message
    user = update.effective_user
    if not msg or (not user and not getattr(msg, "sender_chat", None)):
        return
    if msg.chat.type not in (ChatType.GROUP, ChatType.SUPERGROUP):
        return
    if not engine.is_group_allowed(msg.chat.id):
        return

    target = msg.reply_to_message
    if not target or (not target.from_user and not target.sender_chat):
        return

    # If a properly authorized admin (incl. anonymous group admin) uses /spam, execute /sban directly
    if await engine.check_message_admin_perm(
        context.bot, msg, user=user, require_delete=True, require_restrict=True
    ):
        await cmd_sban(update, context)
        return

    if not user or getattr(msg, "sender_chat", None):
        return

    # Only handle pure /spam or /report replies cleanly (if extra spam text attached, let group 1 audit it!)
    if context.args:
        return

    if not engine.check_and_inc_report_count(msg.chat.id, user.id, limit=5):
        return

    # Exempt command itself from moderation only after passing checks
    engine.mark_command_handled(msg.chat.id, msg.message_id)
    asyncio.create_task(_delete_later(context.bot, msg.chat.id, msg.message_id, 5))

    if target.from_user and await engine.is_group_admin(context.bot, msg.chat.id, target.from_user.id):
        return

    gs = engine.get_group_settings(msg.chat.id, msg.chat.title or "")
    log_chat = await engine.resolve_log_chat(context.bot, gs)
    if not log_chat:
        return

    xray = extract_xray(target, is_edited=False)
    preview = xray.build_preview()
    is_ch = bool(target.sender_chat and target.sender_chat.id != msg.chat.id)
    if is_ch and target.sender_chat:
        target_label = f"[频道马甲] {target.sender_chat.title or target.sender_chat.id}"
        cb = f"upbanch:{msg.chat.id}:{target.sender_chat.id}"
        btn_label = "🚫 确认广告：封禁此频道马甲"
    else:
        target_label = f"{target.from_user.full_name} ({target.from_user.id})"
        cb = f"rptban:{msg.chat.id}:{target.from_user.id}:{target.message_id}"
        btn_label = "🚫 确认广告：删消息并永久封禁"

    text = (
        f"📣 [群友举报疑似广告]\n"
        f"📌 群组：{msg.chat.title or msg.chat.id}\n"
        f"🙋 举报人：{user.full_name} ({user.id})\n"
        f"👤 被举报者：{target_label}\n"
        f"💬 消息摘要：{preview[:400]}"
    )
    keyboard = InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(btn_label, callback_data=cb),
                InlineKeyboardButton("忽略", callback_data="noop_confirm"),
            ]
        ]
    )
    try:
        await context.bot.send_message(log_chat, text, reply_markup=keyboard)
    except TelegramError:
        pass


async def cmd_settopic(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    engine: GuardEngine = context.application.bot_data["engine"]
    msg = update.message
    user = update.effective_user
    if not msg or (not user and not getattr(msg, "sender_chat", None)):
        return
    if msg.chat.type not in (ChatType.GROUP, ChatType.SUPERGROUP):
        return
    if not engine.is_group_allowed(msg.chat.id):
        return
    if not await engine.check_message_admin_perm(context.bot, msg, user=user, require_restrict=True):
        return

    engine.mark_command_handled(msg.chat.id, msg.message_id)
    topic = " ".join(context.args or []).strip()
    gs = engine.get_group_settings(msg.chat.id, msg.chat.title or "")
    if topic.lower() in {"clear", "reset", "无", "清空"}:
        gs.group_topic = ""
        engine.storage.save_group(gs)
        await msg.reply_text("✅ 已清空群主题，恢复使用默认通用反垃圾规则。")
        return
    if not topic:
        await msg.reply_text(
            f"当前群主题：{gs.group_topic or '未设置（默认通用规则）'}\n"
            "用法：/settopic <你的群主题>\n"
            "清空：/settopic clear"
        )
        return
    gs.group_topic = topic[:120]
    engine.storage.save_group(gs)
    await msg.reply_text(f"✅ 已设置本群主题为：「{gs.group_topic}」，AI 将结合主题减少误杀。")


async def cmd_trust(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    engine: GuardEngine = context.application.bot_data["engine"]
    msg = update.message
    user = update.effective_user
    if not msg or (not user and not getattr(msg, "sender_chat", None)):
        return
    if msg.chat.type not in (ChatType.GROUP, ChatType.SUPERGROUP):
        return
    if not engine.is_group_allowed(msg.chat.id):
        return
    if not await engine.check_message_admin_perm(context.bot, msg, user=user, require_restrict=True):
        return

    engine.mark_command_handled(msg.chat.id, msg.message_id)
    if not msg.reply_to_message or not msg.reply_to_message.from_user:
        await msg.reply_text("请回复老群友的一条消息再发送 /trust")
        return
    target = msg.reply_to_message.from_user
    engine.storage.trust_user(msg.chat.id, target.id, target.username or target.full_name)
    sent = await msg.reply_text(f"✅ 已将 {target.full_name} ({target.id}) 加入AI-智能广告杀手永久白名单。")
    asyncio.create_task(_delete_later(context.bot, msg.chat.id, sent.message_id, 10))
    asyncio.create_task(_delete_later(context.bot, msg.chat.id, msg.message_id, 10))


async def cmd_untrust(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    engine: GuardEngine = context.application.bot_data["engine"]
    msg = update.message
    user = update.effective_user
    if not msg or (not user and not getattr(msg, "sender_chat", None)):
        return
    if msg.chat.type not in (ChatType.GROUP, ChatType.SUPERGROUP):
        return
    if not engine.is_group_allowed(msg.chat.id):
        return
    if not await engine.check_message_admin_perm(context.bot, msg, user=user, require_restrict=True):
        return

    engine.mark_command_handled(msg.chat.id, msg.message_id)
    target_id: Optional[int] = None
    if msg.reply_to_message and msg.reply_to_message.from_user:
        target_id = msg.reply_to_message.from_user.id
    elif context.args:
        try:
            target_id = int(context.args[0])
        except ValueError:
            pass
    if not target_id:
        await msg.reply_text("请回复消息发 /untrust，或 /untrust <用户ID>")
        return
    engine.storage.untrust_user(msg.chat.id, target_id)
    sent = await msg.reply_text(f"已将 {target_id} 移出本群白名单。")
    asyncio.create_task(_delete_later(context.bot, msg.chat.id, sent.message_id, 10))


async def cmd_sban(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    engine: GuardEngine = context.application.bot_data["engine"]
    msg = update.message
    user = update.effective_user
    if not msg or (not user and not getattr(msg, "sender_chat", None)):
        return
    if msg.chat.type not in (ChatType.GROUP, ChatType.SUPERGROUP):
        return
    if not engine.is_group_allowed(msg.chat.id):
        return
    # Require explicit delete + restrict rights (supports anonymous group admins without privilege escalation)
    if not await engine.check_message_admin_perm(
        context.bot, msg, user=user, require_delete=True, require_restrict=True
    ):
        return

    engine.mark_command_handled(msg.chat.id, msg.message_id)
    target = msg.reply_to_message
    if not target:
        return

    # Never ban the bot itself, group admins, or the group's own/linked channel
    if target.from_user and (
        target.from_user.id == context.bot.id
        or await engine.is_group_admin(context.bot, msg.chat.id, target.from_user.id)
    ):
        return
    if target.sender_chat:
        if target.sender_chat.id == msg.chat.id:
            return
        linked_id = await engine.get_linked_chat_id(context.bot, msg.chat.id)
        if linked_id and target.sender_chat.id == linked_id:
            return

    xray = extract_xray(target, is_edited=False)
    try:
        await context.bot.delete_message(msg.chat.id, target.message_id)
        await context.bot.delete_message(msg.chat.id, msg.message_id)
    except TelegramError:
        pass
    try:
        if target.sender_chat and target.sender_chat.id != msg.chat.id:
            await context.bot.ban_chat_sender_chat(msg.chat.id, target.sender_chat.id)
            target_label = f"[频道马甲] {target.sender_chat.title or target.sender_chat.id}"
            target_id = target.sender_chat.id
        elif target.from_user:
            await context.bot.ban_chat_member(msg.chat.id, target.from_user.id, revoke_messages=True)
            engine.storage.untrust_user(msg.chat.id, target.from_user.id)
            uname = f" (@{target.from_user.username})" if getattr(target.from_user, "username", None) else ""
            target_label = f"{target.from_user.full_name}{uname}"
            target_id = target.from_user.id
        else:
            return
        engine.storage.inc_metric(msg.chat.id, "bans")
        # Only cache per-chat standalone fingerprint AFTER ban succeeds (same reply guard as automatic pipeline)
        gs = engine.get_group_settings(msg.chat.id, msg.chat.title or "")
        if xray.allow_shared_cache() or not gs.exempt_reply_cache:
            msg_fp = engine.spam_cache.fingerprint_message(msg.chat.id, xray, None)
            if msg_fp:
                engine.spam_cache.remember(msg_fp, 100, "管理员手动封禁样本")
        manual_reason = " ".join(getattr(context, "args", None) or []).strip() or "管理员手动封禁"
        engine.storage.log_action(
            chat_id=msg.chat.id,
            user_id=None if (target.sender_chat and target.sender_chat.id != msg.chat.id) else target_id,
            sender_chat_id=target_id if (target.sender_chat and target.sender_chat.id != msg.chat.id) else None,
            display_name=target_label,
            trigger_type="manual_sban",
            score=100,
            reason=manual_reason,
            preview=xray.build_preview(),
            dry_run=False,
        )
        await engine.announce_ban_in_group(
            context.bot,
            msg.chat.id,
            gs,
            display_name=target_label,
            actor_id=target_id,
            reason=manual_reason,
            duration="永久封禁",
            force_when_dry_run=True,
        )
    except TelegramError as exc:
        logger.warning("手动 /sban 失败: %s", exc)


async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    engine: GuardEngine = context.application.bot_data["engine"]
    query = update.callback_query
    if not query or not query.data:
        return
    user = query.from_user
    data = query.data

    if data.startswith("deploy:"):
        chat = getattr(query.message, "chat", None)
        if not chat or chat.type != ChatType.PRIVATE or chat.id != user.id or not engine.is_owner(user.id):
            await query.answer("仅机器人主人可在私聊中更新", show_alert=True)
            return
        result = await request_update(data.partition(":")[2], user.id)
        feedback = {
            "queued": "已开始更新。完成后我会私信你。",
            "busy": "正在更新，请等待结果。",
            "stale": "这条更新通知已失效，请使用最新通知。",
            "denied": "宿主机未授权这个账号更新。",
        }
        await query.answer(feedback.get(result, "宿主机更新服务暂时不可用。"), show_alert=True)
        return

    # 1. Join captcha answer callback
    if data.startswith("cap:"):
        parts = data.split(":")
        if len(parts) == 4:
            try:
                cid = int(parts[1])
                target_uid = int(parts[2])
            except ValueError:
                return
            choice = parts[3]
            if not engine.is_group_allowed(cid):
                await query.answer("该群未在允许列表中", show_alert=True)
                return
            ok, feedback = await engine.captcha.handle_answer(
                context.bot, cid, target_uid, user.id, choice
            )
            await query.answer(feedback, show_alert=not ok)
        return

    if data == "noop_confirm":
        await query.answer("已处理")
        try:
            await query.edit_message_reply_markup(reply_markup=None)
        except TelegramError:
            pass
        return

    # 1b. Owner-only private-chat interactive AI configuration panel (aiconf:*)
    if data.startswith("aiconf:"):
        msg_chat = getattr(query.message, "chat", None)
        if not msg_chat or msg_chat.type != ChatType.PRIVATE:
            await query.answer("请在机器人私聊中配置 AI 引擎", show_alert=True)
            return
        if not engine.is_owner(user.id):
            await query.answer("仅超级管理员可修改 AI 引擎配置", show_alert=True)
            return

        parts = data.split(":")
        sub = parts[1] if len(parts) > 1 else ""

        if sub == "back":
            engine.clear_owner_input_state(user.id)
            await query.answer()
            bot_uname = getattr(getattr(context, "bot", None), "username", "") or ""
            text, markup = build_start_dashboard(engine, user.id, bot_username=bot_uname)
            try:
                await query.edit_message_text(text, reply_markup=markup)
            except TelegramError:
                pass
            return

        if sub == "toggle_join_guard":
            engine.clear_owner_input_state(user.id)
            new_state = not engine.is_owner_only_join_enabled()
            engine.set_owner_only_join(new_state)
            toast = (
                "已开启「仅超管可拉群」：非超管拉入新群将自动退群并私聊告警"
                if new_state
                else "已关闭「仅超管可拉群」：允许他人拉入新群（仍受 ALLOWED_GROUP_IDS 限制）"
            )
            await query.answer(toast, show_alert=True)
            bot_uname = getattr(getattr(context, "bot", None), "username", "") or ""
            text, markup = build_start_dashboard(engine, user.id, bot_username=bot_uname)
            try:
                await query.edit_message_text(text, reply_markup=markup)
            except TelegramError:
                pass
            return

        if sub in ("menu", "cancel"):
            engine.clear_owner_input_state(user.id)
            await query.answer("已取消输入" if sub == "cancel" else None)
            text, markup = build_ai_config_view(engine)
            try:
                await query.edit_message_text(text, reply_markup=markup)
            except TelegramError:
                pass
            return

        if sub == "preset" and len(parts) == 3 and parts[2] in _AI_PRESETS:
            engine.clear_owner_input_state(user.id)
            label, base_url, model = _AI_PRESETS[parts[2]]
            key_cleared = await engine.update_ai_config(base_url=base_url, model=model)
            notice = f"✅ 已套用 {label} 预设：{model}"
            if key_cleared:
                await query.answer(f"已切换为 {label}，旧 Key 已清空，请填写新 Key")
                notice += (
                    "\n🔒 检测到服务商已变更，已自动清空旧 API Key（防止向新主机发送旧凭据）。\n"
                    "👉 请点击下方「🔑 填写 / 更换 API Key」填写该服务商的密钥！"
                )
            elif engine.llm.is_configured:
                await query.answer(f"已切换为 {label}，正在探测连通与识图...")
                report = await engine.llm.probe_capabilities()
                notice += (
                    f"\n• 文本连通：{'✅ 正常' if report.text_ok else '❌ ' + report.text_detail}"
                    f"\n• 识图能力：{'✅ 支持' if report.vision_supported else '⚠️ 纯文本模式'}"
                )
            else:
                await query.answer(f"已套用 {label} 预设，请再点「填写 API Key」")
                notice += "\n👉 接下来点击下方「🔑 填写 / 更换 API Key」即可启用！"
            text, markup = build_ai_config_view(engine, notice=notice)
            try:
                await query.edit_message_text(text, reply_markup=markup)
            except TelegramError:
                pass
            return

        if sub == "ask" and len(parts) == 3 and parts[2] in ("api_key", "model", "base_url"):
            field = parts[2]
            engine.clear_admin_input_state(msg_chat.id, user.id)
            engine.set_owner_input_state(user.id, field)
            prompts = {
                "api_key": (
                    "🔑 请直接发送你的 API Key（5 分钟内有效）：\n"
                    "例如：sk-xxxxxxxxxxxx\n\n"
                    "发送后将自动保存、热加载并测试连通与多模态识图（无需重启服务）。"
                ),
                "model": (
                    f"✏️ 请直接发送模型名称（当前：{engine.llm.model or '未设置'}）：\n"
                    "例如：deepseek-flash、gpt-5-mini、gemini-2.5-flash、qwen-vl-max"
                ),
                "base_url": (
                    f"🔗 请直接发送 OpenAI 兼容接口地址 Base URL（当前：{sanitize_url_for_display(engine.llm.base_url)}）：\n"
                    "远程接口必须使用 https://（仅本机回环地址允许 http://），例如 https://api.deepseek.com/v1"
                ),
            }
            cancel_kb = InlineKeyboardMarkup(
                [[InlineKeyboardButton("❌ 取消输入", callback_data="aiconf:cancel")]]
            )
            await query.answer("请直接发送内容")
            try:
                await query.edit_message_text(prompts[field], reply_markup=cancel_kb)
            except TelegramError:
                pass
            return

        if sub == "test":
            engine.clear_owner_input_state(user.id)
            await query.answer("正在测试接口连通与多模态识图，请稍候...")
            report = await engine.llm.probe_capabilities()
            notice = (
                f"🧪 探测结果：\n"
                f"• 文本连通：{'✅ ' + report.text_detail if report.text_ok else '❌ ' + report.text_detail}\n"
                f"• 识图能力：{'✅ ' + report.vision_detail if report.vision_supported else '⚠️ ' + report.vision_detail}"
            )
            text, markup = build_ai_config_view(engine, notice=notice)
            try:
                await query.edit_message_text(text, reply_markup=markup)
            except TelegramError:
                pass
            return

        if sub == "clear_key":
            engine.clear_owner_input_state(user.id)
            await engine.update_ai_config(api_key="")
            await query.answer("已清除 API Key，切回纯本地基础防护模式")
            text, markup = build_ai_config_view(
                engine, notice="🧹 已清除 API Key，当前已切回零成本「纯本地基础防护模式」。"
            )
            try:
                await query.edit_message_text(text, reply_markup=markup)
            except TelegramError:
                pass
            return

        if sub == "reset_env":
            engine.clear_owner_input_state(user.id)
            await engine.reset_ai_config_to_env()
            await query.answer("已恢复服务器 .env 默认配置，正在重新探测...")
            report = await engine.llm.probe_capabilities()
            notice = (
                f"↩️ 已恢复服务器 .env 默认配置：\n"
                f"• 文本连通：{'✅ 正常' if report.text_ok else '⚠️ ' + report.text_detail}"
            )
            text, markup = build_ai_config_view(engine, notice=notice)
            try:
                await query.edit_message_text(text, reply_markup=markup)
            except TelegramError:
                pass
            return

        await query.answer("未知操作")
        return

    # 1c. Owner-only private-chat bot branding panel (brand:* — avatar, name, short/full description)
    if data.startswith("brand:"):
        msg_chat = getattr(query.message, "chat", None)
        if not msg_chat or msg_chat.type != ChatType.PRIVATE:
            await query.answer("请在机器人私聊中修改机器人形象资料", show_alert=True)
            return
        if not engine.is_owner(user.id):
            await query.answer("仅超级管理员可修改机器人头像、名称与简介", show_alert=True)
            return

        bot_uname = getattr(getattr(context, "bot", None), "username", "") or ""
        parts = data.split(":")
        sub = parts[1] if len(parts) > 1 else ""

        if sub == "back":
            engine.clear_owner_input_state(user.id)
            await query.answer()
            text, markup = build_start_dashboard(engine, user.id, bot_username=bot_uname)
            try:
                await query.edit_message_text(text, reply_markup=markup)
            except TelegramError:
                pass
            return

        if sub in ("menu", "cancel"):
            engine.clear_owner_input_state(user.id)
            await query.answer("已取消输入" if sub == "cancel" else None)
            text, markup = build_branding_view(engine, bot_username=bot_uname)
            try:
                await query.edit_message_text(text, reply_markup=markup)
            except TelegramError:
                pass
            return

        if sub == "apply_all":
            engine.clear_owner_input_state(user.id)
            await query.answer("正在一键应用AI-智能广告杀手官方头像、名称与简介，请稍候...")
            results = await apply_default_branding(engine.cfg.telegram_bot_token)
            text, markup = build_branding_view(
                engine, bot_username=bot_uname, notice=format_branding_results(results)
            )
            try:
                await query.edit_message_text(text, reply_markup=markup)
            except TelegramError:
                pass
            return

        if sub == "apply_avatar":
            engine.clear_owner_input_state(user.id)
            await query.answer("正在更换AI-智能广告杀手官方头像，请稍候...")
            if not DEFAULT_AVATAR_PATH.is_file():
                notice = "⚠️ 未找到内置AI-智能广告杀手头像文件 assets/avatar.jpg"
            else:
                ok, detail = await set_bot_profile_photo(
                    engine.cfg.telegram_bot_token, DEFAULT_AVATAR_PATH.read_bytes()
                )
                notice = "✅ 已更换为AI-智能广告杀手官方头像！" if ok else f"⚠️ 更换头像失败：{detail}"
            text, markup = build_branding_view(engine, bot_username=bot_uname, notice=notice)
            try:
                await query.edit_message_text(text, reply_markup=markup)
            except TelegramError:
                pass
            return

        if sub == "ask" and len(parts) == 3 and parts[2] in ("name", "short_desc", "desc", "avatar"):
            target_field = parts[2]
            engine.clear_admin_input_state(msg_chat.id, user.id)
            engine.set_owner_input_state(user.id, f"brand_{target_field}")
            prompts = {
                "name": (
                    f"✏️ 请直接发送新的机器人名称（最多 {MAX_BOT_NAME_LEN} 字，5 分钟内有效）：\n"
                    f"例如：{DEFAULT_BOT_NAME}"
                ),
                "short_desc": (
                    f"📝 请直接发送新的机器人简短简介（主页 About 展示，最多 {MAX_BOT_SHORT_DESC_LEN} 字）：\n"
                    f"例如：{DEFAULT_BOT_SHORT_DESC}"
                ),
                "desc": (
                    f"📄 请直接发送新的机器人完整介绍（首次点开 /start 前展示，最多 {MAX_BOT_DESC_LEN} 字）：\n"
                    f"例如：{DEFAULT_BOT_DESC}"
                ),
                "avatar": (
                    "📷 请直接发送一张图片作为机器人的新头像（5 分钟内有效）：\n"
                    "将自动居中裁剪为正方形 JPG 并立即更新。"
                ),
            }
            cancel_kb = InlineKeyboardMarkup(
                [[InlineKeyboardButton("❌ 取消输入", callback_data="brand:cancel")]]
            )
            await query.answer("请直接发送内容")
            try:
                await query.edit_message_text(prompts[target_field], reply_markup=cancel_kb)
            except TelegramError:
                pass
            return

        await query.answer("未知操作")
        return

    # 1d. Owner-only private-chat runtime status & audit reports (stats:*)
    if data.startswith("stats:"):
        msg_chat = getattr(query.message, "chat", None)
        if not msg_chat or msg_chat.type != ChatType.PRIVATE:
            await query.answer("请在机器人私聊中查看运行状态与战报", show_alert=True)
            return
        if not engine.is_owner(user.id):
            await query.answer("仅超级管理员可查看全局运行状态", show_alert=True)
            return
        sub = data.split(":", 1)[1] if ":" in data else "overview"
        bot_uname = getattr(getattr(context, "bot", None), "username", "") or ""
        if sub == "back":
            await query.answer()
            text, markup = build_start_dashboard(engine, user.id, bot_username=bot_uname)
        elif sub in ("overview", "kills", "suspects", "ai"):
            await query.answer("已刷新")
            text, markup = build_stats_view(engine, view=sub)
        else:
            await query.answer("未知视图")
            return
        try:
            await query.edit_message_text(text, reply_markup=markup)
        except TelegramError:
            pass
        return

    # 2. Unban & whitelist from audit card
    if data.startswith("unban:"):
        try:
            _, cid_s, uid_s = data.split(":", 2)
            cid, uid = int(cid_s), int(uid_s)
        except ValueError:
            return
        if not engine.is_group_allowed(cid):
            await query.answer("该群未在允许列表中", show_alert=True)
            return
        if not await engine.check_admin_perm(
            context.bot, cid, user.id, require_restrict=True, fresh=True
        ):
            await query.answer("仅拥有封禁权限的群管理员可操作", show_alert=True)
            return
        try:
            await context.bot.unban_chat_member(cid, uid, only_if_banned=True)
            engine.storage.trust_user(cid, uid, f"unbanned_by_{user.id}")
            await query.answer("已解封并加入永久白名单！", show_alert=True)
            await query.edit_message_text(
                (query.message.text or "") + f"\n\n✅ 已被 {user.full_name} 解封并加入永久白名单"
            )
        except TelegramError as exc:
            await query.answer(f"解封失败: {exc}", show_alert=True)
        return

    # 3. Gray-zone review: upgrade mute -> permanent ban
    if data.startswith("upban:"):
        try:
            _, cid_s, uid_s = data.split(":", 2)
            cid, uid = int(cid_s), int(uid_s)
        except ValueError:
            return
        if not engine.is_group_allowed(cid):
            await query.answer("该群未在允许列表中", show_alert=True)
            return
        if not await engine.check_admin_perm(
            context.bot, cid, user.id, require_delete=True, require_restrict=True, fresh=True
        ):
            await query.answer("仅拥有删消息+封禁权限的群管理员可操作", show_alert=True)
            return
        try:
            await context.bot.ban_chat_member(cid, uid, revoke_messages=True)
            engine.storage.inc_metric(cid, "bans")
            gs = engine.get_group_settings(cid)
            await engine.announce_ban_in_group(
                context.bot,
                cid,
                gs,
                display_name=f"用户 {uid}",
                actor_id=uid,
                reason="管理员复核确认广告，升级封禁",
                duration="永久封禁",
                force_when_dry_run=True,
            )
            await query.answer("已升级为永久封禁！", show_alert=True)
            await query.edit_message_text(
                (query.message.text or "") + f"\n\n🚫 已被 {user.full_name} 确认并升级为永久封禁"
            )
        except TelegramError as exc:
            await query.answer(f"封禁失败: {exc}", show_alert=True)
        return

    # 4. Channel identity gray-zone / report ban
    if data.startswith("upbanch:"):
        try:
            _, cid_s, scid_s = data.split(":", 2)
            cid, scid = int(cid_s), int(scid_s)
        except ValueError:
            return
        if not engine.is_group_allowed(cid):
            await query.answer("该群未在允许列表中", show_alert=True)
            return
        if not await engine.check_admin_perm(
            context.bot, cid, user.id, require_delete=True, require_restrict=True, fresh=True
        ):
            await query.answer("仅拥有删消息+封禁权限的群管理员可操作", show_alert=True)
            return
        try:
            await context.bot.ban_chat_sender_chat(cid, scid)
            engine.storage.inc_metric(cid, "bans")
            gs = engine.get_group_settings(cid)
            await engine.announce_ban_in_group(
                context.bot,
                cid,
                gs,
                display_name=f"[频道马甲] {scid}",
                actor_id=scid,
                reason="管理员复核确认广告频道，永久封禁",
                duration="永久封禁",
                force_when_dry_run=True,
            )
            await query.answer("已永久封禁该频道马甲！", show_alert=True)
            await query.edit_message_text(
                (query.message.text or "") + f"\n\n🚫 已被 {user.full_name} 确认永久封禁频道马甲"
            )
        except TelegramError as exc:
            await query.answer(f"封禁频道失败: {exc}", show_alert=True)
        return

    # 5. Gray-zone review: unmute & trust
    if data.startswith("unmute:"):
        try:
            _, cid_s, uid_s = data.split(":", 2)
            cid, uid = int(cid_s), int(uid_s)
        except ValueError:
            return
        if not engine.is_group_allowed(cid):
            await query.answer("该群未在允许列表中", show_alert=True)
            return
        if not await engine.check_admin_perm(
            context.bot, cid, user.id, require_restrict=True, fresh=True
        ):
            await query.answer("仅拥有封禁权限的群管理员可操作", show_alert=True)
            return
        perms = DEFAULT_UNMUTE_PERMS
        try:
            cinfo = await context.bot.get_chat(cid)
            if getattr(cinfo, "permissions", None):
                perms = cinfo.permissions
        except TelegramError:
            pass
        try:
            await context.bot.restrict_chat_member(cid, uid, permissions=perms)
            engine.storage.trust_user(cid, uid, f"unmuted_by_{user.id}")
            await query.answer("已解除禁言并加入白名单！", show_alert=True)
            await query.edit_message_text(
                (query.message.text or "") + f"\n\n✅ 已被 {user.full_name} 放行解禁并加入永久白名单"
            )
        except TelegramError as exc:
            await query.answer(f"解禁失败: {exc}", show_alert=True)
        return

    # 6. Community /spam report or swarm per-person remote ban
    if data.startswith("rptban:"):
        try:
            _, cid_s, uid_s, mid_s = data.split(":", 3)
            cid, uid, mid = int(cid_s), int(uid_s), int(mid_s)
        except ValueError:
            return
        if not engine.is_group_allowed(cid):
            await query.answer("该群未在允许列表中", show_alert=True)
            return
        if not await engine.check_admin_perm(
            context.bot, cid, user.id, require_delete=True, require_restrict=True, fresh=True
        ):
            await query.answer("仅拥有删消息+封禁权限的群管理员可操作", show_alert=True)
            return
        try:
            await context.bot.delete_message(cid, mid)
        except TelegramError:
            pass
        try:
            await context.bot.ban_chat_member(cid, uid, revoke_messages=True)
            engine.storage.inc_metric(cid, "bans")
            gs = engine.get_group_settings(cid)
            await engine.announce_ban_in_group(
                context.bot,
                cid,
                gs,
                display_name=f"用户 {uid}",
                actor_id=uid,
                reason="管理员核实举报/团伙广告",
                duration="永久封禁",
                force_when_dry_run=True,
            )
            await query.answer("已远程删消息并永久封禁！", show_alert=True)
            await query.edit_message_text(
                (query.message.text or "") + f"\n\n🚫 已被 {user.full_name} 远程封禁 ({uid})"
            )
        except TelegramError as exc:
            await query.answer(f"封禁失败: {exc}", show_alert=True)
        return

    # 7. /config panel interactive buttons
    if not data.startswith("cfg:"):
        return
    parts = data.split(":")
    if len(parts) != 3:
        return
    action = parts[1]
    try:
        cid = int(parts[2])
    except ValueError:
        return

    if not engine.is_group_allowed(cid):
        await query.answer("该群未在 ALLOWED_GROUP_IDS 允许列表中", show_alert=True)
        return

    if not await engine.check_admin_perm(
        context.bot, cid, user.id, require_restrict=True, fresh=True
    ):
        await query.answer("仅拥有封禁/限制成员权限的本群管理员可修改配置", show_alert=True)
        return

    panel_chat = getattr(query.message, "chat", None)
    panel_chat_id = panel_chat.id if panel_chat else cid
    panel_msg_id = getattr(query.message, "message_id", 0) or 0

    if action == "close":
        engine.clear_admin_input_state(panel_chat_id, user.id)
        await query.answer("面板已关闭")
        try:
            await query.message.delete()
        except TelegramError:
            pass
        return

    gs = engine.get_group_settings(cid)
    toast = "已更新"

    if action == "open":
        engine.clear_admin_input_state(panel_chat_id, user.id)
        toast = "已打开面板"
    elif action == "mode":
        if gs.enabled and not gs.dry_run:
            gs.dry_run = True
            toast = "已切换为【观察模式】（只发日志不封禁）"
        elif gs.enabled and gs.dry_run:
            gs.enabled = False
            toast = "已【暂停】本群拦截"
        else:
            gs.enabled = True
            gs.dry_run = False
            toast = "已切换为【全自动秒封】"
        engine.storage.save_group(gs)
    elif action == "score":
        gs.spam_score = _CYCLE_SCORE.get(gs.spam_score, 80)
        engine.storage.save_group(gs)
        toast = f"拦截阈值已设为 {gs.spam_score} 分"
    elif action == "vision":
        if not engine.llm.is_configured:
            await query.answer(
                "当前处于纯本地基础防护模式（未填写 AI_API_KEY）。基础反垃圾规则、CAS、防刷屏、木马拦截与入群验证均正常工作；填入多模态模型 API Key 后即可开启识图。",
                show_alert=True,
            )
            return
        if not engine.llm.vision_supported:
            await query.answer(
                f"当前模型 {engine.llm.model} 不支持多模态识图，其余文字/隐形链接/编辑/防刷屏仍正常工作；更换多模态模型后可点「重新探测多模态」。",
                show_alert=True,
            )
            return
        gs.vision_enabled = not gs.vision_enabled
        engine.storage.save_group(gs)
        toast = f"图片/贴纸识图已{'开启' if gs.vision_enabled else '关闭'}"
    elif action == "gray":
        gs.gray_zone_mute = not gs.gray_zone_mute
        engine.storage.save_group(gs)
        toast = f"灰区禁言复核已{'开启' if gs.gray_zone_mute else '关闭'}"
    elif action == "cas":
        gs.cas_enabled = not gs.cas_enabled
        engine.storage.save_group(gs)
        toast = f"CAS 全球黑库已{'开启' if gs.cas_enabled else '关闭'}"
    elif action == "captcha":
        gs.join_captcha = not gs.join_captcha
        engine.storage.save_group(gs)
        toast = f"简易入群验证已{'开启（请确保未与其他验证Bot冲突）' if gs.join_captcha else '关闭'}"
    elif action == "antiraid":
        if gs.antiraid_until > time.time():
            gs.antiraid_until = 0.0
            toast = "已关闭应急反炸群模式"
        else:
            gs.antiraid_until = time.time() + 3600
            toast = "🚨 已开启 1 小时应急反炸群模式！"
        engine.storage.save_group(gs)
    elif action == "flood":
        gs.anti_flood = not gs.anti_flood
        engine.storage.save_group(gs)
        toast = f"限流防刷屏已{'开启（首次快聊仅60s限流，绝不盲目永封）' if gs.anti_flood else '关闭'}"
    elif action == "swarm":
        gs.swarm_guard = not gs.swarm_guard
        engine.storage.save_group(gs)
        toast = f"团伙复读联动已{'开启（AI核验+逐人复核，绝不盲封）' if gs.swarm_guard else '关闭'}"
    elif action == "edited":
        gs.check_edited = not gs.check_edited
        engine.storage.save_group(gs)
        toast = f"编辑消息监控已{'开启' if gs.check_edited else '关闭'}"
    elif action == "viabot":
        gs.via_bot_mode = _CYCLE_VIA.get(gs.via_bot_mode, "ban")
        engine.storage.save_group(gs)
        toast = f"外部内联卡片策略：{_VIA_LABELS[gs.via_bot_mode]}"
    elif action == "startcmd":
        toast = "普通 /start 指令已免审"
    elif action == "malware":
        gs.block_malware_files = not gs.block_malware_files
        engine.storage.save_group(gs)
        toast = f"木马安装包拦截已{'开启' if gs.block_malware_files else '关闭'}"
    elif action == "service":
        gs.clean_service_msgs = not gs.clean_service_msgs
        engine.storage.save_group(gs)
        toast = f"自动清理进退群提示已{'开启' if gs.clean_service_msgs else '关闭'}"
    elif action == "announce":
        gs.announce_in_group = not gs.announce_in_group
        engine.storage.save_group(gs)
        toast = f"群内播报已{'开启' if gs.announce_in_group else '设为静默'}"
    elif action in ("announce_menu", "an_cancel"):
        engine.clear_admin_input_state(panel_chat_id, user.id)
        engine.clear_admin_input_state(user.id, user.id)
        await query.answer("已取消输入" if action == "an_cancel" else "已打开封禁播报设置")
        text, markup = build_announce_view(engine, gs)
        try:
            await query.edit_message_text(text, reply_markup=markup)
        except TelegramError:
            pass
        return
    elif action in (
        "an_toggle",
        "an_deltoggle",
        "an_del0",
        "an_del60",
        "an_del300",
        "an_del1800",
        "an_del3600",
        "an_reset_tpl",
        "an_preview",
    ):
        engine.clear_admin_input_state(panel_chat_id, user.id)
        engine.clear_admin_input_state(user.id, user.id)
        notice = ""
        if action == "an_toggle":
            gs.announce_in_group = not gs.announce_in_group
            engine.storage.save_group(gs)
            toast = f"群内封禁播报已{'开启' if gs.announce_in_group else '关闭'}"
        elif action == "an_deltoggle":
            gs.announce_delete_seconds = 0 if gs.announce_delete_seconds > 0 else 1800
            engine.storage.save_group(gs)
            toast = (
                f"自动删除已开启（{format_delete_delay(gs.announce_delete_seconds)}后删）"
                if gs.announce_delete_seconds > 0
                else "已关闭自动删除（封禁提示将永久保留）"
            )
        elif action in ("an_del0", "an_del60", "an_del300", "an_del1800", "an_del3600"):
            secs = int(action.replace("an_del", ""))
            gs.announce_delete_seconds = secs
            engine.storage.save_group(gs)
            toast = f"自动删除已设为：{format_delete_delay(secs)}"
        elif action == "an_reset_tpl":
            gs.announce_template = ""
            engine.storage.save_group(gs)
            toast = "已恢复默认播报文案"
        elif action == "an_preview":
            sample = render_ban_announcement(
                gs,
                display_name="示例用户 (@demo)",
                actor_id=123456789,
                reason="发布垃圾广告引流",
                duration="永久封禁",
            )
            notice = f"👀 实际播报效果预览：\n{sample}"
            toast = "已生成预览"
        await query.answer(toast)
        text, markup = build_announce_view(engine, gs, notice=notice)
        try:
            await query.edit_message_text(text, reply_markup=markup)
        except TelegramError:
            pass
        return
    elif action in ("an_ask_tpl", "an_ask_delay"):
        field = "announce_template" if action == "an_ask_tpl" else "announce_delete_seconds"
        if field == "announce_template":
            prompt_text = (
                f"✏️ 请直接在本聊天发送新的群内封禁提示文案（5 分钟内有效，最多 {ANNOUNCE_MAX_TEMPLATE_LEN} 字）：\n\n"
                "可用变量：\n"
                "• {user} — 被封禁用户名称\n"
                "• {user_id} — 用户数字 ID\n"
                "• {reason} — 封禁理由\n"
                "• {duration} — 封禁时长（如「永久封禁」）\n"
                "• {auto_delete} — 自动删除倒计时说明\n\n"
                "示例：\n"
                "🛡 AI-智能广告杀手已经封禁 {user}，理由：{reason}，封禁时长：{duration}\n"
                "（发送「默认」可恢复默认文案）"
            )
        else:
            prompt_text = (
                "⏱ 请直接在本聊天发送封禁提示的自动删除时间（5 分钟内有效）：\n\n"
                "• 纯数字按分钟计，例如：30（30分钟后自动删除）\n"
                "• 支持带单位：45s / 15m / 2h / 30秒 / 10分钟 / 1小时\n"
                "• 支持范围：10 秒 ~ 24 小时\n"
                "• 发送 0 或「不删」表示永久保留（不自动删除）"
            )
        cancel_kb = InlineKeyboardMarkup(
            [[InlineKeyboardButton("❌ 取消输入", callback_data=f"cfg:an_cancel:{cid}")]]
        )

        # Anti-collision guard: when a group has 2+ anonymous admins, Telegram hides which anonymous admin spoke.
        # Route the text input to the clicking admin's personal DM instead of accepting ambiguous group input!
        if (
            panel_chat
            and panel_chat.type in (ChatType.GROUP, ChatType.SUPERGROUP)
            and await engine.is_ambiguous_anon_admin(context.bot, cid, user.id)
        ):
            dm_prompt = f"📌 群组：{gs.chat_title or cid}\n\n{prompt_text}"
            try:
                sent_dm = await context.bot.send_message(user.id, dm_prompt, reply_markup=cancel_kb)
                dm_mid = getattr(sent_dm, "message_id", None)
                engine.clear_owner_input_state(user.id)
                engine.clear_admin_input_state(panel_chat_id, user.id)
                engine.set_admin_input_state(
                    user.id, user.id, cid, field, dm_mid if isinstance(dm_mid, int) else None
                )
                notice = (
                    "🔒 检测到本群有多位匿名管理员，为防止群内发言串改配置，已将输入框发送到你的私聊，"
                    "请在与机器人的私聊中直接回复。"
                )
                await query.answer("已转至私聊输入（防多匿名管串改）", show_alert=True)
            except TelegramError:
                engine.clear_admin_input_state(panel_chat_id, user.id)
                bot_uname = getattr(getattr(context, "bot", None), "username", "") or ""
                dm_tip = f"https://t.me/{bot_uname}" if bot_uname else "机器人私聊"
                notice = (
                    f"🔒 本群有多位匿名管理员，为防止群内发言串改配置，请先前往 {dm_tip} 发送 /start 开启私聊，"
                    "再回到此处点击修改（或直接在私聊面板修改）。"
                )
                await query.answer("请先私聊机器人 /start 后再修改", show_alert=True)
            text, markup = build_announce_view(engine, gs, notice=notice)
            try:
                await query.edit_message_text(text, reply_markup=markup)
            except TelegramError:
                pass
            return

        if panel_chat and panel_chat.type == ChatType.PRIVATE:
            engine.clear_owner_input_state(user.id)
        engine.set_admin_input_state(panel_chat_id, user.id, cid, field, panel_msg_id)
        await query.answer("请直接发送内容")
        try:
            await query.edit_message_text(prompt_text, reply_markup=cancel_kb)
        except TelegramError:
            pass
        return
    elif action == "localrules":
        gs.local_rules_enabled = not gs.local_rules_enabled
        engine.storage.save_group(gs)
        toast = (
            "已开启本地关键词规则（无 AI 或 AI 故障时启用）"
            if gs.local_rules_enabled
            else "已关闭本地关键词规则（语义交由 AI 判断，防多义词误杀）"
        )
    elif action == "exempts":
        await query.answer("已打开豁免与绕过规则面板")
        text, markup = build_exempts_view(engine, gs)
        try:
            await query.edit_message_text(text, reply_markup=markup)
        except TelegramError:
            pass
        return
    elif action in (
        "ex_admins",
        "ex_anon",
        "ex_linked",
        "ex_trusted",
        "ex_owners",
        "ex_extch",
        "ex_first_msg",
        "ex_short",
        "ex_reply",
        "ex_fallback",
    ):
        if action == "ex_admins":
            gs.exempt_admins = not gs.exempt_admins
            toast = f"群主/管理员豁免已{'开启' if gs.exempt_admins else '关闭（可用于本人发消息实测拦截）'}"
        elif action == "ex_anon":
            gs.exempt_anon_admin = not gs.exempt_anon_admin
            toast = f"匿名管理员豁免已{'开启' if gs.exempt_anon_admin else '关闭'}"
        elif action == "ex_linked":
            gs.exempt_linked_channel = not gs.exempt_linked_channel
            toast = f"本群关联频道豁免已{'开启' if gs.exempt_linked_channel else '关闭'}"
        elif action == "ex_trusted":
            gs.exempt_trusted = not gs.exempt_trusted
            toast = f"白名单(/trust)豁免已{'开启' if gs.exempt_trusted else '关闭'}"
        elif action == "ex_owners":
            gs.exempt_owners = not gs.exempt_owners
            toast = f"全局超管跨群免检已{'开启' if gs.exempt_owners else '关闭（按本群管理身份判定）'}"
        elif action == "ex_extch":
            gs.external_channel_mode = _CYCLE_EXT_CH.get(gs.external_channel_mode, "ai")
            toast = f"外部频道马甲策略：{_EXT_CH_LABELS[gs.external_channel_mode]}"
        elif action == "ex_first_msg":
            gs.first_message_only = not gs.first_message_only
            toast = f"成员与频道语义审核已切换为{'仅审首条' if gs.first_message_only else '持续审核'}"
        elif action == "ex_short":
            gs.exempt_veteran_short = not gs.exempt_veteran_short
            toast = f"持续审核时老群友短消息免AI已{'开启' if gs.exempt_veteran_short else '关闭'}"
        elif action == "ex_reply":
            gs.exempt_reply_cache = not gs.exempt_reply_cache
            toast = f"回复消息免缓存秒封已{'开启' if gs.exempt_reply_cache else '关闭'}"
        elif action == "ex_fallback":
            gs.admin_cache_fallback = not gs.admin_cache_fallback
            toast = f"查管理超时防误删兜底已{'开启' if gs.admin_cache_fallback else '关闭'}"
        engine.storage.save_group(gs)
        await query.answer(toast)
        text, markup = build_exempts_view(engine, gs)
        try:
            await query.edit_message_text(text, reply_markup=markup)
        except TelegramError:
            pass
        return
    elif action == "bindlog":
        try:
            await context.bot.send_message(
                user.id,
                f"🛡 已成功将群组「{gs.chat_title or cid}」的封禁与举报审计日志绑定到你的私聊！",
            )
            gs.log_chat_id = user.id
            engine.storage.save_group(gs)
            toast = "已绑定审计日志到你的私聊！"
        except TelegramError:
            await query.answer(
                "请先点开我的私聊发送一次 /start，再回来点此按钮绑定！",
                show_alert=True,
            )
            return
    elif action == "reprobe":
        await query.answer("正在重新探测模型多模态能力，请稍候...")
        report = await engine.llm.probe_capabilities()
        text, markup = build_panel_view(engine, gs)
        try:
            await query.edit_message_text(text, reply_markup=markup)
        except TelegramError:
            pass
        notice = (
            f"✅ 探测完成：{report.vision_detail}"
            if report.vision_supported
            else f"⚠️ 探测完成：{report.vision_detail}"
        )
        try:
            await context.bot.send_message(user.id, notice)
        except TelegramError:
            pass
        return

    await query.answer(toast)
    text, markup = build_panel_view(engine, gs)
    try:
        await query.edit_message_text(text, reply_markup=markup)
    except TelegramError:
        pass
