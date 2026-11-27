"""Entrypoint and startup preflight (multimodal probe, captcha recovery, owner claim code)."""

from __future__ import annotations

import logging

from telegram import (
    BotCommand,
    BotCommandScopeAllChatAdministrators,
    BotCommandScopeAllGroupChats,
    BotCommandScopeAllPrivateChats,
    Update,
)
from telegram.error import TelegramError
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    ChatMemberHandler,
    CommandHandler,
    MessageHandler,
    filters,
)

from . import __app_name__, __app_name_cn__, __version__
from .config import AppConfig
from .guard import GuardEngine
from .llm import UniversalAIClient, sanitize_url_for_display
from .panel import (
    cmd_antiraid,
    cmd_claim,
    cmd_config,
    cmd_report_spam,
    cmd_sban,
    cmd_settopic,
    cmd_start_group,
    cmd_start_private,
    cmd_trust,
    cmd_untrust,
    handle_callback,
    handle_group_admin_input,
    handle_private_owner_input,
)
from .storage import Storage


async def _post_init(app: Application) -> None:
    engine: GuardEngine = app.bot_data["engine"]
    logger = logging.getLogger("adkiller")

    # Restore any pending join captchas & scheduled message auto-deletes from before a restart
    await engine.captcha.restore_pending(app.bot)
    await engine.restore_pending_deletes(app.bot)

    # Register scoped Telegram "/" command menus (private, group members, group admins)
    try:
        await app.bot.set_my_commands(
            [
                BotCommand("start", "打开AI-智能广告杀手主控台（AI配置/运行战报/换头像）"),
            ],
            scope=BotCommandScopeAllPrivateChats(),
        )
        await app.bot.set_my_commands(
            [
                BotCommand("spam", "回复漏网广告一键举报给管理员"),
            ],
            scope=BotCommandScopeAllGroupChats(),
        )
        await app.bot.set_my_commands(
            [
                BotCommand("config", "打开AI-智能广告杀手可视化管理面板"),
                BotCommand("settopic", "设置本群主题降低AI误杀"),
                BotCommand("antiraid", "开启或关闭1小时应急反炸群"),
                BotCommand("trust", "回复消息将老群友加入白名单"),
                BotCommand("untrust", "将成员移出本群白名单"),
                BotCommand("sban", "回复广告一键秒封并入黑库"),
                BotCommand("spam", "回复广告举报或直接秒封"),
                BotCommand("start", "查看AI-智能广告杀手群内快捷指引"),
            ],
            scope=BotCommandScopeAllChatAdministrators(),
        )
        logger.info("✅ 已自动注册 Telegram 聊天指令提示菜单（私聊 / 群成员 / 群管理员分层展示）")
    except TelegramError as exc:
        logger.warning("⚠️ 自动注册指令菜单失败（不影响拦截功能）: %s", exc)

    if not engine.llm.is_configured:
        logger.info(
            "🛡 未配置 AI_API_KEY，AI-智能广告杀手已以【基础硬防模式】启动"
            "（CAS/限流防刷屏/木马拦截/入群验证/反炸群均正常运行；本地关键词规则默认关闭，可在群内 /config 按需开启或配置 AI 接口）"
        )
        report = await engine.llm.probe_capabilities()
    else:
        logger.info(
            "正在执行启动自检（模型: %s | 接口: %s）...",
            engine.llm.model,
            sanitize_url_for_display(engine.llm.base_url),
        )
        report = await engine.llm.probe_capabilities()
        if report.text_ok:
            logger.info("✅ 文本模型自检通过：%s", report.text_detail)
        else:
            logger.warning(
                "⚠️ %s（AI 不可用期间默认仅保留基础硬防，不会用关键词规则盲封；如需兜底可在 /config 开启本地关键词规则）",
                report.text_detail,
            )

        if report.vision_supported:
            logger.info("🖼 ✅ %s", report.vision_detail)
        else:
            logger.warning("🖼 ⚠️ %s", report.vision_detail)

    bot_username = getattr(app.bot, "username", "") or ""
    if bot_username:
        logger.info("🔗 机器人直达链接：https://t.me/%s", bot_username)

    owners = engine.get_owner_ids()
    if owners:
        bot_link_line = f"• 直达链接：https://t.me/{bot_username}\n" if bot_username else ""
        if not engine.llm.is_configured:
            warn_line = f"\n• {engine.active_ai_warning}" if engine.active_ai_warning else ""
            startup_text = (
                f"🛡 {__app_name_cn__} v{__version__} 已启动\n"
                f"{bot_link_line}"
                f"• 运行引擎：🛡 基础硬防模式（未配置有效 AI 接口）\n"
                f"• 已启用能力：CAS 黑库、分层限流防刷屏、木马安装包拦截、外联卡片/刷指令拦截、入群验证、一键反炸群、群友举报\n"
                f"• 本地关键词规则：默认关闭（避免多义词误杀；如需无 AI 关键词拦截可在群内 /config 点开）"
                f"{warn_line}\n"
                f"• 提示：随时发送 /start 可点按钮配置 AI 接口或一键更换AI-智能广告杀手头像/名称/简介"
            )
        else:
            vision_msg = (
                f"✅ 多模态识图已自动开启（{engine.llm.model} 支持看图）"
                if report.vision_supported
                else f"⚠️ {report.vision_detail}"
            )
            startup_text = (
                f"🛡 {__app_name_cn__} v{__version__} 已启动\n"
                f"{bot_link_line}"
                f"• 模型：{engine.llm.model}\n"
                f"• 文本连通：{'✅ 正常' if report.text_ok else '⚠️ 失败（故障期间仅保基础硬防，不触发关键词误封）— ' + report.text_detail}\n"
                f"• 识图能力：{vision_msg}"
            )
        for oid in owners:
            try:
                await app.bot.send_message(oid, startup_text)
            except Exception:
                pass
    elif engine.claim_code:
        logger.warning(
            "🔑 尚未配置 OWNER_IDS！请由部署者在 15 分钟内私聊机器人发送以下一次性命令认领（单账号输错 5 次自动锁定该账号）：\n"
            "    /claim %s\n"
            "（更推荐直接在 .env 中填写 OWNER_IDS=<你的纯数字ID>）",
            engine.claim_code,
        )


async def _post_shutdown(app: Application) -> None:
    engine: GuardEngine = app.bot_data["engine"]
    engine.cancel_pending_delete_tasks()
    await engine.cas.close()
    await engine.llm.close()
    engine.storage.close()


def main() -> None:
    cfg = AppConfig()
    cfg.validate()

    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        level=cfg.log_level,
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logger = logging.getLogger("adkiller")

    storage = Storage(cfg.db_path)
    llm = UniversalAIClient(
        api_key=cfg.ai_api_key,
        base_url=cfg.ai_base_url,
        model=cfg.ai_model,
        timeout=cfg.ai_timeout_seconds,
        concurrency=cfg.ai_concurrency,
    )
    engine = GuardEngine(cfg, storage, llm)

    app = (
        Application.builder()
        .token(cfg.telegram_bot_token)
        .concurrent_updates(32)
        .post_init(_post_init)
        .post_shutdown(_post_shutdown)
        .build()
    )
    app.bot_data["engine"] = engine

    # Group 0: Commands & Callbacks & Membership/Service events
    app.add_handler(CommandHandler("start", cmd_start_private, filters=filters.ChatType.PRIVATE), group=0)
    app.add_handler(CommandHandler("start", cmd_start_group, filters=filters.ChatType.GROUPS), group=0)
    app.add_handler(CommandHandler("claim", cmd_claim, filters=filters.ChatType.PRIVATE), group=0)
    app.add_handler(
        MessageHandler(
            filters.ChatType.PRIVATE & ~filters.COMMAND,
            handle_private_owner_input,
        ),
        group=0,
    )
    app.add_handler(
        MessageHandler(
            filters.ChatType.GROUPS & filters.TEXT & ~filters.COMMAND,
            handle_group_admin_input,
        ),
        group=0,
    )
    app.add_handler(CommandHandler("config", cmd_config), group=0)
    app.add_handler(CommandHandler("settopic", cmd_settopic), group=0)
    app.add_handler(CommandHandler("antiraid", cmd_antiraid), group=0)
    app.add_handler(CommandHandler("trust", cmd_trust), group=0)
    app.add_handler(CommandHandler("untrust", cmd_untrust), group=0)
    app.add_handler(CommandHandler("sban", cmd_sban), group=0)
    app.add_handler(CommandHandler(["spam", "report"], cmd_report_spam), group=0)
    app.add_handler(CallbackQueryHandler(handle_callback), group=0)
    app.add_handler(ChatMemberHandler(engine.handle_my_chat_member, ChatMemberHandler.MY_CHAT_MEMBER), group=0)
    app.add_handler(ChatMemberHandler(engine.handle_chat_member, ChatMemberHandler.CHAT_MEMBER), group=0)
    app.add_handler(
        MessageHandler(
            filters.ChatType.GROUPS
            & (filters.StatusUpdate.NEW_CHAT_MEMBERS | filters.StatusUpdate.LEFT_CHAT_MEMBER),
            engine.handle_service_message,
        ),
        group=0,
    )

    # Group 1 (independent!): Group message & edited-message moderation.
    # Runs even if a non-admin sent a rejected admin command like "/config 广告"!
    app.add_handler(
        MessageHandler(
            filters.ChatType.GROUPS & ~filters.StatusUpdate.ALL,
            engine.handle_message,
        ),
        group=1,
    )

    logger.info("🛡 %s v%s 启动轮询...", __app_name_cn__, __version__)
    app.run_polling(
        allowed_updates=[
            Update.MESSAGE,
            Update.EDITED_MESSAGE,
            Update.CALLBACK_QUERY,
            Update.CHAT_MEMBER,
            Update.MY_CHAT_MEMBER,
        ],
        drop_pending_updates=True,
    )


if __name__ == "__main__":
    main()
