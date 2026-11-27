"""Crash-safe 1-tap emoji join captcha with finite Telegram mute deadlines & DB recovery."""

from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass
from typing import Any, Optional

from telegram import ChatPermissions, InlineKeyboardButton, InlineKeyboardMarkup, User
from telegram.error import TelegramError

from .storage import Storage

logger = logging.getLogger("adkiller.captcha")

FRUIT_CHOICES = [
    ("orange", "🍊 橘子"),
    ("apple", "🍎 苹果"),
    ("grape", "🍇 葡萄"),
    ("banana", "🍌 香蕉"),
    ("melon", "🍉 西瓜"),
    ("peach", "🍑 桃子"),
]

MUTE_PERMS = ChatPermissions(
    can_send_messages=False,
    can_send_audios=False,
    can_send_documents=False,
    can_send_photos=False,
    can_send_videos=False,
    can_send_video_notes=False,
    can_send_voice_notes=False,
    can_send_polls=False,
    can_send_other_messages=False,
    can_add_web_page_previews=False,
)

DEFAULT_UNMUTE_PERMS = ChatPermissions(
    can_send_messages=True,
    can_send_audios=True,
    can_send_documents=True,
    can_send_photos=True,
    can_send_videos=True,
    can_send_video_notes=True,
    can_send_voice_notes=True,
    can_send_polls=True,
    can_send_other_messages=True,
    can_add_web_page_previews=True,
)


@dataclass
class PendingCaptcha:
    chat_id: int
    user_id: int
    answer_key: str
    message_id: int
    expires_at: float
    task: Optional[asyncio.Task] = None


class SimpleCaptchaManager:
    """Zero-typing 1-tap button captcha with finite until_date and restart recovery."""

    def __init__(self, storage: Optional[Storage] = None, timeout_seconds: int = 90) -> None:
        self.storage = storage
        self.timeout_seconds = max(45, timeout_seconds)
        self.pending: dict[tuple[int, int], PendingCaptcha] = {}
        self._resolving: set[tuple[int, int]] = set()

    async def restore_pending(self, bot: Any) -> None:
        """Recover pending captchas from SQLite after bot restart so no user is stranded."""
        if not self.storage:
            return
        now = time.time()
        for row in self.storage.list_pending_captchas():
            entry = PendingCaptcha(
                chat_id=int(row["chat_id"]),
                user_id=int(row["user_id"]),
                answer_key=str(row["answer_key"]),
                message_id=int(row["message_id"]),
                expires_at=float(row["expires_at"]),
            )
            delay = max(0.0, entry.expires_at - now)
            self.pending[(entry.chat_id, entry.user_id)] = entry
            entry.task = asyncio.create_task(self._expire_after(bot, entry, delay))

    async def _restore_user_perms(self, bot: Any, chat_id: int, user_id: int) -> None:
        perms = DEFAULT_UNMUTE_PERMS
        try:
            chat_info = await bot.get_chat(chat_id)
            if getattr(chat_info, "permissions", None):
                perms = chat_info.permissions
        except TelegramError:
            pass
        await bot.restrict_chat_member(chat_id, user_id, permissions=perms)

    async def start_challenge(self, bot: Any, chat_id: int, user: User) -> None:
        key = (chat_id, user.id)
        if key in self.pending or key in self._resolving:
            return

        now = time.time()
        expires_at = now + self.timeout_seconds
        # Finite Telegram-side deadline (+60s safety buffer, well above Telegram's 30s forever cutoff)
        # Guarantees a user can NEVER be permanently muted even if the server crashes!
        mute_until = int(expires_at + 60)

        try:
            await bot.restrict_chat_member(
                chat_id, user.id, permissions=MUTE_PERMS, until_date=mute_until
            )
        except TelegramError as exc:
            logger.debug("入群验证禁言失败（可能缺少权限）chat=%s uid=%s: %s", chat_id, user.id, exc)
            return

        others = [c for c in FRUIT_CHOICES if c[0] != "orange"]
        sample = [("orange", "🍊 橘子")] + random.sample(others, 3)
        random.shuffle(sample)

        buttons = [
            InlineKeyboardButton(label, callback_data=f"cap:{chat_id}:{user.id}:{code}")
            for code, label in sample
        ]
        markup = InlineKeyboardMarkup([buttons[:2], buttons[2:]])

        prompt = (
            f"🍊 欢迎 {user.full_name}！\n"
            f"请在 {self.timeout_seconds} 秒内点击下方【🍊 橘子】按钮解除禁言（验证后本消息自动清理）："
        )
        try:
            sent = await bot.send_message(chat_id, prompt, reply_markup=markup)
        except TelegramError as exc:
            logger.warning("发送入群验证消息失败，立即回滚禁言 chat=%s: %s", chat_id, exc)
            try:
                await self._restore_user_perms(bot, chat_id, user.id)
            except TelegramError:
                pass
            return

        entry = PendingCaptcha(
            chat_id=chat_id,
            user_id=user.id,
            answer_key="orange",
            message_id=sent.message_id,
            expires_at=expires_at,
        )
        if self.storage:
            self.storage.save_captcha(chat_id, user.id, entry.answer_key, entry.message_id, expires_at)
        entry.task = asyncio.create_task(self._expire_after(bot, entry, float(self.timeout_seconds)))
        self.pending[key] = entry

    async def handle_answer(
        self, bot: Any, chat_id: int, target_uid: int, clicker_uid: int, choice: str
    ) -> tuple[bool, str]:
        if clicker_uid != target_uid:
            return False, "这不是你的验证按钮哦"

        key = (chat_id, target_uid)
        # Mutual exclusion: if either an answer or timeout is already executing network I/O, reject overlap
        if key in self._resolving:
            return False, "验证正在处理中，请稍候…"

        entry = self.pending.get(key)
        if not entry and self.storage:
            row = self.storage.get_captcha(chat_id, target_uid)
            if row:
                entry = PendingCaptcha(
                    chat_id=int(row["chat_id"]),
                    user_id=int(row["user_id"]),
                    answer_key=str(row["answer_key"]),
                    message_id=int(row["message_id"]),
                    expires_at=float(row["expires_at"]),
                )

        if not entry:
            return False, "验证已过期或已完成"

        if choice != entry.answer_key:
            return False, "点错啦，请点击【🍊 橘子】！"

        # Atomically claim ownership BEFORE the first await so _expire_after can NEVER race to kick
        self.pending.pop(key, None)
        self._resolving.add(key)
        prev_task = entry.task
        entry.task = None
        if prev_task and not prev_task.done():
            prev_task.cancel()

        try:
            # Unmute FIRST before clearing persistent state; if unmute fails, restore recoverable pending state
            try:
                await self._restore_user_perms(bot, chat_id, target_uid)
            except TelegramError as exc:
                logger.warning("解除验证禁言失败 chat=%s uid=%s: %s", chat_id, target_uid, exc)
                remaining = max(15.0, entry.expires_at - time.time())
                entry.expires_at = max(entry.expires_at, time.time() + remaining)
                self.pending[key] = entry
                if self.storage:
                    self.storage.save_captcha(
                        chat_id, target_uid, entry.answer_key, entry.message_id, entry.expires_at
                    )
                entry.task = asyncio.create_task(self._expire_after(bot, entry, remaining))
                return False, "解除禁言暂时失败，请稍后重试或联系管理员"

            if self.storage:
                self.storage.delete_captcha(chat_id, target_uid)

            try:
                await bot.delete_message(chat_id, entry.message_id)
            except TelegramError:
                pass

            return True, "🍊 验证通过，欢迎加入！"
        finally:
            self._resolving.discard(key)

    async def _expire_after(self, bot: Any, entry: PendingCaptcha, delay: float) -> None:
        try:
            if delay > 0:
                await asyncio.sleep(delay)
        except asyncio.CancelledError:
            return

        key = (entry.chat_id, entry.user_id)
        # Atomically claim ownership BEFORE any network await; abort if handle_answer already claimed or replaced it
        if key in self._resolving or self.pending.get(key) is not entry:
            return
        self.pending.pop(key, None)
        self._resolving.add(key)

        try:
            try:
                await bot.delete_message(entry.chat_id, entry.message_id)
            except TelegramError:
                pass
            try:
                # Finite Telegram-valid until_date (60s > Telegram's 30s permanent-ban cutoff)
                # guarantees a crash or unban error can NEVER turn a timeout soft-kick into a permanent ban!
                kick_until = int(time.time()) + 60
                await bot.ban_chat_member(entry.chat_id, entry.user_id, until_date=kick_until)
                await asyncio.sleep(1.0)
                await bot.unban_chat_member(entry.chat_id, entry.user_id, only_if_banned=True)
                logger.info("入群验证超时已软踢: chat=%s uid=%s", entry.chat_id, entry.user_id)
            except TelegramError as exc:
                logger.debug("超时踢出失败 chat=%s uid=%s: %s", entry.chat_id, entry.user_id, exc)
            finally:
                if self.storage:
                    self.storage.delete_captcha(entry.chat_id, entry.user_id)
        finally:
            self._resolving.discard(key)
