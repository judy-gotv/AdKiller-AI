"""Comprehensive unit & security regression tests for AI-智能广告杀手 v0.2.x."""

from __future__ import annotations

import asyncio
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from adkiller.captcha import SimpleCaptchaManager
from adkiller.cas import CASChecker
from adkiller.config import AppConfig
from adkiller.guard import (
    FloodTracker,
    GuardEngine,
    SpamFingerprintCache,
    SwarmTracker,
)
from adkiller.llm import SpamVerdict, UniversalAIClient, parse_verdict_json
from adkiller.prompts import SYSTEM_PROMPT
from adkiller.rules import evaluate_basic_rules
from adkiller.storage import Storage
from adkiller.xray import (
    _transcode_jpeg_sync,
    analyze_profile_risk,
    extract_xray,
    normalize_and_detect_obfuscation,
)


def _fake_msg(
    *,
    chat_id: int = -1001,
    msg_id: int = 10,
    user_id: int = 500,
    text: str = "hello world test message",
    sender_chat: object = None,
    entities: list | None = None,
    photo: list | None = None,
    document: object = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        chat=SimpleNamespace(id=chat_id, title="TestGroup", type="supergroup"),
        message_id=msg_id,
        from_user=(
            SimpleNamespace(id=user_id, full_name="Test User", first_name="Test", username="tuser", is_bot=False)
            if user_id
            else None
        ),
        sender_chat=sender_chat,
        is_automatic_forward=False,
        text=text,
        caption=None,
        entities=entities,
        caption_entities=None,
        link_preview_options=None,
        reply_markup=None,
        via_bot=None,
        external_reply=None,
        quote=None,
        reply_to_message=None,
        forward_origin=None,
        poll=None,
        story=None,
        paid_media=None,
        photo=photo,
        sticker=None,
        video=None,
        animation=None,
        document=document,
        media_group_id=None,
    )


class TestXRayExtractor(unittest.TestCase):
    def test_hidden_text_link_emoji_poll_malware_and_obfuscation(self) -> None:
        ent = SimpleNamespace(type="text_link", offset=2, length=3, url="https://t.me/spam_chan")
        msg = SimpleNamespace(
            text="🔥点这里 ｔ．ｍｅ 出\u200bU",
            caption=None,
            entities=[ent],
            caption_entities=None,
            link_preview_options=SimpleNamespace(url="https://spam.top/go"),
            reply_markup=SimpleNamespace(
                inline_keyboard=[
                    [SimpleNamespace(text="立即进入", url="https://t.me/+abc123", web_app=None, callback_data=None)]
                ]
            ),
            via_bot=SimpleNamespace(username="ad_inline_bot", full_name="AdBot"),
            external_reply=SimpleNamespace(
                origin=SimpleNamespace(chat=SimpleNamespace(title="灰产频道", username="gray_ch")),
                chat=None,
            ),
            quote=SimpleNamespace(text="日结500预付开工"),
            reply_to_message=None,
            forward_origin=None,
            sender_chat=SimpleNamespace(id=-100999, title="马甲广告频道", username="mask_ad"),
            chat=SimpleNamespace(id=-100111),
            poll=SimpleNamespace(question="免费领福利?", options=[SimpleNamespace(text="点我进群")]),
            story=None,
            paid_media=SimpleNamespace(star_count=50),
            photo=None,
            sticker=None,
            video=None,
            animation=None,
            document=SimpleNamespace(file_name="free_vpn.apk"),
        )

        xray = extract_xray(msg, is_edited=True)
        self.assertTrue(xray.is_edited)
        self.assertTrue(xray.has_risk_signal())
        self.assertIn("[点这里 -> https://t.me/spam_chan]", xray.hidden_links)
        self.assertIn("[网页预览隐藏链接 -> https://spam.top/go]", xray.hidden_links)
        self.assertIn("[立即进入 -> https://t.me/+abc123]", xray.inline_buttons)
        self.assertEqual(xray.via_bot, "@ad_inline_bot")
        self.assertIn("灰产频道", xray.external_reply)
        self.assertIn("免费领福利", xray.poll_info)
        self.assertIn("50 Stars", xray.special_payload)
        self.assertEqual(xray.dangerous_filename, "free_vpn.apk")
        self.assertTrue(any("零宽" in f for f in xray.obfuscation_flags))
        self.assertIn("t.me", xray.normalized_text)
        self.assertIn("出U", xray.normalized_text)

    def test_clean_chinese_text_has_no_obfuscation_flags(self) -> None:
        norm, flags = normalize_and_detect_obfuscation("请问今天怎么配置网络？谢谢！")
        self.assertEqual(flags, [])
        self.assertIn("配置网络", norm)

    def test_blank_two_part_random_latin_account_risk(self) -> None:
        spammer_profile = {
            "full_name": "aawsda sdawsda",
            "username": "(无)",
            "bio": "",
            "personal_channel": "",
            "has_photo": False,
        }
        flags, boost, is_max = analyze_profile_risk(spammer_profile, clean_count=0)
        self.assertTrue(is_max)
        self.assertEqual(boost, 21)
        self.assertTrue(any("两段随机/无意义字母" in f for f in flags))

        _, vet_boost, vet_max = analyze_profile_risk(spammer_profile, clean_count=10)
        self.assertTrue(vet_max)
        self.assertEqual(vet_boost, 21)

        latin_only = {
            "full_name": "John Smith",
            "username": "@johnsmith",
            "bio": "hello",
            "personal_channel": "",
            "has_photo": True,
        }
        _, l_boost, l_max = analyze_profile_risk(latin_only, clean_count=0)
        self.assertFalse(l_max)
        self.assertEqual(l_boost, 10)

        ordinary_tg_user = {
            "full_name": "小明",
            "username": "(无)",
            "bio": "",
            "personal_channel": "",
            "has_photo": False,
        }
        _, o_boost, o_max = analyze_profile_risk(ordinary_tg_user, clean_count=0)
        self.assertFalse(o_max)
        self.assertEqual(o_boost, 9)
        _, o_vet_boost, _ = analyze_profile_risk(ordinary_tg_user, clean_count=5)
        self.assertEqual(o_vet_boost, 0)

        normal_profile = {
            "full_name": "Kylin",
            "username": "@kylin",
            "bio": "Linux & VPS",
            "personal_channel": "",
            "has_photo": True,
        }
        n_flags, n_boost, n_max = analyze_profile_risk(normal_profile, clean_count=0)
        self.assertEqual(n_flags, [])
        self.assertEqual(n_boost, 0)
        self.assertFalse(n_max)


class TestSecurityReviewRegressions(unittest.TestCase):
    """Regression tests covering all 15 findings from the AI-智能广告杀手 security review."""

    def test_01_owner_claim_requires_secret_code_and_explicit_owner_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Storage(str(Path(tmp) / "t.db"))
            cfg = AppConfig(telegram_bot_token="t", ai_api_key="", owner_ids=set())
            llm = UniversalAIClient("", "https://example.com/v1", "")
            eng = GuardEngine(cfg, db, llm)

            # Random stranger cannot claim with bad code
            ok, _ = eng.try_claim_owner(99999, "wrong-code")
            self.assertFalse(ok)
            self.assertEqual(eng.get_owner_ids(), set())

            # Real deployer claims with one-time code, then code is invalidated
            secret = eng.claim_code
            self.assertIsNotNone(secret)
            ok2, _ = eng.try_claim_owner(10001, secret or "")
            self.assertTrue(ok2)
            self.assertEqual(eng.get_owner_ids(), {10001})
            ok3, _ = eng.try_claim_owner(20002, secret or "")
            self.assertFalse(ok3)

            # Later configuring explicit OWNER_IDS strictly replaces and wipes auto_owner_id!
            cfg2 = AppConfig(telegram_bot_token="t", ai_api_key="", owner_ids={88888})
            eng2 = GuardEngine(cfg2, db, llm)
            self.assertEqual(eng2.get_owner_ids(), {88888})
            self.assertNotIn(10001, eng2.get_owner_ids())
            self.assertIsNone(db.get_meta("auto_owner_id"))
            db.conn.close()

    def test_01b_claim_ttl_lockout_and_dm_rate_limit(self) -> None:
        from adkiller.panel import cmd_claim, cmd_start_private

        with tempfile.TemporaryDirectory() as tmp, Storage(str(Path(tmp) / "t2.db")) as db:
            cfg = AppConfig(telegram_bot_token="t", ai_api_key="sk-secret", ai_model="deepseek-flash", owner_ids=set())
            llm = UniversalAIClient("sk-secret", "https://example.com/v1", "deepseek-flash")
            eng = GuardEngine(cfg, db, llm)

            # 1. Expired claim code (> 15 min) is invalidated
            valid_code = eng.claim_code or ""
            ok_exp, _ = eng.try_claim_owner(1001, valid_code, now=eng.claim_expires_at + 1.0)
            self.assertFalse(ok_exp)
            self.assertIsNone(eng.claim_code)

            # 2. Per-requester 5-attempt lockout: locks ONLY attacker 2002, NEVER DoS-locks real deployer!
            eng2 = GuardEngine(cfg, db, llm)
            real_code = eng2.claim_code or ""
            for _ in range(5):
                ok_bad, _ = eng2.try_claim_owner(2002, "bad-guess")
                self.assertFalse(ok_bad)
            self.assertTrue(eng2.is_claim_locked_for(2002))
            self.assertIsNotNone(eng2.claim_code)
            # Locked attacker 2002 cannot claim even with real code, and cmd_claim silently drops them
            ok_locked, _ = eng2.try_claim_owner(2002, real_code)
            self.assertFalse(ok_locked)
            locked_replies: list[str] = []
            locked_msg = SimpleNamespace(
                chat=SimpleNamespace(id=2002, type="private"),
                reply_text=AsyncMock(side_effect=lambda t, **kw: locked_replies.append(t)),
            )
            asyncio.run(
                cmd_claim(
                    SimpleNamespace(message=locked_msg, effective_user=SimpleNamespace(id=2002)),
                    SimpleNamespace(args=[real_code], application=SimpleNamespace(bot_data={"engine": eng2})),
                )
            )
            self.assertEqual(locked_replies, [])

            # 3. Non-owner private /start leaks ZERO internal state & obeys per-user + global rate limits
            replies: list[str] = []
            msg = SimpleNamespace(
                chat=SimpleNamespace(id=3003, type="private"),
                reply_text=AsyncMock(side_effect=lambda t, **kw: replies.append(t)),
            )
            upd = SimpleNamespace(message=msg, effective_user=SimpleNamespace(id=3003))
            ctx = SimpleNamespace(application=SimpleNamespace(bot_data={"engine": eng2}))
            asyncio.run(cmd_start_private(upd, ctx))
            asyncio.run(cmd_start_private(upd, ctx))  # Second immediate call dropped by 10s cooldown!
            self.assertEqual(len(replies), 1)
            self.assertIn("3003", replies[0])
            self.assertNotIn("deepseek-flash", replies[0])
            self.assertNotIn("claim", replies[0].lower())
            self.assertNotIn("未绑定", replies[0])

            # Global DM budget caps distributed flood (20/min)
            for uid in range(5000, 5030):
                eng2.allow_dm_reply(uid, now=5000.0)
            self.assertFalse(eng2.allow_dm_reply(9999, now=5001.0))

            # Real deployer (uid=7777) CAN still claim successfully despite attacker 2002's 5 bad tries!
            ok_deployer, _ = eng2.try_claim_owner(7777, real_code)
            self.assertTrue(ok_deployer)
            self.assertEqual(eng2.get_owner_ids(), {7777})
            self.assertIsNone(eng2.claim_code)

            # Once bound, inactive /claim silently drops with ZERO reply & ZERO API calls
            claim_replies: list[str] = []
            claim_msg = SimpleNamespace(
                chat=SimpleNamespace(id=3004, type="private"),
                reply_text=AsyncMock(side_effect=lambda t, **kw: claim_replies.append(t)),
            )
            claim_upd = SimpleNamespace(message=claim_msg, effective_user=SimpleNamespace(id=3004))
            claim_ctx = SimpleNamespace(args=["anything"], application=SimpleNamespace(bot_data={"engine": eng2}))
            asyncio.run(cmd_claim(claim_upd, claim_ctx))
            self.assertEqual(claim_replies, [])

    def test_02_per_chat_composite_spam_cache_isolation_and_threshold(self) -> None:
        cache = SpamFingerprintCache(ttl_seconds=300)
        xray_mixed = extract_xray(_fake_msg(chat_id=-1001, text="这是一段推广广告文案超过十六个字"))
        xray_text_only = extract_xray(_fake_msg(chat_id=-1001, text="这是一段推广广告文案超过十六个字"))
        xray_group_b = extract_xray(_fake_msg(chat_id=-1002, text="这是一段推广广告文案超过十六个字"))
        img = "data:image/jpeg;base64,ABCDEF"

        fp_combo = cache.fingerprint_message(-1001, xray_mixed, img)
        fp_txt_a = cache.fingerprint_message(-1001, xray_text_only, None)
        fp_img_a = cache.fingerprint_message(-1001, extract_xray(_fake_msg(chat_id=-1001, text="")), img)
        fp_combo_b = cache.fingerprint_message(-1002, xray_group_b, img)

        cache.remember(fp_combo, 82, "图文广告", now=100.0)
        # Same group, exact combo hits at threshold 80
        self.assertIsNotNone(cache.lookup(fp_combo, min_score=80, now=110.0))
        # Raising threshold to 90 invalidates 82-score entry
        self.assertIsNone(cache.lookup(fp_combo, min_score=90, now=110.0))
        # Standalone text or standalone image does NOT hit combo verdict!
        self.assertIsNone(cache.lookup(fp_txt_a, min_score=80, now=110.0))
        self.assertIsNone(cache.lookup(fp_img_a, min_score=80, now=110.0))
        # Group B NEVER hits Group A's cache!
        self.assertIsNone(cache.lookup(fp_combo_b, min_score=80, now=110.0))

    def test_03_and_12_swarm_tracker_bounded_and_never_auto_bans_earlier_users(self) -> None:
        swarm = SwarmTracker(window_seconds=60, min_distinct_actors=3, max_keys=3)
        for i in range(5):
            swarm.record_and_check(-1001, f"k{i}", 1, i, now=100.0 + i)
        self.assertLessEqual(len(swarm._events), 3)

        # Verify handle_message only bans current actor, sends review card for earlier actors
        with tempfile.TemporaryDirectory() as tmp:
            db = Storage(str(Path(tmp) / "swarm.db"))
            cfg = AppConfig(telegram_bot_token="t", ai_api_key="", owner_ids={999})
            llm = UniversalAIClient("", "https://example.com/v1", "")
            eng = GuardEngine(cfg, db, llm)
            gs = eng.get_group_settings(-1001, "G")
            gs.cas_enabled = False
            gs.local_rules_enabled = True
            db.save_group(gs)

            bot = SimpleNamespace(
                id=1,
                get_chat_administrators=AsyncMock(return_value=[]),
                get_chat=AsyncMock(return_value=SimpleNamespace(photo=object(), bio="", personal_chat=None, linked_chat_id=None)),
                delete_message=AsyncMock(),
                ban_chat_member=AsyncMock(),
                send_message=AsyncMock(),
            )
            ctx = SimpleNamespace(bot=bot)

            # Seed 2 earlier accounts with same spam fingerprint in SwarmTracker
            spam_text = "预付开工 日结500 帮发消息 做的联系"
            m3 = _fake_msg(chat_id=-1001, msg_id=30, user_id=300, text=spam_text)
            fp = eng.spam_cache.fingerprint_message(-1001, extract_xray(m3), None)
            eng.swarm.record_and_check(-1001, fp, 100, 10)
            eng.swarm.record_and_check(-1001, fp, 200, 20)

            upd = SimpleNamespace(edited_message=None, message=m3)
            asyncio.run(eng.handle_message(upd, ctx))

            # Only actor 300 should be banned; actors 100 and 200 MUST NOT be auto-banned!
            banned_uids = [call.args[1] for call in bot.ban_chat_member.call_args_list]
            self.assertEqual(banned_uids, [300])
            # Admin should receive a swarm review card mentioning 100 & 200
            sent_texts = [call.args[1] for call in bot.send_message.call_args_list]
            self.assertTrue(any("逐人复核" in t and "100" in t and "200" in t for t in sent_texts))
            db.conn.close()

    def test_04_and_05_granular_admin_rights_and_demotion_revokes_log_chat(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Storage(str(Path(tmp) / "adm.db"))
            cfg = AppConfig(telegram_bot_token="t", ai_api_key="", owner_ids={999})
            llm = UniversalAIClient("", "https://example.com/v1", "")
            eng = GuardEngine(cfg, db, llm)
            gs = eng.get_group_settings(-1001, "G")
            gs.log_chat_id = 555
            db.save_group(gs)

            # Limited admin (no can_restrict_members) cannot pass require_restrict=True
            limited_member = SimpleNamespace(
                status="administrator", can_delete_messages=True, can_restrict_members=False
            )
            bot = SimpleNamespace(get_chat_member=AsyncMock(return_value=limited_member))
            ok = asyncio.run(
                eng.check_admin_perm(bot, -1001, 555, require_delete=True, require_restrict=True, fresh=True)
            )
            self.assertFalse(ok)

            # resolve_log_chat auto-revokes demoted admin's DM log subscription and falls back to owner 999
            resolved = asyncio.run(eng.resolve_log_chat(bot, eng.get_group_settings(-1001)))
            self.assertEqual(resolved, 999)
            self.assertIsNone(eng.get_group_settings(-1001).log_chat_id)
            db.conn.close()

    def test_06_and_07_allowed_group_ids_and_rejected_command_still_moderated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Storage(str(Path(tmp) / "g67.db"))
            cfg = AppConfig(
                telegram_bot_token="t",
                ai_api_key="",
                owner_ids={999},
                allowed_group_ids={-1001},
            )
            llm = UniversalAIClient("", "https://example.com/v1", "")
            eng = GuardEngine(cfg, db, llm)
            self.assertTrue(eng.is_group_allowed(-1001))
            self.assertFalse(eng.is_group_allowed(-1002))

            # Non-admin sends rejected "/config 预付开工 日结500 帮发消息" -> NOT marked handled -> moderated in group 1!
            gs = eng.get_group_settings(-1001, "G")
            gs.cas_enabled = False
            gs.local_rules_enabled = True
            db.save_group(gs)

            spam_cmd = _fake_msg(chat_id=-1001, msg_id=71, user_id=404, text="/config 预付开工 日结500 帮发消息 私聊我")
            bot = SimpleNamespace(
                id=1,
                get_chat_administrators=AsyncMock(return_value=[]),
                get_chat=AsyncMock(return_value=SimpleNamespace(photo=object(), bio="", personal_chat=None, linked_chat_id=None)),
                delete_message=AsyncMock(),
                ban_chat_member=AsyncMock(),
                send_message=AsyncMock(),
            )
            asyncio.run(eng.handle_message(SimpleNamespace(edited_message=None, message=spam_cmd), SimpleNamespace(bot=bot)))
            bot.ban_chat_member.assert_called_once()

            # Authorized command IS marked handled -> skipped by group 1 moderation!
            ok_cmd = _fake_msg(chat_id=-1001, msg_id=72, user_id=405, text="/config 预付开工 日结500 帮发消息 私聊我")
            eng.mark_command_handled(-1001, 72)
            bot.ban_chat_member.reset_mock()
            asyncio.run(eng.handle_message(SimpleNamespace(edited_message=None, message=ok_cmd), SimpleNamespace(bot=bot)))
            bot.ban_chat_member.assert_not_called()
            db.conn.close()

    def test_08_captcha_finite_mute_rollback_and_unmute_failure(self) -> None:
        from telegram.error import Forbidden

        with tempfile.TemporaryDirectory() as tmp, Storage(str(Path(tmp) / "cap.db")) as db:
            cap = SimpleCaptchaManager(storage=db, timeout_seconds=90)
            user = SimpleNamespace(id=77, full_name="Newbie")

            # Prompt send failure -> immediately rolls back mute
            bot_fail_send = SimpleNamespace(
                restrict_chat_member=AsyncMock(),
                send_message=AsyncMock(side_effect=Forbidden("cannot send")),
                get_chat=AsyncMock(return_value=SimpleNamespace(permissions=None)),
            )
            asyncio.run(cap.start_challenge(bot_fail_send, -1001, user))
            self.assertEqual(bot_fail_send.restrict_chat_member.call_count, 2)
            # First call had finite until_date
            self.assertIn("until_date", bot_fail_send.restrict_chat_member.call_args_list[0].kwargs)

            # Unmute failure during handle_answer -> must NOT falsely claim success or drop state!
            db.save_captcha(-1001, 77, "orange", 501, time.time() + 60)
            bot_fail_unmute = SimpleNamespace(
                get_chat=AsyncMock(return_value=SimpleNamespace(permissions=None)),
                restrict_chat_member=AsyncMock(side_effect=Forbidden("no rights")),
                delete_message=AsyncMock(),
            )
            ok, msg = asyncio.run(cap.handle_answer(bot_fail_unmute, -1001, 77, 77, "orange"))
            self.assertFalse(ok)
            self.assertIn("失败", msg)
            self.assertIsNotNone(db.get_captcha(-1001, 77))

    def test_09_antiraid_skips_restrict_when_remaining_under_45s(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Storage(str(Path(tmp) / "raid.db"))
            cfg = AppConfig(telegram_bot_token="t", ai_api_key="", owner_ids={999})
            llm = UniversalAIClient("", "https://example.com/v1", "")
            eng = GuardEngine(cfg, db, llm)
            gs = eng.get_group_settings(-1001, "G")
            gs.antiraid_until = time.time() + 20  # < 45s remaining -> must NOT restrict!
            db.save_group(gs)

            bot = SimpleNamespace(restrict_chat_member=AsyncMock())
            upd = SimpleNamespace(
                chat_member=SimpleNamespace(
                    chat=SimpleNamespace(id=-1001, title="G", type="supergroup"),
                    old_chat_member=SimpleNamespace(status="left", user=SimpleNamespace(id=50, is_bot=False, full_name="U")),
                    new_chat_member=SimpleNamespace(status="member", user=SimpleNamespace(id=50, is_bot=False, full_name="U")),
                )
            )
            asyncio.run(eng.handle_chat_member(upd, SimpleNamespace(bot=bot)))
            bot.restrict_chat_member.assert_not_called()
            db.conn.close()

    def test_10_channel_gray_zone_only_deletes_never_bans(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Storage(str(Path(tmp) / "ch.db"))
            cfg = AppConfig(telegram_bot_token="t", ai_api_key="", owner_ids={999})
            llm = UniversalAIClient("", "https://example.com/v1", "")
            eng = GuardEngine(cfg, db, llm)
            gs = eng.get_group_settings(-1001, "G")

            ch_msg = _fake_msg(
                chat_id=-1001,
                msg_id=88,
                user_id=0,
                text="可疑频道灰区消息",
                sender_chat=SimpleNamespace(id=-100999, title="某频道", username="some_ch"),
            )
            bot = SimpleNamespace(
                delete_message=AsyncMock(),
                ban_chat_sender_chat=AsyncMock(),
                send_message=AsyncMock(),
            )
            asyncio.run(
                eng.enforce_action(
                    bot,
                    ch_msg,
                    gs,
                    action="mute_review",
                    trigger_type="gray_zone",
                    score=72,
                    reason="灰区",
                    xray=extract_xray(ch_msg),
                    profile={},
                )
            )
            bot.delete_message.assert_called_once()
            bot.ban_chat_sender_chat.assert_not_called()
            db.conn.close()

    def test_11_malformed_llm_json_raises_and_falls_back_without_clean_credit(self) -> None:
        with self.assertRaises(ValueError):
            parse_verdict_json("")
        with self.assertRaises(ValueError):
            parse_verdict_json("not valid json at all")

        with tempfile.TemporaryDirectory() as tmp:
            db = Storage(str(Path(tmp) / "llmerr.db"))
            cfg = AppConfig(telegram_bot_token="t", ai_api_key="sk-test", ai_model="deepseek-flash", owner_ids={999})
            llm = UniversalAIClient("sk-test", "https://example.com/v1", "deepseek-flash")
            bad_resp = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=""))])
            llm.client = SimpleNamespace(
                chat=SimpleNamespace(completions=SimpleNamespace(create=AsyncMock(return_value=bad_resp)))
            )
            eng = GuardEngine(cfg, db, llm)
            gs = eng.get_group_settings(-1001, "G")
            gs.cas_enabled = False
            db.save_group(gs)

            bot = SimpleNamespace(
                id=1,
                get_chat_administrators=AsyncMock(return_value=[]),
                get_chat=AsyncMock(return_value=SimpleNamespace(photo=object(), bio="", personal_chat=None, linked_chat_id=None)),
                delete_message=AsyncMock(),
                ban_chat_member=AsyncMock(),
                send_message=AsyncMock(),
            )
            m = _fake_msg(chat_id=-1001, msg_id=41, user_id=701, text="普通测试消息内容够长触发AI")
            asyncio.run(eng.handle_message(SimpleNamespace(edited_message=None, message=m), SimpleNamespace(bot=bot)))

            self.assertEqual(db.get_today_metrics(-1001)["ai_errors"], 1)
            # Clean count MUST NOT increment on AI failure!
            self.assertEqual(db.get_clean_count(-1001, 701), 0)
            db.conn.close()

    def test_14_cas_429_uses_short_error_cache_not_24h(self) -> None:
        cas = CASChecker(ttl_seconds=86400, error_ttl_seconds=60)
        resp_429 = SimpleNamespace(status_code=429, json=lambda: {})
        resp_banned = SimpleNamespace(status_code=200, json=lambda: {"ok": True})
        mock_get = AsyncMock(side_effect=[resp_429, resp_banned])
        cas._client = SimpleNamespace(is_closed=False, get=mock_get)

        self.assertFalse(asyncio.run(cas.is_banned(12345, now=1000.0)))
        # Still inside 60s error cooldown -> cached False
        self.assertFalse(asyncio.run(cas.is_banned(12345, now=1030.0)))
        # After 60s cooldown expires -> re-queries and catches banned user!
        self.assertTrue(asyncio.run(cas.is_banned(12345, now=1070.0)))

    def test_15_ban_failure_does_not_announce_success_in_group(self) -> None:
        from telegram.error import Forbidden

        with tempfile.TemporaryDirectory() as tmp, Storage(str(Path(tmp) / "bf.db")) as db:
            cfg = AppConfig(telegram_bot_token="t", ai_api_key="", owner_ids={999})
            llm = UniversalAIClient("", "https://example.com/v1", "")
            eng = GuardEngine(cfg, db, llm)
            gs = eng.get_group_settings(-1001, "G")
            gs.announce_in_group = True
            db.save_group(gs)

            m = _fake_msg(chat_id=-1001, msg_id=99, user_id=666, text="垃圾广告")
            bot = SimpleNamespace(
                delete_message=AsyncMock(),
                ban_chat_member=AsyncMock(side_effect=Forbidden("Not enough rights")),
                send_message=AsyncMock(),
            )
            asyncio.run(
                eng.enforce_action(
                    bot,
                    m,
                    gs,
                    action="ban",
                    trigger_type="ai_text",
                    score=95,
                    reason="广告",
                    xray=extract_xray(m),
                    profile={},
                )
            )
            # Only log DM to owner 999 should be sent, NEVER a fake success announcement in group -1001!
            group_announcements = [c for c in bot.send_message.call_args_list if c.args[0] == -1001]
            self.assertEqual(group_announcements, [])

    def test_16_same_group_profile_or_history_never_poisons_spam_cache(self) -> None:
        from adkiller.llm import SpamVerdict

        with tempfile.TemporaryDirectory() as tmp:
            db = Storage(str(Path(tmp) / "iso_same.db"))
            cfg = AppConfig(telegram_bot_token="t", ai_api_key="sk-test", ai_model="test-m", owner_ids={999})
            llm = UniversalAIClient("sk-test", "https://example.com/v1", "test-m")

            seen_prompts: list[str] = []

            async def fake_classify(*, summary_text: str, **kw) -> SpamVerdict:
                seen_prompts.append(summary_text)
                if "色粉福利群" in summary_text:
                    return SpamVerdict(is_spam=True, score=92, reason="资料含色粉引流")
                if "独家渠道对接项目" in summary_text:
                    return SpamVerdict(is_spam=True, score=94, reason="纯内容推广广告")
                return SpamVerdict(is_spam=False, score=5, reason="正常聊天")

            llm.classify = fake_classify  # type: ignore[method-assign]
            eng = GuardEngine(cfg, db, llm)
            gs = eng.get_group_settings(-1001, "G")
            gs.cas_enabled = False
            gs.first_message_only = False
            db.save_group(gs)

            async def fake_get_chat(uid: int):
                if uid == 101:
                    return SimpleNamespace(photo=object(), bio="色粉福利群 t.me/+spam", personal_chat=None)
                return SimpleNamespace(photo=object(), bio="", personal_chat=None)

            bot = SimpleNamespace(
                id=1,
                get_chat_administrators=AsyncMock(return_value=[]),
                get_chat=AsyncMock(side_effect=fake_get_chat),
                delete_message=AsyncMock(),
                ban_chat_member=AsyncMock(),
                send_message=AsyncMock(),
            )
            ctx = SimpleNamespace(bot=bot)

            # Part A: Member 101 has spam bio + neutral text -> banned, MUST NOT poison shared spam_cache!
            neutral_text = "今天天气真不错大家吃午饭了吗聊一聊"
            m_a = _fake_msg(chat_id=-1001, msg_id=10, user_id=101, text=neutral_text)
            asyncio.run(eng.handle_message(SimpleNamespace(edited_message=None, message=m_a), ctx))
            banned_after_a = [c.args[1] for c in bot.ban_chat_member.call_args_list]
            self.assertEqual(banned_after_a, [101])

            # Innocent Member 202 posts identical neutral text -> MUST undergo per-person review & NOT be banned!
            m_b = _fake_msg(chat_id=-1001, msg_id=11, user_id=202, text=neutral_text)
            asyncio.run(eng.handle_message(SimpleNamespace(edited_message=None, message=m_b), ctx))
            banned_after_b = [c.args[1] for c in bot.ban_chat_member.call_args_list]
            self.assertEqual(banned_after_b, [101])

            # Part B: Two distinct bots post pure standalone ad -> 2nd hit runs pure-content-only AI check
            # (with ZERO profile/bio/fragments/context) and promotes cache so 3rd bot hits cache at 0 AI calls!
            seen_prompts.clear()
            ad_text = "独家渠道对接项目优质资源欢迎咨询合作细节"
            m_c1 = _fake_msg(chat_id=-1001, msg_id=21, user_id=301, text=ad_text)
            m_c2 = _fake_msg(chat_id=-1001, msg_id=22, user_id=302, text=ad_text)
            m_c3 = _fake_msg(chat_id=-1001, msg_id=23, user_id=303, text=ad_text)
            asyncio.run(eng.handle_message(SimpleNamespace(edited_message=None, message=m_c1), ctx))
            asyncio.run(eng.handle_message(SimpleNamespace(edited_message=None, message=m_c2), ctx))
            self.assertEqual(len(seen_prompts), 3)  # bot1 + bot2 + pure-content-only verification
            self.assertIn("纯消息内容独立复核", seen_prompts[-1])
            self.assertNotIn("发件人资料", seen_prompts[-1])
            self.assertNotIn("群内最近聊天上下文", seen_prompts[-1])
            # 3rd bot hits pure-content spam_cache with ZERO extra LLM call!
            asyncio.run(eng.handle_message(SimpleNamespace(edited_message=None, message=m_c3), ctx))
            self.assertEqual(len(seen_prompts), 3)
            self.assertIn(303, [c.args[1] for c in bot.ban_chat_member.call_args_list])

            # Part C: Opt-in local keyword mode — bio-contaminated rule ban MUST NOT poison shared spam_cache
            gs.local_rules_enabled = True
            db.save_group(gs)
            llm_off = UniversalAIClient("", "https://example.com/v1", "")
            eng_off = GuardEngine(AppConfig(telegram_bot_token="t", ai_api_key="", owner_ids={999}), db, llm_off)
            bot_off = SimpleNamespace(
                id=1,
                get_chat_administrators=AsyncMock(return_value=[]),
                get_chat=AsyncMock(
                    side_effect=lambda uid: SimpleNamespace(
                        photo=object(),
                        bio="色粉福利群 预付开工 日结500" if uid == 401 else "",
                        personal_chat=None,
                    )
                ),
                delete_message=AsyncMock(),
                ban_chat_member=AsyncMock(),
                send_message=AsyncMock(),
            )
            m_z1 = _fake_msg(chat_id=-1001, msg_id=31, user_id=401, text=neutral_text)
            m_z2 = _fake_msg(chat_id=-1001, msg_id=32, user_id=402, text=neutral_text)
            asyncio.run(eng_off.handle_message(SimpleNamespace(edited_message=None, message=m_z1), SimpleNamespace(bot=bot_off)))
            asyncio.run(eng_off.handle_message(SimpleNamespace(edited_message=None, message=m_z2), SimpleNamespace(bot=bot_off)))
            self.assertEqual([c.args[1] for c in bot_off.ban_chat_member.call_args_list], [401])
            db.conn.close()

    def test_17_captcha_pass_and_timeout_are_mutually_exclusive(self) -> None:
        from adkiller.captcha import PendingCaptcha

        async def _scenario() -> None:
            with tempfile.TemporaryDirectory() as tmp:
                db = Storage(str(Path(tmp) / "race.db"))
                cap = SimpleCaptchaManager(storage=db, timeout_seconds=90)

                # Case A: handle_answer claims first, pauses during unmute await; timeout wakes up -> MUST NOT kick!
                in_unmute = asyncio.Event()
                release_unmute = asyncio.Event()

                async def slow_unmute(*args, **kwargs):
                    in_unmute.set()
                    await release_unmute.wait()

                bot = SimpleNamespace(
                    get_chat=AsyncMock(return_value=SimpleNamespace(permissions=None)),
                    restrict_chat_member=AsyncMock(side_effect=slow_unmute),
                    delete_message=AsyncMock(),
                    ban_chat_member=AsyncMock(),
                    unban_chat_member=AsyncMock(),
                )
                entry = PendingCaptcha(
                    chat_id=-1001, user_id=88, answer_key="orange", message_id=701, expires_at=time.time() + 10
                )
                cap.pending[(-1001, 88)] = entry
                db.save_captcha(-1001, 88, "orange", 701, entry.expires_at)

                ans_task = asyncio.create_task(cap.handle_answer(bot, -1001, 88, 88, "orange"))
                await in_unmute.wait()
                # Timeout fires while unmute is in flight
                await cap._expire_after(bot, entry, 0.0)
                release_unmute.set()
                ok, _ = await ans_task
                self.assertTrue(ok)
                bot.ban_chat_member.assert_not_called()

                # Case B: timeout claims first, pauses during ban; user clicks button -> MUST NOT unmute/pass!
                in_ban = asyncio.Event()
                release_ban = asyncio.Event()

                async def slow_ban(*args, **kwargs):
                    in_ban.set()
                    await release_ban.wait()

                bot2 = SimpleNamespace(
                    get_chat=AsyncMock(return_value=SimpleNamespace(permissions=None)),
                    restrict_chat_member=AsyncMock(),
                    delete_message=AsyncMock(),
                    ban_chat_member=AsyncMock(side_effect=slow_ban),
                    unban_chat_member=AsyncMock(),
                )
                entry2 = PendingCaptcha(
                    chat_id=-1001, user_id=89, answer_key="orange", message_id=702, expires_at=time.time() + 10
                )
                cap.pending[(-1001, 89)] = entry2
                db.save_captcha(-1001, 89, "orange", 702, entry2.expires_at)

                exp_task = asyncio.create_task(cap._expire_after(bot2, entry2, 0.0))
                await in_ban.wait()
                ok2, _ = await cap.handle_answer(bot2, -1001, 89, 89, "orange")
                release_ban.set()
                await exp_task
                self.assertFalse(ok2)
                bot2.restrict_chat_member.assert_not_called()
                db.conn.close()

        asyncio.run(_scenario())

    def test_18_per_member_indices_and_report_counts_are_bounded_and_pruned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Storage(str(Path(tmp) / "mem.db"))
            cfg = AppConfig(telegram_bot_token="t", ai_api_key="", owner_ids={999})
            llm = UniversalAIClient("", "https://example.com/v1", "")
            eng = GuardEngine(cfg, db, llm)

            # FloodTracker outer dict bounded
            flood = FloodTracker(max_keys=5)
            for uid in range(1, 20):
                flood.record_and_check(-1001, uid, uid, None, window_seconds=10, max_messages=5, now=1000.0 + uid)
            self.assertLessEqual(len(flood._buckets), 5)

            # recent_msgs and user_fragments outer dicts bounded; reading empty fragment doesn't allocate key
            self.assertEqual(eng.get_user_recent_fragments(-1001, 99999), ([], []))
            self.assertNotIn((-1001, 99999), eng.user_fragments)
            for uid in range(1, 20):
                eng.record_recent_msg(-1001, uid, uid, now=1000.0 + uid, max_keys=5)
                eng.record_user_fragment(-1001, uid, uid, "hello", now=1000.0 + uid, max_keys=5)
            self.assertLessEqual(len(eng.recent_msgs), 5)
            self.assertLessEqual(len(eng.user_fragments), 5)

            # report_counts evicts previous day completely on date rollover & obeys max_entries
            for uid in range(1, 10):
                self.assertTrue(eng.check_and_inc_report_count(-1001, uid, day="2026-11-22", max_entries=5))
            self.assertLessEqual(len(eng.report_counts), 5)
            self.assertTrue(eng.check_and_inc_report_count(-1001, 50, day="2026-11-23", max_entries=5))
            self.assertEqual(list(eng.report_counts.keys()), [(-1001, 50, "2026-11-23")])
            db.conn.close()

    def test_19_transient_telegram_error_does_not_wipe_log_chat_binding(self) -> None:
        from telegram.error import TelegramError

        with tempfile.TemporaryDirectory() as tmp:
            db = Storage(str(Path(tmp) / "logbind.db"))
            cfg = AppConfig(telegram_bot_token="t", ai_api_key="", owner_ids={999})
            llm = UniversalAIClient("", "https://example.com/v1", "")
            eng = GuardEngine(cfg, db, llm)
            gs = eng.get_group_settings(-1001, "G")
            gs.log_chat_id = 4001
            db.save_group(gs)

            # 1. Transient TelegramError -> pause DM delivery to 4001, MUST NOT wipe DB binding!
            bot_err = SimpleNamespace(get_chat_member=AsyncMock(side_effect=TelegramError("network timeout")))
            dest = asyncio.run(eng.resolve_log_chat(bot_err, gs))
            self.assertEqual(dest, 999)  # falls back to owner for this call
            self.assertEqual(gs.log_chat_id, 4001)
            self.assertEqual(eng.get_group_settings(-1001, "G").log_chat_id, 4001)

            # 2. After recovery -> valid admin resumes receiving logs automatically!
            bot_ok = SimpleNamespace(
                get_chat_member=AsyncMock(
                    return_value=SimpleNamespace(status="administrator", can_restrict_members=True)
                )
            )
            self.assertEqual(asyncio.run(eng.resolve_log_chat(bot_ok, gs)), 4001)

            # 3. Confirmed demotion -> binding IS revoked and persisted as None!
            bot_demoted = SimpleNamespace(
                get_chat_member=AsyncMock(return_value=SimpleNamespace(status="member"))
            )
            self.assertEqual(asyncio.run(eng.resolve_log_chat(bot_demoted, gs)), 999)
            self.assertIsNone(eng.get_group_settings(-1001, "G").log_chat_id)
            db.conn.close()

    def test_20_captcha_timeout_kick_uses_finite_until_date(self) -> None:
        from adkiller.captcha import PendingCaptcha
        from telegram.error import TelegramError

        with tempfile.TemporaryDirectory() as tmp:
            db = Storage(str(Path(tmp) / "kick.db"))
            cap = SimpleCaptchaManager(storage=db, timeout_seconds=90)
            entry = PendingCaptcha(
                chat_id=-1001, user_id=77, answer_key="orange", message_id=901, expires_at=time.time() - 1
            )
            cap.pending[(-1001, 77)] = entry
            db.save_captcha(-1001, 77, "orange", 901, entry.expires_at)

            # Simulate unban failure / outage right after ban_chat_member
            bot = SimpleNamespace(
                delete_message=AsyncMock(),
                ban_chat_member=AsyncMock(),
                unban_chat_member=AsyncMock(side_effect=TelegramError("connection lost")),
            )
            before = int(time.time())
            asyncio.run(cap._expire_after(bot, entry, 0.0))

            bot.ban_chat_member.assert_awaited_once()
            until_date = bot.ban_chat_member.call_args.kwargs.get("until_date")
            self.assertIsNotNone(until_date)
            self.assertGreaterEqual(until_date, before + 45)
            self.assertLessEqual(until_date, before + 300)
            self.assertIsNone(db.get_captcha(-1001, 77))
            db.conn.close()

    def test_21_owner_private_ai_config_hot_reload_persistence_and_access_control(self) -> None:
        import sqlite3
        from adkiller.llm import ProbeReport
        from adkiller.panel import (
            _validate_base_url,
            handle_callback,
            handle_private_owner_input,
        )

        # URL validation: remote MUST be HTTPS; HTTP allowed ONLY on explicit local loopback hosts
        self.assertIsNone(_validate_base_url("javascript:alert(1)"))
        self.assertIsNone(_validate_base_url("ftp://example.com/v1"))
        self.assertIsNone(_validate_base_url("https://bad host/v1"))
        self.assertIsNone(_validate_base_url("http://api.example.com/v1"))
        self.assertIsNone(_validate_base_url("http://1.2.3.4:8080/v1"))
        self.assertEqual(_validate_base_url("https://api.deepseek.com/v1"), "https://api.deepseek.com/v1")
        self.assertEqual(_validate_base_url("http://localhost:11434/v1"), "http://localhost:11434/v1")
        self.assertEqual(_validate_base_url("http://127.0.0.1:8000/v1"), "http://127.0.0.1:8000/v1")
        self.assertEqual(_validate_base_url("http://host.docker.internal:3000/v1"), "http://host.docker.internal:3000/v1")

        with tempfile.TemporaryDirectory() as tmp, Storage(str(Path(tmp) / "aiconf.db")) as db:
            cfg_empty_ai = AppConfig(telegram_bot_token="t", ai_api_key="", owner_ids={999})
            llm = UniversalAIClient("", cfg_empty_ai.ai_base_url, cfg_empty_ai.ai_model)
            eng = GuardEngine(cfg_empty_ai, db, llm)
            ctx = SimpleNamespace(application=SimpleNamespace(bot_data={"engine": eng}))

            # 1. Non-owner clicking aiconf:* in private chat is rejected
            q_stranger = SimpleNamespace(
                data="aiconf:preset:openai",
                from_user=SimpleNamespace(id=12345),
                message=SimpleNamespace(chat=SimpleNamespace(id=12345, type="private")),
                answer=AsyncMock(),
                edit_message_text=AsyncMock(),
            )
            asyncio.run(handle_callback(SimpleNamespace(callback_query=q_stranger), ctx))
            q_stranger.edit_message_text.assert_not_called()
            self.assertEqual(eng.llm.model, cfg_empty_ai.ai_model)

            # 2. Owner clicking aiconf:* inside a GROUP chat is rejected (private DM only!)
            q_group = SimpleNamespace(
                data="aiconf:preset:openai",
                from_user=SimpleNamespace(id=999),
                message=SimpleNamespace(chat=SimpleNamespace(id=-1001, type="supergroup")),
                answer=AsyncMock(),
                edit_message_text=AsyncMock(),
            )
            asyncio.run(handle_callback(SimpleNamespace(callback_query=q_group), ctx))
            q_group.edit_message_text.assert_not_called()

            # 3. Owner selects OpenAI preset then clicks ask:api_key in private chat
            q_preset = SimpleNamespace(
                data="aiconf:preset:openai",
                from_user=SimpleNamespace(id=999),
                message=SimpleNamespace(chat=SimpleNamespace(id=999, type="private")),
                answer=AsyncMock(),
                edit_message_text=AsyncMock(),
            )
            asyncio.run(handle_callback(SimpleNamespace(callback_query=q_preset), ctx))
            self.assertEqual(eng.llm.base_url, "https://api.openai.com/v1")
            self.assertEqual(eng.llm.model, "gpt-5-mini")

            q_ask = SimpleNamespace(
                data="aiconf:ask:api_key",
                from_user=SimpleNamespace(id=999),
                message=SimpleNamespace(chat=SimpleNamespace(id=999, type="private")),
                answer=AsyncMock(),
                edit_message_text=AsyncMock(),
            )
            asyncio.run(handle_callback(SimpleNamespace(callback_query=q_ask), ctx))
            self.assertIn(999, eng.pending_owner_input)

            # 4. Non-owner sending private text does nothing
            m_stranger = SimpleNamespace(
                chat=SimpleNamespace(id=12345, type="private"),
                text="sk-attacker-key-99999999",
                delete=AsyncMock(),
                reply_text=AsyncMock(),
            )
            asyncio.run(
                handle_private_owner_input(
                    SimpleNamespace(message=m_stranger, effective_user=SimpleNamespace(id=12345)),
                    ctx,
                )
            )
            self.assertFalse(eng.llm.is_configured)

            # 5. Owner sends API Key -> hot-reloads, masks secret in reply, persists across restart!
            raw_secret = "sk-live-secret-1234567890"
            replies: list[str] = []
            m_owner = SimpleNamespace(
                chat=SimpleNamespace(id=999, type="private"),
                text=raw_secret,
                delete=AsyncMock(),
                reply_text=AsyncMock(side_effect=lambda t, **kw: replies.append(t)),
            )
            probe_mock = AsyncMock(return_value=ProbeReport(True, True, "OK", "支持识图"))
            eng.llm.probe_capabilities = probe_mock  # type: ignore[method-assign]
            asyncio.run(
                handle_private_owner_input(
                    SimpleNamespace(message=m_owner, effective_user=SimpleNamespace(id=999)),
                    ctx,
                )
            )
            m_owner.delete.assert_awaited_once()
            self.assertTrue(eng.llm.is_configured)
            self.assertEqual(eng.llm.api_key, raw_secret)
            self.assertEqual(len(replies), 1)
            self.assertNotIn(raw_secret, replies[0])  # NEVER echo raw secret!
            self.assertIn("sk-l••••••7890", replies[0])
            probe_mock.assert_awaited_once()

            # 5b. Origin-bound credential protection: switching preset to another host MUST clear old key
            #     and MUST NOT send a probe request to the new host with the old key!
            probe_mock.reset_mock()
            q_switch = SimpleNamespace(
                data="aiconf:preset:openrouter",
                from_user=SimpleNamespace(id=999),
                message=SimpleNamespace(chat=SimpleNamespace(id=999, type="private")),
                answer=AsyncMock(),
                edit_message_text=AsyncMock(),
            )
            asyncio.run(handle_callback(SimpleNamespace(callback_query=q_switch), ctx))
            self.assertEqual(eng.llm.base_url, "https://openrouter.ai/api/v1")
            self.assertEqual(eng.llm.api_key, "")
            self.assertFalse(eng.llm.is_configured)
            probe_mock.assert_not_awaited()

            # Re-bind a new key on OpenRouter, then change custom base_url to another HTTPS host -> clears key & no probe!
            asyncio.run(eng.update_ai_config(api_key="sk-openrouter-999999999"))
            self.assertTrue(eng.llm.is_configured)
            eng.set_owner_input_state(999, "base_url")
            m_new_url = SimpleNamespace(
                chat=SimpleNamespace(id=999, type="private"),
                text="https://other-provider.example.com/v1",
                delete=AsyncMock(),
                reply_text=AsyncMock(),
            )
            asyncio.run(
                handle_private_owner_input(
                    SimpleNamespace(message=m_new_url, effective_user=SimpleNamespace(id=999)),
                    ctx,
                )
            )
            self.assertEqual(eng.llm.base_url, "https://other-provider.example.com/v1")
            self.assertEqual(eng.llm.api_key, "")
            self.assertFalse(eng.llm.is_configured)
            probe_mock.assert_not_awaited()

            # 5c. Atomic DB-first transaction: DB write failure leaves live runtime AND DB untouched!
            asyncio.run(
                eng.update_ai_config(
                    base_url="https://api.openai.com/v1",
                    model="gpt-5-mini",
                    api_key=raw_secret,
                )
            )
            orig_set_many = db.set_meta_many

            def fail_db(_items):
                raise sqlite3.OperationalError("disk full")

            db.set_meta_many = fail_db  # type: ignore[method-assign]
            try:
                with self.assertRaises(sqlite3.OperationalError):
                    asyncio.run(eng.update_ai_config(model="broken-model"))
            finally:
                db.set_meta_many = orig_set_many  # type: ignore[method-assign]
            self.assertEqual(eng.llm.model, "gpt-5-mini")
            self.assertEqual(db.get_meta("ai_model"), "gpt-5-mini")

            # 6. Restart with unchanged .env -> restores in-bot configured OpenAI preset + key
            llm_restarted = UniversalAIClient("", cfg_empty_ai.ai_base_url, cfg_empty_ai.ai_model)
            eng_restarted = GuardEngine(cfg_empty_ai, db, llm_restarted)
            self.assertTrue(eng_restarted.llm.is_configured)
            self.assertEqual(eng_restarted.llm.base_url, "https://api.openai.com/v1")
            self.assertEqual(eng_restarted.llm.model, "gpt-5-mini")
            self.assertEqual(eng_restarted.llm.api_key, raw_secret)

            # 7. Restart after server .env was explicitly edited -> server .env wins cleanly!
            cfg_env_updated = AppConfig(
                telegram_bot_token="t",
                ai_api_key="sk-from-server-env",
                ai_base_url="https://api.deepseek.com/v1",
                ai_model="deepseek-flash",
                owner_ids={999},
            )
            llm_env = UniversalAIClient(
                cfg_env_updated.ai_api_key, cfg_env_updated.ai_base_url, cfg_env_updated.ai_model
            )
            eng_env = GuardEngine(cfg_env_updated, db, llm_env)
            self.assertEqual(eng_env.llm.api_key, "sk-from-server-env")
            self.assertEqual(eng_env.llm.model, "deepseek-flash")
            self.assertIsNone(db.get_meta("ai_config_override"))

            # 8. Pending input state expires after TTL
            eng_env.set_owner_input_state(999, "model", ttl=60.0, now=1000.0)
            self.assertIsNone(eng_env.pop_owner_input_state(999, now=1061.0))

    def test_22_legacy_db_without_key_origin_and_remote_http_env_are_blocked_on_startup(self) -> None:
        # 1. Remote plaintext HTTP in .env or direct client construction MUST NOT create an API client!
        bad_http = UniversalAIClient("sk-secret-123456", "http://remote-api.example.com/v1", "gpt-5-mini")
        self.assertFalse(bad_http.is_configured)
        self.assertIsNone(bad_http.client)
        self.assertIn("https://", bad_http.config_warning)

        bad_ip = UniversalAIClient("sk-secret-123456", "http://1.2.3.4:8080/v1", "gpt-5-mini")
        self.assertFalse(bad_ip.is_configured)
        self.assertIsNone(bad_ip.client)

        # Local loopback HTTP and remote HTTPS remain allowed
        ok_local = UniversalAIClient("sk-local", "http://localhost:11434/v1", "qwen")
        self.assertTrue(ok_local.is_configured)
        self.assertIsNotNone(ok_local.client)
        self.assertEqual(ok_local.config_warning, "")

        # 2. Legacy SQLite upgrade (pre-origin-binding DB missing ai_key_origin):
        #    MUST refuse to load/send unverified legacy key and pause in local mode with admin warning!
        with tempfile.TemporaryDirectory() as tmp, Storage(str(Path(tmp) / "legacy.db")) as db:
            cfg = AppConfig(telegram_bot_token="t", ai_api_key="", owner_ids={999})
            env_hash = GuardEngine._env_ai_hash(cfg)
            db.set_meta_many(
                {
                    "ai_config_override": "1",
                    "ai_env_hash": env_hash,
                    "ai_api_key": "sk-legacy-deepseek-secret",
                    "ai_base_url": "https://api.openai.com/v1",
                    "ai_model": "gpt-5-mini",
                    # Intentionally NO ai_key_origin (simulating upgrade from 57ced7c)
                }
            )
            llm = UniversalAIClient("", cfg.ai_base_url, cfg.ai_model)
            eng = GuardEngine(cfg, db, llm)
            self.assertFalse(eng.llm.is_configured)
            self.assertIsNone(eng.llm.client)
            self.assertEqual(eng.llm.api_key, "")
            self.assertIn("来源主机绑定", eng.active_ai_warning)

            # Even if legacy DB had a remote HTTP URL + matching origin, apply_sync still blocks it!
            db.set_meta_many(
                {
                    "ai_base_url": "http://remote.example.com/v1",
                    "ai_key_origin": "http://remote.example.com:80",
                }
            )
            llm2 = UniversalAIClient("", cfg.ai_base_url, cfg.ai_model)
            eng2 = GuardEngine(cfg, db, llm2)
            self.assertFalse(eng2.llm.is_configured)
            self.assertIsNone(eng2.llm.client)
            self.assertIn("https://", eng2.active_ai_warning)

    def test_23_url_sanitization_no_secret_leak_and_sban_callback_hardening(self) -> None:
        from adkiller.llm import sanitize_url_for_display, validate_ai_base_url
        from adkiller.panel import cmd_sban, handle_callback
        from telegram.error import Forbidden

        # 1. Query/userinfo URLs rejected by validator & scrubbed in display/warnings
        leaky_url = "http://admin:SuperSecretPass@remote.example.com:8080/v1?api_key=leak999#frag"
        self.assertIsNone(validate_ai_base_url(leaky_url))
        self.assertIsNone(validate_ai_base_url("https://api.example.com/v1?api_key=leak999"))
        self.assertEqual(sanitize_url_for_display(leaky_url), "http://remote.example.com:8080")
        self.assertEqual(
            sanitize_url_for_display("https://u:p@api.deepseek.com/v1?k=secret"),
            "https://api.deepseek.com",
        )

        bad_client = UniversalAIClient("sk-test-123456", leaky_url, "gpt-5-mini")
        self.assertFalse(bad_client.is_configured)
        self.assertIn("http://remote.example.com:8080", bad_client.config_warning)
        self.assertNotIn("SuperSecretPass", bad_client.config_warning)
        self.assertNotIn("admin", bad_client.config_warning)
        self.assertNotIn("leak999", bad_client.config_warning)

        # 2. /sban refuses to ban group admins & never poisons spam_cache when ban fails;
        #    malformed callback payloads never raise ValueError
        with tempfile.TemporaryDirectory() as tmp, Storage(str(Path(tmp) / "sban.db")) as db:
            cfg = AppConfig(telegram_bot_token="t", ai_api_key="", owner_ids={999})
            llm = UniversalAIClient("", cfg.ai_base_url, cfg.ai_model)
            eng = GuardEngine(cfg, db, llm)

            target_msg = _fake_msg(chat_id=-1001, msg_id=40, user_id=555, text="这是一段手动封禁测试广告文案十六字")
            cmd_msg = _fake_msg(chat_id=-1001, msg_id=41, user_id=999, text="/sban")
            cmd_msg.reply_to_message = target_msg

            bot_fail = SimpleNamespace(
                id=1,
                get_chat_administrators=AsyncMock(return_value=[]),
                delete_message=AsyncMock(),
                ban_chat_member=AsyncMock(side_effect=Forbidden("no ban rights")),
            )
            ctx = SimpleNamespace(bot=bot_fail, application=SimpleNamespace(bot_data={"engine": eng}))
            asyncio.run(cmd_sban(SimpleNamespace(message=cmd_msg, effective_user=SimpleNamespace(id=999)), ctx))
            fp = eng.spam_cache.fingerprint_message(-1001, extract_xray(target_msg), None)
            self.assertIsNone(eng.spam_cache.lookup(fp, min_score=80))

            # Malformed callback data returns cleanly without raising ValueError
            for bad_cb in ("cap:bad:1:orange", "unban:bad:1", "cfg:mode:bad", "rptban:x:y:z"):
                q = SimpleNamespace(
                    data=bad_cb,
                    from_user=SimpleNamespace(id=999),
                    message=SimpleNamespace(chat=SimpleNamespace(id=-1001, type="supergroup")),
                    answer=AsyncMock(),
                )
                asyncio.run(handle_callback(SimpleNamespace(callback_query=q), ctx))

    def test_24_safe_llm_error_logging_and_reply_to_media_cache_exclusion(self) -> None:
        import logging
        from adkiller.llm import format_safe_llm_error
        from adkiller.panel import cmd_sban

        # 1. format_safe_llm_error logs ONLY class + HTTP status + safe request_id (NEVER raw body/URL/key!)
        class FakeProviderError(Exception):
            def __init__(self, msg: str, status_code: int, request_id: str) -> None:
                super().__init__(msg)
                self.status_code = status_code
                self.request_id = request_id

        leaky_exc = FakeProviderError(
            "Invalid key sk-secret-leak999 at https://u:pass@bad.example.com/v1?k=xyz echo=user_private_chat",
            status_code=401,
            request_id="req_abc-123",
        )
        safe_str = format_safe_llm_error(leaky_exc)
        self.assertEqual(safe_str, "FakeProviderError (HTTP 401, req=req_abc-123)")
        self.assertNotIn("sk-secret", safe_str)
        self.assertNotIn("bad.example.com", safe_str)
        self.assertNotIn("user_private_chat", safe_str)

        # Verify runtime vision-fallback & guard audit logs never emit raw provider error text!
        with tempfile.TemporaryDirectory() as tmp, Storage(str(Path(tmp) / "safelog.db")) as db:
            cfg = AppConfig(telegram_bot_token="t", ai_api_key="sk-test", ai_model="deepseek-flash", owner_ids={999})
            llm = UniversalAIClient("sk-test", "https://api.deepseek.com/v1", "deepseek-flash")
            llm.vision_supported = True
            llm.client = SimpleNamespace(
                chat=SimpleNamespace(
                    completions=SimpleNamespace(create=AsyncMock(side_effect=leaky_exc))
                )
            )
            eng = GuardEngine(cfg, db, llm)
            gs = eng.get_group_settings(-1001, "G")
            gs.cas_enabled = False
            gs.first_message_only = False
            db.save_group(gs)

            captured_logs: list[str] = []

            class _ListHandler(logging.Handler):
                def emit(self, record: logging.LogRecord) -> None:
                    captured_logs.append(self.format(record))

            handler = _ListHandler()
            root_logger = logging.getLogger("adkiller")
            root_logger.addHandler(handler)
            try:
                bot = SimpleNamespace(
                    id=1,
                    get_chat_administrators=AsyncMock(return_value=[]),
                    get_chat=AsyncMock(return_value=SimpleNamespace(photo=object(), bio="", personal_chat=None)),
                    delete_message=AsyncMock(),
                    ban_chat_member=AsyncMock(),
                    send_message=AsyncMock(),
                )
                m = _fake_msg(chat_id=-1001, msg_id=10, user_id=200, text="这是一段触发AI审核异常的普通消息测试")
                asyncio.run(
                    eng.handle_message(SimpleNamespace(edited_message=None, message=m), SimpleNamespace(bot=bot))
                )
            finally:
                root_logger.removeHandler(handler)

            joined_logs = "\n".join(captured_logs)
            self.assertIn("FakeProviderError (HTTP 401, req=req_abc-123)", joined_logs)
            self.assertNotIn("sk-secret", joined_logs)
            self.assertNotIn("bad.example.com", joined_logs)
            self.assertNotIn("user_private_chat", joined_logs)

            # 2. Reply to a sticker or captionless photo (reply_preview == "") MUST still be treated as a reply
            #    and NEVER populate or hit shared spam_cache (both manual /sban and automatic pipeline)!
            sticker_only_msg = SimpleNamespace(text=None, caption=None, sticker=SimpleNamespace(emoji="😂"))
            reply_to_sticker = _fake_msg(
                chat_id=-1001,
                msg_id=50,
                user_id=555,
                text="哈哈哈哈这个表情包太好笑了真的笑死我了",
            )
            reply_to_sticker.reply_to_message = sticker_only_msg
            xray_reply = extract_xray(reply_to_sticker)
            self.assertEqual(xray_reply.reply_preview, "")
            self.assertTrue(xray_reply.is_reply)
            self.assertFalse(xray_reply.allow_shared_cache())

            # Manual /sban on a reply-to-sticker message bans the user, MUST NOT write shared spam_cache!
            cmd_msg = _fake_msg(chat_id=-1001, msg_id=51, user_id=999, text="/sban")
            cmd_msg.reply_to_message = reply_to_sticker
            bot_ok = SimpleNamespace(
                id=1,
                get_chat_administrators=AsyncMock(return_value=[]),
                delete_message=AsyncMock(),
                ban_chat_member=AsyncMock(),
                send_message=AsyncMock(),
            )
            ctx_ok = SimpleNamespace(bot=bot_ok, application=SimpleNamespace(bot_data={"engine": eng}))
            asyncio.run(cmd_sban(SimpleNamespace(message=cmd_msg, effective_user=SimpleNamespace(id=999)), ctx_ok))
            bot_ok.ban_chat_member.assert_awaited_once()
            fp_reply = eng.spam_cache.fingerprint_message(-1001, xray_reply, None)
            self.assertIsNone(eng.spam_cache.lookup(fp_reply, min_score=80))

            # Automatic pipeline: even if fp is cached, a reply to a captionless photo MUST NOT hit spam_cache!
            eng.spam_cache.remember(fp_reply, 95, "样本")
            reply_to_photo = _fake_msg(
                chat_id=-1001,
                msg_id=52,
                user_id=556,
                text="哈哈哈哈这个表情包太好笑了真的笑死我了",
            )
            reply_to_photo.reply_to_message = SimpleNamespace(text=None, caption=None, photo=[object()])
            bot_auto = SimpleNamespace(
                id=1,
                get_chat_administrators=AsyncMock(return_value=[]),
                get_chat=AsyncMock(return_value=SimpleNamespace(photo=object(), bio="", personal_chat=None)),
                delete_message=AsyncMock(),
                ban_chat_member=AsyncMock(),
                send_message=AsyncMock(),
            )
            asyncio.run(
                eng.handle_message(
                    SimpleNamespace(edited_message=None, message=reply_to_photo),
                    SimpleNamespace(bot=bot_auto),
                )
            )
            bot_auto.ban_chat_member.assert_not_called()

    def test_25_configurable_exemption_and_bypass_gui_toggles(self) -> None:
        from adkiller.panel import build_exempts_view, handle_callback
        from telegram.error import TelegramError

        with tempfile.TemporaryDirectory() as tmp, Storage(str(Path(tmp) / "ex.db")) as db:
            cfg = AppConfig(telegram_bot_token="t", ai_api_key="", owner_ids={999})
            llm = UniversalAIClient("", cfg.ai_base_url, cfg.ai_model)
            eng = GuardEngine(cfg, db, llm)
            gs = eng.get_group_settings(-1001, "ExGroup")
            gs.cas_enabled = False
            db.save_group(gs)

            # 1. Verify sensible defaults: core safety exemptions ON; exempt_owners OFF; external_channel="ai"
            self.assertTrue(gs.exempt_admins)
            self.assertTrue(gs.exempt_anon_admin)
            self.assertTrue(gs.exempt_linked_channel)
            self.assertTrue(gs.exempt_trusted)
            self.assertFalse(gs.exempt_owners)
            self.assertEqual(gs.external_channel_mode, "ai")
            self.assertTrue(gs.exempt_veteran_short)
            self.assertTrue(gs.first_message_only)
            self.assertTrue(gs.exempt_reply_cache)
            self.assertTrue(gs.admin_cache_fallback)

            # 2. GUI subpanel opens & toggles persist via cfg:exempts / cfg:ex_* callbacks
            text, markup = build_exempts_view(eng, gs)
            self.assertIn("豁免与绕过规则", text)
            self.assertIsNotNone(markup)

            ctx_cb = SimpleNamespace(
                bot=SimpleNamespace(),
                application=SimpleNamespace(bot_data={"engine": eng}),
            )
            for action in ("exempts", "ex_admins", "ex_extch", "ex_short", "ex_first_msg"):
                q = SimpleNamespace(
                    data=f"cfg:{action}:-1001",
                    from_user=SimpleNamespace(id=999),
                    message=SimpleNamespace(chat=SimpleNamespace(id=-1001, type="supergroup")),
                    answer=AsyncMock(),
                    edit_message_text=AsyncMock(),
                )
                asyncio.run(handle_callback(SimpleNamespace(callback_query=q), ctx_cb))
                q.edit_message_text.assert_awaited_once()

            gs_reloaded = eng.get_group_settings(-1001, "ExGroup")
            self.assertFalse(gs_reloaded.exempt_admins)
            self.assertEqual(gs_reloaded.external_channel_mode, "ban")
            self.assertFalse(gs_reloaded.exempt_veteran_short)
            self.assertFalse(gs_reloaded.first_message_only)

            # 3. With exempt_admins=False & exempt_owners=False (and opt-in local_rules_enabled=True),
            #    an admin/owner CAN self-test moderation!
            gs_reloaded.local_rules_enabled = True
            db.save_group(gs_reloaded)
            spam_text = "预付开工 日结500 帮发消息 做的联系"
            admin_member = SimpleNamespace(
                status="administrator",
                user=SimpleNamespace(id=999),
                can_delete_messages=True,
                can_restrict_members=True,
            )
            bot_test = SimpleNamespace(
                id=1,
                get_chat_administrators=AsyncMock(return_value=[admin_member]),
                get_chat=AsyncMock(return_value=SimpleNamespace(photo=object(), bio="", personal_chat=None, linked_chat_id=None)),
                delete_message=AsyncMock(),
                ban_chat_member=AsyncMock(),
                ban_chat_sender_chat=AsyncMock(),
                send_message=AsyncMock(),
            )
            m_owner_test = _fake_msg(chat_id=-1001, msg_id=101, user_id=999, text=spam_text)
            asyncio.run(
                eng.handle_message(
                    SimpleNamespace(edited_message=None, message=m_owner_test),
                    SimpleNamespace(bot=bot_test),
                )
            )
            bot_test.delete_message.assert_awaited()

            # 4. External channel mode: "ban" blocks immediately; "allow" bypasses completely!
            ch_msg = _fake_msg(
                chat_id=-1001,
                msg_id=102,
                user_id=0,
                text="普通测试内容",
                sender_chat=SimpleNamespace(id=-100888, title="外部频道", username="ext_ch"),
            )
            bot_test.ban_chat_sender_chat.reset_mock()
            asyncio.run(
                eng.handle_message(
                    SimpleNamespace(edited_message=None, message=ch_msg),
                    SimpleNamespace(bot=bot_test),
                )
            )
            bot_test.ban_chat_sender_chat.assert_awaited_once_with(-1001, -100888)

            gs_reloaded.external_channel_mode = "allow"
            db.save_group(gs_reloaded)
            bot_test.ban_chat_sender_chat.reset_mock()
            bot_test.delete_message.reset_mock()
            ch_spam = _fake_msg(
                chat_id=-1001,
                msg_id=103,
                user_id=0,
                text=spam_text,
                sender_chat=SimpleNamespace(id=-100889, title="外部频道2", username="ext_ch2"),
            )
            asyncio.run(
                eng.handle_message(
                    SimpleNamespace(edited_message=None, message=ch_spam),
                    SimpleNamespace(bot=bot_test),
                )
            )
            bot_test.ban_chat_sender_chat.assert_not_called()
            bot_test.delete_message.assert_not_called()

            # 5. Admin cache transient-outage fallback protects known admins from false deletion,
            #    while check_admin_perm stays strictly fail-closed on TelegramError!
            gs_reloaded.exempt_admins = True
            gs_reloaded.admin_cache_fallback = True
            db.save_group(gs_reloaded)
            admin_42 = SimpleNamespace(
                status="administrator",
                user=SimpleNamespace(id=42),
                can_delete_messages=True,
                can_restrict_members=True,
            )
            bot_seed = SimpleNamespace(get_chat_administrators=AsyncMock(return_value=[admin_42]))
            self.assertTrue(asyncio.run(eng.is_chat_admin_only(bot_seed, -1001, 42, allow_stale_fallback=True)))
            # Expire primary 5-min admin_cache, simulate transient TelegramError
            eng.admin_cache.pop(-1001, None)
            bot_outage = SimpleNamespace(
                get_chat_administrators=AsyncMock(side_effect=TelegramError("timeout")),
                get_chat_member=AsyncMock(side_effect=TelegramError("timeout")),
            )
            # Moderation exemption still protects admin 42 via 30-min stale fallback
            self.assertTrue(asyncio.run(eng.is_chat_admin_only(bot_outage, -1001, 42, allow_stale_fallback=True)))
            # With fallback turned OFF, does not use stale cache
            self.assertFalse(asyncio.run(eng.is_chat_admin_only(bot_outage, -1001, 42, allow_stale_fallback=False)))
            # Privileged check_admin_perm NEVER uses stale fallback (stays strictly fail-closed!)
            self.assertFalse(
                asyncio.run(eng.check_admin_perm(bot_outage, -1001, 42, require_restrict=True, fresh=True))
            )

            # 6. Veteran short-message toggle: exempt_veteran_short=False forces AI check even on <=5 chars
            short_xray = extract_xray(_fake_msg(chat_id=-1001, msg_id=104, user_id=500, text="好的"))
            self.assertFalse(eng.should_send_to_ai(short_xray, clean_count=10, exempt_veteran_short=True))
            self.assertTrue(eng.should_send_to_ai(short_xray, clean_count=10, exempt_veteran_short=False))

    def test_26_polysemy_anti_scam_graduated_flood_and_outage_downgrade(self) -> None:
        # 1. GPT's exact 4 normal Chinese sentences MUST score 0 (never muted or banned!)
        benign_sentences = [
            "今晚吃菠菜，怎么炒好吃？",
            "这张显卡跑分怎么样？",
            "周末准备换床上四件套，有推荐的吗？",
            "提醒新人：刷单和洗钱都是骗局，别信。",
        ]
        for sentence in benign_sentences:
            res = evaluate_basic_rules(extract_xray(_fake_msg(text=sentence)), {})
            self.assertEqual(res.score, 0, f"Unexpected false positive on: {sentence} -> {res}")

        # Pure news/discussion mentioning sensitive words with ZERO promotion action MUST stay <= 50 (no mute/ban!)
        news_res = evaluate_basic_rules(
            extract_xray(_fake_msg(text="昨晚新闻报道警方打掉一个刷单洗钱团伙")), {}
        )
        self.assertLessEqual(news_res.score, 50)

        # Real spam WITH independent promotion/conversion evidence MUST still score >= 80!
        real_spams = [
            "菠菜网赌代理 稳赚包赢 加V: abc12345",
            "银行卡四件套出售 预付开工 私聊我",
        ]
        for spam_s in real_spams:
            res = evaluate_basic_rules(extract_xray(_fake_msg(text=spam_s)), {})
            self.assertGreaterEqual(res.score, 80, f"Missed real spam: {spam_s} -> {res}")

        # 2. Local keyword rules DEFAULT OFF + Graduated Anti-Flood:
        #    normal fast chatters & weird words are NEVER blindly keyword-banned!
        from adkiller.panel import handle_callback

        with tempfile.TemporaryDirectory() as tmp, Storage(str(Path(tmp) / "flood.db")) as db:
            cfg = AppConfig(telegram_bot_token="t", ai_api_key="", owner_ids={999})
            llm = UniversalAIClient("", cfg.ai_base_url, cfg.ai_model)
            eng = GuardEngine(cfg, db, llm)
            gs = eng.get_group_settings(-1001, "ChatGroup")
            gs.cas_enabled = False
            db.save_group(gs)
            self.assertEqual(gs.flood_max, 6)
            self.assertFalse(gs.local_rules_enabled)

            bot = SimpleNamespace(
                id=1,
                get_chat_administrators=AsyncMock(return_value=[]),
                get_chat=AsyncMock(return_value=SimpleNamespace(photo=object(), bio="", personal_chat=None, linked_chat_id=None)),
                delete_message=AsyncMock(),
                ban_chat_member=AsyncMock(),
                restrict_chat_member=AsyncMock(),
                send_message=AsyncMock(return_value=SimpleNamespace(message_id=999)),
            )
            ctx = SimpleNamespace(bot=bot, application=SimpleNamespace(bot_data={"engine": eng}))

            # 2a. With default local_rules_enabled=False and no AI, keyword text is NOT regex-banned!
            m_kw_off = _fake_msg(chat_id=-1001, msg_id=100, user_id=555, text="预付开工 日结500 帮发消息 做的联系")
            asyncio.run(eng.handle_message(SimpleNamespace(edited_message=None, message=m_kw_off), ctx))
            bot.ban_chat_member.assert_not_called()
            bot.restrict_chat_member.assert_not_called()

            # 2b. 4 quick chat replies ("我试了"/"还是不行"/"等下"/"好了") -> does NOT even trigger flood!
            for idx, txt in enumerate(["我试了", "还是不行", "等下", "好了"], start=1):
                m = _fake_msg(chat_id=-1001, msg_id=idx, user_id=501, text=txt)
                asyncio.run(eng.handle_message(SimpleNamespace(edited_message=None, message=m), ctx))
            bot.ban_chat_member.assert_not_called()
            bot.restrict_chat_member.assert_not_called()

            # 2 more distinct replies (total 6 in <8s) -> 1st strike: ONLY 60s cooldown mute, NO ban, NO deletes!
            for idx, txt in enumerate(["再试一次", "搞定了"], start=5):
                m = _fake_msg(chat_id=-1001, msg_id=idx, user_id=501, text=txt)
                asyncio.run(eng.handle_message(SimpleNamespace(edited_message=None, message=m), ctx))
            bot.ban_chat_member.assert_not_called()
            bot.delete_message.assert_not_called()
            bot.restrict_chat_member.assert_awaited_once()
            until_60 = bot.restrict_chat_member.call_args.kwargs.get("until_date", 0)
            self.assertLessEqual(until_60 - int(time.time()), 90)

            # 2nd normal rapid burst within 10 min -> mute_review (24h mute + admin review), STILL no blind ban!
            bot.restrict_chat_member.reset_mock()
            for idx in range(10, 16):
                m = _fake_msg(chat_id=-1001, msg_id=idx, user_id=501, text=f"正常快聊消息{idx}")
                asyncio.run(eng.handle_message(SimpleNamespace(edited_message=None, message=m), ctx))
            bot.ban_chat_member.assert_not_called()
            bot.restrict_chat_member.assert_awaited_once()

            # 3. AI outage behavior:
            #    (a) Default local_rules_enabled=False -> AI outage skips keyword punishment & does NOT credit clean_count!
            llm_down = UniversalAIClient("sk-test", "https://api.deepseek.com/v1", "deepseek-flash")
            llm_down.classify = AsyncMock(side_effect=RuntimeError("timeout"))  # type: ignore[method-assign]
            eng_ai = GuardEngine(
                AppConfig(telegram_bot_token="t", ai_api_key="sk-test", ai_model="deepseek-flash", owner_ids={999}),
                db,
                llm_down,
            )
            bot_ai = SimpleNamespace(
                id=1,
                get_chat_administrators=AsyncMock(return_value=[]),
                get_chat=AsyncMock(return_value=SimpleNamespace(photo=object(), bio="", personal_chat=None, linked_chat_id=None)),
                delete_message=AsyncMock(),
                ban_chat_member=AsyncMock(),
                restrict_chat_member=AsyncMock(),
                send_message=AsyncMock(),
            )
            m_outage_off = _fake_msg(chat_id=-1001, msg_id=29, user_id=700, text="预付开工 日结500 帮发消息")
            asyncio.run(
                eng_ai.handle_message(
                    SimpleNamespace(edited_message=None, message=m_outage_off),
                    SimpleNamespace(bot=bot_ai),
                )
            )
            bot_ai.ban_chat_member.assert_not_called()
            bot_ai.restrict_chat_member.assert_not_called()
            self.assertEqual(db.get_clean_count(-1001, 700), 0)

            #    (b) Admin clicks /config button cfg:localrules:-1001 -> enables local_rules_enabled in SQLite!
            q_toggle = SimpleNamespace(
                data="cfg:localrules:-1001",
                from_user=SimpleNamespace(id=999),
                message=SimpleNamespace(chat=SimpleNamespace(id=-1001, type="supergroup")),
                answer=AsyncMock(),
                edit_message_text=AsyncMock(),
            )
            asyncio.run(handle_callback(SimpleNamespace(callback_query=q_toggle), ctx))
            self.assertTrue(eng.get_group_settings(-1001, "ChatGroup").local_rules_enabled)

            #    (c) With opt-in local_rules_enabled=True: spam flooder banned, and AI outage <95 downgraded to mute_review!
            for idx in range(20, 26):
                m = _fake_msg(chat_id=-1001, msg_id=idx, user_id=666, text="预付开工 日结500 帮发消息 做的联系")
                asyncio.run(eng.handle_message(SimpleNamespace(edited_message=None, message=m), ctx))
            self.assertIn(666, [c.args[1] for c in bot.ban_chat_member.call_args_list])

            # Score ~93 (<95): Tier A (68) + Tier C (25) = 93 -> downgraded to mute_review during LLM outage!
            m_outage = _fake_msg(chat_id=-1001, msg_id=30, user_id=701, text="预付开工 日结500 帮发消息")
            asyncio.run(
                eng_ai.handle_message(
                    SimpleNamespace(edited_message=None, message=m_outage),
                    SimpleNamespace(bot=bot_ai),
                )
            )
            bot_ai.ban_chat_member.assert_not_called()
            bot_ai.restrict_chat_member.assert_awaited_once()

            # 4. Active veteran (clean_count>=15) sending clean short chat <=20 chars skips AI for lower latency
            vet_xray = extract_xray(_fake_msg(text="这个我刚才试了一下没问题"))
            self.assertFalse(eng_ai.should_send_to_ai(vet_xray, clean_count=20, profile_boost=0))

    def test_27_customizable_ban_announcement_gui_and_persistent_auto_delete(self) -> None:
        from adkiller.guard import (
            format_delete_delay,
            parse_delete_delay_input,
            render_ban_announcement,
        )
        from adkiller.panel import (
            build_announce_view,
            handle_callback,
            handle_group_admin_input,
            handle_private_owner_input,
        )

        # 1. Delay parser & formatter
        self.assertEqual(parse_delete_delay_input("0"), 0)
        self.assertEqual(parse_delete_delay_input("不删"), 0)
        self.assertEqual(parse_delete_delay_input("永久"), 0)
        self.assertEqual(parse_delete_delay_input("30"), 1800)  # plain integer -> minutes
        self.assertEqual(parse_delete_delay_input("45s"), 45)
        self.assertEqual(parse_delete_delay_input("15m"), 900)
        self.assertEqual(parse_delete_delay_input("2h"), 7200)
        self.assertEqual(parse_delete_delay_input("10分钟"), 600)
        self.assertIsNone(parse_delete_delay_input("5s"))  # below 10s minimum
        self.assertIsNone(parse_delete_delay_input("48h"))  # above 24h maximum
        self.assertIsNone(parse_delete_delay_input("abc"))
        self.assertIsNone(parse_delete_delay_input("-5"))
        self.assertEqual(format_delete_delay(1800), "30 分钟")
        self.assertEqual(format_delete_delay(0), "不自动删除（永久保留）")

        with tempfile.TemporaryDirectory() as tmp, Storage(str(Path(tmp) / "ann.db")) as db:
            cfg = AppConfig(telegram_bot_token="t", ai_api_key="", owner_ids={999})
            llm = UniversalAIClient("", cfg.ai_base_url, cfg.ai_model)
            eng = GuardEngine(cfg, db, llm)
            gs = eng.get_group_settings(-1001, "AnnGroup")

            # 2. Verify defaults: group ban announcement ON + 30-minute (1800s) auto-delete!
            self.assertTrue(gs.announce_in_group)
            self.assertEqual(gs.announce_delete_seconds, 1800)
            self.assertEqual(gs.announce_template, "")

            # Default rendering includes user, reason, duration, and 30-minute auto-delete notice
            default_txt = render_ban_announcement(
                gs,
                display_name="广告哥 (@spambot)",
                actor_id=888,
                reason="发布灰产引流广告",
                duration="永久封禁",
            )
            self.assertIn("AI-智能广告杀手已封禁用户：广告哥 (@spambot)", default_txt)
            self.assertIn("发布灰产引流广告", default_txt)
            self.assertIn("永久封禁", default_txt)
            self.assertIn("30 分钟", default_txt)

            # Security: single-pass substitution prevents second-order expansion & arbitrary braces never crash!
            gs.announce_template = "封禁 {user} | 理由 {reason} | 保留字 {unknown_tag}"
            safe_txt = render_ban_announcement(
                gs,
                display_name="{reason}\n伪造新行",
                actor_id=889,
                reason="真实原因XYZ",
                duration="永久封禁",
            )
            self.assertIn("封禁 {reason} 伪造新行 | 理由 真实原因XYZ | 保留字 {unknown_tag}", safe_txt)
            gs.announce_template = ""
            db.save_group(gs)

            # 3. Interactive Telegram GUI subpanel (presets, never-delete, custom template & custom delay in group & DM)
            text_v, markup_v = build_announce_view(eng, gs)
            self.assertIn("群内封禁播报设置", text_v)
            self.assertIn("30 分钟后自动删除", text_v)
            self.assertIsNotNone(markup_v)

            bot_gui = SimpleNamespace(
                id=1,
                edit_message_text=AsyncMock(),
                delete_message=AsyncMock(),
                send_message=AsyncMock(return_value=SimpleNamespace(message_id=777)),
                ban_chat_member=AsyncMock(),
            )
            ctx_gui = SimpleNamespace(bot=bot_gui, application=SimpleNamespace(bot_data={"engine": eng}))

            def _make_cb(cb_data: str, *, chat_id: int = -1001, chat_type: str = "supergroup", uid: int = 999):
                return SimpleNamespace(
                    data=cb_data,
                    from_user=SimpleNamespace(id=uid),
                    message=SimpleNamespace(chat=SimpleNamespace(id=chat_id, type=chat_type), message_id=50),
                    answer=AsyncMock(),
                    edit_message_text=AsyncMock(),
                )

            # Open menu -> switch to never-delete -> toggle back to 30m -> set 5m preset -> preview
            for cb_str in (
                "cfg:announce_menu:-1001",
                "cfg:an_del0:-1001",
                "cfg:an_deltoggle:-1001",
                "cfg:an_del300:-1001",
                "cfg:an_preview:-1001",
            ):
                q = _make_cb(cb_str)
                asyncio.run(handle_callback(SimpleNamespace(callback_query=q), ctx_gui))
                q.edit_message_text.assert_awaited_once()
            self.assertEqual(eng.get_group_settings(-1001).announce_delete_seconds, 300)

            # Admin clicks "custom template" in group -> sends custom template text -> saved & exempt from Group 1!
            q_ask_tpl = _make_cb("cfg:an_ask_tpl:-1001")
            asyncio.run(handle_callback(SimpleNamespace(callback_query=q_ask_tpl), ctx_gui))
            self.assertIn((-1001, 999), eng.pending_admin_input)

            # Non-admin message in group does NOT hijack admin's pending input
            m_other = SimpleNamespace(
                chat=SimpleNamespace(id=-1001, type="supergroup"),
                message_id=60,
                text="恶意篡改模板",
                reply_text=AsyncMock(),
            )
            asyncio.run(
                handle_group_admin_input(
                    SimpleNamespace(message=m_other, effective_user=SimpleNamespace(id=12345)),
                    ctx_gui,
                )
            )
            self.assertEqual(eng.get_group_settings(-1001).announce_template, "")
            self.assertIn((-1001, 999), eng.pending_admin_input)

            # Real admin sends custom template in group -> saved & marked handled!
            m_tpl = SimpleNamespace(
                chat=SimpleNamespace(id=-1001, type="supergroup"),
                message_id=61,
                text="🛡 AI-智能广告杀手已处决 {user}，原因：{reason}，时长：{duration}",
                reply_text=AsyncMock(),
            )
            asyncio.run(
                handle_group_admin_input(
                    SimpleNamespace(message=m_tpl, effective_user=SimpleNamespace(id=999)),
                    ctx_gui,
                )
            )
            self.assertEqual(
                eng.get_group_settings(-1001).announce_template,
                "🛡 AI-智能广告杀手已处决 {user}，原因：{reason}，时长：{duration}",
            )
            self.assertTrue(eng.consume_handled_command(-1001, 61))

            # Owner opens custom delay prompt in private DM -> sends "45s" -> persisted to SQLite!
            q_ask_dm = _make_cb("cfg:an_ask_delay:-1001", chat_id=999, chat_type="private")
            asyncio.run(handle_callback(SimpleNamespace(callback_query=q_ask_dm), ctx_gui))
            m_dm_delay = SimpleNamespace(
                chat=SimpleNamespace(id=999, type="private"),
                message_id=62,
                text="45s",
                reply_text=AsyncMock(),
            )
            asyncio.run(
                handle_private_owner_input(
                    SimpleNamespace(message=m_dm_delay, effective_user=SimpleNamespace(id=999)),
                    ctx_gui,
                )
            )
            self.assertEqual(eng.get_group_settings(-1001).announce_delete_seconds, 45)

            # 4. Ban enforcement sends custom announcement & persists pending auto-delete to SQLite!
            gs_live = eng.get_group_settings(-1001)
            m_spam = _fake_msg(chat_id=-1001, msg_id=80, user_id=707, text="广告测试")
            asyncio.run(
                eng.enforce_action(
                    bot_gui,
                    m_spam,
                    gs_live,
                    action="ban",
                    trigger_type="ai_text",
                    score=95,
                    reason="推销刷单",
                    xray=extract_xray(m_spam),
                    profile={"full_name": "小广告", "username": "@ad707"},
                )
            )
            group_msgs = [c.args[1] for c in bot_gui.send_message.call_args_list if c.args[0] == -1001]
            self.assertEqual(len(group_msgs), 1)
            self.assertEqual(group_msgs[0], "🛡 AI-智能广告杀手已处决 小广告 (@ad707)，原因：推销刷单，时长：永久封禁")
            pending_rows = db.list_pending_deletes()
            self.assertEqual(len(pending_rows), 1)
            self.assertEqual((pending_rows[0][0], pending_rows[0][1]), (-1001, 777))

            # 5. Restart recovery: overdue persisted message is deleted automatically & DB row cleared!
            db.save_pending_delete(-1001, 888, time.time() - 5.0)
            bot_restore = SimpleNamespace(delete_message=AsyncMock())

            async def _run_restore() -> None:
                await eng.restore_pending_deletes(bot_restore)
                await asyncio.sleep(0.05)

            asyncio.run(_run_restore())
            bot_restore.delete_message.assert_any_await(-1001, 888)
            remaining_mids = {mid for _, mid, _ in db.list_pending_deletes()}
            self.assertNotIn(888, remaining_mids)

            # 6. When announce_delete_seconds == 0 (never delete), ban notice is sent WITHOUT pending_delete row!
            gs_live.announce_delete_seconds = 0
            db.save_group(gs_live)
            bot_keep = SimpleNamespace(
                send_message=AsyncMock(return_value=SimpleNamespace(message_id=999))
            )
            asyncio.run(
                eng.announce_ban_in_group(
                    bot_keep,
                    -1001,
                    gs_live,
                    display_name="永久留档用户",
                    actor_id=708,
                    reason="测试保留",
                )
            )
            bot_keep.send_message.assert_awaited_once()
            remaining_mids2 = {mid for _, mid, _ in db.list_pending_deletes()}
            self.assertNotIn(999, remaining_mids2)

    def test_28_bot_branding_gui_token_scrub_and_avatar_upload(self) -> None:
        from adkiller import branding
        from adkiller.panel import (
            build_branding_view,
            build_start_dashboard,
            handle_callback,
            handle_private_owner_input,
        )

        # 1. Bundled official AI-智能广告杀手 avatar exists & is a valid JPEG
        self.assertTrue(branding.DEFAULT_AVATAR_PATH.is_file())
        raw_avatar = branding.DEFAULT_AVATAR_PATH.read_bytes()
        self.assertEqual(raw_avatar[:2], b"\xff\xd8")

        # 2. Token scrubbing & safe error reporting (NEVER leaks bot token from httpx exceptions!)
        secret_tok = "123456789:AABBCCDDEEFFGGHHIIJJKKLLMMNN"
        self.assertEqual(
            branding.scrub_bot_token(f"POST https://api.telegram.org/bot{secret_tok}/setMyName failed"),
            "POST https://api.telegram.org/bot***/setMyName failed",
        )

        class _LeakyHttpxErr(Exception):
            pass

        err_client = SimpleNamespace(
            post=AsyncMock(
                side_effect=_LeakyHttpxErr(
                    f"ConnectError for url https://api.telegram.org/bot{secret_tok}/setMyName"
                )
            ),
            aclose=AsyncMock(),
        )
        ok_err, msg_err = asyncio.run(branding.set_bot_name(secret_tok, "AI-智能广告杀手", client=err_client))
        self.assertFalse(ok_err)
        self.assertNotIn(secret_tok, msg_err)
        self.assertIn("_LeakyHttpxErr", msg_err)

        # 3. apply_default_branding calls setMyName, setMyShortDescription, setMyDescription, setMyProfilePhoto
        seen_calls: list[tuple[str, dict | None, dict | None]] = []

        async def fake_post(url: str, *, data=None, files=None):
            method = url.rsplit("/", 1)[-1]
            seen_calls.append((method, data, files))
            return SimpleNamespace(status_code=200, json=lambda: {"ok": True, "result": True})

        ok_client = SimpleNamespace(post=fake_post, aclose=AsyncMock())
        results = asyncio.run(branding.apply_default_branding(secret_tok, client=ok_client))
        self.assertEqual(len(results), 4)
        self.assertTrue(all(ok for _, ok, _ in results))
        self.assertEqual(
            [m for m, _, _ in seen_calls],
            ["setMyName", "setMyShortDescription", "setMyDescription", "setMyProfilePhoto"],
        )
        # Verify setMyProfilePhoto multipart format matches Bot API InputProfilePhotoStatic spec
        photo_method, photo_data, photo_files = seen_calls[-1]
        self.assertEqual(photo_method, "setMyProfilePhoto")
        self.assertEqual(photo_data, {"photo": '{"type":"static","photo":"attach://avatar"}'})
        self.assertIn("avatar", photo_files or {})

        # 4. Owner /start dashboard displays clickable https://t.me/<username> & branding button;
        #    brand:* callbacks strictly enforce Private DM + Owner-only access control!
        with tempfile.TemporaryDirectory() as tmp, Storage(str(Path(tmp) / "brand.db")) as db:
            cfg = AppConfig(telegram_bot_token=secret_tok, ai_api_key="", owner_ids={999})
            llm = UniversalAIClient("", cfg.ai_base_url, cfg.ai_model)
            eng = GuardEngine(cfg, db, llm)

            dash_txt, dash_kb = build_start_dashboard(eng, 999, bot_username="AdKillerAIDemoBot")
            self.assertIn("https://t.me/AdKillerAIDemoBot", dash_txt)
            btn_cbs = [b.callback_data for row in dash_kb.inline_keyboard for b in row]
            self.assertIn("brand:menu", btn_cbs)

            bview_txt, _ = build_branding_view(eng, bot_username="AdKillerAIDemoBot")
            self.assertIn("https://t.me/AdKillerAIDemoBot", bview_txt)

            ctx = SimpleNamespace(
                bot=SimpleNamespace(username="AdKillerAIDemoBot"),
                application=SimpleNamespace(bot_data={"engine": eng}),
            )

            # Non-owner rejected
            q_stranger = SimpleNamespace(
                data="brand:apply_all",
                from_user=SimpleNamespace(id=12345),
                message=SimpleNamespace(chat=SimpleNamespace(id=12345, type="private")),
                answer=AsyncMock(),
                edit_message_text=AsyncMock(),
            )
            asyncio.run(handle_callback(SimpleNamespace(callback_query=q_stranger), ctx))
            q_stranger.edit_message_text.assert_not_called()

            # Group chat rejected even for owner
            q_group = SimpleNamespace(
                data="brand:apply_all",
                from_user=SimpleNamespace(id=999),
                message=SimpleNamespace(chat=SimpleNamespace(id=-1001, type="supergroup")),
                answer=AsyncMock(),
                edit_message_text=AsyncMock(),
            )
            asyncio.run(handle_callback(SimpleNamespace(callback_query=q_group), ctx))
            q_group.edit_message_text.assert_not_called()

            # Owner clicks brand:ask:name -> sends custom name in DM -> updates via set_bot_name!
            orig_set_name = branding.set_bot_name
            from adkiller import panel as panel_mod

            orig_panel_set_name = panel_mod.set_bot_name
            mock_set_name = AsyncMock(return_value=(True, "成功"))
            panel_mod.set_bot_name = mock_set_name  # type: ignore[assignment]
            try:
                q_ask = SimpleNamespace(
                    data="brand:ask:name",
                    from_user=SimpleNamespace(id=999),
                    message=SimpleNamespace(chat=SimpleNamespace(id=999, type="private")),
                    answer=AsyncMock(),
                    edit_message_text=AsyncMock(),
                )
                asyncio.run(handle_callback(SimpleNamespace(callback_query=q_ask), ctx))
                self.assertIn(999, eng.pending_owner_input)

                m_name = SimpleNamespace(
                    chat=SimpleNamespace(id=999, type="private"),
                    text="我的AI-智能广告杀手守卫",
                    photo=None,
                    reply_text=AsyncMock(),
                )
                asyncio.run(
                    handle_private_owner_input(
                        SimpleNamespace(message=m_name, effective_user=SimpleNamespace(id=999)),
                        ctx,
                    )
                )
                mock_set_name.assert_awaited_once_with(secret_tok, "我的AI-智能广告杀手守卫")
                m_name.reply_text.assert_awaited_once()
            finally:
                branding.set_bot_name = orig_set_name
                panel_mod.set_bot_name = orig_panel_set_name

            # 5. Bot joins a group (MY_CHAT_MEMBER) -> posts AI-智能广告杀手 avatar photo + entrance announcement!
            from telegram.error import Forbidden

            bot_join = SimpleNamespace(
                send_photo=AsyncMock(),
                send_message=AsyncMock(),
            )
            upd_join = SimpleNamespace(
                my_chat_member=SimpleNamespace(
                    chat=SimpleNamespace(id=-10077, title="NewGroup", type="supergroup"),
                    from_user=SimpleNamespace(id=999, full_name="Owner"),
                    old_chat_member=SimpleNamespace(status="left"),
                    new_chat_member=SimpleNamespace(
                        status="administrator",
                        can_delete_messages=True,
                        can_restrict_members=True,
                    ),
                )
            )
            asyncio.run(eng.handle_my_chat_member(upd_join, SimpleNamespace(bot=bot_join)))
            bot_join.send_photo.assert_awaited_once()
            self.assertEqual(bot_join.send_photo.call_args.args[0], -10077)
            self.assertIn("AI-智能广告杀手入场报到", bot_join.send_photo.call_args.kwargs["caption"])
            self.assertEqual(bot_join.send_photo.call_args.kwargs["photo"][:2], b"\xff\xd8")
            # Immediate duplicate event within 60s is deduplicated
            asyncio.run(eng.handle_my_chat_member(upd_join, SimpleNamespace(bot=bot_join)))
            self.assertEqual(bot_join.send_photo.call_count, 1)

            # Fallback to plain text if group restricts send_photo before promotion
            bot_no_photo = SimpleNamespace(
                send_photo=AsyncMock(side_effect=Forbidden("no media rights")),
                send_message=AsyncMock(),
            )
            upd_join2 = SimpleNamespace(
                my_chat_member=SimpleNamespace(
                    chat=SimpleNamespace(id=-10078, title="MediaRestrictedGroup", type="supergroup"),
                    from_user=SimpleNamespace(id=999, full_name="Owner"),
                    old_chat_member=SimpleNamespace(status="left"),
                    new_chat_member=SimpleNamespace(status="member"),
                )
            )
            asyncio.run(eng.handle_my_chat_member(upd_join2, SimpleNamespace(bot=bot_no_photo)))
            bot_no_photo.send_message.assert_awaited_once()
            self.assertIn("AI-智能广告杀手入场报到", bot_no_photo.send_message.call_args.args[1])
            self.assertIn("设为群管理员", bot_no_photo.send_message.call_args.args[1])

    def test_29_runtime_status_stats_telegram_key_detection_and_reports(self) -> None:
        import io
        from contextlib import redirect_stdout
        from adkiller import cli_stats
        from adkiller.panel import build_start_dashboard, build_stats_view, handle_callback

        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            data_dir = work / "data"
            data_dir.mkdir(parents=True, exist_ok=True)
            # Server .env intentionally has EMPTY AI_API_KEY (simulating user configuring AI inside Telegram /start!)
            (work / ".env").write_text(
                "TELEGRAM_BOT_TOKEN=123456789:AABBCCDDEEFFGGHHIIJJKKLL\n"
                "OWNER_IDS=999\n"
                "AI_API_KEY=\n"
                "AI_BASE_URL=https://api.deepseek.com/v1\n"
                "AI_MODEL=deepseek-flash\n",
                encoding="utf-8",
            )
            db_path = data_dir / "adkiller.db"
            with Storage(str(db_path)) as db:
                cfg = AppConfig(telegram_bot_token="123456789:AABBCCDDEEFFGGHHIIJJKKLL", ai_api_key="", owner_ids={999})
                llm = UniversalAIClient("", cfg.ai_base_url, cfg.ai_model)
                eng = GuardEngine(cfg, db, llm)

                # Owner sets API Key via Telegram private chat (saved to SQLite kv_meta, NOT .env!)
                secret_ai_key = "sk-tg-secret-999988887777"
                asyncio.run(
                    eng.update_ai_config(
                        base_url="https://api.openai.com/v1",
                        model="gpt-5-mini",
                        api_key=secret_ai_key,
                    )
                )

                # Seed 2 groups (1 active, 1 dry_run) + kills + suspects + AI reports + metrics
                g1 = eng.get_group_settings(-1001, "技术交流群")
                g2 = eng.get_group_settings(-1002, "测试观察群")
                g2.dry_run = True
                db.save_group(g1)
                db.save_group(g2)
                db.inc_metric(-1001, "bans", 3)
                db.inc_metric(-1001, "mutes", 1)
                db.inc_metric(-1001, "ai_checks", 12)
                db.inc_metric(-1001, "vision_checks", 2)
                db.record_token_usage(-1001, 2000, 150, 1500)
                db.log_action(-1001, 101, None, "广告A", "ai_text", 95, "推销兼职刷单", "日结500", False)
                db.log_action(-1001, 102, None, "广告B", "ai_vision", 92, "二维码图片引流", "[图片]", False)
                db.log_action(-1001, 103, None, "黑库C", "cas_join", 100, "命中 CAS 全球黑库", "入群触发", False)
                db.log_action(-1001, 104, None, "疑似D", "gray_zone", 72, "疑似软广外链", "看看这个链接", False)
                db.log_action(-1001, 105, None, "轻疑E", "ai_suspect", 48, "略像推广但证据不足", "帮朋友转发", True)

                # 1. cli_stats detects Telegram-configured API key from SQLite even when .env AI_API_KEY is blank!
                snap = cli_stats.collect_runtime_snapshot(work)
                self.assertTrue(snap["ai"]["configured"])
                self.assertEqual(snap["ai"]["source"], "telegram")
                self.assertEqual(snap["ai"]["model"], "gpt-5-mini")
                self.assertEqual(snap["groups_total"], 2)
                self.assertEqual(snap["groups_enabled"], 1)
                self.assertEqual(snap["groups_dry"], 1)
                self.assertEqual(snap["today"]["bans"], 3)
                self.assertEqual(snap["suspect_total"], 2)
                self.assertEqual(dict(snap["breakdown"]), {"ai_text": 1, "ai_vision": 1, "cas_join": 1})

                # 2. All 5 CLI report modes render cleanly & NEVER leak raw API key!
                for mode in ("summary", "overview", "kills", "suspects", "ai"):
                    buf = io.StringIO()
                    with redirect_stdout(buf):
                        rc = cli_stats.main(["cli_stats", mode, str(work)])
                    out = buf.getvalue()
                    self.assertEqual(rc, 0)
                    self.assertNotIn(secret_ai_key, out)
                    self.assertNotIn("AABBCCDDEEFF", out)
                    if mode == "summary":
                        self.assertIn("AI_CONFIGURED=1", out)
                        self.assertIn("AI_MODEL=gpt-5-mini", out)
                        self.assertIn("GROUPS_TOTAL=2", out)
                    elif mode == "kills":
                        self.assertIn("AI 语义拦截", out)
                        self.assertIn("CAS 入群黑库", out)
                    elif mode == "suspects":
                        self.assertIn("疑似D", out)
                        self.assertIn("轻疑E", out)
                    elif mode == "ai":
                        self.assertIn("gpt-5-mini", out)
                        self.assertIn("75%", out)  # 1500/2000 KV cache hit rate!

                # 3. Telegram private /start dashboard & stats:* GUI sub-views + access control
                dash_txt, dash_kb = build_start_dashboard(eng, 999, bot_username="AdKillerAIBot")
                self.assertIn("共 2 个群", dash_txt)
                self.assertIn("stats:overview", [b.callback_data for row in dash_kb.inline_keyboard for b in row])

                for view_name, expected_str in (
                    ("overview", "运行状态总览"),
                    ("kills", "广告击杀明细"),
                    ("suspects", "疑似与待复核排查"),
                    ("ai", "AI 审核汇报"),
                ):
                    vtxt, _ = build_stats_view(eng, view=view_name)
                    self.assertIn(expected_str, vtxt)

                ctx = SimpleNamespace(
                    bot=SimpleNamespace(username="AdKillerAIBot"),
                    application=SimpleNamespace(bot_data={"engine": eng}),
                )
                # Stranger cannot open stats:*
                q_bad = SimpleNamespace(
                    data="stats:kills",
                    from_user=SimpleNamespace(id=12345),
                    message=SimpleNamespace(chat=SimpleNamespace(id=12345, type="private")),
                    answer=AsyncMock(),
                    edit_message_text=AsyncMock(),
                )
                asyncio.run(handle_callback(SimpleNamespace(callback_query=q_bad), ctx))
                q_bad.edit_message_text.assert_not_called()

                # Owner can open stats:kills in private DM
                q_ok = SimpleNamespace(
                    data="stats:kills",
                    from_user=SimpleNamespace(id=999),
                    message=SimpleNamespace(chat=SimpleNamespace(id=999, type="private")),
                    answer=AsyncMock(),
                    edit_message_text=AsyncMock(),
                )
                asyncio.run(handle_callback(SimpleNamespace(callback_query=q_ok), ctx))
                q_ok.edit_message_text.assert_awaited_once()

                # 4. Group /start: admin gets quick guide + /config button; non-admin is ignored so Group 1 anti-spam runs!
                from adkiller.panel import cmd_start_group

                m_grp_nonadmin = SimpleNamespace(
                    chat=SimpleNamespace(id=-1001, title="技术交流群", type="supergroup"),
                    message_id=301,
                    reply_text=AsyncMock(),
                )
                bot_grp = SimpleNamespace(
                    username="AdKillerAIBot",
                    get_chat_member=AsyncMock(return_value=SimpleNamespace(status="member")),
                    delete_message=AsyncMock(),
                )
                ctx_grp = SimpleNamespace(bot=bot_grp, application=SimpleNamespace(bot_data={"engine": eng}))
                asyncio.run(
                    cmd_start_group(
                        SimpleNamespace(message=m_grp_nonadmin, effective_user=SimpleNamespace(id=5555)),
                        ctx_grp,
                    )
                )
                m_grp_nonadmin.reply_text.assert_not_called()
                self.assertFalse(eng.consume_handled_command(-1001, 301))

                m_grp_admin = SimpleNamespace(
                    chat=SimpleNamespace(id=-1001, title="技术交流群", type="supergroup"),
                    message_id=302,
                    reply_text=AsyncMock(return_value=SimpleNamespace(message_id=303)),
                )
                asyncio.run(
                    cmd_start_group(
                        SimpleNamespace(message=m_grp_admin, effective_user=SimpleNamespace(id=999)),
                        ctx_grp,
                    )
                )
                m_grp_admin.reply_text.assert_awaited_once()
                self.assertTrue(eng.consume_handled_command(-1001, 302))

    def test_30_anonymous_admin_and_linked_channel_command_auth(self) -> None:
        from adkiller.panel import (
            cmd_config,
            cmd_sban,
            cmd_start_group,
            handle_group_admin_input,
        )

        with tempfile.TemporaryDirectory() as tmp, Storage(str(Path(tmp) / "anon.db")) as db:
            cfg = AppConfig(telegram_bot_token="t", ai_api_key="", owner_ids={999})
            llm = UniversalAIClient("", cfg.ai_base_url, cfg.ai_model)
            eng = GuardEngine(cfg, db, llm)

            anon_creator = SimpleNamespace(
                status="creator",
                user=SimpleNamespace(id=5689),
                is_anonymous=True,
                can_delete_messages=None,
                can_restrict_members=None,
            )
            bot_only_creator = SimpleNamespace(
                id=1,
                username="AdKillerAIBot",
                get_chat_administrators=AsyncMock(return_value=[anon_creator]),
                get_chat=AsyncMock(return_value=SimpleNamespace(linked_chat_id=-100444)),
                get_chat_member=AsyncMock(return_value=anon_creator),
                delete_message=AsyncMock(),
                ban_chat_member=AsyncMock(),
                send_message=AsyncMock(return_value=SimpleNamespace(message_id=900)),
                edit_message_text=AsyncMock(),
            )
            ctx_ok = SimpleNamespace(
                bot=bot_only_creator,
                args=[],
                application=SimpleNamespace(bot_data={"engine": eng}),
            )

            # 1. Anonymous Group Creator (from_user=1087968824, sender_chat=group) -> /start, /config, /sban all work!
            anon_user = SimpleNamespace(id=1087968824, full_name="Group", username="GroupAnonymousBot", is_bot=True)
            group_sender = SimpleNamespace(id=-1001, title="TestGroup", type="supergroup")

            m_start = SimpleNamespace(
                chat=group_sender,
                message_id=10,
                from_user=anon_user,
                sender_chat=group_sender,
                is_automatic_forward=False,
                reply_text=AsyncMock(return_value=SimpleNamespace(message_id=11)),
            )
            asyncio.run(cmd_start_group(SimpleNamespace(message=m_start, effective_user=anon_user), ctx_ok))
            m_start.reply_text.assert_awaited_once()
            self.assertTrue(eng.consume_handled_command(-1001, 10))

            m_cfg = SimpleNamespace(
                chat=group_sender,
                message_id=12,
                from_user=anon_user,
                sender_chat=group_sender,
                is_automatic_forward=False,
                reply_text=AsyncMock(),
            )
            asyncio.run(cmd_config(SimpleNamespace(message=m_cfg, effective_user=anon_user), ctx_ok))
            m_cfg.reply_text.assert_awaited_once()
            self.assertTrue(eng.consume_handled_command(-1001, 12))

            spam_target = _fake_msg(chat_id=-1001, msg_id=13, user_id=777, text="广告消息")
            m_sban = SimpleNamespace(
                chat=group_sender,
                message_id=14,
                from_user=anon_user,
                sender_chat=group_sender,
                is_automatic_forward=False,
                reply_to_message=spam_target,
                reply_text=AsyncMock(),
            )
            asyncio.run(cmd_sban(SimpleNamespace(message=m_sban, effective_user=anon_user), ctx_ok))
            bot_only_creator.ban_chat_member.assert_awaited_once_with(-1001, 777, revoke_messages=True)

            # 2. Anonymous admin replying to a GUI custom-template prompt (originally clicked with real UID 5689!)
            eng.set_admin_input_state(-1001, 5689, -1001, "announce_template", panel_msg_id=50)
            m_anon_tpl = SimpleNamespace(
                chat=group_sender,
                message_id=15,
                from_user=anon_user,
                sender_chat=group_sender,
                text="匿名自定义封禁：{user} ({reason})",
                reply_text=AsyncMock(),
            )
            asyncio.run(
                handle_group_admin_input(
                    SimpleNamespace(message=m_anon_tpl, effective_user=anon_user),
                    ctx_ok,
                )
            )
            self.assertEqual(
                eng.get_group_settings(-1001).announce_template,
                "匿名自定义封禁：{user} ({reason})",
            )

            # 3. Privilege-escalation guard: if another limited anonymous admin exists without ban rights,
            #    anonymous /config still opens (buttons check real UID), while anonymous /sban is DENIED!
            limited_anon = SimpleNamespace(
                status="administrator",
                user=SimpleNamespace(id=5690),
                is_anonymous=True,
                can_delete_messages=True,
                can_restrict_members=False,
            )
            bot_only_creator.get_chat_administrators = AsyncMock(return_value=[anon_creator, limited_anon])
            bot_only_creator.ban_chat_member.reset_mock()
            m_cfg2 = SimpleNamespace(
                chat=group_sender,
                message_id=16,
                from_user=anon_user,
                sender_chat=group_sender,
                is_automatic_forward=False,
                reply_text=AsyncMock(),
            )
            asyncio.run(cmd_config(SimpleNamespace(message=m_cfg2, effective_user=anon_user), ctx_ok))
            m_cfg2.reply_text.assert_awaited_once()

            m_sban2 = SimpleNamespace(
                chat=group_sender,
                message_id=17,
                from_user=anon_user,
                sender_chat=group_sender,
                is_automatic_forward=False,
                reply_to_message=spam_target,
                reply_text=AsyncMock(),
            )
            asyncio.run(cmd_sban(SimpleNamespace(message=m_sban2, effective_user=anon_user), ctx_ok))
            bot_only_creator.ban_chat_member.assert_not_called()

            # 4. Linked channel Send-As (-100444) can open read-only /config, NEVER execute /sban;
            #    External random channel (-100999) is DENIED on BOTH /config and /sban!
            ch_bot_user = SimpleNamespace(id=136817688, full_name="Channel", username="Channel_Bot", is_bot=True)
            linked_sender = SimpleNamespace(id=-100444, title="LinkedCh", type="channel")
            ext_sender = SimpleNamespace(id=-100999, title="RandomExtCh", type="channel")

            m_linked_cfg = SimpleNamespace(
                chat=group_sender,
                message_id=18,
                from_user=ch_bot_user,
                sender_chat=linked_sender,
                is_automatic_forward=False,
                reply_text=AsyncMock(),
            )
            asyncio.run(cmd_config(SimpleNamespace(message=m_linked_cfg, effective_user=ch_bot_user), ctx_ok))
            m_linked_cfg.reply_text.assert_awaited_once()

            m_linked_sban = SimpleNamespace(
                chat=group_sender,
                message_id=19,
                from_user=ch_bot_user,
                sender_chat=linked_sender,
                is_automatic_forward=False,
                reply_to_message=spam_target,
                reply_text=AsyncMock(),
            )
            asyncio.run(cmd_sban(SimpleNamespace(message=m_linked_sban, effective_user=ch_bot_user), ctx_ok))
            bot_only_creator.ban_chat_member.assert_not_called()

            m_ext_cfg = SimpleNamespace(
                chat=group_sender,
                message_id=20,
                from_user=ch_bot_user,
                sender_chat=ext_sender,
                is_automatic_forward=False,
                reply_text=AsyncMock(),
            )
            asyncio.run(cmd_config(SimpleNamespace(message=m_ext_cfg, effective_user=ch_bot_user), ctx_ok))
            m_ext_cfg.reply_text.assert_not_called()

            # 5. Anti-collision guard with 2+ full-rights anonymous admins:
            #    (a) Even if group input was pending, resolve_anon_admin_input_uid returns None so
            #        Admin B's anonymous chat can NEVER hijack Admin A's pending config!
            #    (b) Clicking an_ask_tpl in group routes the input prompt to Admin A's personal DM!
            from adkiller.panel import handle_callback
            from telegram.error import Forbidden

            anon_admin_b = SimpleNamespace(
                status="administrator",
                user=SimpleNamespace(id=5699),
                is_anonymous=True,
                can_delete_messages=True,
                can_restrict_members=True,
            )
            bot_only_creator.get_chat_administrators = AsyncMock(return_value=[anon_creator, anon_admin_b])
            bot_only_creator.get_chat_member = AsyncMock(return_value=anon_creator)
            bot_only_creator.send_message = AsyncMock(return_value=SimpleNamespace(message_id=501))

            # (a) Race condition: group pending input exists for 5689, Admin B chats anonymously -> ignored!
            gs_before = eng.get_group_settings(-1001).announce_template
            eng.set_admin_input_state(-1001, 5689, -1001, "announce_template", panel_msg_id=14)
            m_b_chat = SimpleNamespace(
                chat=group_sender,
                message_id=21,
                from_user=anon_user,
                sender_chat=group_sender,
                text="管理员B的普通群聊发言",
                reply_text=AsyncMock(),
            )
            asyncio.run(handle_group_admin_input(SimpleNamespace(message=m_b_chat, effective_user=anon_user), ctx_ok))
            self.assertEqual(eng.get_group_settings(-1001).announce_template, gs_before)
            self.assertIn((-1001, 5689), eng.pending_admin_input)

            # (b) Clicking an_ask_tpl in group routes cleanly to Admin A's DM (5689, 5689), NOT group (-1001, 5689)!
            q_ask = SimpleNamespace(
                data="cfg:an_ask_tpl:-1001",
                from_user=SimpleNamespace(id=5689, full_name="OwnerA"),
                message=SimpleNamespace(chat=group_sender, message_id=14),
                answer=AsyncMock(),
                edit_message_text=AsyncMock(),
            )
            asyncio.run(handle_callback(SimpleNamespace(callback_query=q_ask), ctx_ok))
            bot_only_creator.send_message.assert_awaited_once()
            self.assertEqual(bot_only_creator.send_message.call_args.args[0], 5689)
            self.assertNotIn((-1001, 5689), eng.pending_admin_input)
            self.assertIn((5689, 5689), eng.pending_admin_input)

            # (c) If Admin A hasn't started DM (Forbidden), refuse to set group pending input!
            eng.clear_admin_input_state(5689, 5689)
            bot_only_creator.send_message = AsyncMock(side_effect=Forbidden("bot was blocked"))
            q_ask2 = SimpleNamespace(
                data="cfg:an_ask_delay:-1001",
                from_user=SimpleNamespace(id=5689, full_name="OwnerA"),
                message=SimpleNamespace(chat=group_sender, message_id=14),
                answer=AsyncMock(),
                edit_message_text=AsyncMock(),
            )
            asyncio.run(handle_callback(SimpleNamespace(callback_query=q_ask2), ctx_ok))
            self.assertNotIn((-1001, 5689), eng.pending_admin_input)
            self.assertNotIn((5689, 5689), eng.pending_admin_input)

    def test_31_obfuscated_promo_nickname_cas_401_and_dm_forward_diagnostics(self) -> None:
        """Verify obfuscated promo-bait nicknames + single-digit bait ban cleanly, CAS 401 circuit-breaks,
        extended media types avoid '(空消息)', and owner DM forwarded samples are diagnosed & archived."""
        from adkiller.llm import SpamVerdict
        from adkiller.panel import handle_private_owner_input
        from adkiller.xray import deobfuscate_profile_text, inspect_raw_message_fields

        # 1. Obfuscated promo nickname de-obfuscation & additive scoring
        for raw_name in [
            "-点-简界*·看·橡·-木",
            "好*路·子-在-朱*叶·稳",
            "🔥*抖音1代2刷🔥",
            "·副·业看·简界·曰3K",
        ]:
            _, _, is_obf = deobfuscate_profile_text(raw_name)
            self.assertTrue(is_obf, msg=f"expected obfuscation hit for {raw_name}")
            flags, boost, is_max = analyze_profile_risk(
                {"full_name": raw_name, "username": "(无)", "bio": "", "personal_channel": "", "has_photo": True},
                clean_count=0,
            )
            self.assertGreaterEqual(boost, 30, msg=f"boost too low for {raw_name}: {flags}")
            self.assertTrue(is_max, msg=f"expected max_risk for {raw_name}")

        # Normal nicknames (including ALL-CAPS tech acronyms & bio links) must stay at +0 boost
        for normal_name in ["Kylin-010", "王小明", "Linux_Dev", "广州-张三", "HTTP", "NVMe"]:
            flags, boost, is_max = analyze_profile_risk(
                {"full_name": normal_name, "username": "@devuser", "bio": "个人博客 https://t.me/mytech", "personal_channel": "我的笔记 @mynote", "has_photo": True},
                clean_count=0,
            )
            self.assertEqual(boost, 0, msg=f"unexpected boost for normal user {normal_name}: {flags}")
            self.assertFalse(is_max)

        # Single-word vowel-less gibberish bot name (like live 'Gbgjf' / 'Zllh') gets +8 & max_risk with blank profile
        g_flags, g_boost, g_max = analyze_profile_risk(
            {"full_name": "Gbgjf", "username": "(无)", "bio": "", "personal_channel": "", "has_photo": False},
            clean_count=0,
        )
        self.assertEqual(g_boost, 17)  # +8 gibberish +4 no_avatar +3 empty +2 no_username
        self.assertTrue(g_max)

        # 2. Live pipeline test: '-点-简界*·看·橡·-木' sends '5' with spam_score=85 and hesitant AI=57 -> BANNED!
        with tempfile.TemporaryDirectory() as tmp:
            db = Storage(str(Path(tmp) / "t.db"))
            try:
                cfg = AppConfig(telegram_bot_token="123456:TESTTOKEN", ai_api_key="sk-test", owner_ids={5689})
                llm = UniversalAIClient("sk-test", "https://api.deepseek.com/v1", "deepseek-flash")
                llm.classify = AsyncMock(
                    return_value=SpamVerdict(
                        is_spam=False, score=57, reason="单字5，昵称疑似引流", used_vision=False
                    )
                )
                eng = GuardEngine(cfg, db, llm)
                gs = eng.get_group_settings(-1001, "TestGrp")
                gs.spam_score = 85
                gs.cas_enabled = False
                gs.announce_in_group = False
                db.save_group(gs)

                spam_user = SimpleNamespace(id=7525595504, full_name="-点-简界*·看·橡·-木", username=None, is_bot=False)
                bot = SimpleNamespace(
                    id=111,
                    get_chat_administrators=AsyncMock(return_value=[]),
                    get_chat_member=AsyncMock(return_value=SimpleNamespace(status="member")),
                    get_chat=AsyncMock(
                        return_value=SimpleNamespace(photo=object(), bio="", personal_chat=None)
                    ),
                    delete_message=AsyncMock(),
                    ban_chat_member=AsyncMock(),
                    send_message=AsyncMock(),
                )
                grp_chat = SimpleNamespace(id=-1001, title="TestGrp", type="supergroup")
                msg_bait = SimpleNamespace(
                    chat=grp_chat,
                    message_id=99,
                    from_user=spam_user,
                    sender_chat=None,
                    text="5",
                    caption=None,
                    entities=[],
                    caption_entities=[],
                    media_group_id=None,
                    reply_to_message=None,
                    reply_markup=None,
                    via_bot=None,
                    external_reply=None,
                    quote=None,
                    forward_origin=None,
                    link_preview_options=None,
                    poll=None,
                    story=None,
                    paid_media=None,
                    photo=None,
                    sticker=None,
                    video=None,
                    video_note=None,
                    animation=None,
                    voice=None,
                    audio=None,
                    document=None,
                    contact=None,
                    venue=None,
                    location=None,
                    dice=None,
                    game=None,
                )
                ctx = SimpleNamespace(bot=bot, application=SimpleNamespace(bot_data={"engine": eng}))
                asyncio.run(eng.handle_message(SimpleNamespace(message=msg_bait, edited_message=None), ctx))
                # 57 + 32 = 89 >= 85 -> permanently banned!
                bot.ban_chat_member.assert_awaited_once_with(-1001, 7525595504, revoke_messages=True)
                # Verify prompt sent to AI included de-obfuscated nickname + bait exposure warning
                sent_summary = llm.classify.call_args.kwargs["summary_text"]
                self.assertIn("点简界看橡木", sent_summary)
                self.assertIn("蹭曝光", sent_summary)

                # 3. Extended media extraction prevents '(空消息)' on contact / voice / video_note / animated sticker
                msg_contact = SimpleNamespace(
                    text=None, caption=None, entities=[], caption_entities=[],
                    contact=SimpleNamespace(first_name="招代理", last_name="", phone_number="+852123456"),
                )
                x_contact = extract_xray(msg_contact)
                self.assertIn("分享名片", x_contact.build_preview())
                msg_vsticker = SimpleNamespace(
                    text=None, caption=None, entities=[], caption_entities=[],
                    sticker=SimpleNamespace(is_animated=False, is_video=True, thumbnail=None, emoji="🔥", set_name="adset"),
                )
                x_vs = extract_xray(msg_vsticker)
                self.assertIn("kind=video, thumb=no", x_vs.sticker_info)
                raw_vs = inspect_raw_message_fields(msg_vsticker)
                self.assertTrue(raw_vs["sticker"]["is_video"])
                self.assertFalse(raw_vs["sticker"]["has_thumbnail"])

                # 4. CAS 401 circuit breaker: hits API once, pauses subsequent calls
                cas = CASChecker(auth_cooldown_seconds=3600)
                mock_http = SimpleNamespace(
                    is_closed=False,
                    get=AsyncMock(return_value=SimpleNamespace(status_code=401, json=lambda: {"ok": False})),
                )
                cas._client = mock_http
                self.assertFalse(asyncio.run(cas.is_banned(10001, now=1000.0)))
                self.assertFalse(asyncio.run(cas.is_banned(10002, now=1005.0)))
                self.assertEqual(mock_http.get.await_count, 1)

                # 5. Owner DM forwarded sample diagnosis saves to SQLite & replies; non-owner is ignored
                dm_chat = SimpleNamespace(id=5689, type="private")
                owner_u = SimpleNamespace(id=5689, full_name="Owner")
                fwd_origin = SimpleNamespace(type="user", sender_user=spam_user)
                m_fwd = SimpleNamespace(
                    chat=dm_chat,
                    message_id=200,
                    from_user=owner_u,
                    text="5",
                    caption=None,
                    entities=[],
                    caption_entities=[],
                    forward_origin=fwd_origin,
                    reply_text=AsyncMock(),
                )
                asyncio.run(handle_private_owner_input(SimpleNamespace(message=m_fwd, effective_user=owner_u), ctx))
                m_fwd.reply_text.assert_awaited_once()
                reply_txt = m_fwd.reply_text.call_args.args[0]
                self.assertIn("样本诊断 #1", reply_txt)
                self.assertIn("92 分", reply_txt)
                saved = db.list_forwarded_samples(limit=5)
                self.assertEqual(len(saved), 1)
                self.assertEqual(saved[0]["ai_score"], 92)
                self.assertEqual(saved[0]["origin_user_id"], 7525595504)

                # Non-owner forward in DM -> completely ignored!
                stranger = SimpleNamespace(id=99999, full_name="Stranger")
                m_stranger_fwd = SimpleNamespace(
                    chat=SimpleNamespace(id=99999, type="private"),
                    message_id=201,
                    from_user=stranger,
                    text="5",
                    forward_origin=fwd_origin,
                    reply_text=AsyncMock(),
                )
                asyncio.run(handle_private_owner_input(SimpleNamespace(message=m_stranger_fwd, effective_user=stranger), ctx))
                m_stranger_fwd.reply_text.assert_not_called()
                self.assertEqual(len(db.list_forwarded_samples(limit=5)), 1)
            finally:
                db.conn.close()

    def test_32_owner_only_group_join_guard_and_auto_leave(self) -> None:
        """Verify owner-only group join guard defaults ON, auto-leaves stranger groups (online & offline add),
        alerts owner in DM without spending AI tokens, and can be toggled from private /start dashboard."""
        from adkiller.panel import build_start_dashboard, handle_callback

        with tempfile.TemporaryDirectory() as tmp:
            db = Storage(str(Path(tmp) / "t.db"))
            try:
                cfg = AppConfig(telegram_bot_token="123456:TESTTOKEN", ai_api_key="sk-test", owner_ids={5689})
                llm = UniversalAIClient("sk-test", "https://api.deepseek.com/v1", "deepseek-flash")
                llm.classify = AsyncMock()
                eng = GuardEngine(cfg, db, llm)

                # 1. Default ON
                self.assertTrue(eng.is_owner_only_join_enabled())
                dash_txt, _ = build_start_dashboard(eng, 5689, bot_username="DemoBot")
                self.assertIn("仅超管可拉群", dash_txt)

                # 2. Stranger (8888) adds bot to -100991 -> auto-leave + alert owner + zero DB pollution
                bot = SimpleNamespace(
                    id=111,
                    leave_chat=AsyncMock(),
                    send_photo=AsyncMock(),
                    send_message=AsyncMock(),
                    get_chat_administrators=AsyncMock(return_value=[]),
                )
                upd_stranger = SimpleNamespace(
                    my_chat_member=SimpleNamespace(
                        chat=SimpleNamespace(id=-100991, title="StrangerGrp", type="supergroup"),
                        from_user=SimpleNamespace(id=8888, full_name="Stranger", username="stranger"),
                        old_chat_member=SimpleNamespace(status="left"),
                        new_chat_member=SimpleNamespace(status="administrator", can_delete_messages=True, can_restrict_members=True),
                    )
                )
                asyncio.run(eng.handle_my_chat_member(upd_stranger, SimpleNamespace(bot=bot)))
                bot.leave_chat.assert_awaited_once_with(-100991)
                bot.send_photo.assert_not_called()
                self.assertFalse(db.has_group(-100991))
                bot.send_message.assert_awaited_once()
                self.assertEqual(bot.send_message.call_args.args[0], 5689)
                self.assertIn("已拦截未授权拉群并自动退群", bot.send_message.call_args.args[1])

                # 3. Offline-add loophole: unseen group -100992 sends a message, no owner in admins -> auto-leave, 0 AI calls!
                bot.leave_chat.reset_mock()
                bot.send_message.reset_mock()
                stranger_chat = SimpleNamespace(id=-100992, title="OfflineStrangerGrp", type="supergroup")
                msg_offline = SimpleNamespace(
                    chat=stranger_chat,
                    message_id=10,
                    from_user=SimpleNamespace(id=7777, full_name="User", username=None, is_bot=False),
                    sender_chat=None,
                    text="微信洗钱 一天8000",
                    caption=None,
                    entities=[],
                    caption_entities=[],
                )
                ctx = SimpleNamespace(bot=bot, application=SimpleNamespace(bot_data={"engine": eng}))
                asyncio.run(eng.handle_message(SimpleNamespace(message=msg_offline, edited_message=None), ctx))
                bot.leave_chat.assert_awaited_once_with(-100992)
                llm.classify.assert_not_called()
                self.assertFalse(db.has_group(-100992))

                # 4. Offline-add by Owner: unseen group -100993 has Owner as admin -> auto-authorized, NOT left!
                bot.leave_chat.reset_mock()
                bot.get_chat_administrators = AsyncMock(
                    return_value=[SimpleNamespace(status="creator", user=SimpleNamespace(id=5689))]
                )
                owner_chat = SimpleNamespace(id=-100993, title="OwnerOfflineGrp", type="supergroup")
                ok_auth = asyncio.run(eng._ensure_group_authorized_runtime(bot, owner_chat))
                self.assertTrue(ok_auth)
                bot.leave_chat.assert_not_called()
                self.assertTrue(db.has_group(-100993))

                # 5. Owner toggles join guard OFF via /start callback -> stranger can now add -100994
                q_tog = SimpleNamespace(
                    data="aiconf:toggle_join_guard",
                    from_user=SimpleNamespace(id=5689, full_name="Owner"),
                    message=SimpleNamespace(chat=SimpleNamespace(id=5689, type="private")),
                    answer=AsyncMock(),
                    edit_message_text=AsyncMock(),
                )
                asyncio.run(handle_callback(SimpleNamespace(callback_query=q_tog), ctx))
                self.assertFalse(eng.is_owner_only_join_enabled())

                bot.leave_chat.reset_mock()
                bot.send_photo.reset_mock()
                upd_open = SimpleNamespace(
                    my_chat_member=SimpleNamespace(
                        chat=SimpleNamespace(id=-100994, title="OpenGrp", type="supergroup"),
                        from_user=SimpleNamespace(id=8888, full_name="Stranger", username="stranger"),
                        old_chat_member=SimpleNamespace(status="left"),
                        new_chat_member=SimpleNamespace(status="member"),
                    )
                )
                asyncio.run(eng.handle_my_chat_member(upd_open, SimpleNamespace(bot=bot)))
                bot.leave_chat.assert_not_called()
                bot.send_photo.assert_awaited_once()
                self.assertTrue(db.has_group(-100994))
            finally:
                db.conn.close()


class TestFirstMessageReview(unittest.IsolatedAsyncioTestCase):
    async def test_established_member_joke_skips_semantic_moderation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, Storage(str(Path(tmp) / "moderation.db")) as db:
            cfg = AppConfig(telegram_bot_token="t", ai_api_key="sk-test", owner_ids={999})
            llm = UniversalAIClient("sk-test", "https://example.com/v1", "test-model")
            self.addAsyncCleanup(llm.close)
            llm.classify = AsyncMock(return_value=SpamVerdict(True, 98, "误认群友玩笑"))
            eng = GuardEngine(cfg, db, llm)
            gs = eng.get_group_settings(-1001)
            gs.gray_zone_mute = False
            db.save_group(gs)
            db.increment_clean_count(-1001, 500)
            bot = SimpleNamespace(
                id=1,
                get_chat_administrators=AsyncMock(return_value=[]),
                get_chat=AsyncMock(return_value=SimpleNamespace(photo=None, bio="", personal_chat=None)),
                delete_message=AsyncMock(),
                ban_chat_member=AsyncMock(),
                send_message=AsyncMock(),
            )
            ctx = SimpleNamespace(bot=bot)
            joke = _fake_msg(text="胆大来洗米")
            cached_joke = _fake_msg(msg_id=11, text="刚才有人开玩笑说胆大来洗米，原来是在玩梗")
            fingerprint = eng.spam_cache.fingerprint_message(-1001, extract_xray(cached_joke), None)
            self.assertIsNotNone(fingerprint)
            eng.spam_cache.remember(fingerprint, 98, "历史误判")

            await eng.handle_message(SimpleNamespace(edited_message=None, message=joke), ctx)
            await eng.handle_message(SimpleNamespace(edited_message=None, message=cached_joke), ctx)
            llm.classify.assert_not_awaited()
            bot.delete_message.assert_not_awaited()
            bot.ban_chat_member.assert_not_awaited()

            executable = _fake_msg(msg_id=12, text="", document=SimpleNamespace(file_name="fixture.exe"))
            await eng.handle_message(SimpleNamespace(edited_message=None, message=executable), ctx)
            bot.delete_message.assert_any_await(-1001, 12)
            bot.ban_chat_member.assert_awaited_once_with(-1001, 500, revoke_messages=True)
            llm.classify.assert_not_awaited()

    async def test_first_review_is_per_group_and_survives_concurrency_failure_and_restart(self) -> None:
        cfg = AppConfig(telegram_bot_token="t", ai_api_key="sk-test", owner_ids={999})
        llm = UniversalAIClient("sk-test", "https://example.com/v1", "test-model")
        self.addAsyncCleanup(llm.close)
        first_review_started = asyncio.Event()
        finish_first_review = asyncio.Event()

        async def unavailable(**kwargs):
            first_review_started.set()
            await finish_first_review.wait()
            raise RuntimeError("test provider unavailable")

        llm.classify = AsyncMock(side_effect=unavailable)
        bot = SimpleNamespace(
            id=1,
            get_chat_administrators=AsyncMock(return_value=[]),
            get_chat=AsyncMock(return_value=SimpleNamespace(photo=None, bio="", personal_chat=None)),
            delete_message=AsyncMock(),
            ban_chat_member=AsyncMock(),
        )
        ctx = SimpleNamespace(bot=bot)
        first = _fake_msg(text="你好，第一次来")
        second = _fake_msg(msg_id=11, text="胆大来洗米")
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "moderation.db")
            with Storage(db_path) as db:
                eng = GuardEngine(cfg, db, llm)
                for chat_id in (-1001, -1002):
                    gs = eng.get_group_settings(chat_id)
                    gs.cas_enabled = False
                    db.save_group(gs)
                first_task = asyncio.create_task(
                    eng.handle_message(SimpleNamespace(edited_message=None, message=first), ctx)
                )
                try:
                    await asyncio.wait_for(first_review_started.wait(), timeout=2)
                    await eng.handle_message(SimpleNamespace(edited_message=None, message=second), ctx)
                    llm.classify.assert_awaited_once()
                    self.assertIn(
                        extract_xray(first).normalized_text, llm.classify.call_args.kwargs["summary_text"]
                    )
                finally:
                    finish_first_review.set()
                    await first_task
                self.assertEqual(db.get_clean_count(-1001, 500), 0)

            with Storage(db_path) as db:
                eng = GuardEngine(cfg, db, llm)
                llm.classify = AsyncMock(return_value=SpamVerdict(False, 0, "正常"))
                await eng.handle_message(SimpleNamespace(edited_message=first, message=None), ctx)
                await eng.handle_message(SimpleNamespace(edited_message=None, message=second), ctx)
                llm.classify.assert_not_awaited()
                bot.delete_message.assert_not_awaited()
                bot.ban_chat_member.assert_not_awaited()

                other_group = _fake_msg(chat_id=-1002)
                await eng.handle_message(SimpleNamespace(edited_message=None, message=other_group), ctx)
                llm.classify.assert_awaited_once()

    async def test_plain_start_and_normal_first_messages_are_not_punished(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, Storage(str(Path(tmp) / "moderation.db")) as db:
            cfg = AppConfig(telegram_bot_token="t", ai_api_key="sk-test", owner_ids={999})
            llm = UniversalAIClient("sk-test", "https://example.com/v1", "test-model")
            self.addAsyncCleanup(llm.close)
            normal = SpamVerdict(False, 5, "正常玩笑")
            spam = SpamVerdict(True, 98, "明确招揽广告")
            llm.classify = AsyncMock(return_value=normal)
            eng = GuardEngine(cfg, db, llm)
            gs = eng.get_group_settings(-1001)
            gs.cas_enabled = False
            gs.start_cmd_mode = "ban"
            db.save_group(gs)
            bot = SimpleNamespace(
                id=1,
                get_chat_administrators=AsyncMock(return_value=[]),
                get_chat=AsyncMock(return_value=SimpleNamespace(photo=object(), bio="Linux", personal_chat=None)),
                delete_message=AsyncMock(),
                ban_chat_member=AsyncMock(),
                restrict_chat_member=AsyncMock(),
                send_message=AsyncMock(),
            )
            ctx = SimpleNamespace(bot=bot)
            for message_id, text in enumerate(("/start", "/start@ExampleBot test-token"), 1):
                start = _fake_msg(msg_id=message_id, text=text)
                await eng.handle_message(SimpleNamespace(edited_message=None, message=start), ctx)
            llm.classify.assert_not_awaited()
            bot.delete_message.assert_not_awaited()
            bot.ban_chat_member.assert_not_awaited()

            joke = _fake_msg(text="胆大来洗米")
            joke.from_user.full_name = "小明"
            await eng.handle_message(SimpleNamespace(edited_message=None, message=joke), ctx)

            llm.classify.assert_awaited_once()
            bot.delete_message.assert_not_awaited()
            bot.ban_chat_member.assert_not_awaited()
            bot.restrict_chat_member.assert_not_awaited()
            self.assertEqual(db.get_recent_suspects()[0], 0)

            ad = _fake_msg(msg_id=11, user_id=501, text="招代发，预付开工")
            llm.classify.return_value = spam
            await eng.handle_message(SimpleNamespace(edited_message=None, message=ad), ctx)
            bot.ban_chat_member.assert_awaited_once_with(-1001, 501, revoke_messages=True)

            bot.delete_message.reset_mock()
            llm.classify.reset_mock()
            llm.classify.return_value = normal
            channel = SimpleNamespace(id=-10010, title="Test channel", username="test_channel")
            channel_joke = _fake_msg(msg_id=12, user_id=0, text=joke.text, sender_chat=channel)
            channel_reply = _fake_msg(msg_id=13, user_id=0, text="继续聊天", sender_chat=channel)
            for message in (channel_joke, channel_reply):
                await eng.handle_message(SimpleNamespace(edited_message=None, message=message), ctx)
            llm.classify.assert_awaited_once()
            bot.delete_message.assert_not_awaited()
            self.assertEqual(db.get_recent_suspects()[0], 0)

            other_channel = SimpleNamespace(id=-10020, title="Test ads", username="test_ads")
            channel_ad = _fake_msg(msg_id=14, user_id=0, text=ad.text, sender_chat=other_channel)
            bot.ban_chat_sender_chat = AsyncMock()
            llm.classify.return_value = spam
            await eng.handle_message(SimpleNamespace(edited_message=None, message=channel_ad), ctx)
            bot.delete_message.assert_awaited_once_with(-1001, 14)
            bot.ban_chat_sender_chat.assert_not_awaited()
            _, suspects = db.get_recent_suspects()
            self.assertEqual(suspects[0]["trigger_type"], "channel_review")

    async def test_first_message_collection_ads_are_removed_without_reviewing_followups(self) -> None:
        spam = SpamVerdict(True, 98, "明确招揽广告")
        normal = SpamVerdict(False, 5, "正常交流")
        cases = (
            ("微信帮收款 赚一万", "加群看项目 一天7ooo", spam),
            ("微信帮收款 赚一万", "加群看项目 日赚7千", spam),
            ("微信帮收款 赚一万", "加群看项目", spam),
            ("替我收米 日赚9000", "加群项目 日入6ooo", spam),
            ("招代收 一天9ooo", "", spam),
            ("胆大来洗米", "看看我的技术频道 https://t.me/example", normal),
            ("替我收米 日赚9000是骗局，别信", "", normal),
            ("帮我收款 日结150元", "", normal),
        )
        with tempfile.TemporaryDirectory() as tmp, Storage(str(Path(tmp) / "moderation.db")) as db:
            cfg = AppConfig(telegram_bot_token="t", ai_api_key="sk-test", owner_ids={999})
            llm = UniversalAIClient("sk-test", "https://example.com/v1", "test-model")
            self.addAsyncCleanup(llm.close)
            llm.classify = AsyncMock()
            eng = GuardEngine(cfg, db, llm)
            gs = eng.get_group_settings(-1001)
            gs.spam_score = 85
            gs.cas_enabled = False
            gs.announce_in_group = False
            db.save_group(gs)
            bot = SimpleNamespace(
                id=1,
                get_chat_administrators=AsyncMock(return_value=[]),
                get_chat=AsyncMock(),
                delete_message=AsyncMock(),
                ban_chat_member=AsyncMock(),
                restrict_chat_member=AsyncMock(),
                send_message=AsyncMock(),
            )
            ctx = SimpleNamespace(bot=bot)

            for index, (text, bio, verdict) in enumerate(cases):
                with self.subTest(text=text, bio=bio):
                    llm.classify.reset_mock()
                    llm.classify.return_value = verdict
                    bot.get_chat.return_value = SimpleNamespace(photo=object(), bio=bio, personal_chat=None)
                    bot.delete_message.reset_mock()
                    bot.ban_chat_member.reset_mock()
                    bot.restrict_chat_member.reset_mock()
                    user_id = 500 + index
                    first_id = 2 * index + 1
                    first = _fake_msg(msg_id=first_id, user_id=user_id, text=text)
                    followup = _fake_msg(msg_id=first_id + 1, user_id=user_id, text="微信帮收款 赚一万")

                    await eng.handle_message(SimpleNamespace(edited_message=None, message=first), ctx)
                    llm.classify.return_value = spam
                    await eng.handle_message(SimpleNamespace(edited_message=None, message=followup), ctx)

                    llm.classify.assert_awaited_once()
                    bot.restrict_chat_member.assert_not_awaited()
                    if verdict.is_spam:
                        bot.delete_message.assert_awaited_once_with(-1001, first_id)
                        bot.ban_chat_member.assert_awaited_once_with(-1001, user_id, revoke_messages=True)
                    else:
                        bot.delete_message.assert_not_awaited()
                        bot.ban_chat_member.assert_not_awaited()


class TestCoreFeatures(unittest.TestCase):
    def test_album_deduplication_and_flood(self) -> None:
        tracker = FloodTracker()
        for i in range(6):
            triggered, _ = tracker.record_and_check(
                -1001, 42, 100 + i, "album_xyz", window_seconds=8, max_messages=4, now=1000.0 + i * 0.1
            )
            self.assertFalse(triggered)

        triggered = False
        for i in range(4):
            triggered, burst_ids = tracker.record_and_check(
                -1001, 99, 200 + i, None, window_seconds=8, max_messages=4, now=2000.0 + i
            )
        self.assertTrue(triggered)
        self.assertEqual(burst_ids, [200, 201, 202, 203])

    def test_repeat_send_escalation_math(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Storage(str(Path(tmp) / "esc.db"))
            eff1, h1, ids1 = db.record_repeat_suspect("k1", -1001, 55, 55, 101, now=1000.0)
            eff2, h2, ids2 = db.record_repeat_suspect("k1", -1001, 55, 55, 102, now=1100.0)
            eff3, h3, ids3 = db.record_repeat_suspect("k1", -1001, 55, 55, 103, now=1200.0)
            self.assertEqual((eff1, h1, ids1), (55, 1, [101]))
            self.assertEqual((eff2, h2, ids2), (78, 2, [101, 102]))
            self.assertEqual((eff3, h3, ids3), (89, 3, [101, 102, 103]))
            db.conn.close()

    def test_static_system_prompt_and_usage_extraction(self) -> None:
        client = UniversalAIClient("sk-test", "https://example.com/v1", "deepseek-flash")
        ok_resp = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content='{"state":0,"spam_score":10,"spam_reason":"正常"}')
                )
            ],
            usage=SimpleNamespace(prompt_tokens=800, completion_tokens=40, prompt_cache_hit_tokens=600),
        )
        captured = []

        async def fake_create(**kwargs):
            captured.append(kwargs["messages"])
            return ok_resp

        client.client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=fake_create)))
        report = asyncio.run(client.probe_capabilities())
        self.assertTrue(report.vision_supported)
        verdict = asyncio.run(client.classify(summary_text="聊一下开源工具配置", group_topic="开源技术交流群"))
        self.assertEqual(captured[-1][0]["content"], SYSTEM_PROMPT)
        self.assertIn("开源技术交流群", captured[-1][1]["content"])
        self.assertEqual((verdict.prompt_tokens, verdict.cached_tokens, verdict.completion_tokens), (800, 600, 40))

    def test_zero_llm_basic_rules(self) -> None:
        spam_msg = _fake_msg(
            text="🔥点这里 预付开工 日结500 私聊我",
            entities=[SimpleNamespace(type="text_link", offset=2, length=3, url="https://t.me/+secret123")],
        )
        spam_profile = {"full_name": "aawsda sdawsda", "username": "(无)", "bio": "", "has_photo": False}
        _, boost, _ = analyze_profile_risk(spam_profile, clean_count=0)
        res = evaluate_basic_rules(extract_xray(spam_msg), spam_profile, profile_boost=boost)
        self.assertGreaterEqual(res.score, 80)

        ok_msg = _fake_msg(
            text="大佬们，Linux 装 Docker 报错怎么解决？https://github.com/docker/compose",
            entities=[SimpleNamespace(type="url", offset=22, length=34)],
        )
        ok_res = evaluate_basic_rules(extract_xray(ok_msg), spam_profile, profile_boost=boost)
        self.assertEqual(ok_res.score, 0)

    def test_image_pixel_bomb_rejected(self) -> None:
        from adkiller import xray as xray_mod

        # Oversize byte payload rejected immediately
        self.assertIsNone(_transcode_jpeg_sync(b"x" * (6 * 1024 * 1024)))

        # Oversize pixel dimensions (6000x6000 = 36MP > 25MP) rejected before full decode
        class FakeBombImg:
            width = 6000
            height = 6000
            mode = "RGB"

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        orig_open = getattr(xray_mod.Image, "open", None)
        xray_mod.Image.open = lambda _: FakeBombImg()
        try:
            self.assertIsNone(_transcode_jpeg_sync(b"small_compressed_bomb_bytes"))
        finally:
            if orig_open is not None:
                xray_mod.Image.open = orig_open


if __name__ == "__main__":
    unittest.main()
