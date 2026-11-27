"""SQLite persistence for per-group settings, whitelist, repeat-send escalation, audit logs, and token metrics."""

from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class GroupSettings:
    chat_id: int
    chat_title: str = ""
    enabled: bool = True
    dry_run: bool = False
    vision_enabled: bool = True
    spam_score: int = 80
    gray_zone_mute: bool = True       # 65..(spam_score-1) -> delete + 24h mute + admin review
    cas_enabled: bool = True          # Free Combot Anti-Spam global blacklist pre-check
    join_captcha: bool = False        # Simple 1-tap 🍊 emoji join captcha (off by default to avoid clash with other bots)
    clean_service_msgs: bool = True   # Auto-delete join/leave system notifications
    block_malware_files: bool = True  # Block .apk/.exe/.msi/.bat/.scr/.cmd/.dmg from non-trusted users
    anti_flood: bool = True
    swarm_guard: bool = True          # Multi-account identical repeat -> AI-verified swarm purge (never blind-bans!)
    flood_window: int = 8
    flood_max: int = 6
    via_bot_mode: str = "ban"         # "ban" | "ai" | "off"
    start_cmd_mode: str = "delete"    # "delete" | "ban" | "off"
    check_edited: bool = True
    announce_in_group: bool = True    # Announce ban in group chat (customizable template & auto-delete in GUI)
    announce_delete_seconds: int = 1800  # Auto-delete group ban notice after N seconds (default 30 min; 0 = keep forever)
    announce_template: str = ""       # Custom ban notice template (empty = built-in default)
    log_chat_id: Optional[int] = None
    group_topic: str = ""
    antiraid_until: float = 0.0       # Epoch timestamp until AntiRaid auto-expires
    # Configurable per-group exemption / bypass rules (toggleable in Telegram GUI subpanel)
    exempt_admins: bool = True            # Exempt group creator & administrators
    exempt_anon_admin: bool = True        # Exempt anonymous group admins (sender_chat == chat)
    exempt_linked_channel: bool = True    # Exempt auto-forwarded / linked channel posts
    exempt_trusted: bool = True           # Exempt /trust whitelisted members
    exempt_owners: bool = False           # Off by default: owners are already protected as admins in real groups & can test freely in test groups!
    external_channel_mode: str = "ai"     # "ai" (audit) | "ban" (block all) | "allow" (bypass)
    exempt_veteran_short: bool = True     # Exempt veterans' short <=5-char clean messages from AI
    exempt_reply_cache: bool = True       # Replies skip shared spam_cache auto-ban (always per-person review)
    admin_cache_fallback: bool = True     # Fall back to last known admin list (<=30m) on transient API timeout to avoid deleting admin msgs
    local_rules_enabled: bool = False     # Local keyword heuristic rules: OFF by default (let AI judge semantics to avoid polysemy false positives!)


class Storage:
    def __init__(self, db_path: str):
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self._init_schema()
        self._migrate_schema()
        if os.name != "nt":
            for p in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
                if p.exists():
                    try:
                        os.chmod(p, 0o600)
                    except OSError:
                        pass

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS kv_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS group_settings (
                chat_id INTEGER PRIMARY KEY,
                chat_title TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                dry_run INTEGER NOT NULL DEFAULT 0,
                vision_enabled INTEGER NOT NULL DEFAULT 1,
                spam_score INTEGER NOT NULL DEFAULT 80,
                gray_zone_mute INTEGER NOT NULL DEFAULT 1,
                cas_enabled INTEGER NOT NULL DEFAULT 1,
                join_captcha INTEGER NOT NULL DEFAULT 0,
                clean_service_msgs INTEGER NOT NULL DEFAULT 1,
                block_malware_files INTEGER NOT NULL DEFAULT 1,
                anti_flood INTEGER NOT NULL DEFAULT 1,
                swarm_guard INTEGER NOT NULL DEFAULT 1,
                flood_window INTEGER NOT NULL DEFAULT 8,
                flood_max INTEGER NOT NULL DEFAULT 6,
                via_bot_mode TEXT NOT NULL DEFAULT 'ban',
                start_cmd_mode TEXT NOT NULL DEFAULT 'delete',
                check_edited INTEGER NOT NULL DEFAULT 1,
                announce_in_group INTEGER NOT NULL DEFAULT 1,
                announce_delete_seconds INTEGER NOT NULL DEFAULT 1800,
                announce_template TEXT NOT NULL DEFAULT '',
                log_chat_id INTEGER,
                group_topic TEXT NOT NULL DEFAULT '',
                antiraid_until REAL NOT NULL DEFAULT 0,
                exempt_admins INTEGER NOT NULL DEFAULT 1,
                exempt_anon_admin INTEGER NOT NULL DEFAULT 1,
                exempt_linked_channel INTEGER NOT NULL DEFAULT 1,
                exempt_trusted INTEGER NOT NULL DEFAULT 1,
                exempt_owners INTEGER NOT NULL DEFAULT 0,
                external_channel_mode TEXT NOT NULL DEFAULT 'ai',
                exempt_veteran_short INTEGER NOT NULL DEFAULT 1,
                exempt_reply_cache INTEGER NOT NULL DEFAULT 1,
                admin_cache_fallback INTEGER NOT NULL DEFAULT 1,
                local_rules_enabled INTEGER NOT NULL DEFAULT 0,
                updated_at REAL NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS trusted_users (
                chat_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                label TEXT NOT NULL DEFAULT '',
                added_at REAL NOT NULL,
                PRIMARY KEY (chat_id, user_id)
            );

            CREATE TABLE IF NOT EXISTS user_stats (
                chat_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                clean_count INTEGER NOT NULL DEFAULT 0,
                first_seen_at REAL NOT NULL,
                PRIMARY KEY (chat_id, user_id)
            );

            CREATE TABLE IF NOT EXISTS repeat_suspects (
                suspect_key TEXT PRIMARY KEY,
                chat_id INTEGER NOT NULL,
                actor_id INTEGER NOT NULL,
                base_score INTEGER NOT NULL,
                hit_count INTEGER NOT NULL,
                msg_ids_json TEXT NOT NULL,
                updated_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS action_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                user_id INTEGER,
                sender_chat_id INTEGER,
                display_name TEXT NOT NULL,
                trigger_type TEXT NOT NULL,
                score INTEGER NOT NULL,
                reason TEXT NOT NULL,
                preview TEXT NOT NULL,
                dry_run INTEGER NOT NULL,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pending_captchas (
                chat_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                answer_key TEXT NOT NULL,
                message_id INTEGER NOT NULL,
                expires_at REAL NOT NULL,
                PRIMARY KEY (chat_id, user_id)
            );

            CREATE TABLE IF NOT EXISTS pending_deletes (
                chat_id INTEGER NOT NULL,
                message_id INTEGER NOT NULL,
                delete_at REAL NOT NULL,
                PRIMARY KEY (chat_id, message_id)
            );

            CREATE TABLE IF NOT EXISTS daily_metrics (
                day TEXT NOT NULL,
                chat_id INTEGER NOT NULL,
                ai_checks INTEGER NOT NULL DEFAULT 0,
                ai_errors INTEGER NOT NULL DEFAULT 0,
                vision_checks INTEGER NOT NULL DEFAULT 0,
                bans INTEGER NOT NULL DEFAULT 0,
                mutes INTEGER NOT NULL DEFAULT 0,
                deletes INTEGER NOT NULL DEFAULT 0,
                cas_bans INTEGER NOT NULL DEFAULT 0,
                swarm_bans INTEGER NOT NULL DEFAULT 0,
                prompt_tokens INTEGER NOT NULL DEFAULT 0,
                completion_tokens INTEGER NOT NULL DEFAULT 0,
                cached_tokens INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (day, chat_id)
            );

            CREATE TABLE IF NOT EXISTS forwarded_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                origin_desc TEXT NOT NULL,
                origin_user_id INTEGER,
                origin_profile_json TEXT NOT NULL,
                media_type TEXT NOT NULL,
                raw_payload_json TEXT NOT NULL,
                xray_summary TEXT NOT NULL,
                vision_attached INTEGER NOT NULL DEFAULT 0,
                ai_score INTEGER NOT NULL DEFAULT -1,
                ai_reason TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL
            );
            """
        )
        self.conn.commit()

    def _migrate_schema(self) -> None:
        """Non-destructive column migration when upgrading from v0.1.0 DBs."""
        gs_cols = {
            r["name"] for r in self.conn.execute("PRAGMA table_info(group_settings)").fetchall()
        }
        gs_additions = {
            "gray_zone_mute": "INTEGER NOT NULL DEFAULT 1",
            "cas_enabled": "INTEGER NOT NULL DEFAULT 1",
            "join_captcha": "INTEGER NOT NULL DEFAULT 0",
            "clean_service_msgs": "INTEGER NOT NULL DEFAULT 1",
            "block_malware_files": "INTEGER NOT NULL DEFAULT 1",
            "swarm_guard": "INTEGER NOT NULL DEFAULT 1",
            "antiraid_until": "REAL NOT NULL DEFAULT 0",
            "exempt_admins": "INTEGER NOT NULL DEFAULT 1",
            "exempt_anon_admin": "INTEGER NOT NULL DEFAULT 1",
            "exempt_linked_channel": "INTEGER NOT NULL DEFAULT 1",
            "exempt_trusted": "INTEGER NOT NULL DEFAULT 1",
            "exempt_owners": "INTEGER NOT NULL DEFAULT 0",
            "external_channel_mode": "TEXT NOT NULL DEFAULT 'ai'",
            "exempt_veteran_short": "INTEGER NOT NULL DEFAULT 1",
            "exempt_reply_cache": "INTEGER NOT NULL DEFAULT 1",
            "admin_cache_fallback": "INTEGER NOT NULL DEFAULT 1",
            "local_rules_enabled": "INTEGER NOT NULL DEFAULT 0",
            "announce_delete_seconds": "INTEGER NOT NULL DEFAULT 1800",
            "announce_template": "TEXT NOT NULL DEFAULT ''",
        }
        for col, ddl in gs_additions.items():
            if col not in gs_cols:
                self.conn.execute(f"ALTER TABLE group_settings ADD COLUMN {col} {ddl}")

        dm_cols = {
            r["name"] for r in self.conn.execute("PRAGMA table_info(daily_metrics)").fetchall()
        }
        dm_additions = {
            "ai_errors": "INTEGER NOT NULL DEFAULT 0",
            "mutes": "INTEGER NOT NULL DEFAULT 0",
            "cas_bans": "INTEGER NOT NULL DEFAULT 0",
            "swarm_bans": "INTEGER NOT NULL DEFAULT 0",
            "prompt_tokens": "INTEGER NOT NULL DEFAULT 0",
            "completion_tokens": "INTEGER NOT NULL DEFAULT 0",
            "cached_tokens": "INTEGER NOT NULL DEFAULT 0",
        }
        for col, ddl in dm_additions.items():
            if col not in dm_cols:
                self.conn.execute(f"ALTER TABLE daily_metrics ADD COLUMN {col} {ddl}")
        self.conn.commit()

    def _row_to_group(self, row: sqlite3.Row, fallback_title: str = "") -> GroupSettings:
        return GroupSettings(
            chat_id=int(row["chat_id"]),
            chat_title=str(row["chat_title"] or fallback_title),
            enabled=bool(row["enabled"]),
            dry_run=bool(row["dry_run"]),
            vision_enabled=bool(row["vision_enabled"]),
            spam_score=int(row["spam_score"]),
            gray_zone_mute=bool(row["gray_zone_mute"]),
            cas_enabled=bool(row["cas_enabled"]),
            join_captcha=bool(row["join_captcha"]),
            clean_service_msgs=bool(row["clean_service_msgs"]),
            block_malware_files=bool(row["block_malware_files"]),
            anti_flood=bool(row["anti_flood"]),
            swarm_guard=bool(row["swarm_guard"]),
            flood_window=int(row["flood_window"]),
            flood_max=int(row["flood_max"]),
            via_bot_mode=str(row["via_bot_mode"]),
            start_cmd_mode=str(row["start_cmd_mode"]),
            check_edited=bool(row["check_edited"]),
            announce_in_group=bool(row["announce_in_group"]),
            announce_delete_seconds=int(row["announce_delete_seconds"]),
            announce_template=str(row["announce_template"] or ""),
            log_chat_id=int(row["log_chat_id"]) if row["log_chat_id"] is not None else None,
            group_topic=str(row["group_topic"] or ""),
            antiraid_until=float(row["antiraid_until"] or 0.0),
            exempt_admins=bool(row["exempt_admins"]),
            exempt_anon_admin=bool(row["exempt_anon_admin"]),
            exempt_linked_channel=bool(row["exempt_linked_channel"]),
            exempt_trusted=bool(row["exempt_trusted"]),
            exempt_owners=bool(row["exempt_owners"]),
            external_channel_mode=str(row["external_channel_mode"] or "ai"),
            exempt_veteran_short=bool(row["exempt_veteran_short"]),
            exempt_reply_cache=bool(row["exempt_reply_cache"]),
            admin_cache_fallback=bool(row["admin_cache_fallback"]),
            local_rules_enabled=bool(row["local_rules_enabled"]),
        )

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Storage":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    # ---- Global metadata ----
    def get_meta(self, key: str) -> Optional[str]:
        row = self.conn.execute("SELECT value FROM kv_meta WHERE key=?", (key,)).fetchone()
        return str(row["value"]) if row else None

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO kv_meta (key, value) VALUES (?, ?)", (key, value)
        )
        self.conn.commit()

    def set_meta_many(self, items: dict[str, str]) -> None:
        """Atomically persist multiple metadata keys in a single SQLite transaction."""
        with self.conn:
            self.conn.executemany(
                "INSERT OR REPLACE INTO kv_meta (key, value) VALUES (?, ?)",
                list(items.items()),
            )

    def delete_meta(self, key: str) -> None:
        self.conn.execute("DELETE FROM kv_meta WHERE key=?", (key,))
        self.conn.commit()

    def delete_meta_many(self, keys: list[str]) -> None:
        """Atomically delete multiple metadata keys in a single SQLite transaction."""
        with self.conn:
            self.conn.executemany("DELETE FROM kv_meta WHERE key=?", [(k,) for k in keys])

    # ---- Persisted pending captchas (survive restarts) ----
    def save_captcha(
        self, chat_id: int, user_id: int, answer_key: str, message_id: int, expires_at: float
    ) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO pending_captchas
            (chat_id, user_id, answer_key, message_id, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (chat_id, user_id, answer_key, message_id, expires_at),
        )
        self.conn.commit()

    def get_captcha(self, chat_id: int, user_id: int) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM pending_captchas WHERE chat_id=? AND user_id=?",
            (chat_id, user_id),
        ).fetchone()
        return dict(row) if row else None

    def delete_captcha(self, chat_id: int, user_id: int) -> None:
        self.conn.execute(
            "DELETE FROM pending_captchas WHERE chat_id=? AND user_id=?",
            (chat_id, user_id),
        )
        self.conn.commit()

    def list_pending_captchas(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM pending_captchas").fetchall()
        return [dict(r) for r in rows]

    # ---- Persisted pending message auto-deletes (survive restarts) ----
    def save_pending_delete(
        self, chat_id: int, message_id: int, delete_at: float, *, max_rows: int = 5000
    ) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO pending_deletes (chat_id, message_id, delete_at)
            VALUES (?, ?, ?)
            """,
            (chat_id, message_id, delete_at),
        )
        # Keep bounded under extreme spam waves
        count_row = self.conn.execute("SELECT COUNT(*) AS c FROM pending_deletes").fetchone()
        if count_row and int(count_row["c"]) > max_rows:
            excess = int(count_row["c"]) - max_rows
            self.conn.execute(
                """
                DELETE FROM pending_deletes
                WHERE rowid IN (
                    SELECT rowid FROM pending_deletes ORDER BY delete_at ASC LIMIT ?
                )
                """,
                (excess,),
            )
        self.conn.commit()

    def delete_pending_delete(self, chat_id: int, message_id: int) -> None:
        self.conn.execute(
            "DELETE FROM pending_deletes WHERE chat_id=? AND message_id=?",
            (chat_id, message_id),
        )
        self.conn.commit()

    def list_pending_deletes(self) -> list[tuple[int, int, float]]:
        rows = self.conn.execute(
            "SELECT chat_id, message_id, delete_at FROM pending_deletes ORDER BY delete_at ASC"
        ).fetchall()
        return [(int(r["chat_id"]), int(r["message_id"]), float(r["delete_at"])) for r in rows]

    # ---- Per-group settings ----
    def has_group(self, chat_id: int) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM group_settings WHERE chat_id = ?", (chat_id,)
        ).fetchone()
        return row is not None

    def get_group(
        self,
        chat_id: int,
        chat_title: str = "",
        *,
        default_dry_run: bool = False,
        default_spam_score: int = 80,
        default_flood_window: int = 8,
        default_flood_max: int = 6,
    ) -> GroupSettings:
        row = self.conn.execute(
            "SELECT * FROM group_settings WHERE chat_id=?", (chat_id,)
        ).fetchone()
        if not row:
            gs = GroupSettings(
                chat_id=chat_id,
                chat_title=chat_title,
                dry_run=default_dry_run,
                spam_score=default_spam_score,
                flood_window=default_flood_window,
                flood_max=default_flood_max,
            )
            self.save_group(gs)
            return gs

        gs = self._row_to_group(row, chat_title)
        if chat_title and chat_title != row["chat_title"]:
            gs.chat_title = chat_title
            self.conn.execute(
                "UPDATE group_settings SET chat_title=?, updated_at=? WHERE chat_id=?",
                (chat_title, time.time(), chat_id),
            )
            self.conn.commit()
        return gs

    def save_group(self, gs: GroupSettings) -> None:
        self.conn.execute(
            """
            INSERT INTO group_settings (
                chat_id, chat_title, enabled, dry_run, vision_enabled, spam_score,
                gray_zone_mute, cas_enabled, join_captcha, clean_service_msgs,
                block_malware_files, anti_flood, swarm_guard, flood_window, flood_max,
                via_bot_mode, start_cmd_mode, check_edited,
                announce_in_group, announce_delete_seconds, announce_template,
                log_chat_id, group_topic, antiraid_until,
                exempt_admins, exempt_anon_admin, exempt_linked_channel,
                exempt_trusted, exempt_owners, external_channel_mode,
                exempt_veteran_short, exempt_reply_cache, admin_cache_fallback,
                local_rules_enabled, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(chat_id) DO UPDATE SET
                chat_title=excluded.chat_title,
                enabled=excluded.enabled,
                dry_run=excluded.dry_run,
                vision_enabled=excluded.vision_enabled,
                spam_score=excluded.spam_score,
                gray_zone_mute=excluded.gray_zone_mute,
                cas_enabled=excluded.cas_enabled,
                join_captcha=excluded.join_captcha,
                clean_service_msgs=excluded.clean_service_msgs,
                block_malware_files=excluded.block_malware_files,
                anti_flood=excluded.anti_flood,
                swarm_guard=excluded.swarm_guard,
                flood_window=excluded.flood_window,
                flood_max=excluded.flood_max,
                via_bot_mode=excluded.via_bot_mode,
                start_cmd_mode=excluded.start_cmd_mode,
                check_edited=excluded.check_edited,
                announce_in_group=excluded.announce_in_group,
                announce_delete_seconds=excluded.announce_delete_seconds,
                announce_template=excluded.announce_template,
                log_chat_id=excluded.log_chat_id,
                group_topic=excluded.group_topic,
                antiraid_until=excluded.antiraid_until,
                exempt_admins=excluded.exempt_admins,
                exempt_anon_admin=excluded.exempt_anon_admin,
                exempt_linked_channel=excluded.exempt_linked_channel,
                exempt_trusted=excluded.exempt_trusted,
                exempt_owners=excluded.exempt_owners,
                external_channel_mode=excluded.external_channel_mode,
                exempt_veteran_short=excluded.exempt_veteran_short,
                exempt_reply_cache=excluded.exempt_reply_cache,
                admin_cache_fallback=excluded.admin_cache_fallback,
                local_rules_enabled=excluded.local_rules_enabled,
                updated_at=excluded.updated_at
            """,
            (
                gs.chat_id,
                gs.chat_title,
                int(gs.enabled),
                int(gs.dry_run),
                int(gs.vision_enabled),
                gs.spam_score,
                int(gs.gray_zone_mute),
                int(gs.cas_enabled),
                int(gs.join_captcha),
                int(gs.clean_service_msgs),
                int(gs.block_malware_files),
                int(gs.anti_flood),
                int(gs.swarm_guard),
                gs.flood_window,
                gs.flood_max,
                gs.via_bot_mode,
                gs.start_cmd_mode,
                int(gs.check_edited),
                int(gs.announce_in_group),
                int(gs.announce_delete_seconds),
                gs.announce_template,
                gs.log_chat_id,
                gs.group_topic,
                gs.antiraid_until,
                int(gs.exempt_admins),
                int(gs.exempt_anon_admin),
                int(gs.exempt_linked_channel),
                int(gs.exempt_trusted),
                int(gs.exempt_owners),
                gs.external_channel_mode,
                int(gs.exempt_veteran_short),
                int(gs.exempt_reply_cache),
                int(gs.admin_cache_fallback),
                int(gs.local_rules_enabled),
                time.time(),
            ),
        )
        self.conn.commit()

    def list_groups(self) -> list[GroupSettings]:
        rows = self.conn.execute(
            "SELECT * FROM group_settings ORDER BY updated_at DESC"
        ).fetchall()
        return [self._row_to_group(r) for r in rows]

    # ---- Repeat-Send Escalation (content-free SHA-256 hashes, 24h window) ----
    def record_repeat_suspect(
        self,
        suspect_key: str,
        chat_id: int,
        actor_id: int,
        score: int,
        message_id: int,
        *,
        window_seconds: int = 86400,
        now: Optional[float] = None,
    ) -> tuple[int, int, list[int]]:
        """Track borderline repeats; each repeat halves distance to 100.

        Returns (effective_score, hit_count, tracked_msg_ids).
        """
        ts = now if now is not None else time.time()
        row = self.conn.execute(
            "SELECT * FROM repeat_suspects WHERE suspect_key=?", (suspect_key,)
        ).fetchone()

        if not row or (ts - float(row["updated_at"])) > window_seconds:
            msg_ids = [message_id]
            hit_count = 1
            base_score = score
        else:
            prev_ids = json.loads(row["msg_ids_json"] or "[]")
            msg_ids = (prev_ids + [message_id])[-10:]
            hit_count = int(row["hit_count"]) + 1
            base_score = max(int(row["base_score"]), score)

        self.conn.execute(
            """
            INSERT OR REPLACE INTO repeat_suspects
            (suspect_key, chat_id, actor_id, base_score, hit_count, msg_ids_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (suspect_key, chat_id, actor_id, base_score, hit_count, json.dumps(msg_ids), ts),
        )
        # Occasional pruning of expired rows
        if hit_count == 1:
            self.conn.execute(
                "DELETE FROM repeat_suspects WHERE updated_at < ?", (ts - window_seconds,)
            )
        self.conn.commit()

        # Halve remaining distance to 100 on every repeat: 55 -> 78 -> 89 -> 94
        effective = int(round(100 - (100 - base_score) / (2 ** (hit_count - 1))))
        return min(100, effective), hit_count, msg_ids

    # ---- Whitelist ----
    def is_trusted(self, chat_id: int, user_id: int) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM trusted_users WHERE chat_id=? AND user_id=?",
            (chat_id, user_id),
        ).fetchone()
        return row is not None

    def trust_user(self, chat_id: int, user_id: int, label: str = "") -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO trusted_users (chat_id, user_id, label, added_at) VALUES (?, ?, ?, ?)",
            (chat_id, user_id, label, time.time()),
        )
        self.conn.commit()

    def untrust_user(self, chat_id: int, user_id: int) -> None:
        self.conn.execute(
            "DELETE FROM trusted_users WHERE chat_id=? AND user_id=?",
            (chat_id, user_id),
        )
        self.conn.commit()

    def trusted_count(self, chat_id: int) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS c FROM trusted_users WHERE chat_id=?", (chat_id,)
        ).fetchone()
        return int(row["c"]) if row else 0

    # ---- Clean message stats ----
    def get_clean_count(self, chat_id: int, user_id: int) -> int:
        row = self.conn.execute(
            "SELECT clean_count FROM user_stats WHERE chat_id=? AND user_id=?",
            (chat_id, user_id),
        ).fetchone()
        return int(row["clean_count"]) if row else 0

    def increment_clean_count(self, chat_id: int, user_id: int) -> int:
        now = time.time()
        self.conn.execute(
            """
            INSERT INTO user_stats (chat_id, user_id, clean_count, first_seen_at)
            VALUES (?, ?, 1, ?)
            ON CONFLICT(chat_id, user_id) DO UPDATE SET clean_count = clean_count + 1
            """,
            (chat_id, user_id, now),
        )
        self.conn.commit()
        return self.get_clean_count(chat_id, user_id)

    # ---- Metrics & Token Usage ----
    def inc_metric(self, chat_id: int, field_name: str, delta: int = 1) -> None:
        allowed = {
            "ai_checks",
            "ai_errors",
            "vision_checks",
            "bans",
            "mutes",
            "deletes",
            "cas_bans",
            "swarm_bans",
            "prompt_tokens",
            "completion_tokens",
            "cached_tokens",
        }
        if field_name not in allowed or delta <= 0:
            return
        day = time.strftime("%Y-%m-%d")
        self.conn.execute(
            f"""
            INSERT INTO daily_metrics (day, chat_id, {field_name}) VALUES (?, ?, ?)
            ON CONFLICT(day, chat_id) DO UPDATE SET {field_name} = {field_name} + ?
            """,
            (day, chat_id, delta, delta),
        )
        self.conn.commit()

    def record_token_usage(
        self, chat_id: int, prompt_tokens: int, completion_tokens: int, cached_tokens: int
    ) -> None:
        day = time.strftime("%Y-%m-%d")
        self.conn.execute(
            """
            INSERT INTO daily_metrics (day, chat_id, prompt_tokens, completion_tokens, cached_tokens)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(day, chat_id) DO UPDATE SET
                prompt_tokens = prompt_tokens + excluded.prompt_tokens,
                completion_tokens = completion_tokens + excluded.completion_tokens,
                cached_tokens = cached_tokens + excluded.cached_tokens
            """,
            (day, chat_id, max(0, prompt_tokens), max(0, completion_tokens), max(0, cached_tokens)),
        )
        self.conn.commit()

    def get_today_metrics(self, chat_id: Optional[int] = None) -> dict[str, int]:
        day = time.strftime("%Y-%m-%d")
        cols = (
            "ai_checks",
            "ai_errors",
            "vision_checks",
            "bans",
            "mutes",
            "deletes",
            "cas_bans",
            "swarm_bans",
            "prompt_tokens",
            "completion_tokens",
            "cached_tokens",
        )
        if chat_id is None:
            agg = ", ".join(f"COALESCE(SUM({c}), 0) AS {c}" for c in cols)
            row = self.conn.execute(
                f"SELECT {agg} FROM daily_metrics WHERE day=?", (day,)
            ).fetchone()
        else:
            row = self.conn.execute(
                f"SELECT {', '.join(cols)} FROM daily_metrics WHERE day=? AND chat_id=?",
                (day, chat_id),
            ).fetchone()
        if not row:
            return {c: 0 for c in cols}
        return {c: int(row[c] or 0) for c in cols}

    def get_lifetime_metrics(self, chat_id: Optional[int] = None) -> dict[str, int]:
        cols = (
            "ai_checks",
            "ai_errors",
            "vision_checks",
            "bans",
            "mutes",
            "deletes",
            "cas_bans",
            "swarm_bans",
            "prompt_tokens",
            "completion_tokens",
            "cached_tokens",
        )
        agg = ", ".join(f"COALESCE(SUM({c}), 0) AS {c}" for c in cols)
        if chat_id is None:
            row = self.conn.execute(f"SELECT {agg} FROM daily_metrics").fetchone()
        else:
            row = self.conn.execute(
                f"SELECT {agg} FROM daily_metrics WHERE chat_id=?", (chat_id,)
            ).fetchone()
        if not row:
            return {c: 0 for c in cols}
        return {c: int(row[c] or 0) for c in cols}

    def get_group_summary_rows(self) -> list[dict]:
        """Return all groups with today's and lifetime ban/mute/AI counts."""
        day = time.strftime("%Y-%m-%d")
        rows = self.conn.execute(
            """
            SELECT
                g.chat_id,
                g.chat_title,
                g.enabled,
                g.dry_run,
                COALESCE(td.bans, 0) AS today_bans,
                COALESCE(td.mutes, 0) AS today_mutes,
                COALESCE(td.ai_checks, 0) AS today_ai,
                COALESCE(lt.total_bans, 0) AS total_bans,
                COALESCE(lt.total_mutes, 0) AS total_mutes
            FROM group_settings g
            LEFT JOIN daily_metrics td
                ON td.chat_id = g.chat_id AND td.day = ?
            LEFT JOIN (
                SELECT chat_id, SUM(bans) AS total_bans, SUM(mutes) AS total_mutes
                FROM daily_metrics
                GROUP BY chat_id
            ) lt ON lt.chat_id = g.chat_id
            ORDER BY g.enabled DESC, g.updated_at DESC
            """,
            (day,),
        ).fetchall()
        return [dict(r) for r in rows]

    _SUSPECT_TRIGGERS = (
        "gray_zone",
        "gray_basic",
        "ai_suspect",
        "anti_flood_review",
        "anti_flood_repeat",
    )
    _AI_TRIGGERS = ("ai_text", "ai_vision", "edited_ai", "gray_zone", "ai_suspect")

    def get_trigger_breakdown(self) -> list[tuple[str, int]]:
        placeholders = ",".join("?" for _ in self._SUSPECT_TRIGGERS)
        rows = self.conn.execute(
            f"""
            SELECT trigger_type, COUNT(*) AS cnt
            FROM action_logs
            WHERE dry_run = 0 AND trigger_type NOT IN ({placeholders})
            GROUP BY trigger_type
            ORDER BY cnt DESC
            """,
            self._SUSPECT_TRIGGERS,
        ).fetchall()
        return [(str(r["trigger_type"]), int(r["cnt"])) for r in rows]

    def get_recent_kills(self, limit: int = 10) -> list[dict]:
        placeholders = ",".join("?" for _ in self._SUSPECT_TRIGGERS)
        rows = self.conn.execute(
            f"""
            SELECT a.*, COALESCE(g.chat_title, '') AS chat_title
            FROM action_logs a
            LEFT JOIN group_settings g ON g.chat_id = a.chat_id
            WHERE a.dry_run = 0 AND a.trigger_type NOT IN ({placeholders})
            ORDER BY a.id DESC
            LIMIT ?
            """,
            (*self._SUSPECT_TRIGGERS, max(1, min(50, limit))),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_recent_suspects(self, limit: int = 10) -> tuple[int, list[dict]]:
        placeholders = ",".join("?" for _ in self._SUSPECT_TRIGGERS)
        cnt_row = self.conn.execute(
            f"""
            SELECT COUNT(*) AS c
            FROM action_logs
            WHERE dry_run = 1 OR trigger_type IN ({placeholders})
            """,
            self._SUSPECT_TRIGGERS,
        ).fetchone()
        total = int(cnt_row["c"]) if cnt_row else 0
        rows = self.conn.execute(
            f"""
            SELECT a.*, COALESCE(g.chat_title, '') AS chat_title
            FROM action_logs a
            LEFT JOIN group_settings g ON g.chat_id = a.chat_id
            WHERE a.dry_run = 1 OR a.trigger_type IN ({placeholders})
            ORDER BY a.id DESC
            LIMIT ?
            """,
            (*self._SUSPECT_TRIGGERS, max(1, min(50, limit))),
        ).fetchall()
        return total, [dict(r) for r in rows]

    def get_recent_ai_reports(self, limit: int = 10) -> list[dict]:
        placeholders = ",".join("?" for _ in self._AI_TRIGGERS)
        rows = self.conn.execute(
            f"""
            SELECT a.*, COALESCE(g.chat_title, '') AS chat_title
            FROM action_logs a
            LEFT JOIN group_settings g ON g.chat_id = a.chat_id
            WHERE a.trigger_type IN ({placeholders})
            ORDER BY a.id DESC
            LIMIT ?
            """,
            (*self._AI_TRIGGERS, max(1, min(50, limit))),
        ).fetchall()
        return [dict(r) for r in rows]

    def log_action(
        self,
        chat_id: int,
        user_id: Optional[int],
        sender_chat_id: Optional[int],
        display_name: str,
        trigger_type: str,
        score: int,
        reason: str,
        preview: str,
        dry_run: bool,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO action_logs (
                chat_id, user_id, sender_chat_id, display_name,
                trigger_type, score, reason, preview, dry_run, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                chat_id,
                user_id,
                sender_chat_id,
                display_name,
                trigger_type,
                score,
                reason,
                preview[:500],
                int(dry_run),
                time.time(),
            ),
        )
        # Keep action_logs bounded (max ~5000 newest entries) so SQLite stays lean forever
        cnt_row = self.conn.execute("SELECT COUNT(*) AS c FROM action_logs").fetchone()
        if cnt_row and int(cnt_row["c"]) > 5500:
            self.conn.execute(
                """
                DELETE FROM action_logs
                WHERE id NOT IN (SELECT id FROM action_logs ORDER BY id DESC LIMIT 5000)
                """
            )
        self.conn.commit()

    def save_forwarded_sample(
        self,
        *,
        owner_id: int,
        origin_desc: str,
        origin_user_id: Optional[int],
        origin_profile: dict[str, Any],
        media_type: str,
        raw_payload: dict[str, Any],
        xray_summary: str,
        vision_attached: bool,
        ai_score: int,
        ai_reason: str,
    ) -> int:
        cur = self.conn.execute(
            """
            INSERT INTO forwarded_samples (
                owner_id, origin_desc, origin_user_id, origin_profile_json,
                media_type, raw_payload_json, xray_summary, vision_attached,
                ai_score, ai_reason, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                owner_id,
                origin_desc[:300],
                origin_user_id,
                json.dumps(origin_profile, ensure_ascii=False)[:2000],
                media_type[:120],
                json.dumps(raw_payload, ensure_ascii=False)[:6000],
                xray_summary[:4000],
                int(vision_attached),
                int(ai_score),
                (ai_reason or "")[:400],
                time.time(),
            ),
        )
        sample_id = int(cur.lastrowid or 0)
        cnt_row = self.conn.execute("SELECT COUNT(*) AS c FROM forwarded_samples").fetchone()
        if cnt_row and int(cnt_row["c"]) > 220:
            self.conn.execute(
                """
                DELETE FROM forwarded_samples
                WHERE id NOT IN (SELECT id FROM forwarded_samples ORDER BY id DESC LIMIT 200)
                """
            )
        self.conn.commit()
        return sample_id

    def list_forwarded_samples(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT * FROM forwarded_samples
            ORDER BY id DESC
            LIMIT ?
            """,
            (max(1, min(100, limit)),),
        ).fetchall()
        return [dict(r) for r in rows]
