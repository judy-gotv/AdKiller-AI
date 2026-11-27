"""Stdlib-only read-only status, kill-breakdown, suspect & AI report module for AI-智能广告杀手 CLI and GUI."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

TRIGGER_LABELS: dict[str, str] = {
    "ai_text": "AI 语义拦截",
    "ai_vision": "AI 识图拦截",
    "edited_ai": "编辑后 AI 拦截",
    "spam_cache": "广告指纹缓存",
    "cas_blacklist": "CAS 发言黑库",
    "cas_join": "CAS 入群黑库",
    "anti_flood_spam": "刷屏广告拦截",
    "malware_file": "木马安装包",
    "via_bot": "外联机器人卡片",
    "start_cmd": "群内 /start 刷屏",
    "external_channel": "外部频道马甲",
    "basic_rules": "本地关键词规则",
    "manual_sban": "管理员手动封禁",
    "gray_zone": "AI 灰区禁言",
    "gray_basic": "关键词灰区禁言",
    "ai_suspect": "AI 轻度怀疑",
    "anti_flood_review": "疑似刷屏复核",
    "anti_flood_repeat": "多次快聊复核",
}

SUSPECT_TRIGGERS = (
    "gray_zone",
    "gray_basic",
    "ai_suspect",
    "anti_flood_review",
    "anti_flood_repeat",
)
AI_TRIGGERS = ("ai_text", "ai_vision", "edited_ai", "gray_zone", "ai_suspect")


def trigger_label(trigger_type: str) -> str:
    return TRIGGER_LABELS.get(trigger_type, trigger_type or "未知方式")


def _parse_env_file(env_path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not env_path.is_file():
        return out
    try:
        for raw in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip()
            if len(v) >= 2 and ((v[0] == '"' and v[-1] == '"') or (v[0] == "'" and v[-1] == "'")):
                v = v[1:-1]
            out[k] = v
    except OSError:
        pass
    return out


def _url_origin(url: str) -> str:
    try:
        p = urlparse((url or "").strip())
    except ValueError:
        return ""
    scheme = (p.scheme or "").lower()
    host = (p.hostname or "").lower()
    if scheme not in ("http", "https") or not host:
        return ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = p.port or (443 if scheme == "https" else 80)
    return f"{scheme}://{host}:{port}"


def _sanitize_url(url: str) -> str:
    origin = _url_origin(url)
    if not origin:
        return "(未设置)"
    if origin.startswith("https://") and origin.endswith(":443"):
        return origin[:-4]
    if origin.startswith("http://") and origin.endswith(":80"):
        return origin[:-3]
    return origin


def _is_valid_base_url(url: str) -> bool:
    s = (url or "").strip()
    if not s or len(s) > 300 or any(c.isspace() for c in s) or "?" in s or "#" in s:
        return False
    try:
        p = urlparse(s)
    except ValueError:
        return False
    if p.username or p.password:
        return False
    scheme = (p.scheme or "").lower()
    host = (p.hostname or "").lower()
    if scheme == "https" and host:
        return True
    if scheme == "http" and host in {"localhost", "127.0.0.1", "::1", "host.docker.internal"}:
        return True
    return False


def _env_ai_hash(base_url: str, model: str, api_key: str) -> str:
    raw = f"{base_url}\x00{model}\x00{api_key}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _resolve_effective_ai(env: dict[str, str], kv: dict[str, str]) -> dict[str, Any]:
    env_url = env.get("AI_BASE_URL") or "https://api.deepseek.com/v1"
    env_model = env.get("AI_MODEL") or "deepseek-flash"
    env_key = env.get("AI_API_KEY") or ""
    cur_hash = _env_ai_hash(env_url, env_model, env_key)

    if kv.get("ai_config_override") == "1" and kv.get("ai_env_hash", "") == cur_hash:
        eff_url = kv.get("ai_base_url", env_url)
        eff_model = kv.get("ai_model", env_model)
        eff_key = kv.get("ai_api_key", env_key)
        saved_origin = kv.get("ai_key_origin", "")
        eff_origin = _url_origin(eff_url)
        if eff_key and saved_origin and eff_origin and saved_origin == eff_origin and _is_valid_base_url(eff_url):
            return {
                "configured": True,
                "model": eff_model or "(未命名)",
                "url": _sanitize_url(eff_url),
                "source": "telegram",
            }
        return {
            "configured": False,
            "model": eff_model,
            "url": _sanitize_url(eff_url),
            "source": "none",
        }

    if env_key and _is_valid_base_url(env_url):
        return {
            "configured": True,
            "model": env_model or "(未命名)",
            "url": _sanitize_url(env_url),
            "source": "env",
        }
    return {
        "configured": False,
        "model": env_model,
        "url": _sanitize_url(env_url),
        "source": "none",
    }


def collect_runtime_snapshot(work_dir: Path) -> dict[str, Any]:
    env = _parse_env_file(work_dir / ".env")
    db_rel = env.get("DB_PATH") or "./data/adkiller.db"
    db_path = Path(db_rel)
    if not db_path.is_absolute():
        db_path = work_dir / db_path
    # Container default DB_PATH=/app/data/adkiller.db maps to <work_dir>/data/adkiller.db on host
    if not db_path.is_file():
        host_fallback = work_dir / "data" / "adkiller.db"
        if host_fallback.is_file():
            db_path = host_fallback

    kv: dict[str, str] = {}
    groups: list[dict[str, Any]] = []
    today: dict[str, int] = {
        "ai_checks": 0,
        "ai_errors": 0,
        "vision_checks": 0,
        "bans": 0,
        "mutes": 0,
        "deletes": 0,
        "cas_bans": 0,
        "swarm_bans": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "cached_tokens": 0,
    }
    lifetime = dict(today)
    breakdown: list[tuple[str, int]] = []
    recent_kills: list[dict[str, Any]] = []
    suspect_total = 0
    recent_suspects: list[dict[str, Any]] = []
    recent_ai: list[dict[str, Any]] = []
    db_found = False

    if db_path.is_file():
        conn: Optional[sqlite3.Connection] = None
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2.0)
            conn.row_factory = sqlite3.Row
            db_found = True

            tables = {
                str(r["name"])
                for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            }
            if "kv_meta" in tables:
                for r in conn.execute("SELECT key, value FROM kv_meta").fetchall():
                    kv[str(r["key"])] = str(r["value"])

            day = time.strftime("%Y-%m-%d")
            if "daily_metrics" in tables:
                cols = list(today.keys())
                dm_cols = {
                    str(r["name"])
                    for r in conn.execute("PRAGMA table_info(daily_metrics)").fetchall()
                }
                present = [c for c in cols if c in dm_cols]
                if present:
                    agg = ", ".join(f"COALESCE(SUM({c}), 0) AS {c}" for c in present)
                    r_td = conn.execute(
                        f"SELECT {agg} FROM daily_metrics WHERE day=?", (day,)
                    ).fetchone()
                    if r_td:
                        for c in present:
                            today[c] = int(r_td[c] or 0)
                    r_lt = conn.execute(f"SELECT {agg} FROM daily_metrics").fetchone()
                    if r_lt:
                        for c in present:
                            lifetime[c] = int(r_lt[c] or 0)

            if "group_settings" in tables:
                if "daily_metrics" in tables:
                    rows = conn.execute(
                        """
                        SELECT
                            g.chat_id, g.chat_title, g.enabled, g.dry_run,
                            COALESCE(td.bans, 0) AS today_bans,
                            COALESCE(td.mutes, 0) AS today_mutes,
                            COALESCE(td.ai_checks, 0) AS today_ai,
                            COALESCE(lt.total_bans, 0) AS total_bans,
                            COALESCE(lt.total_mutes, 0) AS total_mutes
                        FROM group_settings g
                        LEFT JOIN daily_metrics td ON td.chat_id = g.chat_id AND td.day = ?
                        LEFT JOIN (
                            SELECT chat_id, SUM(bans) AS total_bans, SUM(mutes) AS total_mutes
                            FROM daily_metrics GROUP BY chat_id
                        ) lt ON lt.chat_id = g.chat_id
                        ORDER BY g.enabled DESC, g.updated_at DESC
                        """,
                        (day,),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT chat_id, chat_title, enabled, dry_run, 0 AS today_bans, 0 AS today_mutes, 0 AS today_ai, 0 AS total_bans, 0 AS total_mutes FROM group_settings"
                    ).fetchall()
                groups = [dict(r) for r in rows]

            if "action_logs" in tables:
                s_ph = ",".join("?" for _ in SUSPECT_TRIGGERS)
                ai_ph = ",".join("?" for _ in AI_TRIGGERS)
                for r in conn.execute(
                    f"""
                    SELECT trigger_type, COUNT(*) AS cnt
                    FROM action_logs
                    WHERE dry_run = 0 AND trigger_type NOT IN ({s_ph})
                    GROUP BY trigger_type
                    ORDER BY cnt DESC
                    """,
                    SUSPECT_TRIGGERS,
                ).fetchall():
                    breakdown.append((str(r["trigger_type"]), int(r["cnt"])))

                title_join = (
                    "LEFT JOIN group_settings g ON g.chat_id = a.chat_id"
                    if "group_settings" in tables
                    else ""
                )
                title_col = "COALESCE(g.chat_title, '') AS chat_title" if title_join else "'' AS chat_title"

                recent_kills = [
                    dict(r)
                    for r in conn.execute(
                        f"""
                        SELECT a.*, {title_col}
                        FROM action_logs a {title_join}
                        WHERE a.dry_run = 0 AND a.trigger_type NOT IN ({s_ph})
                        ORDER BY a.id DESC LIMIT 12
                        """,
                        SUSPECT_TRIGGERS,
                    ).fetchall()
                ]

                c_row = conn.execute(
                    f"""
                    SELECT COUNT(*) AS c FROM action_logs
                    WHERE dry_run = 1 OR trigger_type IN ({s_ph})
                    """,
                    SUSPECT_TRIGGERS,
                ).fetchone()
                suspect_total = int(c_row["c"]) if c_row else 0
                recent_suspects = [
                    dict(r)
                    for r in conn.execute(
                        f"""
                        SELECT a.*, {title_col}
                        FROM action_logs a {title_join}
                        WHERE a.dry_run = 1 OR a.trigger_type IN ({s_ph})
                        ORDER BY a.id DESC LIMIT 12
                        """,
                        SUSPECT_TRIGGERS,
                    ).fetchall()
                ]
                recent_ai = [
                    dict(r)
                    for r in conn.execute(
                        f"""
                        SELECT a.*, {title_col}
                        FROM action_logs a {title_join}
                        WHERE a.trigger_type IN ({ai_ph})
                        ORDER BY a.id DESC LIMIT 12
                        """,
                        AI_TRIGGERS,
                    ).fetchall()
                ]
        except sqlite3.Error:
            pass
        finally:
            if conn is not None:
                conn.close()

    ai = _resolve_effective_ai(env, kv)
    enabled_groups = sum(1 for g in groups if g.get("enabled") and not g.get("dry_run"))
    dry_groups = sum(1 for g in groups if g.get("enabled") and g.get("dry_run"))
    paused_groups = sum(1 for g in groups if not g.get("enabled"))
    return {
        "db_found": db_found,
        "ai": ai,
        "groups": groups,
        "groups_total": len(groups),
        "groups_enabled": enabled_groups,
        "groups_dry": dry_groups,
        "groups_paused": paused_groups,
        "today": today,
        "lifetime": lifetime,
        "breakdown": breakdown,
        "recent_kills": recent_kills,
        "suspect_total": suspect_total,
        "recent_suspects": recent_suspects,
        "recent_ai": recent_ai,
    }


# ---- 3-Color (Cyan + Yellow + White) Terminal Box Renderer ----
def _use_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty() or os.environ.get("ADKILLER_COLOR") == "1"


def _disp_width(s: str) -> int:
    w = 0
    for ch in s:
        w += 1 if ord(ch) < 128 else 2
    return w


def _trunc(s: str, max_w: int) -> str:
    clean = " ".join((s or "").split())
    if _disp_width(clean) <= max_w:
        return clean
    out: list[str] = []
    cur = 0
    limit = max(1, max_w - 3)
    for ch in clean:
        cw = 1 if ord(ch) < 128 else 2
        if cur + cw > limit:
            break
        out.append(ch)
        cur += cw
    return "".join(out) + "..."


def _fmt_ts(ts: Any) -> str:
    try:
        return time.strftime("%m-%d %H:%M", time.localtime(float(ts)))
    except Exception:
        return "--:--"


class _Box:
    def __init__(self, inner: int = 48):
        self.inner = inner
        on = _use_color()
        self.r = "\033[0m" if on else ""
        self.c = "\033[36m" if on else ""
        self.cb = "\033[1;36m" if on else ""
        self.y = "\033[33m" if on else ""
        self.yb = "\033[1;33m" if on else ""
        self.w = "\033[97m" if on else ""

    def top(self) -> None:
        print(f"{self.c}╭{'─' * self.inner}╮{self.r}")

    def sep(self) -> None:
        print(f"{self.c}├{'─' * self.inner}┤{self.r}")

    def bottom(self) -> None:
        print(f"{self.c}╰{'─' * self.inner}╯{self.r}")

    def center(self, title: str) -> None:
        w = _disp_width(title)
        pl = max(0, (self.inner - w) // 2)
        pr = max(0, self.inner - w - pl)
        print(f"{self.c}│{self.r}{' ' * pl}{self.yb}{title}{self.r}{' ' * pr}{self.c}│{self.r}")

    def kv(self, label: str, value: str, *, warn: bool = False) -> None:
        val_max = self.inner - 15
        v = _trunc(value, val_max)
        used = 2 + _disp_width(label) + 3 + _disp_width(v)
        pr = max(0, self.inner - used)
        vcol = self.y if warn else self.w
        print(f"{self.c}│{self.r}  {self.c}{label}{self.r}   {vcol}{v}{self.r}{' ' * pr}{self.c}│{self.r}")

    def line(self, text: str, *, color: Optional[str] = None) -> None:
        t = _trunc(text, self.inner - 4)
        used = 2 + _disp_width(t)
        pr = max(0, self.inner - used)
        col = color if color is not None else self.w
        print(f"{self.c}│{self.r}  {col}{t}{self.r}{' ' * pr}{self.c}│{self.r}")


def _print_summary_kv(snap: dict[str, Any]) -> None:
    ai = snap["ai"]
    print(f"AI_CONFIGURED={1 if ai['configured'] else 0}")
    print(f"AI_MODEL={ai['model']}")
    print(f"AI_URL={ai['url']}")
    print(f"AI_SOURCE={ai['source']}")
    print(f"GROUPS_TOTAL={snap['groups_total']}")
    print(f"GROUPS_ENABLED={snap['groups_enabled']}")
    print(f"GROUPS_DRY={snap['groups_dry']}")
    print(f"TODAY_BANS={snap['today']['bans']}")
    print(f"TODAY_MUTES={snap['today']['mutes']}")
    print(f"TODAY_AI={snap['today']['ai_checks']}")
    print(f"TOTAL_BANS={snap['lifetime']['bans']}")
    print(f"SUSPECT_TOTAL={snap['suspect_total']}")


def _print_overview(snap: dict[str, Any]) -> None:
    b = _Box(48)
    ai = snap["ai"]
    td = snap["today"]
    lt = snap["lifetime"]

    src_tag = {"telegram": "私聊配", "env": ".env", "none": "未配置"}[ai["source"]]
    ai_val = f"{ai['model']} ({src_tag})" if ai["configured"] else "未配置"
    grp_val = (
        f"共 {snap['groups_total']} 群 (自动{snap['groups_enabled']} 观察{snap['groups_dry']} 停{snap['groups_paused']})"
        if snap["groups_total"] > 0
        else "0 个群 (拉机器人进群即可自动接入)"
    )

    print()
    b.top()
    b.center("AI-智能广告杀手  运行状态总览")
    b.sep()
    b.kv("防护群组", grp_val, warn=(snap["groups_total"] == 0))
    b.kv("累计击杀", f"封禁 {lt['bans']} 条 / 禁言复核 {lt['mutes']} 条")
    b.kv("今日战果", f"封禁 {td['bans']} / 禁言 {td['mutes']} / AI审 {td['ai_checks']}")
    b.kv("疑似记录", f"共 {snap['suspect_total']} 条 (含灰区与轻度怀疑)", warn=(snap["suspect_total"] > 0))
    b.kv("模型引擎", ai_val, warn=(not ai["configured"]))
    if snap["groups"]:
        b.sep()
        b.line("已接入群组列表:", color=b.c)
        for g in snap["groups"][:10]:
            mode = "全自动" if (g["enabled"] and not g["dry_run"]) else ("观察" if g["enabled"] else "暂停")
            title = g["chat_title"] or str(g["chat_id"])
            row_txt = f"- {_trunc(title, 18)} [{mode}] 今杀{g['today_bans']}/累{g['total_bans']}"
            b.line(row_txt, color=b.w if g["enabled"] else b.y)
    b.bottom()


def _print_kills(snap: dict[str, Any]) -> None:
    b = _Box(54)
    print()
    b.top()
    b.center("广告击杀明细  (怎么被杀的)")
    b.sep()
    if snap["breakdown"]:
        b.line("按触发方式统计:", color=b.c)
        for trig, cnt in snap["breakdown"][:10]:
            lbl = _trunc(trigger_label(trig), 16)
            pad = max(2, 18 - _disp_width(lbl))
            b.line(f"{lbl}{' ' * pad}{cnt} 条", color=b.w)
    else:
        b.line("暂无广告封禁记录", color=b.y)

    b.sep()
    if snap["recent_kills"]:
        b.line("最近击杀记录 (最新 10 条):", color=b.c)
        for r in snap["recent_kills"][:10]:
            gname = r.get("chat_title") or str(r["chat_id"])
            head = f"[{_fmt_ts(r['created_at'])}] {_trunc(gname, 12)} | {trigger_label(r['trigger_type'])} ({r['score']}分)"
            b.line(head, color=b.cb)
            b.line(f"  用户: {_trunc(r['display_name'], 18)} | 理由: {_trunc(r['reason'], 24)}", color=b.w)
    else:
        b.line("最近没有广告击杀记录。", color=b.y)
    b.bottom()


def _print_suspects(snap: dict[str, Any]) -> None:
    b = _Box(54)
    print()
    b.top()
    b.center("疑似与待复核排查  (有没有怀疑的)")
    b.sep()
    if snap["suspect_total"] == 0:
        b.line("当前暂无疑似或待复核记录，群内很干净！", color=b.w)
    else:
        b.kv("累计疑似", f"{snap['suspect_total']} 条 (展示最新 10 条)", warn=True)
        b.sep()
        for r in snap["recent_suspects"][:10]:
            gname = r.get("chat_title") or str(r["chat_id"])
            tag = "观察标记" if (r.get("dry_run") and r["trigger_type"] != "ai_suspect") else trigger_label(r["trigger_type"])
            head = f"[{_fmt_ts(r['created_at'])}] {_trunc(gname, 12)} | {tag} ({r['score']}分)"
            b.line(head, color=b.y)
            b.line(f"  用户: {_trunc(r['display_name'], 16)} | 理由: {_trunc(r['reason'], 24)}", color=b.w)
            if r.get("preview"):
                b.line(f"  摘要: {_trunc(r['preview'], 42)}", color=b.w)
    b.bottom()


def _print_ai_report(snap: dict[str, Any]) -> None:
    b = _Box(54)
    ai = snap["ai"]
    td = snap["today"]
    lt = snap["lifetime"]

    hit_rate = (
        f"{int(round(td['cached_tokens'] * 100 / td['prompt_tokens']))}%"
        if td["prompt_tokens"] > 0
        else "0%"
    )
    src_txt = {"telegram": "私聊面板配置", "env": "服务器 .env", "none": "未配置"}[ai["source"]]

    print()
    b.top()
    b.center("AI 审核汇报")
    b.sep()
    b.kv("运行状态", f"已启用 ({src_txt})" if ai["configured"] else "未配置 API Key", warn=(not ai["configured"]))
    b.kv("当前模型", ai["model"] if ai["configured"] else "无", warn=(not ai["configured"]))
    b.kv("接口主机", ai["url"] if ai["configured"] else "无", warn=(not ai["configured"]))
    b.kv("今日审核", f"共 {td['ai_checks']} 次 (识图 {td['vision_checks']} / 异常 {td['ai_errors']})", warn=(td["ai_errors"] > 0))
    b.kv("累计审核", f"共 {lt['ai_checks']} 次 (识图 {lt['vision_checks']} / 异常 {lt['ai_errors']})")
    b.kv("今日消耗", f"输入 {td['prompt_tokens']:,} (缓存 {hit_rate}) / 输出 {td['completion_tokens']:,}")
    b.sep()
    if snap["recent_ai"]:
        b.line("最近 AI 判定汇报 (最新 10 条):", color=b.c)
        for r in snap["recent_ai"][:10]:
            gname = r.get("chat_title") or str(r["chat_id"])
            verdict_col = b.y if r["trigger_type"] in ("gray_zone", "ai_suspect") else b.cb
            head = f"[{_fmt_ts(r['created_at'])}] {_trunc(gname, 12)} | {trigger_label(r['trigger_type'])} {r['score']}分"
            b.line(head, color=verdict_col)
            b.line(f"  用户: {_trunc(r['display_name'], 16)} | AI理由: {_trunc(r['reason'], 24)}", color=b.w)
    else:
        b.line("暂无 AI 命中或疑似汇报记录（正常聊天不写审计表）。", color=b.w)
    b.bottom()


def main(argv: list[str]) -> int:
    mode = argv[1] if len(argv) > 1 else "overview"
    work_dir = Path(argv[2]).resolve() if len(argv) > 2 else Path.cwd()
    snap = collect_runtime_snapshot(work_dir)
    if mode == "summary":
        _print_summary_kv(snap)
    elif mode == "overview":
        _print_overview(snap)
    elif mode == "kills":
        _print_kills(snap)
    elif mode == "suspects":
        _print_suspects(snap)
    elif mode == "ai":
        _print_ai_report(snap)
    else:
        print(f"Unknown mode: {mode}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
