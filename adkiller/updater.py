"""Host-side deployment service and the bot's restricted local request protocol."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sqlite3
import stat
import subprocess
import tempfile
import time
from contextlib import closing, suppress
from pathlib import Path
from urllib.request import Request, urlopen


REPOSITORY = "https://github.com/judy-gotv/AdKiller-AI.git"
MAIN_REF = "refs/heads/main"
SOCKET_PATH = Path("data/adkiller-update.sock")
LOCK_PATH = Path(".git/adkiller-update.lock")
CHECK_INTERVAL = 60
SHA_RE = re.compile(r"[0-9a-f]{40}")
logger = logging.getLogger(__name__)


async def request_update(sha: str, owner: int) -> str:
    """Submit an already authenticated private callback to the host service."""
    try:
        async with asyncio.timeout(3):
            reader, writer = await asyncio.open_unix_connection(SOCKET_PATH, limit=512)
            try:
                writer.write(json.dumps({"sha": sha, "owner": owner}).encode() + b"\n")
                await writer.drain()
                return (await reader.readline()).decode().strip()
            finally:
                writer.close()
                await writer.wait_closed()
    except (OSError, TimeoutError, ValueError):
        return "offline"


def command(*args: str, timeout: int = 60, include_stderr: bool = False) -> str:
    return subprocess.run(
        args, timeout=timeout, check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT if include_stderr else subprocess.PIPE,
    ).stdout.strip()


def remote_head() -> str:
    head, ref = command("git", "ls-remote", "--exit-code", REPOSITORY, MAIN_REF).split()
    if ref != MAIN_REF or not SHA_RE.fullmatch(head):
        raise ValueError("Invalid main branch response")
    return head


def credentials() -> tuple[str, set[int]]:
    config = json.loads(command("docker", "compose", "config", "--format", "json"))
    env = config["services"]["adkiller"]["environment"]
    token = env.get("TELEGRAM_BOT_TOKEN") or ""
    owners = {
        int(part.strip()) for part in (env.get("OWNER_IDS") or "").split(",")
        if part.strip().isascii() and part.strip().isdigit() and int(part.strip()) > 0
    }
    if not re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]+", token) or not owners:
        raise ValueError("Telegram updates require TELEGRAM_BOT_TOKEN and explicit OWNER_IDS")
    return token, owners


def notify(token: str, owner: int, text: str, sha: str | None = None) -> bool:
    payload = {"chat_id": owner, "text": text}
    if sha:
        payload["reply_markup"] = {
            "inline_keyboard": [[{"text": "⬆️ 一键更新", "callback_data": f"deploy:{sha}"}]]
        }
    request = Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urlopen(request, timeout=12) as reply:
            return json.load(reply).get("ok") is True
    except (OSError, ValueError) as exc:
        logger.warning("Telegram 通知失败（%s）", type(exc).__name__)
        return False


def backup_database(state_dir: Path) -> None:
    database = Path("data/adkiller.db")
    if not database.is_file():
        return
    if database.is_symlink():
        raise RuntimeError("Database backup requires a regular file")
    with tempfile.TemporaryDirectory(dir=state_dir) as tmp:
        snapshot = Path(tmp) / "adkiller.db"
        with closing(sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True)) as source:
            with closing(sqlite3.connect(snapshot)) as backup:
                source.backup(backup, pages=128)
                if backup.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise RuntimeError("Database backup failed integrity check")
        snapshot.replace(state_dir / "pre-update.db")


def wait_for_polling(expected_image: str) -> None:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        status, image, restarts, started = command(
            "docker", "inspect", "--format",
            "{{.State.Status}} {{.Image}} {{.RestartCount}} {{.State.StartedAt}}", "adkiller",
            timeout=10,
        ).split()
        if status == "running" and image == expected_image and restarts == "0":
            log = command(
                "docker", "logs", "--since", started, "adkiller", timeout=10, include_stderr=True
            )
            if "telegram.ext.Application: Application started" in log:
                return
        time.sleep(2)
    raise RuntimeError("Telegram polling did not start")


def deploy(sha: str, owner: int, state_dir: Path) -> str:
    """Build and test an immutable main commit, then replace only the bot container."""
    import fcntl

    if not SHA_RE.fullmatch(sha):
        raise ValueError("Invalid commit")
    if owner not in credentials()[1]:
        raise ValueError("Owner permission was revoked")
    with closing(os.fdopen(os.open(LOCK_PATH, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600), "wb")) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if command("git", "status", "--porcelain") or command("git", "symbolic-ref", "--short", "HEAD") != "main":
            raise RuntimeError("The deployment checkout must be clean and on main")
        old_sha = command("git", "rev-parse", "HEAD")
        if old_sha == sha:
            return "already"
        command("git", "fetch", "--no-tags", REPOSITORY, MAIN_REF)
        if command("git", "rev-parse", "FETCH_HEAD") != sha:
            return "stale"
        command("git", "merge-base", "--is-ancestor", old_sha, sha)
        old_image, live_tag = command(
            "docker", "inspect", "--format", "{{.Image}} {{.Config.Image}}", "adkiller"
        ).split()
        candidate = f"adkiller-tg-update:{sha[:12]}"
        with tempfile.TemporaryDirectory(prefix="adkiller-stage-") as tmp:
            stage = Path(tmp) / "source"
            command("git", "worktree", "add", "--detach", str(stage), sha)
            try:
                command("docker", "build", "--tag", candidate, str(stage), timeout=600)
                command(
                    "docker", "run", "--rm", "--network", "none",
                    "--mount", f"type=bind,source={stage / 'tests'},target=/app/tests,readonly",
                    candidate, "python", "-m", "unittest", "discover", "-s", "tests",
                    timeout=120,
                )
            finally:
                command("git", "worktree", "remove", str(stage))
        if remote_head() != sha:
            return "stale"
        if command("git", "status", "--porcelain") or command("git", "rev-parse", "HEAD") != old_sha:
            raise RuntimeError("The deployment checkout changed during the build")
        backup_database(state_dir)
        command("docker", "image", "tag", old_image, "adkiller-tg-update:rollback")
        command("git", "merge", "--ff-only", sha)
        try:
            command("docker", "image", "tag", candidate, live_tag)
            command("docker", "compose", "up", "-d", "--no-build", "--no-deps", "adkiller")
            image = command("docker", "image", "inspect", "--format", "{{.Id}}", candidate)
            wait_for_polling(image)
        except (OSError, subprocess.SubprocessError, RuntimeError, ValueError):
            logger.exception("新版启动失败，恢复原部署")
            command("git", "reset", "--keep", old_sha)
            command("docker", "image", "tag", old_image, live_tag)
            command("docker", "compose", "up", "-d", "--no-build", "--no-deps", "adkiller")
            wait_for_polling(old_image)
            return "rolled_back"
        return "updated"


class Updater:
    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.notice_file = state_dir / "notified.json"
        self.notified: dict[str, str] = {}
        with suppress(FileNotFoundError, ValueError):
            self.notified = json.loads(self.notice_file.read_text())
        self.offered: str | None = None
        self.token = ""
        self.owners: set[int] = set()
        self.job: asyncio.Task | None = None
        self.restart = asyncio.Event()

    async def check(self) -> None:
        first_check = not self.token
        self.token, self.owners = await asyncio.to_thread(credentials)
        latest = await asyncio.to_thread(remote_head)
        installed = await asyncio.to_thread(command, "git", "rev-parse", "HEAD")
        available = latest if latest != installed else None
        if first_check or available != self.offered:
            logger.info("已检查 GitHub 更新，本机 %s，main %s", installed[:7], latest[:7])
        self.offered = available
        if self.offered:
            for owner in sorted(self.owners):
                if self.notified.get(str(owner)) == latest:
                    continue
                if await asyncio.to_thread(
                    notify, self.token, owner, f"🛡 AI-智能广告杀手有新版本\n当前 {installed[:7]} · 最新 {latest[:7]}", latest
                ):
                    self.notified[str(owner)] = latest
                    temporary = self.notice_file.with_suffix(".tmp")
                    temporary.write_text(json.dumps(self.notified))
                    temporary.replace(self.notice_file)

    async def run_update(self, sha: str, owner: int) -> None:
        token = self.token
        try:
            result = await asyncio.to_thread(deploy, sha, owner, self.state_dir)
        except (OSError, subprocess.SubprocessError, RuntimeError, ValueError, KeyError):
            logger.exception("部署失败")
            await asyncio.to_thread(notify, token, owner, "更新失败。请查看宿主机更新服务日志。", sha)
            return
        if result == "updated":
            await asyncio.to_thread(notify, token, owner, f"✅ AI-智能广告杀手已更新到 {sha[:7]}，Telegram 轮询已恢复。")
            self.restart.set()
        elif result == "rolled_back":
            await asyncio.to_thread(notify, token, owner, "新版启动失败，已恢复原版本。", sha)
        elif result == "already":
            self.offered = None
            await asyncio.to_thread(notify, token, owner, f"已运行 {sha[:7]}。")
        else:
            self.offered = None
            await asyncio.to_thread(notify, token, owner, "GitHub 上已有更新的提交，请使用新的更新通知。")
            await self.check()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            async with asyncio.timeout(3):
                request = json.loads(await reader.readline())
                owner, sha = request["owner"], request["sha"]
                if type(owner) is not int or owner not in self.owners:
                    reply = "denied"
                elif self.job and not self.job.done():
                    reply = "busy"
                elif not isinstance(sha, str) or not SHA_RE.fullmatch(sha) or sha != self.offered:
                    reply = "stale"
                else:
                    self.job = asyncio.create_task(self.run_update(sha, owner))
                    reply = "queued"
                writer.write(reply.encode() + b"\n")
                await writer.drain()
        except (KeyError, TypeError, ValueError, OSError, TimeoutError):
            pass
        finally:
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()

    async def poll(self) -> None:
        while not self.restart.is_set():
            if not self.job or self.job.done():
                try:
                    await self.check()
                except (OSError, subprocess.SubprocessError, RuntimeError, ValueError, KeyError):
                    logger.exception("检查 GitHub 更新失败")
            try:
                await asyncio.wait_for(self.restart.wait(), CHECK_INTERVAL)
            except TimeoutError:
                pass


async def serve(state_dir: Path) -> None:
    SOCKET_PATH.parent.mkdir(exist_ok=True)
    if SOCKET_PATH.exists() or SOCKET_PATH.is_symlink():
        if not stat.S_ISSOCK(SOCKET_PATH.lstat().st_mode):
            raise RuntimeError("Update socket path is occupied")
        SOCKET_PATH.unlink()
    updater = Updater(state_dir)
    server = await asyncio.start_unix_server(updater.handle_client, path=SOCKET_PATH, limit=512)
    try:
        async with server:
            await updater.poll()
    finally:
        SOCKET_PATH.unlink(missing_ok=True)


if __name__ == "__main__":
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    asyncio.run(serve(Path(os.environ["STATE_DIRECTORY"])))
