import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, call, patch

from adkiller import updater
from adkiller.panel import handle_callback


OLD = "a" * 40
NEW = "b" * 40


class TestUpdateNotifications(unittest.IsolatedAsyncioTestCase):
    async def test_each_owner_is_notified_once_per_version_across_restarts(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            with (
                patch.object(updater, "credentials", return_value=("test", {101, 102})),
                patch.object(updater, "remote_head", return_value=NEW),
                patch.object(updater, "command", return_value=OLD),
                patch.object(updater, "notify", return_value=True) as notify,
            ):
                await updater.Updater(state_dir).check()
                await updater.Updater(state_dir).check()

            self.assertEqual(notify.call_count, 2)
            self.assertEqual({c.args[1] for c in notify.call_args_list}, {101, 102})
            self.assertTrue(all(c.args[-1] == NEW for c in notify.call_args_list))

    async def test_only_a_private_owner_callback_reaches_the_host(self):
        engine = SimpleNamespace(is_owner=lambda owner: owner == 101)
        ctx = SimpleNamespace(application=SimpleNamespace(bot_data={"engine": engine}))

        with patch("adkiller.panel.request_update", new_callable=AsyncMock) as request:
            request.return_value = "queued"
            for chat_type, chat_id, user_id in (
                ("supergroup", -100, 101),
                ("private", 102, 102),
                ("private", 102, 101),
                ("private", 101, 101),
            ):
                query = SimpleNamespace(
                    data=f"deploy:{NEW}",
                    from_user=SimpleNamespace(id=user_id),
                    message=SimpleNamespace(chat=SimpleNamespace(id=chat_id, type=chat_type)),
                    answer=AsyncMock(),
                )
                await handle_callback(SimpleNamespace(callback_query=query), ctx)
                query.answer.assert_awaited_once()
            request.assert_awaited_once_with(NEW, 101)

    async def test_socket_accepts_only_current_offer_and_runs_one_update(self):
        with tempfile.TemporaryDirectory() as tmp:
            socket = Path(tmp) / "updater.sock"
            service = updater.Updater(Path(tmp))
            service.offered = NEW
            service.owners = {101}
            in_progress = asyncio.Event()
            complete = asyncio.Event()

            async def run_update(sha, owner):
                in_progress.set()
                await complete.wait()

            with (
                patch.object(updater, "SOCKET_PATH", socket),
                patch.object(service, "run_update", side_effect=run_update) as deploy,
            ):
                server = await asyncio.start_unix_server(service.handle_client, path=socket)
                async with server:
                    try:
                        self.assertEqual(await updater.request_update(NEW, 102), "denied")
                        self.assertEqual(await updater.request_update(OLD, 101), "stale")
                        self.assertEqual(await updater.request_update(NEW, 101), "queued")
                        await asyncio.wait_for(in_progress.wait(), timeout=2)
                        self.assertEqual(await updater.request_update(NEW, 101), "busy")
                        deploy.assert_awaited_once_with(NEW, 101)
                    finally:
                        complete.set()
                        if service.job:
                            await service.job


class TestDeployment(unittest.TestCase):
    def test_failed_start_restores_checkout_and_old_image(self):
        responses = {
            ("git", "symbolic-ref", "--short", "HEAD"): "main",
            ("git", "rev-parse", "HEAD"): OLD,
            ("git", "rev-parse", "FETCH_HEAD"): NEW,
            ("docker", "inspect", "--format", "{{.Image}} {{.Config.Image}}", "adkiller"):
                "sha256:old adkiller-adkiller",
            ("docker", "image", "inspect", "--format", "{{.Id}}", f"adkiller-tg-update:{NEW[:12]}"):
                "sha256:new",
        }
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            with (
                patch.object(updater, "LOCK_PATH", state_dir / "lock"),
                patch.object(updater, "credentials", return_value=("test", {101})),
                patch.object(updater, "remote_head", return_value=NEW),
                patch.object(updater, "backup_database") as backup,
                patch.object(updater, "command", side_effect=lambda *args, **kw: responses.get(args, "")) as cmd,
                patch.object(updater, "wait_for_polling", side_effect=[RuntimeError("startup failed"), None]) as health,
                self.assertLogs(updater.logger, level="ERROR"),
            ):
                self.assertEqual(updater.deploy(NEW, 101, state_dir), "rolled_back")

            backup.assert_called_once_with(state_dir)
            cmd.assert_any_call("git", "merge", "--ff-only", NEW)
            cmd.assert_any_call("git", "reset", "--keep", OLD)
            cmd.assert_any_call("docker", "image", "tag", "sha256:old", "adkiller-adkiller")
            self.assertEqual(health.call_args_list, [call("sha256:new"), call("sha256:old")])
