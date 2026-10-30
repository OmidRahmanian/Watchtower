import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import launcher
from session import acquire_session, running_pid


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.settings = json.loads((launcher.ROOT / "setting.json").read_text())
        self.targets = {"old.example.com": {"report_url": "", "out_of_scope": []}}
        (self.root / "targets.json").write_text(json.dumps(self.targets))
        (self.root / "setting.json").write_text(json.dumps(self.settings))
        self.output = io.StringIO()

    def test_domains_normalize_and_reject_shell_url_and_ip_input(self):
        self.assertEqual(launcher.domain_name(" EXAMPLE.COM. "), "example.com")
        self.assertEqual(launcher.domain_name("bücher.example"), "xn--bcher-kva.example")
        for value in ("https://example.com", "example.com/path", "example.com;id", "$(id).com",
                      "*.example.com", "127.0.0.1", "example.com:443", "-bad.example", "localhost"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                launcher.domain_name(value)

    def test_exclusions_are_exact_and_within_selected_domain(self):
        self.assertEqual(launcher.exclusions("A.example.com, ,a.example.com", "example.com"), ["a.example.com"])
        self.assertEqual(launcher.exclusions("-", "example.com"), [])
        self.assertEqual(launcher.report_url("-"), "")
        for value in ("*.example.com", "example.com", "other.com", "notexample.com"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                launcher.exclusions(value, "example.com")

    def test_profile_preserves_unrelated_settings_and_disables_other_jobs(self):
        original = json.loads(json.dumps(self.settings))
        settings = launcher.discovery_settings(self.settings, 1, "minutes", True)
        self.assertEqual(self.settings, original)
        self.assertEqual(settings["subfinder"], {"time": "minutes", "value": "1", "status": "enable"})
        for name in launcher.JOBS[1:]:
            self.assertEqual(settings[name]["status"], "disable")
        self.assertEqual(settings["sendmessage"]["status"], "enable")
        self.assertEqual(settings["nuclei_command"], original["nuclei_command"])

    def test_backup_is_exact_and_webhook_is_private(self):
        previous = (self.root / "targets.json").read_bytes()
        (self.root / ".env").write_text("SECURITYTRAILS_API_KEYS='keep-me'\n")
        webhook = "https://discord.com/api/webhooks/123456789012345678/" + "a" * 68
        backup = launcher.save_configuration(self.root, {}, self.settings, webhook)
        self.assertEqual((backup / "targets.json").read_bytes(), previous)
        self.assertEqual((backup / ".env").read_text(), "SECURITYTRAILS_API_KEYS='keep-me'\n")
        self.assertIn("keep-me", (self.root / ".env").read_text())
        self.assertEqual((self.root / ".env").stat().st_mode & 0o777, 0o600)
        env = launcher.runtime_environment(self.root, sys.executable)
        self.assertTrue(all(env[key] == webhook for key in launcher.WEBHOOK_KEYS))

    def test_failed_second_write_restores_original_configuration(self):
        before = {name: (self.root / name).read_bytes() for name in ("targets.json", "setting.json")}
        original_write = launcher.atomic_write
        def fail_settings(path, text, mode=None):
            if path.name == "setting.json":
                raise OSError("disk unavailable")
            original_write(path, text, mode)
        with patch.object(launcher, "atomic_write", side_effect=fail_settings), self.assertRaises(OSError):
            launcher.save_configuration(self.root, {}, self.settings)
        for name, content in before.items():
            self.assertEqual((self.root / name).read_bytes(), content)

    def wizard(self, answers, **patches):
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(contextlib.redirect_stdout(self.output))
        stack.enter_context(patch("builtins.input", side_effect=answers))
        stack.enter_context(patch.object(launcher, "runtime_environment", return_value=dict(os.environ)))
        stack.enter_context(patch.object(launcher, "running_pid", return_value=None))
        for name, replacement in patches.items():
            stack.enter_context(patch.object(launcher, name, replacement))
        return launcher.wizard(self.root)

    def test_save_only_wizard_selects_one_target_and_does_not_start_services(self):
        start = Mock()
        result = self.wizard(["1", "bad/url", "EXAMPLE.COM", "", "skip.example.com", "1", "n", "2"],
                             start_mongodb=start)
        self.assertEqual(result, 0)
        self.assertEqual(json.loads((self.root / "targets.json").read_text()), {
            "example.com": {"report_url": "", "out_of_scope": ["skip.example.com"]},
        })
        self.assertEqual(json.loads((self.root / "setting.json").read_text())["sendmessage"]["status"], "disable")
        start.assert_not_called()

    def test_cancel_preserves_all_files(self):
        original = (self.root / "targets.json").read_bytes()
        self.wizard(["1", "example.com", "", "", "1", "n", "3"])
        self.assertEqual((self.root / "targets.json").read_bytes(), original)
        self.assertFalse((self.root / "files/config-backups").exists())

    def test_configured_notifications_reuse_webhook_without_printing_it(self):
        webhook = "https://discord.com/api/webhooks/123456789012345678/" + "a" * 68
        env = dict.fromkeys(launcher.WEBHOOK_KEYS, webhook)
        self.wizard(
            ["1", "example.com", "", "", "1", "y", "2"],
            runtime_environment=Mock(return_value=env),
        )
        settings = json.loads((self.root / "setting.json").read_text())
        self.assertEqual(settings["sendmessage"]["status"], "enable")
        self.assertNotIn(webhook, self.output.getvalue())

    def test_webhook_validation_matches_backend_requirements(self):
        valid = "https://discord.com/api/webhooks/123456789012345678/" + "a" * 68
        self.assertTrue(launcher.valid_webhook(valid))
        self.assertFalse(launcher.valid_webhook(valid.replace("123456789012345678", "123")))
        self.assertFalse(launcher.valid_webhook(valid.replace("a" * 68, "short")))
        self.assertFalse(launcher.valid_webhook(valid.replace("discord.com", "discord.com.evil.example")))

    def test_real_cli_can_save_setup_without_starting_services(self):
        for name in ("launcher.py", "session.py"):
            shutil.copy2(launcher.ROOT / name, self.root / name)
        result = subprocess.run(
            [sys.executable, str(self.root / "launcher.py"), "--configure-only"],
            input="1\nexample.com\n\n\n1\nn\n", cwd=self.root,
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Configuration saved", result.stdout)
        self.assertNotIn("Starting MongoDB", result.stdout)
        self.assertEqual(list(json.loads((self.root / "targets.json").read_text())), ["example.com"])

    def test_saved_target_custom_schedule_and_automatic_start(self):
        dependencies, mongodb, monitor = Mock(), Mock(), Mock(return_value=0)
        result = self.wizard(["2", "1", "", "", "3", "0", "5", "2", "n", "1"],
                             check_dependencies=dependencies, start_mongodb=mongodb, run_monitor=monitor)
        self.assertEqual(result, 0)
        config = json.loads((self.root / "setting.json").read_text())
        self.assertEqual(config["subfinder"]["value"], "5")
        self.assertEqual(config["subfinder"]["time"], "hours")
        dependencies.assert_called_once()
        mongodb.assert_called_once()
        monitor.assert_called_once()

    def test_running_session_requires_stop_before_configuration_changes(self):
        original = (self.root / "targets.json").read_bytes()
        with contextlib.redirect_stdout(self.output), \
                patch("builtins.input", side_effect=["1", "example.com", "", "", "1", "n", "2", "n"]), \
                patch.object(launcher, "runtime_environment", return_value={}), \
                patch.object(launcher, "running_pid", return_value=12345), \
                patch.object(launcher, "stop_session") as stop:
            launcher.wizard(self.root)
        stop.assert_not_called()
        self.assertEqual((self.root / "targets.json").read_bytes(), original)

    def test_compose_falls_back_to_standalone(self):
        with patch("launcher.shutil.which", return_value="installed"), \
                patch("launcher.subprocess.run", side_effect=[Mock(returncode=1), Mock(returncode=0)]):
            self.assertEqual(launcher.compose_command(), ["docker-compose"])

    def test_mongodb_failure_prevents_readiness_check(self):
        with contextlib.redirect_stdout(self.output), \
                patch.object(launcher, "compose_command", return_value=["docker-compose"]), \
                patch("launcher.subprocess.run", return_value=Mock(returncode=1)) as command, \
                self.assertRaises(RuntimeError):
            launcher.start_mongodb(self.root, sys.executable, dict(os.environ))
        command.assert_called_once_with(["docker-compose", "up", "-d", "mongodb"], cwd=self.root)

    def test_live_output_is_logged_and_child_failure_is_propagated(self):
        (self.root / "watch.py").write_text("print('fake discovery output', flush=True)\nraise SystemExit(7)\n")
        with acquire_session(self.root) as lock, contextlib.redirect_stdout(self.output):
            code = launcher.run_monitor(self.root, sys.executable, dict(os.environ), lock)
        self.assertEqual(code, 7)
        self.assertIn("fake discovery output", self.output.getvalue())
        self.assertIn("fake discovery output", (self.root / "files/watchtower.log").read_text())

    def test_interrupt_stops_monitor_and_cleans_pid(self):
        process = Mock(pid=54321)
        process.stdout.__iter__ = Mock(side_effect=KeyboardInterrupt)
        process.poll.return_value = None
        (self.root / "files").mkdir()
        (self.root / "files/watchtower.pid").write_text("54321")
        with acquire_session(self.root) as lock, contextlib.redirect_stdout(self.output), \
                patch("launcher.subprocess.Popen", return_value=process), \
                patch("launcher.os.killpg") as stop, self.assertRaises(KeyboardInterrupt):
            launcher.run_monitor(self.root, sys.executable, dict(os.environ), lock)
        stop.assert_called_once()
        self.assertFalse((self.root / "files/watchtower.pid").exists())

    def test_session_lock_blocks_concurrent_launchers(self):
        with acquire_session(self.root):
            with self.assertRaises(RuntimeError):
                acquire_session(self.root)
        with acquire_session(self.root):
            pass

    def test_actual_monitor_adopts_launcher_lock_without_running_scans(self):
        settings = launcher.discovery_settings(self.settings, 1, "minutes", False)
        (self.root / "setting.json").write_text(json.dumps(settings))
        for name in ("watch.py", "session.py"):
            shutil.copy2(launcher.ROOT / name, self.root / name)
        script = (
            "import sys\nfrom unittest.mock import patch\n"
            "with patch('pymongo.MongoClient'):\n"
            " import watch\n"
            " watch.schedule.run_pending = lambda: sys.exit(0)\n"
            " watch.main()\n"
        )
        with acquire_session(self.root) as lock:
            result = subprocess.run(
                [sys.executable, "-u", "-c", script], cwd=self.root,
                env=dict(os.environ, WATCHTOWER_LOCK_FD=str(lock.fileno())),
                pass_fds=(lock.fileno(),), capture_output=True, text=True, timeout=10,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("WatchTower running: 1 scheduled jobs", result.stdout)
        self.assertIn("Notifications: disabled", result.stdout)
        self.assertFalse((self.root / "files/watchtower.pid").exists())

    def test_stale_pid_does_not_stop_unrelated_process(self):
        (self.root / "files").mkdir()
        (self.root / "files/watchtower.pid").write_text("12345")
        with patch("session.subprocess.run", return_value=Mock(returncode=0, stdout="python other_app.py")):
            self.assertIsNone(running_pid(self.root))


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.settings = launcher.discovery_settings(
            json.loads((launcher.ROOT / "setting.json").read_text()), 1, "minutes", False,
        )
        (self.root / "setting.json").write_text(json.dumps(self.settings))
        (self.root / "targets.json").write_text(json.dumps({
            "example.com": {"report_url": "", "out_of_scope": ["skip.example.com"]},
        }))
        previous = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        spec = importlib.util.spec_from_file_location("watchtower_under_test", launcher.ROOT / "watch.py")
        self.monitor = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, {}, clear=True), patch("pymongo.MongoClient"):
            spec.loader.exec_module(self.monitor)
        self.monitor.__file__ = str(self.root / "watch.py")
        self.addCleanup(self.monitor.schedule.clear)

    def test_notifications_off_needs_no_secrets(self):
        self.assertIsInstance(self.monitor.new_sub_webhook, self.monitor.DisabledWebhook)
        self.assertEqual(self.monitor.telegram_chat_id, "")

    def test_discovery_filters_empty_excluded_and_outside_results(self):
        collection = Mock()
        collection.find_one.return_value = None
        client = Mock()
        client.__getitem__ = Mock(return_value=client)
        client.__getitem__.return_value = client
        client.find_one = collection.find_one
        client.insert_one = collection.insert_one
        output = "\nnew.example.com\nskip.example.com\nother.com\n"
        with contextlib.redirect_stdout(io.StringIO()), \
                patch.object(self.monitor.pymongo, "MongoClient", return_value=client), \
                patch.object(self.monitor.subprocess, "run", return_value=Mock(stdout=output)) as command:
            self.monitor.subfinder()
        command.assert_called_once_with(
            ["subfinder", "-d", "example.com", "-all", "-silent"],
            capture_output=True, text=True, check=True,
        )
        collection.insert_one.assert_called_once()
        self.assertEqual(collection.insert_one.call_args[0][0]["subdomain"], "new.example.com")

    def test_failed_tool_does_not_insert_error_text(self):
        client = Mock()
        client.__getitem__ = Mock(return_value=client)
        with contextlib.redirect_stdout(io.StringIO()), \
                patch.object(self.monitor.pymongo, "MongoClient", return_value=client), \
                patch.object(self.monitor.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "subfinder")), \
                self.assertRaises(subprocess.CalledProcessError):
            self.monitor.subfinder()
        client.insert_one.assert_not_called()

    def test_settings_reload_does_not_duplicate_jobs(self):
        calls = []
        def pending():
            calls.append(len(self.monitor.schedule.jobs))
            if len(calls) == 1:
                self.settings["subfinder"]["value"] = "2"
                (self.root / "setting.json").write_text(json.dumps(self.settings))
            else:
                raise KeyboardInterrupt
        with contextlib.redirect_stdout(io.StringIO()), \
                patch.object(self.monitor.schedule, "run_pending", side_effect=pending), \
                patch.object(self.monitor.time, "sleep"), self.assertRaises(KeyboardInterrupt):
            self.monitor.main()
        self.assertEqual(calls, [1, 1])
        self.assertFalse((self.root / "files/watchtower.pid").exists())


if __name__ == "__main__":
    unittest.main()
