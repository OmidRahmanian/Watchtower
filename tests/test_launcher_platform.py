import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import launcher


class PlatformLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.token = self.root / "token"
        self.output = io.StringIO()
        self.cli = Mock(return_value=0)

    def run_wizard(self, answers, *, token_exists=True, env=None):
        if token_exists:
            self.token.write_text("wt_token\n")
        environment = {"WATCHTOWER__DATABASE__URL": "postgresql://example", "WATCHTOWER_TOKEN_FILE": str(self.token),
                       **(env or {})}
        with contextlib.redirect_stdout(self.output), \
                patch("builtins.input", side_effect=answers), \
                patch.object(launcher, "runtime_environment", return_value=environment), \
                patch.object(launcher, "platform_ready"), \
                patch.object(launcher, "platform_cli", self.cli):
            return launcher.platform_wizard(self.root)

    def commands(self):
        return [call.args[3:] for call in self.cli.call_args_list]

    def test_banner_is_kept_and_scope_needs_explicit_confirmation(self):
        answers = ["1", "acme", "1", "shop.acme.example", "", "1", "TICKET-7", "Acme CISO", "n"]
        self.assertEqual(self.run_wizard(answers), 0)
        self.assertIn("WATCHTOWER", self.output.getvalue())
        self.assertIn("The scope was not changed", self.output.getvalue())
        self.assertFalse(any("publish" in command for command in self.commands()))

    def test_publishes_authorized_scope_then_starts_and_watches_a_run(self):
        answers = ["2", "", "1", "acme-lab.test", "legacy.acme-lab.test", "1", "lab/README.md", "Lab Owner", "y",
                   "1", "y"]
        self.assertEqual(self.run_wizard(answers), 0)
        token = ("--token-file", str(self.token))
        status, publish, start = self.commands()
        self.assertEqual(status, (*token, "status"))
        self.assertEqual(publish, (*token, "scope", "publish", "--include", "acme-lab.test", "--include",
                                   "*.acme-lab.test", "--authorization-kind", "asset_owner", "--reference",
                                   "lab/README.md", "--granted-by", "Lab Owner", "--i-am-authorized", "--exclude",
                                   "legacy.acme-lab.test"))
        self.assertEqual(start, (*token, "run", "start", "--reason", "started from launcher", "--watch", "--work"))
        env = self.cli.call_args.args[2]
        self.assertEqual((env["WATCHTOWER_PROFILE"], env["WATCHTOWER_PROJECT"]), ("lab", "acme-lab"))

    def test_target_input_is_validated_before_anything_runs(self):
        answers = ["1", "Bad Slug!", "acme", "1", "https://acme.example/x", "127.0.0.1", "acme.example", "-",
                   "2", "SOW-1", "Acme", "y", "4"]
        self.assertEqual(self.run_wizard(answers), 0)
        publish = self.commands()[1]
        self.assertIn("contract", publish)
        self.assertIn("Use a domain such as example.com", self.output.getvalue())
        self.assertIn("Enter a domain name rather than an IP address", self.output.getvalue())

    def test_missing_token_offers_bootstrap_and_saves_it_privately(self):
        answers = ["1", "acme", "y", "Ada Owner", "2", "2", "n"]
        self.assertEqual(self.run_wizard(answers, token_exists=False), 0)
        bootstrap, status, watch = self.commands()
        self.assertEqual(bootstrap, ("bootstrap", "acme", "--owner", "Ada Owner", "--save-token", str(self.token)))
        self.assertEqual(watch, ("--token-file", str(self.token), "watch"))

    def test_failed_status_stops_before_any_scope_change(self):
        self.cli.return_value = 2
        with self.assertRaises(RuntimeError):
            self.run_wizard(["1", "acme"])
        self.assertEqual(len(self.cli.call_args_list), 1)

    def test_mode_menu_routes_to_platform_or_legacy(self):
        with contextlib.redirect_stdout(self.output), patch("builtins.input", side_effect=["1"]), \
                patch.object(launcher, "platform_wizard", return_value=0) as platform, \
                patch.object(launcher, "wizard", return_value=0) as legacy:
            self.assertEqual(launcher.main([]), 0)
            platform.assert_called_once()
            legacy.assert_not_called()
        with patch.object(launcher, "wizard", return_value=0) as legacy, \
                patch.object(launcher, "platform_wizard") as platform:
            launcher.main(["--configure-only"])
            legacy.assert_called_once_with(configure_only=True)
            platform.assert_not_called()


if __name__ == "__main__":
    unittest.main()
