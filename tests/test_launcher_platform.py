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

    def test_platform_keeps_banner_loads_private_environment_and_opens_home(self):
        environment = {"WATCHTOWER__DATABASE__URL": "private-database-url"}
        with contextlib.redirect_stdout(self.output), \
                patch.object(launcher, "runtime_environment", return_value=environment), \
                patch.object(launcher, "platform_ready") as ready, \
                patch.object(launcher.subprocess, "run", return_value=Mock(returncode=0)) as run:
            self.assertEqual(launcher.platform_wizard(self.root), 0)
        self.assertIn("WATCHTOWER", self.output.getvalue())
        ready.assert_called_once()
        args = run.call_args.args[0]
        self.assertEqual(args[-1], str(self.root / "terminal_ui.py"))
        self.assertNotIn("private-database-url", " ".join(args))
        self.assertEqual(run.call_args.kwargs["env"], environment)

    def test_platform_dependency_failure_does_not_open_home(self):
        with contextlib.redirect_stdout(self.output), \
                patch.object(launcher, "runtime_environment", return_value={}), \
                patch.object(launcher, "platform_ready", side_effect=RuntimeError("Database not configured")), \
                patch.object(launcher.subprocess, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "Database not configured"):
                launcher.platform_wizard(self.root)
            run.assert_not_called()

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
